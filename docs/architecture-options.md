# Architecture Options

Status: Phase 0 draft — proposal, not a final decision
Last updated: 2026-08-20

This document lays out major architecture options and trade-offs. It does
not commit to implementation. Formal architecture decision records (ADRs)
will be created per-decision starting in Phase 1, using a template also
delivered in Phase 1.

## 1. Overall Style: Modular Event-Driven Services

The master prompt mandates a modular, event-driven platform with 15
logical services (Collector, Aggregator, Classifier, Detector, Incident
Manager, Mitigation Controller, Notification, Public API, Internal gRPC API,
Web App, CLI, Configuration, Audit, Reporting, Backup/Restore).

**Option A — Monorepo, multiple deployable binaries (recommended for MVP)**
Single repository (`tidegard`), Cargo workspace for Rust crates, one
binary per service, shared internal libraries in `crates/common`,
`crates/storage`, etc. Deployed as separate containers/processes but built
and versioned together up through v1.0.0.

- Pros: simplest CI/CD, easiest cross-service refactors during early
  phases, matches the prescribed repository layout exactly, lowest
  operational overhead for a single-tenant appliance.
- Cons: coarser release granularity; will need to be revisited for v2.0.0
  distributed HA.

**Option B — Polyrepo per service**
Separate repositories per service from day one.

- Pros: independent versioning and release cadence per team/service.
- Cons: heavy overhead for a pre-v1.0 product with no dedicated team per
  service; contradicts the explicit monorepo layout in the master prompt
  section 22.

**Recommendation:** Option A. The master prompt already specifies the
monorepo layout; deviating would require a blocking decision, not a Phase 0
default.

## 2. Event Transport Between Services

The master prompt requires evaluating NATS JetStream, Redpanda, and Kafka,
with an ADR selecting the default.

| Option | Pros | Cons |
|---|---|---|
| NATS JetStream | Lightweight, single small binary, low ops burden, good fit for a self-hosted appliance, native Rust and Go clients | Smaller ecosystem than Kafka for very large-scale stream processing |
| Redpanda | Kafka-API-compatible, no ZooKeeper, strong throughput | Heavier resource footprint than NATS for a small appliance deployment |
| Kafka | Industry-standard, huge ecosystem, best tooling for very large multi-tenant deployments | Heaviest operational cost (ZooKeeper/KRaft, JVM), likely overkill for MVP single-tenant appliance and bare-metal Ubuntu target |

**Decision (ADR 0004):** narrower than the original leaning — Phase 3 uses
an in-process bounded channel within the collector binary (no separate
Aggregator process yet), with NATS JetStream recorded as the transport to
implement when the Aggregator needs to run independently. See
[ADR 0004](architecture/decisions/0004-collector-aggregator-event-transport.md)
for the full reasoning (no Docker in the dev environment to validate NATS
against, and Phase 3's own scope doesn't require a separate process).
Kafka/Redpanda remain deferred to the v2.0.0 distributed-HA milestone.

## 3. Collector Language: Rust vs Go

Required by master prompt section 6 as an explicit ADR before
implementation (Phase 2). **Decided:** see
[ADR 0001](architecture/decisions/0001-collector-implementation-language.md)
— Rust, for the collector and everything upstream of storage (parsing,
aggregation, classification). The comparison table below is preserved as
the supporting analysis; the Mitigation Controller's language remains a
separate, later decision (see below).

| Dimension | Rust | Go |
|---|---|---|
| Memory safety | Compile-time guarantees, no GC pauses | GC-managed, safe but with pause behavior |
| Parser safety | Strong; `no_std`-friendly parsing, exhaustive match on untrusted input | Safe but historically more panics-from-index-out-of-range in hand-rolled binary parsers |
| Fuzzing support | Mature (`cargo-fuzz`, `libFuzzer`) | Mature (`go-fuzz`, native fuzzing since Go 1.18) |
| Concurrency | `tokio` async, fine-grained control | Goroutines, simpler mental model |
| Performance | Typically lower latency/memory for hot-path packet parsing | Very good, slightly higher baseline memory due to GC |
| Ecosystem maturity | Strong for networking (`tokio`, `nom`, `pnet`) but smaller than Go's | Very mature for network services and BGP tooling (GoBGP itself is Go) |
| Ease of deployment | Static binaries, small footprint | Static binaries, small footprint, comparable |
| Long-term maintenance | Steeper learning curve, stronger correctness guarantees | Easier to onboard contributors, faster iteration |
| Developer availability | Smaller pool | Larger pool |

**Decision (ADR 0001):** Rust for the Telemetry Collector and protocol
parsers specifically (untrusted-input parsing is the highest-risk attack
surface — see [security-principles.md](security-principles.md) threat
model), per the master prompt's stated preference. Go remains attractive
for the Mitigation Controller given GoBGP is itself a Go library — that
stays a separate, dedicated ADR rather than assuming Rust everywhere, due
before Phase 7.

## 4. Storage Architecture

Master prompt section 12 already prescribes: ClickHouse (primary
analytics), InfluxDB v1-compatible output (legacy/compatibility),
PostgreSQL (config/metadata), Prometheus (metrics). This is treated as
fixed direction, not an open option, because it is explicitly specified.
Table-level schema design is deferred to Phase 3/5 — see
[out-of-scope.md](out-of-scope.md).

## 5. Frontend Architecture

Master prompt section 15 prescribes React + TypeScript + Vite + Tailwind +
shadcn/ui + Recharts/ECharts. Treated as fixed direction. Choice between
Recharts and ECharts is deferred to Phase 6 as a lightweight ADR (Recharts
is simpler/lighter for standard time-series; ECharts is stronger for dense
NOC-style multi-series/heatmap panels — likely ECharts given the NOC use
case, to be confirmed in Phase 6).

## 6. Deployment Targets

All three targets (Docker Compose, Kubernetes/Helm, bare-metal
Ubuntu/systemd) are required, not alternatives to choose between. Docker
Compose is the fastest path to a working Phase 2–4 demo environment and
should be the first one made real; Kubernetes and bare-metal come later
without blocking early phases.

## 7. Decision Process Going Forward

Every option marked "leaning" above must become a formal ADR (template
delivered in Phase 1) with explicit trade-off comparison before the phase
that depends on it begins. None of the leanings in this document authorize
writing production code in Phase 0.
