# Capacity Planning

Status: The flow-rate target (Phase 3) is **not yet benchmarked**. The
incident database **was benchmarked on 2026-10-05** (Phase 5F); see
[Incident persistence, measured](#incident-persistence-measured).

## Performance Target

> Sustain at least 100,000 normalized flow records per second on the
> documented test machine, without packet generation over public
> networks.

This is a **target**, not a benchmark result. No performance benchmark
has been executed against this target — per
`prompts/CLAUDE_MASTER_PROMPT.md` §30 rule 12 and the explicit Phase 3
instruction not to claim a performance target was met without an actual
benchmark run and recorded machine specifications, this document makes
no throughput claim. Benchmarking is a Phase 9 (production hardening)
deliverable; Phase 3 defines the target so Phase 9's benchmark has
something concrete to measure against.

## Memory Sizing (Aggregator)

Each aggregation dimension's worst-case memory is bounded by
`max_entries × (key size + TrafficCounters size)`. `TrafficCounters` is
12 × `u64` = 96 bytes. Approximate per-entry overhead (key + `HashMap`/
tracking overhead) varies by dimension:

| Dimension | Key | Approx. bytes/entry | Default `max_entries` | Approx. worst case |
|---|---|---|---|---|
| Hosts (v4+v6 combined) | `IpAddr` (up to 17 bytes) + counters | ~150 | 100,000 | ~15 MB |
| Networks (all prefix dimensions) | `(IpAddr, u8)` + counters | ~160 | 50,000 | ~8 MB |
| Hostgroups | `String` + counters | ~180 (varies with name length) | 1,000 | ~0.2 MB |
| ASNs | `u32` + counters | ~140 | 10,000 | ~1.4 MB |
| Exporters | `IpAddr` + counters | ~150 | 1,000 (default, not yet env-configurable) | ~0.15 MB |

These are architectural estimates from struct sizes, not measured
allocations — a real memory-under-load measurement is part of the Phase
9 benchmark, not asserted here as fact.

## Queue Memory

`WETECHINETMON_COLLECTOR_QUEUE_CAPACITY` (default 10,000) bounds the
in-process channel between UDP receive and classify/aggregate. Each
queued item is a raw datagram (`Vec<u8>`, up to `MAX_DATAGRAM_SIZE` =
65,535 bytes) plus a `SocketAddr`. Worst case: 10,000 × ~65KB ≈ 640MB if
every datagram were maximum-sized and the queue were completely full —
in practice, real IPFIX datagrams are far smaller (well under the 1500
byte path MTU), so actual queue memory under backpressure is expected to
be much lower. Not measured; documented as an upper bound from the
configuration, not an observed value.

## ClickHouse Export Data-Loss Trade-off

Per [ADR 0005](../architecture/decisions/0005-clickhouse-batching-and-retry.md):
under prolonged ClickHouse unavailability, this project **loses data by
design** rather than growing memory without bound. Specifically:

- The retry queue holds at most `RetryConfig::default().max_pending_batches`
  (100) batches. Once full, the **oldest** pending batch is dropped to
  make room for a new failure — not the newest.
- Each batch is retried at most `max_attempts` (5) times with exponential
  backoff (1s → 2s → 4s → 8s → 16s, capped at 60s) before being
  permanently dropped.
- At default settings (10,000 rows or 5s per batch, 100 pending batches),
  roughly 8–9 minutes of accumulated failed writes can be held before the
  oldest starts being dropped — a rough arithmetic estimate from the
  configured limits, not a measured outage-tolerance figure.

**Operator guidance:** if ClickHouse outages longer than this are
expected in your environment, either increase `RetryConfig`'s
`max_pending_batches` (accepting higher worst-case memory use during an
outage) or treat ClickHouse analytics data as best-effort and rely on
Prometheus metrics (which are not subject to this trade-off) for
operational alerting during an outage.

## Incident persistence, measured

Measured 2026-10-05 by the Benchmark workflow,
[run 37316065893](https://github.com/LogiXhare/wetechi-netmon/actions/runs/37316065893),
at commit `0f0dd71`. The harness is
`crates/incident-postgres/tests/benchmark.rs`. Anyone can rerun it from
the Actions tab.

**Machine.** A GitHub-hosted `ubuntu-latest` runner:

- AMD EPYC 9V74, 4 vCPUs;
- 15 GiB of memory;
- Linux 6.17 (Azure).

**Database.** PostgreSQL 17.11 (`postgres:17-alpine`) on the same host:

- default settings;
- data on the runner's disk, so every commit pays for a real fsync;
- client and server talk over loopback TCP.

**Method.** The service is wired as the API wires it, with UUIDv7 ids and
the system clock. Each operation is called 300 times in sequence on one
connection. Latency is the whole call, measured at the client, including
every round trip the service makes.

### Latency at 10,000 incidents of history

| Operation | p50 ms | p95 ms | p99 ms | max ms |
|---|---:|---:|---:|---:|
| Create an incident (opening event) | 11.39 | 12.25 | 14.40 | 17.18 |
| Link an update to an open incident | 8.84 | 9.39 | 10.91 | 16.91 |
| Refuse a duplicate event | 1.06 | 1.12 | 1.16 | 1.17 |
| Acknowledge (versioned, with an idempotency key) | 9.23 | 10.77 | 16.59 | 26.73 |
| Replay an idempotent request | 5.07 | 5.52 | 5.97 | 6.10 |
| Add a note | 8.99 | 10.47 | 13.07 | 22.68 |
| List the newest 50 incidents | 0.88 | 0.93 | 1.09 | 2.02 |
| List 50 acknowledged incidents | 1.44 | 1.53 | 2.18 | 2.85 |
| Read an incident's timeline | 1.15 | 1.27 | 1.42 | 1.70 |
| Claim and publish an outbox batch of up to 100 | 4.19 | 73.45 | 78.97 | 158.33 |

At 1,000 incidents of history, every p50 was lower than these, by up to
about 20%. The outbox figure is the exception (see below). The full tables for both sizes are in the run's job
summary.

### Concurrent incident creation in one tenant

| Writers | Incidents | Seconds | Incidents/s |
|---:|---:|---:|---:|
| 1 | 200 | 2.1 | 95 |
| 4 | 800 | 7.0 | 114 |
| 8 | 1,600 | 14.9 | 108 |

### What the numbers say

- **A write is about 9–11 ms, and a read about 1 ms.** Each write is one
  transaction holding several statements: the incident, the timeline, the
  audit trail and the outbox (ADR 0034). It ends in one fsync.
- **History matters little at this size.** Growing from 1,000 to 10,000
  incidents slowed writes by about 15–20%, and reads by at most a few
  tenths of a millisecond. The list
  and timeline queries use their indexes.
- **New incidents in one tenant top out near 100–115 per second, whatever
  the number of writers.** Each new incident takes the next number from
  that tenant's allocator row, under a row lock. The design wants this:
  numbers are gapless and per tenant
  ([ADR 0013](../architecture/decisions/0013-incident-identity.md)).
  Updates to existing incidents do not take that lock. A real attack wave
  opens incidents in the tens, not thousands per second, so the ceiling
  leaves wide headroom.
- **The outbox figure is bimodal.** A claim that finds a full batch
  publishes 100 rows, one acknowledgement each, which takes about 70 ms.
  A claim that finds nothing takes about 1 ms. The p50 is mostly the
  second case. No consumer exists in Phase 5 (FU-62).
- **Pool sizing.** One tenant gains nothing past about four concurrent
  writers. The default pool of 16 per process is therefore enough for a
  single node. Raise it only for many busy tenants, and only if
  `max_connections` has room.

### How far to trust them

- **Shared runners vary.** An earlier run of the same code on another
  runner ([run 37314862055](https://github.com/LogiXhare/wetechi-netmon/actions/runs/37314862055))
  was 30–40% faster on writes: about 5–7 ms at p50, with 149–186
  incidents/s. Read the numbers as an order of magnitude and as a
  baseline for regressions, not as a guarantee.
- **They are not a production figure.** A database on another host adds
  the network round trip to every statement. A tuned server, faster
  storage or `synchronous_commit` settings move the write numbers in
  either direction.
- The API's own HTTP, authentication and JSON costs are not included.

## PostgreSQL planning inputs (Phase 5B)

Added 2026-08-24 during Phase 5B PostgreSQL-persistence planning. Every
figure here is a **planning input**, not a benchmark result — the
performance-test plan in
[phase5b-postgresql-persistence-plan.md](../architecture/phase5b-postgresql-persistence-plan.md)
defines what will actually be measured at Milestone 5B-5.

- **Row-count growth is unbounded by design** for `incidents` (retained
  indefinitely while open, 24 months after close),
  `incident_detection_events` (one row per linked event), and
  `incident_timeline`/`incident_audit` (append-only, no cap in Phase 5B —
  `TIMELINE_ENTRY_LIMIT` remains an unenforced constant, see
  [FU-32](../development/follow-ups.md)). Real growth depends entirely on
  attack volume and tenant count, neither of which this planning pass
  has a production figure for.
- **Connection-pool sizing** (`max_size`, `create_timeout`,
  `wait_timeout` on `deadpool-postgres`,
  [ADR 0022](../architecture/decisions/0022-phase5b-connection-pool.md))
  has **no default asserted here** — sizing must be informed by the
  Milestone 5B-5 performance tests, not guessed at in planning.
- **Outbox lease duration**
  ([ADR 0033](../architecture/decisions/0033-phase5b-transactional-outbox-and-dead-letter.md))
  is similarly deferred to implementation time, informed by measured
  consumer processing latency once a consumer exists.
- **Index growth:** three target-specific partial unique indexes
  (`incidents_active_host`, `incidents_active_network`,
  `incidents_active_hostgroup`) are bounded by the *active* incident
  count, not the historical total — partial indexes only index rows
  matching their predicate, so this stays small relative to the
  full-table row count regardless of history depth.
- **RPO/RTO** technical design targets (15 minutes / 4 hours,
  [phase5b-postgresql-persistence-plan.md](../architecture/phase5b-postgresql-persistence-plan.md))
  inform backup frequency and restore-procedure scope, not a capacity
  figure directly.

## What This Document Does Not Claim

- No sustained-throughput benchmark has been run.
- No memory-under-load measurement has been taken.
- No latency-under-load (P50/P95/P99) figures exist yet.
- PostgreSQL latency and throughput for the incident database **are**
  measured, above. Index growth beyond 10,000 incidents, and latency
  through the HTTP API, are not.

The rest are Phase 9 deliverables, once a documented test machine and a
load-generation setup exist.
