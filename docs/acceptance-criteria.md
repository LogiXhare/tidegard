# Acceptance Criteria

Status: Phase 0 draft
Last updated: 2026-08-20

## Phase 0 Acceptance Criteria (this phase)

Phase 0 is complete when:

- [x] `prompts/CLAUDE_MASTER_PROMPT.md` has been read in full.
- [x] All 16 documents listed in master prompt §31 exist under `docs/`.
- [x] No production code (no `crates/`, `apps/`, application source) has
      been written.
- [x] Clean-room boundary is documented and unambiguous.
- [x] Product naming/branding decision is documented and does not use any
      proprietary vendor's name, trademark, CLI, or terminology.
- [x] Functional and non-functional requirements are captured at a
      traceable level (FR-/NFR- IDs) for later phases to reference.
- [x] At least one dependency-license matrix entry raises verification
      status honestly (`REQUIRES VERIFICATION`), with no fabricated
      license claims.
- [x] Risk register and blocking questions exist and are non-empty where
      genuine risk/ambiguity exists.
- [x] A repository (`git init`) exists locally with `main` as the default
      branch, ready for a Phase 0 commit.
- [ ] Phase 0 has been reviewed by WeTechi Solutions before Phase 1 begins
      (external gate — cannot be self-certified by the agent).

## Forward-Looking Acceptance Criteria (per future phase, for planning only)

These are stated now so later phases can be scoped against them; they are
**not** being evaluated in Phase 0.

### Phase 1 — Repository foundation

- Monorepo skeleton matches master prompt §22 layout.
- CI validates formatting/linting on an empty or skeleton codebase.
- LICENSE decision is made and documented (not left as TBD).
- ADR template exists and is used for at least the collector-language and
  event-transport decisions once Phase 1 lands.

### Phase 2 — IPFIX collector MVP (complete 2026-08-20)

- [x] IPFIX parser has unit and property-based (`proptest`) tests
      asserting no panic on arbitrary/malformed byte input (34 tests,
      3 properties). **Partial**: true `cargo-fuzz`/libFuzzer coverage
      requires a nightly toolchain not installed here — tracked as a
      follow-up in [risk-register.md](risk-register.md) R4, not silently
      dropped.
- [x] Template cache correctly survives exporter restart — tested via
      `exporter::tests::a_regression_is_detected_as_a_restart_and_clears_templates`
      and end-to-end via a real running collector process.
- [x] Prometheus metrics for parser failures/unknown templates are
      observable end to end — verified against a real running
      `tidegard-collector` process scraped via `curl`, not just unit
      tests. **Partial**: `udp_receive_buffer_errors_total` from the
      master-prompt metric list is not implemented (documented limitation
      in `crates/collector/README.md`, platform-specific socket-drop
      counters deferred).
- [x] Replay tool (`tools/flow-replay`) drives the collector from a
      synthetic fixture — verified end-to-end (template + 5 data records
      sent, received, decoded, and reflected in `/metrics`).

### Phase 3 — Aggregation and Direction Classification (complete 2026-08-20)

Full detail in the Phase 3 completion report (commit message / session
summary). Status against the acceptance checklist:

#### Functional

- [x] Normalized flow record (`tidegard_common::NormalizedFlow`) —
      protocol-independent, IPFIX today, reusable by future NetFlow/sFlow
      collectors.
- [x] Sampling correction with the documented priority order
      (record-level → options-template → exporter-configured → global
      default → 1), zero-rate rejection, overflow rejection,
      double-correction prevented by construction.
- [x] IPv4 prefix matching (binary trie, ADR 0002).
- [x] IPv6 prefix matching (same trie, 128-bit).
- [x] Incoming/outgoing/internal/other classification — implemented and
      tested for both address families.
- [x] Per-host counters.
- [x] Per-network counters (configurable prefix lengths).
- [x] /24 counters (always-on IPv4 dimension).
- [x] Hostgroup counters.
- [x] ASN counters when available (`source_asn`/`destination_asn`
      populated from IPFIX IE 16/17 when present).
- [x] Protocol counters (TCP/UDP/ICMP/ICMPv6/Other).
- [x] ClickHouse output — schema, batch writer, retry, migrations
      implemented and unit-tested; **not verified against a live server**
      (none available in this environment) — see
      [integrations/clickhouse.md](integrations/clickhouse.md).
- [x] Prometheus platform metrics — 14 new Phase 3 metrics, verified
      end-to-end against a real running collector process.

#### Safety

- [x] Memory bounded (per-dimension `BoundedMap` with configurable caps).
- [x] Maximum tracked hosts configurable (`TIDEGARD_COLLECTOR_MAX_HOSTS`).
- [x] Maximum tracked networks configurable (`..._MAX_NETWORKS`).
- [x] Expiration implemented (inactivity TTL, swept every 30s).
- [x] High-cardinality labels avoided in Prometheus (only bounded label
      sets — Set kind, Direction; per-entity detail goes to ClickHouse,
      not Prometheus labels).
- [x] Malformed normalized flows rejected (`FlowError::Empty`,
      `NormalizeError::MissingAddresses`).
- [x] Integer overflow handled (`SamplingOverflow`, saturating counter
      arithmetic in `TrafficCounters`).
- [x] Sample rate zero rejected (falls through the priority chain,
      counted via `sampling_errors_total`).
- [x] Duplicate flows are documented (not deduplicated — a known,
      explicit limitation in `docs/architecture/aggregation.md`, not
      silently absent).
- [x] Missing fields are handled safely (optional fields default to
      `None`; only missing addresses reject a record).

#### Tests

(All executed; see full counts in the Phase 3 completion report.)

- [x] Unit tests (all new crates).
- [x] Direction classification tests (IPv4 + IPv6, all four directions +
      Unknown).
- [x] Prefix-overlap tests (broader-ancestor and narrower-descendant
      cases).
- [x] IPv6 tests (trie, registry, classification, normalization, replay
      round-trip).
- [x] Sampling correction tests (all five priority tiers, zero-rate
      skip, overflow).
- [x] Overflow tests (sampling correction, counter saturation).
- [x] Expiration tests (`BoundedMap`, `Aggregator`).
- [x] Aggregation correctness tests (per-dimension, two-sided accounting).
- [x] Hostgroup tests.
- [x] ASN tests (present/absent).
- [x] ClickHouse serialization/schema tests — unit-level (13 tests, no
      live server).
- [x] ClickHouse retry-behavior tests (backoff, overflow, permanent
      drop) — unit-level, no live server.
- [ ] ClickHouse *integration* test against a real server — test file
      exists (`crates/storage/tests/clickhouse_integration.rs`) and
      skips cleanly (not fabricated) when `CLICKHOUSE_TEST_URL` is
      unset, which it was throughout this environment.
- [x] End-to-end UDP-to-aggregation test — both as a Rust integration-
      style unit test (`crates/collector/src/lib.rs`
      `a_full_ipfix_flow_is_normalized_classified_and_aggregated`) and as
      a real running-process smoke test with `tools/flow-replay`.
- [x] Arbitrary input safety properties (`proptest`) where applicable —
      classifier trie insertion, existing IPFIX decoder properties.

#### Performance

- [x] Target defined: sustain ≥100,000 normalized flow records/sec on a
      documented test machine (see
      [operations/capacity-planning.md](operations/capacity-planning.md)).
- [ ] **No benchmark executed.** Per explicit instruction, no performance
      claim is made — this is a target for Phase 9, not a Phase 3 result.

### Phase 4 — Detection engine

- Threshold detection has passing hysteresis and cooldown tests.
- Dry-run and alert-only modes never trigger a mitigation action, verified
  by test.

### Phase 5 — Incident management

- Full incident state-machine transition table is tested, including
  invalid-transition rejection.
- Audit trail entries are created for every state transition.

### Phase 6 — Dashboards and notifications

- Grafana dashboard JSON validates in CI.
- Each notification channel has an integration test using a mock/sandbox
  endpoint, not a real external send in CI.

### Phase 7 — BGP mitigation lab

- All mitigation actions default to dry-run in a fresh install.
- Unauthorized-prefix test suite proves the controller refuses to announce
  outside the allowlist.
- Production BGP remains disabled by default, verified by a test asserting
  the default configuration value.

### Phase 8 — Multi-tenancy and RBAC

- Multi-tenant isolation tests prove tenant A cannot read tenant B's data
  via API, DB query, or export.
- RBAC tests cover every role listed in FR-12.2 for at least one
  allow/deny case each.

### Phase 9 — Production hardening

- Load/soak test results are real, executed, and reported (not
  estimated).
- Backup/restore is demonstrated round-trip, not just documented.
- Security review findings are triaged with no open Critical/High items
  at release.

### Phase 10 — v1.0.0 release

- Release includes changelog, release notes, upgrade guide, rollback
  guide, checksums, SBOM, signed artifacts, migration notes, known issues,
  and a real test summary.
- Production checklist and security checklist are both signed off.

## General Rule

No phase may claim a criterion is met without the actual command/test
execution and result backing it, per master prompt §30 rules 9–13.
