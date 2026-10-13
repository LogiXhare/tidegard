# Architecture Decision Records (ADRs)

Status: Phase 5F. 0011–0017 are Accepted as of 2026-10-05. Where the
implementation differs from the plan, each one records how. 0018 stays
Proposed, because it holds selection criteria only.

## Purpose

An ADR captures one significant, hard-to-reverse architecture or
technology decision: the context, the options considered, the decision,
and its consequences. WetechiNetMon requires an ADR before implementation
begins for any decision flagged as an open "leaning" in
[docs/architecture-options.md](../../architecture-options.md) or
[docs/technology-options.md](../../technology-options.md).

## Process

1. Copy [0000-adr-template.md](0000-adr-template.md) to
   `NNNN-short-title.md`, where `NNNN` is the next sequential four-digit
   number.
2. Fill in every section — do not leave "Options Considered" as a single
   option; a decision with no real alternative considered is not an ADR.
3. Open a pull request. The ADR must be reviewed and merged **before** the
   code that depends on it, per `prompts/CLAUDE_MASTER_PROMPT.md` §30
   rule 20 ("Stop when a major architecture decision requires approval").
4. Once merged, an ADR is immutable history. If a decision changes later,
   write a new ADR that supersedes the old one — do not edit the original
   decision away.

## Known Upcoming ADRs

These are anticipated based on Phase 0 findings and are **not** decided
yet:

| Topic | Needed before | Reference |
|---|---|---|
| Mitigation Controller implementation language | Phase 7 | [architecture-options.md §3](../../architecture-options.md) |
| Recharts vs. Apache ECharts for the web UI | Phase 6 | [architecture-options.md §5](../../architecture-options.md) |
| NATS JetStream transport (deferred from Phase 3, see ADR 0004) | When Aggregator needs to scale independently | [0004](0004-collector-aggregator-event-transport.md) |

## Index

| # | Title | Status |
|---|---|---|
| [0001](0001-collector-implementation-language.md) | Telemetry Collector Implementation Language: Rust | Accepted |
| [0002](0002-prefix-lookup-data-structure.md) | Prefix Lookup Data Structure: Binary Trie | Accepted |
| [0003](0003-in-memory-aggregation-structure.md) | In-Memory Aggregation Structure: Bounded HashMap + Eviction | Accepted |
| [0004](0004-collector-aggregator-event-transport.md) | Collector-to-Aggregator Event Transport: In-Process Channel (NATS Deferred) | Accepted |
| [0005](0005-clickhouse-batching-and-retry.md) | ClickHouse Batching and Retry Behavior | Accepted |
| [0006](0006-contribution-licensing-dco-not-cla.md) | Contribution Licensing: DCO Sign-Off, No CLA | Accepted |
| [0007](0007-detection-engine-cannot-mitigate.md) | The Detection Engine Cannot Mitigate | Accepted |
| [0008](0008-detection-policy-configuration.md) | Detection Policy Configuration: JSON, Not YAML | Accepted |
| [0009](0009-detection-event-identity.md) | Detection Event Identity and Deduplication | Accepted |
| [0010](0010-detector-owns-its-windowed-counters.md) | The Detector Keeps Its Own Windowed Counters | Accepted |
| [0011](0011-incident-domain-boundary.md) | The Incident Domain Is Separate From the Detection Domain | Accepted |
| [0012](0012-incident-event-ingestion.md) | Detection-Event Ingestion: Transactional Outbox, At-Least-Once | Accepted (amended by 0031, 0035) |
| [0013](0013-incident-identity.md) | Incident Identity and the Human-Readable Incident Number | Accepted |
| [0014](0014-incident-state-machine.md) | The Incident State Machine Does Not Mirror the Detector's | Accepted |
| [0015](0015-incident-operational-storage.md) | PostgreSQL Is the Operational Source of Truth for Incidents | Accepted |
| [0016](0016-incident-concurrency-and-idempotency.md) | Optimistic Concurrency and Fingerprinted Idempotency | Accepted |
| [0017](0017-incident-community-enterprise-boundary.md) | The Community/Enterprise Seam Is an Extension Point, Not a Limitation | Accepted |
| [0018](0018-phase5-dependency-selection.md) | Phase 5 Dependency Selection: Criteria and Shortlist | Proposed |
| [0019](0019-phase5b-uuidv7-identity-generation.md) | Phase 5B UUIDv7 Identity Generation | Conditionally Accepted |
| [0020](0020-phase5b-postgresql-client.md) | Phase 5B PostgreSQL Client | Conditionally Accepted |
| [0021](0021-phase5b-async-runtime-boundary.md) | Phase 5B Async Runtime Boundary | Accepted |
| [0022](0022-phase5b-connection-pool.md) | Phase 5B Connection Pool | Conditionally Accepted |
| [0023](0023-phase5b-postgresql-tls.md) | Phase 5B PostgreSQL TLS | Conditionally Accepted |
| [0024](0024-phase5b-migration-framework.md) | Phase 5B Migration Framework | Conditionally Accepted |
| [0025](0025-phase5b-postgresql-version-support.md) | Phase 5B PostgreSQL Version Support Range | Accepted |
| [0026](0026-phase5b-transaction-isolation.md) | Phase 5B Transaction Isolation Model | Accepted |
| [0027](0027-phase5b-durable-record-identity.md) | Phase 5B Durable Record Identity (Timeline, Audit, Outbox) | Accepted |
| [0028](0028-phase5b-idempotency-fingerprint.md) | Phase 5B Durable Idempotency Fingerprint | Accepted |
| [0029](0029-phase5b-repository-and-unit-of-work-seam.md) | Phase 5B Repository and Unit-of-Work Seam Extraction | Accepted |
| [0030](0030-phase5b-aggregate-reconstitution.md) | Phase 5B Aggregate Reconstitution | Accepted |
| [0031](0031-phase5b-durable-time.md) | Phase 5B Durable Time Semantics | Accepted |
| [0032](0032-phase5b-tenant-isolation-and-rls-readiness.md) | Phase 5B Tenant Isolation and Row-Level Security Readiness | Accepted |
| [0033](0033-phase5b-transactional-outbox-and-dead-letter.md) | Phase 5B Transactional Outbox and Dead-Letter Design | Accepted |
| [0034](0034-phase5b-persistence-bridge-load-run-flush.md) | Phase 5B Persistence Bridge: Load, Run, Flush | Accepted |
| [0035](0035-phase5c-detection-event-inbox.md) | Phase 5C Detection-Event Inbox | Accepted |
| [0036](0036-phase5c-incident-manager-process.md) | Phase 5C Incident Manager Process | Accepted |
| [0037](0037-phase5d-http-framework-and-openapi.md) | Phase 5D HTTP Framework and OpenAPI | Accepted |
| [0038](0038-phase5d-api-boundary.md) | Phase 5D API Boundary: TLS, Identity, Authorization, Rate Limits, Errors | Accepted |
| [0039](0039-phase5d-manual-incidents.md) | Phase 5D Manual Incidents | Accepted |
| [0040](0040-phase5e-cli-client.md) | Phase 5E CLI Client | Accepted |
| [0041](0041-phase6a-grafana-dashboards-as-code.md) | Phase 6A Grafana Dashboards as Code | Accepted |
| [0042](0042-phase6b-traffic-read-api.md) | Phase 6B Traffic Read API | Accepted |
| [0043](0043-phase6c-browser-sessions.md) | Phase 6C Browser Sessions | Accepted |
| [0044](0044-phase6d-noc-ui.md) | Phase 6D NOC UI: Build, Serving and Supply Chain | Accepted |
| [0045](0045-phase6e-notification-delivery.md) | Phase 6E Notification Delivery | Accepted |
| [0046](0046-phase7a-mitigation-record.md) | Phase 7A The Mitigation Record | Accepted |
| [0047](0047-phase7b-safety-guard.md) | Phase 7B The Safety Guard | Accepted |
| [0048](0048-phase7c-gobgp-adapter.md) | Phase 7C The GoBGP Adapter | Accepted |
| [0049](0049-phase7d-mitigator-service.md) | Phase 7D The Mitigator Service | Accepted |
| [0050](0050-phase7e-mitigation-api-cli-ui.md) | Phase 7E Mitigations in the API, CLI and UI | Accepted |
| [0051](0051-phase7f-two-speaker-lab.md) | Phase 7F The Two-Speaker BGP Lab | Accepted |
| [0052](0052-phase9a-packaging.md) | Phase 9A Packaging | Accepted |
| [0053](0053-phase9a-collector-clickhouse-tls.md) | Phase 9A The Collector's ClickHouse Connection | Accepted |
| [0054](0054-phase9b-load-and-soak.md) | Phase 9B Load and Soak Tests | Accepted |
| [0055](0055-phase9c-backup-upgrade-rollback.md) | Phase 9C Backup, Restore, Upgrade and Rollback | Accepted |
| [0056](0056-phase9d-collector-input-bounds.md) | Phase 9D Bounds on What the Collector Remembers | Accepted |
