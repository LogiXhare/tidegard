# Phase 5B: PostgreSQL Persistence — Plan

Status: **Planning only.** Stage A (research) and Stage B (this
document set) complete 2026-08-24. No implementation has started. Part of
the [Phase 5 plan](phase5-incident-management-plan.md).

This document is the entry point for Phase 5B. Schema, active-incident
invariant, transaction boundaries, retention, and tenant isolation live
in [incident-persistence.md](incident-persistence.md), which this
planning pass updated in place. Individual decisions live in the ADR
series [0019](decisions/0019-phase5b-uuidv7-identity-generation.md)–[0033](decisions/0033-phase5b-transactional-outbox-and-dead-letter.md).
This document covers what does not have another natural home: the
architecture correction Phase 5B must make, the dependency-selection
summary, the milestone sequence, the test-database and integration-test
strategy, backup and restore, and the Community/Enterprise boundary.

## The architecture correction Phase 5B starts from

`phase5-implementation-plan.md` previously stated Milestone 5A delivered
"repository *traits* with in-memory implementations." Verified against
actual source (2026-08-24), it did not: `tidegard-incident` exposes
three narrow traits (`IncidentGenerator`, `NumberAllocator`,
`PermissionResolver`); `IncidentUnitOfWork` is a 2,713-line concrete
struct with 72 direct accesses to its own storage fields, and `Incident`
cannot be constructed or fully read from outside the crate. **Phase 5B
is a refactor-and-implement milestone, not an implement-only one.** Full
finding and the extraction plan:
[ADR 0029](decisions/0029-phase5b-repository-and-unit-of-work-seam.md)
and [ADR 0030](decisions/0030-phase5b-aggregate-reconstitution.md).

A second correction, equally load-bearing: `Timestamp`'s reopen-window
and suppression-expiry comparisons use a process-local `Instant`, which
cannot be persisted or restored. Naively porting 5A's comparison logic
to PostgreSQL would silently break BQ-9's reopen window after any
process restart. See [ADR 0031](decisions/0031-phase5b-durable-time.md).

## Dependency selection — summary

Full comparative reasoning lives in each decision's own ADR; the
verified evidence (version, license, advisory status, upstream activity)
lives in [dependency-license-matrix.md](../dependency-license-matrix.md)
rows 32–37. Summary:

| Decision | Selected | Status | ADR |
|---|---|---|---|
| Incident identity generation | `uuid` 1.25.0, `v7` feature only | Conditionally Accepted | [0019](decisions/0019-phase5b-uuidv7-identity-generation.md) |
| PostgreSQL client | `tokio-postgres` 0.7.18 | Conditionally Accepted | [0020](decisions/0020-phase5b-postgresql-client.md) |
| Async runtime | Tokio (already a workspace dependency), adapters only | Accepted | [0021](decisions/0021-phase5b-async-runtime-boundary.md) |
| Connection pool | `deadpool-postgres` 0.14.1 | Conditionally Accepted | [0022](decisions/0022-phase5b-connection-pool.md) |
| TLS | `rustls` 0.23.43 + `tokio-postgres-rustls` 0.14.0 | Conditionally Accepted | [0023](decisions/0023-phase5b-postgresql-tls.md) |
| Migrations | `refinery` 0.9.2, now 0.10.0 | Conditionally Accepted | [0024](decisions/0024-phase5b-migration-framework.md) |

**Zero of these six crates has been added to any `Cargo.toml`.** Every
"Conditionally Accepted" status is gated on the **Phase 5B-1 dependency
probe** — measured `cargo tree`, `cargo audit`, `unsafe` inventory, and a
Windows-GNU + Linux build for the actual selected feature combination,
per [ADR 0018](decisions/0018-phase5-dependency-selection.md)'s honesty
constraint. `sqlx` 0.9.0 remains the documented alternative to the
client selection specifically (ADR 0020); it is not rejected on license,
advisory, or maintenance grounds.

Architecture-only decisions needing no new dependency: transaction
isolation ([0026](decisions/0026-phase5b-transaction-isolation.md)),
durable record identity via native `BIGINT IDENTITY`
([0027](decisions/0027-phase5b-durable-record-identity.md)), the
idempotency fingerprint staying a direct byte comparison rather than a
new hashing crate ([0028](decisions/0028-phase5b-idempotency-fingerprint.md)),
the repository seam and aggregate reconstitution
([0029](decisions/0029-phase5b-repository-and-unit-of-work-seam.md),
[0030](decisions/0030-phase5b-aggregate-reconstitution.md)), durable
time ([0031](decisions/0031-phase5b-durable-time.md)), tenant isolation
and RLS readiness ([0032](decisions/0032-phase5b-tenant-isolation-and-rls-readiness.md)),
and the transactional outbox's claim mechanics
([0033](decisions/0033-phase5b-transactional-outbox-and-dead-letter.md)).

## PostgreSQL version support

Minimum **15**, recommended production **17**, tested **15/16/17/18**.
PostgreSQL 14 reaches end-of-life 2026-11-12 and is excluded. Full
rationale: [ADR 0025](decisions/0025-phase5b-postgresql-version-support.md).

## RPO / RTO — technical design targets

**RPO: 15 minutes. RTO: 4 hours.** These are technical design targets
this plan is built to accommodate — informing backup frequency and
restore-procedure scope below — and explicitly **not** an SLA
commitment, a legal requirement, or a contractual guarantee to any
customer. Formal commitments, if any are ever made, are a separate,
explicit business decision outside this planning pass's scope.

## Milestones

Full entry gates and per-milestone detail:
[phase5-implementation-plan.md](../development/phase5-implementation-plan.md)'s
5B section. Summary:

| Milestone | Scope | Dependencies added |
|---|---|---|
| **5B-0** | Repository/UoW seam extraction, aggregate snapshot + `reconstitute`, durable-time API shape, FU-38 guard hardening, in-memory adapter migrated to the new seam, regression tests | **None** |
| **5B-1** | Dependency probe: measured `cargo tree`, `cargo audit`, `unsafe` inventory, Windows-GNU + Linux build for the six conditionally-accepted crates; license matrix and `NOTICE` updated | Adds the six crates *if* the probe passes |
| **5B-2** | Schema and migrations: extensions, `incidents`, detection links, timeline, audit, notes/tags/assignments, `incident_policy_references`, `incident_number_allocators`, idempotency, outbox/dead-letter, constraints/indexes, RLS-ready roles | None (SQL only) |
| **5B-3** | Repository implementations against the 5B-0 seam, transactional unit-of-work, optimistic concurrency, durable identity/time wiring | None |
| **5B-4** | Outbox claim/lease/retry/dead-letter implementation, retention/cleanup jobs | None |
| **5B-5** | Integration tests (real PostgreSQL, all four supported versions), failure-injection tests per the isolation matrix, performance-test scaffolding | Adds the test-database tooling selected below |

## Test database strategy

**Docker Compose PostgreSQL, one ephemeral database per test suite,
migrations applied from zero.** Rejected as the Phase 5B default:
`testcontainers` — a capable tool, but ADR 0018's own discipline requires
it be selected on measured evidence, not adopted for convenience inside
this planning pass; a shared or production database — never, under any
configuration. Requirements: isolated credentials (never the production
role), deterministic setup, safe under concurrent test runs, working on
both Windows and Linux, and startable under GitHub Actions once
[FU-1](../development/follow-ups.md)'s billing block clears.

## Required integration tests (Phase 5B-5)

Migration-from-empty and migration-idempotency; repository CRUD per
table; tenant isolation and cross-tenant concealment (404-not-403,
extending the existing suite [ADR 0032](decisions/0032-phase5b-tenant-isolation-and-rls-readiness.md)
requires); optimistic-version conflict; idempotency replay and conflict;
duplicate detection-event ingestion; the three active-incident partial
unique indexes, individually, under concurrent-create races; concurrent
reopen races; timeline/audit append; outbox append and atomic rollback
on a forced audit or outbox failure; statement timeout; connection loss;
serialization and deadlock retry (per the [isolation matrix](decisions/0026-phase5b-transaction-isolation.md));
pool exhaustion; service-restart recovery; stale outbox lease reclaim;
dead-letter transition; retention cleanup; the `incident_policy_references`
65th-distinct-policy behavior (never silently omitted); UUIDv7 round
trip; the durable-time clock-skew contract
([ADR 0031](decisions/0031-phase5b-durable-time.md)); Windows and Linux
builds of the full suite.

## Performance-test plan

Benchmarks planned, **not executed by this planning pass**, for:
incident-creation transaction latency, detection-link transaction
latency, correlation lookup, reopen-candidate lookup, optimistic update,
timeline/audit append, idempotency lookup, outbox claim, a
tenant-isolated filtered query, and the retention-cleanup job — each
across a range of active-incident counts, historical-incident counts,
detection-links-per-incident, tenant counts, and concurrent-worker
counts. No number is published before it is measured, per this
project's existing rule (see
[capacity-planning.md](../operations/capacity-planning.md)).

## Backup and restore

Logical (`pg_dump`) backups plus continuous WAL archiving for
point-in-time recovery, sized against the 15-minute RPO target above. A
backup is taken before every migration. **Restore is tested, not
assumed** — an untested backup is not a backup, it is an unverified
file. Tenant-scoped export/restore is **not** designed in Phase 5B
(§ [ADR 0032](decisions/0032-phase5b-tenant-isolation-and-rls-readiness.md));
a full-database restore is the Phase 5B mechanism. Encryption at rest
and in transit for backup artifacts follows the same TLS/secrets
posture as the live connection ([ADR 0023](decisions/0023-phase5b-postgresql-tls.md)).
Outbox rows in flight at backup time are recovered from `pending` on
restore, consistent with the existing service-restart failure behavior
in [incident-persistence.md](incident-persistence.md).

## Community and Enterprise boundary

Everything in this plan is **Community**: PostgreSQL operational
persistence, transaction safety, tenant-aware schema, optimistic
concurrency, idempotency, timeline, audit, detection links, outbox
persistence, migration tooling, backup guidance, single-node deployment,
and every security/durability control above. None of these is reserved
for a future Enterprise edition — ordinary correctness and data
integrity are never license-gated, consistent with
[ADR 0017](decisions/0017-incident-community-enterprise-boundary.md).
Potential Enterprise extensions, not designed here: HA topology
automation, compliance-grade retention, multi-region replication,
customer-managed encryption keys, managed backup services, and advanced
SLA reporting. No license check or disabled stub is introduced by this
plan.

## Risks

- **Regression risk in the seam extraction (5B-0):** it touches code two
  adversarial reviews already certified. Mitigated by keeping 5B-0
  dependency-free and SQL-free, so its own correctness is provable by
  the existing 531 tests before any persistence code exists.
- **Durable-time is a real semantic change**, not a mechanical port —
  see [ADR 0031](decisions/0031-phase5b-durable-time.md). Must be
  implemented and tested as its own unit of work, not folded silently
  into schema migration.
- **`sqlx` 0.9.0's youth** (three months old at this decision) if
  [ADR 0020](decisions/0020-phase5b-postgresql-client.md) is later
  revisited in its favor.
- **CI remains blind** ([FU-1](../development/follow-ups.md)) — every
  validation in this planning pass and in 5B-1 through 5B-5 must be run
  and reported locally until the billing block clears.

## Owner decisions still required before implementation

1. Phase 5B-1 probe results — implementation-approval gate for the six
   conditionally-accepted crates.
2. The exact sync/async bridging mechanism at 5B-3
   ([ADR 0021](decisions/0021-phase5b-async-runtime-boundary.md)'s
   follow-up).
3. Concrete pool-sizing and outbox lease-duration defaults, once informed
   by the (not-yet-run) performance tests.

## Community and this plan's own limits

This plan does not implement Rust code, does not add a dependency, does
not create a migration file, and does not start or connect to any
database. It is the reviewable contract Phase 5B implementation work is
measured against.
