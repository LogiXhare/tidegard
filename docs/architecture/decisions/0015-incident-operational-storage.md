# 0015. PostgreSQL Is the Operational Source of Truth for Incidents

Status: **Accepted** — BQ-7 resolved 2026-08-22; the crates were selected
in ADRs 0019–0024 and passed the Phase 5B-1 probe on 2026-09-03.
Date: 2026-08-22
Deciders: Repository owner — decided 2026-08-22

## Context

Incidents are mutable, transactional, and relational: a state change must
atomically update a row, append a timeline entry, append an audit record,
and enqueue an outbox row. Losing any one of those while keeping the
others produces a record that is wrong in a way nobody can detect later.

The repository already runs ClickHouse for
`wetechinetmon_detection_events` and the Phase 3 traffic tables, so
"reuse what we have" is the obvious first question. The
[master prompt](https://github.com/badshashorif/wetechi-netmon/blob/main/prompts/CLAUDE_MASTER_PROMPT.md) names
PostgreSQL for Phase 5, and this ADR should either confirm that with
reasons or dispute it — not simply defer to it.

## Options Considered

### Option A — ClickHouse for everything

- Pros: no new store, no new dependency, one backup story.
- Cons: ClickHouse is an analytical column store. `ALTER TABLE ... UPDATE`
  is an asynchronous mutation, not a transactional update. There are no
  multi-table transactions, no foreign keys, and no enforced unique
  constraints — so the partial unique index that makes "two open
  incidents for one correlation key" impossible cannot exist. Optimistic
  concurrency would have to be emulated in application code, in a race.
  Every property Phase 5 needs would be hand-built and unreliable.

### Option B — PostgreSQL for operational state, ClickHouse for analytics

- Pros: real transactions across tables; foreign keys; partial unique
  indexes; `SELECT ... FOR UPDATE`; mature migration tooling; JSONB for
  bounded semi-structured fields; Row-Level Security available for
  Phase 8; the outbox pattern is natural. ClickHouse keeps doing what it
  is good at.
- Cons: a second datastore to deploy, secure, back up, and monitor; new
  dependencies; two backup and restore procedures.

### Option C — SQLite

- Pros: no server; trivial single-node deployment; real transactions.
- Cons: single-writer concurrency is a poor fit for a correlator plus an
  API plus operators; no `LISTEN`/`NOTIFY`; no RLS; and it would be
  replaced before multi-node, making it throwaway work.

### Option D — Embedded key-value store

- Pros: no server; fast.
- Cons: every relational property — constraints, joins, indexes,
  transactions across "tables" — hand-built. Reinventing a database
  badly.

## Decision

**Option B.** PostgreSQL is the operational source of truth for
incidents, timeline, notes, assignments, audit, idempotency, outbox, and
dead-letter records. ClickHouse remains authoritative for detection
events and traffic, and additionally receives **immutable incident
analytics events** through the outbox.

**There is exactly one authority for any given fact.** ClickHouse never
holds mutable incident state, and PostgreSQL never becomes an analytics
store. A dual-authoritative design where both hold incident state and
disagree is the specific outcome this decision exists to prevent.

Minimum version: **PostgreSQL 14**, for `JSONB` improvements and mature
partial-index behaviour. RLS is available from 9.5 and is designed for
but not enabled in Phase 5.

Not decided here: the Rust driver (`sqlx` vs `tokio-postgres` vs `diesel`)
and the migration tool. Those belong with the implementation and depend
on **BQ-7**.

## Consequences

**Easier.** Atomic multi-table commits, which is the property the entire
persistence design rests on. Database-enforced invariants instead of
application-enforced conventions. A migration story that already exists.
Phase 8 tenancy has RLS available without a schema change.

**Harder.** A second datastore: deployment, credentials, connection
pooling, backup, restore, monitoring, and a documented upgrade path.
Single-node installation gains a prerequisite. Two restore procedures
that must both be *tested*, per NFR-2 — an untested restore is not a
backup.

**Forecloses.** Little. PostgreSQL is a common baseline. If incident
volume ever outgrew it — which would be surprising, since incidents are
thousands per day, not millions per second — partitioning and read
replicas come long before any rewrite.

**Security.** New credentials to manage, from the environment and never
committed. A new network surface to firewall. In exchange: real
constraints, real transactions, and a path to database-enforced tenant
isolation instead of application-enforced filtering.

**License.** PostgreSQL is under the PostgreSQL Licence, permissive and
compatible with the Apache-2.0 core. The Rust driver must be added to
[dependency-license-matrix.md](../../dependency-license-matrix.md) before
use. `sqlx` and `tokio-postgres` are both MIT/Apache-2.0.

**Operational.** Installation documentation, backup and restore runbooks,
and capacity guidance all need writing before Phase 5 ships — tracked in
the [acceptance criteria](../../development/phase5-acceptance-criteria.md).

## Owner Decision — 2026-08-22

**BQ-7 approved at the architectural level.** Phase 5 may introduce
PostgreSQL and HTTP dependencies. What was approved, precisely:

- PostgreSQL as the Phase 5 operational source of truth.
- The **capability** to add a Rust PostgreSQL client and a Rust HTTP
  server framework.

**This is approval of capability, not of any crate.** No dependency is
added by this decision, and none may be added on the strength of it
alone. Before any crate enters `Cargo.toml`, implementation must:

1. Record a dependency-selection ADR comparing real candidates —
   see [ADR 0018](0018-phase5-dependency-selection.md) for the criteria
   and the shortlist.
2. **Verify actual published package metadata** — version, licence,
   maintenance, advisories — rather than relying on the values assumed in
   these planning documents. Several figures quoted here were written
   from knowledge, not from a registry query, and must be re-checked.
3. Add a row to
   [dependency-license-matrix.md](../../dependency-license-matrix.md),
   and update `NOTICE` where the licence requires it.
4. Run security and compatibility validation, including a build on both
   Windows and Linux.

**Security impact.** A database credential and a listening HTTP socket
are both new attack surface, and the transitive dependency count will
rise from Phase 4's deliberately small closure. That is the cost of the
capability and is accepted knowingly. **Operational impact:** a second
datastore to deploy, secure, back up, and *test the restore of*.
**Licence impact:** every added crate needs matrix and NOTICE review
before use.

## Follow-Up

- [x] **BQ-7** — resolved 2026-08-22: approved architecturally, crate
      selection deferred.
- [x] **ADR 0018** — select the PostgreSQL driver and HTTP framework
      before Milestone 5B ([ADR 0020](0020-phase5b-postgresql-client.md),
      [ADR 0037](0037-phase5d-http-framework-and-openapi.md)).
- [x] Add rows to the dependency licence matrix.
- [x] Write and **test** backup and restore procedures (NFR-2):
      [backup-and-restore.md](../../operations/backup-and-restore.md). CI
      restores a real dump on every pull request.
- [ ] Evaluate RLS with Phase 8 (**FU-21**).
