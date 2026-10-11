# 0024. Phase 5B Migration Framework

Status: **Conditionally Accepted** — pending the Phase 5B-1 dependency
probe
Date: 2026-08-24
Deciders: Repository owner

## Context

[ADR 0020](0020-phase5b-postgresql-client.md) selects `tokio-postgres`,
which has no built-in migration system (unlike `sqlx`, one of the costs
weighed in that decision). A separate migration tool is required.

## Verified evidence (2026-08-24)

`refinery` 0.9.2, released 2026-06-10, MIT licensed, no advisory
directory in `rustsec/advisory-db`, repository `rust-db/refinery` pushed
2026-08-14, 1,697 stars, **4 open issues** — the smallest open-issue
count of any candidate researched in this planning pass, weakly
suggestive of a smaller, more stable surface area rather than neglect
(the release cadence — three releases in under a year — argues against
neglect independently).

## Options Considered

### Option A — `refinery`

- Pros: forward-only, checksummed migrations; works with
  `tokio-postgres` directly without requiring `sqlx`; embeddable
  (migrations compiled into the binary) or file-based; small dependency
  surface; MIT licensed.
- Cons: less ecosystem mindshare than `sqlx`'s bundled migrator; no
  compile-time query checking (not its job).

### Option B — `sqlx` migrations

- Pros: would be "free" if `sqlx` were the client.
- Cons: **not applicable** — this ADR is downstream of ADR 0020
  selecting `tokio-postgres`; adopting `sqlx` migrations alone while
  using `tokio-postgres` as the client means depending on `sqlx`'s
  entire crate for one subsystem, defeating the closure-size reasoning
  in ADR 0020.

### Option C — Diesel migrations

- Pros: mature, well-tested.
- Cons: same objection as Diesel-the-ORM in ADR 0020 — pulls in an
  entire different programming model for one subsystem.

### Option D — standalone SQL files managed by hand-rolled application tooling

- Pros: zero dependency.
- Cons: reimplements checksums, ordering, and a schema-version table —
  exactly the "reimplementing transactions in application code" failure
  mode [incident-persistence.md](../incident-persistence.md) already
  warns against for a different subsystem. Rejected — this is
  well-trodden ground with a small, evaluable dependency available.

### Rejected outright — ad hoc application-startup DDL

Running `CREATE TABLE IF NOT EXISTS` at process startup with no
versioning, no checksums, and no ordering guarantee. Explicitly rejected
per this task's own instruction; not a real candidate.

## Decision

**Option A, conditionally: `refinery` 0.9.2.**

**Update 2026-10-12:** upgraded to 0.10.0 by Dependabot (#84) after Phase 5 closed. The release replaces `async-trait` with native async traits, sorts embedded migrations deterministically, and raises the MSRV to 1.92. It changes no migration format or checksum: the migration smoke test and the backup and restore drill passed on PostgreSQL 15 to 18 with V1–V17 unchanged. The licence is still MIT.

Binding requirements regardless of implementation timing:

- **Forward-only.** No down-migration is treated as safe by default.
  Rollback is roll-forward (a corrective migration) or restore-from-
  backup ([incident-persistence.md](../incident-persistence.md)'s
  retention table plus the backup/restore plan), never an assumed
  automatic reverse of a destructive change.
- **Checksummed.** A migration file's content is hashed; an already-
  applied migration whose file changed on disk must fail loudly, not
  silently re-apply.
- **Transactional per migration**, where the migration's statements
  allow it (PostgreSQL DDL is transactional; a few operations —
  `CREATE INDEX CONCURRENTLY`, for one — are not, and must be
  identified and handled outside a transaction deliberately, not by
  accident).
- **Locking.** Concurrent application startup (more than one instance
  migrating simultaneously) must not race; `refinery`'s
  migration-runner locking (or an explicit PostgreSQL advisory lock
  wrapping it) prevents two instances from applying the same migration
  twice.
- **Numbered, reviewable steps** — see the migration sequence in the
  main persistence plan
  ([phase5b-postgresql-persistence-plan.md](../phase5b-postgresql-persistence-plan.md)).
- **No actual migration file is created by this planning task.**

## Consequences

**Easier.** A migration system matched to the selected client, with a
small dependency footprint consistent with this workspace's posture.

**Harder.** Building an online-index-creation story (for a future large
table) needs deliberate handling outside `refinery`'s default
transactional-per-migration behavior.

**Forecloses.** Nothing structural — the migration files themselves are
plain SQL, portable to a different runner later if needed.

**Security.** Checksums prevent an already-applied migration file from
being silently altered and re-trusted.

**License.** MIT, compatible with the Apache-2.0 core.

## Follow-Up

- [ ] Run the Phase 5B-1 probe for `refinery`.
- [ ] Define the concrete migration numbering/naming convention at
      Phase 5B-2, before the first migration file is written.
- [ ] Decide embedded-in-binary vs. file-based migrations at
      Phase 5B-2, weighing deployment simplicity against operator
      visibility into pending schema changes.
