# Incident PostgreSQL Adapter

**Status:** Milestone 5B-3(b), in progress. This crate carries:

- the forward-only, checksummed PostgreSQL schema for the incident domain
  (`migrations/`, 5B-2), with a migration smoke test and a compose file
  for an ephemeral local/CI PostgreSQL instance
- `src/staging.rs`, the in-memory `IncidentStore` that one unit-of-work
  call runs against under
  [ADR 0034](../../docs/architecture/decisions/0034-phase5b-persistence-bridge-load-run-flush.md)'s
  load–run–flush. It records what the call changed and refuses to hand
  back changes if the call looked up a key the load step never fetched.
- `src/row.rs`, the pure mapping between an incident and its `incidents`,
  notes, tags and policy-reference rows, and `src/sql.rs`, which inserts,
  version-guard updates and loads one incident. `tests/incident_row_mapping.rs`
  checks the mapping without a database; `tests/incident_row_round_trip.rs`
  runs the SQL against PostgreSQL.

- `src/load.rs`, `src/flush.rs` and `src/service.rs`: the rest of the
  load–run–flush. `IncidentPersistence` runs each unit-of-work entry
  point as one Read Committed transaction: load the working set under
  the ADR's locks, run the domain call over the staging store, flush the
  incidents and their detection-event links, timeline, audit, outbox and
  idempotency rows (`src/history.rs` maps those), then commit.
  `tests/service_round_trip.rs` covers it on PostgreSQL, including
  FU-44's gate that a connection killed mid-flush commits nothing.

- `src/retry.rs`: which failures are transient under ADR 0026, and the
  backoff. The service reruns a call from a fresh load on one, at most
  3 attempts. `tests/retry_and_races.rs` checks the classification
  against real PostgreSQL errors and that two concurrent first
  detections for one target open one incident.

- `src/outbox.rs` and `src/retention.rs` (5B-4). `OutboxConsumer` claims
  outbox rows under ADR 0033's lease-aware `FOR UPDATE SKIP LOCKED`
  query, marks each one published or failed, retries with backoff, and
  dead-letters at the retry limit. `run_retention` purges expired
  idempotency records, published outbox rows after 7 days, reviewed
  dead-letter rows after 90 days, and closed incidents after 24 months.
  It never purges audit or unreviewed dead-letter rows.
  `tests/outbox_and_retention.rs` covers both.
- `src/platform.rs` (5B-5). The outbox consumer, its stats and retention
  are the only cross-tenant paths, and each takes a `PlatformAuthority`.
  Only a context holding `PlatformIncidentAdmin` can produce one
  (ADR 0032, item 7). Every other function is scoped to a tenant.
- `src/fault.rs` (5B-5). Test-only failure injection behind the
  `fault-injection` feature, which only this crate's own dev-dependency
  turns on. `tests/failure_injection.rs` fails a creating ingest at each of
  the eight flush points and proves nothing committed, fails a command the
  same way, and checks that a transient failure is rerun and commits once.
- `tests/outbox_concurrency.rs` (5B-5) runs ADR 0033's outbox concurrency
  and crash list on separate connections. It covers simultaneous
  claimers, a rolled-back claim, and a worker crashing before and after
  its claim commits. It also checks that lease and backoff are measured
  on `transaction_timestamp()`, that `attempts` counts once when two
  holders race, and that the retry limit dead-letters on the same failure
  whatever claims happen in between.
- Decision time (ADR 0031). Each `IncidentPersistence` attempt reads
  PostgreSQL's `transaction_timestamp()` and gives it to the domain as
  wall time. The injected clock supplies only monotonic time, unless a
  test opts into `with_injected_decision_time()`. `tests/clock_skew.rs`
  checks that a recurrence against a future `resolved_at` returns
  `ClockSkew`, with no reopen or duplicate, and that decisions use the
  database's time.
- `tests/concurrent_races.rs` (5B-5) checks each of the three
  active-incident partial unique indexes on its own. A second active
  incident is refused with a retryable 23505 on that index, and two
  connections ingesting first detections at once open exactly one
  incident. It also races two recurrences on one resolved incident: it
  reopens once, and the other recurrence links to it.
- `src/id.rs` (5B-5, ADR 0019). `UuidV7IncidentGenerator` is the
  production `IncidentGenerator`. It builds version 7 UUIDs with the
  pinned `v7` feature only, and refuses to repeat an id.
  `tests/uuidv7_round_trip.rs` checks that ids keep their text, bytes and
  version through PostgreSQL's `uuid` column, and sort in generation
  order on the server.
- `tests/timeouts_and_restart.rs` (5B-5). A statement timeout on a held
  lock fails the call with `57014`. It is not retried, commits nothing,
  and the same command succeeds once the lock is released. After a
  restart, a new service on a new connection claims the outbox messages
  left pending, still treats a replayed event as a duplicate, links to
  the open incident, and continues numbering from the database's
  allocator.
- `src/pool.rs` (5B-5, ADR 0022). `build_pool` verifies every reused
  connection (`RecyclingMethod::Verified`) and bounds waiting for,
  opening and verifying a connection. `acquire` returns
  `PersistError::Unavailable` when no connection comes in time, and that
  error is not retried. `tests/pool_exhaustion.rs` checks that a full
  pool fails within its wait timeout, that a released connection is
  reused, and that a connection killed while idle is replaced.
- `src/tls.rs` (5B-5, ADR 0023). `build_tls_pool` is the production pool.
  It refuses a configuration that could reach a non-loopback host without
  TLS (`sslmode=prefer` included, since it falls back to plaintext), and
  its rustls connector trusts only the CA certificates it is given and
  checks the host name. A refused handshake is `Unavailable` and is not
  retried. `tests/tls_connector.rs` runs against the CI server with TLS
  turned on by a throwaway, per-run CA: a verified connection is really
  encrypted, and an untrusted CA or a certificate for another name is
  refused. Mutual TLS is supported but not yet exercised against a server.
- `src/inbox.rs` and `V14` (5C, ADR 0035), the detection-event inbox.
  - `enqueue` adds a batch for one tenant. It is idempotent per
    `(tenant_id, dedup_key)` and refuses another tenant's event.
  - `InboxWorker` claims rows under ADR 0033's lease, ingests each event
    under its row's tenant, and records the outcome.
  - A payload it cannot read is dead-lettered at once. Other failures back
    off, then go to `incident_dead_letter`. Processed rows are purged after
    7 days.
  - `tests/detection_event_inbox.rs` also checks that a worker crashing
    between ingest and mark still yields one incident.
- `src/producer.rs` (5C, ADR 0035) is the detector's side of the inbox.
  - `InboxSink` is a `DetectionEventSink` that only pushes onto a bounded
    queue. When the queue is full it refuses the newest event and never
    evicts one it already accepted.
  - `InboxDrain::run` writes batches with `enqueue`, removes a batch only
    after it commits, and backs off on failure. On shutdown it closes the
    sink, flushes what is left, and reports anything abandoned.
  - `tests/inbox_producer.rs` takes the inbox offline and back to check
    that no event is lost, then turns the events into one incident.
- `InboxWorker::run` (5C) is the correlation worker loop. It processes
  batches until shutdown, backs off after a database failure without
  stopping, and notices shutdown only between batches: the batch in flight
  commits, and nothing is claimed after. `tests/inbox_worker_loop.rs`
  covers it.
- `src/maintenance.rs` (5C) runs the incident timers as one cross-tenant
  pass: the staleness sweep (`detector_silent`), recovery confirmation, and
  automatic closure. SQL on `transaction_timestamp()` proposes due
  incidents, and each domain call re-checks its own timer before acting.
  Critical incidents are never proposed for automatic closure (BQ-8).
  `tests/maintenance_timers.rs` covers it.

**Not here yet:** a scheduler for the consumer and retention jobs, measured pool
sizing, the operational runbook for the production connection string
(ADR 0023 follow-up), and any production database connection. See
[ADR 0029](../../docs/architecture/decisions/0029-phase5b-repository-and-unit-of-work-seam.md)
for why this is the crate's real, final placement, and
[FU-42](../../docs/development/follow-ups.md) for the dependency probe it
started as.

The six conditionally-accepted dependencies (`uuid`, `tokio-postgres`,
`deadpool-postgres`, `rustls`, `tokio-postgres-rustls`, `refinery`) remain
declared here at the exact versions their respective ADRs pinned; see
`src/lib.rs`'s `_probe_every_dependency_links` for the Phase 5B-1 probe
this crate started as (all six approved, [dependency-license-matrix.md](../../docs/dependency-license-matrix.md)
rows 32–37).

## Migrations

`migrations/` holds fourteen `refinery`-compatible SQL files
(`V1__enable_extensions.sql` through
`V14__detection_event_inbox.sql`). V1–V11 follow the dependency order
[phase5-implementation-plan.md](../../docs/development/phase5-implementation-plan.md)'s
5B-2 section fixes: extensions, `incidents`, detection-event links,
timeline, audit, notes/tags/assignments, policy references and number
allocators, idempotency, outbox and dead-letter, the active-incident
partial unique indexes, and the RLS-ready application role (ADR
0032). V12 (5B-3(b)) adds `ref_index` so a load keeps policy references
in the order the domain holds them. V13 (5B-5) adds
`policy_refs_omitted`, so a policy past the per-incident cap is counted
rather than silently dropped (FU-34). V14 (5C) adds the
detection-event inbox (ADR 0035).

They are embedded into this crate's binary at compile time via
[`refinery::embed_migrations!`] (`src/lib.rs`'s `migrations` module) —
embedded so a deployed binary carries its own schema history with no
separate file-distribution step, while staying file-based and
individually reviewable in this repository (ADR 0024's own follow-up
left "embedded vs. file-based" as an open 5B-2 decision; this is the
resolution).

Design notes, open questions, and where this schema deliberately diverges
from `docs/architecture/incident-persistence.md`'s literal sketch (with
the reasoning for each) are documented inline in the migration files
themselves — start with `V2__incidents.sql`'s header comment.

[`refinery::embed_migrations!`]: https://docs.rs/refinery/0.9.2/refinery/macro.embed_migrations.html

## Running the migrations locally

This project never connects a migration to a real or production
database. `docker-compose.yml` next to this file brings up a throwaway,
loopback-only PostgreSQL 17 instance with no persistent volume:

```sh
docker compose -f crates/incident-postgres/docker-compose.yml up -d --wait

TIDEGARD_INCIDENT_POSTGRES_TEST_URL="host=127.0.0.1 port=55432 user=tidegard_test password=tidegard_test_only dbname=tidegard_incident_test" \
    cargo test -p tidegard-incident-postgres --test migration_smoke_test

docker compose -f crates/incident-postgres/docker-compose.yml down -v
```

`tests/migration_smoke_test.rs` applies every migration, asserts a
second run is a no-op, and checks the resulting schema shape (every
table exists, the three active-incident partial unique indexes exist,
the durable-identity columns are real `GENERATED ALWAYS AS IDENTITY`
columns, and the `wetechinetmon_app` role exists without `BYPASSRLS`).
Without `TIDEGARD_INCIDENT_POSTGRES_TEST_URL` set, this test skips
itself with an explanatory message rather than failing — an environment
with no Docker/PostgreSQL available must still be able to run `cargo
test --workspace` cleanly.

**In CI (FU-46, 5B-5):** the `postgres` job in
`.github/workflows/validate.yml` runs this crate's tests once for each
PostgreSQL version
[ADR 0025](../../docs/architecture/decisions/0025-phase5b-postgresql-version-support.md)
supports: 15, 16, 17 and 18. Each run gets an ephemeral
`postgres:<version>-alpine` service container and sets
`TIDEGARD_INCIDENT_POSTGRES_TEST_URL`. The job fails if any test
prints its skip message, so a skip cannot pass silently there. Every PR
therefore runs every PostgreSQL test against all four versions.

## What this crate does not do

No `IncidentStore` implementation, no connection pool, no HTTP, no CLI,
no notification, no BGP, no mitigation. See
[phase5-implementation-plan.md](../../docs/development/phase5-implementation-plan.md)'s
5B-3 section onward for what comes next.
