# Phase 5 Implementation Plan

Status: **Milestones 5A to 5F complete** (2026-10-11). Gate 2 is
assessed in the [Gate 2 assessment](phase5-gate2-assessment.md), which
names what remains open. Each milestone's progress is recorded in its
section below. Part of the
[Phase 5 plan](../architecture/phase5-incident-management-plan.md).

Six milestones, each independently reviewable and independently
mergeable, each ending green. The ordering has one governing property:
**everything testable without a database is built and proven before the
database arrives.** Milestone 5A produces a complete, exhaustively tested
domain with in-memory repositories, so that when PostgreSQL lands in 5B
the only new risk is persistence rather than persistence *and* domain
logic at once.

## Before any milestone starts

**Resolved 2026-08-22 — 5A and 5B are unblocked:**

- **BQ-5** incident identity → **UUIDv7**, conditional on a dependency and
  licence review. Determines the primary key type; 5A may proceed.
- **BQ-6** FR-5.1 deviation → mitigation states **excluded**; seven-state
  lifecycle; suppression is an attribute. Determines the state set; 5A may
  proceed.
- **BQ-7** dependency approval → **approved architecturally**. 5B may
  proceed once [ADR 0018](../architecture/decisions/0018-phase5-dependency-selection.md)
  selects crates with verified evidence (**FU-25**, **FU-26**).

- **BQ-8** critical closure → **manual by default**. 5A implements the
  guard that refuses an automatic `Resolved` → `Closed` for `critical`;
  5B stores the override; 5D exposes effective-configuration diagnostics.
- **BQ-9** reopen window → **15 minutes, inclusive boundary**, range
  0–24 h. 5A implements the boundary comparison and its tests.

**No Phase 5 planning decision remains outstanding.** The only thing
standing between here and 5B is crate selection under
[ADR 0018](../architecture/decisions/0018-phase5-dependency-selection.md),
which is implementation work with verification requirements rather than
an open architectural question (**FU-25**, **FU-26**).

## Milestone 5A — Domain and state machine

**No database. No API. No dependencies beyond the workspace.**

New crate `wetechinetmon-incident`. Domain types from the
[domain model](../architecture/incident-domain-model.md); the state
machine with a guard refusing illegal edges; correlation key construction
and canonicalisation; category derivation; the `Clock` seam reused from
the detector; a bounded in-memory unit of work; `CorrelationStrategy` and
`AssignmentPolicy` seams from ADR 0017.

**Correction (2026-08-24, Phase 5B Stage A planning):** this line
originally read "repository *traits* with in-memory implementations."
Verified against actual source, that was not delivered — see the
**Status** paragraph below and
[ADR 0029](../architecture/decisions/0029-phase5b-repository-and-unit-of-work-seam.md)
for the finding and the Milestone 5B-0 correction.

Tests: all domain tests, all state-machine tests, and property tests
1–13 from the [testing plan](../architecture/incident-testing-plan.md).

**Exit:** every legal and illegal transition tested; correlation
order-independence proven; no dependency added; existing 403 tests still
green.

**Reviewable because** it is pure logic with no infrastructure, so review
attention goes to the rules rather than to wiring.

**Status: merged to `main`** (PR #16, merge commit `2cd116d`,
2026-08-24), superseding the "not yet merged" note this paragraph
originally carried.
New crate `wetechinetmon-incident`, dependency-free beyond the workspace
(a path dependency on `wetechinetmon-detector` for its published event
vocabulary and clock trait only — see the crate's `lib.rs` module doc for
the exact import boundary and **FU-29** for its current lack of
mechanical enforcement). Covers domain identities, the seven-state
lifecycle guard, deterministic correlation with typed target identity,
category derivation, closure and reopen policy, suppression as an
attribute, severity/priority, assignment, typed timeline and audit
records, idempotency with a canonical-bytes fingerprint (not a hash —
see the crate's `idempotency` module doc), the outbox abstraction, a
single bounded in-memory `IncidentUnitOfWork`, and a dependency-free
end-to-end domain test.

An Opus 5 adversarial review of the initial implementation found two
blockers (a `Resolved` incident's automatic reopen path was unreachable
from ingestion; `ResolveIncident` bypassed the transition guard entirely,
accepting `Closed -> Resolved`) and seven high-severity findings
(transition metadata misattributed between commands; automatic-maintenance
methods bypassing authorization; the idempotency fingerprint omitting its
target incident; failed commands collapsing to a single `Unauthorized` on
replay instead of preserving their real error; a misleadingly named
atomicity test that asserted partial state *did* survive while claiming
to prove otherwise; and a tautological order-independence property test).
All nine were corrected on the same branch, with regression tests, and
version/`reopen_count` overflow was hardened with `checked_add` across
every mutation site (never mutate-then-fail). **5A does not claim a
cross-record transaction** — every mutation validates everything
fallible before touching the incident, so a predictable error never
mutates anything. A focused Opus 5 re-review (2026-08-24) confirmed this
is stronger than first stated: in a `cfg(not(test))` build there is no
reachable post-write failure at all, since the injected-failure hook
that exposes genuine partial state is `cfg(test)`-gated and does not
exist in a production binary (see **FU-31**). The same re-review
verified both blockers and all seven high findings above were correctly
and durably fixed, confirmed zero blockers and zero high findings
remained, and raised twelve further, lower-severity findings — the
still-tautological monotonicity property test, a stale documentation
contradiction on the reopen anchor, an unbounded-panic path on
suppression duration, a severity-downgrade path that could bypass BQ-8's
manual-closure protection, and several smaller items. All were fixed or
explicitly deferred with rationale on 2026-08-24; the
[complete finding register](follow-ups.md#phase-5a-focused-re-review-finding-register-2026-08-24)
is the authoritative record of what remains outstanding, superseding the
Medium/low list in **FU-30** through **FU-37** above (kept current, not
duplicated), and now extended through **FU-41** (see the register). The
final sanity review, publication, and merge (PR #16, merge commit
`2cd116d`) all completed 2026-08-24. Milestone 5B has not started
implementation; its planning (this document's 5B section, the ADR series
0019–0033, and
[phase5b-postgresql-persistence-plan.md](../architecture/phase5b-postgresql-persistence-plan.md))
completed the same day.

**5A is database-independent and dependency-free.** It may implement
incident domain types, the seven-state lifecycle, correlation, reopen
behaviour, the suppression attribute, severity and priority, assignment
abstractions, timeline and audit types, in-memory repositories,
idempotency and outbox *abstractions*, and unit and property tests.

It must **not** add a PostgreSQL driver, an HTTP framework, migrations, a
REST server, notification delivery, mitigation, BGP, or FlowSpec. If 5A
needs any of those, the domain boundary in
[ADR 0011](../architecture/decisions/0011-incident-domain-boundary.md)
has been drawn wrong and that is the thing to fix, not the constraint.

## Milestone 5B — PostgreSQL persistence

**BQ-7 resolved architecturally; Stage A/B planning complete 2026-08-24.**
BQ-7 approved the *capability*; Stage A researched and Stage B decided
the specific, defensible set of crates and the schema/transaction design
— see [phase5b-postgresql-persistence-plan.md](../architecture/phase5b-postgresql-persistence-plan.md)
and ADRs [0019](../architecture/decisions/0019-phase5b-uuidv7-identity-generation.md)–[0033](../architecture/decisions/0033-phase5b-transactional-outbox-and-dead-letter.md).
**Status: 5B-0 and 5B-1 merged to `main`** (PR #22, merge commit
`775fb1f`, and PR #23, merge commit `4350412`, both 2026-09-03),
superseding the "Implementation has not started" note this paragraph
originally carried. 5B is a **refactor-and-implement** milestone, not
implement-only — Stage A found 5A did not deliver the repository seam
this document previously assumed (see the Milestone 5A correction above
and [ADR 0029](../architecture/decisions/0029-phase5b-repository-and-unit-of-work-seam.md)).
**5B-2 (schema and migrations): merged to `main`** (PR #25, merge commit
`167c357`, 2026-09-05) — see that milestone's own status note below.
**5B-3 (repository implementations): in progress** — its bridge design is
[ADR 0034](../architecture/decisions/0034-phase5b-persistence-bridge-load-run-flush.md),
and step (a) is the staging store; see that milestone's note below.
5B-4 onward has not started.

### 5B-0 — Seam extraction (no SQL, no dependency)

Persistence contract extraction from `IncidentUnitOfWork`'s current
concrete shape; `IncidentSnapshot` and `Incident::reconstitute` with
invariant validation ([ADR 0030](../architecture/decisions/0030-phase5b-aggregate-reconstitution.md));
durable-time API shape ([ADR 0031](../architecture/decisions/0031-phase5b-durable-time.md));
**FU-38** guard hardening (move the transition check inside
`close_internal`/`reopen_incident_internal` themselves); the in-memory
adapter migrated to the new seam as its reference implementation.

**Exit:** all 531 existing tests remain green throughout — this is a
refactor, not a behaviour change; the table-driven illegal-source-state
test FU-38 specifies passes for both hardened functions.

**Status: merged to `main`** (PR #22, merge commit `775fb1f`,
2026-09-03).

### 5B-1 — Dependency probe

Entry gates, all required before any of the six conditionally-accepted
crates ([ADR 0019](../architecture/decisions/0019-phase5b-uuidv7-identity-generation.md),
[0020](../architecture/decisions/0020-phase5b-postgresql-client.md),
[0022](../architecture/decisions/0022-phase5b-connection-pool.md),
[0023](../architecture/decisions/0023-phase5b-postgresql-tls.md),
[0024](../architecture/decisions/0024-phase5b-migration-framework.md))
is actually added:

| # | Entry gate |
|---|---|
| 1 | **Verified registry metadata** for every candidate — queried, not recalled (done in Stage A; see the ADRs above and [dependency-license-matrix.md](../dependency-license-matrix.md) rows 32–37) |
| 2 | Dependency licence review against the Apache-2.0 core (done in Stage A) |
| 3 | `cargo tree` — a **measured** transitive closure for the actual selected feature set, not an estimate |
| 4 | `cargo audit` clean, with no open unfixed advisory |
| 5 | `unsafe` inventory measured, not assumed absent |
| 6 | **Windows-GNU build** — the primary development machine |
| 7 | **Linux build** — the deployment target |
| 8 | [Dependency licence matrix](../dependency-license-matrix.md) updated from "Conditionally Approved" to "Approved" or "Rejected" |
| 9 | `NOTICE` reviewed and updated where a licence requires attribution |

Gates 3–7 exist because every transitive-closure, `unsafe`, and
cross-platform-build figure in Stage A's research is what could be
verified from registry/repository metadata **without adding the
dependency** — actually measuring them requires adding it, which is
exactly why this milestone exists as a distinct, reversible step before
5B-2 onward depends on the result. See
[ADR 0018](../architecture/decisions/0018-phase5-dependency-selection.md).

**Status: merged to `main`** (PR #23, merge commit `4350412`,
2026-09-03). All nine entry gates closed — see **FU-42** for the measured
`cargo tree` (73 new crates), `cargo audit` (0 vulnerabilities/252
crates), `unsafe` inventory, and Windows-GNU + Linux build results.
Dependency-license-matrix rows 32–37 flipped to **Approved**.

### 5B-2 — Schema and migrations

Forward-only `refinery` migrations, in reviewable steps (extensions →
`incidents` → detection links → timeline → audit → notes/tags/
assignments → `incident_policy_references` / `incident_number_allocators`
→ idempotency → outbox/dead-letter → constraints/indexes → RLS-ready
roles), per [incident-persistence.md](../architecture/incident-persistence.md)
and [ADR 0024](../architecture/decisions/0024-phase5b-migration-framework.md).

**Status: merged to `main`** (PR #25, merge commit `167c357`, 2026-09-05).
Eleven `refinery`-compatible SQL migrations added under
`crates/incident-postgres/migrations/` (`V1__enable_extensions.sql`
through `V11__rls_ready_roles.sql`), embedded into the crate via
`refinery::embed_migrations!`; an ephemeral, loopback-only
`docker-compose.yml` for local/CI PostgreSQL; a migration smoke test
(`tests/migration_smoke_test.rs`) that applies all migrations, asserts a
second run is a no-op, and checks the resulting schema shape. **No
`IncidentStore` implementation, no connection pool wiring, and no
production database connection** — unchanged from this milestone's scope,
deferred to 5B-3. Docker was unavailable in the authoring environment, so
the smoke test was verified for real on a separate Docker-capable host
before merge (FU-45) rather than merged on eye-review alone. Schema-design
questions flagged for owner review, where `incident-persistence.md`'s
sketch was ambiguous or where the actual `Incident`/`IncidentSnapshot`
source diverged from the older `incident-domain-model.md` planning doc,
are tracked in FU-47.

### 5B-3 — Repository implementations

Real repository implementations against the 5B-0 seam; optimistic
concurrency ([ADR 0026](../architecture/decisions/0026-phase5b-transaction-isolation.md));
idempotency with the persisted fingerprint
([ADR 0028](../architecture/decisions/0028-phase5b-idempotency-fingerprint.md));
the transactional state-plus-timeline-plus-audit-plus-outbox write; the
sync/async bridge ([ADR 0021](../architecture/decisions/0021-phase5b-async-runtime-boundary.md)).

**Status (2026-09-15):** the bridge is decided as load–run–flush
([ADR 0034](../architecture/decisions/0034-phase5b-persistence-bridge-load-run-flush.md)),
delivered in three steps:

- **(a) Staging store, no SQL.** `IncidentUnitOfWork` gains `with_store`/`into_store`, and `IdempotencyStore` gains record iteration. `crates/incident-postgres/src/staging.rs` holds one call's loaded rows, records its changes, and fails closed on unloaded lookups.
- **(b) Load/flush SQL and integration tests,** including FU-44's acceptance gate. In progress:
  - **Part 1 (row mapping):** `src/row.rs` maps an incident to its `incidents`, notes, tags and policy-reference rows and back, with no database. `src/sql.rs` inserts one incident, updates it under the `WHERE version = loaded_version` guard, and loads it with an optional `FOR UPDATE` lock. `V12__policy_reference_order.sql` keeps policy-reference order. Tests: `tests/incident_row_mapping.rs` runs without a database, `tests/incident_row_round_trip.rs` runs on CI PostgreSQL. Found along the way: FU-48, FU-49, FU-50.
  - **Part 2 (load, flush, transaction):** `src/load.rs` fetches each entry point's working set under ADR 0034's locks. When a create is possible, it locks the allocator row and then re-checks the active incident. `src/flush.rs` writes the change set, and `src/history.rs` maps the timeline, audit, outbox, detection-link and idempotency rows. `src/service.rs` (`IncidentPersistence`) wraps each entry point in one Read Committed transaction. `tests/service_round_trip.rs` covers the service on PostgreSQL, including FU-44's killed-connection gate.
- **(c) Retry and conflict classification per ADR 0026.** `src/retry.rs` marks a failure transient when it is one of these:
  - `40001` or `40P01`
  - `23505` on an active-incident index or the dedup constraint
  - a concurrently taken idempotency key
  - a flush version-guard conflict

  `IncidentPersistence` reruns the whole load–run–flush from a fresh load on one of these, at most 3 attempts with jittered exponential backoff. Everything else, including domain errors and a closed connection, is returned at once. `tests/retry_and_races.rs` classifies real PostgreSQL errors and races two first detections for one target.

### 5B-4 — Outbox and retention

Claim/lease/retry/dead-letter implementation
([ADR 0033](../architecture/decisions/0033-phase5b-transactional-outbox-and-dead-letter.md));
retention and cleanup jobs per
[incident-persistence.md](../architecture/incident-persistence.md)'s
retention table.

**Status (2026-09-15):** implemented in `crates/incident-postgres`.

- **`src/outbox.rs`:** `OutboxConsumer` claims, publishes, retries and dead-letters. The starting defaults are a 60 s lease, a batch of 100, and 10 attempts with 1 s–5 min backoff; all are configurable. ADR 0033 asks that the lease default be revisited against the performance-test plan.
- **`src/retention.rs`:** `run_retention`. Audit and unreviewed dead-letter rows are never purged.
- **`tests/outbox_and_retention.rs`:** covers the lease, backoff, reclaim, lease-lost, dead-letter and retention paths. ADR 0033's full concurrency and crash test list remains 5B-5's.

### 5B-5 — Integration and performance tests

Tests: all persistence tests, with **injected failure at each commit
point** proving all-or-nothing; genuine concurrent inserts proving each
of the three target-specific partial unique indexes holds; migrations
applying cleanly against all four tested PostgreSQL versions
([ADR 0025](../architecture/decisions/0025-phase5b-postgresql-version-support.md));
the full required-integration-test list in
[phase5b-postgresql-persistence-plan.md](../architecture/phase5b-postgresql-persistence-plan.md).

**Exit:** atomicity proven by failure injection, not by observing
success; tenant-less queries impossible to construct; retention never
cascades into audit.

**Status (2026-09-15):** in progress.

- **Done:** the CI `postgres` job runs every PostgreSQL test against 15, 16, 17 and 18 and fails if any skips (ADR 0025, FU-46). Cross-tenant paths take a `PlatformAuthority` (ADR 0032 item 7). `tests/failure_injection.rs` injects a failure at each of the eight flush points and proves nothing commits, and runs a transient failure through the retry loop. `tests/outbox_concurrency.rs` covers ADR 0033's concurrency and crash test list. A policy past the per-incident cap is now counted in `policy_refs_omitted` (V13, FU-34) and tested in `tests/policy_reference_overflow.rs`. `IncidentPersistence` decides on `transaction_timestamp()` and returns `ClockSkew` for a reopen against a future reference, instead of creating a duplicate (ADR 0031, `tests/clock_skew.rs`). `UuidV7IncidentGenerator` (ADR 0019) is the production id generator, and `tests/uuidv7_round_trip.rs` covers the UUIDv7 round trip. `tests/service_round_trip.rs` asserts cross-tenant concealment (`NotFound`, not `Unauthorized`). `tests/concurrent_races.rs` covers each of the three partial unique indexes under concurrent creates, and the concurrent reopen race. `tests/timeouts_and_restart.rs` covers statement timeout and service-restart recovery. `src/pool.rs` is the ADR 0022 pool, and `tests/pool_exhaustion.rs` covers pool exhaustion. CI's `windows` job builds and tests the workspace on Windows.
- **Remaining:** the benchmarks in the persistence plan's performance-test plan, which are planned but not yet run. Measured pool sizing (ADR 0022). The rustls connector (ADR 0023) is in `src/tls.rs`; its production connection-string runbook waits for a deployment. ADR 0031's clock-skew metric waits for 5C's metrics.

## Milestone 5C — Ingestion and correlation

Outbox producer on the detector side; the correlation worker; retry,
backoff, dead-letter; the staleness sweep; recovery and auto-close
timers; Prometheus metrics; structured logging.

**Progress:** the detection-event inbox, with its enqueue, claim, ingest and dead-letter paths, follows [ADR 0035](../architecture/decisions/0035-phase5c-detection-event-inbox.md) (migration V14). The detector-side sink and drain task are in `src/producer.rs`; the worker loop and its shutdown drain are `InboxWorker::run`. The staleness sweep, recovery confirmation and automatic closure are `run_maintenance` (FU-40 closed). The worker, the timers and retention run on a schedule in the `wetechinetmon-incident-manager` binary ([ADR 0036](../architecture/decisions/0036-phase5c-incident-manager-process.md)), with structured logs and allowlisted metrics. The collector attaches the producer to its detection stage when `WETECHINETMON_COLLECTOR_INCIDENT_DATABASE_URL` is set: one queue and drain task per policy tenant. `crates/collector/tests/incident_end_to_end.rs` runs both real processes on PostgreSQL: synthetic IPFIX over UDP becomes one incident, nothing is published from the outbox, every event is a dry run whose action was not executed, and replaying the events (again, and after the inbox rows are gone) changes nothing. With the label allowlist test in `crates/incident-manager`, that meets the exit criteria below.

Tests: duplicate, late, and out-of-order events; poison event handling;
replay safety; the five distinct end reasons; detector restart producing
one incident rather than two; **the full end-to-end test** from synthetic
IPFIX bytes through to an incident, including the negative assertions
that nothing was notified and nothing was mitigated.

**Exit:** end-to-end test passing; replay proven safe; metric label sets
asserted against an allowlist.

## Milestone 5D — REST API

**Entry gates**, all required before the first endpoint is written:

| # | Entry gate |
|---|---|
| 1 | HTTP framework ADR, under the [ADR 0018](../architecture/decisions/0018-phase5-dependency-selection.md) criteria |
| 2 | OpenAPI approach — generated from code, or hand-maintained and tested against the implementation |
| 3 | TLS boundary — terminated at the service or at a proxy, stated either way |
| 4 | Authentication seam, so Phase 8 can replace the identity provider without touching the incident domain |
| 5 | Authorization seam — `PermissionResolver`, per [ADR 0017](../architecture/decisions/0017-incident-community-enterprise-boundary.md) |
| 6 | Rate-limiting approach and its storage |
| 7 | API error model — RFC 9457 problem details with stable `error` codes |
| 8 | Dependency review for the framework and its closure, gates 6–13 of 5B |

**Gate status (2026-10-05):** gates 1–2 are decided in [ADR 0037](../architecture/decisions/0037-phase5d-http-framework-and-openapi.md): `axum` 0.8, and an OpenAPI document generated from code with `utoipa` and checked against a committed file. Gates 3–7 are decided in [ADR 0038](../architecture/decisions/0038-phase5d-api-boundary.md):

- TLS at the service off loopback;
- opaque, hashed API tokens behind an `Authenticator` seam;
- the existing `PermissionResolver`;
- in-memory GCRA limits per actor and surface;
- RFC 9457 errors with stable codes.

Gate 8 closed on 2026-10-05 with the dependency probe in `apps/api`:

- `axum`, `utoipa` and `getrandom` approved: 16 new third-party crates, `cargo audit` clean over 270, no `unsafe` in the framework or OpenAPI crates, Windows-GNU and Linux builds.
- `governor` rejected on closure: about 920 `unsafe` occurrences for a limiter. GCRA is implemented in-house instead.
- `matchit`'s BSD-3-Clause notice recorded in `NOTICE` (FU-53).

Endpoints may now be written.

**Progress:** the API foundation is `apps/api` (`wetechinetmon-api`):

- RFC 9457 errors behind an `ErrorCode` registry that `docs/api/error-codes.md` must match;
- a UUIDv7 request id;
- a std GCRA rate limiter;
- loopback-or-TLS binding;
- `/healthz` and `/readyz`;
- the OpenAPI document committed at `docs/api/openapi.json` and checked by a test.

Authentication is in place:

- `api_tokens` (migration V15) stores SHA-256 only and forbids `platform_admin`;
- the `Authenticator` seam with the token-table implementation;
- the bearer middleware: one `401` for every failure, per-address failure limiting, and `503` on an outage;
- the `wetechinetmon-api token create|revoke|list` subcommand.

The first incident endpoint is `GET /api/v1/incidents/{id}`. It goes through `incident_postgres::queries`, which checks `incident.read` and scopes the read to the caller's tenant in one read-only snapshot. Another tenant's incident returns the same 404 as a missing one, and a PostgreSQL test proves it. The representation follows the API plan, with the gaps recorded as FU-54.

`GET /api/v1/incidents` lists the caller's incidents (5D-4):

- allowlisted filters and sorts, with unknown parameters refused;
- keyset pagination on `(sort column, incident_id)`, served by the V16 indexes;
- an opaque cursor bound to tenant, sort and order;
- page size capped at 200;
- 90-day ranges;
- an optional count.

An incident's history is read through four sub-resources (5D-5): `timeline`, `notes`, `detections` and `audit`. Each one:

- checks the incident is in the caller's tenant, and otherwise returns the same 404 as a missing incident;
- needs `incident.read`, except `audit`, which needs `incident.audit.read` and has the tighter audit limit;
- is keyset-paginated oldest first, except notes, which the domain bounds and which are returned whole.

The transitions are twelve `POST` actions (5D-6), from `acknowledge` to `priority`. Each one:

- requires an `Idempotency-Key` and an `expected_version`;
- is decided by the same unit of work the incident manager runs, which checks the permission, the tenant and the state machine;
- answers with the incident as it now is.

A stale version names the current version and state. A suppression is bounded at 30 days. The acknowledge `note` waits on the domain (FU-55).

Adding a note is `POST .../notes` (5D-7). It needs no version, because notes are append-only, and the key is optional. A customer-visible note is refused with `501`.

Tags are a sub-resource (5D-8): `PUT .../tags/{key}` sets one and `DELETE` removes one. `incident.update` joins the `noc_lead` bundle, by Shorif's decision of 5 Oct 2026. Until then only `platform_admin`, which no token can hold, had it.

Manual creation is `POST /api/v1/incidents` (5D-9, [ADR 0039](../architecture/decisions/0039-phase5d-manual-incidents.md)). It needs `incident.create` (`senior_operator` and up) and an `Idempotency-Key`. A manual incident takes the correlation key of its target, so a second incident for an active target is refused and later detections attach to it.

The export is `POST .../export` (5D-10). It needs `incident.export` and returns one JSON document read from a single snapshot. Each history is capped at 5000 entries, and the audit section is included only with `incident.audit.read`. The export is audited before it is read, and it has its own limit of 10 per minute.

Every endpoint in the API plan now exists, except `PATCH` for title and description (FU-56).

The tenant-isolation suite (`apps/api/tests/tenant_isolation.rs`) reads every per-incident operation from the committed OpenAPI document, so a new endpoint without a case fails it. Another tenant's broadest role gets a `404` identical to a missing incident on every one of them, sending a body the endpoint would accept. The incident is unchanged afterwards, and the other tenant's list never shows it. This meets the first exit criterion. The second, OpenAPI matching the implementation, is the drift test.

Remaining 5D gaps, all recorded: FU-54 (representation fields), FU-55 (acknowledge note), FU-56 (title and description).

Endpoints from the [API plan](../architecture/incident-api-plan.md);
authorization at the command boundary; cursor pagination; filtering and
sorting through an allowlist; rate limiting; RFC 9457 error bodies; the
OpenAPI document promoted from draft to a real file.

Tests: all API tests, especially **404-not-403 for cross-tenant on every
endpoint**, and rejection of unknown fields and undocumented sort fields.

**Exit:** tenant isolation suite passing on every endpoint; OpenAPI
matching the implementation.

## Milestone 5E — CLI

`wetechinetmonctl incidents` per the
[CLI plan](../architecture/incident-cli-plan.md); table, JSON, and wide
output; exit codes; confirmations; per-command idempotency keys reused
across retries.

**Progress:** `apps/cli` is `wetechinetmonctl` ([ADR 0040](../architecture/decisions/0040-phase5e-cli-client.md)). It adds no new crates: hyper and tokio-rustls, which are already in the tree, and a hand-written parser. 5E-1 adds the read commands:

- `list`, `show`, `timeline`, `detections`, `audit`, `note list`;
- table, wide and verbatim JSON output;
- the exit codes;
- retries only on connection errors and `5xx`;
- credentials never accepted as flags, and plaintext only to loopback;
- an incident number resolved through the API's new exact `incident_number` filter.

The RFC 3339 helpers moved to `wetechinetmon_common::rfc3339`, so the API and the CLI share them. 5E-2 adds the commands that change an incident: every transition, assignment, severity, priority and notes. Each change:

- reads the version first, unless `--expected-version` pins it;
- sends one UUIDv7 `Idempotency-Key`, reused on every retry;
- asks before closing, reopening, suppressing and lowering severity. With no terminal and no `--yes`, that is an error and nothing is sent;
- exits `4` on a `409`, showing the current version and state, without re-issuing.

5E-3 completes the command set:

- `claim`, through a new `GET /api/v1/whoami` that answers with the token's own tenant, actor, role and permission names (`Permission::name`, checked against the security model);
- `export`, to stdout or a new file that is never overwritten;
- `open`, and `tag set` and `tag remove`.

Every command maps to one endpoint, and the CLI holds no business logic. This meets the 5E exit criterion.

Tests: output formats; exit codes per error class; confirmation required
without `--yes`; **no TTY plus no `--yes` is an error, never an assumed
yes**; keys reused on retry.

**Exit:** every command mapped to an endpoint with no business logic in
the CLI.

## Milestone 5F — Operations and hardening

Installation and upgrade documentation; the runbook promoted from plan;
**tested** backup and restore (NFR-2); capacity benchmarks actually run,
with real numbers replacing the placeholders; a security review against
all 24 threats; final full validation.

**Exit:** every threat has a passing test; benchmarks measured and
published; restore tested rather than assumed; acceptance criteria met.

**Progress:** complete on 2026-10-11.

- **Security review:** every threat in the model is mapped to its tests
  in the [threat tests](../security/incident-threat-tests.md). Five
  findings were fixed: late news reopening resolved incidents (T-18), a
  NUL causing a `500` (T-07), the audit row lacking before and after
  (T-20, FU-59), raw NUL bytes in source, and an event claiming an
  executed action being linked rather than quarantined.
- **The safety property, tested:** `dependency_closure.rs` holds the
  detector and the incident domain to a reviewed crate allowlist (FU-9).
- **Backup and restore:** a [drill](../operations/backup-and-restore.md)
  dumps, restores and verifies on every pull request, on PostgreSQL 15
  to 18.
- **Benchmarks:** measured and published in
  [capacity planning](../operations/capacity-planning.md#incident-persistence-measured).
- **Documentation:** ADRs 0011–0017 accepted as implemented; the
  [runbook](../operations/incident-runbook.md) promoted from its plan;
  an [installation guide](../installation/incident-management.md).
- **Notes with supersession and redaction** (FU-63), which Gate 2 names
  and the schema had planned but nothing used.
- **CI:** the History job enforces the secret scan and DCO again, with
  the free gitleaks binary, after months of failing on every pull
  request.

## Dependency graph

```text
BQ-5, BQ-6 (resolved) ──► 5A ──► 5B ──► 5C ──► 5D ──► 5E ──► 5F
                                  ▲       │              │
   BQ-7 (resolved) + ADR 0018 ────┘       └── 5D may ────┘
   crate selection                            start once
                                              5B lands
```

5D depends on 5B for persistence, not on 5C, so API work can proceed in
parallel with ingestion once the repositories exist.

## Per-milestone gate

Every milestone must pass, before review:

`cargo fmt --check` · `cargo clippy --workspace --all-targets -- -D
warnings` · `cargo test --workspace` · `cargo build --workspace
--all-targets` · `make validate` · `mkdocs build --strict` ·
`markdownlint-cli2` at the CI pin · `js-yaml` · `actionlint` ·
`git diff --check` · DCO on every commit.

Plus, every milestone: **the existing 403 Phase 4 tests remain green**,
no Phase 4 behaviour is modified, no dependency is added beyond those
approved in BQ-7, and ClickHouse stays on `0.13`.

## Not in Phase 5

Notification delivery, mitigation, BGP, RTBH, FlowSpec, firewall, router
control, webhooks, script execution, full RBAC, SSO, Entra ID, customer
portal, PDF reports, ML, distributed correlation, multi-region, SLA
billing, subscriptions, bulk mutation (**FU-22**), binary evidence
storage (**FU-23**), and customer-visible notes.

Seams are planned for several of these. **A planned seam is not an
implementation**, and no milestone above delivers functionality behind
one.
