# Incident Persistence

Status: **Planning only — Phase 5B Stage A/B planning complete
(2026-08-24), implementation not started.** Part of the
[Phase 5 plan](phase5-incident-management-plan.md). Decisions in
[ADR 0015](decisions/0015-incident-operational-storage.md),
[ADR 0012](decisions/0012-incident-event-ingestion.md), and the Phase 5B
ADR series [0019](decisions/0019-phase5b-uuidv7-identity-generation.md)–[0033](decisions/0033-phase5b-transactional-outbox-and-dead-letter.md).

**No migration is written by this document.** The DDL sketches below are
design artefacts for review, not files in a migrations directory.

**This document describes the target schema, not the current
implementation seam.** Verified against actual Phase 5A source
(2026-08-24): `tidegard-incident` has no repository trait a
PostgreSQL implementation could satisfy today —
`IncidentUnitOfWork` is a concrete struct, not an interface, and
`Incident` cannot be reconstituted from outside the crate. Phase 5B's
first milestone (5B-0) extracts that seam *before* any of the SQL below
is implemented — see [ADR 0029](decisions/0029-phase5b-repository-and-unit-of-work-seam.md)
and [ADR 0030](decisions/0030-phase5b-aggregate-reconstitution.md). This
corrects `phase5-implementation-plan.md`'s earlier claim that 5A already
delivered "repository traits with in-memory implementations."

## Two stores, one source of truth

| Store | Holds | Authority |
|---|---|---|
| **PostgreSQL** | Incidents, timeline, notes, audit, idempotency, outbox | **Source of truth** for all operational state |
| **ClickHouse** | Immutable incident analytics events | Derived; never authoritative |

ClickHouse already holds `wetechinetmon_detection_events` with a 365-day
TTL and is excellent at what Phase 3 and 4 use it for: high-volume
immutable appends scanned analytically. It is a poor fit for incident
*state*, which needs row-level updates, transactions across several
tables, unique constraints, and foreign keys. Using it for both would
mean either dual-authoritative mutable state — the failure mode where two
stores disagree and nobody can say which is right — or reimplementing
transactions in application code.

So: PostgreSQL owns mutable operational state. ClickHouse receives
immutable analytics events through the outbox. There is exactly one
authority for any given fact.

## Tables

Sketches. Types and constraints are the design; exact DDL is Milestone 5B.

### Tenant-aware composite foreign keys — added 2026-08-30

[ADR 0032](decisions/0032-phase5b-tenant-isolation-and-rls-readiness.md)'s
defense-in-depth layer 2 requires that a foreign key from one
tenant-owned table to another **includes `tenant_id` in the key**, so a
cross-tenant reference is structurally rejected by the database rather
than only by application discipline. This requires a **candidate key**
on the referenced table that includes `tenant_id` — `incidents` declares
`UNIQUE (tenant_id, incident_id)` alongside its existing
`PRIMARY KEY (incident_id)` specifically to make this expressible; the
primary key itself stays `incident_id` alone, unchanged from the
originally approved design.

Every table below states explicitly whether it references an incident
and, if so, does so with the composite pattern:

```sql
FOREIGN KEY (tenant_id, incident_id)
REFERENCES incidents (tenant_id, incident_id)
```

A table whose rows are not scoped to one specific incident (a per-tenant
allocator, or a table using a polymorphic `resource_type`/`resource_id`
or `aggregate_type`/`aggregate_id` pair that is not always an incident)
does not get this foreign key — a generic reference cannot target one
fixed parent table, and forcing one would either break the table's
actual purpose or silently narrow it. Each such table states why below.

**Deletion behavior:** where the [retention table](#retention) already
states a child "follows its incident" (timeline, notes, detection
events, policy references, assignments, tags), the composite foreign key
is `ON DELETE CASCADE` — deleting a retained-past-24-months closed
incident deletes its own timeline/notes/etc. with it, matching the
stated retention behavior rather than leaving orphaned rows. **Audit is
the deliberate exception**: it has no foreign key to `incidents` at all
(see its own table section below), so it is structurally unable to
cascade-delete when an incident is removed — the retention table already
requires audit to outlive its incident (24 months minimum, versus the
incident's own 24-month-after-close window) and the tenant-isolation
section already requires "tenant deletion must never cascade into
audit"; the same non-FK design serves both requirements at once.

### `incidents`

Columns follow the [domain model](incident-domain-model.md). Key
constraints:

```text
PRIMARY KEY (incident_id)
UNIQUE (tenant_id, incident_id)    -- candidate key; see "Tenant-aware
                                    -- composite foreign keys" above
UNIQUE (tenant_id, incident_number)
CHECK (state IN ('open','acknowledged','investigating','monitoring',
                 'recovering','resolved','closed'))
CHECK (suppressed_until IS NULL OR suppression_reason IS NOT NULL)
CHECK (severity IN ('info','minor','major','critical'))
CHECK (severity_source IN ('detection','operator'))
CHECK (maximum_detected_severity IN ('info','minor','major','critical'))
CHECK (address_family IN (4,6))
CHECK (closed_at IS NOT NULL OR state <> 'closed')
CHECK (
  (target_type = 'host'      AND target_addr    IS NOT NULL AND target_network IS NULL AND target_hostgroup IS NULL) OR
  (target_type = 'network'   AND target_network IS NOT NULL AND target_addr    IS NULL AND target_hostgroup IS NULL) OR
  (target_type = 'hostgroup' AND target_hostgroup IS NOT NULL AND target_addr  IS NULL AND target_network   IS NULL)
)
```

`target_addr` is `inet`, `target_network` is `cidr`, `target_hostgroup`
is `text` — the typed target identity from the detector's `ScopeId`
(`Host`, `Network`, `Hostgroup`, verified against
`crates/detector/src/input.rs`)
mapped directly to native PostgreSQL address types, not to a display
string. This is what makes typed IPv6 canonicalisation a database
property instead of an application-code promise.

`maximum_detected_severity` and `ever_critical` are new columns beyond
the original sketch, added to support **FU-41** (detection-driven
severity escalation): Phase 5A's `link_event_to_open_incident` never
updates `severity` when a later, more severe detection links to an
already-open incident, so an operator-editable `severity` alone cannot
safely gate Critical manual-closure protection.
`maximum_detected_severity` is a monotonic column a future Phase 5C
escalation design can read without a migration; Phase 5B persists it and
does **not** implement automatic escalation. See
[follow-ups.md FU-41](../development/follow-ups.md).

### Active-incident invariant — corrected 2026-08-24

The original sketch here used a single partial unique index with
predicate `WHERE state <> 'closed'`. **This predicate is incorrect** and
is corrected below: verified against actual Phase 5A source, `Resolved`
is not an active state for correlation — `link_event_to_open_incident`
removes an incident from its `open_index` the moment it resolves, and
[the state-machine ADR](decisions/0014-incident-state-machine.md) treats
`Resolved` as outside correlation. A predicate of `state <> 'closed'`
would still block a legitimate reopen-window recurrence from inserting a
new incident row for the same key while a `Resolved` incident (correctly
outside correlation) still occupies it.

The **active states are exactly:** Open, Acknowledged, Investigating,
Monitoring, Recovering. Resolved and Closed are not active.

**Target-type-specific partial unique indexes**, not one generated
canonical-key column — corrected 2026-08-30 from a citation that
attributed this design to [ADR 0032](decisions/0032-phase5b-tenant-isolation-and-rls-readiness.md),
which covers tenant isolation and RLS readiness, not typed target
identity or index design; the typed-target schema decision belongs to
this document (see `incidents`'s own `CHECK` constraint above and
[the `incidents` table](incident-domain-model.md) it follows) — using
`inet`/`cidr` equality
directly keeps the invariant expressed over the same native types the
`incidents` table itself stores, rather than introducing a second,
derived string representation that could drift from the typed columns:

```sql
CREATE UNIQUE INDEX incidents_active_host
  ON incidents (tenant_id, target_addr, direction, address_family)
  WHERE target_type = 'host'
    AND state NOT IN ('resolved', 'closed');

CREATE UNIQUE INDEX incidents_active_network
  ON incidents (tenant_id, target_network, direction, address_family)
  WHERE target_type = 'network'
    AND state NOT IN ('resolved', 'closed');

CREATE UNIQUE INDEX incidents_active_hostgroup
  ON incidents (tenant_id, target_hostgroup, direction)
  WHERE target_type = 'hostgroup'
    AND state NOT IN ('resolved', 'closed');
```

A **partial unique index** makes "two active incidents for one
correlation key" impossible at the database level. Without it, two
concurrent correlator instances — or one instance processing a
redelivered event during a retry — could each check "is there an active
incident?", both see none, and both insert. Enforcing it in application
code means enforcing it in a race. Enforcing it here means the second
insert fails loudly (`23505`) and the correlator retries into the update
path, per the operation matrix in
[ADR 0026](decisions/0026-phase5b-transaction-isolation.md).

Suppression is three columns — `suppressed_until`, `suppression_reason`,
`suppressed_by` — and **not** a state, per
[ADR 0014](decisions/0014-incident-state-machine.md). The `CHECK` above
makes a suppression without a reason unrepresentable; the mandatory
expiry is enforced at the command boundary because it is a policy bound
rather than a data invariant.

Supporting indexes: `(tenant_id, state, opened_at DESC)` for the default
queue view; `(tenant_id, suppressed_until) WHERE suppressed_until IS NOT
NULL` so an alerting consumer can find live suppressions cheaply; `(tenant_id, assigned_user_id) WHERE state <> 'closed'`;
`(tenant_id, target_id)`; `(tenant_id, closed_at DESC)` for reopen-window
lookups; GIN on `tags`.

### `incident_detection_events`

The link table. One row per detection event associated with an incident.

```text
PRIMARY KEY (incident_id, detection_event_id)
UNIQUE (tenant_id, dedup_key)      -- the duplicate gate
INDEX (incident_id, observed_at DESC)
FOREIGN KEY (tenant_id, incident_id)
  REFERENCES incidents (tenant_id, incident_id) ON DELETE CASCADE
```

**References an incident:** yes, every row belongs to exactly one
incident; a cross-tenant `(tenant_id, incident_id)` pair is rejected by
the database, not only by the correlator's own tenant-scoped queries.

The `UNIQUE (tenant_id, dedup_key)` constraint is how at-least-once
delivery becomes effectively-once *processing*. Phase 4's `dedup_key` is
`{detection_id}:{kind}:{sequence}` with a gapless sequence, so redelivery
is exactly detectable. The correlator does not need to ask "have I seen
this?" — it inserts, and a unique violation *is* the answer.

Columns store the correlation-relevant fields, not the whole event: the
authoritative copy stays in ClickHouse. Stored here: `detection_event_id`,
`dedup_key`, `detection_id`, `policy_id`, `policy_version`, `kind`,
`severity`, `observed_at`, `detected_at`, `matched` (JSONB), `rates`
(JSONB), `link_type` (`opening`, `update`, `closing`, `late`, `evidence`).

### `incident_timeline`

Append-only. No `UPDATE`, no `DELETE` — enforced by a revoked grant, not
just convention, so an application bug cannot rewrite history.

```text
PRIMARY KEY (timeline_id)
INDEX (incident_id, occurred_at, timeline_id)
FOREIGN KEY (tenant_id, incident_id)
  REFERENCES incidents (tenant_id, incident_id) ON DELETE CASCADE
```

**References an incident:** yes, every timeline entry belongs to exactly
one incident, tenant-checked at the database layer.

`timeline_id` is `BIGINT GENERATED ALWAYS AS IDENTITY`
([ADR 0027](decisions/0027-phase5b-durable-record-identity.md)) — not a
saturating in-memory counter, closing **FU-39** for this table.
`occurred_at` and `recorded_at` are both `timestamptz`, sourced from
`transaction_timestamp()` ([ADR 0031](decisions/0031-phase5b-durable-time.md)):
`occurred_at` is when the transition was decided, `recorded_at` is when
this row was durably written — normally identical, distinguished for a
late-linked event where "when the event happened" and "when we found out"
genuinely differ. This closes **FU-35** ("Timeline and audit entries
carry no timestamp") for the timeline table.

Fields: `timeline_id`, `incident_id`, `tenant_id`, `occurred_at`,
`recorded_at`, `entry_type`, `actor_type` (`operator`, `system`, `service_account`),
`actor_id`, `correlation_id`, `command_id`, `source_event_id`,
`previous_value` (JSONB), `new_value` (JSONB), `payload` (JSONB),
`schema_version`.

Entry types: `opened`, `event_linked`, `state_changed`,
`severity_changed`, `priority_changed`, `assignment_changed`,
`note_added`, `note_superseded`, `note_redacted` (V17), `evidence_added`, `recovery_detected`,
`recovery_aborted`, `resolved`, `closed`, `reopened`, `suppressed`,
`unsuppressed`, `duplicate_ignored`, `late_event_linked`,
`correlation_decision`, `category_changed`, `limit_reached`,
`persistence_retry`, plus reserved `notification_result` and
`mitigation_result` that nothing writes in Phase 5.

### `incident_notes`

Notes are **immutable with supersession**, not editable in place. An
edited note destroys the record of what the operator originally believed,
which during a post-mortem is often the interesting part.

```text
PRIMARY KEY (note_id)
UNIQUE (tenant_id, note_id)        -- candidate key for the tenant-aware
                                    -- self-reference below
INDEX (incident_id, created_at DESC)
FOREIGN KEY (tenant_id, incident_id)
  REFERENCES incidents (tenant_id, incident_id) ON DELETE CASCADE
FOREIGN KEY (tenant_id, supersedes_note_id)
  REFERENCES incident_notes (tenant_id, note_id)
```

**References an incident:** yes. The supersession self-reference is also
tenant-aware — a note cannot be recorded as superseding a note that
belongs to a different tenant, corrected from the original single-column
`FOREIGN KEY (supersedes_note_id) REFERENCES incident_notes(note_id)`,
which had no tenant check at all.

Editing writes a new row with `supersedes_note_id` set; the superseded
row gets `superseded_at` and `superseded_by`. The API returns only
current notes by default and the full chain on request. Deleting is
soft — `redacted_at`, `redacted_by`, `redaction_reason`, body replaced —
because a note may contain something that genuinely must be removed, and
that removal must itself be auditable.

`visibility` is `internal` or `customer_visible`. **Phase 5 stores the
field and refuses to set `customer_visible`**, returning `501`, because
there is no customer-facing surface and no tenant authorization model to
decide who may publish to one. Storing the column now avoids a migration
later; honouring it now would be shipping an unreviewed disclosure path.

### `incident_number_allocators`

New table, added 2026-08-24 to support the
[ADR 0013 amendment](decisions/0013-incident-identity.md#phase-5b-resolution-incident-number-format-2026-08-24)
resolving **FU-24**: the incident number is a continuous per-tenant
sequence, not year-scoped. One row per tenant holds the current counter.

```text
PRIMARY KEY (tenant_id)
```

**References an incident:** no, deliberately. One row per tenant, not
per incident — the row exists before, during, and after any single
incident's lifetime, and outlives every incident that has ever consumed
a number from it. There is no `incident_id` column to reference: this
table's whole purpose is to hand out an `incident_id`-independent counter
value **before** the row that would consume it exists.

Allocation reads the row with `SELECT ... FOR UPDATE`, checks the
increment (refuses rather than silently repeating a number at
exhaustion, matching every other counter in this design), and writes the
new value back inside the same transaction that creates the incident —
this durably replaces Phase 5A's `InMemoryNumberAllocator`
(process-local, resets on restart) behind the same `NumberAllocator`
trait it already defines.

### `incident_policy_references`

New table, added 2026-08-24. Phase 5A's in-memory `policy_refs` is a
`Vec` capped at 64 distinct policies per incident with **silent
omission** past the cap (no counter, no flag, no timeline record) — this
task's instruction is explicit that silent omission is unacceptable for
durable persistence.

```text
PRIMARY KEY (incident_id, policy_id)
FOREIGN KEY (tenant_id, incident_id)
  REFERENCES incidents (tenant_id, incident_id) ON DELETE CASCADE
```

**References an incident:** yes — corrected 2026-08-30 from a
single-column `FOREIGN KEY (incident_id) REFERENCES
incidents(incident_id)`, which could not detect a hand-crafted or buggy
row whose `tenant_id` disagreed with its `incident_id`'s actual owner.

Fields: `incident_id`, `tenant_id`, `policy_id`, `policy_version`,
`first_seen_sequence`, `last_seen_sequence`. A normalized relation has no
inherent per-incident cap — the operational query/export limit (if any
UI or API caps how many are *displayed*) is a separate, later concern
from persistence *correctness*. If a bound is still wanted for abuse
resistance, it is enforced with an explicit **omitted-count column** on
`incidents` (e.g. `policy_references_omitted_count`), incremented
instead of silently dropping a row past the bound — matching
`EvidenceLedger`'s existing accurate-omission pattern
(`observed_total`/`omitted_count`) rather than repeating the gap
[follow-ups.md FU-34](../development/follow-ups.md) already documents
for the in-memory version.

### `incident_assignments`, `incident_tags`

```text
PRIMARY KEY (assignment_id)  -- incident_assignments; BIGINT GENERATED
                              -- ALWAYS AS IDENTITY, append-only history
PRIMARY KEY (incident_id, tag)  -- incident_tags; set semantics
FOREIGN KEY (tenant_id, incident_id)
  REFERENCES incidents (tenant_id, incident_id) ON DELETE CASCADE
  -- on both tables
```

**References an incident:** yes, both tables — added 2026-08-30; no key
block existed here before this correction.

Assignment history is append-only, so "who owned this at 02:00?" is
answerable. The current assignment on the incident row is a denormalised
convenience, not the record.

### `incident_audit`

**References an incident:** no, deliberately, and this is not an
oversight — this table's `resource_type`/`resource_id` pair is
polymorphic by design (an incident, a note, a tenant-level setting,
whatever a future authorization decision needs to name), and a **denied**
command frequently has no incident at all, since denial can happen before
an incident is ever identified or created. A foreign key can target
exactly one parent table; forcing `incident_audit` to reference
`incidents` would either exclude every non-incident and every denied-
before-identification row, or require `resource_id` to be nullable and
the foreign key to be conditional — neither of which this generic audit
design intends. The absence of a foreign key here is also what makes
audit's own retention independent of `incidents`' retention possible (see
"Tenant-aware composite foreign keys" above and the retention table
below): with no `ON DELETE CASCADE` to inherit, an audit row is never at
risk of disappearing when its named incident eventually is.

Separate from the timeline. Records authorization decisions including
**denials**, which have no incident to attach to and therefore cannot
live on a timeline. `audit_id` is `BIGINT GENERATED ALWAYS AS IDENTITY`
([ADR 0027](decisions/0027-phase5b-durable-record-identity.md)), closing
**FU-39** for this table. `occurred_at` and `recorded_at` are both
`timestamptz` sourced from `transaction_timestamp()`
([ADR 0031](decisions/0031-phase5b-durable-time.md)), closing **FU-35**
for this table — same distinction as `incident_timeline`: when the
audited action happened versus when this row was durably written.
Fields: `audit_id`, `occurred_at`, `recorded_at`, `tenant_id`,
`actor_type`, `actor_id`, `action`, `resource_type`, `resource_id`,
`result` (`allowed`, `denied`, `error`), `reason`, `source_ip`,
`user_agent`, `request_id`, `trace_id`, `before` (JSONB), `after`
(JSONB), `schema_version`.

### Auditing a command that was denied

A denied command has no incident mutation, so it has no transaction to
ride along with — and it is exactly the record a security review needs.
Audit therefore has **two** write paths, and only one of them is the
mutation transaction:

| Path | When | Transaction |
|---|---|---|
| **In-transaction** | The command was authorized and mutated an incident | The same transaction as state, timeline, and outbox. If the audit write fails, the mutation rolls back |
| **Standalone** | Authorization denied, tenant mismatch, validation rejected, or the resource does not exist | Its own short transaction, committed independently, **before** the response is returned |

The standalone path must not be able to fail silently. If it cannot
commit, the request returns `503` rather than proceeding unaudited: a
denial that is not recorded is indistinguishable from one that never
happened, which is the whole value of the record.

The standalone path records what it can — actor, action, attempted
resource id, the tenant *of the caller*, result, and reason — and
deliberately **not** whether the target resource actually exists. Storing
that would rebuild, inside the audit log, the existence oracle the
404-not-403 rule exists to prevent.

Append-only, and `source_ip` and `user_agent` are recorded only where
they are trustworthy — behind a proxy that sets them, with the proxy
trusted. A forged `X-Forwarded-For` written into an audit log as fact is
worse than no field at all.

Tamper evidence — hash chaining each row to its predecessor — is
**deferred**, not dismissed. It is cheap to add later if the column is
reserved now, and the threat it addresses is an attacker who already has
database write access. Recorded as **FU-19**.

### `incident_idempotency`

```text
PRIMARY KEY (tenant_id, idempotency_key)
INDEX (expires_at)
```

Fields: `operation`, `resource_type`, `resource_id`,
`request_fingerprint` (hash of the canonicalised body),
`response_status`, `response_body_ref`, `created_at`, `expires_at`.
Retention 24 h by default. See
[ADR 0016](decisions/0016-incident-concurrency-and-idempotency.md).

**References an incident:** no, deliberately — same reasoning as
`incident_audit`. `resource_type`/`resource_id` is polymorphic (the
idempotency key covers any command, not only incident-mutating ones), so
a single foreign key cannot target one fixed parent table.

### `incident_outbox`

```text
PRIMARY KEY (outbox_id)
INDEX (status, available_at) WHERE status IN ('pending','retrying')
```

`outbox_id` is `BIGINT GENERATED ALWAYS AS IDENTITY`
([ADR 0027](decisions/0027-phase5b-durable-record-identity.md)), closing
**FU-39** for this table. Claim mechanics (`SELECT ... FOR UPDATE SKIP
LOCKED`, lease expiry, retry-then-dead-letter) are fixed in
[ADR 0033](decisions/0033-phase5b-transactional-outbox-and-dead-letter.md),
which also adds `locked_at`/`locked_by` fields for the claim lease.

Fields: `outbox_id`, `tenant_id`, `aggregate_type`, `aggregate_id`,
`aggregate_version`, `event_type`, `payload` (JSONB), `status`,
`attempts`, `available_at`, `locked_at`, `locked_by`, `last_error`,
`created_at`, `published_at`.

Consumers: the ClickHouse analytics exporter in Phase 5; notification in
Phase 6; mitigation in Phase 7. Phase 5 writes event types those later
phases will consume and publishes only the analytics ones. **Producing an
event nobody consumes is not implementing a notification** — it is
leaving the seam ADR 0011 requires.

**References an incident:** no, deliberately. `aggregate_type`/
`aggregate_id` is a generic outbox pattern by design — every aggregate
this system ever publishes an event for goes through this one table, not
only `Incident`. Today `aggregate_type` is always `'incident'` in
practice, but the schema does not hardcode that, so no foreign key to
`incidents` specifically is declared. Where `aggregate_type = 'incident'`,
the application is responsible for `aggregate_id` actually naming a real,
tenant-matching incident — this is an application-level invariant, not a
database-enforced one, consistent with this table's polymorphic design.

### `incident_dead_letter`

Events that failed repeatedly or could not be parsed. Holds the raw
payload, the failure reason, attempt count, and first/last seen. Never
auto-purged while unreviewed — a dead-letter row that ages out silently
is an incident nobody knows was missed.

**References an incident:** no, deliberately, and for a stronger reason
than `incident_outbox`'s own polymorphism — a dead-letter row exists
specifically because its payload **failed to process or failed to
parse**. A row that could not be parsed may not reliably contain a valid
`incident_id` at all; requiring a foreign key here would mean a
corrupted or malformed payload could itself fail to be recorded as
dead-lettered, defeating the table's entire purpose ("never auto-purged
while unreviewed" requires the row to exist unconditionally, not only
when it happens to reference a real incident).

## Durable time

Phase 5A's `Timestamp` pairs a monotonic `Instant` with a `SystemTime`,
and every reopen-window and suppression-expiry comparison uses the
**monotonic** half — deliberate in 5A, because `Instant` cannot go
backward under a wall-clock correction. `Instant` is process-local by
definition and **cannot be persisted or restored** across a process
restart, which persistence requires 5A did not.

**PostgreSQL's `transaction_timestamp()` is the authoritative decision
time** for every durable comparison this schema needs: reopen decisions,
suppression expiry, lifecycle timestamps, closure eligibility, and
`incident_timeline`/`incident_audit`'s `occurred_at`. Monotonic time
remains available only for process-local latency and timeout
measurement, never persisted. If a decision timestamp is earlier than
the persisted reference it is being compared against, the design does
**not** clamp silently, does **not** reopen, and does **not** create a
duplicate incident — it returns a structured clock-skew error and emits
a bounded metric. Full rationale, rejected alternatives, and the
skew-handling contract:
[ADR 0031](decisions/0031-phase5b-durable-time.md).

## Transaction boundaries

**Isolation:** Read Committed by default for every operation, with
correctness from constraints and explicit locks rather than a blanket
stronger isolation level — full operation-by-operation matrix (locks,
retryable `SQLSTATE`s, bounded retry counts) in
[ADR 0026](decisions/0026-phase5b-transaction-isolation.md).

The central rule:

> **A command is acknowledged only if the state change, its timeline
> entry, its audit record, and its outbox row all committed. One
> transaction, or none of it.**

Opening an incident, in one transaction:

1. Allocate `incident_number` from the per-tenant sequence.
2. `INSERT` the incident.
3. `INSERT` the link row for the opening event — unique violation here
   means a duplicate, so roll back and treat it as one.
4. `INSERT` timeline `opened` and `event_linked`.
5. `INSERT` audit.
6. `INSERT` outbox `incident.opened`.
7. `INSERT` the idempotency record.
8. Commit.

Linking an event to an existing incident, and every operator command,
follow the same shape: read with the expected version, mutate, append
timeline, append audit, enqueue outbox, record idempotency, commit.

ClickHouse export is **outside** the transaction, by design. It reads
committed outbox rows and publishes them. A ClickHouse outage therefore
delays analytics and never blocks or corrupts operational state — the
outbox is exactly the mechanism that buys that separation.

## Failure behaviour

| Failure | Behaviour |
|---|---|
| PostgreSQL unavailable | Reject commands with `503`; ingestion stops consuming and does not acknowledge; no partial state |
| ClickHouse unavailable | Outbox backs up; operational state unaffected; `outbox_pending` rises and is alerted |
| Queue full | Backpressure to ingestion; `503` on the API; never drop silently |
| Malformed event | Quarantine to dead-letter, increment `events_rejected_total` |
| Unsupported schema version | Quarantine; **never** guess at unknown fields |
| Duplicate event | Unique violation, counted, not an error |
| Late or out-of-order event | Linked as evidence, no state change |
| Version conflict | `409` with current version; never a silent overwrite |
| Audit write fails | **Whole transaction rolls back.** An unauditable mutation must not happen |
| Outbox publish fails | Retry with backoff; then dead-letter; operational state untouched |
| Service restart | Uncommitted work is lost by construction; the outbox is re-read from `pending` |
| Disk full | PostgreSQL rejects writes; commands fail closed |
| Clock skew | Never clamped silently, never reopens, never creates a duplicate incident on an unreliable comparison — structured error plus bounded metric. Ordering uses `BIGINT` identity ([ADR 0027](decisions/0027-phase5b-durable-record-identity.md)), decision time uses `transaction_timestamp()` ([ADR 0031](decisions/0031-phase5b-durable-time.md)), never client-supplied time |

Retries use exponential backoff with jitter, capped attempts, then
dead-letter. No infinite retry loop: a poison event that can never
succeed must stop consuming resources and become visible instead.

## Retention

| Data | Default | Notes |
|---|---|---|
| Open incidents | Indefinite | |
| Closed incidents | 24 months | Owner decision; not a legal claim |
| Timeline | Follows its incident | |
| Notes | Follows its incident | |
| Audit | 24 months minimum | Longer than incidents deliberately |
| Idempotency | 24 h | |
| Outbox published | 7 days | Then purged |
| Dead-letter | 90 days, **never while unreviewed** | |
| ClickHouse analytics | 365 days | Matches detection events |

**No legal or regulatory retention requirement is asserted here.** These
are engineering defaults. Anything contractual or regulatory needs formal
review — recorded as **FU-20**.

Tenant deletion must never cascade into audit. The design is: purge or
anonymise incident content, retain audit rows with the tenant reference
intact, and require an explicit, separately authorized, separately
audited operation to remove audit history. Accidental cascade from a
`DELETE FROM tenants` is exactly the failure this prevents.

## Tenant isolation

`tenant_id` is present on **every** table, including timeline, notes,
audit, idempotency, and outbox — not only on `incidents`. Isolation must
not depend on a join being written correctly every time.

Every query carries a tenant predicate, and repository interfaces should
make a tenant-less query **impossible to express** rather than merely
discouraged: the tenant context is a constructor argument, not a
parameter a caller can forget.

PostgreSQL Row-Level Security is the right long-term enforcement and is
**evaluated, not claimed**: it belongs with the Phase 8 tenancy work,
because it needs a per-tenant database role model that does not exist
yet. Phase 5 designs the schema so RLS can be switched on without a
migration — every table has `tenant_id`, and no table relies on a join to
establish tenancy. Recorded as **FU-21**, formalized as
[ADR 0032](decisions/0032-phase5b-tenant-isolation-and-rls-readiness.md),
which also fixes the Phase 5B defense-in-depth layers (composite
tenant-aware foreign keys, a separate migration role, an application
runtime role provisioned without `BYPASSRLS`) that apply before RLS
itself activates.
