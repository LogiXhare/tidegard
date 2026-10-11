# 0012. Detection-Event Ingestion: Transactional Outbox, At-Least-Once

Status: **Accepted** — 2026-10-05, as amended by ADR 0031 and ADR 0035 (see [Acceptance](#acceptance))
Date: 2026-08-22
Deciders: Repository owner — accepted 2026-10-05 (Phase 5F) under the owner's standing delegation for Phase 5

## Context

[ADR 0011](0011-incident-domain-boundary.md) separates the detection and
incident domains. That separation needs a delivery mechanism, and the
choice determines what Phase 5 can promise about not losing incidents.

The requirement that rules out the easy answer: **a detection event must
not be lost because the incident manager was restarting.** A missed
`Started` event means an attack with no incident, which is the single
worst failure this system can have. It is worse than a duplicate, worse
than a delay, and worse than a crash — all of which are recoverable.

[ADR 0004](0004-collector-aggregator-event-transport.md) faced a similar
question in Phase 3 and chose an in-process channel, deferring NATS until
a component needed independent scaling. That precedent is relevant but
not binding: Phase 3's channel carried *aggregatable* flow records where
losing one costs a rounding error. Phase 5 carries *events* where losing
one costs an incident.

## Options Considered

### Option A — In-process bounded channel

- Pros: zero new dependencies; matches ADR 0004; lowest latency; simplest.
- Cons: **not durable.** A restart between detection and correlation
  loses the event permanently. No replay. No recovery.

### Option B — Transactional outbox in PostgreSQL

The detector's event sink writes to an outbox table; a correlation worker
reads, processes, and marks complete.

- Pros: durable; survives restart; replayable; no new infrastructure
  because PostgreSQL is already required for incidents
  ([ADR 0015](0015-incident-operational-storage.md)); the write can share
  a transaction with the consumer's state change; ordering per
  correlation key is achievable; visible and debuggable with SQL.
- Cons: polling latency (mitigated by `LISTEN`/`NOTIFY`); throughput
  bounded by PostgreSQL; the outbox table needs its own retention.

### Option C — NATS JetStream

- Pros: durable; designed for this; already the recorded direction in
  ADR 0004; scales to multi-node.
- Cons: **a new piece of infrastructure to deploy, secure, monitor, and
  back up** for a single-node release; two durable stores that can
  disagree; the outbox pattern is still needed to write to NATS
  atomically with the database, so it does not remove complexity so much
  as add a hop.

### Option D — Redpanda or Kafka

- Pros: highest throughput; strong ordering; mature replay.
- Cons: substantially heavier than a single-node release justifies;
  significant operational burden; same atomicity problem as C.

### Option E — Database polling of ClickHouse detection events

- Pros: no new table; events are already there.
- Cons: ClickHouse is analytical, not a queue — no per-row acknowledgment,
  no locking, no efficient "unprocessed" cursor; eventual-consistency
  semantics make exactly-tracking-a-cursor unreliable; couples incident
  progress to an analytics store that is explicitly non-authoritative.

### Option F — Direct synchronous call

- Pros: simplest possible; no queue.
- Cons: puts a database transaction on the detector's tick path, which
  ADR 0011 exists to prevent; a slow or unavailable incident manager
  applies backpressure to *detection*; no durability if the call fails.

## Decision

**Option B: a transactional outbox in PostgreSQL, with at-least-once
delivery**, for the single-node Phase 5 release. NATS JetStream (Option C)
remains the recorded direction for when correlation must scale beyond one
node — the same narrowing ADR 0004 applied, for the same reason.

### Delivery semantics, stated honestly

**At-least-once. Not exactly-once.** Exactly-once delivery across a
process boundary is not achievable without a distributed transaction, and
claiming it would be false. What Phase 5 provides instead is
**at-least-once delivery with effectively-once processing**, achieved by
idempotent consumption:

- Phase 4's `dedup_key` is `{detection_id}:{kind}:{sequence}` with a
  gapless sequence, so a redelivery is *exactly* identifiable rather than
  heuristically guessed.
- `UNIQUE (tenant_id, dedup_key)` on `incident_detection_events` makes
  the second processing attempt fail at the database rather than in a
  race.
- The consumer therefore does not check-then-act. It acts, and a unique
  violation is the duplicate answer.

The design must **expect** duplicates and delays as normal operation, not
as errors.

### Mechanics

| Concern | Design |
|---|---|
| Ingestion identity | `detection_event_id` |
| Idempotency key | `dedup_key` |
| Ordering key | `correlation_key`; ordered per key, not globally |
| Ordering enforcement | Per-key serialisation in the worker; `observed_at_ms` decides lateness |
| Retry | Exponential backoff with jitter, capped attempts |
| Poison event | After the cap, move to `incident_dead_letter`, alert, keep consuming |
| Dead letter | Retained 90 days; **never auto-purged while unreviewed** |
| Replay | Re-run from the outbox; idempotent consumption makes it safe |
| Schema compatibility | Unknown `schema_version` is quarantined, never guessed |
| Backpressure | Bounded in-memory batch; the outbox itself is the buffer |
| Queue limit | Outbox depth alerted via `outbox_pending`; PostgreSQL applies the real bound |
| Shutdown drain | Finish the in-flight batch, commit, stop claiming; uncommitted work stays `pending` |

Global ordering is deliberately not promised. Two unrelated incidents in
different tenants have no meaningful order, and promising one would
serialise the whole worker for no benefit.

## Consequences

**Easier.** Events survive restarts. Replay is a SQL query. Debugging is
`SELECT * FROM incident_outbox WHERE status = 'pending'`. No new
infrastructure. The outbox that ingests detection events is the same
mechanism that later feeds notification and mitigation.

**Harder.** Polling latency, mitigated with `LISTEN`/`NOTIFY` but not
eliminated. The outbox needs retention management. Throughput is bounded
by PostgreSQL, which is ample for incident rates and would not be for
flow rates — this mechanism is correct precisely because incidents are
thousands per day, not millions per second.

**Forecloses.** Nothing important. Moving to NATS later means changing
the producer and consumer while the idempotent-consumption design stays
identical.

**Security.** The outbox holds detection data including target addresses,
so it inherits tenant scoping and retention. Dead-letter rows may hold
malformed input and must never be executed, interpolated, or rendered.

**License.** No new dependency beyond the PostgreSQL driver already
implied by [ADR 0015](0015-incident-operational-storage.md) — see BQ-7.

**Operational.** Two new alerts: outbox depth, and dead-letter count
above zero.

## Acceptance

The decision stands: at-least-once delivery, effectively-once processing,
and `UNIQUE (tenant_id, dedup_key)` as the duplicate answer. Later ADRs
changed three mechanics.

- **The detection side is an inbox, not an outbox.** The detector has no
  database transaction to write an outbox row in. Events reach
  `detection_event_inbox` through a bounded, non-blocking sink
  ([ADR 0035](0035-phase5c-detection-event-inbox.md)), which states its
  small loss window plainly. `incident_outbox` carries the incident
  domain's own events ([ADR 0033](0033-phase5b-transactional-outbox-and-dead-letter.md)).
- **Lateness is not decided by `observed_at_ms`.** Decisions use the
  database's time ([ADR 0031](0031-phase5b-durable-time.md)). Whether an
  event is late news about a resolved incident is decided by detection
  identity: an `Ended` event, or an event of an episode the incident
  already holds, links as evidence and never reopens (threat T-18).
- **Consumers poll.** `LISTEN`/`NOTIFY` is not used yet.

The two alerts the decision calls for exist as the `outbox_pending` and
`dead_letter_pending` gauges.

## Follow-Up

- [x] **BQ-7** — dependency approval.
- [ ] Revisit when correlation needs more than one node; NATS is the
      recorded direction (ADR 0004).
- [x] Runbook entries for outbox backlog and dead-letter review —
      [incident runbook](../../operations/incident-runbook.md).
