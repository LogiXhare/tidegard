# 0016. Optimistic Concurrency and Fingerprinted Idempotency

Status: **Accepted** — 2026-10-05, as implemented (see [Acceptance](#acceptance))
Date: 2026-08-22
Deciders: Repository owner — accepted 2026-10-05 (Phase 5F) under the owner's standing delegation for Phase 5

## Context

Two operators work one incident during a live attack. A correlator
updates it from a detection event at the same moment. The API client
times out and retries a close it cannot tell succeeded. All three happen
routinely, and each can silently corrupt the record.

The failures to prevent, concretely:

- **Lost update.** Two operators read version 5; one sets severity to
  `critical`, the other assigns a team; last write wins and one change
  vanishes with no trace that it ever existed.
- **Duplicate effect.** A retried close produces two closures, two
  timeline entries, and two audit records for one human intention.
- **Silent divergence.** A retry reuses an idempotency key with a
  *different* body; the server replays the old response and the caller
  believes a change was applied that never was.

## Options Considered

### Concurrency options

**Option A — Last write wins.** Simple; silently destroys operator work.
Unacceptable for an audited system.

**Option B — Pessimistic locking (`SELECT ... FOR UPDATE`).** Correct, but
a lock held across an operator's think-time blocks the correlator; a lock
held only across the write does not prevent the lost update at all.

**Option C — Optimistic concurrency on a version integer.** No locks held
across think-time; the conflict is detected and reported; the loser
re-reads and decides. Costs a round trip and requires clients to handle
`409`.

### Idempotency options

**Option D — None.** Retries duplicate effects.

**Option E — Key only.** Same key returns the stored response. Fails the
"same key, different body" case by silently discarding the new request.

**Option F — Key plus request fingerprint.** Same key and same
fingerprint replays; same key and *different* fingerprint is a conflict.

## Decision

**Option C for concurrency, Option F for idempotency.**

### Concurrency

Every incident carries an integer `version`, incremented on every
mutation. Commands that change state or a safety-relevant field must
supply `expected_version`; a mismatch is `409` carrying the current
version and state, never a silent overwrite.

Required: state transitions, severity, priority, assignment, closure,
reopen, suppress. Not required: notes and tags, which are append-only or
set-semantic and cannot meaningfully conflict.

**Correlator writes do not use `expected_version`.** They re-read and
re-decide on conflict, because the correct response to "the incident
changed under me" is to re-evaluate the correlation decision against the
new state, not to force through a decision made against stale state. An
event that arrives while an operator is closing an incident should link
as evidence, not reopen it by winning a race.

### Idempotency

`Idempotency-Key` is **required** for state transitions and optional
elsewhere. Each record stores a `request_fingerprint` — a hash of the
canonicalised body plus operation and resource.

| Case | Result |
|---|---|
| Same key, same fingerprint, completed | Replay stored response, `200` |
| Same key, same fingerprint, in flight | `409 incident.request_in_progress` |
| Same key, different fingerprint | `409 incident.idempotency_key_reuse` |
| New key | Process normally |

The third row is the decision that matters. Returning the old response
for a different request is worse than an error: the caller is told their
change succeeded when it was never applied.

Records are scoped `(tenant_id, idempotency_key)` and expire after 24
hours. Keys need at least 128 bits of entropy, 16–255 characters.

**Idempotency keys are not credentials.** Knowing one grants no access;
they are never accepted in place of authentication, never used as
authorization, and never treated as secrets in logs — they are logged as
correlation identifiers, which is what they are.

### Ingestion idempotency

Detection-event ingestion does not use client-supplied keys. It uses
Phase 4's `dedup_key` and the `UNIQUE (tenant_id, dedup_key)` constraint,
so the consumer inserts rather than checking-then-acting, and a unique
violation *is* the duplicate detection. See
[ADR 0012](0012-incident-event-ingestion.md).

## Consequences

**Easier.** No operator's change is silently discarded. Retries are safe,
which means clients and the CLI can retry aggressively on timeout without
reasoning about partial effects. Conflicts surface as structured,
actionable errors carrying the current state.

**Harder.** Clients must handle `409` and re-read; the CLI must generate
and reuse keys per logical command. Two extra columns and a table. An
extra round trip on conflict.

**Forecloses.** Little. Adding pessimistic locking later for a specific
hot path remains possible.

**Security.** Prevents unauthorized silent overwrites. The
different-fingerprint rejection prevents an attacker replaying a captured
key with modified content. Bounded key length prevents storage abuse
through crafted keys. Covered by threat-model entries T-13 and T-14.

**Operational.** `tidegard_incident_command_conflicts_total` is a
real signal: a sustained rise means either an integration retrying
incorrectly or two operators repeatedly colliding, and both are worth
knowing.

## Acceptance

Accepted as implemented in Phase 5, with two differences:

- **There is no in-flight state.** An idempotency record commits in the
  same transaction as the change it records. A retry therefore finds
  either no record, because the change did not happen, or the completed
  one. `incident.request_in_progress` was never needed and is not in the
  [error registry](../../api/error-codes.md).
- **The conflict metric does not exist yet.**
  `tidegard_incident_command_conflicts_total` has not been built,
  because the API exports no metrics in Phase 5.

Keys are 16–255 characters and are kept for 24 hours, as decided, and
each record is tenant-scoped.

## Follow-Up

- [x] Document `409` handling in the
      [API plan](../incident-api-plan.md) and
      [CLI plan](../incident-cli-plan.md).
- [x] Tests: same key and body returns the same result; same key
      and different body conflicts (`domain_end_to_end.rs`, the API's `transitions.rs`) —
      [testing plan](../incident-testing-plan.md).
- [ ] Decide whether idempotency retention should be configurable per
      tenant.
