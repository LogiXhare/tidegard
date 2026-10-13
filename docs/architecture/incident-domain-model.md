# Incident Domain Model

Status: **Planning only.** Part of the
[Phase 5 plan](phase5-incident-management-plan.md). No code implements
this yet.

## Four things, not one

The most common way to get incident management wrong is to keep one
mutable row and call it the history. It is not: the moment an operator
changes the severity, the previous severity is gone, and the audit
question "who lowered this and when?" is unanswerable. Phase 5 therefore
splits the domain into four kinds of data with different mutability
rules.

| Kind | Mutability | Lifetime | Answers |
|---|---|---|---|
| **Incident identity** | Immutable after creation | Forever | Which incident is this? |
| **Incident current state** | Mutable, versioned | Until closed | What is true right now? |
| **Timeline** | Append-only | Forever | What happened, in order? |
| **Audit** | Append-only, separate store | Retention-bound | Who did what, and were they allowed? |

Timeline and audit overlap but are not the same. The timeline is the
operational narrative an engineer reads during a post-mortem; the audit
log is the security record of *authorization decisions*, including the
ones that were **denied**. A denied cross-tenant read never appears on
any incident timeline — there is no incident to attach it to — but it is
exactly what a security review needs. See
[the security model](incident-security-model.md).

## Incident fields

Legend: **I** immutable after creation · **M** mutable via a command ·
**D** derived, never directly settable · **O** optional/nullable.

### Identity and classification

| Field | Kind | Type | Notes |
|---|---|---|---|
| `incident_id` | I | see [ADR 0013](decisions/0013-incident-identity.md) | Internal, database and API |
| `incident_number` | I | `TEXT` | Human-readable, tenant-scoped, e.g. `WNM-2026-000123` |
| `schema_version` | I | `INTEGER` | Starts at 1, independent of the detection schema version |
| `tenant_id` | I | `TEXT` | From `event.target.tenant`. Never mutable — moving an incident between tenants is a security hole, not a feature |
| `correlation_key` | I | `TEXT` | The deterministic key; see [correlation](incident-correlation.md) |
| `title` | D then M | `TEXT` ≤ 200 | Seeded from `event.summary`, editable |
| `description` | M, O | `TEXT` ≤ 8 000 | Free text |
| `category` | D | `TEXT` | Derived from crossed metrics; **not** a Phase 4 field |
| `address_family` | I | `SMALLINT` | 4 or 6 |
| `direction` | I | `TEXT` | `incoming`, `outgoing`, `internal` |
| `target_type` | I | `TEXT` | `host`, `prefix`, `slash24`, `hostgroupTotal` |
| `target_id` | I | `TEXT` | Canonical form of `scope_id` |
| `target_display` | I | `TEXT` ≤ 128 | From `event.target.display` |

### State and priority

| Field | Kind | Type | Notes |
|---|---|---|---|
| `state` | M | `TEXT` | See [state machine](incident-state-machine.md) |
| `severity` | D then M | `TEXT` | `info`, `minor`, `major`, `critical` — Phase 4's four values exactly |
| `severity_source` | D | `TEXT` | `detection` or `operator`, so an operator override is never silently re-overwritten by the next event |
| `priority` | M, O | `TEXT` | `P1`–`P4`, NOC-assigned, defaulted from severity |
| `closure_reason` | M, O | `TEXT` | Required when closing; see state machine |
| `state_before_recovering` | D, O | `TEXT` | Restored when a recovery aborts |
| `suppressed_until` | M, O | `TIMESTAMPTZ` | Suppression expiry; **mandatory when suppressing** |
| `suppression_reason` | M, O | `TEXT` ≤ 500 | Mandatory alongside `suppressed_until` |
| `suppressed_by` | M, O | `TEXT` | Actor reference |
| `version` | D | `BIGINT` | Optimistic concurrency; increments on every mutation |

**Suppression is an attribute, not a lifecycle state** — decided
2026-08-22, [ADR 0014](decisions/0014-incident-state-machine.md). It
governs whether an incident *alerts*, not where the human response has
reached, so it is orthogonal to `state` and both are independently
queryable. `suppressed` is derived — `suppressed_until IS NOT NULL AND
suppressed_until > now()` — rather than stored, so a suppression cannot
outlive its own expiry through a sweep that failed to run.

Severity and priority are **not** the same field. Severity is the
technical impact of the traffic; priority is how urgently a human should
deal with it. A `critical` flood against a decommissioned lab prefix can
legitimately be `P4`, and a `minor` anomaly against a payment gateway can
be `P1`. Collapsing them is the mistake that makes NOC teams stop
trusting the queue. Default mapping, overridable per-incident:

| Severity | Default priority |
|---|---|
| `critical` | `P1` |
| `major` | `P2` |
| `minor` | `P3` |
| `info` | `P4` |

### Timestamps

All `TIMESTAMPTZ`, all set from an injectable clock, never from
`now()` inside application code that tests cannot control.

| Field | Kind | Set when |
|---|---|---|
| `first_detected_at` | I | Earliest `detected_at_ms` of any linked event |
| `opened_at` | I | Incident created |
| `last_detected_at` | D | Latest linked event, monotonic — never moves backwards |
| `last_updated_at` | D | Any mutation |
| `acknowledged_at` | M, O | First acknowledgement |
| `recovering_since` | M, O | Entered `Recovering` |
| `resolved_at` | M, O | Entered `Resolved` |
| `closed_at` | M, O | Entered `Closed` |
| `reopened_at` | M, O | Most recent reopen |
| `reopen_count` | D | Times reopened |

### Ownership and context

| Field | Kind | Type | Notes |
|---|---|---|---|
| `assigned_user_id` | M, O | `TEXT` | Opaque directory reference, not an email |
| `assigned_team_id` | M, O | `TEXT` | Opaque |
| `customer_id` | D, O | `TEXT` | Enrichment; not a Phase 4 field |
| `site_id` | D, O | `TEXT` | Enrichment |
| `datacenter_id` | D, O | `TEXT` | Enrichment |
| `created_by` | I | `TEXT` | Actor reference; `system:correlator` for automatic creation |
| `updated_by` | D | `TEXT` | Last mutating actor |

`customer_id`, `site_id`, and `datacenter_id` do not exist in the Phase 4
event. They are incident-domain enrichment looked up from tenant
configuration at open time. Phase 5 may leave all three `NULL` and still
be complete; the columns exist so Phase 6 reporting is not a migration.

### Evidence and metrics

| Field | Kind | Type | Notes |
|---|---|---|---|
| `current_metrics` | D | `JSONB` | Latest `MetricRates` |
| `peak_metrics` | D | `JSONB` | Worst-so-far, monotonic per metric |
| `baseline_metrics` | D, O | `JSONB` | **Always `NULL` in Phase 5** — Phase 4 has no baselining |
| `opening_reason` | I | `JSONB` | The `matched` list that opened the incident |
| `evidence_summary` | D | `JSONB` ≤ 16 KB | Bounded rollup; see below |
| `policy_refs` | D | `JSONB` | `[{policy_id, policy_version, first_seen, last_seen}]` |
| `detection_event_count` | D | `INTEGER` | Cheap count; the events themselves live in a child table |
| `mitigation_status` | I | `TEXT` | **Always `none` in Phase 5.** Placeholder for Phase 7 |
| `notification_status` | I | `TEXT` | **Always `none` in Phase 5.** Placeholder for Phase 6 |

`mitigation_status` and `notification_status` follow the same reasoning
as Phase 4's `executed` field: a consumer should be able to filter on
"nothing was done" without knowing which product version could have done
something. Like `executed`, they should be derived from an exhaustive
match over an enum with no acting variant, so a later phase that adds one
has to come to that function and say so.

### Bounds

Every collection is bounded. Unbounded growth on an incident row is how a
single sustained attack turns into a multi-megabyte JSONB blob that
breaks every list query.

| Thing | Limit | On exceeding |
|---|---|---|
| `title` | 200 chars | Reject the command (400) |
| `description` | 8 000 chars | Reject |
| Note body | 16 000 chars | Reject |
| Notes per incident | 500 | Reject, `incident.limit.notes` |
| Tags per incident | 32 | Reject |
| Tag key / value | 64 / 256 chars | Reject |
| Linked detection events | 10 000 | Stop linking, keep counting, emit `incident.limit.events` |
| Affected targets | 256 | Stop adding, keep counting |
| `evidence_summary` | 16 KB | Roll up oldest into a count |
| Timeline entries | 50 000 | **Never truncated.** Alert instead — see below |
| `policy_refs` | 64 | Stop adding, keep counting |

Two of these deliberately behave differently from the rest, and the
difference matters:

- **Linked events and affected targets stop growing but keep counting.**
  Losing the ten-thousand-and-first event reference costs a little
  evidence detail; the incident is still correct.
- **The timeline is never truncated.** It is the audit narrative. If an
  incident reaches 50 000 timeline entries, something is wrong
  operationally — a flapping detection, most likely — and the answer is
  an alert on `tidegard_incident_timeline_pressure`, not silent data
  loss. Truncating audit-bearing content to stay inside a limit converts
  a capacity problem into an integrity problem, which is the same
  reasoning that made Phase 4's state table *refuse* rather than evict.

## What is not on the incident

- **Raw packet captures or any large binary.** Evidence rows hold
  *references*; the bytes live elsewhere. Storage for them is out of
  scope for Phase 5.
- **Credentials, tokens, or API keys.** Ever.
- **Full note bodies in log lines.** See
  [observability](incident-observability.md).
- **Detector runtime state.** That is deliberately ephemeral and stays in
  the detector; see ADR 0010.
