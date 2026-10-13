# Incident Observability

Status: **Planning, partly implemented.** Part of the
[Phase 5 plan](phase5-incident-management-plan.md).

**Implemented so far (Milestone 5C, [ADR 0036](decisions/0036-phase5c-incident-manager-process.md)):**
the incident manager serves `inbox_pending`, `outbox_pending` and
`dead_letter_pending`; `inbox_events_total{result}` and
`inbox_batches_total{result}` for the correlation worker (the
per-outcome `events_ingested_total` is FU-52); `clock_skew_total`
(ADR 0031); `maintenance_transitions_total{transition}` and
`maintenance_incident_failures_total` for the timers;
`retention_deleted_total{table}`; and `job_runs_total{job,result}`. Every
label value is on the allowlist in `crates/incident-manager/src/metrics.rs`,
which a test enforces. The rest of this page is still the plan.

## Metrics

Prefix `tidegard_incident_*`, matching the
`tidegard_<component>_*` convention that ADR 0009's naming decision
established and that Phase 4's `tidegard_detector_*` follows.

### Counters

| Metric | Labels |
|---|---|
| `tidegard_incident_events_ingested_total` | `result` |
| `tidegard_incident_events_duplicate_total` | — |
| `tidegard_incident_events_late_total` | — |
| `tidegard_incident_events_rejected_total` | `reason` |
| `tidegard_incident_events_quarantined_total` | `reason` |
| `tidegard_incidents_opened_total` | `severity`, `category` |
| `tidegard_incidents_acknowledged_total` | `severity` |
| `tidegard_incidents_resolved_total` | `severity`, `result` |
| `tidegard_incidents_closed_total` | `severity`, `closure_reason` |
| `tidegard_incidents_reopened_total` | `severity` |
| `tidegard_incidents_suppressed_total` | `severity` |
| `tidegard_incident_state_transitions_total` | `from`, `to`, `actor_type` |
| `tidegard_incident_command_conflicts_total` | `command`, `reason` |
| `tidegard_incident_commands_total` | `command`, `result` |
| `tidegard_incident_authz_denied_total` | `permission` |
| `tidegard_incident_repository_failures_total` | `operation` |
| `tidegard_incident_audit_failures_total` | — |
| `tidegard_incident_outbox_published_total` | `event_type`, `result` |
| `tidegard_incident_outbox_failures_total` | `event_type` |
| `tidegard_incident_dead_letter_total` | `reason` |
| `tidegard_incident_limit_reached_total` | `limit` |

### Gauges

| Metric | Labels |
|---|---|
| `tidegard_incidents_active` | `state`, `severity` |
| `tidegard_incidents_unassigned` | `severity` |
| `tidegard_incident_outbox_pending` | — |
| `tidegard_incident_dead_letter_pending` | — |
| `tidegard_incident_inbox_pending` | — |
| `tidegard_incident_timeline_pressure` | — |
| `tidegard_incident_oldest_unacknowledged_seconds` | `severity` |

### Histograms

| Metric | Labels |
|---|---|
| `tidegard_incident_correlation_duration_seconds` | `outcome` |
| `tidegard_incident_command_duration_seconds` | `command` |
| `tidegard_incident_detection_to_open_seconds` | `severity` |
| `tidegard_incident_time_to_acknowledge_seconds` | `severity` |
| `tidegard_incident_time_to_resolve_seconds` | `severity` |
| `tidegard_incident_time_to_close_seconds` | `severity` |

### Cardinality

Every label is a **closed set**, following the discipline Phase 4 applied
to `tidegard_detector_*`:

| Label | Values |
|---|---|
| `state`, `from`, `to` | 7 |
| `severity` | 4 |
| `priority` | 4 |
| `category` | 10 |
| `actor_type` | 3 |
| `result`, `outcome` | small fixed sets |
| `command` | ~18 |
| `closure_reason` | 6 |
| `permission`, `limit`, `reason`, `operation`, `event_type` | fixed enumerations |

**Never a label:** incident ID, incident number, event ID, **tenant ID**,
policy ID, host address, prefix, user ID, team ID, customer name, or note
content. Tenant deserves emphasis — it looks bounded and is not: a
managed-service deployment adds tenants over time, multiplying every
series by a number that only grows. Per-tenant figures belong in
ClickHouse, which is built for exactly that.

Because critical incidents never auto-close (BQ-8), a
resolved-but-unclosed backlog is now an expected steady state rather than
an anomaly. `tidegard_incidents_active{state="resolved"}` is what
makes it visible, and the alert above is what stops it becoming a place
incidents go to be forgotten.

`tidegard_incident_timeline_pressure` exists because the timeline is
never truncated: it reports the largest timeline size so an operator is
alerted before an incident becomes unmanageable, rather than discovering
it when a query times out.

## Structured logging

JSON via `tracing`, matching the existing crates.

| Field | Notes |
|---|---|
| `timestamp`, `level`, `service` | Always |
| `incident_id`, `incident_number` | When known |
| `tenant_id` | Always — safe in logs, forbidden as a metric label |
| `detection_event_id`, `dedup_key` | Ingestion paths |
| `command`, `command_id`, `idempotency_key` | Command paths |
| `actor_type`, `actor_id` | Command paths |
| `request_id`, `trace_id`, `correlation_id` | Always |
| `previous_state`, `next_state` | Transitions |
| `result`, `reason` | Always on completion |
| `repository_version` | Mutations |
| `duration_ms` | Completed operations |

Levels:

| Level | Use |
|---|---|
| `ERROR` | Storage unavailable, audit write failure, dead-letter |
| `WARN` | Conflicts, rejected events, limits reached, authorization denials |
| `INFO` | Incident opened, state changed, assignment, closure |
| `DEBUG` | Correlation decisions, duplicates, late events |
| `TRACE` | Per-event detail; off in production |

### Never logged

- Credentials, tokens, API keys, database passwords.
- **Note bodies at `INFO`.** A note may contain customer-identifying
  detail; log the note ID and length instead. `DEBUG` may include a
  prefix only where the deployment has accepted that.
- Complete raw detection payloads — the ID and correlation key suffice.
- `Authorization`, `Cookie`, or `Idempotency-Key` headers as if
  sensitive. The key *is* logged as a correlation identifier, which is
  what it is, and it is not a credential.
- Unnecessary customer PII.

Log injection is prevented by structured JSON with escaped values, never
string concatenation. Operator-supplied text — notes, reasons, tags — is
a JSON *value*, so a newline in a note cannot forge a log line.

## Capacity

Limits and their behaviour on breach, from the
[domain model](incident-domain-model.md):

| Limit | Default | On breach |
|---|---|---|
| Open incidents per tenant | 10 000 | Refuse new, alert; **never evict** |
| Total incidents per tenant | Unbounded, retention-managed | — |
| Linked events per incident | 10 000 | Stop linking, keep counting |
| Timeline entries | 50 000 | **Never truncate**; alert |
| Notes per incident | 500 | Reject |
| Note body | 16 000 chars | Reject |
| Tags | 32 | Reject |
| Affected targets | 256 | Stop adding, keep counting |
| Correlation candidates | 1 | Partial unique index guarantees it |
| Page size | 200 | Clamp server-side |
| Export | 10 000 incidents | Reject with a narrower-filter hint |
| Ingestion batch | 500 | Backpressure |
| Outbox batch | 200 | — |
| Concurrent commands per incident | 1 writer | Optimistic conflict |

The open-incident limit **refuses rather than evicts**, exactly as Phase
4's state table does. Evicting an open incident would discard operator
work and audit history to satisfy a memory bound, converting a capacity
problem into a data-loss problem. Refusing is visible, alertable, and
recoverable.

## Alerts

| Alert | Condition |
|---|---|
| Outbox backlog | `outbox_pending` > 1 000 for 10 min |
| Dead letter | `dead_letter_pending` > 0 |
| Audit failure | `audit_failures_total` increases at all |
| Storage failures | `repository_failures_total` rate > 0 for 5 min |
| Ingestion stalled | `events_ingested_total` flat while detections continue |
| Unacknowledged critical | `oldest_unacknowledged_seconds{severity="critical"}` > 900 |
| Resolved criticals awaiting closure | `incidents_active{state="resolved",severity="critical"}` > 0 for 24 h |
| Limit pressure | `limit_reached_total` increases |
| Conflict storm | `command_conflicts_total` rate spikes |

"Audit failure increases at all" is deliberately a zero-tolerance
threshold: an audit write failure rolls back the whole transaction, so
each occurrence is a mutation that could not be recorded and therefore
did not happen. That is worth waking someone.
