# Incident API — Reference Plan

Status: **Planning only.** Nothing here is implemented. Design rationale
is in
[incident-api-plan.md](../architecture/incident-api-plan.md); this page
holds concrete schemas and a draft specification for review.

The OpenAPI below is embedded as a fenced block rather than shipped as a
standalone `.yaml`, deliberately: a spec file in the repository is the
kind of artefact that gets fed to a code generator, and Phase 5 is not
implementing anything. It becomes a real file at Milestone 5D.

## Representations

### Incident

```json
{
  "incident_id": "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d",
  "incident_number": "WNM-2026-000123",
  "schema_version": 1,
  "tenant_id": "wetechi",
  "title": "critical incoming bandwidth on 203.0.113.7",
  "description": null,
  "state": "acknowledged",
  "severity": "critical",
  "severity_source": "detection",
  "priority": "P1",
  "category": "udp_flood",
  "direction": "incoming",
  "address_family": 4,
  "target_type": "host",
  "target_id": "203.0.113.7",
  "target_display": "203.0.113.7",
  "correlation_key": "wetechi|host|203.0.113.7|incoming|4",
  "first_detected_at": "2026-08-22T14:03:11Z",
  "opened_at": "2026-08-22T14:03:12Z",
  "last_detected_at": "2026-08-22T14:09:44Z",
  "last_updated_at": "2026-08-22T14:05:02Z",
  "acknowledged_at": "2026-08-22T14:05:02Z",
  "recovering_since": null,
  "resolved_at": null,
  "closed_at": null,
  "reopened_at": null,
  "reopen_count": 0,
  "assigned_user_id": "u_4821",
  "assigned_team_id": null,
  "customer_id": null,
  "site_id": null,
  "datacenter_id": null,
  "current_metrics": { "bps": 4200000000, "pps": 3100000 },
  "peak_metrics": { "bps": 6100000000, "pps": 4400000 },
  "baseline_metrics": null,
  "opening_reason": [
    {
      "metric": "bps",
      "observed": 4200000000,
      "threshold": 1000000000,
      "excess": 3200000000,
      "ratio_percent": 420
    }
  ],
  "policy_refs": [
    {
      "policy_id": "edge-host-inbound",
      "policy_version": 3,
      "first_seen": "2026-08-22T14:03:11Z",
      "last_seen": "2026-08-22T14:09:44Z"
    }
  ],
  "detection_event_count": 14,
  "tags": ["edge", "customer-a"],
  "mitigation_status": "none",
  "notification_status": "none",
  "version": 4,
  "created_by": "system:correlator",
  "updated_by": "u_4821",
  "closure_reason": null
}
```

`baseline_metrics` is `null`, not `0`. Phase 4 has no baselining, and
"never measured" is a different fact from "measured as zero". Clients
must render it as unknown.

`mitigation_status` and `notification_status` are `"none"` in every
Phase 5 response, always. They exist so a consumer can filter on them
without knowing which product version could have acted — the same
reasoning as Phase 4's `executed` field.

### Timeline entry

```json
{
  "timeline_id": "0192f3c4-9b12-7a44-8e51-0c1d2e3f4a5b",
  "incident_id": "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d",
  "occurred_at": "2026-08-22T14:05:02Z",
  "entry_type": "state_changed",
  "actor_type": "operator",
  "actor_id": "u_4821",
  "correlation_id": "corr_01H...",
  "command_id": "cmd_01H...",
  "source_event_id": null,
  "previous_value": { "state": "open" },
  "new_value": { "state": "acknowledged" },
  "payload": {},
  "schema_version": 1
}
```

### Note

```json
{
  "note_id": "0192f3c4-a1b2-7c33-9d44-5e6f7a8b9c0d",
  "incident_id": "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d",
  "author_id": "u_4821",
  "created_at": "2026-08-22T14:07:30Z",
  "body": "Upstream confirms the source is spoofed. Asked for a filter at the transit edge.",
  "visibility": "internal",
  "supersedes_note_id": null,
  "superseded_at": null,
  "superseded_by": null,
  "redacted_at": null
}
```

`body` is **untrusted operator text**. The API stores and returns it
verbatim. Consumers must escape it on output; the API does not sanitise
on input, because sanitising destroys what the operator actually wrote.

### Paginated list

```json
{
  "items": [],
  "next_cursor": "eyJvIjoiMjAyNi0wOC0yMlQxNDowMzoxMloiLCJpIjoiMDE5..." ,
  "has_more": true,
  "total": null
}
```

`total` is `null` unless `include_total=true`, because counting is the
expensive part of the query and most callers do not need it.

## Requests

```jsonc
// POST /incidents/{id}/acknowledge
{ "expected_version": 3, "note": "picking this up" }

// POST /incidents/{id}/assign
{ "expected_version": 4, "user_id": "u_4821" }        // or "team_id"

// POST /incidents/{id}/severity
{ "expected_version": 5, "severity": "major", "reason": "traffic subsided, host stable" }

// POST /incidents/{id}/resolve
{ "expected_version": 7, "resolution_note": "attack ended, no customer impact" }

// POST /incidents/{id}/close
{ "expected_version": 8, "closure_reason": "resolved" }

// POST /incidents/{id}/reopen
{ "expected_version": 9, "reason": "recurred within the hour" }

// POST /incidents/{id}/suppress
{ "expected_version": 3, "reason": "known backup window", "expires_at": "2026-08-23T02:00:00Z" }

// POST /incidents/{id}/notes
{ "body": "Upstream confirms spoofed sources.", "visibility": "internal" }
```

`reason` is mandatory when *lowering* severity and optional when raising:
an escalation explains itself, a de-escalation is the one an auditor asks
about. `expires_at` is mandatory on suppression — an indefinite
suppression is how a real attack gets missed.

**As implemented (5D-6):**

- **The acknowledge `note` is not taken yet.** The domain command has no note, so the field is refused as unknown rather than dropped (FU-55).
- **A suppression ends at most 30 days ahead.** `expires_at` must be in the future and no further away than that. Otherwise the request is refused with `422 incident.validation_failed`.
- **A transition answers with the incident as it now is.** On a replay, that is the current incident, not a stored copy of the first answer.
- **A note answers `201` with the incident.** The domain numbers notes by position, so the response does not identify the note. `GET .../notes` lists them.
- **Tags are a sub-resource, not a `PATCH`.** `PUT /incidents/{id}/tags/{key}` sets one tag and `DELETE` removes one. Each is one domain command, so it is atomic. A `PATCH` carrying several tag changes would have been several commands, and not atomic. `PATCH /incidents/{id}` stays reserved for title and description, which have no domain command yet (FU-56).
- **A manual incident names its target in the detector's vocabulary** (`target_scope`, `target`, `direction`, `address_family`) and takes that correlation key ([ADR 0039](../architecture/decisions/0039-phase5d-manual-incidents.md)). A second incident for an active target is `409 incident.duplicate_active`, and its body names the active incident's `incident_id`.
- **An export is one JSON document,** audited before it is read and capped at 5000 entries per history. Its audit section is `null` unless the caller also holds `incident.audit.read`. It answers with `Content-Disposition: attachment`.
- **A version conflict carries extension members.** It includes `expected_version`, `current_version` and `current_state`.

## Draft OpenAPI

Abridged to the shapes that carry the contract.

```yaml
openapi: 3.1.0
info:
  title: Tidegard Incident API
  version: 0.0.0-draft
  description: >-
    PLANNING DRAFT. Not implemented. No endpoint sends a notification or
    performs mitigation.
servers:
  - url: /api/v1
security:
  - bearerAuth: []
paths:
  /incidents:
    get:
      operationId: listIncidents
      parameters:
        - { name: state, in: query, schema: { type: array, items: { type: string } } }
        - { name: severity, in: query, schema: { type: string, enum: [info, minor, major, critical] } }
        - { name: priority, in: query, schema: { type: string, enum: [P1, P2, P3, P4] } }
        - { name: cursor, in: query, schema: { type: string } }
        - { name: limit, in: query, schema: { type: integer, minimum: 1, maximum: 200, default: 50 } }
        - { name: include_total, in: query, schema: { type: boolean, default: false } }
      responses:
        "200": { description: A page of incidents }
        "400": { description: Query too broad or malformed }
  /incidents/{incidentId}/acknowledge:
    post:
      operationId: acknowledgeIncident
      parameters:
        - { name: incidentId, in: path, required: true, schema: { type: string } }
        - name: Idempotency-Key
          in: header
          required: true
          schema: { type: string, minLength: 16, maxLength: 255 }
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [expected_version]
              properties:
                expected_version: { type: integer }
                note: { type: string, maxLength: 16000 }
      responses:
        "200": { description: Acknowledged, or an idempotent replay }
        "403": { description: Missing incident.acknowledge }
        "404": { description: Not found, or belongs to another tenant }
        "409": { description: Version conflict, illegal transition, or key reuse }
components:
  securitySchemes:
    bearerAuth: { type: http, scheme: bearer }
```

`additionalProperties: false` throughout is deliberate, mirroring Phase
4's `deny_unknown_fields` on policy documents: a misspelled field must
fail loudly, not be silently discarded while the operator believes it
took effect.

## Errors

| `error` | Status | Meaning |
|---|---|---|
| `incident.not_found` | 404 | Missing, or another tenant's |
| `incident.forbidden` | 403 | Authenticated, lacks permission |
| `incident.version_conflict` | 409 | `expected_version` stale |
| `incident.illegal_transition` | 409 | Not a legal edge |
| `incident.state_unchanged` | 409 | Already in the target state, no key |
| `incident.idempotency_key_reuse` | 409 | Same key, different body |
| `incident.request_in_progress` | 409 | Same key, still running |
| `incident.validation_failed` | 400 | Malformed or unknown field |
| `incident.query_too_broad` | 400 | Would not use an index |
| `incident.limit.notes` | 409 | Note limit reached |
| `incident.limit.events` | 409 | Linked-event limit reached |
| `incident.suppression_requires_expiry` | 422 | No `expires_at` |
| `incident.customer_visible_unsupported` | 501 | Not available in Phase 5 |
| `incident.rate_limited` | 429 | Retry after the header says |
| `incident.storage_unavailable` | 503 | PostgreSQL down; failed closed |
