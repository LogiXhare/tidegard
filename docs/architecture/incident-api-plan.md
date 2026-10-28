# Incident API — Design

Status: **Planning only.** Design rationale; the endpoint-by-endpoint
reference and the draft OpenAPI live in
[docs/api/incident-api-plan.md](../api/incident-api-plan.md). No API is
implemented.

## Shape

Resource-oriented REST under `/api/v1`, with **state transitions as
sub-resource actions** rather than a `PATCH` on `state`.

`POST /incidents/{id}/acknowledge` rather than
`PATCH /incidents/{id} {"state": "acknowledged"}` — because a transition
is not a field assignment. It has its own permission, its own required
fields, its own idempotency semantics, and its own audit entry. Modelling
it as a field would mean inferring all four from the value being written,
and would let a client attempt an illegal transition by writing any state
name at all.

Reads are `GET` and are resource-shaped. Only transitions are actions.

## Conventions

| Concern | Rule |
|---|---|
| Version | `/api/v1`; breaking changes get `/v2` |
| Auth | Bearer token; `401` unauthenticated, `403` authenticated-but-unpermitted |
| Tenant | From the auth context, **never** from a request parameter |
| Cross-tenant | `404`, never `403` — see [security model](incident-security-model.md) |
| Unknown fields | **Rejected** with `400`, never ignored |
| Idempotency | `Idempotency-Key` required on transitions |
| Concurrency | `expected_version` required on transitions |
| Content type | `application/json` only |
| Timestamps | RFC 3339 UTC |
| Errors | RFC 9457 problem details plus a stable `error` code |
| Pagination | Cursor, never offset |
| Rate limits | `429` with `Retry-After` |

### Why cursor pagination, not offset

Incidents are inserted continuously during an attack — exactly when an
operator is paging through the list. With offset pagination, a new
incident at the top shifts every subsequent row down one, so page 2 shows
an item already seen on page 1 and skips another entirely. Cursor
pagination over an immutable sort key does not drift.

Cursors are opaque and encode the sort key plus tenant. A cursor
from another tenant is rejected rather than honoured, so cursors cannot
be used to cross the tenant boundary.

**As implemented (5D-4):** cursors are not signed. Every list query is
scoped to the caller's tenant in SQL, so an edited cursor can only move
the position within the caller's own incidents, which the caller may
read anyway. Signing would add a secret to manage and protect nothing
further. A cursor naming another tenant, another sort or another order
is refused with `400`.

### Error body

```json
{
  "type": "https://logixhare.com/tidegard/problems/incident-version-conflict",
  "title": "Version conflict",
  "status": 409,
  "detail": "The incident was modified by another actor.",
  "error": "incident.version_conflict",
  "request_id": "req_01H...",
  "current_version": 8,
  "expected_version": 6,
  "current_state": "resolved"
}
```

The `error` field is the stable, machine-readable contract. `title` and
`detail` are for humans and may be reworded; a client that switches on
`detail` is broken by design.

## Query surface

`GET /api/v1/incidents` filters: `state` (repeatable), `severity`,
`priority`, `category`, `direction`, `address_family`, `target`,
`target_type`, `policy_id`, `assigned_user`, `assigned_team`,
`unassigned=true`, `tag`, `opened_from`/`opened_to`,
`updated_from`/`updated_to`, `closed_from`/`closed_to`, `q` (substring
over title and target).

Sort: `opened_at`, `last_detected_at`, `severity`, `priority`,
`last_updated_at`; default `opened_at desc`. Page size default 50,
**maximum 200 enforced server-side** regardless of what the client asks
for.

Bounding rules, because an unbounded query is a denial-of-service
primitive that costs one request:

- Time-range filters are capped at 90 days per query.
- `q` requires at least 3 characters and is never a leading wildcard.
- Every filter combination must be index-supported; a request that would
  force a sequential scan is rejected with `400 incident.query_too_broad`
  rather than served slowly.
- Total result count is **not** returned by default — counting is the
  expensive part. `include_total=true` is available and separately rate
  limited.

## Endpoint summary

Full request and response schemas are in the
[API reference plan](../api/incident-api-plan.md).

| Method | Path | Permission | Idem. | Ver. |
|---|---|---|---|---|
| `GET` | `/incidents` | `incident.list` | — | — |
| `POST` | `/incidents` | `incident.create` | Required | — |
| `GET` | `/incidents/{id}` | `incident.read` | — | — |
| `PATCH` | `/incidents/{id}` | `incident.update` | Optional | Required |
| `GET` | `/incidents/{id}/timeline` | `incident.read` | — | — |
| `GET` | `/incidents/{id}/notes` | `incident.read` | — | — |
| `POST` | `/incidents/{id}/notes` | `incident.note.create` | Optional | — |
| `GET` | `/incidents/{id}/detections` | `incident.read` | — | — |
| `GET` | `/incidents/{id}/audit` | `incident.audit.read` | — | — |
| `POST` | `/incidents/{id}/acknowledge` | `incident.acknowledge` | Required | Required |
| `POST` | `/incidents/{id}/assign` | `incident.assign` | Required | Required |
| `POST` | `/incidents/{id}/unassign` | `incident.assign` | Required | Required |
| `POST` | `/incidents/{id}/investigate` | `incident.investigate` | Required | Required |
| `POST` | `/incidents/{id}/monitor` | `incident.investigate` | Required | Required |
| `POST` | `/incidents/{id}/severity` | `incident.severity.change` | Required | Required |
| `POST` | `/incidents/{id}/priority` | `incident.priority.change` | Required | Required |
| `POST` | `/incidents/{id}/resolve` | `incident.resolve` | Required | Required |
| `POST` | `/incidents/{id}/close` | `incident.close` | Required | Required |
| `POST` | `/incidents/{id}/reopen` | `incident.reopen` | Required | Required |
| `POST` | `/incidents/{id}/suppress` | `incident.suppress` | Required | Required |
| `POST` | `/incidents/{id}/unsuppress` | `incident.suppress` | Required | Required |
| `POST` | `/incidents/{id}/export` | `incident.export` | Optional | — |

`POST /incidents` exists for manual incident creation — an operator
opening an incident for something the detector cannot see. It is **not**
the ingestion path; detection events arrive through the outbox, never
over HTTP.

## Status codes

| Code | When |
|---|---|
| `200` | Success, including an idempotent replay |
| `201` | Incident created |
| `400` | Malformed body, unknown field, invalid ID shape, query too broad |
| `401` | Missing or invalid credentials |
| `403` | Authenticated, lacks the permission, **same tenant** |
| `404` | Not found, **or another tenant's resource** |
| `409` | Version conflict, illegal transition, idempotency reuse, state unchanged |
| `422` | Well-formed but semantically invalid, e.g. suppression with no expiry |
| `429` | Rate limited |
| `500` | Unexpected — no internal detail in the body |
| `503` | PostgreSQL unavailable; the API fails closed |

## What the API does not do

- **No notification.** No endpoint sends anything anywhere.
- **No mitigation.** No endpoint touches a router. There is no
  `/mitigate`.
- **No detection ingestion over HTTP.** That path is the outbox.
- **No customer-visible notes.** The field is accepted and setting it
  returns `501`, per the [domain model](incident-domain-model.md).
- **No bulk mutation.** Bulk close across a filter is a foot-gun that
  needs its own authorization design; deferred as **FU-22**.
