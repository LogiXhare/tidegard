# API Error Codes

Every error response from the incident API is RFC 9457 problem details
(`application/problem+json`) with a stable `error` member
([ADR 0038](../architecture/decisions/0038-phase5d-api-boundary.md)).
**Switch on `error`, never on `title` or `detail`.** A code, once
published, is never reused for another meaning.

This table is the registry. A test in `apps/api/src/problem.rs` fails
when the code can emit an error missing from it, or with a different
status.

| Code | Status | Meaning |
|---|---|---|
| `api.unauthenticated` | 401 | No usable credential. Sent with `WWW-Authenticate: Bearer`, and the same for every cause. |
| `api.forbidden` | 403 | Authenticated, but lacking the permission, for a resource in the caller's own tenant. |
| `api.not_found` | 404 | No such path or resource. |
| `api.method_not_allowed` | 405 | The path exists, but not with this method. |
| `api.invalid_request` | 400 | A malformed body, query or path parameter. |
| `api.unknown_field` | 400 | The body has a field the endpoint does not define. Unknown fields are never ignored. |
| `api.unsupported_media_type` | 415 | The body is not `application/json`. |
| `api.csrf_rejected` | 403 | A request made with a session cookie that changes anything lacks the session's `X-WNM-CSRF` value, or has the wrong one ([ADR 0043](../architecture/decisions/0043-phase6c-browser-sessions.md)). |
| `api.payload_too_large` | 413 | The body is over 64 KiB. |
| `api.rate_limited` | 429 | Over the rate limit. Sent with `Retry-After`. |
| `api.unavailable` | 503 | The database cannot be reached. The API fails closed. Sent with `Retry-After`. |
| `api.internal` | 500 | Unexpected. The body carries nothing but this code and the request id. |
| `incident.not_found` | 404 | No such incident, **or another tenant's**. The two are indistinguishable by design. |
| `incident.illegal_transition` | 409 | The state machine does not allow this transition from the current state. |
| `incident.version_conflict` | 409 | `expected_version` is stale. Re-read the incident and retry. |
| `incident.idempotency_key_reuse` | 409 | The `Idempotency-Key` was used for a different request. |
| `incident.forbidden` | 403 | The domain refused the command for lack of a permission. |
| `incident.validation_failed` | 422 | Well-formed, but semantically invalid, for example a suppression with no expiry. |
| `incident.limit_reached` | 409 | A per-tenant bound, such as open incidents, is reached. |
| `incident.duplicate_active` | 409 | An active incident for the same correlation key already exists. |
| `incident.invalid_reopen` | 409 | The incident cannot be reopened, for example outside the reopen window. |
| `incident.manual_closure_required` | 409 | This incident must be closed by an operator. |
| `incident.suppressed_operation` | 409 | The operation is not allowed while the incident is suppressed. |
| `incident.evidence_unavailable` | 422 | The evidence the command needs is not available. |
| `incident.state_unchanged` | 409 | The command would not change anything. |
| `incident.clock_skew` | 503 | The decision time ran backward ([ADR 0031](../architecture/decisions/0031-phase5b-durable-time.md)). Retry. |
| `incident.correlation_conflict` | 409 | The correlation key conflicts with an existing incident. |
| `incident.customer_visible_unsupported` | 501 | A customer-visible note was asked for. Phase 5 keeps every note internal. |
| `mitigation.not_found` | 404 | No such mitigation, **or another tenant's**. The two are indistinguishable by design ([ADR 0050](../architecture/decisions/0050-phase7e-mitigation-api-cli-ui.md)). |
| `mitigation.forbidden` | 403 | The role lacks the mitigation permission. |
| `mitigation.illegal_transition` | 409 | The mitigation's state does not allow this, for example approving one that is already active. |
| `mitigation.self_approval` | 403 | The requester tried to approve their own mitigation, and the deployment does not allow it. |
| `mitigation.invalid` | 422 | The request is well formed but not a valid mitigation: a prefix with host bits, an RTBH that is not a host route, ports without TCP or UDP, a reason or duration out of range. |
| `mitigation.duplicate` | 409 | A live mitigation already does the same action on the same prefix and match. |
| `mitigation.version_conflict` | 409 | `expected_version` is stale. Carries `current_version`. |
| `mitigation.idempotency_key_reuse` | 409 | The `Idempotency-Key` was used for a different mitigation request. |
| `mitigation.kill_switch` | 409 | The kill switch is on: no mitigation may start. |
| `mitigation.not_allowlisted` | 403 | The prefix is not on this tenant's allowlist. Another tenant's prefix gets the same answer. |
| `mitigation.action_not_allowed` | 403 | The allowlist entry does not permit this action. |
| `mitigation.too_wide` | 422 | The prefix is wider than the configured minimum length. |
| `mitigation.too_long` | 422 | The duration is over the configured maximum. |

The `type` member is `https://wetechi.com/probs/` followed by the code,
with `.` and `_` written as `-`, for example
`https://wetechi.com/probs/incident-version-conflict`. It is an
identifier, and it need not resolve.
