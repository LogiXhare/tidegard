# 0043. Phase 6C Browser Sessions

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-10, 2026-10-11); the details under the
delegation of 2026-10-05 to industry practice

## Context

The NOC UI (6D) runs in a browser. The API authenticates bearer tokens
(ADR 0038), and a browser should not hold one: anything JavaScript can
read, an injected script can steal. BQ-10 settled the approach: an
operator signs in once with an existing API token, and the API answers
with a session cookie. Local accounts and OIDC remain Phase 8.

A cookie brings its own threats, named in the
[Phase 6 plan](../phase6-dashboards-ui-notifications-plan.md): cross-site
request forgery, session fixation, a session outliving its token, and a
session that never ends.

## Decision

### The session

- `POST /api/v1/session` takes `{"token": "wnm_..."}`. If the token is
  valid, unexpired and unrevoked, the API creates a session **with a new
  random id, whatever cookie the request carried**, so a session id
  planted before sign-in is never honoured (fixation).
- The id is `wns_` and 64 hex characters from the OS random source. Only
  its SHA-256 is stored, in `api_sessions` (V18), with the token it came
  from.
- The session is the token's tenant, actor and role, read through the
  token on every request. **Revoking or expiring the token ends every
  session made from it.**
- It ends after **30 minutes idle** or **12 hours** in all, whichever
  comes first. `DELETE /api/v1/session` ends it at once.
- Expired sessions are purged by the incident manager's retention job.

### The cookie

`wnm_session=<id>; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200`,
plus `Secure` whenever the API serves TLS. A plain-HTTP API is loopback
only (ADR 0038), where browsers treat the origin as secure anyway.

### Cross-site request forgery

`SameSite=Strict` stops the browser sending the cookie on cross-site
requests. The API does not rely on that alone. A request authenticated by
the cookie that is not `GET`, `HEAD` or `OPTIONS` must carry
`X-WNM-CSRF`, equal to a value derived from the session id
(`SHA-256("tidegard csrf" ‖ id)`). The page learns it from
`POST /api/v1/session` and `GET /api/v1/session`. A cross-site page can
neither read those answers nor compute the value, since the cookie is
`HttpOnly`. A missing or wrong header is `403 api.csrf_rejected`,
audited. Nothing about it needs storing.

### What stays the same

- A bearer token works exactly as before. When a request carries both,
  the token is used and the cookie ignored.
- Failed sign-ins share the per-address failure limit of bad tokens.
- A session id, its CSRF value and the token are never logged.

### Audit

Sign-in, sign-out and each CSRF refusal write an `incident_audit` row
with resource type `session`, the actor, and the token's id. A sign-in
with an unknown token has no actor to record, so it is logged and
counted against the failure limit, exactly as a bad bearer token is.

## Consequences

- One write per sign-in and sign-out, and at most one per minute per
  session to keep `last_seen_at` current. Reads stay reads otherwise.
- The UI never sees a token after sign-in, and an injected script cannot
  read the session id.
- Sessions add a table that grows with sign-ins. Retention bounds it.

## Alternatives considered

- **Keep the token in browser storage.** Any script on the page can read
  it, and a stolen token lasts up to 366 days.
- **A signed, stateless session cookie.** It cannot be revoked before it
  expires, and revoking the token would not end it.
- **Rely on `SameSite` alone.** Older browsers and same-site subdomains
  weaken it. The header costs nothing.
