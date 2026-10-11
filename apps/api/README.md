# Incident API

**Status:** Milestone 5D, foundation in place. `wetechinetmon-api` serves
liveness and readiness on axum
([ADR 0037](../../docs/architecture/decisions/0037-phase5d-http-framework-and-openapi.md)),
with the boundary rules of
[ADR 0038](../../docs/architecture/decisions/0038-phase5d-api-boundary.md).
The incident endpoints come next.

## What is here

| Module | Purpose |
|---|---|
| `problem` | RFC 9457 problem details. `ErrorCode` is the registry behind [docs/api/error-codes.md](../../docs/api/error-codes.md). Another tenant's incident is `incident.not_found`, and internal faults say only `api.internal`. |
| `request_id` | A UUIDv7 per request, in `X-Request-Id`, every problem body and the tracing span. A client-sent id is never trusted. |
| `rate_limit` | GCRA on `std` (no `unsafe`), bounded keys that fail closed when full, property-tested against the conformance bound. |
| `auth` | Bearer-token authentication behind the `Authenticator` seam. Every failure is the same `401`, failed attempts are limited per source address, and an outage is `503`, not a lockout. |
| `token_admin` | Issuing, revoking and listing tokens for the `token` subcommand. |
| `server` | Loopback may be plaintext (for a same-host proxy). Any other bind requires TLS with rustls, and handshakes run off the accept loop with a deadline. |
| `openapi` | The document generated from the handlers, checked against [docs/api/openapi.json](../../docs/api/openapi.json). |

## Running it

```sh
WETECHINETMON_API_DATABASE_URL="host=127.0.0.1 user=wetechinetmon dbname=incidents" \
wetechinetmon-api
```

| Variable | Default | Meaning |
|---|---|---|
| `WETECHINETMON_API_BIND` | `127.0.0.1:8080` | Listen address. Not loopback: TLS files are required. |
| `WETECHINETMON_API_TLS_CERT_FILE` / `..._TLS_KEY_FILE` | unset | PEM certificate chain and key. Set both. Never commit them. |
| `WETECHINETMON_API_DATABASE_URL` | required | libpq connection string. Never logged. |
| `WETECHINETMON_API_DATABASE_CA_FILE` and `..._CLIENT_CERT_FILE` / `..._CLIENT_KEY_FILE` | unset | Database TLS, the same rule as the incident manager. |
| `WETECHINETMON_API_POOL_MAX_SIZE` | 16 | Most database connections. |
| `WETECHINETMON_API_TRAFFIC_TENANT` | unset | The one tenant whose callers may read deployment-wide traffic ([ADR 0042](../../docs/architecture/decisions/0042-phase6b-traffic-read-api.md)). Set it with the ClickHouse URL, or neither. |
| `WETECHINETMON_API_CLICKHOUSE_URL` | unset | `https://host:port`, or `http://` to a loopback host only. |
| `WETECHINETMON_API_CLICKHOUSE_USER` | `default` | Give the API a ClickHouse user that can only `SELECT`. |
| `WETECHINETMON_API_CLICKHOUSE_PASSWORD_FILE` | unset | A file holding the password. Never logged. |
| `WETECHINETMON_API_CLICKHOUSE_CA_FILE` | unset | The CA bundle for `https://`. Required for it. |
| `RUST_LOG` | `info` | Log filter; logs are JSON. |

`GET /healthz` is liveness: it answers while the process runs.
`GET /readyz` is readiness: `503 api.unavailable` until the database
answers. Neither needs a token.

## Endpoints

| Method | Path | Permission | Limit |
|---|---|---|---|
| `GET` | `/healthz` | none | none |
| `GET` | `/api/v1/whoami` | any token | 120/min per actor |
| `POST` | `/api/v1/session` | a valid token in the body | failed sign-ins: 30/min per address |
| `GET` | `/api/v1/session` | a session cookie | none |
| `DELETE` | `/api/v1/session` | a session cookie and its CSRF value | none |
| `GET` | `/readyz` | none | none |
| `GET` | `/api/v1/incidents` | `incident.list` | 120/min per actor; `include_total` costs 2 |
| `POST` | `/api/v1/incidents` | `incident.create` | 60/min per actor |
| `GET` | `/api/v1/incidents/{id}` | `incident.read` | 120/min per actor |
| `GET` | `/api/v1/incidents/{id}/timeline` | `incident.read` | 120/min per actor |
| `GET` | `/api/v1/incidents/{id}/notes` | `incident.read` | 120/min per actor |
| `POST` | `/api/v1/incidents/{id}/notes` | `incident.note.create` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/notes/{index}/edit` | `incident.note.create`, own note only | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/notes/{index}/redact` | `incident.note.redact` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/export` | `incident.export` | 10/min per actor |
| `PUT` | `/api/v1/incidents/{id}/tags/{key}` | `incident.update` | 60/min per actor |
| `DELETE` | `/api/v1/incidents/{id}/tags/{key}` | `incident.update` | 60/min per actor |
| `GET` | `/api/v1/incidents/{id}/detections` | `incident.read` | 120/min per actor |
| `GET` | `/api/v1/incidents/{id}/audit` | `incident.audit.read` | 30/min per actor |
| `POST` | `/api/v1/incidents/{id}/acknowledge` | `incident.acknowledge` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/investigate` | `incident.investigate` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/monitor` | `incident.investigate` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/resolve` | `incident.resolve` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/close` | `incident.close` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/reopen` | `incident.reopen` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/suppress` | `incident.suppress` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/unsuppress` | `incident.suppress` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/assign` | `incident.assign` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/unassign` | `incident.assign` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/severity` | `incident.severity.change` | 60/min per actor |
| `POST` | `/api/v1/incidents/{id}/priority` | `incident.priority.change` | 60/min per actor |
| `GET` | `/api/v1/traffic/summary` | `traffic.read`, traffic tenant only | 120/min per actor |
| `GET` | `/api/v1/traffic/top` | `traffic.read`, traffic tenant only | 120/min per actor |
| `GET` | `/api/v1/exporters` | `traffic.read`, traffic tenant only | 120/min per actor |

Every transition `POST` needs an `Idempotency-Key` header (16 to 255 characters) and `expected_version` in its JSON body. A retry with the same key and body replays the first outcome; a stale version is `409 incident.version_conflict`. Each answers with the incident as it now is. Adding a note needs neither: notes are append-only, and a key, when given, still makes a retry replay. It answers `201` with the incident. Editing your own note (`201`) or redacting one (`200`) needs neither as well: a note is replaced once and redacted once, so a repeat is `422`. The original of an edited note stays; `GET .../notes` hides it unless `include_superseded=true`. Opening an incident by hand needs an `Idempotency-Key` and answers `201` with a `Location` ([ADR 0039](../../docs/architecture/decisions/0039-phase5d-manual-incidents.md)). An export is one JSON document (`format: wetechinetmon.incident-export`) holding the incident, timeline, notes, detections and, for a caller with `incident.audit.read`, the audit trail. Each history is capped at 5000 entries, and `truncated` reports any cut. Every export writes an audit entry before anything is read. Tags are set with `PUT` and removed with `DELETE`, which are idempotent by definition: no version, and the key is optional.

The full contract is the generated [OpenAPI document](../../docs/api/openapi.json). Another tenant's incident is `404 incident.not_found`, indistinguishable from a missing one.

**Browser sessions** ([ADR 0043](../../docs/architecture/decisions/0043-phase6c-browser-sessions.md)): `POST /api/v1/session` with `{"token": "wnm_..."}` answers with a `wnm_session` cookie (`HttpOnly`, `SameSite=Strict`, `Secure` when the API serves TLS) and a `csrf_token`. The cookie then works like the token. Any cookie request that changes anything needs `X-WNM-CSRF: <csrf_token>`, or it is `403 api.csrf_rejected`. A session ends after 30 minutes idle, 12 hours in all, at sign-out, or when its token is revoked or expires. A bearer token, when present, always wins.

Traffic is deployment-wide until Phase 8 brings prefix ownership, so only the configured traffic tenant reaches the traffic endpoints; every other tenant gets `404 api.not_found`. The API reads ClickHouse read-only, with server-side query parameters, a 10-second limit and a row limit. A range is at most 30 days, and a summary has at most 500 points. ClickHouse being down answers `503` and leaves incidents working.

## API tokens

Every `/api/v1` request needs `Authorization: Bearer <token>`. Tokens are
issued from the same binary, and the command talks straight to the
database. The incident manager must have run once to create the schema
(migration V15).

```sh
wetechinetmon-api token create --tenant acme --actor-id alice --role operator --days 90 --description "alice laptop"
wetechinetmon-api token list --tenant acme
wetechinetmon-api token revoke --token-id <uuid>
```

- The token (`wnm_` and 64 hex characters) is printed **once**. Only its
  SHA-256 is stored, and `list` never shows it.
- The roles are `viewer`, `operator`, `senior_operator` and `noc_lead`.
  `platform_admin` cannot be given to a token. The table refuses it too.
- Every token expires, after at most 366 days. A revoked or expired
  token is refused like a wrong one: `401 api.unauthenticated`. Thirty
  failures a minute from one address lock that address out with `429`.

## Changing the API

Annotate every handler with `#[utoipa::path]` and list it in
`openapi::ApiDoc`, then regenerate the committed document:

```sh
WETECHINETMON_UPDATE_OPENAPI=1 cargo test -p wetechinetmon-api openapi
```

A new error code goes in `problem::ErrorCode` and in
[docs/api/error-codes.md](../../docs/api/error-codes.md). The tests fail
if either is missing.
