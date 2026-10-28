# 0038. Phase 5D API Boundary: TLS, Identity, Authorization, Rate Limits, Errors

Status: **Accepted**, amended by the 5D dependency probe (gate 8,
2026-10-05). `getrandom` was approved. `governor` was rejected, and the
rate limiter is implemented in-house (gate 6 below).
Date: 2026-10-05
Deciders: Repository owner. On 2026-10-05 the owner delegated these choices to
industry practice and standards.

## Context

Milestone 5D's entry gates 3 to 7 must be settled before the first
endpoint is written:

- the TLS boundary;
- the authentication seam;
- the authorization seam;
- rate limiting and its storage;
- the error model.

Settled inputs:

- The [API design](../incident-api-plan.md) fixes the conventions:
  bearer token, tenant from the auth context, 404 for another tenant,
  unknown fields rejected, `Idempotency-Key` and `expected_version` on
  transitions, RFC 9457 errors, and `429` with `Retry-After`.
- The [security model](../incident-security-model.md) fixes the rate
  limits per surface.
- [ADR 0017](0017-incident-community-enterprise-boundary.md) fixes the
  seams: `IdentityProvider`, which is local users and teams in Community,
  and `PermissionResolver`, which is fixed role bundles. Phase 8 replaces
  the identity provider without touching the incident domain.

## Decision

The API is a new binary, `tidegard-api`, in `apps/api`, on `axum`
(ADR 0037).

### Gate 3: the TLS boundary is the service, not an assumption

Same rule as [ADR 0023](0023-phase5b-postgresql-tls.md) applies to the
database:

- **A loopback bind may be plaintext.** This is the reverse-proxy
  deployment: Caddy or nginx on the same host terminates TLS and forwards
  to `127.0.0.1`.
- **Any other bind requires TLS at the service.** That means `rustls`
  through `tokio-rustls`, both already in the closure, with a certificate
  and key from operator-managed files. Startup refuses a non-loopback
  bind without them. There is no flag that allows plaintext off loopback.
- TLS 1.2 minimum; `rustls` defaults for everything else. Client
  certificates are not used for authentication in Phase 5.

Behind a proxy, rate limiting by source address (below) sees the proxy.
Forwarded headers are trusted only from addresses configured as proxies,
and never by default.

### Gate 4: authentication — opaque API tokens behind an `Authenticator` seam

The industry-standard first step for a self-hosted API is long-lived,
revocable, scoped tokens of the GitHub or GitLab personal-access-token
kind. OIDC/JWT and SSO are Phase 8.

- **Token format:** `wnm_` followed by 32 random bytes from the OS CSPRNG
  (`getrandom`), as 64 lowercase hex characters. Hex rather than base64url
  means no encoding dependency, and the shape is trivial to validate
  before any lookup. The prefix makes a leaked
  token recognisable to secret scanners.
- **Storage:** only `SHA-256(token)` is stored, in a new `api_tokens`
  table (a new migration). Each row has the tenant, the actor id, the
  role, `created_at`, `expires_at` and `revoked_at`. The token itself is
  shown once, at creation. A database leak exposes no usable credential.
  The token carries 256 bits of entropy, so an unsalted fast hash is
  appropriate here; a slow password hash is for low-entropy secrets.
- **Lookup** is by hash through a unique index, so no comparison of
  secrets happens in application code.
- **Failures:**
  - A missing, malformed, unknown, expired or revoked token is `401`
    with `WWW-Authenticate: Bearer`.
  - The body is the same in every case, so it never says which check
    failed.
  - Failed attempts are rate-limited per source address.
- **The seam:** an `Authenticator` trait in the API crate, from a
  `Bearer` credential to a `Principal` (tenant, actor, role). The
  Community implementation is the token table. Phase 8 adds an OIDC
  implementation. Nothing past the trait knows how the caller proved who
  they are.
- **Issuing tokens:** an admin subcommand of the API binary
  (`tidegard-api token create|revoke|list`) talks to the database
  directly. This is the bootstrap path, and it needs no running API and
  no prior token. The 5E CLI may wrap it later.

### Gate 5: authorization — the existing `PermissionResolver`

- Each request builds one `AuthorizationContext` from the `Principal`:
  the tenant, `Actor::Operator`, and `PermissionResolver::permissions_for(role)`.
  The Community resolver is `FixedBundleResolver`.
- **The check stays where it already is:** at the command boundary
  inside `crates/incident` and the persistence service. The API only
  translates the result to HTTP. It never re-implements a permission
  check, so the two cannot disagree.
- **The tenant comes from the principal, never from the request.**
  Another tenant's incident is `404`, the same as one that does not
  exist, and a test asserts this for every endpoint.
- `403` is only for a same-tenant resource the caller lacks permission
  for.

### Gate 6: rate limiting — GCRA in memory, per actor and surface

- **Algorithm:** GCRA, a token-bucket equivalent, keyed by actor and
  surface, implemented in `apps/api` on `std` alone.
  - The state is one "theoretical arrival time" per key, behind a
    `Mutex<HashMap>`, with no `unsafe` and property-tested against the
    algorithm's definition.
  - The first draft of this ADR chose `governor` (0.10.4, MIT, 17.4 M
    downloads in 90 days, no advisories). The gate-8 probe rejected it on
    ADR 0018's closure criterion. Even with `default-features = false,
    features = ["std"]` it added 8 crates and about 920 `unsafe`
    occurrences (`portable-atomic` alone 727). That is roughly 1 420 of
    the 1 477 the whole API closure would carry, for an algorithm this
    small.
  - `tower_governor` was never in contention: it keys by address and has
    not been released since August 2025.
- **Limits** from the security model:

  | Surface | Limit |
  |---|---|
  | Mutating commands | 60/min per actor |
  | List and search | 120/min per actor |
  | Audit read | 30/min per actor |
  | Export | 5/hour per tenant |
  | Failed authentication | 30/min per source address |

- **Exceeding a limit** returns `429` with `Retry-After`, in seconds.
- **Storage is in the process.** This matches the Phase 5 single-node
  deployment. With N instances the effective limit is N times the
  configured one. That is stated in the operations docs, and a shared
  store is a Phase 8 concern if horizontal scaling arrives.
- **Every key set is bounded.** Idle keys are swept, so many actors or
  addresses cannot exhaust memory.

### Gate 7: errors — RFC 9457 problem details with stable codes

Every error body is `application/problem+json`:

```json
{
  "type": "https://logixhare.com/tidegard/problems/incident-version-conflict",
  "title": "Version conflict",
  "status": 409,
  "detail": "The incident was modified by another actor.",
  "error": "incident.version_conflict",
  "request_id": "0199a1b2-..."
}
```

- **`error` is the contract.**
  - Domain failures reuse `IncidentError::code()`, for example
    `incident.version_conflict`.
  - API-level failures are `api.*`: `api.unauthenticated`,
    `api.forbidden`, `api.not_found`, `api.invalid_request`,
    `api.unknown_field`, `api.unsupported_media_type`,
    `api.payload_too_large`, `api.rate_limited`, `api.unavailable`,
    `api.internal`.
  - A code, once published, is never reused for another meaning.
  - `docs/api/error-codes.md` lists every code with its status.
- **`type`** is `https://logixhare.com/tidegard/problems/` followed by the code with
  `.` and `_` turned into `-`. It is an identifier and need not resolve.
  (It was `https://wetechi.com/probs/` until 1.0.0-rc.3; the product's
  rename moved it, ADR 0058.)
- **`request_id`** is a UUIDv7. It is generated per request, returned in
  `X-Request-Id`, and logged with every line for that request, so a
  report can be matched to the logs.
- **Status mapping** follows the API design's table:
  - `PersistError::Unavailable` maps to `503`. The API fails closed.
  - An unexpected error maps to `500`. Its body carries only the code and
    `request_id`, never internal detail.
- **Extractor rejections** go through one handler into the same shape:
  malformed JSON, an unknown field (`deny_unknown_fields` on every
  request type), a wrong content type, an oversized body.

## Alternatives considered

- **JWT bearer tokens in Phase 5.** They would need a signing key, a
  rotation story, and either short lifetimes or a revocation list, which
  is a token table again. Opaque tokens give revocation for free, and
  OIDC in Phase 8 is the right home for JWTs.
- **TLS only at a proxy, with the service always plaintext.** Common, but
  it fails open: one misconfigured bind address exposes bearer tokens in
  the clear. The rule above allows the proxy pattern and makes the unsafe
  case impossible.
- **A shared rate-limit store such as Redis.** A new infrastructure
  dependency for a single-node product. Deferred until horizontal
  scaling is real.

## Consequences

**Easier.** Every gate has one answer, and the code can be tested
without a network. A leaked token is recognisable and revocable, and a
database leak yields no tokens. Error handling is one mapping.

**Harder.**

- One more table and an admin subcommand.
- Per-instance rate limits need stating to operators.
- The error-code registry must be maintained, and a test keeps it in step
  with the code.

## Follow-ups

- [x] The `api_tokens` migration (V15), the `Authenticator` trait and the
  token subcommand.
- [x] `docs/api/error-codes.md`, with a test that every code the API can
  emit is listed.
- [ ] The rate-limit numbers and the multi-instance caveat in the
  operations docs.
