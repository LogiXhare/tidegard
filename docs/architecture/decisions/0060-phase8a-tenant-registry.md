# 0060. Phase 8A: The Tenant Registry

Status: **Accepted**
Date: 2026-10-28
Deciders: Repository owner (BQ-20, 2026-10-28), the details under the
delegation of 2026-10-05 to industry practice

## Context

Until v1.0.0 a tenant was only an id. Tokens, incidents, mitigations and
the outbox carried it, and the detector's and the mitigator's
configuration files said which prefixes it owned. Nothing said which
tenants exist, so nothing could suspend one, and two files could give
the same prefix to two tenants without either service noticing.

BQ-20 settled where tenants live: a registry in PostgreSQL that every
service reads, managed by platform roles. This ADR records the
registry's shape and how an existing install moves onto it. The roles
of FR-12.2 and the platform API come in 8A-2 and 8A-3, each in this ADR's
"Later in 8A" section when it lands.

## Decision

### The tables (V22)

- **`tenants`:** the id (the same text ids already in use, 1 to 128
  characters), a display name, a status of `active` or `suspended`, and
  timestamps. `platform` is refused by a `CHECK`: it is the scope of
  deployment-wide records such as BGP session events, never a tenant.
- **`tenant_prefixes`:** one row per prefix, with its tenant. An
  exclusion constraint, `EXCLUDE USING gist (prefix inet_ops WITH &&)`,
  refuses any two rows that overlap, in one tenant or two. PostgreSQL's
  built-in `inet_ops` operator class needs no extension.
- **No claim wider than `/8` (IPv4) or `/16` (IPv6).** One mistaken
  `0.0.0.0/0` would otherwise block every other tenant's claim and own
  every address.
- **`api_tokens.tenant_id` references `tenants`.** A token for a tenant
  nobody registered, a typo for instance, is refused by the database.

The rules live in the schema so that they hold for every writer: the
API, the host command, and a hand-written `psql` session alike.
`crates/incident-postgres/src/tenants.rs` repeats them only to give a
clear error before the database refuses, and names the prefix and owner
an overlapping claim collides with.

### Upgrading an install

V22 registers every tenant id already present, as an active tenant named
by its id. It finds them by reading the catalog for every table with a
`tenant_id` column, not from a list kept by hand, so a table added in a
later release cannot be missed. `platform` is skipped. Nothing else
changes for a single-tenant install: its one tenant is registered, its
tokens keep working, and it needs no new configuration (FR-13.2).

Prefixes are not imported. The detector's and the mitigator's files keep
working as they are; 8D makes each service check them against the
registry, with an upgrade step to register the prefixes first.

### Suspension

A suspended tenant's tokens and sessions are refused exactly like an
unknown token: `401 api.unauthenticated`, which says nothing about why.
The bearer lookup, the session lookup and the sign-in exchange each join
`tenants` and require `active`. Its incidents, mitigations and audit
records are kept, and reactivating the tenant restores access.

### The host command

`tidegard-api tenant create|list|suspend|activate` and
`tidegard-api tenant prefix add|remove|list` manage the registry from
the host, as `tidegard-api token` manages tokens: the first tenant needs
no running API and no prior token.

`tidegard-api token create` registers a tenant it has not seen before
and says so on standard error. Every v1.0.0 script, drill and guide that
creates a token for a new tenant therefore keeps working. The library
function behind it, `token_admin::create`, does not: it refuses an
unregistered tenant with `UnknownTenant`, and the platform API in 8A-3
will require the tenant to exist.

## Consequences

**Easier.** Every service can read one answer to "who owns this
address" (`tenants::owner_of`, `tenants::ownership`). A tenant can be
suspended without deleting anything. A prefix overlap is impossible, not
merely checked.

**Harder.** A test or script that inserts a token directly must register
its tenant first; the API's tests do so in their token helpers.

**Not yet.** Changes to the registry are not audited: the audit table
has no actor type for a platform actor yet (FU-48). 8A-3 adds the
platform actor and audits every registry change made through the API.
The host command acts with the host's own authority, as the token
command does.

## 8A-2: the roles and the platform scope

### Twelve roles in two scopes

FR-12.2's ten roles become twelve bundles in `FixedBundleResolver`,
because the four v1.0.0 roles stay as they were: no existing token gains
or loses a permission, and a test pins each of the four. The
[security model](../incident-security-model.md) lists every bundle.

| Scope | Roles |
|---|---|
| Tenant | `viewer`, `operator`, `senior_operator`, `noc_lead`, `customer_admin`, `security_analyst`, `automation` |
| Platform | `noc_operator`, `noc_admin`, `auditor`, `platform_admin`, `super_admin` |

- **`platform_admin` no longer holds every permission.** It administers
  tenants, tokens and the kill switch release, and reads, but changes no
  incident. `super_admin` holds every human permission, and is the only
  bundle with `incident.closure_policy.override`. No token could carry
  `platform_admin` before, so nothing deployed changes.
- **`automation` is a fixed bundle for integrations** (read, open,
  acknowledge, note), held only by service accounts. The plan imagined a
  per-token permission list; a fixed bundle is easier to review and
  covers a ticketing or SOAR integration. A per-token list can come
  later without a schema change to roles.
- Two permissions join: `platform.tenant.admin` for the registry, and
  `tenant.token.admin` for a tenant's own tokens. `customer_admin` holds
  the second, `platform_admin` both. The endpoints that check them come
  in 8A-3.

### Platform tokens (V23)

`api_tokens` gains a `scope`, `tenant` or `platform`. One `CHECK`
couples scope, tenant and role: a tenant token names a tenant and holds a
tenant role; a platform token names none, holds a provider role, and
lives at most 90 days (R36). Another keeps `automation` for service
accounts. `tidegard-api token create --platform` issues one on the host,
and `token list --platform` lists them. Suspending a tenant never
touches a platform token.

### Acting in a tenant

A platform principal names the tenant it acts in, per request, in the
`Tidegard-Tenant` header. Every handler and every domain call already
scope by the principal's tenant, so none of them changes: the
authentication middleware sets that tenant from the header, after
checking the tenant is registered. A suspended tenant can still be
looked into by its provider.

- **No header:** only `whoami`, the session and `/api/v1/platform/*`
  answer. Everything else is `400 api.tenant_required`.
- **An unregistered tenant**, or `platform`: `400 api.tenant_unknown`.
- **A tenant principal** may send the header only with its own tenant.
  Naming any other, registered or not, is `403 api.forbidden`, so it
  learns nothing about other tenants.
- `whoami` answers with the scope and the tenant acted in.

Every cross-tenant access is to be audited (BQ-21); that lands with 8D,
where the provider's identity is recorded on the tenant's audit trail.
The NOC UI cannot send the header yet; its tenant switcher is 8E.

## 8A-3: the registry and tokens over the API

### The registry

`/api/v1/platform/tenants` lists and registers tenants;
`/platform/tenants/{tenant_id}` reads one with its prefixes; `suspend` and
`activate` change its status; `/prefixes` registers a prefix, and
`/prefixes/{address}/{length}` removes one, the prefix's slash becoming a
path separator. Reading needs `platform.incident.read_all`, which every
provider role holds and no tenant role does; changing needs
`platform.tenant.admin`. A tenant principal gets `403 api.forbidden`.

The overlap is looked for before the insert, so the `409
tenant.prefix_overlap` names the prefix in the way and its owner: an
insert that failed would have aborted the transaction before anything
could be read. The exclusion constraint still decides a race between two
writers, which is refused without a name.

### A tenant's tokens

`/api/v1/tokens` lists and issues tokens in the tenant acted in, and
`/tokens/{token_id}/revoke` revokes one, under `tenant.token.admin`:

- **A platform principal may issue any tenant role.** That is how a
  provider gives a new customer its first `customer_admin`.
- **A tenant principal may issue only a role whose every permission it
  holds itself**, so no token is worth more than its issuer.
- **Platform tokens are issued on the host only.** The API never mints
  a key to every tenant.
- Another tenant's token, a platform token, a revoked one and a
  malformed id are the same `404 token.not_found`.

### Audit

Every change, to the registry or to a token, writes an `incident_audit`
row in the same transaction, on the tenant concerned, with the actor
that made it: a provider's change is on its customer's trail, readable
by the customer (BQ-21). A change that cannot be audited does not
happen. No secret is in any record. The host commands are not audited:
they act with the host's own authority, as before.

## Later in 8A

- **8A-4:** `tidegardctl tenants` and `tokens`, and a `--tenant` option
  for platform principals.
