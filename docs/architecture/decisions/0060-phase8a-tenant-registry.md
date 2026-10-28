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

## Later in 8A

- **8A-2:** the roles of FR-12.2, a principal's scope (one tenant or the
  platform), and platform tokens.
- **8A-3:** `/api/v1/platform/tenants` and their prefixes,
  `tidegardctl tenants`, and audit of registry changes.
