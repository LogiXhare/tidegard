# Phase 8 Plan: Multi-Tenancy and Enterprise Authentication

Status: **Planning, accepted by the owner 2026-10-28.** No Phase 8 code
exists yet. The decisions this plan rests on are BQ-19 to BQ-22 in
[blocking questions](../blocking-questions.md). Each milestone records
its own engineering decisions in an ADR when it starts, as Phases 5 to
10 did.

Phase 8 delivers what FR-12 and FR-13 ask for and v1.0.0 left out:
tenant isolation enforced by the database as well as the application,
traffic scoped to the tenant that owns it, the ten roles of FR-12.2, and
sign-in through local accounts, OIDC and Microsoft Entra ID with MFA. It
ships in two releases (BQ-19): **v1.1.0**, multi-tenancy (8A to 8E), and
**v1.2.0**, enterprise authentication (8F to 8H), as the
[roadmap](../roadmap.md) has always listed them.

## What does not change

- **A v1.0.0 install keeps working.** A single-tenant deployment
  upgrades to v1.1.0 and v1.2.0 with its tenant ids, tokens, incidents
  and mitigations intact, and needs no new configuration to go on running
  as one tenant (FR-13.2). An upgrade test with v1.0.0 data proves it in
  CI, as 9C did for v0.9.0.
- **The four tenant roles keep their meaning.** `viewer`, `operator`,
  `senior_operator` and `noc_lead` keep their names and permissions, so
  no existing token gains or loses anything.
- **API tokens stay.** They remain the way in for scripts, service
  accounts and the `AutomationService` role. v1.2.0 adds people's
  sign-in beside them; it does not replace them.
- **Production BGP stays off by default, and nothing announces without a
  human** (BQ-17). Phase 8 changes who may approve, never whether
  approval is needed.
- **No real network.** Tests use the documentation prefixes and private
  ASNs, and sign in against identity providers CI starts itself. No real
  Entra ID tenant's credentials enter CI.
- **Free tier only**, as for every phase so far.

## Decisions taken for this plan

| Question | Decision | Why |
|---|---|---|
| BQ-19 Order | Two releases: v1.1.0 multi-tenancy (8A–8E), then v1.2.0 enterprise authentication (8F–8H) | Each release is smaller to review and to roll back. Tenancy is the larger change to data, sign-in the larger change to the attack surface; they should not land together |
| BQ-20 Where tenants live | A tenant registry in PostgreSQL, holding tenants and their prefixes, managed through the API and CLI by platform roles. Detection, notification and mitigation policy stay in configuration files keyed by tenant, checked against the registry | One source of truth for who owns which address, which every service reads. Moving policy editing into the API is a larger product change, left for after v1.2.0 |
| BQ-21 Cross-tenant work | The provider roles of FR-12.2 (SuperAdmin, PlatformAdmin, NOCAdmin, NOCOperator, ReadOnlyAuditor) act across tenants through the API. Every cross-tenant access is audited. Deployment-wide controls move to platform roles (FU-65) | A provider's NOC must see every customer's incidents (the managed-service mode of FR-13.2). One token per tenant does not scale and hides who acted |
| BQ-22 Sign-in methods | Generic OIDC and Microsoft Entra ID (through OIDC), local accounts with argon2id passwords, and TOTP for MFA. LDAP waits for a later release | Covers an ISP with an IdP and one without. LDAP adds a bind credential and a directory protocol for little the OIDC path does not already give |

## The roles

FR-12.2 lists ten roles. The 8A ADR fixes the permission bundles; this
plan fixes their scope and how the existing four fit:

| FR-12.2 role | Name in Tidegard | Scope | Starting point |
|---|---|---|---|
| SuperAdmin | `super_admin` | Platform | Everything, including granting platform roles. Bootstrap only through the host CLI |
| PlatformAdmin | `platform_admin` | Platform | Tenants, prefixes, users, tokens, the kill switch release and BGP peers. No incident write |
| NOCAdmin | `noc_admin` | Platform | `noc_lead`'s permissions in every tenant, and engaging the kill switch |
| NOCOperator | `noc_operator` | Platform | `senior_operator`'s permissions in every tenant |
| ReadOnlyAuditor | `auditor` | Platform | Read everything, including audit records. Change nothing |
| CustomerAdmin | `customer_admin` | Tenant | `noc_lead`'s permissions, and the tenant's own users and tokens |
| CustomerOperator | `operator` | Tenant | Unchanged |
| CustomerViewer | `viewer` | Tenant | Unchanged |
| SecurityAnalyst | `security_analyst` | Tenant | Read, notes, traffic and export. No state change or mitigation |
| AutomationService | `automation` | Tenant | For service accounts: the permissions its token is created with, never more than `noc_lead` |

`senior_operator` and `noc_lead` stay as tenant roles for a single-tenant
appliance, where the ISP's own NOC is the tenant.

## Milestones

Each milestone ends green and is independently mergeable. 8A to 8E
release as v1.1.0; 8F to 8H as v1.2.0.

### 8A — The tenant registry and the roles

- **Tenants:** a `tenants` table with the id (the same text ids tokens
  and incidents already carry), a display name, a status (`active` or
  `suspended`) and timestamps. The migration creates a row for every
  tenant id already present, so an upgraded install finds its tenant
  registered.
- **Prefixes:** `tenant_prefixes`, one row per prefix and tenant. An
  exclusion constraint over `inet` makes two tenants' prefixes
  overlapping impossible in the database, not only in code.
- **A suspended tenant's** tokens and sessions are refused; its data is
  kept.
- **Principals** gain a scope: a tenant, or the platform. The roles in
  the table above join the permission resolver. Platform tokens are
  created only by `super_admin` or on the host, expire sooner than tenant
  tokens, and are listed separately.
- **API and CLI:** `/api/v1/platform/tenants` and their prefixes, in the
  OpenAPI document; `tidegardctl tenants`; `tidegard-api tenant` on the
  host for the first tenant and the first `super_admin` token.

**Exit:** each of the ten roles has at least one allow and one deny
test; two tenants' overlapping prefixes are refused by PostgreSQL 15 to
18; an install with v1.0.0 data upgrades with every tenant registered.

**Progress:** 8A-1 ([ADR 0060](decisions/0060-phase8a-tenant-registry.md)) adds V22: `tenants` and `tenant_prefixes`, with an exclusion constraint that refuses overlapping prefixes, floors of `/8` and `/16`, `platform` reserved, and `api_tokens` referencing `tenants`. The migration registers every tenant id already in use, found from the catalog. A suspended tenant's tokens, sessions and sign-ins are refused. `tidegard-api tenant` manages the registry from the host, and `token create` registers a new tenant so v1.0.0 scripts keep working. `crates/incident-postgres/tests/tenant_registry.rs` proves the upgrade and every refusal on PostgreSQL 15 to 18. 8A-2 adds the twelve role bundles (the four of v1.0.0 unchanged, pinned by a test, and every role with an allow and a deny case), platform tokens (V23: a provider role, no tenant, at most 90 days), and the `Tidegard-Tenant` header a platform principal acts in a tenant with; `apps/api/tests/tenant_isolation.rs` proves a provider sees only the tenant it names, and a tenant token cannot name another. 8A-3 puts the registry under `/api/v1/platform/tenants` for platform roles and a tenant's tokens under `/api/v1/tokens` for `tenant.token.admin`, with no role issued beyond the issuer's own permissions and platform tokens on the host only; every change is audited on the tenant's trail in the same transaction (`apps/api/tests/platform.rs`). 8A-4 adds `tidegardctl tenants` and `tokens`, and `--tenant` for platform principals. **8A is complete.**

### 8B — Row-level security

FU-21 and R16, the work ADR 0032 prepared for:

- **A runtime role that is not the owner.** Today every service logs in
  as the role that owns the tables, and an owner is exempt from its own
  table's policies. The services move to a login role without
  `BYPASSRLS` that owns nothing (V11's `wetechinetmon_app`, renamed as
  ADR 0058 noted), migrations keep running as the owner, and every
  tenant-owned table has `FORCE ROW LEVEL SECURITY`.
- **Policies** on every tenant-owned table admit a row only when its
  `tenant_id` matches the tenant the transaction set. With no tenant
  set, a query returns nothing.
- **The tenant is set per transaction** (`SET LOCAL`), by the unit of
  work that already takes the tenant as an argument, so nothing survives
  into the pool's next borrower (ADR 0032, layer 6).
- **Cross-tenant work is explicit.** Provider roles, and the services
  that work across tenants (the incident manager's ingest, the notifier's
  outbox, the mitigator), use a platform scope that only named code
  paths can set. The 8B ADR chooses between a scope setting and a second
  role. Either way, no role has `BYPASSRLS`, and a tenant-scoped endpoint
  never runs under the platform scope.
- Installation, the Compose stack and the upgrade guide gain the role
  change, with its password from the operator's secret store.

**Exit:** a test reads the catalog and fails if any table with a
`tenant_id` lacks a forced policy, so a new table cannot be forgotten.
As the runtime role, with tenant A set, raw `SELECT`s on every such
table return only A's rows; with none set, none. R16 is closed.

### 8C — Traffic tenancy

R21: ClickHouse traffic carries no tenant today.

- **Scoped at query time.** The API answers a tenant's traffic queries
  from the per-address tables (host, network, `/24`, hostgroup),
  filtered to the tenant's registered prefixes. Nothing on the ingest
  path changes, so the collector's measured rate is not put at risk.
  The 8C ADR confirms this against tagging rows at ingest, with a
  benchmark.
- **Deployment-wide tables stay platform-only.** Totals, ASNs,
  exporters and interfaces mix every tenant's traffic and are readable
  only by platform roles.
- **Detection events** already carry their tenant and are filtered by
  it.
- **The API gets a read-only ClickHouse user** (FU-66).
- **Grafana stays the provider's tool**, on platform data. A tenant's
  traffic view is the NOC UI.

**Exit:** the tenant-isolation suite covers every traffic endpoint:
tenant A never receives a row for B's prefixes, and the platform-only
tables refuse every tenant role.

### 8D — Tenant-checked configuration and deployment controls

- **Configuration checked against the registry** (BQ-20). The detector's
  policies, the mitigator's allowlist and the notifier's routes stay
  files keyed by tenant. Each service refuses, at start and on reload,
  a tenant that is unknown or suspended, and a prefix outside the
  tenant's registered prefixes.
- **Deployment-wide controls are platform controls** (FU-65). Engaging
  the kill switch needs `noc_admin` or above, releasing it
  `platform_admin` or above; BGP peers are platform-only. A tenant sees
  only its own mitigations and routes.
- **Audit across tenants.** Every action a provider role takes in a
  tenant is audited with the provider's identity, and the tenant can
  read those records about its own data.
- **Per-tenant quotas** for API requests and exports (FR-13.1), with
  deployment-wide defaults.

**Exit:** configuration naming an unknown tenant or a foreign prefix is
refused by every service; FU-65 is closed by tests that a tenant's
`noc_lead` can no longer engage the kill switch or read the peers.

### 8E — The UI, hardening and v1.1.0

- **NOC UI:** a tenant switcher for provider roles, the current tenant
  always visible, and platform pages for tenants and prefixes.
- **CLI:** `--tenant` for provider principals.
- **Threat model** (T-58 onwards): cross-tenant reads through the
  platform scope, the tenant setting forged or leaked across pooled
  connections, a suspended tenant's live sessions, prefix overlap to
  claim another tenant's traffic, and a provider token stolen. Each has
  a test or a recorded acceptance.
- **The release acceptance test** runs with two tenants and a provider
  NOC, and proves each sees what it should, end to end.
- An upgrade test from v1.0.0, a Gate 2 assessment, and **v1.1.0**
  through the release pipeline.

**Exit:** Gate 2 of the
[acceptance criteria](../development/phase8-acceptance-criteria.md).

### 8F — Users and local accounts

- **A user directory:** users, each with role assignments (a user may
  hold a platform role, or roles in one or more tenants), disablement,
  and the time of the last sign-in. An assignee is checked against it
  (FU-60, T-21).
- **Local accounts:** passwords hashed with argon2id at OWASP's current
  parameters, a minimum length and a check against common passwords
  (NIST SP 800-63B), and failed sign-ins rate-limited per account and per
  address, without a lockout an attacker can use to deny service.
- **TOTP** (RFC 6238) with single-use recovery codes. Required for every
  platform role; a deployment setting may require it for all.
- **Sessions** come from a password and TOTP sign-in. Signing in with an
  API token (BQ-10) stays for compatibility and can be turned off.
- **Self-service:** a `customer_admin` manages its tenant's users and
  tokens; a reset is an administrator-issued one-time link, since
  Tidegard sends no email of its own outside notifications.

**Exit:** sign-in, MFA enrolment, disablement ending live sessions, and
the rate limit are tested end to end against the API and the UI.

### 8G — OIDC and Microsoft Entra ID

- **Authorization code flow with PKCE**, `state` and `nonce`, the ID
  token's signature checked against the provider's published keys, and
  its issuer, audience and expiry checked.
- **Entra ID** through its OIDC endpoints, for one configured Entra
  tenant; no "any organisation" sign-in unless configured.
- **Roles from claims:** groups or app roles map to Tidegard roles and
  tenants by configuration. A user who matches no mapping signs in to
  nothing. MFA can be required through the `amr` claim.
- **Library:** the 8G ADR reviews a maintained OIDC crate; it is pinned,
  confined to the API by the dependency closure test, and at least two
  weeks old.
- **CI** signs in through a local OIDC provider it starts itself. Entra
  ID is tested against its documented token shapes; the owner may try a
  real Entra tenant by hand before the release.

**Exit:** a Playwright test signs in through the local provider, end to
end; negative tests refuse a wrong issuer, a wrong audience, an expired
token, `alg: none`, a replayed `nonce` and an unmapped user.

### 8H — Hardening and v1.2.0

- **Rotation and expiry** for sessions, passwords and tokens, as FR-12.1
  lists, and an audit trail of every sign-in, failure, MFA change and
  role change.
- **Threat model:** credential stuffing, MFA bypass, token substitution
  between providers, open redirects, session fixation and CSRF on the
  sign-in flow. Each has a test.
- **An independent review** of the authentication code before the
  release, as the release candidates had.
- A Gate 3 assessment and **v1.2.0** through the release pipeline.

**Exit:** Gate 3 of the
[acceptance criteria](../development/phase8-acceptance-criteria.md).

## What Phase 8 does not build

- LDAP (BQ-22), SAML and SCIM provisioning.
- Editing detection, notification or mitigation policy through the API
  (BQ-20).
- Per-tenant retention in ClickHouse, per-tenant Grafana organisations,
  and tenant-scoped backup and restore.
- Billing or subscription management (the Managed Service proposal in
  [commercial boundaries](../commercial-boundaries.md)).

## Risks

| Id | Risk | Response |
|---|---|---|
| R35 | A new tenant-owned table is created without a row-level security policy | The catalog test fails any table with a `tenant_id` and no forced policy (8B) |
| R36 | A stolen provider token or account reaches every tenant | Shorter expiry for platform tokens, MFA required for platform roles, and every cross-tenant access audited (8A, 8D, 8F) |
| R37 | The upgrade from v1.0.0 breaks a running install: the role change, or policies hiding rows | An upgrade test with v1.0.0 data in CI, tenants registered by the migration, and the steps in the upgrade guide (8A, 8B, 8E) |
| R38 | Filtering traffic by prefix at query time is slow for a tenant with many prefixes | A bounded prefix count per tenant, measured before the decision (8C) |
| R39 | A flaw in OIDC validation lets a forged or foreign token sign in | A reviewed library, negative tests for each validation, and an independent review (8G, 8H) |
| R40 | Local passwords bring credential stuffing and a stored-hash target | argon2id, rate limits per account and address, TOTP, and OIDC preferred in the guides (8F) |

## Where to read next

- [Phase 8 acceptance criteria](../development/phase8-acceptance-criteria.md)
- [Blocking questions](../blocking-questions.md): BQ-19 to BQ-22
- [ADR 0032](decisions/0032-phase5b-tenant-isolation-and-rls-readiness.md):
  what Phase 5 prepared for row-level security
- [Known issues](../release/known-issues.md): the v1.0.0 limits Phase 8
  closes
