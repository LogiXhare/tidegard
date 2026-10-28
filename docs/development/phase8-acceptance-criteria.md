# Phase 8 Acceptance Criteria

Status: **Defined 2026-10-28, before any Phase 8 code.** Part of the
[Phase 8 plan](../architecture/phase8-multi-tenancy-enterprise-auth-plan.md).

As in Phases 5 to 10, the criteria are written before the work starts,
so the work is judged against them rather than the other way round. Each
one is assessed with the test, run or document that proves it. The
general criteria for Phase 8 in
[acceptance criteria](../acceptance-criteria.md) still apply; these make
them concrete.

## Gate 1 — Planning accepted

- [x] The owner has decided BQ-19 to BQ-22
  ([blocking questions](../blocking-questions.md)).
- [x] The plan names each milestone, its exit criterion, and the risks
  (R35 to R40 in the [risk register](../risk-register.md)).
- [x] These criteria exist before any Phase 8 code.

## Gate 2 — v1.1.0, multi-tenancy

### Compatibility

- An install with v1.0.0 data upgrades to v1.1.0 in CI with its
  incidents, mitigations and tokens intact, every tenant id registered,
  and every service ready.
- The four v1.0.0 roles grant exactly the permissions they granted in
  v1.0.0, asserted by a test.

### The registry and the roles (8A)

- Two tenants' overlapping prefixes are refused by the database on
  PostgreSQL 15 to 18.
- A suspended tenant's tokens and sessions are refused, and its data is
  kept.
- Each of the ten FR-12.2 roles has at least one allow and one deny
  test.

### Row-level security (8B)

- No service logs in as a role that owns the tables or has `BYPASSRLS`.
- A catalog test fails if any table with a `tenant_id` lacks a forced
  row-level security policy.
- As the runtime role, raw queries on every tenant-owned table return
  only the set tenant's rows, and none with no tenant set.
- Every cross-tenant code path is named in the 8B ADR and tested.
- R16 is closed in the risk register.

### Isolation (8B, 8C)

- The tenant-isolation suite proves tenant A cannot read tenant B's data
  through any API operation, including traffic and export, with the
  operations read from the OpenAPI document as before.
- The platform-only traffic tables refuse every tenant role.
- R21 is closed in the risk register.

### Configuration and controls (8D)

- The detector, the mitigator and the notifier each refuse
  configuration naming an unknown or suspended tenant, or a prefix
  outside its tenant's prefixes.
- A tenant's `noc_lead` can no longer engage the kill switch or read the
  BGP peers (FU-65 closed).
- A provider role's action in a tenant is audited with its identity and
  is readable by that tenant.

### Release (8E)

- Every new threat has a test or a recorded acceptance.
- The release acceptance test passes with two tenants and a provider
  NOC.
- A Gate 2 assessment records each criterion with its proof, and v1.1.0
  is published by the release pipeline and verifies from a clean runner.

## Gate 3 — v1.2.0, enterprise authentication

### Local accounts (8F)

- Passwords are stored only as argon2id hashes, and the parameters are
  asserted by a test.
- Failed sign-ins are rate-limited per account and per address, and a
  test shows an attacker cannot lock a user out.
- TOTP is required for every platform role, and recovery codes work
  once each.
- Disabling a user ends their live sessions at once.
- An assignee is checked against the user directory (FU-60 and T-21
  closed).

### OIDC and Entra ID (8G)

- A Playwright test signs in through a local OIDC provider in CI, end to
  end.
- Tokens with a wrong issuer, a wrong audience, an expired time,
  `alg: none` or a replayed `nonce`, and users matching no role mapping,
  are each refused by a test.
- The OIDC dependencies are confined to the API by the dependency
  closure test.

### Release (8H)

- Sign-ins, failures, MFA changes and role changes are in the audit
  trail.
- An independent review of the authentication code has no Critical or
  High finding open.
- A Gate 3 assessment records each criterion with its proof, and v1.2.0
  is published by the release pipeline and verifies from a clean runner.
