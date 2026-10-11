# 0017. The Community/Enterprise Seam Is an Extension Point, Not a Limitation

Status: **Accepted** — 2026-10-05, as implemented (see [Acceptance](#acceptance))
Date: 2026-08-22
Deciders: Repository owner — accepted 2026-10-05 (Phase 5F) under the owner's standing delegation for Phase 5

## Context

[commercial-boundaries.md](../../commercial-boundaries.md) proposes a
Community Edition that ships first and fully, with Enterprise features
layered on later, and states plainly that **no artificial limitations are
added to the open-source core to manufacture demand**. Incident
management is the first phase where that principle meets a feature set
with obvious commercial appeal — SLA tracking, ITSM integration, approval
workflows, cross-tenant correlation.

The risk is real and runs in both directions. Crippling Community
incident management would break the stated promise and the Apache-2.0
positioning settled in BQ-1. But building every Enterprise idea into the
core now would deliver none of it well and foreclose the commercial model
the project depends on.

## Options Considered

### Option A — Everything in Community, decide commercially later

- Pros: maximum openness; no seam to design.
- Cons: no extension point means Enterprise features later require
  invasive changes to core code, which is exactly how a clean seam
  becomes impossible.

### Option B — Feature flags with licence checks in the core

- Pros: one codebase; flip a flag.
- Cons: **licence-check code inside an Apache-2.0 core is an artificial
  limitation** and directly contradicts the stated principle. It also
  invites the community to patch the check out, which poisons the
  relationship.

### Option C — Trait seams; Community ships complete implementations

Define extension traits at the domain boundary. Community provides
complete, production-quality implementations of all of them. Enterprise
substitutes alternatives.

- Pros: Community is fully functional with no stubs and no checks;
  Enterprise extends without forking; the seams are useful in their own
  right for testing and for operators substituting behaviour.
- Cons: requires deciding *where* the seams go before the Enterprise
  features exist, and a wrong guess means a seam nobody uses.

## Decision

**Option C.** Community Phase 5 ships complete incident management:
ingestion, correlation, the full state machine, notes, assignment,
PostgreSQL persistence, immutable timeline, audit, REST API, CLI,
Prometheus metrics, single-node deployment. Nothing is withheld.

Extension points, each with a complete Community implementation:

| Seam | Community implementation | Enterprise might substitute |
|---|---|---|
| `CorrelationStrategy` | Deterministic key from the five dimensions | Cross-policy, cross-target, ML-assisted |
| `AssignmentPolicy` | Manual assignment with a team abstraction | Rotas, escalation matrices, follow-the-sun |
| `IdentityProvider` | Local users and teams | SSO, Entra ID, SCIM |
| `PermissionResolver` | Fixed permission-to-role bundles | Custom roles, per-field authorization |
| `RetentionPolicy` | Fixed defaults | Compliance retention, legal hold |
| `IncidentEventPublisher` | ClickHouse analytics | ITSM, SLA engines, customer portals |
| `NumberAllocator` | Per-tenant yearly sequence | Custom formats |

**No licence checks, no artificial limits, no non-functional stubs.**
Every trait listed has a real Community implementation. A trait whose
Community implementation returns "not available" would be exactly the
artificial limitation this ADR forbids.

Deliberately *not* seams, because they are correctness-critical and
substituting them would let an Enterprise build be quietly wrong: the
state machine, the transaction boundary, tenant isolation enforcement,
the audit record, and optimistic concurrency. These are invariants, not
policies.

**Confirmed 2026-08-22:** the BQ-8 critical-manual-closure default is
Community behaviour, not an Enterprise feature. It is a correctness and
safety default, and this ADR forbids reserving one. The same applies to
the reopen-window mechanism from BQ-9, to effective-configuration
diagnostics, and to the audit of closure-policy overrides — a deployment
that cannot see or audit its own safety settings is not a cheaper
deployment, it is a broken one.

## Consequences

**Easier.** Community is genuinely complete, which is what the licence
and the charter promise. Enterprise extends without forking. The seams
are independently useful — the test suite substitutes clocks and
repositories through the same interfaces.

**Harder.** Seven interfaces to design before their second implementation
exists, which is a real risk of designing the wrong abstraction. The
mitigation is that each has a working Community implementation from day
one, so a seam that turns out wrong is discovered while it is still cheap
to move.

**Forecloses.** Any future decision to restrict Community incident
management. That is deliberate: this ADR is the record that the seam is
an extension point and not a lever.

**Security.** Tenant isolation, audit, and concurrency are explicitly
**not** substitutable, so no alternative implementation can weaken them.

**License.** Consistent with Apache-2.0 (BQ-1) and with
[commercial-boundaries.md](../../commercial-boundaries.md). Enterprise
implementations live outside this repository.

## Acceptance

The principle is accepted unchanged:

- Community ships complete incident management.
- There are no licence checks, artificial limits or non-functional stubs.
- Correctness invariants are never seams.

The seam list is accepted as built, which is narrower than planned:

| Seam | State in Phase 5 |
|---|---|
| `PermissionResolver` | A trait, with the fixed role bundles |
| `NumberAllocator` | A trait, with the per-tenant sequence in PostgreSQL |
| `IncidentGenerator`, `Clock` | Traits (UUIDv7 and system time), also used by tests |
| `Authenticator` (API) | A trait, with bearer tokens |
| `CorrelationStrategy`, `AssignmentPolicy`, `IdentityProvider`, `RetentionPolicy`, `IncidentEventPublisher` | Complete Community behaviour, not yet behind a trait |

The five not yet extracted follow this ADR's own warning about designing
an abstraction before its second implementation exists. Each will be
extracted when a second implementation is real. None is a stub, and
none withholds anything.

## Follow-Up

- [x] Review seam list after Milestone 5A, when the domain types exist
      and a wrong abstraction is still cheap to change.
- [x] Cross-reference from
      [commercial-boundaries.md](../../commercial-boundaries.md).
