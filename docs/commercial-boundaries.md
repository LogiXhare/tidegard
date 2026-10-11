# Commercial Boundaries

Status: Phase 0 draft
Last updated: 2026-08-20

## 1. Business Intent

WeTechi Solutions intends to use WetechiNetMon for internal network
monitoring, ISP infrastructure monitoring, enterprise customer monitoring,
data-center traffic visibility, managed DDoS detection/mitigation services,
as an on-premises customer appliance, as a subscription-based commercial
product, as an open-source community product, and as the foundation for
professional support services.

## 2. Edition Boundaries (proposed, not final)

### Community Edition

- Open telemetry collector (IPFIX/NetFlow/sFlow)
- Core aggregation
- Static threshold detection
- Basic incident lifecycle
- Prometheus metrics
- Grafana dashboards
- Manual mitigation
- Community support (issues/discussions, no SLA)

### Enterprise Edition (proposal — not built pre-v1.0)

- Multi-tenancy
- Advanced RBAC
- SSO (OIDC / Entra ID)
- Audit retention
- Advanced (statistical/baseline) anomaly detection
- Approval workflows
- Reporting
- Enterprise support
- HA deployment
- Premium integrations

### Managed Service (proposal — not built pre-v1.0)

- Hosted control plane
- Multi-customer monitoring
- Managed NOC
- Managed mitigation
- SLA
- Customer portal
- Usage reporting
- Subscription management

## 3. Explicit Rule for the MVP

**Do not implement artificial limitations in the open-source core during
the MVP.** Feature gating between Community and Enterprise is a later,
deliberate product decision — not something to bake into MVP code paths
as a shortcut. This avoids both (a) accidentally crippling the open-source
core in ways that are hard to walk back, and (b) building enterprise gating
logic before there is an Enterprise edition to gate.

## 4. Architectural Boundaries Required to Support This Later

Even though editions are not built pre-v1.0, the architecture must not
foreclose them:

- Open-source core must be independently useful and deployable on its own.
- Optional enterprise modules, optional commercial control plane, optional
  hosted SaaS control plane, managed-service integrations, customer-specific
  plugins, private branding packages, and professional support tooling must
  all be things the architecture *can* grow into, without a rewrite.
- Multi-tenancy (schema-level tenant scoping) should exist from early
  phases even though tenant *isolation enforcement* (RBAC, SSO) ships later
  — retrofitting tenant IDs into schemas after the fact is expensive and
  error-prone.
- For incident management, the seams an Enterprise build may extend, and
  the correctness invariants it may never replace, are fixed by
  [ADR 0017](architecture/decisions/0017-incident-community-enterprise-boundary.md).

## 5. Licensing Posture for the Product Itself

This document does not select WetechiNetMon's own open-source license.
That is a Phase 1 decision (`LICENSE` file, per master prompt section 22)
and should weigh:

- Community adoption goals (permissive licenses like Apache-2.0 lower
  adoption friction)
- Protecting WeTechi Solutions' ability to offer Enterprise/Managed tiers
  without a competitor forking and undercutting the exact same code
  (may favor a source-available or dual-license model, or a permissive
  core with enterprise modules kept proprietary/separate)
- Avoiding entanglement with copyleft dependencies flagged in
  [dependency-license-matrix.md](dependency-license-matrix.md) (notably
  Grafana AGPLv3 exposure)

This is flagged as a **blocking question** — see
[blocking-questions.md](blocking-questions.md) — because it materially
shapes Phase 1 repository scaffolding (LICENSE, NOTICE, CONTRIBUTING) and
should be a deliberate WeTechi Solutions decision, not an agent default.

## 6. Pricing Dimensions (documented, not priced)

Per master prompt section 27, potential commercial pricing dimensions to
document for future use, without inventing final prices: monitored
bandwidth, flow records per second, exporters, protected prefixes, tenants,
data retention, automated mitigation, managed support, SLA, premium
integrations. No pricing figures are proposed in Phase 0 or any phase
unless WeTechi Solutions supplies them.

## 7. Non-Goals

- No commercial pricing is fabricated.
- No customer contracts, SLAs, or support terms are drafted here — this is
  a technical/product document, not a legal one.
- No competitive claims against any named or unnamed proprietary vendor.
