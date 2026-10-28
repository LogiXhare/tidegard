# Out of Scope

Status: Phase 0 draft
Last updated: 2026-08-20

Items below are explicitly deferred. Listing them here prevents silent
scope creep and gives each a home to be picked up deliberately later.

## Deferred to Post-MVP (v1.1.0+)

- **Multi-tenancy enforcement** (v1.1.0) — schema-level tenant scoping may
  exist earlier, but full tenant isolation across API/DB/UI/CLI/reports/
  dashboards/notifications/audit is a v1.1.0 deliverable (Phase 8).
- **Enterprise authentication**: OIDC, Microsoft Entra ID, local
  accounts and TOTP MFA (v1.2.0, Phase 8). LDAP comes after v1.2.0
  (BQ-22).
- **Advanced statistical/baseline anomaly detection**: EWMA, MAD,
  hour-of-day/day-of-week/seasonal baselines, cold-start protection,
  confidence scoring, baseline versioning (explicitly "add later" per
  master prompt §9 — static thresholds ship first in Phase 4).
- **Distributed, high-availability architecture** (v2.0.0) — horizontal
  partitioning is designed for from the start (NFR-3) but full HA/
  distributed operation is a v2.0.0 milestone, not MVP.
- **Managed Service tier**: hosted control plane, multi-customer
  monitoring, managed NOC, customer portal, subscription management —
  proposal only until WeTechi Solutions commits to building it (see
  [commercial-boundaries.md](commercial-boundaries.md)).
- **Enterprise Edition tier**: advanced RBAC, SSO, audit retention
  policies, approval workflows, premium integrations, HA deployment as a
  packaged offering — proposal only, not built pre-v1.0.
- **SMS notification plugin** — listed as "optional" in the master prompt;
  not part of the core notification set for MVP.
- **PagerDuty integration depth** — included in the channel list but not
  prioritized ahead of email/Teams/Slack/Telegram/webhook for MVP UI/UX
  polish.

## Explicitly Not This Product's Job

- Generating real attack traffic, under any circumstance, for any testing
  purpose (safety rule, not a scope trade-off — see
  [security-principles.md](security-principles.md)).
- Enabling production BGP automatically — remains an explicit,
  human-gated action forever, not just during MVP.
- Legal/contractual work: SLAs, customer contracts, pricing agreements,
  trademark filings — this is a technical/product repository.
- Reproducing any proprietary vendor's dashboards, schemas, CLI syntax, or
  documentation — permanently out of scope, not phase-limited (see
  [clean-room-boundary.md](clean-room-boundary.md)).

## Deferred Technical Decisions (not scope cuts, just not decided yet)

- Final event-transport selection (NATS JetStream vs. Redpanda vs. Kafka)
  — ADR required before Phase 3.
- Mitigation Controller implementation language (Rust vs. Go) — ADR
  required before Phase 7.
- Tidegard's own open-source license — blocking question, see
  [blocking-questions.md](blocking-questions.md).
- Recharts vs. Apache ECharts for the web UI — lightweight ADR before
  Phase 6.

## Review Cadence

This list should be revisited at the start of each phase — items may move
into scope for that phase, but nothing here should be built early "since
we're in the area" without updating this document and the roadmap first.
