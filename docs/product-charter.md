# Tidegard — Product Charter

Status: Phase 0 draft
Owner: WeTechi Solutions
Last updated: 2026-08-20

## 1. Purpose

Tidegard is an independently engineered open network telemetry, DDoS
detection, traffic analytics, and policy-controlled mitigation platform for
ISPs, enterprises, data centers, hosting providers, and managed network
service providers.

It exists to give WeTechi Solutions (and later, third-party operators) a
self-owned, clean-room alternative to proprietary flow-analytics/DDoS
platforms, with no licensing dependency on any proprietary vendor and no
reuse of proprietary code, schemas, terminology, or UI.

## 2. Product Identity

| Item | Value |
|---|---|
| Company | WeTechi Solutions |
| Product | Tidegard |
| Core engine | SentinelFlow Engine |
| CLI | `tidegardctl` |
| Tagline | "See Every Flow. Defend Every Network." |
| Repository | `tidegard` |
| GitHub organization | `wetechi` |
| Service namespace | `tidegard` |

Container images (proposed):

- `ghcr.io/wetechi/tidegard-collector`
- `ghcr.io/wetechi/tidegard-aggregator`
- `ghcr.io/wetechi/tidegard-detector`
- `ghcr.io/wetechi/tidegard-api`
- `ghcr.io/wetechi/tidegard-web`
- `ghcr.io/wetechi/tidegard-mitigator`

Full naming rationale lives in [naming-and-branding.md](naming-and-branding.md).

## 3. Problem Statement

ISP and enterprise operators need visibility into NetFlow / IPFIX / sFlow
traffic, automated DDoS detection, and policy-gated BGP RTBH/FlowSpec
mitigation, without depending on a proprietary product's license terms,
source availability, or roadmap.

## 4. Product Description (approved wording)

Use only this description in all product-facing materials:

> "Tidegard is an independently engineered open network telemetry,
> DDoS detection, traffic analytics, and policy-controlled mitigation
> platform."

Never describe it as a clone, replica, copy, alternative build,
reverse-engineered edition, or replacement edition of any proprietary
product. See [clean-room-boundary.md](clean-room-boundary.md).

## 5. Business Objectives

1. Internal network monitoring for WeTechi Solutions' own and affiliated ISP infrastructure
2. ISP infrastructure monitoring
3. Enterprise customer monitoring
4. Data-center traffic visibility
5. Managed DDoS detection services
6. Managed mitigation services
7. On-premises customer appliance
8. Subscription-based commercial product
9. Open-source community product
10. Foundation for professional support services

## 6. Primary Product Categories

NetFlow monitoring, IPFIX monitoring, sFlow monitoring, network traffic
analytics, DDoS detection, network anomaly detection, incident management,
Grafana dashboards, BGP RTBH automation, BGP FlowSpec automation, managed
DDoS monitoring, policy-controlled mitigation.

## 7. Stakeholders

| Role | Interest |
|---|---|
| WeTechi Solutions (product owner) | Commercial product, internal use, IP ownership |
| ISP/NOC operators | Operational telemetry, DDoS defense |
| Enterprise/data-center customers | Traffic visibility, managed mitigation |
| Open-source contributors | Community edition adoption |
| Claude Code (execution agent) | Phased, documented, tested delivery |

## 8. Success Criteria (Phase 0 level)

- Product identity, clean-room boundary, and license posture are documented
  and unambiguous before any code is written.
- Architecture and technology direction are proposed with trade-offs, not
  prescribed as fait accompli.
- Blocking questions are surfaced explicitly rather than silently assumed.

## 9. Out of Scope for This Charter

Implementation details, schemas, and code are intentionally excluded — see
[mvp-scope.md](mvp-scope.md), [out-of-scope.md](out-of-scope.md), and the
per-phase deliverables in [roadmap.md](roadmap.md).

## 10. Governing Document

This charter is subordinate to `prompts/CLAUDE_MASTER_PROMPT.md`, which is
the authoritative source for all product, architectural, legal, and process
requirements. Where any Phase 0 document appears to conflict with the
master prompt, the master prompt governs.
