# Tidegard

**See Every Flow. Defend Every Network.**

Tidegard is an independently engineered open network telemetry, DDoS
detection, traffic analytics, and policy-controlled mitigation platform
for ISPs, enterprises, data centers, hosting providers, and managed
network service providers.

> **Project status: v1.0.0**, released 2026-10-28: the production-ready
> single-tenant release. Collector, aggregator, detector, and incident
> management with PostgreSQL persistence, a REST API, a CLI, a web NOC UI,
> Grafana dashboards, notifications, and approval-gated BGP mitigation
> (RTBH and FlowSpec through GoBGP), off and in dry-run as shipped. Signed
> tarballs and public images: see [Getting Started](#getting-started),
> and [Project Status](#project-status) for its limits.

Built by **WeTechi Solutions**.

---

## Table of Contents

- [Project Status](#project-status)
- [What Tidegard Is](#what-tidegard-is)
- [What Tidegard Is Not](#what-tidegard-is-not)
- [Architecture](#architecture)
- [Core Capabilities (Planned)](#core-capabilities-planned)
- [Getting Started](#getting-started)
- [Repository Layout](#repository-layout)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Security](#security)
- [License](#license)
- [Contributing](#contributing)
- [Support](#support)

## Project Status

**v1.0.0.** This repository follows an explicit, phased delivery model
(see [ROADMAP.md](ROADMAP.md)). Phases 0–7, 9 and 10 are merged to `main`
and released as v1.0.0:

- **Phase 0–1**: product foundation, clean-room boundary, repository
  governance and documentation/validation tooling.
- **Phase 2–3**: IPFIX/NetFlow/sFlow telemetry collector, aggregation,
  and ClickHouse analytics storage.
- **Phase 4**: static-threshold detection engine.
- **Phase 5**: incident management. A seven-state lifecycle that
  correlates detections, PostgreSQL persistence with an append-only
  timeline and audit trail, the incident manager process, a
  [REST API](apps/api/README.md) and the
  [`tidegardctl` CLI](apps/cli/README.md). See the
  [Gate 2 assessment](docs/development/phase5-gate2-assessment.md).
- **Phase 6**: dashboards, the NOC UI and notifications. Grafana
  dashboards as code, a read API for traffic, browser sessions, a
  [React NOC UI](apps/web/README.md) served by the API, and a
  [notifier](crates/notification/README.md) for email, Slack, Teams,
  Telegram and signed webhooks. See the
  [Gate 2 assessment](docs/development/phase6-gate2-assessment.md).
- **Phase 7**: the BGP mitigation lab. RTBH, parent-prefix and FlowSpec
  mitigations, each requested by one person and approved by a NOC lead.
  A safety guard with a per-tenant allowlist and hard prefix floors, a
  kill switch, and a mitigator that alone speaks to GoBGP. Mitigations
  appear in the API, the CLI, the UI and notifications, and a
  two-speaker lab in CI proves what an edge router receives. See the
  [RTBH guide](docs/operations/rtbh-guide.md) and the
  [Gate 2 assessment](docs/development/phase7-gate2-assessment.md).
- **Phase 9**: production hardening. Tarballs with systemd units, images
  and a Docker Compose stack; load and soak tests; backup, restore,
  upgrade and rollback proven in CI; a security review with a fuzzing
  report.
- **Phase 10**: the signed release pipeline, the
  [release documents](docs/release/index.md), and an acceptance test of
  every published release, from flows to a withdrawn route.

**Explicit safety boundaries, as of v1.0.0:**

- No automated mitigation, ever: every announcement needs a NOC lead's
  approval, and the mitigator may only propose. BGP is off and dry-run is
  on by default, and nothing is announced until an operator turns both
  around in the guard file (see [Security](#security) below).
- Notifications are delivered only to the destinations an operator
  allows, and every incident message says where its mitigation stands.
- v1.0.0 is single-tenant; multi-tenancy is Phase 8. It was tested in
  CI and in a lab, never against a production network: start with
  mitigation off, as shipped. [Known issues](docs/release/known-issues.md)
  lists what it does not do.
- Every release is signed with cosign keyless and carries build
  provenance; [Verifying a Release](docs/operations/verifying-a-release.md)
  shows how to check one before installing it.

## What Tidegard Is

Tidegard is an independently engineered open network telemetry, DDoS
detection, traffic analytics, and policy-controlled mitigation platform.
Planned product categories:

- NetFlow / IPFIX / sFlow monitoring
- Network traffic analytics
- DDoS and network anomaly detection
- Incident management
- Grafana dashboards
- BGP RTBH and BGP FlowSpec automation
- Managed DDoS monitoring and policy-controlled mitigation

Full detail: [docs/product-charter.md](docs/product-charter.md).

## What Tidegard Is Not

Tidegard is not a clone, replica, copy, alternative build,
reverse-engineered edition, or replacement edition of any proprietary
product, named or unnamed. It is built exclusively from public RFCs,
public protocol specifications, vendor documentation, and independently
designed schemas and interfaces. See
[docs/clean-room-boundary.md](docs/clean-room-boundary.md) for the full,
binding clean-room policy.

## Architecture

Tidegard is designed as a modular, event-driven platform of 15
logical services (Telemetry Collector, Traffic Aggregator, Direction
Classifier, Detection Engine, Incident Manager, Mitigation Controller,
Notification Service, Public REST API, Internal gRPC API, Web Application,
CLI, Configuration Service, Audit Service, Reporting Service, Backup and
Restore Service).

Architecture direction (not yet finalized — tracked via Architecture
Decision Records once decided):

- [docs/architecture-options.md](docs/architecture-options.md)
- [docs/technology-options.md](docs/technology-options.md)
- [docs/architecture/decisions/](docs/architecture/decisions/index.md)

*A visual architecture diagram will be added once the core service
boundaries are implemented (Phase 2–5) — a placeholder link only, no
diagram exists yet.*

## Core Capabilities (Planned)

| Area | Summary |
|---|---|
| Telemetry Collector | IPFIX, NetFlow v9/v5, sFlow v5 decoding with template caching and sampling correction |
| Aggregation | Traffic totals across host/network/hostgroup/ASN/exporter/interface dimensions |
| Detection | Static thresholds first, statistical/baseline anomaly detection later |
| Incident Management | Explicit incident state machine with full audit trail |
| Mitigation | GoBGP-integrated RTBH/FlowSpec, dry-run and disabled by default |
| Dashboards | Original Grafana dashboards and a native NOC web UI |
| Notifications | Email, Teams, Slack, Telegram, PagerDuty, generic webhook |
| Multi-Tenancy | Designed in from the schema level, enforced starting v1.1.0 |

Full requirement traceability:
[docs/functional-requirements.md](docs/functional-requirements.md) and
[docs/non-functional-requirements.md](docs/non-functional-requirements.md).

## Getting Started

Install from the
[latest release](https://github.com/LogiXhare/tidegard/releases/latest),
after [verifying it](docs/operations/verifying-a-release.md):

- **One host with Docker:** the [Quick Start](docs/quick-start.md) runs
  the Compose reference stack from the public images.
- **Ubuntu 22.04 or later, with systemd:** the tarball's `install.sh`, as
  [deployments/systemd](deployments/systemd/README.md) describes.
- **From source:** [docs/development/local-setup.md](docs/development/local-setup.md).

Then [Customer Onboarding](docs/operations/customer-onboarding.md) takes
you from your routers' flows to a first incident. The NOC UI, in
[apps/web](apps/web/README.md), is served by the API.

## Repository Layout

```text
tidegard/
├── .github/          CI, issue/PR templates, CODEOWNERS, Dependabot
├── apps/             api and cli (Phase 5); web, the NOC UI (Phase 6)
├── crates/           Rust service crates — 13 populated with real,
│                     tested code (see Cargo.toml); the rest remain
│                     README-only placeholders for later phases
├── deployments/       docker-compose and systemd (Phase 9); kubernetes, helm reserved
├── docs/             product, architecture, and operational documentation
├── grafana/          dashboards and provisioning (Phase 6)
├── database/         reserved; incident migrations live in crates/incident-postgres
├── tests/            integration, replay, performance, security, fixtures
├── tools/            flow-generator, flow-replay, diagnostics, migration
├── scripts/          developer/CI helper scripts
├── examples/         example configurations
├── branding/         logos and brand assets
├── mkdocs.yml        documentation site configuration
├── Makefile          developer task runner (make targets)
├── Taskfile.yml      developer task runner (Task targets)
└── prompts/          the governing master prompt for this project
```

`crates/` (13 of them), `apps/api`, `apps/cli`, `apps/web`, `tools/flow-replay/` and `tools/dashboard-check/` carry real, tested
source (see `Cargo.toml`'s `[workspace] members`). Every still-empty
directory contains a `README.md` explaining what it is reserved for and
which phase populates it — see [docs/roadmap.md](docs/roadmap.md).

## Documentation

Product-foundation documentation set (Phase 0 + Phase 1; the full,
current documentation tree — including Phase 2–7 architecture, ADRs,
and operational docs — is browsable via `mkdocs serve` or directly under
`docs/`):

- [Product Charter](docs/product-charter.md)
- [Clean-Room Boundary](docs/clean-room-boundary.md)
- [Functional Requirements](docs/functional-requirements.md)
- [Non-Functional Requirements](docs/non-functional-requirements.md)
- [Architecture Options](docs/architecture-options.md)
- [Technology Options](docs/technology-options.md)
- [Dependency License Matrix](docs/dependency-license-matrix.md)
- [Commercial Boundaries](docs/commercial-boundaries.md)
- [Security Principles](docs/security-principles.md)
- [MVP Scope](docs/mvp-scope.md) / [Out of Scope](docs/out-of-scope.md)
- [Risk Register](docs/risk-register.md)
- [Detailed Roadmap](docs/roadmap.md)
- [Acceptance Criteria](docs/acceptance-criteria.md)
- [Blocking Questions](docs/blocking-questions.md)
- [Naming and Branding](docs/naming-and-branding.md)
- [License Recommendation Warning](docs/license-recommendation.md)

A browsable documentation site (MkDocs Material) will be published once
hosting is configured; until then, browse `docs/` directly or run
`mkdocs serve` locally per
[docs/development/local-setup.md](docs/development/local-setup.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the milestone summary and
[docs/roadmap.md](docs/roadmap.md) for full per-phase detail.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability, and
[docs/security-principles.md](docs/security-principles.md) for the
project's threat model and security design principles. **Automated BGP
mitigation is disabled and dry-run by default at every layer, permanently
— this is a hard safety rule, not a configuration default that will
change.** Since Phase 7 a person may request a mitigation and a NOC lead
may approve it. Only an approved one is ever announced, and only once an
operator has turned BGP on and dry-run off.

## License

Licensed under the [Apache License 2.0](LICENSE) — resolved 2026-08-21
by WeTechi Solutions; see
[docs/blocking-questions.md](docs/blocking-questions.md) (BQ-1) and
[docs/license-recommendation.md](docs/license-recommendation.md) for the
full decision record and the fork-risk trade-off accepted knowingly.
Contributions are accepted under the same license via DCO sign-off, no
CLA — see [ADR 0006](docs/architecture/decisions/0006-contribution-licensing-dco-not-cla.md).

See also [NOTICE](NOTICE) and
[docs/dependency-license-matrix.md](docs/dependency-license-matrix.md).

## Contributing

Contributions are welcome once there is code to contribute to. Read
[CONTRIBUTING.md](CONTRIBUTING.md) first — in particular the clean-room
and dependency-licensing rules, which are non-negotiable. See also
[GOVERNANCE.md](GOVERNANCE.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Support

See [SUPPORT.md](SUPPORT.md).

---

© 2026 WeTechi Solutions. Tidegard, SentinelFlow Engine, and
`tidegardctl` are original names — see
[docs/naming-and-branding.md](docs/naming-and-branding.md).
