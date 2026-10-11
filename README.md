# WetechiNetMon

**See Every Flow. Defend Every Network.**

WetechiNetMon is an independently engineered open network telemetry, DDoS
detection, traffic analytics, and policy-controlled mitigation platform
for ISPs, enterprises, data centers, hosting providers, and managed
network service providers.

> **Project status: Development Preview.** Phases 0–5 are complete, with
> real, tested Rust source: collector, aggregator, detector, and incident
> management with PostgreSQL persistence, a REST API and a CLI. There is
> no packaged release, no web UI, no notification delivery, and
> mitigation is not implemented. See [Project Status](#project-status)
> below before evaluating this as a production-ready product.

Built by **WeTechi Solutions**.

---

## Table of Contents

- [Project Status](#project-status)
- [What WetechiNetMon Is](#what-wetechinetmon-is)
- [What WetechiNetMon Is Not](#what-wetechinetmon-is-not)
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

**Development Preview.** This repository follows an explicit, phased
delivery model (see [ROADMAP.md](ROADMAP.md)). Phases 0–5 are merged to
`main`:

- **Phase 0–1**: product foundation, clean-room boundary, repository
  governance and documentation/validation tooling.
- **Phase 2–3**: IPFIX/NetFlow/sFlow telemetry collector, aggregation,
  and ClickHouse analytics storage.
- **Phase 4**: static-threshold detection engine.
- **Phase 5**: incident management. A seven-state lifecycle that
  correlates detections, PostgreSQL persistence with an append-only
  timeline and audit trail, the incident manager process, a
  [REST API](apps/api/README.md) and the
  [`wetechinetmonctl` CLI](apps/cli/README.md). See the
  [Gate 2 assessment](docs/development/phase5-gate2-assessment.md).

**Explicit safety boundaries, current as of this preview:**

- No production BGP or FlowSpec mitigation execution — automated
  mitigation is disabled and dry-run by default at every layer,
  permanently (see [Security](#security) below).
- No notification delivery is implemented (Phase 6).
- No web UI is implemented yet (Phase 6).
- APIs, schemas, and storage architecture may still change.
- Production use is not yet recommended unless explicitly supported by
  WeTechi Solutions.

There is no packaged release yet — the first runnable component (the
IPFIX telemetry collector) shipped in Phase 2, and the repository has
carried real, tested source code since.

## What WetechiNetMon Is

WetechiNetMon is an independently engineered open network telemetry, DDoS
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

## What WetechiNetMon Is Not

WetechiNetMon is not a clone, replica, copy, alternative build,
reverse-engineered edition, or replacement edition of any proprietary
product, named or unnamed. It is built exclusively from public RFCs,
public protocol specifications, vendor documentation, and independently
designed schemas and interfaces. See
[docs/clean-room-boundary.md](docs/clean-room-boundary.md) for the full,
binding clean-room policy.

## Architecture

WetechiNetMon is designed as a modular, event-driven platform of 15
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

There is no packaged release or installer yet. The Rust workspace
(`cargo build --workspace`, `cargo test --workspace`) builds and its 531
tests pass locally, but there is no HTTP API, web UI, or CLI to run
against real traffic yet — see
[docs/development/local-setup.md](docs/development/local-setup.md) for
what you *can* do today (build the workspace, run the test suite,
preview documentation, run Markdown/YAML validation). Installation
guides for Docker Compose, Kubernetes/Helm, and bare-metal Ubuntu will be
published once the corresponding phase ships a deployable service.

*Screenshots and a quick-start walkthrough will be added once the web
application and NOC UI exist (Phase 6) — placeholder only, no
screenshots exist yet.*

## Repository Layout

```text
wetechi-netmon/
├── .github/          CI, issue/PR templates, CODEOWNERS, Dependabot
├── apps/             api and cli (Phase 5); web reserved for Phase 6
├── crates/           Rust service crates — 10 populated with real,
│                     tested code (see Cargo.toml); the rest remain
│                     README-only placeholders for later phases
├── deployments/       docker-compose, kubernetes, helm, systemd — reserved
├── docs/             product, architecture, and operational documentation
├── grafana/          dashboards, provisioning — reserved, Phase 6
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

`crates/` (10 of them), `apps/api`, `apps/cli` and `tools/flow-replay/` carry real, tested
source (see `Cargo.toml`'s `[workspace] members`). Every still-empty
directory contains a `README.md` explaining what it is reserved for and
which phase populates it — see [docs/roadmap.md](docs/roadmap.md).

## Documentation

Product-foundation documentation set (Phase 0 + Phase 1; the full,
current documentation tree — including Phase 2–5B architecture, ADRs,
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
change.**

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

© 2026 WeTechi Solutions. WetechiNetMon, SentinelFlow Engine, and
`wetechinetmonctl` are original names — see
[docs/naming-and-branding.md](docs/naming-and-branding.md).
