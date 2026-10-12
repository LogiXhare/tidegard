# Roadmap

This is the public-facing summary. The full, detailed roadmap — including
per-phase deliverables, exit criteria, and open sequencing questions — is
maintained at [docs/roadmap.md](docs/roadmap.md); this file should stay in
sync with it.

## Delivery Model

WetechiNetMon is built in explicit, sequential phases. A phase does not
begin until the previous one has documented output, acceptance criteria,
passing tests, a summary, a decision record, a commit, and updated
documentation. See [docs/acceptance-criteria.md](docs/acceptance-criteria.md).

## Milestones

| Version | Milestone | Status |
|---|---|---|
| — | Phase 0: Product foundation and clean-room boundary | ✅ Complete |
| v0.1.0 | Phase 1: GitHub repository and documentation foundation | ✅ Complete |
| v0.2.0 | Phase 2: IPFIX collector MVP | ✅ Complete |
| v0.3.0 | Phase 3: Aggregation and direction classification | ✅ Complete |
| v0.4.0 | Phase 3 (cont.): ClickHouse and Prometheus metrics | ✅ Complete |
| v0.5.0 | Phase 4: Static detection engine | ✅ Complete |
| v0.6.0 | Phase 5: Incident lifecycle | ✅ Complete (2026-10-11) |
| v0.7.0 | Phase 6: Grafana and native UI | ✅ Complete (2026-10-12) |
| v0.8.0 | Phase 6 (cont.): Notification integrations | ✅ Complete (2026-10-12) |
| v0.9.0 | Phase 7: BGP mitigation lab | ✅ Complete (2026-10-12) |
| v1.0.0 | Phase 10: Production-ready single-tenant release | Not started |
| v1.1.0 | Phase 8: Multi-tenancy | Not started |
| v1.2.0 | Phase 8 (cont.): Enterprise authentication | Not started |
| v2.0.0 | Future: Distributed high-availability architecture | Not started |

Note: Phase 8 (multi-tenancy/enterprise auth) vs. the v1.0.0 cut has an
open sequencing question — see
[docs/blocking-questions.md — BQ-4](docs/blocking-questions.md).

## Editions (proposed, not built pre-v1.0)

Community Edition ships first and fully; Enterprise Edition and Managed
Service are proposals layered on top later — see
[docs/commercial-boundaries.md](docs/commercial-boundaries.md). No
artificial limitations are added to the open-source core to manufacture
demand for later tiers.

## Full Detail

For the complete phase-by-phase deliverable list, see
[docs/roadmap.md](docs/roadmap.md). For what each phase explicitly does
*not* include, see [docs/out-of-scope.md](docs/out-of-scope.md).
