# Roadmap

Status: Phases 0–7 complete; Phases 9 and 10 planned
Last updated: 2026-10-12

This roadmap mirrors the phased delivery model and versioning plan in the
master prompt (sections 28–29). No phase begins until the prior phase has
documented output, acceptance criteria, passing required tests, a summary,
an explicit decision record, a commit, and updated documentation.

## Phases and Milestones

| Phase | Milestone | Deliverable focus |
|---|---|---|
| Phase 0 | — | Product foundation and clean-room boundary (this document set) — ✅ complete |
| Phase 1 | v0.1.0 | GitHub repository and documentation foundation — ✅ complete |
| Phase 2 | v0.2.0 | IPFIX collector MVP — ✅ complete |
| Phase 3 | v0.3.0 | Aggregation and direction classification — ✅ complete |
| Phase 3 (cont.) | v0.4.0 | ClickHouse and Prometheus metrics — ✅ complete |
| Phase 4 | v0.5.0 | Static detection engine — ✅ complete |
| Phase 5 | v0.6.0 | Incident lifecycle — ✅ complete |
| Phase 6 | v0.7.0 | Grafana and native UI — ✅ complete |
| Phase 6 (cont.) | v0.8.0 | Notification integrations — ✅ complete |
| Phase 7 | v0.9.0 | BGP mitigation lab — ✅ complete |
| Phase 8 | v1.1.0 | Multi-tenancy |
| Phase 8 (cont.) | v1.2.0 | Enterprise authentication |
| Phase 9 | — | Production hardening (feeds into v1.0.0) — ✅ complete |
| Phase 10 | v1.0.0 | Production-ready single-tenant release — ✅ released 2026-10-28 |
| Future | v2.0.0 | Distributed high-availability architecture |

Note: the master prompt's phase list (0–10) and version list (v0.1.0–v2.0.0)
interleave slightly — multi-tenancy/enterprise auth (v1.1.0/v1.2.0, Phase 8)
land before the v1.0.0 single-tenant release phase (Phase 10) is finalized
in the phase numbering, but v1.0.0 is defined as the single-tenant MVP. This
sequencing ambiguity is noted as a **minor open question**, not a blocking
one — Phase 1 planning should confirm whether Phase 8 (tenancy) precedes or
follows the v1.0.0 cut, since the version numbers imply tenancy is
post-1.0 while the phase list places it at Phase 8 of 10. Recommended
resolution: treat Phase 8–9 as post-v1.0.0 work items (v1.1.0/v1.2.0) and
let Phase 10 (v1.0.0) be reached after Phase 7, with Phase 9 hardening
tasks applied twice (once before v1.0.0, once before v1.1.0/v1.2.0) —
subject to confirmation, see [blocking-questions.md](blocking-questions.md).

## Per-Phase Exit Requirements (restated from master prompt §29 and §30)

Every phase must produce, before the next phase starts:

- Completed items
- Files created / modified
- Tests executed and their actual results
- Security considerations
- License considerations
- Documentation created
- Known limitations
- Risks (feeding [risk-register.md](risk-register.md))
- Next phase
- Recommended Conventional Commits message

## Phase 0 (this phase) — Scope

Product charter, clean-room boundary, functional and non-functional
requirements, architecture and technology options, dependency license
matrix, commercial boundaries, security principles, MVP scope, out-of-scope
list, risk register, this roadmap, acceptance criteria, blocking questions,
and naming/branding decision. No production code.

## Phase 1 — Scope (complete)

GitHub repository and documentation foundation — monorepo skeleton,
README, LICENSE recommendation, NOTICE, SECURITY, CONTRIBUTING,
CODE_OF_CONDUCT, GOVERNANCE, SUPPORT, ROADMAP, CHANGELOG, MkDocs skeleton,
ADR template, issue templates, PR template, CODEOWNERS, Dependabot,
validation CI, local dev setup, Makefile, Taskfile.

## Phase 2 — Scope (complete)

IPFIX collector MVP: clean-room IPFIX decoder (`crates/protocol-ipfix`),
per-exporter template caching and restart detection, Prometheus metrics,
structured JSON logging (`crates/common`), a synthetic flow replay tool
(`tools/flow-replay`), unit tests, property-based ("never panics on
arbitrary bytes") tests, and documentation (IPFIX collector guide,
configuration reference, ADR 0001 recording the Rust-for-collector
decision). See [architecture/decisions/0001-collector-implementation-language.md](architecture/decisions/0001-collector-implementation-language.md).

**Known limitation carried forward:** true coverage-guided fuzzing
(`cargo-fuzz`/libFuzzer) requires a nightly Rust toolchain, not installed
in this environment — property-based tests cover the same "never panics"
safety property via `proptest` instead. Tracked in
[risk-register.md](risk-register.md) R4, not silently dropped.

## Phase 3 — Scope (complete)

Aggregation and direction classification: `NormalizedFlow` protocol-
independent flow model (`crates/common`), sampling correction with a
documented priority order, tenant-aware prefix registry and direction
classification (`crates/classifier`, binary trie — ADR 0002), bounded
multi-dimensional aggregation and rate windows (`crates/aggregator` —
ADR 0003), ClickHouse output (`crates/storage` — ADR 0005), an in-process
bounded-channel pipeline (ADR 0004), SIGTERM graceful shutdown, extended
`tools/flow-replay`, and 8 new documentation pages. ~154 tests passing;
end-to-end verified against a real running collector process.

**Known limitations carried forward:**

- `cargo-fuzz` target exists but has not been executed (no nightly
  toolchain in this environment) — see
  [risk-register.md](risk-register.md) R4.
- ClickHouse write path implemented and unit-tested but not verified
  against a live server (none available here) — see
  [integrations/clickhouse.md](integrations/clickhouse.md).
- `interface_traffic` ClickHouse table not yet exported (aggregator's
  interface dimension isn't exporter-scoped).
- No performance benchmark executed — the 100k flows/sec target is
  documented, not measured (see
  [operations/capacity-planning.md](operations/capacity-planning.md)).

## Phase 4: Detection Engine — Implemented

Static threshold detection across host, prefix, /24, and hostgroup
scopes; direction-aware windowed counters; hysteresis and the four
timers (`triggerFor`, `clearFor`, `holdDown`, `cooldown`); deterministic
policy precedence; explainable detection events with stable identity;
observe, alert-only, and dry-run execution modes; a ClickHouse analytics
table for events; Prometheus metrics; and traffic patterns in
`flow-replay` that exercise the whole path.

See [detection-engine.md](architecture/detection-engine.md) and
ADRs [0007](architecture/decisions/0007-detection-engine-cannot-mitigate.md),
[0008](architecture/decisions/0008-detection-policy-configuration.md),
[0009](architecture/decisions/0009-detection-event-identity.md), and
[0010](architecture/decisions/0010-detector-owns-its-windowed-counters.md).

**The detection engine cannot mitigate**, and that is structural rather
than configured — see
[detection-safety.md](security/detection-safety.md).

Not covered, and deliberately: incident lifecycle (Phase 5),
notifications (Phase 6), and any form of mitigation (Phase 7).

## Phases 9 and 10: Production Hardening and v1.0.0 — Complete

**v1.0.0 released on 2026-10-28**, after four release candidates, an
independent review and the owner's sign-off of both checklists. See the
[release documents](release/index.md) and the
[test summary](release/test-summary.md).

Planned on 2026-10-12, with the owner's decisions on BQ-3 and BQ-16 to
BQ-18. Phase 8 (multi-tenancy) follows v1.0.0 (BQ-4), so Phase 9 comes
next. Phase 9 has four milestones: packaging (9A), load and soak tests
on the `ubuntu-latest` runner against the 100,000 records a second
target (9B), backup, restore, upgrade and rollback proven in CI (9C), and
a security review with a fuzzing report (9D). Phase 10 adds the signed
release pipeline (10A), the release documentation (10B) and v1.0.0
itself (10C), after the owner signs off the production and security
checklists. v1.0.0 is a public GitHub release signed with cosign
keyless; it adds no automatic mitigation, and nothing is tested against
a real network. See the
[Phases 9 and 10 plan](architecture/phase9-10-production-release-plan.md)
and its [acceptance criteria](development/phase9-10-acceptance-criteria.md).

## Phase 7: BGP Mitigation Lab — Complete

**Complete on 2026-10-12**, in six milestones:

- **7A:** the mitigation record and its state machine, with no route
  before approval and no self-approval by default
  ([ADR 0046](architecture/decisions/0046-phase7a-mitigation-record.md)).
- **7B:** the safety guard: dry-run and BGP off by default, a per-tenant
  allowlist, prefix floors no configuration can lower, and bounded
  durations
  ([ADR 0047](architecture/decisions/0047-phase7b-safety-guard.md)).
- **7C:** the GoBGP adapter over gRPC, with vendored, checksummed protos,
  the ownership community, and plaintext to loopback only
  ([ADR 0048](architecture/decisions/0048-phase7c-gobgp-adapter.md)).
- **7D:** the mitigator service: announcing, expiry, reconciliation, the
  kill switch and proposals
  ([ADR 0049](architecture/decisions/0049-phase7d-mitigator-service.md)).
- **7E:** mitigations in the API, the CLI, the UI and notifications, and
  the incident's real `mitigation_status`
  ([ADR 0050](architecture/decisions/0050-phase7e-mitigation-api-cli-ui.md)).
- **7F:** the two-speaker lab, the RTBH and FlowSpec guides, the runbook,
  the installation guide and threats T-42 to T-48
  ([ADR 0051](architecture/decisions/0051-phase7f-two-speaker-lab.md)).

The [Gate 2 assessment](development/phase7-gate2-assessment.md) finds
every criterion met. T-21 stays partial and FU-65 open until Phase 8.

### Phase 7 planning

Planned on 2026-10-12, with the owner's decisions on BQ-4 and BQ-13 to
BQ-15. Six milestones: the mitigation record (7A), the safety guard
(7B), the GoBGP adapter (7C), the mitigator service (7D), the API, CLI,
UI and notifications (7E), and the lab and hardening (7F). It is v0.9.0.
GoBGP is reached over its gRPC API; nothing announces without approval;
production BGP stays off by default; and nothing is pointed at a real
network. See the
[Phase 7 plan](architecture/phase7-bgp-mitigation-lab-plan.md) and its
[acceptance criteria](development/phase7-acceptance-criteria.md).

## Phase 6: Dashboards, NOC UI and Notifications — Complete

**Complete on 2026-10-12**, in six milestones:

- **6A:** four Grafana dashboards as code, checked against the code's
  metrics and the schema's tables, and loaded in a real Grafana in CI
  ([ADR 0041](architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)).
- **6B:** a read-only, bounded traffic API over ClickHouse, for one
  configured traffic tenant until Phase 8
  ([ADR 0042](architecture/decisions/0042-phase6b-traffic-read-api.md)).
- **6C:** browser sessions from an API token, with CSRF protection and
  idle and absolute expiry
  ([ADR 0043](architecture/decisions/0043-phase6c-browser-sessions.md)).
- **6D:** the React NOC UI, served by the API under a strict
  Content-Security-Policy, tested end to end in a real browser
  ([ADR 0044](architecture/decisions/0044-phase6d-noc-ui.md)).
- **6E:** the notifier: email, Slack, Teams, Telegram and signed
  webhooks, with SSRF checks, deduplication and rate limits
  ([ADR 0045](architecture/decisions/0045-phase6e-notification-delivery.md)).
- **6F:** threats T-30 to T-41, the runbook and the installation guide.

The [Gate 2 assessment](development/phase6-gate2-assessment.md) finds
every criterion met. T-21 stays partial until Phase 8, and FU-64 is
open.

### Planning

Planned on 2026-10-11, with the owner's decisions on BQ-2 and BQ-10 to
BQ-12. Six milestones: Grafana dashboards as code (6A), read APIs for
the UI (6B), browser sessions (6C), the React NOC UI (6D), notifications
(6E) and hardening (6F). Dashboards and the UI are v0.7.0;
notifications are v0.8.0. Nothing mitigates, and nothing is sent from
CI. See the
[Phase 6 plan](architecture/phase6-dashboards-ui-notifications-plan.md)
and its [acceptance criteria](development/phase6-acceptance-criteria.md).

## Phase 5: Incident Management — Complete

**Complete on 2026-10-11**, in six milestones:

- **5A:** a dependency-free incident domain, with the seven-state
  lifecycle, tenant-aware correlation and idempotency.
- **5B:** PostgreSQL persistence (migrations V1–V17), the transactional
  outbox, retries, and tests on PostgreSQL 15 to 18.
- **5C:** the incident manager process, ingesting detection events
  through an inbox.
- **5D:** the [REST API](https://github.com/LogiXhare/tidegard/tree/main/apps/api).
- **5E:** the [`tidegardctl` CLI](https://github.com/LogiXhare/tidegard/tree/main/apps/cli).
- **5F:** operations and hardening: a tested backup and restore drill,
  measured benchmarks, a security review against every threat, the
  [runbook](operations/incident-runbook.md) and the
  [installation guide](installation/incident-management.md).

The [Gate 2 assessment](development/phase5-gate2-assessment.md) records
each acceptance criterion with its evidence. Every criterion is met but
threat coverage: T-21 needs a user directory (Phase 8) and T-08 stored
XSS needs a UI (Phase 6). The
[implementation plan](development/phase5-implementation-plan.md) holds
the full delivery record.

### History

Phase 4 was reviewed and merged into `main` on 2026-08-22 (merge commit
`3f0cf3e`, PR #14). Phase 5 architecture and documentation planning
followed; **BQ-5 through BQ-9** in
[blocking-questions.md](blocking-questions.md) resolved 2026-08-22.

**Milestone 5A — merged 2026-08-24** (PR #16, merge commit `2cd116d`),
after two Opus 5 adversarial review cycles and a final pre-merge review.
Delivers the dependency-free incident domain: the seven-state lifecycle,
deterministic tenant-aware correlation, closure/reopen policy,
suppression as an attribute, typed timeline and audit records,
idempotency, and a bounded in-memory unit of work — 531 workspace tests,
zero third-party dependency added. See
[phase5-implementation-plan.md](development/phase5-implementation-plan.md)
for the full delivery record and adversarial-review history.

**Milestone 5B — 5B-0 and 5B-1 merged 2026-09-03** (PR #22, merge commit
`775fb1f`; PR #23, merge commit `4350412`); **5B-2 merged 2026-09-05**
(PR #25, merge commit `167c357`). Stage A had found Phase 5A's own planning overstated its
delivered persistence seam — there was no repository trait, and
`Timestamp` could not be restored from a database. Phase 5B is therefore
a refactor-and-implement milestone: seam extraction came first (5B-0, no
SQL, no dependency — done), then a verified dependency probe (5B-1:
`uuid`, `tokio-postgres`, `deadpool-postgres`,
`rustls`/`tokio-postgres-rustls`, `refinery`, all six added to
`Cargo.toml` in `crates/incident-postgres` at their ADR-pinned versions,
0 vulnerabilities across the resulting 252-crate lockfile — done), then
schema and migrations (5B-2: eleven forward-only `refinery` migrations
plus an ephemeral-Postgres migration smoke test, in
`crates/incident-postgres/migrations/` — merged, verified against a real
PostgreSQL instance per FU-45, no `IncidentStore` implementation yet),
then repositories, outbox, and
integration tests remain (5B-3 through 5B-5). Start at
[phase5b-postgresql-persistence-plan.md](architecture/phase5b-postgresql-persistence-plan.md);
decisions are ADRs
[0019](architecture/decisions/0019-phase5b-uuidv7-identity-generation.md)–[0033](architecture/decisions/0033-phase5b-transactional-outbox-and-dead-letter.md).

**No notification and no mitigation.** Those remain Phases 6 and 7.
Phase 5 plans only the seams they will attach to.

ADRs [0011](architecture/decisions/0011-incident-domain-boundary.md)–[0017](architecture/decisions/0017-incident-community-enterprise-boundary.md)
remain the Phase 5 domain/API/concurrency decisions Phase 5A implemented
against.
