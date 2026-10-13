# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once versioned releases begin (see [ROADMAP.md](ROADMAP.md)).

## [Unreleased]

## [1.0.0-rc.1] - 2026-10-13

The first release candidate of Tidegard 1.0.0: IPFIX flow
collection, traffic analytics, static threshold DDoS detection, incident
management and approved BGP mitigation, as a signed release for one
host. Before installing, [verify it](docs/operations/verifying-a-release.md);
before upgrading from v0.9.0, read
[Upgrading](docs/operations/upgrading.md#from-v090) and the
[known issues](docs/release/known-issues.md).

### Changed — needs action when upgrading from v0.9.0

- **WetechiNetMon is now Tidegard** ([ADR 0058](docs/architecture/decisions/0058-rename-to-tidegard.md)):
  binaries `tidegard-*` and `tidegardctl`, settings `TIDEGARD_*`, metrics
  `tidegard_*`, images `ghcr.io/logixhare/tidegard-*`, paths
  `/opt/tidegard` and `/etc/tidegard`, and the repository
  `LogiXhare/tidegard`. `WETECHINETMON_*` settings are still read, with
  a warning, through 1.x. The database role, the ClickHouse tables and
  the token prefix keep their names.
- The collector's ClickHouse export refuses plain HTTP to any host but
  this one, and takes credentials only from
  `TIDEGARD_COLLECTOR_CLICKHOUSE_USER` and `_PASSWORD_FILE`: a remote
  `http://` URL, or a URL carrying a password, now stops it at startup
  ([ADR 0053](docs/architecture/decisions/0053-phase9a-collector-clickhouse-tls.md)).
- The collector tracks each exporter by source address and observation
  domain, as RFC 7011 scopes templates and sequence numbers.
- `scripts/package.sh` needs cargo-about 0.9.2 to write the licence
  notices.

### Added — Phase 10 release

- A release pipeline: native x86_64 and aarch64 tarballs and images,
  CycloneDX SBOMs, `SHA256SUMS`, cosign keyless signatures, build
  provenance, multi-architecture images on GHCR, published only after
  the owner's approval, and verified and installed on a clean runner
  ([ADR 0057](docs/architecture/decisions/0057-phase10a-release-pipeline.md)).
- Operator documentation: the [quick start](docs/quick-start.md),
  [verifying a release](docs/operations/verifying-a-release.md),
  [upgrading and rolling back](docs/operations/upgrading.md),
  [migration notes](docs/release/migration-notes.md),
  [known issues](docs/release/known-issues.md),
  [customer onboarding](docs/operations/customer-onboarding.md), the
  [commercial deployment guide](docs/commercial/deployment-guide.md), and
  the [production](docs/release/production-checklist.md) and
  [security](docs/release/security-checklist.md) checklists.

### Added — Phase 9 production hardening

- Packages: a release tarball with hardened systemd units and one system
  user per service; non-root, read-only images on distroless; a Docker
  Compose stack with TLS between every container; `/healthz` and
  `/readyz` on every service
  ([ADR 0052](docs/architecture/decisions/0052-phase9a-packaging.md)).
- Measured capacity: no loss at 200,000 flow records a second, API p99
  of 107 ms at worst with 10,000 incidents, and five hours at 50,000
  records a second with memory flat
  ([capacity planning](docs/operations/capacity-planning.md)).
- A ClickHouse backup and restore, an upgrade from v0.9.0 with a
  rollback, and a rebuild of a lost host, each drilled in CI on every
  pull request, with the [disaster recovery runbook](docs/operations/disaster-recovery.md)
  ([ADR 0055](docs/architecture/decisions/0055-phase9c-backup-upgrade-rollback.md)).
- The exporter allowlist and limits:
  `TIDEGARD_COLLECTOR_ALLOWED_EXPORTERS`, `_MAX_EXPORTERS` and
  `_EXPORTER_IDLE_SECS`, with
  `tidegard_collector_datagrams_refused_total`
  ([ADR 0056](docs/architecture/decisions/0056-phase9d-collector-input-bounds.md)).
- The third-party licence notices of every dependency, in each tarball
  and image.
- `cargo deny` in CI, and the [security review](docs/security/security-review.md)
  with threats T-49 to T-57.

### Security — Phase 9D review

- A 46-byte IPFIX message could make the collector allocate until it ran
  out of memory (a template of zero-length records). Fixed.
- Spoofed UDP senders could grow the collector's exporter and template
  state without bound. Bounded, with an allowlist (ADR 0056).
- The collector's ClickHouse export could travel in plain HTTP with
  credentials in its URL. Now TLS with a configured CA, and credentials
  from a file (ADR 0053).

### Fixed — Phase 9

- The collector's ClickHouse writer panicked on its first row.
- The shipped detection policy's window did not match the collector's,
  so a fresh install never evaluated it; the collector now logs each
  policy it cannot evaluate.

### Added — Phase 7 BGP mitigation lab

- Mitigations (`crates/mitigation`, migrations V19 to V21): RTBH,
  parent-prefix, FlowSpec discard and FlowSpec rate-limit. Each is
  requested or proposed, approved by a NOC lead, never self-approved by
  default, audited, and written to the outbox with every change.
- A safety guard: dry-run and BGP off by default, a per-tenant
  allowlist, prefix floors of /16 and /32 that no configuration can
  lower, bounded durations, and a kill switch that any NOC lead can
  engage and only the API host can release.
- `tidegard-mitigator`, the only process that speaks to GoBGP
  (v4.9.0, over gRPC, plaintext to loopback only). It announces,
  expires, reconciles by an ownership community, proposes for critical
  incidents, and records BGP peers.
- Mitigations in the API (eleven endpoints), the CLI (`mitigations`,
  `kill-switch`, `bgp`), the NOC UI (a Mitigations page, tested end to
  end through GoBGP), and notifications (mitigation events, the kill
  switch, `bgp.peer_down` and `bgp.peer_up`). The incident's
  `mitigation_status` and `notification_status` come from the records.
- A two-speaker BGP lab in CI that proves what an edge router receives.
  The [RTBH](docs/operations/rtbh-guide.md) and
  [FlowSpec](docs/operations/flowspec-guide.md) guides, the
  [mitigation runbook](docs/operations/mitigation-runbook.md), the
  [installation guide](docs/installation/mitigation.md), threats T-42 to
  T-48, and the
  [Gate 2 assessment](docs/development/phase7-gate2-assessment.md).

### Added — Phase 6 dashboards, NOC UI and notifications

- Four [Grafana dashboards](grafana/dashboards) as code, with
  provisioning files, a static check, and a CI job that loads them in a
  real Grafana. Grafana itself is not shipped.
- A read-only traffic API over ClickHouse (`traffic.read`), bounded in
  time and rows, for one configured traffic tenant.
- Browser sessions: sign in with an API token, then an `HttpOnly`,
  `SameSite=Strict` cookie with CSRF protection (migration V18).
- The [NOC UI](apps/web/README.md), React and TypeScript, served by the
  API under a strict Content-Security-Policy, with an end-to-end test in
  a real browser.
- The [notifier](crates/notification/README.md),
  `tidegard-notifier`: email, Slack, Teams, Telegram and
  HMAC-signed webhooks, routed by tenant, event and severity, with SSRF
  checks, deduplication, rate limits and dead-lettering. Every attempt
  is on the incident's timeline.
- Threats T-30 to T-41, runbook and installation guide updates, and the
  [Gate 2 assessment](docs/development/phase6-gate2-assessment.md).

### Added — Phase 5 incident management

- Incident management, built in six milestones (5A–5F): a tested
  domain, PostgreSQL persistence (migrations V1–V17), ingestion of
  detection events through an inbox, the
  [REST API](apps/api/README.md), and the
  [`tidegardctl` CLI](apps/cli/README.md). Incidents correlate
  detections, move through a seven-state lifecycle, and record every
  change on an append-only timeline and audit trail. Nothing notifies
  and nothing mitigates: those are Phases 6 and 7.
- Operations: an [installation guide](docs/installation/incident-management.md),
  a [runbook](docs/operations/incident-runbook.md), a tested
  [backup and restore drill](docs/operations/backup-and-restore.md), and
  measured [capacity numbers](docs/operations/capacity-planning.md).
- The [Gate 2 assessment](docs/development/phase5-gate2-assessment.md)
  records what is met and what remains open.

### Added — Phase 5 incident management planning

- Phase 5 architecture and documentation planning. **No Phase 5 code,
  schema, migration, or dependency was added** — this is design awaiting
  review. Twenty-three documents: the
  [plan](docs/architecture/phase5-incident-management-plan.md), the
  [domain model](docs/architecture/incident-domain-model.md),
  [correlation](docs/architecture/incident-correlation.md), the
  [state machine](docs/architecture/incident-state-machine.md),
  [persistence](docs/architecture/incident-persistence.md), the
  [security model](docs/architecture/incident-security-model.md),
  [API](docs/architecture/incident-api-plan.md) and
  [CLI](docs/architecture/incident-cli-plan.md) plans,
  [observability](docs/architecture/incident-observability.md), the
  [testing plan](docs/architecture/incident-testing-plan.md), a 24-entry
  [threat model](docs/security/incident-threat-model.md), a
  [configuration plan](docs/configuration/incident-management-plan.md), an
  [operations runbook plan](docs/operations/incident-runbook.md) (since
  renamed), an
  [API reference plan](docs/api/incident-api-plan.md) with a draft
  OpenAPI, an
  [implementation plan](docs/development/phase5-implementation-plan.md),
  [acceptance criteria](docs/development/phase5-acceptance-criteria.md),
  and ADRs 0011-0017, all **Proposed**.
- Five blocking questions raised rather than silently decided: **BQ-5**
  (FR-5.2 requires a UUID, which contradicts the ADR 0009 precedent),
  **BQ-6** (FR-5.1 places mitigation states in the incident machine that
  Phase 5 may not implement), **BQ-7** (Phase 5 needs PostgreSQL and an
  HTTP framework, changing a zero-third-party-dependency posture),
  **BQ-8**, and **BQ-9**. Three change code the first milestone would
  write.
- Risks **R16**-**R18** and follow-ups **FU-16**-**FU-23**.
- Documented five gaps between FR-5 and the detection event Phase 4
  actually produces — most consequentially that `detection_id` is
  instance-scoped and therefore unusable as a correlation key, since a
  collector restart mid-attack mints a new one for the same ongoing
  flood.

### Added — Phase 4 static detection engine

Recorded here after the fact: Phase 4 was merged to `main` on 2026-08-22
as merge commit `3f0cf3e` (PR #14, 15 signed-off commits) without a
changelog entry, and this file claims to record all notable changes.

- `crates/detector`: static threshold detection across host, prefix, /24,
  and hostgroup scopes; direction-aware tumbling-window counters owned by
  the detector; hysteresis with `triggerFor`, `clearFor`, `holdDown`, and
  `cooldown`; deterministic policy precedence; strict versioned JSON
  policies; explainable events with three identifiers and a gapless
  sequence; observe, alert-only, and dry-run execution modes.
- ClickHouse `wetechinetmon_detection_events` with 365-day retention,
  alongside the unchanged 30-day traffic retention.
- Thirteen `tidegard_detector_*` Prometheus metrics, every label a
  closed set.
- Traffic patterns in `flow-replay`, and a full IPFIX-bytes-to-event
  end-to-end test.
- ADRs
  [0007](docs/architecture/decisions/0007-detection-engine-cannot-mitigate.md)-[0010](docs/architecture/decisions/0010-detector-owns-its-windowed-counters.md).
- **The detection engine cannot mitigate**, structurally rather than by
  configuration: no crate in its dependency closure can reach a router,
  and every event carries `executed: false` derived from an exhaustive
  match. See
  [detection-safety.md](docs/security/detection-safety.md).
- 403 tests, no third-party dependency added.

### Fixed

- `mkdocs build --strict` now exits 0 with zero warnings. It previously
  aborted on 9 broken relative links — a failure that predates this work
  and had never been caught, because the strict docs build runs only in
  CI (blocked by the Actions billing state since this repository's first
  workflow run) and is not part of `make validate`. Two links were
  wrong-depth paths to pages that do exist; the other seven pointed
  outside `docs/`, which MkDocs cannot resolve. Root governance files now
  have documentation-native summary pages —
  [Contributing](docs/development/contributing.md) and
  [Security Policy](docs/security/security-policy.md), both registered in
  the nav — and references to source files and crate READMEs use explicit
  repository URLs, added to the `.github/mlc_config.json` ignore list on
  the same grounds as the advisory and discussion URLs already there: the
  repository is private, so an anonymous link checker cannot reach them.
  No warning was suppressed and strict mode was not relaxed.

### Added — Governance records

- [ADR 0006](docs/architecture/decisions/0006-contribution-licensing-dco-not-cla.md)
  — contribution licensing: Apache-2.0 stays, DCO sign-off is required,
  no CLA is introduced. Records plainly what the DCO does *not* do: it is
  not a copyright assignment, contributors keep their copyright, and
  contributed code therefore cannot be relicensed unilaterally. Resolves
  the incoming-contribution half of BQ-1.
- [docs/development/follow-ups.md](docs/development/follow-ups.md) — the
  known, deliberately-deferred engineering loose ends (FU-1..FU-7), each
  with what blocks it.

### Added — Contribution licensing

- `DCO` — the Developer Certificate of Origin 1.1 text, verbatim.
  Contributions are accepted under Apache-2.0 and every non-merge commit
  now requires a matching `Signed-off-by` trailer (`git commit -s`).
  There is no separate CLA. See the new "Licensing and Sign-Off" section
  in [CONTRIBUTING.md](CONTRIBUTING.md); the pull-request template
  carries a matching checklist item.

### Security

- The DCO check's bot exemption no longer trusts commit author metadata.
  It previously skipped any commit whose `%an <%ae>` contained `[bot]`,
  so a contributor could bypass sign-off entirely with
  `git config user.name 'x[bot]'`. Verified against a synthetic commit
  authored as `evil[bot] <attacker@example.com>`: it was silently
  exempted before the fix and is correctly rejected after. The exemption
  is now keyed on the pull request author's login, which GitHub sets.

### Changed — CI efficiency

- `.github/workflows/validate.yml`: consolidated from nine jobs to three
  (`rust`, `docs`, `history`), split by *environment* rather than by
  individual check. `cargo fmt`/`clippy`/`test`/`build` previously ran as
  four separate runners that each recompiled the whole workspace from a
  cold cache; they now share one `target/` directory in a single job. No
  check was removed and no action version changed — the same commands run
  against the same pinned action SHAs.
- The former `secret-scan` job is now `history`, and gained a DCO
  sign-off check: it verifies every non-merge commit in a pull request
  carries a `Signed-off-by` trailer matching its author. It reuses the
  full-history checkout that the secret scan already needed, so it costs
  no extra runner minutes. Bot-authored pull requests are exempted on
  `github.event.pull_request.user.login`, which GitHub sets — never on
  commit author metadata, which a contributor controls.
- `.github/dependabot.yml`: updates are now grouped — all GitHub Actions
  bumps arrive as one pull request, and Cargo minor/patch bumps as
  another. Major Cargo bumps are deliberately left ungrouped so a
  breaking change gets reviewed on its own.
- `.githooks/pre-push` plus `make hooks` / `task hooks` — an opt-in local
  gate running `cargo fmt --check`, `cargo clippy -D warnings`, and
  `cargo test` before each push. It skips itself when `cargo` is absent,
  and honours `WETECHI_SKIP_PREPUSH=1`. Documented in
  [docs/development/local-setup.md](docs/development/local-setup.md).
- `.gitattributes` — pins shell scripts and `.githooks/**` to LF endings.
  Under `core.autocrlf=true` on Windows the hook would otherwise be
  checked out with a CRLF shebang and fail to execute on Linux or WSL.

### Added — Phase 3: Aggregation and Direction Classification

- `crates/common`: `NormalizedFlow` — protocol-independent flow record
  (`flow.rs`) and sampling-correction module (`sampling.rs`) implementing
  the documented priority order (record-level → options-template →
  exporter-configured → global default → unsampled), with zero-rate
  rejection and overflow rejection.
- `crates/classifier` (new crate): binary-trie prefix registry (IPv4 +
  IPv6, longest-prefix match, duplicate/overlap detection, tenant +
  hostgroup ownership — ADR 0002) and direction classification
  (Incoming/Outgoing/Internal/Other/Unknown, with explainable
  diagnostics). 29 tests.
- `crates/aggregator` (new crate): bounded multi-dimensional aggregation
  (hosts, networks, /24, configurable prefix lengths, hostgroups, ASNs,
  exporters, interfaces, protocols — ADR 0003), 1s/5s/15s/1m/5m rate
  windows over processing time, deterministic LRU-style eviction,
  inactivity expiration. 26 tests.
- `crates/storage` (new crate): original ClickHouse schemas for 9 tables,
  bounded batch writer, bounded retry queue with exponential backoff and
  drop-oldest-on-overflow (ADR 0005), idempotent migrations. 13 unit
  tests + 1 skip-cleanly-without-a-server integration test.
- `crates/collector`: wired IPFIX → normalize → classify → aggregate →
  (optional) ClickHouse export pipeline via a bounded in-process channel
  (ADR 0004); SIGTERM graceful shutdown (Unix); 14 new Prometheus
  metrics; periodic inactivity-expiration sweep; env-var configuration
  for local prefixes, aggregation limits, sampling defaults, and optional
  ClickHouse URL. 28 tests.
- `tools/flow-replay`: extended for IPv4/IPv6, TCP/UDP/ICMP, sampling
  (via synthetic Options Templates), and multiple simulated
  exporters/observation domains, with a `--scenario` flag for
  incoming/outgoing/internal/other traffic. 5 tests.
- `crates/protocol-ipfix/fuzz/`: `cargo-fuzz` target for
  `decode_message`, plus `.github/workflows/fuzz.yml` (scheduled/manual,
  nightly toolchain isolated to that workflow only) — **not executed**
  in this environment (no nightly toolchain available locally).
- ADRs 0002–0005 (prefix lookup data structure, in-memory aggregation
  structure, collector-aggregator event transport, ClickHouse batching
  and retry).
- Documentation: `docs/architecture/aggregation.md`,
  `docs/architecture/direction-classification.md`,
  `docs/configuration/prefixes.md`, `docs/configuration/aggregation.md`,
  `docs/integrations/clickhouse.md`,
  `docs/operations/aggregator-monitoring.md`,
  `docs/operations/capacity-planning.md`,
  `docs/development/flow-replay.md`.
- `docs/dependency-license-matrix.md` and `NOTICE` updated with the
  `clickhouse` and `time` Rust crates (both `cargo metadata`-verified).

**Known limitations carried forward:** ClickHouse write path not
verified against a live server (none available here); `cargo-fuzz` not
executed (no nightly toolchain here); `interface_traffic` ClickHouse
table not yet wired (aggregator's interface dimension isn't
exporter-scoped); no performance benchmark executed (100k flows/sec is a
documented target, not a measured result). None of these are silently
dropped — see `docs/risk-register.md` and the relevant docs pages above.

### Added — Phase 2: IPFIX collector MVP

- `crates/protocol-ipfix`: clean-room IPFIX (RFC 7011/7012/7015) decoder
  — message header, Template Sets, Options Template Sets, Data Sets
  (fixed and variable-length fields), per-exporter `TemplateCache`, and
  structural sampling-parameter extraction (`SamplingInfo`). 34 tests
  including 3 `proptest` properties ("never panics on arbitrary bytes").
- `crates/collector` (`tidegard-collector` binary): UDP IPFIX
  listener, per-exporter template caching with sequence-number-regression
  restart detection, a hand-rolled `/metrics` HTTP endpoint (Prometheus
  text format), and environment-variable configuration
  (`TIDEGARD_COLLECTOR_BIND`, `TIDEGARD_COLLECTOR_METRICS_BIND`).
  16 tests, including a real `tokio` TCP integration test of the metrics
  endpoint. Verified end-to-end against a real running process (not just
  unit tests) — see `docs/roadmap.md` Phase 2 section.
- `crates/common`: shared structured JSON logging setup
  (`tidegard_common::logging::init`).
- `tools/flow-replay` (`flow-replay` binary): synthetic-only IPFIX
  traffic generator for safely testing the collector, with a round-trip
  test against the real decoder.
- ADR 0001: Rust selected as the Telemetry Collector's implementation
  language (`docs/architecture/decisions/0001-collector-implementation-language.md`),
  resolving the leaning recorded in Phase 0's `docs/architecture-options.md`.
- Root `Cargo.toml` workspace; `Cargo.lock` now committed (binary crates —
  see `.gitignore`).
- `docs/integrations/ipfix-collector.md`, `docs/configuration/index.md`
  populated with the real collector config options.
- `docs/dependency-license-matrix.md` and `NOTICE` updated with real,
  `cargo metadata`-verified license rows for the crates now vendored
  (tokio, tracing, tracing-subscriber, thiserror, prometheus, proptest).
- `.github/dependabot.yml`: added the `cargo` ecosystem.
- `.github/workflows/validate.yml`: added `cargo fmt --check`,
  `cargo clippy -D warnings`, `cargo test --workspace`, and
  `cargo build --workspace --all-targets` jobs.

**Known limitation carried forward:** true coverage-guided fuzzing
(`cargo-fuzz`/libFuzzer) needs a nightly Rust toolchain, not installed in
this environment. Property-based tests (`proptest`) cover the same
"never panics" safety property via random sampling instead. Tracked in
`docs/risk-register.md` R4, not silently dropped.

### Added — Phase 1: GitHub repository and documentation foundation

- Full monorepo directory skeleton per `prompts/CLAUDE_MASTER_PROMPT.md`
  §22 (apps/, crates/, deployments/, docs/, grafana/, database/, tests/,
  tools/, scripts/, examples/, branding/), with reserved-status README
  placeholders and no production code.
- Professional root `README.md`.
- `LICENSE` (Apache License 2.0, recommendation pending confirmation —
  see `docs/license-recommendation.md`) and `NOTICE`.
- `SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`,
  `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1).
- Root `ROADMAP.md` (public summary of `docs/roadmap.md`).
- MkDocs Material skeleton (`mkdocs.yml` + `docs/*/index.md` section
  landing pages).
- Architecture Decision Record process and template
  (`docs/architecture/decisions/`).
- GitHub issue templates (bug report, feature request, documentation) and
  issue-template config linking to `SECURITY.md`.
- Pull-request template with a clean-room self-certification checklist.
- `.github/CODEOWNERS`.
- `.github/dependabot.yml` (github-actions ecosystem).
- Validation-only GitHub Actions workflow (Markdown lint, YAML lint,
  Markdown link check) — no build, deploy, or release automation yet.
- `Makefile` and `Taskfile.yml` with `lint-markdown`, `lint-yaml`,
  `docs-serve`, `docs-build`, and `validate` targets.
- `docs/development/local-setup.md` documenting how to work with the
  repository at this phase.

### Added — Phase 0: Product foundation and clean-room boundary

- Product charter, clean-room boundary, functional and non-functional
  requirements, architecture and technology options, dependency license
  matrix, commercial boundaries, security principles, MVP scope,
  out-of-scope list, risk register, roadmap, acceptance criteria, blocking
  questions, and naming/branding decisions under `docs/`.

[Unreleased]: https://github.com/LogiXhare/tidegard/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/LogiXhare/tidegard/releases/tag/v1.0.0-rc.1
