# Phases 9 and 10 Plan: Production Hardening and v1.0.0

Status: **Complete: v1.0.0 released 2026-10-28.** Planned and accepted
by the owner 2026-10-12. The decisions this plan rests on are BQ-3 and BQ-16 to BQ-18
in [blocking questions](../blocking-questions.md). Each milestone records
its own engineering decisions in an ADR when it starts, as Phases 5 to 7
did.

Phase 9 hardens what Phases 2 to 7 built: packaging, load and soak tests,
backup, restore, upgrade and rollback, a security review and a fuzzing
report. Phase 10 turns the result into **v1.0.0**, the production-ready
single-tenant release on the [roadmap](../roadmap.md): a signed GitHub
release with checksums, SBOMs, release notes and the guides an operator
needs. Phase 9 carries no version of its own; release candidates are
`v1.0.0-rc.N`. The two phases share one plan because each Phase 9
deliverable exists to be shipped by Phase 10.

## What does not change

- **Production BGP stays off by default.** A fresh install from a
  release artifact is dry-run with BGP disabled, exactly as in Phase 7.
  A release test asserts it against the packaged default configuration,
  not only the source.
- **Nothing announces without a human** (BQ-17). Detection proposes; an
  approver approves. v1.0.0 adds no automatic execution.
- **No real network.** Load and soak tests send synthetic flows from
  `tools/flow-replay` to a collector CI started. Nothing is pointed at a
  real router or exporter (BQ-18), and no attack traffic is generated.
- **Single tenant.** Multi-tenancy and enterprise authentication stay
  v1.1.0 and v1.2.0 (BQ-4). T-21 stays partial and FU-65 open, and the
  release notes say so.
- **Free tier only.** Everything here runs on GitHub's free plan for a
  public repository: hosted runners, GHCR, Sigstore keyless signing and
  artifact attestations.

## Decisions taken for this plan

| Question | Decision | Why |
|---|---|---|
| BQ-3 Reference hardware and rates | The target stays 100,000 flow records a second. The reference machine is GitHub's `ubuntu-latest` runner (4 vCPU, 16 GiB), recorded with every run | Reproducible by anyone, free, and honest: numbers are published with the machine they came from. A runner is a floor, not a promise for other hardware |
| BQ-16 Release publication and signing | v1.0.0 is a public GitHub release under Apache-2.0, and the repository stays public from then on. Artifacts and images are signed with Sigstore cosign, keyless, through GitHub's OIDC identity, with build provenance attestations | Industry practice for open-source releases. No long-lived signing key exists to leak. Signatures enter the public Rekor log, which is intended for a public release |
| BQ-17 Automatic mitigation | Not in v1.0.0. Manual approval stays for every announcement | A first production release should not add a path that announces routes without a person. Revisited after real deployments |
| BQ-18 Real-traffic pilot | None before v1.0.0. Lab and synthetic traffic only | Nothing in this phase touches a live network. A pilot is the owner's decision, after the release |

## Phase 9 milestones

Each milestone ends green and is independently mergeable.

### 9A — Packaging

The six binaries (`tidegard-collector`, `-incident-manager`, `-api`,
`-notifier`, `-mitigator` and `tidegardctl`) and the web UI become
installable artifacts:

- **Linux tarballs** for `x86_64` and `aarch64`, holding the binaries,
  the default configuration files, the systemd units and the licence and
  notice files.
- **systemd units** for every service, hardened: a dedicated user,
  `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, and only the
  capabilities each service needs (none for most; the collector binds a
  UDP port above 1024 by default).
- **Container images** on GHCR for `linux/amd64` and `linux/arm64`: one
  per service, built from a minimal base, running as a non-root user
  with a read-only root filesystem. The web UI is served by the API, as
  it is today.
- **A Docker Compose reference stack** in `deployments/docker-compose`:
  PostgreSQL, ClickHouse and the services, with TLS between them, dry-run
  and BGP off. `gobgpd` stays out of it: BGP runs from the tarball,
  beside `gobgpd` on loopback (ADR 0052).
- CI builds every image, scans it with Trivy, lints the Dockerfiles and
  shell scripts, and verifies the units with `systemd-analyze verify`.

**Exit:** the Compose stack starts from images built in CI, every
service reports ready, and a smoke test sends synthetic flows that end as
an incident visible through the API. No image has a fixable Critical or
High finding. The reserved `deployments/` directories either hold real
content or say plainly that they are not part of v1.0.0 (Kubernetes and
Helm are not).

**Progress:** 9A-1 ([ADR 0052](decisions/0052-phase9a-packaging.md)) gives every service `/healthz` and `/readyz` on its metrics address, as NFR-2 requires. The collector is ready once its socket is bound, the incident manager and the notifier while their batches succeed, and the mitigator while it holds the lock and its passes succeed, so a standby is not ready. The e2e job waits on the incident manager's and the mitigator's `/readyz`. 9A-2 adds `scripts/package.sh`, which builds `tidegard-<version>-linux-<arch>.tar.gz` with the six binaries, the web UI, hardened units, one system user per service and the example settings, and `install.sh`, which installs it and never overwrites a setting. CI builds the tarball natively on x86_64 and aarch64 Ubuntu 22.04, installs it, verifies the units, and starts every service until each is ready. The shipped guard is the fresh install's, dry-run with BGP off, which a test asserts. 9A-3a ([ADR 0053](decisions/0053-phase9a-collector-clickhouse-tls.md)) closes a gap containers would have opened: the collector's ClickHouse export now refuses plain HTTP off loopback, verifies TLS against a configured CA, and logs in with its own user and a password file. CI proves it against ClickHouse served over HTTPS. 9A-3b and 9A-3c add one image per service, built from the tarball on distroless `cc-debian13` and run as non-root with a read-only root filesystem, and the Compose reference stack: PostgreSQL, ClickHouse and the services, with TLS between every container from a CA `setup.sh` makes, dry-run with BGP off and no `gobgpd`. CI builds and Trivy-scans every image on both architectures, and drives synthetic flows through the stack until an incident opens. 9A is complete.

### 9B — Load and soak

`tools/flow-replay` gains a rate-controlled mode, and a workflow measures
the pipeline on the reference runner:

- **Load:** synthetic IPFIX at stepped rates up to and beyond 100,000
  records a second, through the collector, aggregator and detector.
  Reported: sustained rate, records dropped, CPU, resident memory, and
  aggregation and detection latency from the services' own metrics.
- **API latency:** P50, P95 and P99 for the incident and mitigation
  endpoints under concurrent clients, against a database holding
  realistic history. This sets the budgets NFR-1 left to Phase 9.
- **Soak:** the stack under steady load for five hours, which with the
  build fits the six hours a hosted job may run (ADR 0054). Reported: memory over time, queue depths, error
  counts and restarts.
- Pass criteria are written in the 9B ADR before the first run, so the
  numbers are judged against them rather than the reverse. If the target
  is missed, the report says so; it is not adjusted to fit.

**Exit:** real results, with the run links and the machine, are
published in [capacity planning](../operations/capacity-planning.md),
replacing "No sustained-throughput benchmark has been run". FU-12 is
closed with numbers.

**Progress:** 9B-1 ([ADR 0054](decisions/0054-phase9b-load-and-soak.md)) wrote the pass criteria before any run, added `flow-replay --rate` and `scripts/load_test.py`, and ran the load test in the benchmark workflow. On the reference runner the whole collector took 200,000 records a second with no loss, 13 MiB peak memory and under half a core; the 100,000 step meets every criterion. The figures, with their machine and what they do not cover, are in [capacity planning](../operations/capacity-planning.md#flow-pipeline-measured). FU-12 is closed. 9B-2 measured the API with 10,000 incidents the pipeline itself created and 16 clients at their read quotas: p99 of 23 ms for the incident list, 107 ms for an incident's detail and 20 ms for the mitigation list, with no errors, within the 250 ms budget that NFR-1 now states. 9B-3, the five-hour soak at 50,000 records a second, passed: 899,999,914 records with no loss, the deepest queue 57 of 10,000, and mean memory 11.16 MiB in the first hour and 11.55 MiB in the fifth (+3.5%, the limit is 10%), with no error or restart ([capacity planning](../operations/capacity-planning.md#soak-measured)). **9B is complete.**

### 9C — Backup, restore, upgrade and rollback

- **ClickHouse backup**, which the PostgreSQL procedure deliberately left
  out, documented and restored in CI as PostgreSQL's already is.
- **Disaster recovery:** rebuilding a host from the release artifacts,
  the backups and the configuration, written as a runbook and exercised
  in CI from an empty runner.
- **Upgrade:** a CI job installs the v0.9.0 state (`7ca8223`), fills it
  with incidents and mitigations, upgrades to the candidate, and proves
  the data survives and the services start. v0.9.0 is tagged at that
  commit so the path has a name.
- **Rollback:** migrations are forward-only and are never edited, so
  rolling back means restoring the pre-upgrade backup and the previous
  release. CI proves that round trip.

**Exit:** backup, restore, upgrade from v0.9.0 and rollback each run
round-trip in CI, not only on paper (the Phase 9 acceptance criterion).

**Progress:** 9C-1 ([ADR 0055](decisions/0055-phase9c-backup-upgrade-rollback.md)) gives ClickHouse a backup: its own `BACKUP TABLE ... TO File()` and `RESTORE`, proven in the Grafana job by filling every table, backing up, dropping, restoring, comparing each table's rows and hash, and writing every row type into the restored copy. 9C-2 tags v0.9.0 at `7ca8223` and adds the `upgrade` job: v0.9.0's own services fill a database (incidents from a flood, an acknowledgement, a note, a dry-run mitigation request), the candidate upgrades it and must serve the same data and open new incidents, and a rollback restores the pre-upgrade backup and starts v0.9.0 again on it. 9C-3 adds the [disaster recovery runbook](../operations/disaster-recovery.md) and a job that follows it on a fresh runner with only the release tarball and the two backups the other jobs made: roles then database into a new PostgreSQL, the archive into a new ClickHouse, the tarball installed, and every incident and ClickHouse row back. 9C is complete.

### 9D — Security review and fuzzing

- **A review of the whole product**, extending the incident threat model
  to the collector's UDP input, the aggregator and detector, ClickHouse,
  the packaging and the release pipeline. Each new threat gets a test or
  an explicit acceptance, as T-1 to T-48 did.
- **Supply chain:** `cargo audit` and `cargo deny` over the workspace,
  `npm audit` over the UI, Trivy over the images, and a gitleaks scan of
  the full history before the repository becomes permanently public.
- **Fuzzing report:** the IPFIX, NetFlow and sFlow parsers fuzzed for a
  stated time on a nightly toolchain, with coverage and any crashes
  reported and fixed (FU-3).
- **An independent adversarial review** of the release candidate, as
  Phase 5's code had, with every finding triaged.

**Exit:** a security review document lists every finding with its
severity and disposition, and none rated Critical or High is open.

**Progress:** the supply chain checks are in CI: `cargo deny` (RustSec advisories, licences, wildcards, sources) in the Rust job, `npm audit` in the web job, Trivy over every image in the package job, and gitleaks over the full history in the history job, which found nothing in 406 commits. The [security review](../security/security-review.md) lists eleven findings so far, none Critical. Both High are fixed: a 46-byte IPFIX message that exhausted the collector's memory, and unbounded exporter and template state from spoofed UDP senders, now bounded ([ADR 0056](decisions/0056-phase9d-collector-input-bounds.md)). So are the six Medium, among them the plaintext ClickHouse export. Two Low remain, as FU-66 and FU-67. The threat model gains T-49 to T-57. Still to come: the fuzzing report (FU-3) and the independent review of the release candidate.

## Phase 10 milestones

### 10A — The release pipeline

`.github/workflows/release.yml`, triggered by a `v*` tag on `main`:

- Builds the tarballs and multi-architecture images from the tagged
  commit, in a job with read-only contents permission; only the publish
  job may write, inside a `release` environment that needs the owner's
  approval.
- **Checksums:** one `SHA256SUMS` file covering every artifact.
- **SBOMs** in CycloneDX for the Rust workspace, the UI and each image.
- **Signatures:** cosign keyless signatures for the checksum file, the
  SBOMs and every image, and GitHub build provenance attestations.
- **The release:** a GitHub release whose notes come from
  `CHANGELOG.md`, with every artifact attached.
- Every action pinned by commit SHA, as the validate workflow's are.

**Exit:** `v1.0.0-rc.1` is published by the pipeline, and a clean runner
downloads it, verifies every checksum, signature and attestation, installs
it and passes the smoke test.

**Progress:** 10A-1 ([ADR 0057](decisions/0057-phase10a-release-pipeline.md)) adds `release.yml`: a read-only check of the tag (on `main`, equal to the workspace version, with a changelog section), native builds of the tarballs and images, CycloneDX SBOMs by syft for the workspace, the UI and every image, and, after the owner approves the `release` environment, `SHA256SUMS`, cosign keyless signatures, build provenance for every file and image, the images on GHCR and the GitHub release. A last job verifies and installs the release on a clean runner, following the new [Verifying a Release](../operations/verifying-a-release.md) guide. Pull requests that change the pipeline run it as a dry run up to the SBOMs. The exit, `v1.0.0-rc.1`, waits for 9D and 10B.

### 10B — Release documentation

What the master prompt requires of every release, written for operators:

- Release notes, the upgrade guide (from v0.9.0), the rollback guide,
  migration notes (V1 to the latest), known issues, and a test summary
  built from real CI runs.
- A production checklist and a security checklist, each item pointing
  at the test or document that proves it.
- A quick start from the release artifacts, a customer onboarding guide
  and a commercial deployment guide. The commercial guide covers the
  Community Edition as built; the editions in
  [commercial boundaries](../commercial-boundaries.md) stay proposals.
- How to verify a download: checksum, signature and attestation.

**Exit:** the documentation site builds with every page in the
navigation, and each checklist item links to its proof.

**Progress:** 10B-1 adds the operator's release documents: [Upgrading and Rolling Back](../operations/upgrading.md), which follows the upgrade drill (stop the collector and let the inbox empty, back up, install, start in order, check; roll back by restoring) and lists what changes from v0.9.0; [migration notes](../release/migration-notes.md) (none since v0.9.0); [known issues](../release/known-issues.md); and the [production](../release/production-checklist.md) and [security](../release/security-checklist.md) checklists, each item linked to its proof and awaiting the owner's sign-off. 10B-2 adds the [quick start](../quick-start.md) on Docker Compose (whose collector now takes the exporter allowlist), the [customer onboarding guide](../operations/customer-onboarding.md), each step with its check, and the [commercial deployment guide](../commercial/deployment-guide.md) for the Community Edition as built. The release notes and the test summary come with the release candidate, from its own runs.

### 10C — v1.0.0

- Release candidates until one passes every check unchanged.
- The owner signs off the production and security checklists (the
  Phase 10 acceptance criterion). Nothing is tagged before that.
- `v1.0.0` is tagged on `main`, the pipeline publishes it, and the
  roadmap, README and changelog mark it released.

**Exit:** the v1.0.0 GitHub release exists with every required artifact,
and its verification from a clean runner passes.

## Risks

| Id | Risk | Response |
|---|---|---|
| R30 | Numbers from a 4-vCPU runner are read as a promise for production hardware | Every figure is published with its machine and run link, described as a floor, and the capacity guide says how to measure on one's own hardware |
| R31 | A compromised workflow or dependency signs and publishes a malicious release | Actions pinned by SHA, least-privilege tokens, a publish job inside an approval-gated environment, tags only from `main`, and provenance a user can verify |
| R32 | Container base images bring known vulnerabilities | A minimal base, a Trivy gate in CI, Dependabot for base images, and a rebuild for each release |
| R33 | An upgrade from v0.9.0 loses or corrupts data | A mandatory backup before upgrading, an upgrade test with real data in CI, and a rollback proven by restore |
| R34 | The repository becoming permanently public exposes something in its history | A full-history gitleaks scan and a review of the history before v1.0.0, in 9D |

## Where to read next

- [Phases 9 and 10 acceptance criteria](../development/phase9-10-acceptance-criteria.md)
- [Blocking questions](../blocking-questions.md): BQ-3 and BQ-16 to BQ-18
- [Capacity planning](../operations/capacity-planning.md): the 100,000
  records a second target
- [Backup and restore](../operations/backup-and-restore.md): the
  PostgreSQL procedure CI already proves
- [Phase 7 Gate 2 assessment](../development/phase7-gate2-assessment.md):
  what stays open into v1.1.0
