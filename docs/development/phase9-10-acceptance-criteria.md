# Phases 9 and 10 Acceptance Criteria

Status: **Defined 2026-10-12, before any Phase 9 code.** Part of the
[Phases 9 and 10 plan](../architecture/phase9-10-production-release-plan.md).

As in Phases 5 to 7, the criteria are written before the work starts, so
the work is judged against them rather than the other way round. Each
one is assessed with the test, run or document that proves it. The
general criteria for both phases in
[acceptance criteria](../acceptance-criteria.md) still apply; these make
them concrete.

## Gate 1 — Planning accepted

- [x] The owner has decided BQ-3 and BQ-16 to BQ-18
  ([blocking questions](../blocking-questions.md)).
- [x] The plan names each milestone, its exit criterion, and the risks
  (R30 to R34 in the [risk register](../risk-register.md)).
- [x] These criteria exist before any Phase 9 code.

## Gate 2 — Phase 9 complete

### Defaults

- An install from the packaged artifacts is dry-run with BGP disabled,
  asserted by a test against the packaged configuration files.
- The Compose reference stack publishes no port beyond the API, the
  collector and the metrics endpoints, and `gobgpd`'s API is reachable
  only inside its own network namespace.

### Packaging (9A)

- Tarballs build for `x86_64` and `aarch64` Linux, and images for
  `linux/amd64` and `linux/arm64`, in CI.
- Every image runs as a non-root user with a read-only root filesystem,
  and Trivy finds no fixable Critical or High vulnerability in it.
- Every systemd unit passes `systemd-analyze verify` and runs under its
  own unprivileged user.
- The Compose stack starts from the built images, every service reports
  ready, and synthetic flows end as an incident visible through the API.

### Load and soak (9B)

- Pass criteria are recorded in an ADR before the first measured run.
- Load, API latency and soak results are real, executed on the reference
  runner, and published with their run links and machine description.
  None is estimated.
- If the 100,000 records a second target is missed, the published result
  says so.
- The six-hour soak shows no unbounded memory growth and no restart.

### Backup, restore, upgrade and rollback (9C)

- PostgreSQL and ClickHouse are each backed up and restored round-trip
  in CI.
- An upgrade from v0.9.0 with incidents and mitigations in the database
  preserves them, and the services start, in CI.
- A rollback by restoring the pre-upgrade backup and the previous binaries
  is proven in CI.
- The disaster recovery runbook is exercised from an empty runner.

### Security review (9D)

- The threat model covers every component that ships, and each new
  threat has a test or a recorded acceptance.
- `cargo audit`, `cargo deny`, `npm audit`, Trivy and a full-history
  gitleaks scan run, and their results are recorded.
- Each parser has been fuzzed for the time stated in the report, and any
  crash found is fixed with a regression test.
- Every finding is triaged, and none rated Critical or High is open.

## Gate 3 — v1.0.0 released (Phase 10)

### The pipeline (10A)

- A `v*` tag on `main` is the only trigger, and publishing waits for
  approval in the `release` environment.
- The release carries the tarballs, `SHA256SUMS`, CycloneDX SBOMs, cosign
  signatures and build provenance attestations, and its images are
  signed.
- A clean runner verifies every checksum, signature and attestation of a
  release candidate, installs it and passes the smoke test.

### Documentation (10B)

- The release includes the changelog, release notes, upgrade guide,
  rollback guide, migration notes, known issues and a test summary built
  from real runs.
- The production checklist and the security checklist link each item to
  its proof.
- The quick start, customer onboarding guide, commercial deployment
  guide and download verification guide exist and are in the site
  navigation.

### Release (10C)

- The owner has signed off the production checklist and the security
  checklist.
- The v1.0.0 GitHub release is published from its tag by the pipeline,
  and verifies from a clean runner.
- The roadmap, README and changelog mark v1.0.0 released, with T-21,
  FU-65 and the other v1.1.0 items listed as known limitations.
