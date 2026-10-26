# Release

Status: **v1.0.0-rc.2**, 2026-10-26 (Phase 10C).

What an operator needs to take a Tidegard release into production,
and what the owner signs before v1.0.0 is tagged.

- [Quick Start](../quick-start.md): one host with Docker, from a release.
- [Customer Onboarding](../operations/customer-onboarding.md) and the
  [Commercial Deployment Guide](../commercial/deployment-guide.md).
- [Verifying a Release](../operations/verifying-a-release.md): check the
  signatures, checksums and provenance before installing.
- The release acceptance test
  ([ADR 0059](../architecture/decisions/0059-release-acceptance-test.md)):
  the published release, end to end in a lab, from flows to a withdrawn
  route.
- [Upgrading and Rolling Back](../operations/upgrading.md): from v0.9.0,
  and from one release to the next.
- [Migration Notes](migration-notes.md): what each release does to the
  two databases.
- [Known Issues](known-issues.md): what v1.0.0 does not do, or does in
  part.
- [Test Summary](test-summary.md): what the current release candidate
  passed, with every run's link.
- [Production Checklist](production-checklist.md) and
  [Security Checklist](security-checklist.md): every item with the test
  or document that proves it, signed off by the owner.
