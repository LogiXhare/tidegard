# 0057. Phase 10A The Release Pipeline

Status: **Accepted**
Date: 2026-10-13
Deciders: Repository owner (BQ-16, 2026-10-12: a public GitHub release,
signed with cosign keyless, with build provenance); the details under
the delegation of 2026-10-05 to industry practice

## Context

v1.0.0 is a public GitHub release (BQ-16). An operator installing it
must be able to tell that what they downloaded is what this repository's
workflow built from a tagged commit of `main`, and nothing else. Until
now nothing was released: v0.9.0 is a tag only.

## Decision

`.github/workflows/release.yml`, run by a `v*` tag:

1. **check** reads only. The tag must be `v<semver>`, on `main`, equal to
   `[workspace.package] version`, and have a section in `CHANGELOG.md`.
   A tag with a hyphen (`v1.0.0-rc.1`) is published as a pre-release.
2. **build** reads only. On native x86_64 and aarch64 runners (Ubuntu
   22.04, ADR 0052) it builds the tarball with `scripts/package.sh` and
   one image per service from that tarball, as CI's package job does.
3. **sbom** reads only. syft writes CycloneDX SBOMs: one for the Rust
   workspace from `Cargo.lock`, one for the UI from
   `apps/web/package-lock.json`, and one per image and architecture. An
   SBOM without components fails the job.
4. **publish** waits for the owner's approval of the `release`
   environment, and only it can write. It writes `SHA256SUMS` over every
   tarball and SBOM, signs `SHA256SUMS` and each SBOM with cosign
   keyless (a Sigstore bundle beside each), attests build provenance for
   every file, pushes each image to `ghcr.io/logixhare` for both
   architectures under one multi-architecture tag, signs and attests each
   image by digest, and creates the GitHub release with the changelog's
   section as its notes.
5. **verify** runs on a clean runner with no checkout: it downloads the
   release as an operator would, verifies every signature against this
   workflow's identity and the tag, every checksum and every
   attestation, verifies each image the same way, then installs the
   tarball and starts every service until it is ready.

The steps an operator follows are
[Verifying a Release](../../operations/verifying-a-release.md); the
verify job is those steps.

Tools: cosign v3.1.3 and syft 1.52.0 are downloaded and checked against
pinned SHA-256 digests, as gitleaks, Trivy and cargo-deny are. Actions
are pinned by commit SHA, `actions/attest-build-provenance` at v4.2.2.

A pull request that changes `release.yml`, `scripts/package.sh` or the
Dockerfile runs **check**, **build** and **sbom** as a dry run, under a
version no tag can have (`0.0.0-dryrun.<commit>`). Nothing is signed or
published without a tag.

## Consequences

- Keyless signing needs no key to keep, rotate or leak. The signature
  is bound to this repository, this workflow and the tag, and is
  recorded in Sigstore's public transparency log.
- The `release` environment must exist with the owner as required
  reviewer, limited to `v*` tags, before the first tag. GitHub creates a
  missing environment without protection on first use, so the
  environment is created with this ADR.
- Environment protection is free for public repositories only. A tag
  pushed while the repository is private would publish without the
  approval; from v1.0.0 the repository stays public (BQ-16), and until
  then no tag is pushed while it is private.
- Images are tagged with the version alone. There is no `latest`: an
  operator names the version they run.
- The first real run is `v1.0.0-rc.1`, which is 10A's exit: published by
  this pipeline, then verified and installed by its last job.

## Alternatives considered

- **A signing key in a repository secret.** One more secret to protect
  and rotate, and a stolen key signs anything. Keyless signing, which
  BQ-16 chose, binds each signature to the workflow run instead.
- **`docker/build-push-action` with QEMU.** Emulated aarch64 builds are
  slow, and the images would no longer be built from the tarball the
  package job tests. Native runners and `docker buildx imagetools` keep
  them the same.
- **`cargo-cyclonedx`.** It would be built from source on every release.
  syft is one pinned binary that also describes the UI and the images.
