# Verifying a Release

Status: **Phase 10A**, 2026-10-13
([ADR 0057](../architecture/decisions/0057-phase10a-release-pipeline.md)).

Every WetechiNetMon release is built, signed and published by the
repository's release workflow from a tagged commit of `main`. Before you
install one, check that what you downloaded is what that workflow
built. The release workflow runs these same steps on a clean machine
after every release.

## What a release holds

| File | What it is |
|---|---|
| `wetechinetmon-<version>-linux-x86_64.tar.gz`, `...-aarch64.tar.gz` | The install tarballs |
| `wetechinetmon-<version>-rust.cdx.json`, `...-web.cdx.json` | CycloneDX SBOMs of the Rust workspace and the NOC UI |
| `wetechinetmon-<service>-<version>-<amd64\|arm64>.cdx.json` | A CycloneDX SBOM of each image |
| `SHA256SUMS` | The SHA-256 of every file above |
| `*.sigstore.json` | The cosign signature bundle of `SHA256SUMS` and of each SBOM |

The images are `ghcr.io/logixhare/wetechinetmon-<service>:<version>`,
for `collector`, `incident-manager`, `api`, `notifier` and `mitigator`,
each for amd64 and arm64.

## You need

- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
  3.0 or later, which reads the bundles the release workflow writes;
- the [GitHub CLI](https://cli.github.com/) 2.49 or later, signed in,
  for the provenance checks.

## 1. Download

```bash
version=1.0.0
gh release download "v$version" -R LogiXhare/wetechi-netmon -D "wetechinetmon-$version"
cd "wetechinetmon-$version"
```

## 2. Check the signatures

The signature must come from this repository's release workflow, run
for this tag:

```bash
identity="https://github.com/LogiXhare/wetechi-netmon/.github/workflows/release.yml@refs/tags/v$version"
issuer=https://token.actions.githubusercontent.com
for file in SHA256SUMS *.cdx.json; do
  cosign verify-blob --bundle "$file.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$file"
done
```

Each prints `Verified OK`. Anything else, stop.

## 3. Check the checksums

```bash
sha256sum -c SHA256SUMS
```

Every line must end in `OK`. If you downloaded only some of the files,
add `--ignore-missing`.

## 4. Check the build provenance

The provenance says which workflow, commit and runner built each file:

```bash
for file in *.tar.gz *.cdx.json SHA256SUMS; do
  gh attestation verify "$file" -R LogiXhare/wetechi-netmon \
    --signer-workflow LogiXhare/wetechi-netmon/.github/workflows/release.yml
done
```

## 5. Check an image

```bash
image=ghcr.io/logixhare/wetechinetmon-collector:$version
cosign verify "$image" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"
gh attestation verify "oci://$image" -R LogiXhare/wetechi-netmon \
  --signer-workflow LogiXhare/wetechi-netmon/.github/workflows/release.yml
```

Pin the digest that `cosign verify` reports, not the tag, in what you
deploy: a tag can be moved, a digest cannot.

## Then

Install the tarball as the [disaster recovery runbook](disaster-recovery.md)
and `deployments/systemd/README.md` describe, or run the images with the
[Compose reference stack](https://github.com/LogiXhare/wetechi-netmon/blob/main/deployments/docker-compose/README.md).
