# 0052. Phase 9A Packaging

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-16, 2026-10-12); the details under the
delegation of 2026-10-05 to industry practice

## Context

Until now WetechiNetMon has been built from source and started by hand or
by CI. v1.0.0 must be installable: tarballs, systemd units, container
images and a Compose stack
([Phases 9 and 10 plan](../phase9-10-production-release-plan.md), 9A).
Supervisors such as systemd, Docker and Kubernetes need to ask a service
whether it is alive and whether it is ready, and NFR-2 requires both
answers from every service. Only the API gave them: the collector, the
incident manager, the notifier and the mitigator served `/metrics` alone.

9A lands in steps: health and readiness (9A-1), tarballs and systemd
units (9A-2), the collector's ClickHouse connection (9A-3a,
[ADR 0053](0053-phase9a-collector-clickhouse-tls.md)), images (9A-3b),
then the Compose stack (9A-3c).

## Decision

### Health and readiness on the metrics endpoint (9A-1)

The shared metrics server in `crates/common` serves two more paths on
the same address:

| Path | Answer |
|---|---|
| `/healthz` | `200 ok` while the process runs |
| `/readyz` | `200 ready` when the service can do its work, `503 not ready` otherwise |

A `Readiness` flag, shared by clone, starts not ready. Each service sets
it as follows:

| Service | Ready when |
|---|---|
| Collector | its UDP socket is bound; nothing later in startup can fail |
| Incident manager | its latest correlation batch succeeded, so after the migrations |
| Notifier | its latest outbox batch succeeded |
| Mitigator | it holds the single-mitigator lock and its latest pass succeeded; a standby stays not ready |

A failed batch or pass makes the service not ready until the next one
succeeds, so readiness follows the database. Nothing new listens: the
metrics addresses and their defaults are unchanged (all interfaces for
the collector and the incident manager, as Prometheus scrapes them from
elsewhere; loopback for the notifier and the mitigator). The two new
paths reveal only "up" and "ready".

A standby mitigator is alive but not ready on purpose: it does no work,
and `/readyz` tells an operator which instance is active.

### Tarballs and systemd units (9A-2)

- One tarball per architecture, `wetechinetmon-<version>-linux-<arch>.tar.gz`
  for `x86_64` and `aarch64`, holding `bin/`, the web UI's `share/web/`,
  example configuration under `etc/`, the systemd units, `LICENSE` and
  `NOTICE`.
- Built natively on GitHub's `ubuntu-22.04` and `ubuntu-22.04-arm`
  runners, linked against glibc 2.35, so they run on Ubuntu 22.04 and
  24.04 and on Debian 12 and 13. musl is not used: its allocator is slow
  under the collector's allocation pattern, and 9B measures throughput.
- One unit per service, each with its own system user, an
  `EnvironmentFile` in `/etc/wetechinetmon/` readable only by that user
  and root (it holds the database URL), and the hardening options
  `systemd-analyze security` rewards: `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  an empty `CapabilityBoundingSet`, `RestrictAddressFamilies` and a
  `SystemCallFilter` of `@system-service`.

### Images (9A-3b)

- One image per service, `linux/amd64` and `linux/arm64`, built from
  the unpacked tarball by `deployments/docker/Dockerfile` (one target per
  service), so what is tested is what is shipped. CI builds them natively
  on each architecture in the `package` job. They are published to GHCR
  only by the release pipeline (10A), never from a pull request.
- The base is distroless `cc-debian13`: glibc and CA certificates, no
  shell and no package manager. Distroless's Debian 12 images were
  deprecated in August 2026. The base is pinned by digest, normally at
  least two weeks old, and Dependabot proposes a new digest after the
  same wait. A security fix overrides the wait: the first pin moved to a
  newer digest because Trivy found a fixable High in the older one's
  `libssl3t64` (CVE-2026-84782), although no WetechiNetMon binary links
  OpenSSL.
- Every image runs as distroless's `nonroot` user, by its number
  (65532) so a runtime can verify it is not root, and works with a
  read-only root filesystem, no capabilities and `no-new-privileges`.
  CI checks the user of each image and runs one that way.
- Inside a container the metrics address listens on all interfaces, so a
  probe can reach it; publishing decides who can. The API image keeps the
  loopback default: off loopback it needs TLS (ADR 0038), which the
  deployment supplies.
- The API image carries the web UI and sets `WETECHINETMON_API_WEB_ROOT`.
- CI scans every image with Trivy and fails on a fixable Critical or High
  finding. Trivy is installed from its release, pinned by version and
  SHA-256, not through its GitHub Action, whose tags were replaced with
  malicious ones in March 2026 (CVE-2026-33634). hadolint lints the
  Dockerfile, pinned the same way.

### The Compose stack (9A-3c)

- `deployments/docker-compose` holds the reference stack: PostgreSQL,
  ClickHouse and the services, dry-run with BGP off.
- Containers reach each other over a network, not loopback, so every
  connection between them uses TLS, as everywhere else: PostgreSQL,
  ClickHouse ([ADR 0053](0053-phase9a-collector-clickhouse-tls.md)) and
  the API. The certificates come from a CA the stack generates on first
  start, kept in a Docker volume and never written to the repository.
- `gobgpd` is not in the stack. Its API has no authentication, and
  sharing it across a container network would weaken the loopback rule
  ADR 0048 relies on. Mitigation with BGP enabled runs from the tarball,
  beside `gobgpd` on the same host, as the
  [mitigation installation guide](../../installation/mitigation.md)
  describes. The Compose mitigator stays dry-run with BGP off.

Kubernetes manifests and a Helm chart are not part of v1.0.0. Their
directories say so.

## Consequences

- Every service answers the same three paths, so one probe shape fits
  systemd, Docker and Kubernetes.
- The e2e job now waits on the incident manager's and the mitigator's
  `/readyz` instead of polling the database.
- Readiness reflects the database, so a database outage shows as every
  dependent service going not ready, which is the signal an operator
  needs.

## Alternatives considered

- **A separate health port.** Another listener to configure and secure
  for no gain: the metrics address already exists, and the new paths
  disclose nothing that `/metrics` does not.
- **Readiness from startup alone.** A service whose database has gone
  away would still say ready. Following the latest batch costs one
  atomic store.
- **musl static binaries and a `scratch` image.** Smaller, but slower
  for the collector, and without CA certificates or time zone data.
