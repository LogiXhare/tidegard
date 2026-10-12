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

9A lands in three steps: health and readiness (9A-1), tarballs and
systemd units (9A-2), then images and the Compose stack (9A-3).

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

### Images and the Compose stack (9A-3)

- One image per service on GHCR, `linux/amd64` and `linux/arm64`, built
  from the same binaries as the tarballs, so what is tested is what is
  shipped. The base is distroless `cc` (glibc, no shell), pinned by
  digest, running as its `nonroot` user with a read-only root
  filesystem.
- The API image carries the web UI and sets `WETECHINETMON_API_WEB_ROOT`.
- `deployments/docker-compose` holds the reference stack: PostgreSQL,
  ClickHouse and the services, dry-run with BGP off. `gobgpd` is in an
  opt-in profile, its API reachable only inside the Compose network.
- CI scans every image with Trivy and fails on a fixable Critical or High
  finding, lints Dockerfiles with hadolint and scripts with shellcheck,
  and verifies the units with `systemd-analyze verify`.

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
