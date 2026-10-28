# Production Checklist

Status: **v1.0.0-rc.3**, 2026-10-28. **Not yet signed off.**

Phase 10's acceptance criterion: the owner signs this list and the
[security checklist](security-checklist.md) before `v1.0.0` is tagged.
Every item links to what proves it, and every proof is a CI job that
runs on each pull request or a measured run with its link.

## Install and run

| # | Item | Proof |
|---|---|---|
| P-1 | The tarball installs on Ubuntu 22.04 for x86_64 and aarch64, keeps every setting on a second run, and every service becomes ready | The `package` job, both architectures ([ADR 0052](../architecture/decisions/0052-phase9a-packaging.md)) |
| P-2 | Every service answers `/healthz` and `/readyz`; a standby mitigator is not ready | The `package` and `e2e` jobs |
| P-3 | One image per service, non-root, read-only root filesystem, every capability dropped | The `package` job |
| P-4 | The Compose reference stack runs with TLS between every container and turns synthetic flows into an incident | The `package` job, both architectures |
| P-5 | Settings files are root's or their service's only: `0600` and `0640` | The `package` job checks every mode |

## Capacity

| # | Item | Proof |
|---|---|---|
| P-6 | 100,000 flow records a second with loss ≤ 0.1%, memory ≤ 1 GiB | [Flow pipeline, measured](../operations/capacity-planning.md#flow-pipeline-measured): no loss at 200,000, 13 MiB |
| P-7 | API p99 ≤ 250 ms with 10,000 incidents | [API latency, measured](../operations/capacity-planning.md#api-latency-measured): 107 ms at worst |
| P-8 | Five hours at 50,000 records a second with memory growth ≤ 10% | [Soak, measured](../operations/capacity-planning.md#soak-measured): +3.5%, no loss |

## Data

| # | Item | Proof |
|---|---|---|
| P-9 | The PostgreSQL backup restores into a fresh database, on PostgreSQL 15 to 18 | The `postgres` jobs ([Backup and Restore](../operations/backup-and-restore.md)) |
| P-10 | The ClickHouse backup restores every table identically and takes new rows | The `grafana` job ([ADR 0055](../architecture/decisions/0055-phase9c-backup-upgrade-rollback.md)) |
| P-11 | An upgrade from v0.9.0 keeps every incident, note, acknowledgement and mitigation; a rollback restores v0.9.0's | The `upgrade` job ([Upgrading](../operations/upgrading.md)) |
| P-12 | A lost host is rebuilt from the tarball and the two backups alone | The `disaster-recovery` job ([runbook](../operations/disaster-recovery.md)) |

## Operations

| # | Item | Proof |
|---|---|---|
| P-13 | Every connection off this host is TLS, verified against a configured CA: PostgreSQL, ClickHouse, the API, GoBGP | ADRs [0023](../architecture/decisions/0023-phase5b-postgresql-tls.md), [0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md), [0038](../architecture/decisions/0038-phase5d-api-boundary.md), [0048](../architecture/decisions/0048-phase7c-gobgp-adapter.md), each with its tests |
| P-14 | Mitigation ships dry-run with BGP off, and the kill switch stops every announcement | The `package` job checks the shipped mitigator; `crates/mitigator/tests/mitigator_service.rs` (the kill switch, expiry, reconciliation) and the two-speaker lab, in the `rust` job |
| P-15 | Dashboards run every query against real servers | The `grafana` job ([ADR 0041](../architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)) |
| P-16 | Runbooks for incidents, mitigation, upgrades, backups and disaster recovery | [Operations](../operations/index.md) |
| P-17 | Every release is signed and attested, and the pipeline that publishes it verifies and installs it on a clean runner | The release workflow's `verify` job ([ADR 0057](../architecture/decisions/0057-phase10a-release-pipeline.md)) |
| P-18 | What v1.0.0 does not do is written down | [Known issues](known-issues.md) |
| P-19 | The published release, installed as shipped, takes synthetic flows to an incident, an approved RTBH route on a lab edge router, signed notifications and a withdrawal; anyone can download it and pull its images without signing in | The release acceptance test ([ADR 0059](../architecture/decisions/0059-release-acceptance-test.md)), its run in the [test summary](test-summary.md) |

## Sign-off

| | |
|---|---|
| Release candidate | v1.0.0-rc.3 ([test summary](test-summary.md)) |
| Signed off by | |
| Date | |
