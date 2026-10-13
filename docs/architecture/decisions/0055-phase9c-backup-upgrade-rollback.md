# 0055. Phase 9C Backup, Restore, Upgrade and Rollback

Status: **Accepted**
Date: 2026-10-13
Deciders: Repository owner (Phases 9 and 10 plan, 2026-10-12); the
details under the delegation of 2026-10-05 to industry practice

## Context

NFR-2 says an untested restore is not a backup. CI has restored a real
PostgreSQL backup on every pull request since Phase 5F. Three things are
still only on paper
([Phases 9 and 10 plan](../phase9-10-production-release-plan.md), 9C):

- **ClickHouse**, which holds the flow and detection history, has no
  backup procedure at all.
- **Upgrading** from v0.9.0 has never been tried with data in it.
- **Rolling back**, and **rebuilding a lost host**, have never been tried.

## Decision

9C lands in three steps: the ClickHouse drill (9C-1), upgrade and
rollback (9C-2), and disaster recovery from an empty runner (9C-3).

### ClickHouse: its own BACKUP and RESTORE (9C-1)

ClickHouse's own `BACKUP TABLE ... TO File(...)` and `RESTORE`, to a
directory the server's configuration allows (`<backups><allowed_path>`).
No external tool: the server makes a consistent copy of each table's
parts while it keeps writing. The backup goes off the host with the
rest of the backups, as for PostgreSQL.

`scripts/clickhouse-backup-restore-drill.sh` proves it in the Grafana
job, against a throwaway server:

1. Fill every Tidegard table with synthetic rows.
2. Fingerprint each table: its row count and an order-independent hash
   of every row (`groupBitXor(cityHash64(*))`).
3. Back up every table, then drop them all.
4. Restore, and require identical fingerprints.
5. Prove the restored copy takes new rows: the collector's own writer
   writes and reads back every row type
   (`crates/storage/tests/clickhouse_integration.rs`).

ClickHouse's retention (30 days for traffic, 365 for detection events)
means a restore brings back only what had not yet expired when the
backup was taken, and older rows expire again on the next merge.

### Upgrade and rollback (9C-2)

v0.9.0 is tagged at `7ca8223`, the commit Phase 7 closed on, so the
upgrade path has a name. A CI job builds v0.9.0 and the candidate,
fills a v0.9.0 database through v0.9.0's own services, takes the backup
an operator is told to take, upgrades, and proves the data survives and
the services start. Then it rolls back the documented way: restore the
pre-upgrade backup, start v0.9.0 again, and prove it serves the same
data.

Migrations are forward-only and never edited (ADR 0024), so a rollback
is always a restore, never a down-migration.

### Disaster recovery (9C-3)

A job on a fresh runner gets only what an operator would have after
losing a host: the release tarball, the two backups and the settings.
It installs, restores and starts the services, and checks the incidents
through the CLI. The runbook is the procedure that job follows.

## Consequences

- Both databases now have a backup that CI restores and uses on every
  pull request.
- A change that breaks an upgrade from v0.9.0, or a restore, fails CI
  before it merges.

## Alternatives considered

- **`clickhouse-backup` (Altinity).** A separate tool to pin and review,
  for features (remote storage, incremental backups) the single-host
  v1.0.0 does not need. ClickHouse's built-in commands cover a full
  backup and restore.
- **Copying ClickHouse's data directory.** Only safe with the server
  stopped, and tied to the exact server version.
- **Down-migrations for rollback.** Every migration would need a tested
  inverse, and some changes, such as dropped data, have none. Restoring
  the pre-upgrade backup is simpler and always correct.
