# Disaster Recovery

Status: **Phase 9C**, 2026-10-13
([ADR 0055](../architecture/decisions/0055-phase9c-backup-upgrade-rollback.md)).

The host is gone: disk, configuration, everything on it. This runbook
rebuilds a single-node Tidegard on a new machine. CI follows it on
every pull request: the `disaster-recovery` job starts on a fresh runner
with nothing but the release tarball and the two backups, and must end
with every incident and every ClickHouse row back
(`scripts/disaster-recovery-drill.sh`).

## What you need

Kept off the lost host, as [Backup and Restore](backup-and-restore.md)
says:

| Item | From |
|---|---|
| The release tarball of the version that ran, and its checksum | The GitHub release |
| The PostgreSQL roles dump (`pg_dumpall --roles-only`) | Your backups |
| The PostgreSQL database dump (`pg_dump --format=custom`) | Your backups |
| The ClickHouse backup archive | Your backups |
| The settings: `/etc/tidegard/*.env`, the JSON files, the TLS files and the password files | Your secrets store |

Losing the ClickHouse backup loses traffic history and dashboards only.
Losing the PostgreSQL backup loses the incidents, the audit trail and
the mitigations: that one matters most.

## 1. PostgreSQL

Install PostgreSQL 15 to 18 (17 is recommended, ADR 0025), then restore
the roles first and the database second:

```bash
psql -U postgres -f roles.sql            # errors for roles that already exist are fine
psql -U postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'wetechinetmon_app'"   # must print 1
createdb -U postgres -O tidegard tidegard
pg_restore -U postgres -d tidegard --no-owner --exit-on-error --single-transaction incident.dump
```

Migration `V11` grants to `wetechinetmon_app`, so the database restore
fails without the roles. Count the incidents and compare with what you
expect.

## 2. ClickHouse

Install ClickHouse, allow the backup directory
([Backup and Restore](backup-and-restore.md#clickhouse-flow-and-detection-history)),
copy the archive into it, and restore every Tidegard table:

```sql
RESTORE TABLE default.wetechinetmon_total_ipv4_traffic,
        TABLE default.wetechinetmon_total_ipv6_traffic,
        TABLE default.wetechinetmon_host_traffic,
        TABLE default.wetechinetmon_network_traffic,
        TABLE default.wetechinetmon_slash24_network_traffic,
        TABLE default.wetechinetmon_hostgroup_traffic,
        TABLE default.wetechinetmon_asn_traffic,
        TABLE default.wetechinetmon_exporter_traffic,
        TABLE default.wetechinetmon_interface_traffic,
        TABLE default.wetechinetmon_detection_events
FROM File('tidegard-2026-10-13.zip');
```

## 3. Tidegard

Verify the tarball's checksum, then install it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf tidegard-<version>-linux-$(uname -m).tar.gz
sudo ./tidegard-<version>-linux-$(uname -m)/install.sh
```

Put your saved settings back over the examples in `/etc/tidegard`,
with the same owners and modes `install.sh` gives them (`0600 root` for
the env files, `0640 root:<service group>` for the rest). Then start in
order:

```bash
sudo systemctl enable --now tidegard-incident-manager   # finds no migration to apply
curl -fsS http://127.0.0.1:9091/readyz
sudo systemctl enable --now tidegard-api tidegard-collector
sudo systemctl enable --now tidegard-notifier tidegard-mitigator   # if you ran them
```

## 4. Check

- `/readyz` answers `200` on every service.
- The API lists every incident:
  `GET /api/v1/incidents?limit=1&include_total=true` gives the count you
  restored.
- The collector's log says `ClickHouse export enabled`, and the
  dashboards show history up to the backup.
- `tidegardctl kill-switch status` and `bgp peers` answer as before,
  if mitigation ran.

Point your exporters at the new host last, once all of this holds.

## What is lost

Everything between the last backup and the failure: incidents opened
since, their notes and audit entries, and the traffic history since the
ClickHouse backup. Continuous WAL archiving
([point-in-time recovery](backup-and-restore.md#point-in-time-recovery))
narrows the PostgreSQL gap to minutes.
