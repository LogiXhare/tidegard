# Upgrading and Rolling Back

Status: **Phase 10B**, 2026-10-13
([ADR 0055](../architecture/decisions/0055-phase9c-backup-upgrade-rollback.md)).

How to move a running WetechiNetMon to a new release, and back if it goes
wrong. CI follows this on every pull request: the `upgrade` job fills a
v0.9.0 database through v0.9.0's own services, upgrades it to the
candidate, checks that every incident, note, acknowledgement and
mitigation request survived and that new incidents still open, then
rolls back by restoring the pre-upgrade backup
(`scripts/upgrade-rollback-drill.sh`).

## Before you start

1. Read the release notes and [known issues](../release/known-issues.md)
   of every version between yours and the new one.
2. [Verify the release](verifying-a-release.md) you downloaded.
3. Check the [migration notes](../release/migration-notes.md): they say
   whether the new version changes either database.
4. Plan a window. Flows that arrive while the collector is stopped are
   lost; the routers keep exporting, and nothing queues them.

## 1. Stop the collector, and let the queue empty

Detection events the collector has already queued in PostgreSQL become
incidents when the incident manager processes them. Stop the collector
first, so no new ones arrive, and wait until the inbox is empty:

```bash
sudo systemctl stop wetechinetmon-collector
psql -U postgres -d wetechinetmon -tAc \
  "SELECT count(*) FROM detection_event_inbox WHERE status IN ('pending', 'retrying')"
```

Repeat the query until it prints `0`. Then stop the rest:

```bash
sudo systemctl stop wetechinetmon-mitigator wetechinetmon-notifier \
  wetechinetmon-api wetechinetmon-incident-manager
```

While the mitigator is stopped, the routes it announced stay with GoBGP
and the routers, and none expires: if one is due during the window, see
[stale routes](mitigation-runbook.md#stale-routes) in the mitigation
runbook first.

## 2. Back up

Take all three, and keep them off the host, as
[Backup and Restore](backup-and-restore.md) describes:

```bash
pg_dumpall -U postgres --roles-only > roles.sql
pg_dump -U postgres -d wetechinetmon --format=custom > pre-upgrade.dump
```

and the ClickHouse `BACKUP` of every WetechiNetMon table. Copy
`/etc/wetechinetmon` too. This backup is your rollback.

## 3. Install the new release

```bash
tar -xzf wetechinetmon-<version>-linux-$(uname -m).tar.gz
sudo ./wetechinetmon-<version>-linux-$(uname -m)/install.sh
```

`install.sh` replaces the binaries, units and the UI, and never
overwrites a setting: an existing file in `/etc/wetechinetmon` is kept,
and the new example is not installed over it. Compare your settings with
the release's examples in its `etc/` directory for anything new.

## 4. Start, in order

The incident manager applies any new migration when it starts, before
it reports ready:

```bash
sudo systemctl start wetechinetmon-incident-manager
curl -fsS http://127.0.0.1:9091/readyz
sudo systemctl start wetechinetmon-api wetechinetmon-collector
sudo systemctl start wetechinetmon-notifier wetechinetmon-mitigator   # if you run them
```

## 5. Check

- `/readyz` answers `200` on every service.
- `GET /api/v1/incidents?limit=1&include_total=true` counts what it did
  before.
- The collector's `parsed_flow_records_total` rises, and nothing new
  appears in `datagrams_refused_total`.
- `wetechinetmonctl kill-switch status` and `bgp peers` answer as
  before, if mitigation runs.

## Rolling back

Migrations only move forward (ADR 0024): no version can undo another's
schema change. Rolling back is restoring the pre-upgrade backup and
installing the version you had:

```bash
sudo systemctl stop wetechinetmon-collector wetechinetmon-mitigator \
  wetechinetmon-notifier wetechinetmon-api wetechinetmon-incident-manager
psql -U postgres -c "DROP DATABASE wetechinetmon WITH (FORCE)" \
  -c "CREATE DATABASE wetechinetmon OWNER wetechinetmon"
pg_restore -U postgres -d wetechinetmon --no-owner --exit-on-error \
  --single-transaction pre-upgrade.dump
sudo ./wetechinetmon-<previous version>-linux-$(uname -m)/install.sh
```

Put back the `/etc/wetechinetmon` you copied, then start in the order
above. Everything recorded after the backup, incidents, notes and
audit entries included, is lost: decide before you roll back whether
that is worse than the problem.

## From v0.9.0

v0.9.0 was a tag, not a release: it had no tarball or units, so it ran
however you built it. Moving to v1.0.0 is moving to the packaged layout:

- Binaries go to `/opt/wetechinetmon/bin`, settings to
  `/etc/wetechinetmon/*.env` and `*.json`, and each service runs as its
  own system user under the units `install.sh` installs. Move your
  settings into the `.env` files; the variable names are unchanged.
- **The collector's ClickHouse export** now refuses plain HTTP to
  anything but this host, and takes credentials only from
  `WETECHINETMON_COLLECTOR_CLICKHOUSE_USER` and `_PASSWORD_FILE`, never
  the URL ([ADR 0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md)).
  A remote `http://` URL, or one with a password in it, now stops the
  collector at startup: set `https://`, `_CA_FILE` and the password file.
- **`WETECHINETMON_COLLECTOR_ALLOWED_EXPORTERS`** is new. Set it to your
  routers ([ADR 0056](../architecture/decisions/0056-phase9d-collector-input-bounds.md)).
- Every service answers `/healthz` and `/readyz` on its metrics address.
- No database migration: v1.0.0 has the same 21 PostgreSQL migrations
  and the same ClickHouse tables as v0.9.0.
