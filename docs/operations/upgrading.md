# Upgrading and Rolling Back

Status: **Phase 10B**, 2026-10-13
([ADR 0055](../architecture/decisions/0055-phase9c-backup-upgrade-rollback.md)).

How to move a running Tidegard to a new release, and back if it goes
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
sudo systemctl stop tidegard-collector
psql -U postgres -d tidegard -tAc \
  "SELECT count(*) FROM detection_event_inbox WHERE status IN ('pending', 'retrying')"
```

Repeat the query until it prints `0`. Then stop the rest:

```bash
sudo systemctl stop tidegard-mitigator tidegard-notifier \
  tidegard-api tidegard-incident-manager
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
pg_dump -U postgres -d tidegard --format=custom > pre-upgrade.dump
```

and the ClickHouse `BACKUP` of every Tidegard table. Copy
`/etc/tidegard` too. This backup is your rollback.

## 3. Install the new release

```bash
tar -xzf tidegard-<version>-linux-$(uname -m).tar.gz
sudo ./tidegard-<version>-linux-$(uname -m)/install.sh
```

`install.sh` replaces the binaries, units and the UI, and never
overwrites a setting: an existing file in `/etc/tidegard` is kept,
and the new example is not installed over it. Compare your settings with
the release's examples in its `etc/` directory for anything new.

## 4. Start, in order

The incident manager applies any new migration when it starts, before
it reports ready:

```bash
sudo systemctl start tidegard-incident-manager
curl -fsS http://127.0.0.1:9091/readyz
sudo systemctl start tidegard-api tidegard-collector
sudo systemctl start tidegard-notifier tidegard-mitigator   # if you run them
```

## 5. Check

- `/readyz` answers `200` on every service.
- `GET /api/v1/incidents?limit=1&include_total=true` counts what it did
  before.
- The collector's `parsed_flow_records_total` rises, and nothing new
  appears in `datagrams_refused_total`.
- `tidegardctl kill-switch status` and `bgp peers` answer as
  before, if mitigation runs.

## Rolling back

Migrations only move forward (ADR 0024): no version can undo another's
schema change. Rolling back is restoring the pre-upgrade backup and
installing the version you had:

```bash
sudo systemctl stop tidegard-collector tidegard-mitigator \
  tidegard-notifier tidegard-api tidegard-incident-manager
psql -U postgres -c "DROP DATABASE tidegard WITH (FORCE)" \
  -c "CREATE DATABASE tidegard OWNER tidegard"
pg_restore -U postgres -d tidegard --no-owner --exit-on-error \
  --single-transaction pre-upgrade.dump
sudo ./tidegard-<previous version>-linux-$(uname -m)/install.sh
```

Put back the `/etc/tidegard` you copied, then start in the order
above. Everything recorded after the backup, incidents, notes and
audit entries included, is lost: decide before you roll back whether
that is worse than the problem.

## From v1.0.0

Migration V22 ([ADR 0060](../architecture/decisions/0060-phase8a-tenant-registry.md))
adds the tenant registry and registers every tenant your database
already uses, active and named by its id. Tokens, sessions and data are
unchanged, and a single-tenant install needs no new setting.

- `tidegard-api tenant list` shows the registered tenants. Give one a
  display name with `tenant create` only for a new tenant; existing ones
  keep their id as their name.
- `tidegard-api token create` still registers a tenant it has not seen
  before. A token can no longer be inserted for an unregistered tenant
  by hand.
- Suspending a tenant (`tidegard-api tenant suspend --tenant T`) refuses
  its tokens and sessions at once and keeps its data.
- Migration V23 adds platform tokens. Existing tokens are tenant tokens
  and keep their role and permissions. A client that sends a
  `Tidegard-Tenant` header must send its own tenant.

## From v0.9.0

v0.9.0 was a tag, not a release: it had no tarball or units, so it ran
however you built it. Moving to v1.0.0 is moving to the packaged layout,
under the product's new name:

- **The product is Tidegard** ([ADR 0058](../architecture/decisions/0058-rename-to-tidegard.md)).
  The binaries are `tidegard-*` and `tidegardctl`, the metrics
  `tidegard_*`, the images `ghcr.io/logixhare/tidegard-*`. Rename
  Prometheus queries and alerts written against `wetechinetmon_*`
  metrics; the shipped dashboards already are.
- Binaries go to `/opt/tidegard/bin`, settings to
  `/etc/tidegard/*.env` and `*.json`, and each service runs as its
  own system user under the units `install.sh` installs. Move your
  settings into the `.env` files.
- **Settings are `TIDEGARD_*` now.** Your `WETECHINETMON_*` settings
  still work through the 1.x series: each service reads the old name
  when the new one is unset or blank, and logs a warning. Rename them
  when you can. `tidegardctl` reads its profiles from
  `~/.config/tidegard/cli.json` (`%APPDATA%\tidegard\cli.json` on
  Windows), and still finds the `wetechinetmon` one, with a warning.
- **Three names inside messages changed with the product**, and a
  program that checks them needs the new one:
  - the webhook body's `schema` is `tidegard.notification.v1` and its
    `product` `Tidegard`. The `X-WNM-*` headers and their signature
    are unchanged, so a receiver that verifies the signature and reads
    the fields keeps working; one that compares `schema` needs
    `tidegard.notification.v1` added;
  - an incident export's `format` is `tidegard.incident-export`, still
    version 1. Bundles exported by v0.9.0 keep
    `wetechinetmon.incident-export`; tooling that reads both should
    accept both;
  - an API error's `type` is `https://logixhare.com/tidegard/problems/`
    and the code, no longer `https://wetechi.com/probs/`. The `error`
    code itself is unchanged, and is what a client should match.

  A web UI page left open across the upgrade keeps its sign-in and
  keeps working.
- The database role `wetechinetmon_app`, the ClickHouse tables and the
  API token prefix keep their names, so your data and tokens need
  nothing.
- **The collector's ClickHouse export** now refuses plain HTTP to
  anything but this host, and takes credentials only from
  `TIDEGARD_COLLECTOR_CLICKHOUSE_USER` and `_PASSWORD_FILE`, never
  the URL ([ADR 0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md)).
  A remote `http://` URL, or one with a password in it, now stops the
  collector at startup: set `https://`, `_CA_FILE` and the password file.
- **`TIDEGARD_COLLECTOR_ALLOWED_EXPORTERS`** is new. Set it to your
  routers ([ADR 0056](../architecture/decisions/0056-phase9d-collector-input-bounds.md)).
- Every service answers `/healthz` and `/readyz` on its metrics address.
- No database migration: v1.0.0 has the same 21 PostgreSQL migrations
  and the same ClickHouse tables as v0.9.0.
