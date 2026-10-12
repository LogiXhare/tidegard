# Backup and Restore

Status: **Phase 9C**, 2026-10-13. This page covers both databases: the
incident database (PostgreSQL, since Phase 5F) and ClickHouse, which
holds flow and detection history ([below](#clickhouse-flow-and-detection-history)).

An untested restore is not a backup (NFR-2). CI therefore restores a real
backup on every pull request, as described below.

## Targets, not commitments

The [persistence plan](../architecture/phase5b-postgresql-persistence-plan.md)
sets two design targets:

- **RPO** of 15 minutes;
- **RTO** of 4 hours.

These targets size the procedure. They are **not** an SLA or a promise
to any customer.

Logical backups alone cannot meet a 15-minute RPO unless one is taken
every 15 minutes. To meet the target between dumps, add continuous WAL
archiving, described [below](#point-in-time-recovery).

## What to back up

| Item | How | Why |
|---|---|---|
| The incident database | `pg_dump --format=custom` | All incident state, history, audit, idempotency, outbox, and the migration history |
| ClickHouse's tables | `BACKUP TABLE ... TO File(...)`, [below](#clickhouse-flow-and-detection-history) | Flow and detection history for the dashboards and traffic pages |
| Cluster roles | `pg_dumpall --roles-only` | Migration `V11` grants to the role `wetechinetmon_app`. A restore into a new cluster needs that role to exist first |
| Configuration | Copy the services' environment (`WETECHINETMON_API_*` and the incident manager's) | It names the database and the TLS files |

Some of these files are secrets, so treat them that way:

- **The roles dump** holds password hashes.
- **The database dump** holds operator notes, audit entries and the API token table. The table stores only token hashes, but treat the dump as secret anyway.

Store all of them encrypted, off the database host, and with access
controlled. TLS keys and CA bundles are never committed to the
repository. Back them up wherever the rest of the host's secrets live.

## Taking a backup

Run the client tools at the server's major version or newer.

```sh
pg_dump --host=db.example.net --username=wetechinetmon_backup \
  --dbname=wetechinetmon --format=custom --no-owner \
  --file=wetechinetmon-$(date -u +%Y%m%dT%H%M%SZ).dump
pg_restore --list wetechinetmon-*.dump > /dev/null   # the archive is readable
pg_dumpall --host=db.example.net --username=postgres --roles-only \
  --file=wetechinetmon-roles.sql
```

`pg_dump` reads from a single snapshot, so the backup is consistent while
the API and the inbox worker keep running. There is no need to stop them.

Every connection to a database off loopback uses TLS with verification,
the same rule the API follows ([ADR 0023](../architecture/decisions/0023-phase5b-postgresql-tls.md)).
Set `PGSSLMODE=verify-full` and `PGSSLROOTCERT` to the server's CA. Never
lower the mode to get a backup through.

**Before every migration, take a backup.** That is, take one before
starting a new release whose migrations have not yet been applied.

## Restoring

1. Stop the API and the inbox worker, so nothing writes during the restore.
2. If this is a new cluster, restore the roles:
   `psql --file=wetechinetmon-roles.sql`.
3. Create an empty database and restore into it in one transaction. A
   failure then leaves nothing half-restored.

   ```sh
   createdb wetechinetmon_restored
   pg_restore --dbname=wetechinetmon_restored --no-owner \
     --exit-on-error --single-transaction wetechinetmon-20261005T020000Z.dump
   ```

4. Point the API's configuration at the restored database and start it.
   Migrations that are already applied do not run again: the migration
   history is part of the dump.
5. Verify, as described in the next section.

### What comes back, and what happens next

- **Incidents** come back at the versions they had in the backup.
  Commands a client sent after the backup was taken are lost. A client
  that retries one with its original `Idempotency-Key` gets it applied
  again, because the key's record was not in the backup either.
- **Idempotency records** in the backup still replay.
- **Outbox rows** that were `pending` or leased at backup time are
  claimable again, and their consumers deliver them. Delivery is
  at-least-once, so consumers must already tolerate duplicates.
- **Detection events** that arrived after the backup are gone, and the
  detector keeps no replayable copy
  ([ADR 0035](../architecture/decisions/0035-phase5c-detection-event-inbox.md)).
  - An attack still in progress shows up again with its next update.
  - An incident restored as open whose detection ended in the gap is
    handled by the staleness sweep, as for a lost `Ended` event.
  - A detection that started and ended inside the gap leaves no
    incident. Check the detector's logs and metrics for that window.
- **Incident numbering** continues from the restored allocator. A number
  issued after the backup could therefore be issued again to a different
  incident. Any ticket or message that quotes such a number must be
  rechecked.

## Verifying a restore

Check against incidents an operator knows, from tickets or chat:

```sh
wetechinetmonctl incidents list                 # the expected incidents are there
wetechinetmonctl incidents show <incident>      # one you know, at the version you expect
wetechinetmonctl incidents audit <incident>     # the audit trail reaches back as far as expected
```

## The drill CI runs

`scripts/postgres-backup-restore-drill.sh`
runs in the PostgreSQL job on 15, 16, 17 and 18, in five steps:

1. **Seed.** `drill_seed` fills a database through the service. It
   creates three tenants with incidents, links, an acknowledgement made
   with an idempotency key, notes, tags and a resolution, so every
   incident table has rows.
2. **Back up.** It takes a backup with `pg_dump --format=custom`, using the
   tools from the server's own image, and checks the archive with
   `pg_restore --list`.
3. **Restore.** It restores the backup into a fresh database with
   `--exit-on-error --single-transaction`.
4. **Compare.** It compares the two databases. For every table it checks
   the row count and an md5 over all rows in a stable order, and it also
   checks every sequence's position. Any difference fails the job.
5. **Prove it works.** `drill_verify` checks the restored copy:
   - the migration runner finds nothing to apply;
   - every incident reconstitutes, so its invariants hold;
   - the idempotent acknowledgement replays with its original answer;
   - a new command commits at the restored version;
   - a new detection episode reopens the resolved incident;
   - a new target takes the next incident number, and no number repeats;
   - the pending outbox rows are counted and claimable.

The drill only ever connects to CI's ephemeral database.

### What the drill does not cover yet

Each gap is tracked as FU-61:

- **Point-in-time recovery** from archived WAL.
- **Restoring across major versions**, for example a dump from 15
  restored into 17 as part of an upgrade.
- **Restoring into a separate cluster**, where the roles have to be
  restored first.

## ClickHouse (flow and detection history)

ClickHouse holds the traffic tables and the detection events. Losing it
loses history and dashboards, not incidents: those are in PostgreSQL.
Back it up with ClickHouse's own commands
([ADR 0055](../architecture/decisions/0055-phase9c-backup-upgrade-rollback.md)).

**Once, on the server:** allow a backup directory, and make it writable by
the `clickhouse` user.

```xml
<!-- /etc/clickhouse-server/config.d/backups.xml -->
<clickhouse>
  <backups>
    <allowed_path>/backups/</allowed_path>
  </backups>
</clickhouse>
```

**Taking a backup:** every WetechiNetMon table, into one archive.

```sql
BACKUP TABLE default.wetechinetmon_total_ipv4_traffic,
       TABLE default.wetechinetmon_total_ipv6_traffic,
       TABLE default.wetechinetmon_host_traffic,
       TABLE default.wetechinetmon_network_traffic,
       TABLE default.wetechinetmon_slash24_network_traffic,
       TABLE default.wetechinetmon_hostgroup_traffic,
       TABLE default.wetechinetmon_asn_traffic,
       TABLE default.wetechinetmon_exporter_traffic,
       TABLE default.wetechinetmon_interface_traffic,
       TABLE default.wetechinetmon_detection_events
TO File('wetechinetmon-2026-10-13.zip');
```

The server writes it while the collector keeps exporting. Copy the archive
off the host, encrypted, with the PostgreSQL backups.

**Restoring:** drop the tables that are there (or start from an empty
server), then run the same statement with `RESTORE ... FROM` in place of
`BACKUP ... TO`. Start the collector afterwards: it creates any table
that is missing, and writes to the restored ones.

Rows older than each table's retention (30 days for traffic, 365 for
detection events) expire again after a restore, as they would have.

**The drill CI runs.** `scripts/clickhouse-backup-restore-drill.sh`
runs in the Grafana job against a throwaway server. It fills every table,
fingerprints each one (row count and a hash of every row), backs them
up, drops them, restores them and requires identical fingerprints. Then
the collector's own writer writes and reads back every row type in the
restored copy.

## Point-in-time recovery

To come close to the 15-minute RPO, do two things:

- Archive WAL continuously, using `archive_mode = on` and an
  `archive_command`, or a tool such as pgBackRest or WAL-G.
- Take a base backup daily with `pg_basebackup`.

Recovery then replays WAL up to a chosen moment
(`recovery_target_time`). This is standard PostgreSQL, documented in its
*Continuous Archiving and Point-in-Time Recovery* chapter. WetechiNetMon
needs nothing extra for it. This path is not yet drilled (FU-61), so
test it on a staging copy before relying on it.
