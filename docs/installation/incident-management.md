# Installing Incident Management

Status: **Phase 5F**, 2026-10-05. This is a single-node installation built
from source. There are no packages or container images yet. Each step
below matches what CI builds and tests. The systemd units are examples
and do not ship in the repository.

## What you install

| Binary | Role | Listens on |
|---|---|---|
| `wetechinetmon-collector` | Receives flows, runs detection, writes detection events to the incident inbox | UDP `0.0.0.0:2055`; metrics `0.0.0.0:9090` |
| `wetechinetmon-incident-manager` | Turns detection events into incidents; runs the timers and retention; applies migrations | metrics `0.0.0.0:9091` |
| `wetechinetmon-api` | REST API, and the `token` command | `127.0.0.1:8080` |
| `wetechinetmonctl` | CLI for operators, through the API | — |

PostgreSQL holds all incident state. ClickHouse holds flow and detection
analytics for the collector, and is optional for incidents.

## Prerequisites

- Linux (x86-64). Windows builds and passes the tests, but it is not a
  documented deployment target.
- **PostgreSQL 15, 16, 17 or 18.** 17 is recommended, and CI tests all
  four ([ADR 0025](../architecture/decisions/0025-phase5b-postgresql-version-support.md)).
- A stable Rust toolchain, to build.
- The PostgreSQL server's CA certificate, if the database is on another
  host. TLS is required off loopback, and certificate verification
  cannot be turned off.

## 1. Build

```sh
git clone https://github.com/LogiXhare/wetechi-netmon.git
cd wetechi-netmon
cargo build --release --locked \
  -p wetechinetmon-collector -p wetechinetmon-incident-manager \
  -p wetechinetmon-api -p wetechinetmon-cli
sudo install -m 0755 target/release/wetechinetmon-collector \
  target/release/wetechinetmon-incident-manager \
  target/release/wetechinetmon-api target/release/wetechinetmonctl /usr/local/bin/
```

## 2. The database

Create a role and a database for the services. Use a strong password, and
keep it in a libpq password file (`~/.pgpass` of the service user),
never on a command line.

```sql
CREATE ROLE wetechinetmon LOGIN PASSWORD '<from your secret store>';
CREATE DATABASE wetechinetmon OWNER wetechinetmon;
```

Migrations need no manual step. The incident manager applies them on
startup, under an advisory lock. Migration `V11` also creates the role
`wetechinetmon_app`, without a password, ready for row-level security in
Phase 8. Nothing logs in as that role yet.

## 3. Configuration

Each service reads environment variables. Put them in a root-owned file
that only the service user can read, for example
`/etc/wetechinetmon/incident.env`, mode `0640`.

```sh
# The same database for all three. On another host, add the CA file.
WETECHINETMON_INCIDENT_DATABASE_URL="host=db.example.net user=wetechinetmon dbname=wetechinetmon sslmode=require"
WETECHINETMON_INCIDENT_DATABASE_CA_FILE=/etc/wetechinetmon/db-ca.pem
WETECHINETMON_API_DATABASE_URL="host=db.example.net user=wetechinetmon dbname=wetechinetmon sslmode=require"
WETECHINETMON_API_DATABASE_CA_FILE=/etc/wetechinetmon/db-ca.pem
WETECHINETMON_COLLECTOR_INCIDENT_DATABASE_URL="host=db.example.net user=wetechinetmon dbname=wetechinetmon sslmode=require"
WETECHINETMON_COLLECTOR_INCIDENT_DATABASE_CA_FILE=/etc/wetechinetmon/db-ca.pem
# Detection, and so incidents, is off without a policy file.
WETECHINETMON_COLLECTOR_DETECTION_POLICY_FILE=/etc/wetechinetmon/policies.json
```

The full list of settings is in each service's README:

- [collector](https://github.com/LogiXhare/wetechi-netmon/tree/main/crates/collector)
- [incident manager](https://github.com/LogiXhare/wetechi-netmon/tree/main/crates/incident-manager)
- [API](https://github.com/LogiXhare/wetechi-netmon/tree/main/apps/api)

Detection policies are described in
[Detection Policies](../configuration/detection-policies.md).

The connection string is never logged. CA bundles, keys and the
environment file are secrets you manage, and they never go into Git.

## 4. Start the services

Start them in this order:

1. The incident manager, which creates the schema.
2. The API.
3. The collector.

An example unit for the incident manager:

```ini
# /etc/systemd/system/wetechinetmon-incident-manager.service
[Unit]
Description=WetechiNetMon incident manager
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=wetechinetmon
EnvironmentFile=/etc/wetechinetmon/incident.env
ExecStart=/usr/local/bin/wetechinetmon-incident-manager
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The API and the collector use the same shape, with their own `ExecStart`.
The incident manager exits non-zero if it cannot reach or migrate the
database. `Restart=on-failure` then retries it.

The API binds to loopback by default, where plaintext is allowed, for a
reverse proxy on the same host. To serve it directly on another address,
set `WETECHINETMON_API_BIND` together with `WETECHINETMON_API_TLS_CERT_FILE`
and `WETECHINETMON_API_TLS_KEY_FILE`. The API refuses to start without
TLS on any address other than loopback.

## 5. Tokens and the CLI

Issue a token per person, with the least role they need:

- `viewer`
- `operator`
- `senior_operator`
- `noc_lead`

```sh
wetechinetmon-api token create --tenant acme --actor-id alice --role operator \
  --days 90 --description "alice laptop"
```

The token is printed once. Give it to Alice over a secure channel. She
keeps it in `WETECHINETMON_API_TOKEN` or in her CLI profile. It never goes
on a command line.

Alice then configures the CLI, as the
[CLI README](https://github.com/LogiXhare/wetechi-netmon/tree/main/apps/cli)
describes, and checks it:

```sh
wetechinetmonctl incidents list
```

## 6. Check the installation

- `curl -fsS http://127.0.0.1:8080/readyz` answers `200` once the API
  reaches the database.
- `curl -fsS http://127.0.0.1:9091/metrics | grep wetechinetmon_incident_inbox_pending`
  shows the incident manager's gauges.
- Add the [suggested alerts](../operations/incident-runbook.md#health).
- Schedule backups, and run one restore, as
  [Backup and Restore](../operations/backup-and-restore.md) describes,
  before you rely on the system.

## Upgrading

See [the runbook](../operations/incident-runbook.md#upgrades). The order
is backup, then the incident manager, then the API, then the collector.
