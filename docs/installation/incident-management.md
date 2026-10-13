# Installing Incident Management

Status: **Phase 6**, 2026-10-12. This is a single-node installation built
from source. There are no packages or container images yet. Each step
below matches what CI builds and tests. The systemd units are examples
and do not ship in the repository.

## What you install

| Binary | Role | Listens on |
|---|---|---|
| `tidegard-collector` | Receives flows, runs detection, writes detection events to the incident inbox | UDP `0.0.0.0:2055`; metrics `0.0.0.0:9090` |
| `tidegard-incident-manager` | Turns detection events into incidents; runs the timers and retention; applies migrations | metrics `0.0.0.0:9091` |
| `tidegard-api` | REST API, and the `token` command | `127.0.0.1:8080` |
| `tidegardctl` | CLI for operators, through the API | — |
| `tidegard-notifier` | Delivers notifications from the outbox | metrics `127.0.0.1:9093` |
| NOC UI (`apps/web/dist`) | The browser UI, served by the API | through the API |

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
git clone https://github.com/LogiXhare/tidegard.git
cd tidegard
cargo build --release --locked \
  -p tidegard-collector -p tidegard-incident-manager \
  -p tidegard-api -p tidegard-cli -p tidegard-notification
sudo install -m 0755 target/release/tidegard-collector \
  target/release/tidegard-incident-manager \
  target/release/tidegard-api target/release/tidegardctl \
  target/release/tidegard-notifier /usr/local/bin/
```

The UI needs Node.js 22.12 or later, at build time only:

```sh
cd apps/web
npm ci --ignore-scripts
npm run build
sudo mkdir -p /usr/local/share/tidegard
sudo cp -r dist /usr/local/share/tidegard/web
```

## 2. The database

Create a role and a database for the services. Use a strong password, and
keep it in a libpq password file (`~/.pgpass` of the service user),
never on a command line.

```sql
CREATE ROLE tidegard LOGIN PASSWORD '<from your secret store>';
CREATE DATABASE tidegard OWNER tidegard;
```

Migrations need no manual step. The incident manager applies them on
startup, under an advisory lock. Migration `V11` also creates the role
`wetechinetmon_app`, without a password, ready for row-level security in
Phase 8. Nothing logs in as that role yet.

## 3. Configuration

Each service reads environment variables. Put them in a root-owned file
that only the service user can read, for example
`/etc/tidegard/incident.env`, mode `0640`.

```sh
# The same database for all three. On another host, add the CA file.
TIDEGARD_INCIDENT_DATABASE_URL="host=db.example.net user=tidegard dbname=tidegard sslmode=require"
TIDEGARD_INCIDENT_DATABASE_CA_FILE=/etc/tidegard/db-ca.pem
TIDEGARD_API_DATABASE_URL="host=db.example.net user=tidegard dbname=tidegard sslmode=require"
TIDEGARD_API_DATABASE_CA_FILE=/etc/tidegard/db-ca.pem
TIDEGARD_COLLECTOR_INCIDENT_DATABASE_URL="host=db.example.net user=tidegard dbname=tidegard sslmode=require"
TIDEGARD_COLLECTOR_INCIDENT_DATABASE_CA_FILE=/etc/tidegard/db-ca.pem
# Detection, and so incidents, is off without a policy file.
TIDEGARD_COLLECTOR_DETECTION_POLICY_FILE=/etc/tidegard/policies.json
```

The full list of settings is in each service's README:

- [collector](https://github.com/LogiXhare/tidegard/tree/main/crates/collector)
- [incident manager](https://github.com/LogiXhare/tidegard/tree/main/crates/incident-manager)
- [API](https://github.com/LogiXhare/tidegard/tree/main/apps/api)

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
# /etc/systemd/system/tidegard-incident-manager.service
[Unit]
Description=Tidegard incident manager
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=tidegard
EnvironmentFile=/etc/tidegard/incident.env
ExecStart=/usr/local/bin/tidegard-incident-manager
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
set `TIDEGARD_API_BIND` together with `TIDEGARD_API_TLS_CERT_FILE`
and `TIDEGARD_API_TLS_KEY_FILE`. The API refuses to start without
TLS on any address other than loopback.

## 5. Tokens and the CLI

Issue a token per person, with the least role they need:

- `viewer`
- `operator`
- `senior_operator`
- `noc_lead`

```sh
tidegard-api token create --tenant acme --actor-id alice --role operator \
  --days 90 --description "alice laptop"
```

The token is printed once. Give it to Alice over a secure channel. She
keeps it in `TIDEGARD_API_TOKEN` or in her CLI profile. It never goes
on a command line.

Alice then configures the CLI, as the
[CLI README](https://github.com/LogiXhare/tidegard/tree/main/apps/cli)
describes, and checks it:

```sh
tidegardctl incidents list
```

## 6. The NOC UI

Point the API at the build, and restart it:

```sh
TIDEGARD_API_WEB_ROOT=/usr/local/share/tidegard/web
```

Open the API's address in a browser and sign in with a token. Off
loopback the API serves TLS, so the session cookie is `Secure`.

To show traffic in the UI, name the one tenant allowed to see it, and
give the API a ClickHouse user that can only `SELECT`
([ADR 0042](../architecture/decisions/0042-phase6b-traffic-read-api.md)):

```sh
TIDEGARD_API_TRAFFIC_TENANT=acme
TIDEGARD_API_CLICKHOUSE_URL=https://clickhouse.example.net:8443
TIDEGARD_API_CLICKHOUSE_USER=wnm_reader
TIDEGARD_API_CLICKHOUSE_PASSWORD_FILE=/etc/tidegard/clickhouse-password
TIDEGARD_API_CLICKHOUSE_CA_FILE=/etc/tidegard/clickhouse-ca.pem
```

## 7. Notifications

Write the channels-and-routes file and the secret files it names, as the
[notifier README](https://github.com/LogiXhare/tidegard/tree/main/crates/notification)
shows, then run the notifier after the incident manager:

```sh
TIDEGARD_NOTIFY_DATABASE_URL="host=127.0.0.1 user=tidegard dbname=incidents" \
TIDEGARD_NOTIFY_CONFIG=/etc/tidegard/notify.json \
tidegard-notifier
```

Run one notifier per installation, or give each its own
`TIDEGARD_NOTIFY_CONSUMER_ID`. Open an incident by hand
(`tidegardctl incidents open ...`) and check its timeline for a
`notification_result` entry per channel.

## 8. Grafana

Grafana is yours to run; Tidegard ships dashboards, not Grafana
([ADR 0041](../architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)).
Install the `grafana-clickhouse-datasource` plugin, copy
`grafana/provisioning` into Grafana's provisioning directory and
`grafana/dashboards` to `/var/lib/grafana/dashboards/tidegard`, set
the variables the
[provisioning README](https://github.com/LogiXhare/tidegard/tree/main/grafana/provisioning)
lists, and restart Grafana.

## 9. Check the installation

- `curl -fsS http://127.0.0.1:8080/readyz` answers `200` once the API
  reaches the database.
- `curl -fsS http://127.0.0.1:9091/readyz` answers `200` once the
  incident manager's first correlation batch succeeds, so after the
  migrations. Every service except the API answers `/healthz` and
  `/readyz` on its metrics address
  ([ADR 0052](../architecture/decisions/0052-phase9a-packaging.md)).
- `curl -fsS http://127.0.0.1:9091/metrics | grep tidegard_incident_inbox_pending`
  shows the incident manager's gauges.
- `curl -fsS http://127.0.0.1:9093/metrics` answers once the notifier
  runs; its counters appear after the first message.
- Add the [suggested alerts](../operations/incident-runbook.md#health).
- Schedule backups, and run one restore, as
  [Backup and Restore](../operations/backup-and-restore.md) describes,
  before you rely on the system.

## Upgrading

See [the runbook](../operations/incident-runbook.md#upgrades). The order
is backup, then the incident manager, then the API (with the new UI
build), then the notifier, then the collector.
