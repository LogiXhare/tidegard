# Quick Start

Status: **Phase 10B**, 2026-10-13.

Tidegard on one Linux host with Docker, from a release, in about
fifteen minutes: PostgreSQL, ClickHouse and the five services, with TLS
between every container and mitigation in dry-run. For a production
install from the tarball instead, see [Installation](installation/index.md).

## You need

- Linux, x86_64 or aarch64, with Docker Engine and the Compose plugin;
- 4 cores, 8 GiB of memory and 50 GiB of disk to start;
- a router that can export IPFIX to this host, or none, to look around.

## 1. Get the release

```bash
version=1.0.0
curl -fsSLO "https://github.com/LogiXhare/tidegard/archive/refs/tags/v$version.tar.gz"
tar -xzf "v$version.tar.gz"
cd "tidegard-$version/deployments/docker-compose"
```

The images it runs are signed: [verify them](operations/verifying-a-release.md)
before production use.

## 2. Configure and start

```bash
sudo ./setup.sh "$version"         # the CA, every key and password, and .env
```

Tell it your address space and your routers, in `.env`:

```bash
TIDEGARD_LOCAL_PREFIXES=192.0.2.0/24@default
TIDEGARD_ALLOWED_EXPORTERS=198.51.100.1,198.51.100.2
```

Then:

```bash
docker compose up -d
docker compose ps                  # every service healthy
```

## 3. Sign in

```bash
docker compose exec -T api tidegard-api token create \
  --tenant default --actor-id you --role noc_lead --days 30
```

Open `https://127.0.0.1:8443/`, trust `tls/ca.pem` in your browser, and
sign in with the token.

## 4. Send flows

Point your router's IPFIX exporter at this host, UDP port 2055. Within a
minute the traffic pages show your busiest hosts, and
`curl -s http://127.0.0.1:9090/metrics | grep parsed_flow_records_total`
counts what arrived.

## 5. Your first detection

`../config/detection-policy.json` opens a `major` incident when one host
receives more than 1 Gbit/s for 30 seconds. Set its prefixes to yours,
lower the threshold for a test, and restart the collector:

```bash
docker compose restart collector
```

An incident appears on the UI's incident list.
Nothing is ever mitigated on its own: mitigation needs a request, an
approval, and turning off dry-run, as the
[mitigation installation guide](installation/mitigation.md) describes.

## Next

- [Customer onboarding](operations/customer-onboarding.md): prefixes,
  routers, policies, alerts and people, step by step.
- [Detection policies](configuration/detection-policies.md) and
  [notifications](https://github.com/LogiXhare/tidegard/blob/main/crates/notification/README.md).
- [Backup and restore](operations/backup-and-restore.md), before anything
  you would miss is in it.
