# Docker Compose Reference Stack

**Status:** Implemented in Phase 9A-3
([ADR 0052](../../docs/architecture/decisions/0052-phase9a-packaging.md)).

One host, one command: PostgreSQL, ClickHouse and the five WetechiNetMon
services, from the release images. CI starts this stack from the images
it has just built, sends synthetic flows, and checks that an incident
opens.

| Container | Published on the host |
|---|---|
| `api` | `127.0.0.1:8443` (HTTPS); change `WETECHINETMON_API_PUBLISH` to reach it from elsewhere |
| `collector` | UDP `2055` on every interface, for your exporters; metrics on `127.0.0.1:9090` |
| `incident-manager`, `notifier`, `mitigator` | Metrics, `/healthz` and `/readyz` on `127.0.0.1:9091`, `9093` and `9094` |
| `postgres`, `clickhouse` | Nothing |

## Safety

- **Every connection between containers uses TLS**, verified against a
  CA made for this stack by `setup.sh`. ClickHouse has no plaintext
  listener at all, and PostgreSQL connections require TLS.
- **Mitigation is dry-run with BGP off** (`../config/guard.json`), and
  `gobgpd` is not part of the stack. GoBGP's API has no authentication,
  so BGP runs from the tarball, beside `gobgpd` on loopback: see the
  [mitigation installation guide](../../docs/installation/mitigation.md).
- Every WetechiNetMon container runs as a non-root user, with a read-only
  root filesystem, no capabilities and `no-new-privileges`.

## Starting

```bash
cd deployments/docker-compose
sudo ./setup.sh <version>           # once: tls/, secrets/ and .env
docker compose up -d
docker compose ps                   # every service healthy or running
```

`setup.sh` needs root to give each key to the user its container runs as.
It never overwrites a file, so running it again is safe. To serve the
API under a host name, set `WETECHINETMON_API_HOSTNAME` before the first
run so the certificate includes it.

Then:

```bash
# The CA to trust when calling the API.
curl --cacert tls/ca.pem https://127.0.0.1:8443/readyz

# A first token, issued by the API binary inside its container.
docker compose exec -T api wetechinetmon-api token create \
  --tenant default --actor-id alice --role noc_lead --days 30
```

Open `https://127.0.0.1:8443/` and sign in with the token. Your browser
needs `tls/ca.pem` trusted, or a certificate from your own CA in its
place.

## Settings

Put these in `.env` next to the ones `setup.sh` wrote:

| Variable | Default | Meaning |
|---|---|---|
| `WETECHINETMON_VERSION` | set by `setup.sh` | The image tag |
| `WETECHINETMON_IMAGE_PREFIX` | `ghcr.io/logixhare/wetechinetmon-` | Where the images come from |
| `WETECHINETMON_LOCAL_PREFIXES` | `192.0.2.0/24@default` | Your own prefixes, as for the collector |
| `WETECHINETMON_DETECTION_POLICY` | `../config/detection-policy.json` | The detection policy file |
| `WETECHINETMON_DETECTION_WINDOW_SECS` | `5` | The detection window; must equal every policy's `window`, or that policy is never evaluated |
| `WETECHINETMON_NOTIFIER_CONFIG` | `../config/notifier.json` | The notifier's channels and routes |
| `WETECHINETMON_TRAFFIC_TENANT` | `default` | The tenant traffic pages show |
| `WETECHINETMON_API_PUBLISH` | `127.0.0.1:8443` | Where the API is published |
| `WETECHINETMON_FLOW_PUBLISH` | `2055` | Where the collector's UDP port is published |
| `WETECHINETMON_ALLOWED_EXPORTERS` | empty: any source | Your routers' addresses or networks, comma-separated; flows from anywhere else are dropped unread ([ADR 0056](../../docs/architecture/decisions/0056-phase9d-collector-input-bounds.md)). Docker's default NAT keeps a published UDP packet's source address; check `datagrams_refused_total` once it is set |

## Upgrading and backups

Back up first ([Backup and Restore](../../docs/operations/backup-and-restore.md)):
the data lives in the `postgres` and `clickhouse` volumes. Then change
`WETECHINETMON_VERSION` in `.env` and run `docker compose up -d`. The
incident manager applies new migrations when it starts.

`tls/`, `secrets/` and `.env` hold this host's keys and passwords. They
are in `.gitignore`; keep them out of any repository and back them up
with the host's other secrets.
