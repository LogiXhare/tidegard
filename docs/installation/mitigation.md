# Installing BGP Mitigation

Status: **Phase 7F**, 2026-10-12. This guide adds the mitigator and its
`gobgpd` to an existing [incident management](incident-management.md)
installation. It is built from source, and the systemd units are
examples. Read the [RTBH guide](../operations/rtbh-guide.md) and the
[FlowSpec guide](../operations/flowspec-guide.md) first, and agree the
edge router side with whoever runs your routers.

**Nothing is announced until you say so.** A fresh install is in dry-run,
with BGP off and an empty allowlist. The last section turns it on in
stages.

## What you install

| Part | Role | Listens on |
|---|---|---|
| `wetechinetmon-mitigator` | Announces approved mitigations to GoBGP, withdraws ended ones, reconciles, records peers | metrics `127.0.0.1:9094` |
| `gobgpd` (GoBGP v4.9.0) | WetechiNetMon's BGP speaker, peered over iBGP with your edge routers | BGP on the address you choose; **gRPC on `127.0.0.1:50051` only** |
| The guard file | The allowlist and safety switches, shared by the API and the mitigator | — |

## 1. Build the mitigator

```sh
cargo build --release --locked -p wetechinetmon-mitigator
sudo install -m 0755 target/release/wetechinetmon-mitigator /usr/local/bin/
```

## 2. Install `gobgpd`

Use the release WetechiNetMon is tested with, and check its checksum. Both
are in `scripts/gobgp-version.sh`:

```sh
curl -fsSLo gobgp.tar.gz \
  https://github.com/osrg/gobgp/releases/download/v4.9.0/gobgp_4.9.0_linux_amd64.tar.gz
echo "653f52cd11614cff847c9a70dd800b1d2746e61d5796744f591388db7084a038  gobgp.tar.gz" | sha256sum -c -
tar -xzf gobgp.tar.gz gobgpd gobgp
sudo install -m 0755 gobgpd gobgp /usr/local/bin/
```

Configure it to peer with your edge routers over iBGP, in the families
you will use. For example, with documentation addresses:

```toml
# /etc/wetechinetmon/gobgpd.toml
[global.config]
  as = 65001                      # your AS
  router-id = "192.0.2.10"
  local-address-list = ["192.0.2.10"]

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.1"   # an edge router
    peer-as = 65001
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-unicast"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-unicast"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-flowspec"
```

**Start it with its gRPC API on loopback.** `gobgpd`'s default is every
interface, and its API has no authentication: anyone who reaches it can
inject routes (T-46).

```ini
# /etc/systemd/system/gobgpd.service
[Unit]
Description=GoBGP for WetechiNetMon
After=network-online.target
Wants=network-online.target

[Service]
User=gobgpd
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/gobgpd -f /etc/wetechinetmon/gobgpd.toml --api-hosts 127.0.0.1:50051 --pprof-disable
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

To run the mitigator on another host, start `gobgpd` with TLS for its
API, using `--tls`, `--tls-cert-file`, `--tls-key-file` and, to accept only
the mitigator, `--tls-client-ca-file`. Then give the mitigator an
`https://` URL with a `ca_file`, and optionally `client_cert_file` and
`client_key_file`. The mitigator refuses plain HTTP to anything but
loopback.

## 3. The guard file

One file, read by both the API and the mitigator
([ADR 0047](../architecture/decisions/0047-phase7b-safety-guard.md)). Start
with nothing announced:

```json
{
  "dry_run": true,
  "bgp_enabled": false,
  "max_duration_seconds": 3600,
  "approval_window_seconds": 900,
  "allow_self_approval": false,
  "allowlist": [
    { "prefix": "203.0.113.0/24", "tenant": "acme", "actions": ["rtbh", "flowspec_discard", "flowspec_rate_limit"] },
    { "prefix": "198.51.100.0/24", "tenant": "acme", "actions": ["rtbh", "parent_prefix"] }
  ]
}
```

- List only your own space, each prefix with the one tenant it belongs
  to and the actions allowed on it. Entries of different tenants may not
  overlap.
- Nothing shorter than `min_length` is accepted: /24 for IPv4 and /48
  for IPv6 by default. It may be lowered to /16 and /32, never further,
  and a lower value stops the service at start.
- `"kill_switch": true` here stops everything, and survives a database
  restore.

Keep it readable by the API's and the mitigator's users, and writable by
neither.

## 4. The mitigator's configuration

```json
{
  "guard_file": "/etc/wetechinetmon/guard.json",
  "routes": {
    "local_asn": 65001,
    "rtbh_next_hop_ipv4": "192.0.2.66",
    "rtbh_next_hop_ipv6": "2001:db8::66",
    "communities": ["65535:666"],
    "no_export": true
  },
  "gobgp": { "url": "http://127.0.0.1:50051" },
  "proposals": { "enabled": false },
  "poll_interval_ms": 2000,
  "reconcile_interval_seconds": 60
}
```

- `rtbh_next_hop_*` are the addresses your edge routers route to a
  discard interface (see the [RTBH guide](../operations/rtbh-guide.md)).
- `proposals.enabled` lets the mitigator propose an RTBH for new
  critical incoming incidents on a host. A proposal still needs a NOC
  lead's approval.

```sh
# /etc/wetechinetmon/mitigator.env
WETECHINETMON_MITIGATOR_DATABASE_URL=host=127.0.0.1 user=wetechinetmon dbname=incidents
WETECHINETMON_MITIGATOR_CONFIG=/etc/wetechinetmon/mitigator.json
# WETECHINETMON_MITIGATOR_DATABASE_CA_FILE=/etc/wetechinetmon/pg-ca.pem   (database on another host)
# WETECHINETMON_MITIGATOR_METRICS_BIND=127.0.0.1:9094
```

Use the incident manager's unit shape, with
`ExecStart=/usr/local/bin/wetechinetmon-mitigator`,
`EnvironmentFile=/etc/wetechinetmon/mitigator.env` and
`After=gobgpd.service`. Run one per installation. A second one waits as a
standby and takes over if the first stops.

## 5. The API

Point the API at the same guard file, and restart it:

```sh
WETECHINETMON_API_MITIGATION_GUARD_FILE=/etc/wetechinetmon/guard.json
```

Without it, the API refuses every mitigation request: nothing is
allowlisted. Add mitigation events to the notifier's routes, as its
README shows. Send at least `mitigation.requested`, `mitigation.failed`,
`mitigation.kill_switch_engaged` and, under the tenant `platform`,
`bgp.peer_down`.

## 6. Turn it on, in stages

Each stage needs a restart of the API and the mitigator after you edit
the guard file.

1. **BGP off** (as installed). Request and approve a mitigation for a
   test address in your space. It goes `active` marked dry-run, and
   nothing connects to GoBGP. This proves the people, the permissions
   and the notifications.
2. **BGP on, dry-run on** (`"bgp_enabled": true`). The mitigator connects
   to `gobgpd` and records its peers: `wetechinetmonctl bgp peers` shows
   each edge router `established`. Still nothing is announced.
3. **Dry-run off** (`"dry_run": false`), in a maintenance window. Request
   an RTBH for a test address that carries no traffic, approve it, and
   check each edge router: the route is there with `BLACKHOLE` and
   `NO_EXPORT`, and traffic to it is dropped. Withdraw it and see it go.
   Repeat with a FlowSpec rule if you use FlowSpec.

## 7. Check the installation

- `curl -fsS http://127.0.0.1:9094/readyz` answers `200` on the active
  mitigator once a pass succeeds. A standby answers `503`.
- `curl -fsS http://127.0.0.1:9094/metrics | grep wetechinetmon_mitigator`
  shows the mitigator's gauges.
- `wetechinetmonctl kill-switch status` says `released`.
- `wetechinetmonctl bgp peers` lists every edge router, `established`,
  seen within the last minute.
- `ss -ltn | grep 50051` shows `127.0.0.1:50051` and nothing else.
- Add the [alerts](../operations/mitigation-runbook.md#alerts).

## Upgrading

Upgrade the API and the mitigator together. A migration may add to the
mitigation tables, and the incident manager applies it first, as usual.
Upgrade `gobgpd` only to a release WetechiNetMon has been tested with
(`scripts/gobgp-version.sh`).
