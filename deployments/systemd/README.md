# Bare-Metal systemd Deployment

**Status:** Implemented in Phase 9A-2
([ADR 0052](../../docs/architecture/decisions/0052-phase9a-packaging.md)).

The release tarball installs Tidegard on Ubuntu 22.04 or 24.04, or
Debian 12 or 13, as five systemd services. `scripts/package.sh` builds
the tarball from this directory and
[`../config`](../config), and CI installs every build with `install.sh`
and starts every service. Building it needs cargo, npm and
[cargo-about](https://github.com/EmbarkStudios/cargo-about) 0.9.2, which
writes the third-party licence notices the tarball ships.

| File | Installed as |
|---|---|
| `units/tidegard-*.service` | `/etc/systemd/system/` |
| `tidegard.sysusers` | `/etc/sysusers.d/tidegard.conf`: one system user per service, and the `tidegard-guard` group the API and the mitigator share |
| `env/*.env` | `/etc/tidegard/`, mode `0600`, root only: systemd reads them before dropping privileges |
| `../config/*.json` | `/etc/tidegard/`, mode `0640`, readable by the service that uses each |
| `install.sh` | Run from the unpacked tarball |

## Installing

```bash
tar -xzf tidegard-<version>-linux-$(uname -m).tar.gz
sudo ./tidegard-<version>-linux-$(uname -m)/install.sh
```

`install.sh` puts the binaries and the web UI in `/opt/tidegard`,
creates the users, copies each example setting only where none exists,
and installs the units. It enables and starts nothing. Then:

1. Create the PostgreSQL role and database, as the
   [installation guide](../../docs/installation/incident-management.md)
   describes.
2. Replace every `CHANGE_ME` in `/etc/tidegard/*.env`. Off this
   host, set the CA file too: plaintext reaches loopback only.
3. `systemctl enable --now tidegard-incident-manager`, which applies
   the migrations.
4. `systemctl enable --now tidegard-api tidegard-collector`.
5. The notifier and the mitigator when you need them. The mitigator ships
   dry-run with BGP off: read the
   [mitigation installation guide](../../docs/installation/mitigation.md)
   first.

Every service answers `/healthz` and `/readyz`: the API on its own
address, the others on their metrics address.

## Upgrading

Take a backup ([Backup and Restore](../../docs/operations/backup-and-restore.md)),
unpack the new tarball and run its `install.sh`. It replaces the
binaries, the web UI and the units, and keeps every setting. Then restart
the incident manager first, since it applies any new migrations, and the
other services after it.

## Hardening

Each unit runs as its own unprivileged user with no capabilities, a
read-only view of the system (`ProtectSystem=strict`), private `/tmp` and
devices, the `@system-service` system call set without `@privileged`
and `@resources`, and IPv4, IPv6 and Unix sockets only. CI prints
`systemd-analyze security` for each unit.
