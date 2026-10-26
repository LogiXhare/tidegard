#!/usr/bin/env bash
# Installs Tidegard from an unpacked release tarball (ADR 0052).
#
#   sudo ./install.sh
#
# - Binaries and the web UI go to /opt/tidegard, replacing what is
#   there: this is also how to upgrade (take a backup first, see
#   docs/operations/backup-and-restore.md).
# - One system user per service, from share/sysusers.d.
# - Example settings go to /etc/tidegard, but only where no file
#   exists yet: an installed setting is never overwritten.
# - The units go to /etc/systemd/system. Nothing is enabled or started.
#
# Mitigation ships dry-run with BGP off (guard.json). Read
# docs/installation/mitigation.md before changing that.
set -euo pipefail

PREFIX=/opt/tidegard
CONFIG=/etc/tidegard
UNITS=/etc/systemd/system
SERVICES=(collector incident-manager api notifier mitigator)

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root" >&2
  exit 1
fi
for tool in systemctl systemd-sysusers install; do
  command -v "$tool" >/dev/null || { echo "install.sh needs $tool" >&2; exit 1; }
done

# Binaries and the UI. install(1) writes a new file and renames it, so a
# running service keeps its old binary until it restarts.
install -d -m 0755 "$PREFIX/bin" "$PREFIX/share"
for binary in "$here"/bin/*; do
  install -m 0755 "$binary" "$PREFIX/bin/"
done
rm -rf "$PREFIX/share/web.new"
cp -R "$here/share/web" "$PREFIX/share/web.new"
rm -rf "$PREFIX/share/web"
mv "$PREFIX/share/web.new" "$PREFIX/share/web"
chmod -R u=rwX,go=rX "$PREFIX/share/web"
install -m 0644 "$here/LICENSE" "$here/NOTICE" "$here/THIRD-PARTY-NOTICES.txt" \
  "$here/THIRD-PARTY-NOTICES-WEB.txt" "$PREFIX/"

# Users.
install -D -m 0644 "$here/share/sysusers.d/tidegard.conf" /etc/sysusers.d/tidegard.conf
systemd-sysusers /etc/sysusers.d/tidegard.conf

# Settings: copy an example only where nothing is installed yet.
# place <source> <target> <mode> <group>
place() {
  if [ -e "$2" ]; then
    echo "kept     $2"
  else
    install -m "$3" -o root -g "$4" "$1" "$2"
    echo "created  $2"
  fi
}
install -d -m 0755 "$CONFIG"
for service in "${SERVICES[@]}"; do
  place "$here/etc/$service.env" "$CONFIG/$service.env" 0600 root
done
place "$here/etc/detection-policy.json" "$CONFIG/detection-policy.json" 0640 tidegard-collector
place "$here/etc/guard.json" "$CONFIG/guard.json" 0640 tidegard-guard
place "$here/etc/mitigator.json" "$CONFIG/mitigator.json" 0640 tidegard-mitigator
place "$here/etc/notifier.json" "$CONFIG/notifier.json" 0640 tidegard-notifier

# Units.
for service in "${SERVICES[@]}"; do
  install -m 0644 "$here/share/systemd/tidegard-$service.service" "$UNITS/"
done
systemctl daemon-reload

cat <<EOF

Tidegard is installed in $PREFIX. Next:
  1. Create the PostgreSQL role and database (docs/installation/incident-management.md).
  2. Edit the settings in $CONFIG: every file with CHANGE_ME.
  3. systemctl enable --now tidegard-incident-manager   (applies the migrations)
  4. systemctl enable --now tidegard-api tidegard-collector
  5. Optionally tidegard-notifier and tidegard-mitigator.
Each service answers /healthz and /readyz on its metrics address; the API on its own.
EOF
