#!/usr/bin/env bash
# Builds the release tarball for this machine's architecture (ADR 0052):
#
#   scripts/package.sh <version> [output directory, default dist]
#
# Linux only: x86_64 or aarch64, built natively. CI builds on Ubuntu
# 22.04 so the binaries need nothing newer than glibc 2.35. Needs cargo,
# npm and cargo-about 0.9.2 (on PATH, or named by CARGO_ABOUT), which
# writes the third-party licence notices (FU-53). Writes
# wetechinetmon-<version>-linux-<arch>.tar.gz.
set -euo pipefail

version=${1:?usage: scripts/package.sh <version> [output directory]}
out=${2:-dist}
case "$version" in
  *[!0-9A-Za-z.+-]*) echo "the version may hold only letters, digits and . + -" >&2; exit 1 ;;
esac

about=${CARGO_ABOUT:-cargo-about}
command -v "$about" >/dev/null || { echo "cargo-about is needed for the licence notices (FU-53)" >&2; exit 1; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target=${CARGO_TARGET_DIR:-$root/target}
arch=$(uname -m)
case "$arch" in
  x86_64 | aarch64) ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
name="wetechinetmon-$version-linux-$arch"

packages=(
  wetechinetmon-collector
  wetechinetmon-incident-manager
  wetechinetmon-api
  wetechinetmon-notification
  wetechinetmon-mitigator
  wetechinetmon-cli
)
binaries=(
  wetechinetmon-collector
  wetechinetmon-incident-manager
  wetechinetmon-api
  wetechinetmon-notifier
  wetechinetmon-mitigator
  wetechinetmonctl
)

cd "$root"
cargo build --release --locked "${packages[@]/#/-p}"
(cd apps/web && npm ci --ignore-scripts && npm run build)

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
dir="$stage/$name"
mkdir -p "$dir/bin" "$dir/etc" "$dir/share/systemd" "$dir/share/sysusers.d"

for binary in "${binaries[@]}"; do
  install -m 0755 "$target/release/$binary" "$dir/bin/"
done
cp -R apps/web/dist "$dir/share/web"
install -m 0644 deployments/systemd/units/*.service "$dir/share/systemd/"
install -m 0644 deployments/systemd/wetechinetmon.sysusers "$dir/share/sysusers.d/wetechinetmon.conf"
install -m 0644 deployments/systemd/env/*.env deployments/config/*.json "$dir/etc/"
install -m 0755 deployments/systemd/install.sh "$dir/"
install -m 0644 LICENSE NOTICE CHANGELOG.md "$dir/"
# Every third-party licence the binaries and the UI carry, with its
# text, as MIT, BSD and Apache-2.0 require of a binary distribution.
"$about" generate --frozen --fail --all-features --workspace about.hbs \
  -o "$dir/THIRD-PARTY-NOTICES.txt"
node scripts/web-licenses.mjs apps/web > "$dir/THIRD-PARTY-NOTICES-WEB.txt"
printf '%s\n' "$version" > "$dir/VERSION"

mkdir -p "$out"
# Owned by root, sorted and dated by the commit, so nothing about the
# build machine or its clock ends up in the archive's metadata.
epoch=$(git log -1 --format=%ct)
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  -C "$stage" -cf - "$name" | gzip -n -9 > "$out/$name.tar.gz"
echo "$out/$name.tar.gz"
