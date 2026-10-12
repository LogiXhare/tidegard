#!/usr/bin/env bash
# Starts the two-speaker BGP lab (Phase 7F, ADR 0051): WetechiNetMon's
# speaker and a second gobgpd standing in for the edge router, peered over
# iBGP on loopback, as an RTBH trigger router peers with its edge routers.
#
#   speaker  AS 65001, BGP on 127.0.0.1:10179, gRPC API on 127.0.0.1:50061
#   edge     AS 65001, BGP on 127.0.0.2:10179, gRPC API on 127.0.0.1:50062
#
# Both listen on loopback only and peer only with each other, so no route
# can leave the machine. GoBGP is pinned by version and SHA-256 (see
# scripts/gobgp-version.sh). The logs are left in $GOBGP_LAB_DIR.
#
# Linux amd64 only: CI's runner. Separate from scripts/start-gobgpd.sh,
# whose single gobgpd has its BGP port closed and no peers.
set -euo pipefail

# shellcheck source=scripts/gobgp-version.sh
source "$(dirname "$0")/gobgp-version.sh"
LAB_DIR="${GOBGP_LAB_DIR:-${RUNNER_TEMP:-/tmp}/gobgp-lab}"
fetch_gobgpd "$LAB_DIR"
cd "$LAB_DIR"

# One speaker's configuration: $1 name, $2 router id, $3 own address,
# $4 the peer's address.
speaker() {
  cat > "$1.toml" <<EOF
[global.config]
  as = 65001
  router-id = "$2"
  port = 10179
  local-address-list = ["$3"]

[[neighbors]]
  [neighbors.config]
    neighbor-address = "$4"
    peer-as = 65001
  [neighbors.transport.config]
    local-address = "$3"
    remote-port = 10179
  [neighbors.timers.config]
    connect-retry = 1
    hold-time = 9
    keepalive-interval = 3
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
EOF
}

speaker speaker 192.0.2.252 127.0.0.1 127.0.0.2
speaker edge 192.0.2.253 127.0.0.2 127.0.0.1
nohup ./gobgpd -f speaker.toml --api-hosts 127.0.0.1:50061 --pprof-disable --log-plain \
  > speaker.log 2>&1 &
nohup ./gobgpd -f edge.toml --api-hosts 127.0.0.1:50062 --pprof-disable --log-plain \
  > edge.log 2>&1 &

for api in 127.0.0.1:50061 127.0.0.1:50062; do
  for _ in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/${api%:*}/${api#*:}") 2>/dev/null; then
      echo "gobgpd ${GOBGP_VERSION} is listening on ${api}"
      continue 2
    fi
    sleep 1
  done
  cat speaker.log edge.log
  exit 1
done
