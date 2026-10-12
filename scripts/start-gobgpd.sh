#!/usr/bin/env bash
# Starts a throwaway gobgpd for the mitigator's tests (ADR 0048, ADR 0049).
#
# GoBGP is pinned by version and SHA-256. Its gRPC API listens on loopback
# only, and its BGP port is closed (port = -1), so no route can leave the
# machine. The log is left in $GOBGP_WORK_DIR/gobgpd.log.
#
# Linux amd64 only: CI's runner. Locally, run gobgpd yourself and set
# WETECHINETMON_GOBGP_TEST_ENDPOINT.
set -euo pipefail

GOBGP_VERSION="4.9.0"
GOBGP_SHA256="653f52cd11614cff847c9a70dd800b1d2746e61d5796744f591388db7084a038"
WORK_DIR="${GOBGP_WORK_DIR:-${RUNNER_TEMP:-/tmp}/gobgp}"
API="127.0.0.1:50051"

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
curl -fsSLo gobgp.tar.gz \
  "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz"
echo "${GOBGP_SHA256}  gobgp.tar.gz" | sha256sum -c -
tar -xzf gobgp.tar.gz gobgpd
cat > gobgpd.toml <<'EOF'
[global.config]
  as = 65001
  router-id = "192.0.2.254"
  port = -1
EOF
nohup ./gobgpd -f gobgpd.toml --api-hosts "$API" --pprof-disable --log-plain > gobgpd.log 2>&1 &
for _ in $(seq 1 30); do
  if (exec 3<>"/dev/tcp/${API%:*}/${API#*:}") 2>/dev/null; then
    echo "gobgpd ${GOBGP_VERSION} is listening on ${API}"
    exit 0
  fi
  sleep 1
done
cat gobgpd.log
exit 1
