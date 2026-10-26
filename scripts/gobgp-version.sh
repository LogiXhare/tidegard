#!/usr/bin/env bash
# The GoBGP release the labs use, pinned by version and SHA-256 (ADR 0048),
# and the one way to fetch it. Sourced by scripts/start-gobgpd.sh and
# scripts/start-gobgp-lab.sh.

GOBGP_VERSION="4.9.0"
GOBGP_SHA256="653f52cd11614cff847c9a70dd800b1d2746e61d5796744f591388db7084a038"

# Downloads the release into $1, checks it, and leaves ./gobgpd there.
fetch_gobgpd() {
  mkdir -p "$1"
  (
    cd "$1" || exit 1
    curl -fsSLo gobgp.tar.gz \
      "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz"
    echo "${GOBGP_SHA256}  gobgp.tar.gz" | sha256sum -c -
    tar -xzf gobgp.tar.gz gobgpd
  )
}
