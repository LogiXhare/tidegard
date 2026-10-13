#!/usr/bin/env bash
# Prepares the Tidegard reference stack (ADR 0052). Run once, as
# root, from this directory, before the first `docker compose up`:
#
#   sudo ./setup.sh [version]
#
# - tls/: a CA for this stack alone, and certificates for PostgreSQL,
#   ClickHouse and the API. Each key belongs to the user its container
#   runs as, mode 0400; nobody else on the host can read it.
# - secrets/: random passwords for PostgreSQL and ClickHouse.
# - .env: the image version and the database URL (it holds the
#   PostgreSQL password), readable by the user who ran sudo.
#
# Nothing that exists is overwritten, so running it again is safe. To
# rotate, stop the stack, remove the file in question and run it again.
# These files are never committed (.gitignore).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "setup.sh must run as root: it sets each key's owner" >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "setup.sh needs openssl" >&2; exit 1; }
cd "$(dirname "${BASH_SOURCE[0]}")"

version=${1:-}
api_hostname=${TIDEGARD_API_HOSTNAME:-}
owner=${SUDO_UID:-0}:${SUDO_GID:-0}

# The users inside the images: postgres in the Alpine image, clickhouse,
# and distroless's nonroot for every Tidegard service.
POSTGRES_UID=70
CLICKHOUSE_UID=101
NONROOT_UID=65532

umask 077
mkdir -p tls secrets
chmod 0755 tls secrets

if [ ! -e tls/ca.pem ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=Tidegard stack CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout tls/ca.key -out tls/ca.pem 2>/dev/null
  chmod 0400 tls/ca.key
  chmod 0644 tls/ca.pem
  echo "created  tls/ca.pem"
fi

# certificate <name> <owner uid> <subjectAltName>
certificate() {
  if [ -e "tls/$1.crt" ]; then
    echo "kept     tls/$1.crt"
    return
  fi
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
    -keyout "tls/$1.key" -out "tls/$1.csr" 2>/dev/null
  printf '%s\n' "subjectAltName=$3" "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" > "tls/$1.ext"
  openssl x509 -req -in "tls/$1.csr" -CA tls/ca.pem -CAkey tls/ca.key -CAcreateserial \
    -days 825 -extfile "tls/$1.ext" -out "tls/$1.crt" 2>/dev/null
  rm -f "tls/$1.csr" "tls/$1.ext"
  chown "$2:$2" "tls/$1.key"
  chmod 0400 "tls/$1.key"
  chmod 0644 "tls/$1.crt"
  echo "created  tls/$1.crt"
}
certificate postgres "$POSTGRES_UID" "DNS:postgres"
certificate clickhouse "$CLICKHOUSE_UID" "DNS:clickhouse"
api_names="DNS:localhost,IP:127.0.0.1"
if [ -n "$api_hostname" ]; then
  api_names="$api_names,DNS:$api_hostname"
fi
certificate api "$NONROOT_UID" "$api_names"

# password <file> <owner uid> <group gid>
password() {
  if [ -e "secrets/$1" ]; then
    echo "kept     secrets/$1"
    return
  fi
  openssl rand -hex 24 > "secrets/$1"
  chown "$2:$3" "secrets/$1"
  chmod 0440 "secrets/$1"
  echo "created  secrets/$1"
}
password postgres-password "$POSTGRES_UID" "$POSTGRES_UID"
# Read by ClickHouse (its entrypoint, as root) and by the collector and
# the API (nonroot).
password clickhouse-password "$NONROOT_UID" "$CLICKHOUSE_UID"

if [ -e .env ]; then
  echo "kept     .env"
else
  if [ -z "$version" ]; then
    echo "the first run needs the image version: sudo ./setup.sh <version>" >&2
    exit 1
  fi
  postgres_password=$(cat secrets/postgres-password)
  {
    echo "TIDEGARD_VERSION=$version"
    echo "TIDEGARD_DATABASE_URL=host=postgres user=tidegard password=$postgres_password dbname=tidegard sslmode=require"
  } > .env
  chown "$owner" .env
  chmod 0600 .env
  echo "created  .env"
fi

echo
echo "Next: docker compose up -d, then see README.md for the first token."
