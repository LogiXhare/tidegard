#!/usr/bin/env bash
# The disaster recovery drill (Phase 9C, ADR 0055), on a fresh runner.
#
# It has only what an operator has after losing the host: the release
# tarball, the PostgreSQL backup (roles, then the database), the
# ClickHouse backup, and the settings. It follows
# docs/operations/disaster-recovery.md: new databases, restore both,
# install, start, and check that everything is there.
#
# Run as a user with sudo, on a throwaway machine: it installs into
# /opt/tidegard and /etc, and starts containers and services.
#
# Environment:
#   DR             Directory holding the artifacts:
#                    tidegard-*.tar.gz
#                    roles.sql, incident.dump, incidents.txt
#                    tidegard-drill.zip, before.txt (ClickHouse)
#   PG_PASSWORD, CH_PASSWORD   Throwaway passwords for the new servers
set -euo pipefail

: "${DR:?}" "${PG_PASSWORD:?}" "${CH_PASSWORD:?}"
cd "$DR"

echo "dr: a new PostgreSQL"
docker run -d --name dr-postgres -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=tidegard -e POSTGRES_PASSWORD="$PG_PASSWORD" \
  -e POSTGRES_DB=tidegard postgres:17-alpine > /dev/null
for _ in $(seq 60); do
  docker exec dr-postgres pg_isready -U tidegard -d tidegard >/dev/null 2>&1 && break
  sleep 1
done
sleep 2
psql_() { docker exec -i dr-postgres psql -X -U tidegard -d "${1:-tidegard}" "${@:2}"; }

echo "dr: restoring the roles, then the database"
# The roles dump holds every role of the old cluster; those that exist
# here already (its superuser) fail harmlessly. The application role
# migration V11 grants to must come back.
psql_ postgres < roles.sql > /dev/null 2>&1 || true
[ "$(psql_ postgres -tAc "SELECT count(*) FROM pg_roles WHERE rolname = 'wetechinetmon_app'")" = 1 ]
docker exec -i dr-postgres pg_restore -U tidegard -d tidegard --no-owner \
  --exit-on-error --single-transaction < incident.dump
expected=$(cat incidents.txt)
[ "$(psql_ tidegard -tAc 'SELECT count(*) FROM incidents')" = "$expected" ]
echo "dr: $expected incidents restored"

echo "dr: a new ClickHouse, and its backup restored"
mkdir -p backups
cp tidegard-drill.zip backups/
chmod -R a+rwX backups
printf '%s\n' '<clickhouse><backups><allowed_path>/backups/</allowed_path></backups></clickhouse>' > backups.xml
docker run -d --name dr-clickhouse -p 127.0.0.1:8123:8123 \
  -e CLICKHOUSE_USER=tidegard -e CLICKHOUSE_PASSWORD="$CH_PASSWORD" \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  -v "$DR/backups.xml:/etc/clickhouse-server/config.d/backups.xml:ro" \
  -v "$DR/backups:/backups" clickhouse/clickhouse-server:26.8.24.9 > /dev/null
for _ in $(seq 60); do
  curl -sf http://127.0.0.1:8123/ping >/dev/null && break
  sleep 1
done
ch() { curl -sS --fail-with-body --user "tidegard:$CH_PASSWORD" --data-binary "$1" http://127.0.0.1:8123/; }
tables=$(cut -d' ' -f1 before.txt)
list=$(echo "$tables" | sed 's/^/TABLE default./' | paste -sd, -)
ch "RESTORE $list FROM File('tidegard-drill.zip')" > /dev/null
for table in $tables; do
  echo "$table $(ch "SELECT count(), groupBitXor(cityHash64(*)) FROM $table" | tr '\t' ' ')"
done > after.txt
diff -u before.txt after.txt
echo "dr: $(wc -l < after.txt) ClickHouse tables identical"

echo "dr: installing the release"
mkdir -p release
tar -xzf tidegard-*.tar.gz -C release
sudo "$(echo release/tidegard-*/)install.sh" > /dev/null
url="host=127.0.0.1 user=tidegard password=$PG_PASSWORD dbname=tidegard"
sudo sed -i "s|=\"host=127.0.0.1 user=tidegard password=CHANGE_ME dbname=tidegard\"|=\"$url\"|" \
  /etc/tidegard/*.env
printf '%s\n' "$CH_PASSWORD" | sudo tee /etc/tidegard/clickhouse-password > /dev/null
sudo chown root:tidegard-collector /etc/tidegard/clickhouse-password
sudo chmod 0640 /etc/tidegard/clickhouse-password
sudo tee -a /etc/tidegard/collector.env > /dev/null <<EOF
TIDEGARD_COLLECTOR_CLICKHOUSE_URL=http://127.0.0.1:8123
TIDEGARD_COLLECTOR_CLICKHOUSE_USER=tidegard
TIDEGARD_COLLECTOR_CLICKHOUSE_PASSWORD_FILE=/etc/tidegard/clickhouse-password
EOF

echo "dr: starting the services"
ready() {
  for _ in $(seq 60); do
    curl -sf "$1/readyz" >/dev/null && return 0
    sleep 1
  done
  curl -sS --fail-with-body "$1/readyz"
}
sudo systemctl start tidegard-incident-manager
ready http://127.0.0.1:9091
sudo systemctl start tidegard-api tidegard-collector
ready http://127.0.0.1:8080
ready http://127.0.0.1:9090

echo "dr: checking what came back"
fail() { echo "dr: $*" >&2; exit 1; }
created=$(sudo env TIDEGARD_API_DATABASE_URL="$url" /opt/tidegard/bin/tidegard-api \
  token create --tenant default --actor-id dr-check --role viewer --days 1 2>&1) \
  || fail "no token could be issued: $created"
token=$(echo "$created" | awk '/^token:/ {print $2}')
[ -n "$token" ] || fail "token create printed no token: $created"
page=$(curl -sS -H "Authorization: Bearer $token" \
  "http://127.0.0.1:8080/api/v1/incidents?limit=1&include_total=true")
total=$(echo "$page" | python3 -c 'import json, sys; print(json.load(sys.stdin)["total"])') \
  || fail "the incident list answered: $page"
[ "$total" = "$expected" ] || fail "the API counts $total incidents; $expected were restored"
echo "dr: the API serves all $total incidents"
TIDEGARD_API_URL=http://127.0.0.1:8080 TIDEGARD_API_TOKEN="$token" \
  /opt/tidegard/bin/tidegardctl incidents list > /dev/null
for _ in $(seq 30); do
  sudo journalctl -u tidegard-collector --no-pager | grep -q "ClickHouse export enabled" && break
  sleep 1
done
sudo journalctl -u tidegard-collector --no-pager | grep -q "ClickHouse export enabled"
echo "dr: the collector exports to the restored ClickHouse"
echo "dr: passed"
