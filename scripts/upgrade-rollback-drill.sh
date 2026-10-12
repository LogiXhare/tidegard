#!/usr/bin/env bash
# The upgrade and rollback drill (Phase 9C, ADR 0055).
#
# 1. v0.9.0's own services fill an empty database: incidents from a
#    synthetic flood, a note, an acknowledgement and a dry-run mitigation
#    request through its API.
# 2. A pre-upgrade backup, as the upgrade guide says to take.
# 3. The candidate's services start on that database: its incident
#    manager applies any new migrations, and the data must be there,
#    readable through the new API, with new incidents still opening.
# 4. Rollback, the documented way: restore the pre-upgrade backup into a
#    fresh database and start v0.9.0 again; it must serve the same data.
#
# This touches ONLY CI's throwaway PostgreSQL. It drops and recreates
# databases. Never point it at a real one.
#
# Environment:
#   OLD_BIN, NEW_BIN   Directories holding each version's binaries
#   REPLAY             A flow-replay with rate mode (the candidate's)
#   PG_TOOL            Prefix that runs psql/pg_dump/pg_restore in the
#                      server's container, e.g. "docker exec -i <id>"
#   PG_HOST, PG_PORT, PG_USER, PG_PASSWORD, PG_DB
#   WORK               Where logs, the backup and fingerprints go
set -euo pipefail

: "${OLD_BIN:?}" "${NEW_BIN:?}" "${REPLAY:?}" "${PG_TOOL:?}"
: "${PG_HOST:?}" "${PG_PORT:?}" "${PG_USER:?}" "${PG_PASSWORD:?}" "${PG_DB:?}"
work=${WORK:-$(mktemp -d)}
mkdir -p "$work"
url() { echo "host=$PG_HOST port=$PG_PORT user=$PG_USER password=$PG_PASSWORD dbname=$1"; }
database=$(url "$PG_DB")
api=http://127.0.0.1:8080

# shellcheck disable=SC2086 # PG_TOOL is a command prefix and must split.
pg() { $PG_TOOL "$@"; }
sql() { pg psql -X -v ON_ERROR_STOP=1 -U "$PG_USER" -d "${2:-$PG_DB}" -tAc "$1"; }

pids=()
stop_all() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  pids=()
}
trap stop_all EXIT

ready() {
  for _ in $(seq 90); do
    curl -sf "$1/readyz" >/dev/null && return 0
    sleep 1
  done
  echo "drill: $1 never became ready"
  exit 1
}

# start <bin dir> <label>: the incident manager, the API and the collector.
start() {
  local bin=$1 label=$2
  WETECHINETMON_INCIDENT_DATABASE_URL="$database" \
    WETECHINETMON_INCIDENT_METRICS_BIND=127.0.0.1:9091 \
    "$bin/wetechinetmon-incident-manager" > "$work/$label-manager.log" 2>&1 &
  pids+=($!)
  ready http://127.0.0.1:9091
  WETECHINETMON_API_DATABASE_URL="$database" \
    WETECHINETMON_API_MITIGATION_GUARD_FILE="$work/guard.json" \
    "$bin/wetechinetmon-api" > "$work/$label-api.log" 2>&1 &
  pids+=($!)
  ready "$api"
  WETECHINETMON_COLLECTOR_BIND=127.0.0.1:2055 \
    WETECHINETMON_COLLECTOR_METRICS_BIND=127.0.0.1:9090 \
    WETECHINETMON_COLLECTOR_LOCAL_PREFIXES=10.0.0.0/8@default \
    WETECHINETMON_COLLECTOR_DETECTION_POLICY_FILE="$work/policy.json" \
    WETECHINETMON_COLLECTOR_DETECTION_WINDOW_SECS=1 \
    WETECHINETMON_COLLECTOR_INCIDENT_DATABASE_URL="$database" \
    "$bin/wetechinetmon-collector" > "$work/$label-collector.log" 2>&1 &
  pids+=($!)
  ready http://127.0.0.1:9090
}

token() { # token <bin dir> <role> <actor>
  WETECHINETMON_API_DATABASE_URL="$database" "$1/wetechinetmon-api" token create \
    --tenant default --actor-id "$3" --role "$2" --days 1 | awk '/^token:/ {print $2}'
}

call() { # call <token> <method> <path> [body]
  curl -sS --fail-with-body -X "$2" "$api$3" -H "Authorization: Bearer $1" \
    -H "Content-Type: application/json" -H "Idempotency-Key: drill-$RANDOM-$RANDOM" \
    ${4:+--data "$4"}
}

# Rows in every table that holds what an operator would miss.
fingerprint() {
  for table in incidents incident_notes incident_audit incident_timeline incident_outbox \
    mitigations mitigation_history api_tokens; do
    echo "$table $(sql "SELECT count(*) FROM $table" "${1:-$PG_DB}")"
  done
}

incidents_after() { # wait until there are more than $1 incidents
  for _ in $(seq 60); do
    [ "$(sql 'SELECT count(*) FROM incidents')" -gt "$1" ] && return 0
    sleep 1
  done
  echo "drill: no new incident opened"
  exit 1
}

cat > "$work/policy.json" <<'JSON'
{"schemaVersion": 1,
 "tenants": [{"tenant": "default", "prefixes": ["10.0.0.0/8"]}],
 "policies": [{"id": "drill-host-inbound", "name": "drill host inbound", "tenant": "default",
   "scopeType": "host", "direction": "incoming", "window": "1s",
   "thresholds": {"bps": "1M"}, "triggerFor": "2s", "clearFor": "5s",
   "cooldown": "60s", "severity": "major", "executionMode": "dryRun"}]}
JSON
cat > "$work/guard.json" <<'JSON'
{"dry_run": true, "bgp_enabled": false,
 "allowlist": [{"prefix": "203.0.113.0/24", "tenant": "default", "actions": ["rtbh"]}]}
JSON

echo "drill: v0.9.0 fills the database"
start "$OLD_BIN" old
"$REPLAY" 127.0.0.1:2055 --rate 20000 --hosts 200 --duration-secs 10 > /dev/null
incidents_after 0
lead=$(token "$OLD_BIN" noc_lead drill-lead)
operator=$(token "$OLD_BIN" senior_operator drill-operator)
first=$(call "$lead" GET "/api/v1/incidents?limit=1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["items"][0]["incident_id"])')
version=$(call "$lead" GET "/api/v1/incidents/$first" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')
call "$lead" POST "/api/v1/incidents/$first/acknowledge" "{\"expected_version\": $version}" > /dev/null
call "$lead" POST "/api/v1/incidents/$first/notes" '{"body": "written by v0.9.0"}' > /dev/null
mitigation=$(call "$operator" POST /api/v1/mitigations \
  '{"prefix": "203.0.113.9/32", "action": "rtbh", "reason": "upgrade drill", "duration_seconds": 600}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["mitigation_id"])')
sleep 3
stop_all
fingerprint > "$work/v090.txt"
cat "$work/v090.txt"

echo "drill: the pre-upgrade backup"
pg pg_dump -U "$PG_USER" -d "$PG_DB" --format=custom --no-owner > "$work/pre-upgrade.dump"
test -s "$work/pre-upgrade.dump"

echo "drill: upgrading to the candidate"
start "$NEW_BIN" new
fingerprint > "$work/upgraded.txt"
if ! diff -u "$work/v090.txt" "$work/upgraded.txt"; then
  echo "drill: the upgrade changed what v0.9.0 wrote"
  exit 1
fi
new_lead=$(token "$NEW_BIN" noc_lead drill-lead-2)
call "$new_lead" GET "/api/v1/incidents/$first" | grep -q '"state":"acknowledged"'
call "$new_lead" GET "/api/v1/incidents/$first/notes" | grep -q 'written by v0.9.0'
call "$new_lead" GET "/api/v1/mitigations/$mitigation" | grep -q '"state":"requested"'
before=$(sql 'SELECT count(*) FROM incidents')
"$REPLAY" 127.0.0.1:2055 --rate 20000 --hosts 400 --duration-secs 10 > /dev/null
incidents_after "$before"
echo "drill: upgraded; $(sql 'SELECT count(*) FROM incidents') incidents"
stop_all

echo "drill: rolling back by restoring the pre-upgrade backup"
pg psql -X -v ON_ERROR_STOP=1 -U "$PG_USER" -d postgres \
  -c "DROP DATABASE $PG_DB WITH (FORCE)" -c "CREATE DATABASE $PG_DB"
pg pg_restore -U "$PG_USER" -d "$PG_DB" --no-owner --exit-on-error --single-transaction \
  < "$work/pre-upgrade.dump"
start "$OLD_BIN" rolled-back
fingerprint > "$work/rolled-back.txt"
if ! diff -u "$work/v090.txt" "$work/rolled-back.txt"; then
  echo "drill: the rollback does not match what v0.9.0 had"
  exit 1
fi
call "$lead" GET "/api/v1/incidents/$first" | grep -q '"state":"acknowledged"'
call "$lead" GET "/api/v1/mitigations/$mitigation" | grep -q '"state":"requested"'
stop_all

echo "drill: passed"
