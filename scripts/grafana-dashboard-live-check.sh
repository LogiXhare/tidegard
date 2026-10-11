#!/usr/bin/env bash
# Runs every panel query of every WetechiNetMon dashboard through a real
# Grafana, and fails on the first query Grafana or a datasource refuses
# (ADR 0041). CI runs it against throwaway ClickHouse, Prometheus and
# Grafana containers; it is never pointed at a production Grafana.
#
# Usage: GRAFANA_URL=http://127.0.0.1:3000 GRAFANA_AUTH=admin:password \
#        scripts/grafana-dashboard-live-check.sh grafana/dashboards
#
# Needs curl and jq. The datasource variables resolve to the UIDs in
# grafana/provisioning/datasources/wetechinetmon.yaml.
set -euo pipefail

dir="${1:?usage: $0 DASHBOARD_DIR}"
: "${GRAFANA_URL:?set GRAFANA_URL}"
: "${GRAFANA_AUTH:?set GRAFANA_AUTH as user:password}"

api() {
  curl --silent --show-error --fail-with-body --user "$GRAFANA_AUTH" \
    --header 'Content-Type: application/json' "$@"
}

queries=0
failures=0
for file in "$dir"/*.json; do
  uid=$(jq -r '.uid' "$file")
  # The provisioned copy must exist: provisioning refused nothing.
  if ! api "$GRAFANA_URL/api/dashboards/uid/$uid" >/dev/null; then
    echo "FAIL $file: Grafana did not provision dashboard $uid" >&2
    failures=$((failures + 1))
    continue
  fi

  # One request per target, with the dashboard's datasource variables
  # replaced by the provisioned UIDs.
  while IFS= read -r request; do
    title=$(jq -r '.title' <<<"$request")
    body=$(jq -c '{from: "now-1h", to: "now", queries: [.query]}' <<<"$request")
    queries=$((queries + 1))
    if ! response=$(api --request POST --data "$body" "$GRAFANA_URL/api/ds/query"); then
      echo "FAIL $file: panel \"$title\": $response" >&2
      failures=$((failures + 1))
      continue
    fi
    errors=$(jq -r '[.results[] | select(.error != null) | .error] | join("; ")' <<<"$response")
    if [ -n "$errors" ]; then
      echo "FAIL $file: panel \"$title\": $errors" >&2
      failures=$((failures + 1))
    fi
  done < <(jq -c '
    [.panels[] | if .type == "row" then (.panels // [])[] else . end]
    | .[]
    | select(.targets != null)
    | . as $panel
    | .targets[]
    | (.datasource // $panel.datasource) as $ds
    | {
        title: $panel.title,
        query: (. + {
          datasource: {
            type: $ds.type,
            uid: (if $ds.uid == "${ds_prometheus}" then "wnm-prometheus"
                  elif $ds.uid == "${ds_clickhouse}" then "wnm-clickhouse"
                  else $ds.uid end)
          },
          intervalMs: 15000,
          maxDataPoints: 500
        })
      }
  ' "$file")
done

echo "$queries panel queries run, $failures failed"
if [ "$queries" -eq 0 ] || [ "$failures" -ne 0 ]; then
  exit 1
fi
