# Grafana Provisioning

Example provisioning for the [Tidegard dashboards](../dashboards/).
Grafana is not shipped: you run your own, and load these files into it
([ADR 0041](../../docs/architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)).

| File | What it does |
|---|---|
| `dashboards/tidegard.yaml` | Loads every JSON file from `/var/lib/grafana/dashboards/tidegard` into a `Tidegard` folder, read-only |
| `datasources/tidegard.yaml` | An example Prometheus and ClickHouse datasource, configured from the environment |

The ClickHouse datasource needs the `grafana-clickhouse-datasource`
plugin (Apache-2.0). CI tests with version 4.21.3.

Environment for the example datasources:

| Variable | Example |
|---|---|
| `WNM_PROMETHEUS_URL` | `https://prometheus.example.net:9090` |
| `WNM_CLICKHOUSE_HOST` | `clickhouse.example.net` |
| `WNM_CLICKHOUSE_USER` | a read-only user |
| `WNM_CLICKHOUSE_PASSWORD` | from your secret store |

Give Grafana a ClickHouse user that can only `SELECT`. The dashboards
never write.
