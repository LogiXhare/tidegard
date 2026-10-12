# Grafana Dashboards

Original dashboards for WetechiNetMon, designed for this project (see
the [clean-room boundary](../../docs/clean-room-boundary.md)).

| File | UID | Datasources | Shows |
|---|---|---|---|
| `traffic.json` | `wnm-traffic` | ClickHouse | Traffic, protocol mix, attack indicators, top talkers, exporters |
| `collector.json` | `wnm-collector` | Prometheus | Decoding, classification, aggregation, ClickHouse export, inbox writes |
| `detection.json` | `wnm-detection` | Prometheus, ClickHouse | Scopes by state, transitions, events, and the latest detection events |
| `incidents.json` | `wnm-incidents` | Prometheus | The incident manager's inbox, outbox, dead letters, timers and retention, and the notifier's attempts |

Each datasource is a dashboard variable, so the JSON works in any
Grafana; load it with the [provisioning files](../provisioning/). The
traffic data has no tenant until Phase 8, so these dashboards are
deployment-wide.

**Every change is checked** ([ADR 0041](../../docs/architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)):

- `cargo test -p wetechinetmon-dashboard-check` refuses a panel that
  queries a metric no module registers or a table the schema does not
  create, a hard-coded datasource, or a bad UID.
- The CI job **Grafana dashboards** loads them into a real Grafana with
  real ClickHouse and Prometheus, and runs every panel's query.

UIDs never change: operators bookmark them.
