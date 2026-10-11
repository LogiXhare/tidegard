# 0041. Phase 6A Grafana Dashboards as Code

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner, under the delegation of 2026-10-05 to
industry practice

## Context

Milestone 6A ships Grafana dashboards
([Phase 6 plan](../phase6-dashboards-ui-notifications-plan.md)). BQ-2
settled the packaging: the operator runs their own Grafana, and we ship
original dashboard JSON and provisioning files only.

A dashboard is code that nothing compiles. A renamed metric or table
leaves a panel that is quietly empty, and nobody notices until an attack
is under way and the panel shows nothing. So the question is how to make
dashboards fail the build the way code does.

Two facts shape the answer:

- **Prometheus prunes empty families.** A labelled metric appears on
  `/metrics` only once a label value is set, so scraping a fresh process
  does not list every metric.
- **No ClickHouse server has ever run in CI.** The traffic DDL has been
  tested only as text (`crates/storage` module docs).

## Decision

**The dashboards are checked twice: statically on every build, and
against real services in CI.**

### Static check, in `cargo test`

- Each metrics module (collector, detector, incident inbox, incident
  manager) lists its metrics once, in a `collectors()` method. `new`
  registers exactly that list, and `metric_names()` reads it, so the
  names cannot drift from what `/metrics` exports. A test in the
  incident manager proves the list equals the exported families once
  every series is touched.
- `tools/dashboard-check` loads every file in `grafana/dashboards/` and
  refuses:
  - invalid JSON, a missing or duplicate UID, or a UID outside `wnm-*`;
  - a panel whose datasource is not a dashboard variable
    (`${ds_prometheus}` or `${ds_clickhouse}`);
  - a PromQL expression naming a metric that no module registers;
  - SQL reading a table that `CREATE_TABLE_STATEMENTS` does not create.

### Live check, a CI job

A job starts ClickHouse, Prometheus and Grafana from pinned images,
creates the schema from `CREATE_TABLE_STATEMENTS`, provisions the
datasources and dashboards from `grafana/provisioning/`, and runs every
panel's query through Grafana's query API. Any error fails the job. This
is also the first time the ClickHouse DDL runs against a real server.

The images are services used by CI only, never shipped:
`grafana/grafana` 13.2.3, `clickhouse/clickhouse-server` 26.8.24.9 (LTS),
`prom/prometheus` v3.13.4, and the `grafana-clickhouse-datasource`
plugin 4.21.3 (Apache-2.0).

### Conventions

- UIDs are `wnm-` plus a stable slug. They never change, because
  operators bookmark and link them.
- Datasources are variables, so the JSON works in any Grafana.
- Traffic rates divide summed counters by `$__interval_s`, so a panel
  is correct at any zoom.
- Panels never use colour alone (FR-10.2): every threshold also has a
  label or a line style.

## Consequences

- A metric or table rename fails `cargo test` until its dashboards are
  updated.
- The live job adds a few minutes to CI and needs network access to pull
  images and the plugin.
- The dashboards cannot show traffic per tenant: the traffic tables have
  no tenant (R21). They are deployment-wide, like the traffic data.

## Alternatives considered

- **Grafonnet or another generator.** It adds a Jsonnet toolchain and a
  layer to learn, for four dashboards. The check above catches what a
  generator would, and the JSON stays what Grafana itself exports.
- **Validate the JSON schema only.** It catches structure but not the
  failure that matters: a query against something that does not exist.
- **Scrape `/metrics` from running services.** Prometheus prunes empty
  families, so the list would be incomplete.
