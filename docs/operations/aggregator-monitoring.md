# Aggregator Monitoring

Status: Phase 3. Full metric reference lives in
`crates/collector/src/metrics.rs` (self-documenting via each metric's
`HELP` text, visible at `/metrics`); this page is the operator-facing
summary of what to watch and why.

## Health Signals

| Symptom | Check | Likely cause |
|---|---|---|
| `queue_depth` consistently near `TIDEGARD_COLLECTOR_QUEUE_CAPACITY` | `aggregation_latency_seconds` histogram | Classify/aggregate stage can't keep up with datagram rate — consider raising queue capacity as a stopgap, but rising latency is the real signal to investigate |
| `incomplete_records_total` climbing | Exporter's template configuration | Exporter isn't sending address fields, or its Options Templates are malformed |
| `prefix_lookup_failures_total` == all traffic | `TIDEGARD_COLLECTOR_LOCAL_PREFIXES` | No local prefixes configured — see docs/configuration/prefixes.md |
| `sampling_errors_total` climbing | Exporter's sampling configuration | An exporter is declaring a `0` sampling rate somewhere in its Options Template or record-level fields |
| `evicted_entries_total` climbing steadily (not just at startup) | `active_hosts`/`active_networks`/etc. vs. configured max | A dimension is at capacity and churning — raise the relevant `TIDEGARD_COLLECTOR_MAX_*` limit if the traffic pattern is legitimate, or investigate a possible high-cardinality attack (docs/security-principles.md) |
| `clickhouse_write_failures_total` / `clickhouse_retry_queue_dropped_total` climbing | ClickHouse server reachability | See docs/integrations/clickhouse.md |

## Key Metrics by Category

**Pipeline throughput:** `flow_datagrams_received_total`,
`parsed_flow_records_total`, `normalized_flows_total`.

**Data quality:** `incomplete_records_total`,
`unsupported_protocol_fields_total`, `parser_failures_total`,
`unknown_templates_total`.

**Sampling:** `corrected_samples_total`, `sampling_errors_total`.

**Classification:** `classified_flows_by_direction_total{direction=...}`,
`prefix_lookup_failures_total`.

**Aggregation state:** `active_hosts`, `active_networks`,
`active_hostgroups`, `active_asns`, `expired_entries_total`,
`evicted_entries_total`.

**Pipeline health:** `queue_depth`, `aggregation_latency_seconds`.

**Exporter health (Phase 2):** `active_exporters`, `template_cache_size`,
`exporter_restarts_total`, and since Phase 9D
`datagrams_refused_total{reason}` (`not_allowed`, `exporter_limit`;
[ADR 0056](../architecture/decisions/0056-phase9d-collector-input-bounds.md)).

## No Unbounded Labels

Per Phase 3 objective 9, no metric here carries a host IP, network
prefix, customer name, or tenant ID as a Prometheus label — every labeled
metric (`sets_by_kind_total`, `classified_flows_by_direction_total`) uses
a small, fixed set of label values (Set kind; Direction). Per-entity
detail (which host, which network) belongs in ClickHouse
(docs/integrations/clickhouse.md), not in Prometheus label cardinality.

## Example Prometheus Alerting Rules (illustrative, not deployed)

```yaml
# Not wired into any deployment yet — Phase 6 (Grafana/notifications) is
# where alerting integration lands. Shown here as a starting point.
- alert: TidegardQueueSaturated
  expr: tidegard_collector_queue_depth > 0.9 * <configured_queue_capacity>
  for: 5m
- alert: TidegardNoLocalPrefixes
  expr: rate(tidegard_collector_prefix_lookup_failures_total[5m]) > 0
  for: 15m
- alert: TidegardClickHouseWritesFailing
  expr: rate(tidegard_collector_clickhouse_write_failures_total[5m]) > 0
  for: 10m
```
