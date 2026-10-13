# Aggregation Configuration

Status: Phase 3. See [../architecture/aggregation.md](../architecture/aggregation.md)
for the design behind these options. All are environment variables on
`wetechinetmon-collector` — restart required to change any of them.

## `WETECHINETMON_COLLECTOR_MAX_HOSTS`

| Field | Value |
|---|---|
| Type | Non-negative integer |
| Default | `100000` |
| Security implications | Bounds worst-case memory for the host dimension — a high-cardinality flood of distinct source/destination addresses cannot grow this past the configured cap (see docs/security-principles.md "high-cardinality attacks") |
| Related metrics | `wetechinetmon_collector_active_hosts`, `wetechinetmon_collector_evicted_entries_total` |
| Verification | `curl -s http://<metrics_bind>/metrics \| grep active_hosts` |
| Troubleshooting | Setting this to `0` rejects every host-dimension update (see `BoundedMap` — `max_entries: 0` always returns `Rejected`) |

## `WETECHINETMON_COLLECTOR_MAX_NETWORKS`

Same shape as above; bounds the combined size of the /24, configurable-
prefix-length, and IPv6 network dimensions. Default `50000`.

## `WETECHINETMON_COLLECTOR_MAX_HOSTGROUPS`

Same shape; bounds the hostgroup dimension. Default `1000`.

## `WETECHINETMON_COLLECTOR_MAX_ASNS`

Same shape; bounds the ASN dimension (only populated when the exporter
provides `bgpSourceAsNumber`/`bgpDestinationAsNumber`). Default `10000`.

## `WETECHINETMON_COLLECTOR_INACTIVITY_TTL_SECS`

| Field | Value |
|---|---|
| Type | Non-negative integer (seconds) |
| Default | `300` (5 minutes) |
| Related metrics | `wetechinetmon_collector_expired_entries_total` |
| Troubleshooting | Swept every 30 seconds (`EXPIRATION_INTERVAL` in `crates/collector/src/lib.rs`, not itself configurable in Phase 3) — an entry can be up to ~30s past its nominal TTL before actually being removed |

## `WETECHINETMON_COLLECTOR_ALLOWED_EXPORTERS`

| Field | Value |
|---|---|
| Type | Comma-separated networks (`192.0.2.0/24`, `2001:db8::/32`) or addresses (`198.51.100.7`), in canonical form |
| Default | Unset: datagrams from any source are decoded, and the collector warns at startup |
| Security implications | UDP is unauthenticated. A datagram from outside these networks is dropped before it is parsed ([ADR 0056](../architecture/decisions/0056-phase9d-collector-input-bounds.md)). Set it to your routers' addresses, and firewall the flow port to them as well |
| Related metrics | `wetechinetmon_collector_datagrams_refused_total{reason="not_allowed"}` |
| Troubleshooting | A router missing from the list shows as that counter rising and no flows from it. A network with host bits set (`192.0.2.1/24`) stops the collector at startup |

## `WETECHINETMON_COLLECTOR_MAX_EXPORTERS`

| Field | Value |
|---|---|
| Type | Positive integer |
| Default | `1000` |
| Security implications | Bounds the exporters tracked, each a source address and observation domain with its own template cache of at most 512 templates and 8,192 fields: about 125 MiB at the default, whatever is sent |
| Related metrics | `wetechinetmon_collector_active_exporters`, `wetechinetmon_collector_datagrams_refused_total{reason="exporter_limit"}` |
| Troubleshooting | Past the limit, a new exporter's datagrams are dropped and counted; those already tracked carry on |

## `WETECHINETMON_COLLECTOR_EXPORTER_IDLE_SECS`

| Field | Value |
|---|---|
| Type | Non-negative integer (seconds) |
| Default | `3600` |
| Related metrics | `wetechinetmon_collector_active_exporters`, `wetechinetmon_collector_template_cache_size` |
| Troubleshooting | An exporter silent this long is forgotten with its templates, swept every 30 seconds. When it returns, its data is unknown until it sends templates again |

## `WETECHINETMON_COLLECTOR_QUEUE_CAPACITY`

| Field | Value |
|---|---|
| Type | Non-negative integer |
| Default | `10000` |
| Security implications | This is the collector's backpressure control (ADR 0004) — the UDP receive loop's `send` to the classify/aggregate stage blocks once this many datagrams are queued, rather than growing memory without bound under sustained overload |
| Related metrics | `wetechinetmon_collector_queue_depth` |
| Troubleshooting | A consistently near-full queue means the classify/aggregate stage can't keep up with the datagram rate — check `wetechinetmon_collector_aggregation_latency_seconds` |

## `WETECHINETMON_COLLECTOR_SAMPLING_GLOBAL_DEFAULT`

| Field | Value |
|---|---|
| Type | Positive integer sampling rate, or unset |
| Default | Unset (no global default — falls through to rate `1`, unsampled) |
| Related metrics | `wetechinetmon_collector_corrected_samples_total`, `wetechinetmon_collector_sampling_errors_total` |
| Troubleshooting | This is the lowest-priority tier — record-level and options-template sampling always take precedence when present. See [../architecture/aggregation.md](../architecture/aggregation.md) sampling-correction section |

## `WETECHINETMON_COLLECTOR_CLICKHOUSE_URL`

| Field | Value |
|---|---|
| Type | ClickHouse HTTP URL with a host and a port only: `http://127.0.0.1:8123`, or `https://clickhouse.example.net:8443` |
| Default | Unset — ClickHouse export entirely disabled |
| Security implications | Plain `http://` is accepted only for a loopback host; anything else needs `https://` and `WETECHINETMON_COLLECTOR_CLICKHOUSE_CA_FILE`, or the collector refuses to start ([ADR 0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md)). Credentials never go in the URL: use the two settings below |
| Related metrics | `wetechinetmon_collector_clickhouse_rows_written_total`, `wetechinetmon_collector_clickhouse_write_failures_total`, `wetechinetmon_collector_clickhouse_retry_queue_dropped_total` |
| Verification | Check collector startup logs for `ClickHouse export enabled, migrations applied`; if migrations fail, export is disabled for that run and an error is logged — not a crash |
| Troubleshooting | See [../integrations/clickhouse.md](../integrations/clickhouse.md) |

## `WETECHINETMON_COLLECTOR_CLICKHOUSE_USER` and `_PASSWORD_FILE`

| Field | Value |
|---|---|
| Type | A ClickHouse user name; a path to a file holding its password (one line) |
| Default | Unset — ClickHouse's `default` user, with no password |
| Security implications | Give the collector its own ClickHouse user, allowed to create and insert into its tables and nothing else. The password file should be readable by the collector alone |

## `WETECHINETMON_COLLECTOR_CLICKHOUSE_CA_FILE`

| Field | Value |
|---|---|
| Type | Path to the PEM bundle that signed ClickHouse's certificate |
| Default | Unset — required for `https://` |
| Security implications | The server certificate is verified against this bundle alone, never the system's roots |

## Full Reference Example

```bash
export WETECHINETMON_COLLECTOR_MAX_HOSTS=50000
export WETECHINETMON_COLLECTOR_MAX_NETWORKS=20000
export WETECHINETMON_COLLECTOR_MAX_HOSTGROUPS=200
export WETECHINETMON_COLLECTOR_MAX_ASNS=5000
export WETECHINETMON_COLLECTOR_INACTIVITY_TTL_SECS=600
export WETECHINETMON_COLLECTOR_QUEUE_CAPACITY=20000
export WETECHINETMON_COLLECTOR_SAMPLING_GLOBAL_DEFAULT=1
export WETECHINETMON_COLLECTOR_CLICKHOUSE_URL=http://localhost:8123
```

## Known Limitations

- Configurable IPv4/IPv6 prefix-length lists for the network dimension
  (beyond the always-included IPv4 /24) are set in
  `AggregatorConfig::ipv4_prefix_lengths`/`ipv6_prefix_lengths`
  programmatically today, not yet exposed as an environment variable —
  tracked as a follow-up alongside the broader Configuration Service
  work.
- `max_exporters`, `max_interfaces`, and `max_protocols` use fixed
  defaults (`AggregatorConfig::default()`) and are not yet
  environment-configurable — only the four dimensions Phase 3's
  acceptance criteria explicitly call out (hosts, networks, hostgroups,
  ASNs) are.
