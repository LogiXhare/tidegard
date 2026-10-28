# ClickHouse Integration Guide

Status: Phase 3. Implemented in `crates/storage`, wired into
`tidegard-collector` in `crates/collector/src/clickhouse_export.rs`.

**Verified against a live server since Phase 9A-3.** Before then it
was not, and the traffic rows' `#[serde(flatten)]` counters panicked
the collector on its first export: RowBinary cannot encode them
([ADR 0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md)).
CI now writes every row type to a real ClickHouse and reads it back
(`crates/storage/tests/clickhouse_integration.rs`, in the PostgreSQL
jobs), exports over TLS (`clickhouse_tls.rs`, in the Grafana job), and
runs the collector against ClickHouse in the Compose stack.

## Enabling Export

```bash
# On the same host: plain HTTP is allowed to loopback only.
export TIDEGARD_COLLECTOR_CLICKHOUSE_URL=http://127.0.0.1:8123
# Anywhere else: TLS, verified against your CA bundle (ADR 0053).
export TIDEGARD_COLLECTOR_CLICKHOUSE_URL=https://clickhouse.example.net:8443
export TIDEGARD_COLLECTOR_CLICKHOUSE_CA_FILE=/etc/tidegard/tls/ca.pem
export TIDEGARD_COLLECTOR_CLICKHOUSE_USER=tidegard_collector
export TIDEGARD_COLLECTOR_CLICKHOUSE_PASSWORD_FILE=/etc/tidegard/clickhouse-password
```

The collector refuses to start with `http://` to another host, or with
`https://` and no CA bundle. A URL holding credentials, a path or a query
is refused too.
A password file or CA bundle that cannot be read, or a bundle that
holds no certificate, stops it as well. A server that does not answer
within 30 seconds at startup, or refuses the migrations, disables export
for that run and says so in the log; the collector reports ready only
once this is settled.

Unset (the default): ClickHouse export is entirely disabled, and nothing
else about the collector's behavior changes — decode/normalize/classify/
aggregate all work identically with or without it.

On startup, if the URL is set, the collector runs every table's
`CREATE TABLE IF NOT EXISTS` (idempotent — safe on every restart, not
just first install) and then exports a snapshot of the aggregator's
current state every 15 seconds.

## Tables

All original schemas (see docs/clean-room-boundary.md) — no proprietary
table names or definitions copied. Full DDL:
`crates/storage/src/schema.rs`.

| Table | Dimension | Key columns |
|---|---|---|
| `wetechinetmon_total_ipv4_traffic` | Global IPv4 total | `timestamp` |
| `wetechinetmon_total_ipv6_traffic` | Global IPv6 total | `timestamp` |
| `wetechinetmon_host_traffic` | Per-host (v4+v6) | `timestamp, family, address` |
| `wetechinetmon_network_traffic` | Configurable-prefix-length networks | `timestamp, family, prefix_len, address` |
| `wetechinetmon_slash24_network_traffic` | IPv4 /24 | `timestamp, address` |
| `wetechinetmon_hostgroup_traffic` | Per-hostgroup | `timestamp, hostgroup` |
| `wetechinetmon_asn_traffic` | Per-ASN | `timestamp, asn` |
| `wetechinetmon_exporter_traffic` | Per-exporter | `timestamp, exporter` |
| `wetechinetmon_interface_traffic` | Per-interface | schema exists, **not yet exported** — see Known Limitations |

Every table shares the same counter columns: `bytes`, `packets`, `flows`,
`tcp_bytes`, `tcp_packets`, `udp_bytes`, `udp_packets`, `icmp_bytes`,
`icmp_packets`, `tcp_syn_packets`, `fragmented_packets`,
`dropped_packets`.

**Deliberate simplification:** IP addresses are stored as `String` (text
representation), not ClickHouse's native `IPv4`/`IPv6` column types —
documented in `crates/storage/src/schema.rs`, to avoid depending on
native-type (de)serialization behavior that hasn't been verified against
a live server here.

## Retention

All tables: `TTL timestamp + INTERVAL 30 DAY`, `MergeTree` engine
partitioned by day (`PARTITION BY toYYYYMMDD(timestamp)`). Not currently
configurable per-deployment via environment variable — change the DDL in
`crates/storage/src/schema.rs` directly if a different retention is
needed (see `RETENTION_DAYS` constant, kept in sync with the DDL by a
unit test).

## Batching and Retry

See [ADR 0005](../architecture/decisions/0005-clickhouse-batching-and-retry.md).

- Rows accumulate in a bounded in-memory batch (default: 10,000 rows or
  5 seconds, whichever first — `BatchConfig::default()`).
- A failed batch moves to a bounded retry queue (default: 100 pending
  batches, exponential backoff starting at 1s up to 60s, max 5 attempts
  — `RetryConfig::default()`).
- If the retry queue is full when a new failure needs to enqueue, the
  **oldest** pending batch is dropped — never the newest. This is real,
  deliberate data loss under prolonged ClickHouse unavailability,
  favoring bounded memory over unbounded retention. See ADR 0005 for the
  full reasoning.
- After `max_attempts` failures, a batch is permanently dropped (not
  retried forever).

## Failure Metrics

| Metric | Meaning |
|---|---|
| `tidegard_collector_clickhouse_rows_written_total` | Successfully written rows |
| `tidegard_collector_clickhouse_write_failures_total` | Batch write attempts that failed and were queued for retry |
| `tidegard_collector_clickhouse_retry_queue_dropped_total` | Batches lost because the retry queue was full |

## Testing Without a Live Server

`crates/storage`'s unit tests (batch queue behavior, retry backoff,
schema/DDL shape, counter-field conversion) run with `cargo test -p
tidegard-storage` and need no ClickHouse server. An integration test
(`crates/storage/tests/clickhouse_integration.rs`) exists for the actual
write path and skips cleanly — printing why, not silently passing — when
no server is reachable. See that file for how to point it at a real
instance (`CLICKHOUSE_TEST_URL` environment variable).

## Known Limitations

- **`interface_traffic` is not exported.** `crates/aggregator`'s
  interface dimension is keyed by interface index alone, not
  `(exporter, interface index)` — two different exporters both using
  interface `1` would collide. The table/schema exists and is ready;
  wiring is deferred until the aggregator's interface dimension is made
  exporter-scoped.
- No authentication/TLS configuration exposed — set these up on the
  ClickHouse side (or via a reverse proxy) if needed; this project passes
  a plain HTTP URL through to the `clickhouse` Rust crate.
- No live-server integration testing has been performed in this
  environment.
