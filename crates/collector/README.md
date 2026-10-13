# Telemetry Collector

**Status:** Implemented (Phase 2: IPFIX-only decode; Phase 3: full
normalize → classify → aggregate → optional ClickHouse export pipeline).
NetFlow/sFlow are later phases.

Binds a UDP socket, decodes IPFIX messages via
`tidegard-protocol-ipfix`, normalizes Data Records into
`NormalizedFlow`s with sampling correction, classifies direction
(`tidegard-classifier`), aggregates them
(`tidegard-aggregator`), optionally exports to ClickHouse
(`tidegard-storage`), and exposes Prometheus metrics on a separate
HTTP port. See [../../docs/architecture/aggregation.md](../../docs/architecture/aggregation.md).

## Running

```bash
# Optional — defaults shown:
export TIDEGARD_COLLECTOR_BIND=0.0.0.0:2055
export TIDEGARD_COLLECTOR_METRICS_BIND=0.0.0.0:9090
export TIDEGARD_COLLECTOR_LOCAL_PREFIXES="10.0.0.0/8@wetechi@core"
export RUST_LOG=info

cargo run --bin tidegard-collector
# metrics: curl http://localhost:9090/metrics
```

Full configuration reference:
[../../docs/configuration/aggregation.md](../../docs/configuration/aggregation.md),
[../../docs/configuration/prefixes.md](../../docs/configuration/prefixes.md).

Send it synthetic test traffic with the replay tool:
[../../tools/flow-replay](../../tools/flow-replay). **Never point this
collector at a network capture of real traffic or point `flow-replay` at
anything but a lab collector you control** — see
[../../docs/security-principles.md](../../docs/security-principles.md).

## Metrics

See `src/metrics.rs` for the full list (all prefixed
`tidegard_collector_`), or
[../../docs/operations/aggregator-monitoring.md](../../docs/operations/aggregator-monitoring.md)
for the operator-facing summary.

## Known limitations

- Configuration is environment-variable-only for now — the real
  Configuration Service (`crates/configuration`) doesn't exist yet; this
  is a documented MVP simplification, not an oversight (see
  `src/config.rs`).
- Graceful shutdown handles Ctrl+C and, on Unix, `SIGTERM` (Phase 3) —
  Windows has no SIGTERM equivalent handled here.
- `udp_receive_buffer_errors_total` (listed in the master prompt's metric
  set) is not implemented — reading the kernel's UDP drop counter
  portably across Windows/Linux needs platform-specific code this phase
  doesn't need yet.
- `cargo-fuzz` target exists (`crates/protocol-ipfix/fuzz/`) but has not
  been executed — no nightly Rust toolchain in this environment.
- ClickHouse export wiring exists and is unit-tested but not verified
  against a live server — see
  [../../docs/integrations/clickhouse.md](../../docs/integrations/clickhouse.md).

## Testing

```bash
cargo test -p tidegard-collector
```

28 unit tests, including a full IPFIX-to-aggregation end-to-end test, a
malformed-header test, sequence-number-restart detection, unknown-template
handling, a real `tokio::net::TcpListener`/`TcpStream` metrics-server
integration-style test, and config parsing (including the local-prefix
format).
