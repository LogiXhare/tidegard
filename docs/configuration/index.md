# Configuration Reference

Status: Phase 2 — Telemetry Collector options only. Every future
configuration option is added here in the same PR that introduces it, per
`prompts/CLAUDE_MASTER_PROMPT.md` §25.

## Telemetry Collector (`tidegard-collector`)

Configuration is environment-variable-only in Phase 2 — see
[crates/collector/README.md](https://github.com/LogiXhare/tidegard/blob/main/crates/collector/README.md)
"Known limitations" for why (the real Configuration Service doesn't exist
yet). Source of truth: `crates/collector/src/config.rs`.

### `TIDEGARD_COLLECTOR_BIND`

| Field | Value |
|---|---|
| Type | `host:port` (UDP) |
| Default | `0.0.0.0:2055` |
| Allowed values | Any value parseable as a Rust `std::net::SocketAddr` |
| Example | `TIDEGARD_COLLECTOR_BIND=203.0.113.2:2055` |
| Security implications | This is the collector's untrusted-input surface (see [../security-principles.md](../security-principles.md)) — binding `0.0.0.0` exposes it on every interface; bind to a specific management/telemetry interface in production. |
| Reload requirement | Restart required — read once at process startup. |
| Related metrics | `tidegard_collector_flow_datagrams_received_total`, `tidegard_collector_parser_failures_total` |
| Verification command | `curl -s http://<metrics_bind>/metrics \| grep flow_datagrams_received_total` after sending test traffic — see [tools/flow-replay/README.md](https://github.com/LogiXhare/tidegard/blob/main/tools/flow-replay/README.md) |
| Troubleshooting | An invalid value causes the process to log an error and exit(1) at startup rather than silently falling back — check the startup log line for `invalid configuration`. |

### `TIDEGARD_COLLECTOR_METRICS_BIND`

| Field | Value |
|---|---|
| Type | `host:port` (TCP) |
| Default | `0.0.0.0:9090` |
| Allowed values | Any value parseable as a Rust `std::net::SocketAddr` |
| Example | `TIDEGARD_COLLECTOR_METRICS_BIND=127.0.0.1:9090` |
| Security implications | Serves `/metrics` with no authentication — bind to a private/management interface, not a public one, or place behind a reverse proxy that adds access control. |
| Reload requirement | Restart required — read once at process startup. |
| Related metrics | N/A (this is the endpoint metrics are served from) |
| Verification command | `curl -s http://<metrics_bind>/metrics` should return `200 OK` with Prometheus text-format output; any other path returns `404`. |
| Troubleshooting | Same invalid-value behavior as `TIDEGARD_COLLECTOR_BIND` above (fails fast at startup, not silent fallback). |

### `RUST_LOG`

| Field | Value |
|---|---|
| Type | [`tracing-subscriber` `EnvFilter`](https://docs.rs/tracing-subscriber) syntax |
| Default | `info` (used when unset or when the given value fails to parse) |
| Allowed values | e.g. `info`, `debug`, `tidegard_collector=debug,info` |
| Example | `RUST_LOG=tidegard_collector=debug` |
| Security implications | `debug`-level logs may include more detail about received packets; avoid `trace` in production without reviewing for sensitive-value leakage. |
| Reload requirement | Restart required. |
| Related metrics | N/A |
| Verification command | Check process output — JSON log lines include a `level` field. |
| Troubleshooting | An invalid filter expression silently falls back to `info` (see `crates/common/src/logging.rs`) rather than failing startup, since a logging misconfiguration shouldn't take down telemetry collection. |
