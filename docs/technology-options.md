# Technology Options

Status: Phase 0 draft
Last updated: 2026-08-20

Concrete technology candidates per component, distinct from
[architecture-options.md](architecture-options.md) which covers structural
decisions. Nothing here is installed or vendored in Phase 0.

## Telemetry Collector (Rust — leaning, see architecture-options.md)

- Async runtime: `tokio`
- UDP handling: `tokio::net::UdpSocket`
- Parsing: hand-rolled `nom`-based or manual byte-level parsers per
  protocol (IPFIX/NetFlow v9 share template-based parsing logic; NetFlow v5
  is fixed-format; sFlow v5 is a distinct format)
- Fuzzing: `cargo-fuzz` / `libFuzzer`
- Property testing: `proptest`

## Event Transport

- Candidates: NATS JetStream, Redpanda, Kafka — see comparison in
  architecture-options.md. No client library selection until the ADR lands.

## Storage

- ClickHouse: official Rust client candidates (`clickhouse-rs` or HTTP
  interface) — TBD in Phase 3 ADR
- PostgreSQL: `sqlx` (async, compile-time checked queries) is the leading
  candidate for Rust services needing config/metadata access
- InfluxDB v1-compatible output: line-protocol writer, no full client
  needed
- Migrations: `sqlx-cli` or `refinery` for PostgreSQL; ClickHouse migration
  tooling TBD in Phase 3

## Metrics / Observability

- Prometheus: `prometheus` or `metrics` crate (Rust)
- Tracing: `tracing` + `tracing-subscriber` + OpenTelemetry exporter
- Structured logs: `tracing-subscriber` JSON formatter

## Mitigation Controller / BGP

- GoBGP as the BGP speaker, integrated via its gRPC API
- Controller language TBD by Phase-1 ADR (Rust gRPC client via `tonic`, or
  Go given GoBGP's native ecosystem)

## Public REST API / Internal gRPC API

- REST: `axum` (Rust) is the leading candidate — pairs naturally with
  `tokio`/`tower` middleware for auth, rate limiting, tracing
- gRPC: `tonic`
- OpenAPI generation: `utoipa` or hand-maintained spec — TBD Phase 1

## CLI (`tidegardctl`)

- `clap` for argument parsing, `serde`/`serde_json`/`serde_yaml` for
  output formats

## Web Application

- React + TypeScript + Vite + Tailwind CSS + shadcn/ui, charting via
  Recharts or Apache ECharts (leaning ECharts for NOC density — see
  architecture-options.md)

## Grafana

- Dashboard JSON authored directly (original layouts/UIDs), validated in
  CI with a JSON-schema or `jsonnet`/`grafonnet`-based approach — TBD
  Phase 6

## Authentication

- OIDC: `openidconnect` crate or a battle-tested auth proxy pattern — TBD
  Phase 8
- Password hashing: `argon2`

## CI/CD

- GitHub Actions, `cargo-audit`/`cargo-deny` for Rust dependency and
  license scanning, `trivy` or `grype` for container vulnerability
  scanning, `syft` for SBOM generation, `cosign` for image signing

## Documentation

- MkDocs Material (per master prompt default; Docusaurus only if an ADR
  overrides it — none proposed at this time)

## Note on Selection Status

Every item above is a **candidate**, not a commitment. Version pinning,
final selection, and license verification happen when the dependency is
actually introduced, each with its own entry in
[dependency-license-matrix.md](dependency-license-matrix.md).
