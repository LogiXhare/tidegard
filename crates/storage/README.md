# Storage Layer

**Status:** Implemented (Phase 3) — ClickHouse output only; PostgreSQL
(config/metadata, Phase 5) and InfluxDB-compatible output are later.

Original ClickHouse schemas (9 tables), a bounded batch writer, and a
bounded retry queue with exponential backoff and drop-oldest-on-overflow
— see [ADR 0005](../../docs/architecture/decisions/0005-clickhouse-batching-and-retry.md)
and [../../docs/integrations/clickhouse.md](../../docs/integrations/clickhouse.md).

**Not verified against a live ClickHouse server** — none was available
in this development environment. All batching/retry/schema logic is
unit-tested; the actual network write path has an integration test
(`tests/clickhouse_integration.rs`) that skips cleanly, printing why,
when `CLICKHOUSE_TEST_URL` is unset.

## Testing

```bash
cargo test -p tidegard-storage
```

13 unit tests (batch queue, retry backoff/overflow, schema/DDL shape,
counter conversion) + 1 integration test (skips without a live server).
