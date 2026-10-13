# Traffic Aggregator

**Status:** Implemented (Phase 3).

Bounded, multi-dimensional aggregation over `NormalizedFlow`s (hosts,
networks, /24, configurable prefix lengths, hostgroups, ASNs, exporters,
interfaces, protocols), 1s/5s/15s/1m/5m rate windows, deterministic
eviction and inactivity expiration. See
[../../docs/architecture/aggregation.md](../../docs/architecture/aggregation.md)
and [ADR 0003](../../docs/architecture/decisions/0003-in-memory-aggregation-structure.md).

## Known limitations

- Only *total* traffic gets rate windows — per-entity rate windows would
  multiply memory 5× per tracked entry for a capability nothing in
  Phase 3 requires. Per-entity rates are expected from ClickHouse
  time-bucketed queries instead.
- Interface dimension is keyed by interface index alone, not
  `(exporter, interface index)` — see
  [../../docs/integrations/clickhouse.md](../../docs/integrations/clickhouse.md)
  "Known Limitations."

## Testing

```bash
cargo test -p tidegard-aggregator
```

26 tests: bounded-map eviction/expiration, per-dimension aggregation
(including two-sided host/network/ASN/hostgroup accounting), rate-window
finalization, and counter saturation.
