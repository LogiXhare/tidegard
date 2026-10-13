# Common Library

**Status:** Implemented (Phase 2: structured logging; Phase 3: normalized
flow model and sampling correction).

Shared, cross-cutting code used by more than one Tidegard service.
Deliberately small — this is not a dumping ground for unrelated helpers.

- `logging` — shared JSON structured-logging setup
  (`tidegard_common::logging::init()`).
- `flow` — `NormalizedFlow`, the protocol-independent flow record every
  collector (IPFIX today, NetFlow/sFlow later) converts into. See
  [../../docs/architecture/aggregation.md](../../docs/architecture/aggregation.md).
- `sampling` — sampling-rate resolution implementing the documented
  priority order (record-level → options-template → exporter-configured
  → global default → unsampled), with zero-rate rejection and overflow
  handling.

## Testing

```bash
cargo test -p tidegard-common
```

18 tests covering logging setup, flow normalization/validation, and
sampling-rate resolution across all priority tiers.
