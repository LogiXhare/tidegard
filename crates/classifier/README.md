# Direction Classifier

**Status:** Implemented (Phase 3).

Tenant-aware local-prefix registry (IPv4 + IPv6, binary trie, longest-
prefix match — [ADR 0002](../../docs/architecture/decisions/0002-prefix-lookup-data-structure.md))
and traffic direction classification
(Incoming/Outgoing/Internal/Other/Unknown, with explainable diagnostics
— FR-3.3). See
[../../docs/architecture/direction-classification.md](../../docs/architecture/direction-classification.md).

## Testing

```bash
cargo test -p tidegard-classifier
```

29 tests: trie insertion/lookup/overlap/duplicate detection, registry
construction and validation, direction classification (both address
families, all four directions plus Unknown), and 2 `proptest` properties.
