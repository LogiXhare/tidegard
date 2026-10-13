# Direction Classification Architecture

Status: Phase 3 — implemented in `crates/classifier`.

## Rules (FR-3.1)

| Source | Destination | Direction |
|---|---|---|
| External | Local | Incoming |
| Local | External | Outgoing |
| Local | Local | Internal |
| External | External | Other |
| — (no local prefixes configured) | — | Unknown |

"Local" means the address matched a configured prefix in the
[`PrefixRegistry`](https://github.com/badshashorif/tidegard/blob/main/crates/classifier/src/registry.rs). `Unknown` is
returned when the registry has zero configured prefixes — direction is
undefined without any notion of "local," so the classifier says so rather
than guessing (Phase 3 objective 4).

## Prefix Lookup: Binary Trie

See [ADR 0002](decisions/0002-prefix-lookup-data-structure.md). Longest-
prefix-match, O(prefix length) per lookup, separate tries for IPv4 (32
bits) and IPv6 (128 bits) so the two address spaces can never be compared
against each other by accident.

## Registry Construction and Validation

`tidegard_classifier::build_registry` takes a list of
`PrefixConfigEntry` (network, prefix length, tenant, optional hostgroup)
and:

1. Inserts each entry into the appropriate (v4/v6) trie.
2. Collects **every** invalid entry (bad prefix length, exact duplicate)
   as an error, rather than stopping at the first one — an operator
   fixing a prefix list wants to see everything wrong in one pass.
3. Collects overlap diagnostics (a prefix contained within, or
   containing, another already-registered prefix) as non-fatal warnings.

An exact duplicate (same network + same prefix length) is a hard error.
An overlap (a /8 and a /24 within it, say) is expected and normal — it's
how you'd configure "this /8 is generally ours, this /24 within it
belongs to tenant X" — so it's reported, not rejected.

## Explainability (FR-3.3)

`classify()` returns a `ClassificationResult` with a `reason: String`
field spelling out exactly why a flow got its direction — which address
matched (or didn't) which prefix at what length, or why classification
was `Unknown`. This is the foundation for a future diagnostic API
endpoint (`/api/v1/system/diagnostics`-style, per FR-8.1) that lets an
operator ask "why was this flow classified this way?" — not yet exposed
over HTTP in Phase 3 (no Public API crate exists yet), but the underlying
explainability data already exists and is tested
(`crates/classifier/src/direction.rs` tests).

## Determinism

Given the same registry state and the same address, `lookup()` always
returns the same result — proven by
`trie::tests::deterministic_repeated_lookups_are_identical` and the
`longest_prefix_always_wins_regardless_of_insertion_order` property test
(insertion order never changes the outcome).

## Tenant and Hostgroup Ownership

Each matched prefix carries a `tenant: String` and optional
`hostgroup: Option<String>`. `ClassificationResult` surfaces both ends'
matches (`source_matched_tenant`, `destination_matched_hostgroup`, etc.),
feeding `tidegard-aggregator`'s hostgroup dimension directly — see
[aggregation.md](aggregation.md).
