# IPFIX Protocol Parser

**Status:** Implemented (Phase 2 MVP scope).

Clean-room IPFIX (RFC 7011, RFC 7012, RFC 7015) message decoder, built
entirely from the public IETF RFCs and the public IANA IPFIX Information
Elements registry. See [../../docs/clean-room-boundary.md](../../docs/clean-room-boundary.md).

## Scope

Implemented: message header parsing, Template Sets, Options Template
Sets, Data Sets (fixed and variable-length fields), per-exporter template
caching (`TemplateCache`), and structural extraction of sampling
parameters from Options Template data (`SamplingInfo`).

**Known limitations** (documented, not silent gaps):

- Only a small subset of IANA Information Elements are semantically
  interpreted (via `DecodedField::as_u64_be`/`as_ipv4`/`as_ipv6` helpers on
  raw bytes) — full IE-by-IE typing is deferred to whichever later phase
  needs it (see crate-level docs in `src/lib.rs`).
- Sequence-number-based exporter-restart detection (in
  `tidegard-collector`, which owns per-exporter `TemplateCache`
  instances) does not handle 32-bit wraparound specially.
- True coverage-guided fuzzing (`cargo-fuzz`/libFuzzer) requires a nightly
  Rust toolchain, not installed in this environment. Property-based tests
  (`proptest`, see `src/lib.rs`'s `proptests` module) cover the same
  "never panics on arbitrary bytes" safety property via random sampling
  instead, and are run as part of `cargo test`. Adding real `cargo-fuzz`
  coverage is tracked as a follow-up, not silently skipped — see
  [../../docs/risk-register.md](../../docs/risk-register.md) R4.

## Testing

```bash
cargo test -p tidegard-protocol-ipfix
```

34 tests: unit tests per module (header/template/record/template_cache/
decoder) plus three `proptest` properties asserting the decoder never
panics on arbitrary or malformed input.
