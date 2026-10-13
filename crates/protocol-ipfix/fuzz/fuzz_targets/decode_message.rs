//! cargo-fuzz target for `tidegard_protocol_ipfix::decode_message`.
//!
//! This is the coverage-guided complement to the `proptest` properties
//! in `crates/protocol-ipfix/src/lib.rs` — same "never panics on
//! arbitrary bytes" property, exercised via libFuzzer's mutation engine
//! instead of proptest's random sampling. Requires a nightly Rust
//! toolchain; see docs/development/local-setup.md for the local command
//! and `.github/workflows/fuzz.yml` for the scheduled CI run — neither
//! has been executed in the environment this was developed in (no
//! nightly toolchain installed here), flagged in docs/risk-register.md
//! R4, not silently skipped.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tidegard_protocol_ipfix::{decode_message, TemplateCache};

fuzz_target!(|data: &[u8]| {
    let mut cache = TemplateCache::new();
    let _ = decode_message(data, &mut cache);
});
