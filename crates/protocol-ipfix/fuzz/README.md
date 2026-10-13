# IPFIX Decoder Fuzz Targets

Requires a **nightly** Rust toolchain and `cargo-fuzz` — neither is
required for normal builds/tests of this workspace (`cargo build`/`test`/
`clippy`/`fmt` all work on stable, and CI's `validate.yml` workflow never
needs nightly). This directory is intentionally excluded from the main
workspace for that reason.

## Local Usage

```bash
rustup install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run decode_message
```

Run with a time limit for a quick local check:

```bash
cargo +nightly fuzz run decode_message -- -max_total_time=60
```

**Not executed in the environment this project was developed in** — no
nightly toolchain was installed there. See
`.github/workflows/fuzz.yml` for the scheduled/manual CI run, and
docs/risk-register.md R4 for the tracked follow-up.

## What's Covered

`fuzz_targets/decode_message.rs` fuzzes
`tidegard_protocol_ipfix::decode_message` — the same "never panics
on arbitrary bytes" property already covered by `proptest` in
`crates/protocol-ipfix/src/lib.rs`, but via libFuzzer's coverage-guided
mutation engine rather than proptest's random sampling.
