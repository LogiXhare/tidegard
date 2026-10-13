# Flow Replay Tool

**Status:** Implemented (Phase 2: basic IPv4; Phase 3: IPv4/IPv6,
protocols, sampling, multi-exporter scenarios).

Sends synthetic, well-formed IPFIX messages over UDP to a target
collector — for local/lab testing only. See
[../../docs/security-principles.md](../../docs/security-principles.md):
this tool must only ever be pointed at an authorized lab collector you
control, and only ever sends synthetic data (see `src/synthetic.rs`) —
never real captured traffic and never anything resembling attack traffic.

## Usage

```bash
cargo run -p tidegard-flow-replay -- <target_host:port> [options]
```

See [../../docs/development/flow-replay.md](../../docs/development/flow-replay.md)
for the full option reference (`--count`, `--scenario`, `--family`,
`--protocol`, `--exporters`, `--sampling-rate`) and the address
convention used for `--scenario`.

## Testing

```bash
cargo test -p tidegard-flow-replay
```

5 tests, including round-trip tests (IPv4, IPv6, and Options-Template
sampling) that build synthetic messages with this tool's own byte-
building code and decode them with the real
`tidegard-protocol-ipfix` decoder, confirming the values survive
unchanged — the same path a live exporter's traffic would take.
