# IPFIX Collector Guide

Status: Phase 2

## What This Covers

How to point an IPFIX exporter at `tidegard-collector` and verify
it's receiving and decoding flows. This is a Phase 2 MVP guide — NetFlow
v9/v5 and sFlow v5 exporter guides will be added when those protocols are
implemented (see [../roadmap.md](../roadmap.md)).

## 1. Start the Collector

```bash
export TIDEGARD_COLLECTOR_BIND=0.0.0.0:2055
export TIDEGARD_COLLECTOR_METRICS_BIND=0.0.0.0:9090
export RUST_LOG=info
cargo run --bin tidegard-collector
```

Full option reference: [../configuration/index.md](../configuration/index.md).

## 2. Point an Exporter at It

### Generic router/exporter

Configure your device to export IPFIX to the collector's host on the UDP
port from `TIDEGARD_COLLECTOR_BIND` (default `2055`).

### Cisco NCS540 (reference lab device)

The reference lab configuration in
`prompts/CLAUDE_MASTER_PROMPT.md` §4 uses:

- Router telemetry/BGP IP: `203.0.113.1`
- Collector IP: `203.0.113.2/30`
- Protocol: IPFIX, UDP port `2055`

These are **lab reference values only** — never hardcode them; configure
your own deployment's actual addresses via
`TIDEGARD_COLLECTOR_BIND`. Cisco NCS540-specific IPFIX export
configuration (flow monitor / flow exporter / sampler CLI) will be
documented here once validated against real hardware — not fabricated
from memory in the meantime.

## 3. Verify Flows Are Being Received

```bash
curl -s http://localhost:9090/metrics | grep tidegard_collector
```

Expect `tidegard_collector_flow_datagrams_received_total` and
`tidegard_collector_parsed_flow_records_total` to increase. If
`tidegard_collector_parser_failures_total` increases instead, check
the collector's structured logs (`RUST_LOG=debug`) for the specific
`DecodeError` reported per datagram.

If `tidegard_collector_unknown_templates_total` increases and stays
elevated, the exporter's Data Sets are arriving before (or without) their
Template Set — check the exporter's template-refresh interval.

## 4. Test Safely Without a Real Exporter

Use the replay tool to send synthetic IPFIX traffic instead of pointing a
real router at a test collector:

```bash
cargo run -p tidegard-flow-replay -- 127.0.0.1:2055 10
```

See [tools/flow-replay/README.md](https://github.com/LogiXhare/tidegard/blob/main/tools/flow-replay/README.md).
Per [../security-principles.md](../security-principles.md), never use
real captured traffic or anything resembling attack traffic for testing —
synthetic fixtures only.

## Known Limitations (Phase 2)

- Only IPFIX is supported; NetFlow v9/v5 and sFlow v5 are later phases.
- No exporter authentication or allowlisting yet (FR-1.9) — anyone who can
  reach the UDP port can send it messages. Treat the collector's bind
  address as untrusted-network-facing and firewall accordingly until
  allowlisting ships.
- No TLS/encryption — IPFIX over UDP is inherently unauthenticated at the
  protocol level; this is a known IPFIX characteristic, not specific to
  this implementation.
