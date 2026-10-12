# Flow Replay Tool

Status: Phase 3 — extended from the Phase 2 IPFIX-only version.

`tools/flow-replay` sends **synthetic-only** IPFIX traffic over UDP to a
target collector. See docs/security-principles.md: never point this at
anything but a lab/test collector you control, and never use it (or
anything else) to generate real attack traffic.

## Usage

```bash
cargo run -p wetechinetmon-flow-replay -- <target_host:port> [options]
```

| Option | Values | Default |
|---|---|---|
| `--count N` | number of data records to send | `5` |
| `--scenario S` | `incoming` \| `outgoing` \| `internal` \| `other` | `incoming` |
| `--family F` | `ipv4` \| `ipv6` | `ipv4` |
| `--protocol P` | `tcp` \| `udp` \| `icmp` | `tcp` |
| `--exporters N` | number of distinct observation domains to simulate | `1` |
| `--sampling-rate N` | advertise this rate via an Options Template | none |

## Rate Mode (load and soak tests)

`--rate N` sends N IPv4 flow records a second for `--duration-secs`,
40 to a datagram, over `--hosts` local hosts (default 1,000, in
`10.0.0.0/8`) from 50 remote ones in `203.0.113.0/24`. It paces itself
against the clock and ends with one line a script can read:

```text
load: sent 6000000 records in 150000 datagrams over 60.000 s (100000 records/s)
```

`scripts/load_test.py` uses it for the Phase 9B load and soak tests
([ADR 0054](../architecture/decisions/0054-phase9b-load-and-soak.md)),
comparing what was sent with what the collector parsed. As with every
mode, point it only at a collector you run.

## Address Convention

The tool doesn't know the target collector's configured local prefixes,
so it uses a fixed, documented convention:

- **Local**: `10.0.0.0/8` (IPv4), `2001:db8::/32` (IPv6)
- **External**: `203.0.113.0/24` / `198.51.100.0/24` (RFC 5737
  TEST-NET-2/3, reserved for documentation) for IPv4; `2606:4700::/32` /
  `2620:fe::/32` for IPv6

For `--scenario` to actually produce the direction you expect, point the
collector under test at a local-prefix configuration matching this
convention:

```bash
export WETECHINETMON_COLLECTOR_LOCAL_PREFIXES="10.0.0.0/8@test@lab,2001:db8::/32@test@lab-v6"
```

## Examples

```bash
# Basic incoming IPv4 TCP traffic
cargo run -p wetechinetmon-flow-replay -- 127.0.0.1:2055 --count 10

# IPv6 UDP, outgoing, with a declared 1:100 sampling rate
cargo run -p wetechinetmon-flow-replay -- 127.0.0.1:2055 \
  --scenario outgoing --family ipv6 --protocol udp --sampling-rate 100

# Simulate 3 separate exporters sending internal ICMP traffic
cargo run -p wetechinetmon-flow-replay -- 127.0.0.1:2055 \
  --scenario internal --protocol icmp --exporters 3
```

## What It Builds

`tools/flow-replay/src/synthetic.rs` constructs real, well-formed IPFIX
messages byte-for-byte:

- `template_message_ipv4`/`template_message_ipv6` — Template Sets for a
  7-field record (source/destination address, ports, protocol, bytes,
  packets)
- `data_message_ipv4`/`data_message_ipv6` — matching Data Sets
- `options_template_message` / `options_data_message` — an Options
  Template declaring `samplingInterval`, scoped by `ingressInterface`,
  and its Data Set

Every builder function has a round-trip test decoding its own output
through the real `wetechinetmon-protocol-ipfix` decoder — the same
exercise a live exporter's traffic gets.

## Verifying a Test Run

```bash
curl -s http://localhost:9090/metrics | grep -E \
  "normalized_flows_total|classified_flows_by_direction|corrected_samples"
```

`classified_flows_by_direction_total{direction="..."}` should match the
`--scenario` you sent; `corrected_samples_total` should increase only
when `--sampling-rate` was used.
