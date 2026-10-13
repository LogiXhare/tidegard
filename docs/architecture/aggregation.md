# Aggregation Architecture

Status: Phase 3

## Pipeline Shape

```text
IPFIX UDP datagram
  -> tidegard-protocol-ipfix (decode)
  -> tidegard-collector::normalize (IPFIX Data Record -> NormalizedFlow, sampling correction)
  -> tidegard-classifier::classify (direction, tenant, hostgroup)
  -> tidegard-aggregator::Aggregator::ingest (bounded, multi-dimensional aggregation)
  -> (optional) tidegard-storage (ClickHouse batch export)
```

Collector (UDP receive) and the classify/aggregate stage run as two
tasks connected by a bounded in-process channel — see
[ADR 0004](decisions/0004-collector-aggregator-event-transport.md). NATS
JetStream remains the direction for when the Aggregator needs to run as
an independently scaled process; not needed for Phase 3's scope.

## Normalized Flow Model

`tidegard_common::NormalizedFlow` is protocol-independent — nothing
downstream of `normalize_ipfix_record` (in `crates/collector/src/normalize.rs`)
knows IPFIX exists. A future NetFlow v9/v5 or sFlow v5 collector only
needs its own `normalize_*` function producing the same `NormalizedFlow`
type to reuse the classifier/aggregator/storage pipeline unchanged.

## Sampling Correction

Priority order (highest first), implemented in
`tidegard_common::sampling::resolve`:

1. Record-level sampling information (rare for IPFIX; some exporters
   attach a `samplingInterval` field directly on the data record)
2. Options-template sampling information (the common case — an exporter's
   Options Template Set declares sampling rate per interface, consumed by
   `tidegard-protocol-ipfix`'s `TemplateCache`)
3. Exporter-specific configured sampling rate (operator config)
4. Global default sampling rate (operator config)
5. Rate `1` (unsampled) if nothing above declares a usable rate

A declared rate of exactly `0` is treated as "not usable" and the
resolver falls through to the next tier — never constructed as a real
`SamplingRate` (which is a `NonZeroU32` by construction). Overflow during
correction (`raw × rate` exceeding `u64::MAX`) rejects the flow rather
than wrapping or panicking — see `NormalizedFlowBuilder::build`.

**Double-correction prevention** is structural, not a runtime check:
`NormalizedFlow::bytes`/`packets` are always post-correction; there is no
public API to re-apply correction to an already-built `NormalizedFlow`,
and correction happens exactly once, inside `normalize_ipfix_record`.

## Direction Classification

See [direction-classification.md](direction-classification.md).

## Bounded In-Memory Aggregation

See [ADR 0003](decisions/0003-in-memory-aggregation-structure.md) for the
bounded-`HashMap`-plus-eviction design. Every dimension (host, network,
/24, hostgroup, ASN, exporter, interface, protocol) shares the same
`BoundedMap` implementation (`crates/aggregator/src/bounded_map.rs`),
tested once rather than once per dimension.

**Two-sided accounting**: per-host, per-network, per-ASN, and
per-hostgroup dimensions count traffic toward *both* the source and
destination ends of a flow — matching how "top talkers" views are
conventionally read. Total traffic and per-exporter/per-interface/
per-protocol dimensions are naturally single-sided (there's exactly one
exporter, one pair of interfaces, one protocol per flow).

### Configured Prefix Lengths

IPv4 always gets a `/24` dimension regardless of configuration
(`Aggregator::ipv4_slash24`), plus any additional lengths in
`AggregatorConfig::ipv4_prefix_lengths`. IPv6 has no implicit default —
only `AggregatorConfig::ipv6_prefix_lengths` produces network-dimension
entries. See [../configuration/aggregation.md](../configuration/aggregation.md).

## Rate Windows

1s / 5s / 15s / 1m / 5m tumbling windows over **processing time**
(`Instant::now()` when the flow is ingested), not the flow's own
declared timestamps. This single design choice resolves all four
handling requirements at once:

- **Exporter clock skew**: irrelevant — only the collector's own clock is
  used for windowing.
- **Missing timestamps**: irrelevant for the same reason.
- **Late records**: counted in whichever window they *arrive* in; no
  out-of-order/watermark logic exists or is needed.
- **Long-duration flows**: a flow's entire byte/packet count lands in the
  single window it was received in, not spread proportionally across its
  duration — a documented simplification (see
  `crates/aggregator/src/rate_window.rs` module docs), not a hidden gap.

Only *total* traffic gets rate windows today (`Aggregator::total_rates`)
— maintaining five windows per tracked host/network/etc. would multiply
memory cost by 5× per entry for a capability nothing in Phase 3 requires
per-entity; per-entity rate curves are expected to come from ClickHouse
time-bucketed queries instead.

## Bounded-Memory Controls

| Control | Mechanism |
|---|---|
| Maximum tracked hosts/networks/hostgroups/ASNs | Per-dimension `BoundedMapConfig.max_entries`, configurable (see [../configuration/aggregation.md](../configuration/aggregation.md)) |
| Inactivity expiration | `BoundedMapConfig.inactivity_ttl`, swept every 30s (`EXPIRATION_INTERVAL` in `crates/collector/src/lib.rs`) |
| Deterministic eviction | Least-recently-updated entry evicted when a dimension is at capacity — see [ADR 0003](decisions/0003-in-memory-aggregation-structure.md) |
| Queue limits | The bounded mpsc channel between receive and process stages — `TIDEGARD_COLLECTOR_QUEUE_CAPACITY` |
| High-cardinality protection | The combination of the above — no dimension can grow past its configured cap regardless of input cardinality |

## Malformed Input Handling

- **Malformed normalized flows rejected**: `NormalizedFlowBuilder::build`
  rejects a flow with zero bytes *and* zero packets
  (`FlowError::Empty`), and rejects sampling-correction overflow
  (`FlowError::SamplingOverflow`).
- **Missing fields handled safely**: optional fields (ports, protocol,
  interfaces, ASNs, timestamps) are `None` rather than causing rejection;
  only missing source/destination addresses reject the record
  (`NormalizeError::MissingAddresses`).
- **Duplicate flows**: not deduplicated in Phase 3 — an exporter that
  retransmits the same flow record (e.g. after a network hiccup) will be
  double-counted. This is a known, documented limitation; deduplication
  (typically via a flow key + short time window) is deferred — no
  evidence yet that it's needed given IPFIX's UDP delivery model doesn't
  itself retransmit.
