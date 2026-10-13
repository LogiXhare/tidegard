# 0010. The Detector Keeps Its Own Windowed Counters

Status: Accepted
Date: 2026-08-22
Deciders: WeTechi Solutions (badshashorif)

## Context

Phase 3 built an aggregator that already counts traffic per host, per
network, per /24, per hostgroup, per ASN, and per exporter
([ADR 0003](0003-in-memory-aggregation-structure.md),
[aggregation.md](../aggregation.md)). Phase 4 needs per-scope traffic
rates to compare against thresholds. The obvious move is to read the
aggregator.

Two properties of the Phase 3 aggregator make that not work.

**It is direction-blind.** A flow between A and B increments the entry
for A *and* the entry for B, and neither entry records which way the
traffic was going. That is right for analytics — "how much did this host
move" — and wrong for detection, where "10 Gbps arriving at this host"
and "10 Gbps leaving it" are different incidents needing different
thresholds. A host serving a large download would trip an inbound flood
policy.

**Its per-key entries are cumulative, not windowed.** Rate windows exist
only for the global total (`total_rates`). A per-key entry is a running
`TrafficCounters` since the entry was created. Deriving a rate from it
requires remembering the previous reading and the interval, which is a
windowing layer — the thing this ADR is about — bolted onto the outside.

So the choice is where the direction-aware, windowed counters live.

## Options Considered

### Option A — Add direction and rate windows to the Phase 3 aggregator

Widen the aggregation key with a direction dimension, and give every key
a `RateWindowSet`.

This multiplies the aggregator's memory by the number of directions and
by the number of window sizes, for every consumer — including the
ClickHouse analytics export, which wants neither. It also changes the
meaning of every existing table: `wetechinetmon_host_traffic` would
either double its rows or need a direction column, and either is a
breaking change to a schema already in use.

It also breaks the documented Phase 3 contract that the aggregator is
two-sided, which downstream analytics queries rely on.

### Option B — The detector keeps its own counters

`tidegard-detector` maintains direction-aware, scope-keyed,
windowed counters, reusing the aggregator's **public** `BoundedMap` and
`TrafficCounters` types. Phase 3 is not modified at all.

Costs one extra counter update per flow per scope type, and one extra
bounded map per scope type.

### Option C — Derive rates from aggregator deltas

Sample the aggregator each window and subtract the previous reading.

No extra ingest cost, but it inherits the direction problem entirely,
and a sampled delta silently loses everything that happened to a key
between its eviction and its recreation. It also makes the detector's
correctness depend on the aggregator's eviction policy, which exists for
different reasons.

## Decision

**Option B.** Specifically:

- The detector counts each flow against the **local** side of it:
  destination for `Incoming`, source for `Outgoing`, and both for
  `Internal` (as incoming and outgoing respectively). A flow with no
  local side is counted as unscoped and dropped.
- Windows **tumble** rather than roll. Counters accumulate for one
  window, are emitted, and are cleared. A rolling window would need a
  per-scope ring buffer, which at a hundred thousand scopes is the
  difference between a few megabytes and a few hundred.
- Rates are computed from the time that **actually elapsed**, not from
  the configured window, so a late tick reports the truth rather than an
  inflated rate. The snapshot still carries the configured window,
  because that is what a policy matches on.
- Every map is bounded per scope type, and a `max_*` of zero disables
  that scope type outright.

## Consequences

**Good.** Phase 3 is untouched. Its tables, its documented two-sided
semantics, and its memory profile are all unchanged, and a deployment
that does not configure detection pays nothing.

**Good.** Detection thresholds mean what an operator expects: an inbound
policy fires on inbound traffic.

**Cost.** Two counter updates per flow instead of one. The detector's
update is the same saturating-add work the aggregator does, so the
ingest path roughly doubles in counting cost — still small next to
decoding and normalizing the record, but real, and worth measuring
before claiming a throughput figure.

**Cost.** Tumbling windows split a burst that straddles a boundary
across two snapshots, so a burst can read lower than its true peak.
Requiring `triggerFor` to be at least one full window (enforced by
policy validation) is what makes that acceptable: a burst short enough
to be halved by a boundary is also too short to trigger.

**Cost.** The detector's counters and the aggregator's can disagree,
because they count different things. An operator comparing a detection
event's `bps` against a `wetechinetmon_host_traffic` row will see
different numbers, and that is correct rather than a bug. Documented in
[detection-engine.md](../detection-engine.md).

**Follow-up.** ASN and interface scopes are not implemented. Both exist
in the aggregator and both are plausible detection scopes; neither is
needed for the flood cases Phase 4 targets. Recorded in
[follow-ups.md](../../development/follow-ups.md).
