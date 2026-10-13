# Detection Engine

Status: Phase 4 — implemented in `crates/detector`, wired into the
collector, off unless a policy document is configured.

The detection engine decides that traffic toward or from something you
own is abnormal, and says so in an event that explains itself. It cannot
do anything about it — see
[ADR 0007](decisions/0007-detection-engine-cannot-mitigate.md) and
[detection-safety.md](../security/detection-safety.md).

## The pipeline

```text
NormalizedFlow ──► classify ──► DetectionWindows ──► DetectionSnapshot
   (Phase 2)      (Phase 3)      (per scope,          (rates + how much
                                  direction-aware)      to trust them)
                                                              │
                                                              ▼
                                                    PolicySet::select
                                                     (one winner per scope)
                                                              │
                                                              ▼
                                                         evaluate
                                                   (which thresholds crossed)
                                                              │
                                                              ▼
                                                        StateTable::step
                                                   (triggerFor / clearFor /
                                                    holdDown / cooldown)
                                                              │
                                                              ▼
                                                     EventFactory::build
                                                              │
                                                              ▼
                                              DetectionEventSink (tracing,
                                                    ClickHouse, in-memory)
```

Each stage is a separate module with one job. `engine.rs` is the only
piece that knows the order.

## Why the detector counts traffic itself

Phase 3's aggregator is two-sided and direction-blind: a flow between A
and B counts against both, and the entry never records which way it was
going. Right for analytics, wrong for detection, where inbound and
outbound floods are different incidents needing different thresholds.

So the detector keeps its own counters, reusing the aggregator's public
`BoundedMap` and `TrafficCounters` without modifying Phase 3. Full
reasoning in
[ADR 0010](decisions/0010-detector-owns-its-windowed-counters.md).

**A consequence worth knowing before you file a bug:** the `bps` on a
detection event and the `bytes` in `wetechinetmon_host_traffic` for the
same host will not agree. They are counting different things — one is
one direction over one window, the other is both directions
cumulatively. That is correct.

### Which side is the target

| Classified direction | Scoped on | Reported as |
|---|---|---|
| `Incoming` | destination | `incoming` |
| `Outgoing` | source | `outgoing` |
| `Internal` | destination **and** source | `incoming` and `outgoing` |
| `Other` | nothing | counted as unscoped |
| `Unknown` | nothing | counted as unscoped |

`Internal` counting both sides is what makes an internal host being
flooded visible as incoming, and an internal host doing the flooding
visible as outgoing, without a separate scope type for either.

### Scopes

| Scope | Key | Specificity |
|---|---|---|
| `host` | one address | 40 |
| `prefix` | the configured local prefix the address matched | 30 |
| `slash24` | the implicit IPv4 /24 containing the address | 20 |
| `hostgroupTotal` | every address in one hostgroup, summed | 10 |

ASN and interface scopes are not implemented — see
[follow-ups.md](../development/follow-ups.md).

### Windows tumble

Counters accumulate for one window, are emitted, and are cleared. A
rolling window would need a per-scope ring buffer, which at a hundred
thousand scopes is hundreds of megabytes rather than a few.

Rates are computed from the time that **actually elapsed**, not from the
configured window, so a late tick reports the truth rather than an
inflated rate. The snapshot still carries the configured window, because
that is what a policy matches on. A tick more than 10% away from the
configured window increments `skewed_ticks`.

## Absent data is not zero

A metric whose source field the exporter never sent is **skipped**, not
compared against zero. Without this, a `droppedPps` threshold on an
exporter that sends no forwarding-status field would report "0 dropped
pps, nothing wrong" forever, which is indistinguishable from a healthy
network and is not the same fact.

| Metric | Requires |
|---|---|
| `tcpSynBps`, `tcpSynPps` | TCP flags present on at least one flow |
| `fragmentedBps`, `fragmentedPps` | fragmentation reported on at least one flow |
| `droppedBps`, `droppedPps` | a forwarding-status field on at least one flow |

Skipped metrics appear on the event in `skipped`, with the reason. A
policy whose thresholds were *all* skipped never opens a detection and
never clears one either: with nothing evaluated, the engine cannot claim
the traffic is below its clear level.

## Policy precedence

Several policies may match one scope; exactly one wins. In order:

1. **Specificity** — a host policy beats a prefix policy beats a /24
   policy beats a hostgroup policy. A policy naming a specific target
   beats one using `any`. A tenant-named policy beats a wildcard-tenant
   one.
2. **Priority** — higher wins.
3. **Policy id** — lowest wins, so the outcome is deterministic rather
   than dependent on load order.

The losers are recorded alongside the winner, so "why did this host page
me under that policy?" is answerable without re-deriving the whole
configuration by hand.

## Hysteresis and the four timers

A threshold comparison alone is not a detection. Traffic crosses a line
and falls back constantly, and an engine that paged on every crossing
would be useless within an hour.

| Timer | What it does |
|---|---|
| `triggerFor` | how long the crossing must persist before a detection opens |
| `clearFor` | how long the recovery must persist before it closes |
| `holdDown` | minimum time a detection stays open once opened, regardless of traffic |
| `cooldown` | how long after closing before the same scope may open another |

Plus `clearPercent`: the clear threshold is that percentage of the
trigger threshold. Between the two is a **hysteresis band** where
traffic neither opens a new detection nor begins clearing an existing
one. Integer arithmetic throughout, so an operator can reproduce every
number by hand.

### States

```text
        threshold crossed
  Idle ───────────────────► PendingTrigger
   ▲                             │  sustained for triggerFor
   │ cooldown expired            ▼
Cooldown ◄──────────────────  Active ◄───────────┐
   ▲   clear sustained            │              │ traffic returned
   │                              │ fell to clear│
   └──────────────────────── PendingClear ───────┘
                              clear sustained
```

Every transition records where it came from, where it went, why, under
which policy version, how long it had been in the previous state, and
what the traffic looked like. Illegal edges are refused by a guard
rather than assigned, so an edit that introduces an edge nobody reasoned
about fails instead of silently entering a state whose timers mean
nothing.

`PendingTrigger` requires the *trigger* threshold continuously —
hysteresis governs leaving `Active`, not aborting a trigger that never
completed. `PendingClear` likewise requires the clear condition
continuously: traffic in the hysteresis band is not recovering, so it
aborts the clear and returns to `Active`.

## Restart and staleness

**Runtime state is not persisted.** On restart every scope begins at
`Idle`, so a detection open before the restart is re-derived from live
traffic rather than resumed from a record that may no longer be true.
The trade-off is explicit: a restart during an attack costs one
`triggerFor` of re-detection latency and emits a second start event,
which is recoverable; resuming a persisted `Active` state that no longer
reflects reality is not.

**Detection events are persisted; detector state is not.** These are
different things and it is worth being blunt about which is which.
Runtime state — where each scope sits in the state machine, its timers,
its accumulated peaks — lives only in memory and is deliberately
disposable, because its only job is to decide what happens next, and
"what happens next" is better derived from traffic arriving now than
from a record written before a restart. Detection *events* are the
opposite: an immutable record of something that was true at an instant,
written once to `wetechinetmon_detection_events` and never updated.
Losing runtime state costs one `triggerFor` of latency; losing events
costs the audit trail. There is deliberately no store abstraction over
the runtime state, because introducing one would suggest a persistence
option that is not wanted here — see
[ADR 0010](decisions/0010-detector-owns-its-windowed-counters.md) for
where the detector's state lives and why.

**A scope that stops reporting is force-closed.** If no snapshot arrives
for an open detection for longer than the stale timeout, the detection
is closed with reason `stale` and a zeroed rate. Without this, an
exporter that fails mid-attack leaves a detection open forever. The
event says `stale` rather than `clearSustained`, so nobody has to guess
whether the traffic stopped or the telemetry did.

**An absent scope is not a cleared scope.** A window that closes with no
traffic for a scope produces no snapshot for it at all — it does not
produce a zero. Only the stale sweep closes such a detection.

## Bounds

Two bounds, deliberately behaving differently:

- The **windowing layer** evicts the least-recently-updated scope when
  full, and counts it. Losing a counter costs at most one window of
  visibility.
- The **state table** refuses new scopes when full, and never evicts a
  tracked one. LRU eviction there would silently discard an open
  detection and its end event, turning a memory bound into a correctness
  bug. Refusals are counted as
  `tidegard_detector_state_table_full_total` — each one is a
  detection that could not be opened.

## Events

One start, zero or more updates paced by `eventUpdateInterval`, one end.
Every event carries the policy id and version, the thresholds actually
compared against, the peak of the detection so far, the completeness
flags, and the sampling status — enough to explain itself without
joining against configuration that may since have changed.

Three identifiers doing three jobs — `event_id`, `detection_id`,
`dedup_key` — plus a gapless `sequence`. See
[ADR 0009](decisions/0009-detection-event-identity.md).

Every event also carries `executed`, always `false` in this phase and
structurally so — see
[detection-safety.md](../security/detection-safety.md).

Events reach a tracing sink always, and a ClickHouse sink
(`wetechinetmon_detection_events`, 365-day retention) when ClickHouse
export is configured. A fan-out sink attempts every sink even after one
fails: a detection reaching the log but not the database is far better
than it reaching neither.

## See also

- [Configuring detection policies](../configuration/detection-policies.md)
- [Monitoring detection](../operations/detection-monitoring.md)
- [Detection safety](../security/detection-safety.md)
- [Testing detection](../development/detection-testing.md)
