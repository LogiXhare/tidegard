# Testing Detection

How the detection engine is tested, and how to exercise it by hand.

## Layers

**Unit tests** live beside the code, one module at a time: the state
machine's transitions, threshold evaluation, policy validation,
precedence, event identity, windowing arithmetic, the sinks, and the
config loader.

**Integration tests** in `crates/detector/tests/detection_lifecycle.rs`
drive the crate through its public API only — synthetic flows in,
detection events out. They exercise the same path the collector does, so
they would notice a component that works alone but not in sequence.

**Property tests** in the same file assert the invariants no unit test
can establish across a whole run:

| Property | Why it matters |
|---|---|
| Events form well-nested detections | An incident tracker that receives two starts without an end between has no way to know which detection the eventual end belongs to. |
| Sequence numbers are gapless within a detection | A gap must mean a lost event, which only works if the engine never leaves one. |
| Dedup keys are unique across a run | An at-least-once transport must collapse repeats without collapsing distinct events. |
| A reported crossing carries a rate that actually crosses | The engine may never say "over threshold" while carrying a figure that is not. |
| Absurd volumes do not panic | A detector that panics on absurd input is a detector an attacker can switch off. |

**Capacity tests** prove the two bounds behave differently on purpose:
the windowing layer evicts under pressure and counts it, while the state
table refuses new scopes and never drops an open detection to make room.

## Running them

```powershell
cargo test -p tidegard-detector
cargo test -p tidegard-detector --test detection_lifecycle
cargo test --workspace
```

The full gate before anything is merged:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

## Exercising it by hand

`flow-replay` can generate traffic shapes that make a policy fire, hold,
and clear. Each pattern varies volume over time and nothing else — every
record is the same synthetic, well-formed IPFIX record the tool has
always sent. No spoofed sources, no amplification payloads, nothing
resembling real attack traffic. **Only ever point it at a lab collector
you control** — see [security-principles.md](../security-principles.md).

| Pattern | What it should prove |
|---|---|
| `steady` | A policy at a sane threshold stays silent. |
| `flood` | A sustained crossing opens exactly one detection. |
| `spike` | A crossing shorter than `triggerFor` opens nothing. |
| `flap` | Hysteresis and `cooldown` stop one attack becoming ten events. |
| `ramp` | A detection opens when the rate crosses, not when it starts rising. |

```powershell
cargo run -p tidegard-flow-replay -- 127.0.0.1:2055 `
  --pattern flood --duration-secs 40 --peak-bps 10000000
```

Each run prints what to expect before it starts and again when it
finishes, so a failed expectation is obvious without reading the source.

### A lab policy that matches the tool's addresses

`flow-replay` uses `10.0.0.0/8` as "local" and `203.0.113.0/24` as
"external" — see [flow-replay.md](flow-replay.md). A policy document
matching that convention:

```json
{
  "schemaVersion": 1,
  "tenants": [ { "tenant": "lab", "prefixes": ["10.0.0.0/8"] } ],
  "policies": [
    {
      "id": "lab-host-inbound",
      "name": "lab host inbound",
      "tenant": "lab",
      "scopeType": "host",
      "direction": "incoming",
      "window": "1s",
      "thresholds": { "bps": "5M" },
      "triggerFor": "3s",
      "clearFor": "3s",
      "cooldown": "20s",
      "executionMode": "alertOnly"
    }
  ]
}
```

Run the collector with it:

```powershell
$env:TIDEGARD_COLLECTOR_LOCAL_PREFIXES = "10.0.0.0/8=lab"
$env:TIDEGARD_COLLECTOR_DETECTION_POLICY_FILE = "lab-policies.json"
$env:TIDEGARD_COLLECTOR_DETECTION_WINDOW_SECS = "1"
cargo run -p tidegard-collector
```

Then send `--pattern flood` at it and watch the log. The detection
appears as a `warn` line naming the target, the policy, and how far over
threshold it was.

**The window must match.** `TIDEGARD_COLLECTOR_DETECTION_WINDOW_SECS`
and every policy's `window` have to agree, or nothing is evaluated —
visible as `snapshots_ignored_total{reason="windowMismatch"}` climbing.

## What is not tested here

**ClickHouse writes.** No live server is available in this environment.
`DetectionEventRow` conversion is unit-tested, and the batching and retry
machinery is tested in `crates/storage`, but the wiring has never been
exercised against a real ClickHouse — same caveat as Phase 3's export
path, recorded in [clickhouse.md](../integrations/clickhouse.md).

**Throughput.** No detection benchmark has been run on representative
hardware, so no throughput figure is published. An invented number is
worse than none.

**The collector's full loop under load.** The detection stage is tested
directly and the collector's wiring is unit-tested, but the two have not
been run together against sustained real-rate traffic.

## See also

- [Detection engine architecture](../architecture/detection-engine.md)
- [Configuring detection policies](../configuration/detection-policies.md)
- [Flow Replay tool](flow-replay.md)
