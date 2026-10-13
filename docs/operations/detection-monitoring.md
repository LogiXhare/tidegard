# Monitoring Detection

Every metric below is exposed on the collector's existing `/metrics`
endpoint and is prefixed `tidegard_detector_`. None appears until a
policy document is configured — if you see no detector metrics at all,
detection is off.

## Metrics

| Metric | Type | Labels | What it tells you |
|---|---|---|---|
| `snapshots_evaluated_total` | counter | `scope_type` | Traffic snapshots handed to the engine. |
| `snapshots_unmatched_total` | counter | — | Snapshots no policy applied to. Normally the large majority. |
| `snapshots_ignored_total` | counter | `reason` | Snapshots the state machine refused. |
| `state_transitions_total` | counter | `from`, `to`, `reason` | Every state machine move. |
| `suppressed_total` | counter | `reason` | Crossings that deliberately produced no detection. |
| `events_total` | counter | `kind` | Events built, including observe-mode ones. |
| `events_published_total` | counter | `kind` | Events accepted by every sink. |
| `events_failed_total` | counter | `kind`, `sink` | Events at least one sink refused. |
| `thresholds_skipped_total` | counter | — | Thresholds not evaluated because the data never carried their source field. |
| `scopes_in_state` | gauge | `state` | Scopes currently in each detection state. |
| `tracked_scopes` | gauge | — | Scopes the windowing layer is accumulating counters for. |
| `state_table_full_total` | counter | — | Scopes refused admission. **Each one is a detection that could not open.** |
| `detections_stale_total` | counter | — | Open detections force-closed because snapshots stopped arriving. |

Every label value comes from a closed set — a state, a reason, a kind.
None carries an address, tenant, hostgroup, or policy id: a detector
labelled by target address grows one time series per attacked host.

That means you cannot ask Prometheus "which policy is firing". Use the
`wetechinetmon_detection_events` table for that; it is what the table is
for.

## What to alert on

**`state_table_full_total` increasing.** This is an availability
problem, not a tuning nit — the detector is refusing to track new scopes,
so a real attack on a newly seen address will not be detected. Raise
`TIDEGARD_COLLECTOR_DETECTION_MAX_SCOPES`, or find out why the
distinct-address count grew.

```promql
increase(tidegard_detector_state_table_full_total[15m]) > 0
```

**`events_failed_total` increasing.** An alert nobody received. Check
which sink from the `sink` label — `clickhouse` usually means the export
buffer filled because ClickHouse is slow or down.

```promql
increase(tidegard_detector_events_failed_total[5m]) > 0
```

**`detections_stale_total` increasing while traffic looks normal.** Either
attacks really are ending by their source going silent, or an exporter
stopped sending. Cross-check against
`tidegard_collector_flow_datagrams_received_total`.

**`snapshots_ignored_total{reason="windowMismatch"}` non-zero.** Your
policies' `window` does not match
`TIDEGARD_COLLECTOR_DETECTION_WINDOW_SECS`. Nothing is being
evaluated. This should be zero always.

```promql
tidegard_detector_snapshots_ignored_total{reason="windowMismatch"} > 0
```

## What to watch while tuning

**`scopes_in_state{state="active"}` sitting high.** Either you are under
sustained attack or a threshold is too low. Compare against
`events_total{kind="started"}` — many active scopes with few starts
means detections are opening and staying open, which is usually a
threshold problem.

**`suppressed_total{reason="cooldown"}` high.** Attacks are recurring
faster than `cooldown` allows a new detection. That is cooldown doing
its job, but if the number is large the attack may be flapping and worth
a longer `holdDown` instead.

**`suppressed_total{reason="holdDown"}` high.** Detections are trying to
close early and being held open. Usually means `holdDown` is longer than
attacks actually last.

**`thresholds_skipped_total` climbing.** Some thresholds are never being
evaluated because the exporters do not send those fields. Check the
`skipped` array on a recent event to see which. A `tcpSynPps` policy on
an exporter that omits TCP flags is a policy that will never fire, and
this counter is the only sign.

**`snapshots_ignored_total{reason="outOfOrder"}` or `{reason="duplicate"}`.**
Snapshots arriving late or twice. A few is harmless — they are dropped
and counted. A steady stream means something upstream is redelivering.

## Reading the events table

```sql
-- Detections open right now, worst first.
SELECT detection_id, tenant, target, direction, policy_id,
       top_metric, top_observed, severity, detected_at
FROM wetechinetmon_detection_events
WHERE kind = 'started'
  AND detection_id NOT IN (
    SELECT detection_id FROM wetechinetmon_detection_events WHERE kind = 'ended'
  )
ORDER BY top_ratio_percent DESC;
```

```sql
-- How long detections actually last, by policy. Use this to sanity-check
-- clearFor and holdDown against reality.
SELECT policy_id,
       count() AS detections,
       quantile(0.5)(duration_ms) / 1000 AS median_secs,
       quantile(0.95)(duration_ms) / 1000 AS p95_secs
FROM wetechinetmon_detection_events
WHERE kind = 'ended' AND timestamp > now() - INTERVAL 7 DAY
GROUP BY policy_id
ORDER BY detections DESC;
```

```sql
-- Detections that ended because telemetry stopped, not because traffic did.
SELECT tenant, target, policy_id, detected_at, duration_ms
FROM wetechinetmon_detection_events
WHERE kind = 'ended' AND reason = 'stale'
  AND timestamp > now() - INTERVAL 1 DAY
ORDER BY timestamp DESC;
```

```sql
-- Which policies are noisiest. A policy far above the others is usually
-- mistuned rather than unlucky.
SELECT policy_id, policy_version, severity, count() AS starts
FROM wetechinetmon_detection_events
WHERE kind = 'started' AND timestamp > now() - INTERVAL 7 DAY
GROUP BY policy_id, policy_version, severity
ORDER BY starts DESC;
```

```sql
-- Audit: confirm nothing has ever claimed to act on traffic.
-- Must return zero rows for as long as mitigation is unimplemented.
SELECT count() FROM wetechinetmon_detection_events WHERE executed != 0;
```

`matched_json` and `peak_json` hold the full reason lists as JSON text;
query into them with ClickHouse's JSON functions when the flattened
`top_*` columns are not enough.

## Capacity

The detector's cost is roughly:

- **Per flow:** one counter update per scope type it belongs to (up to
  four for an IPv4 flow with a matched prefix and a hostgroup, up to
  eight for an internal flow counted on both sides), plus one prefix
  lookup.
- **Per scope, per window:** one `TrafficCounters` (about 100 bytes)
  plus completeness, sampling, and an 8-byte exporter sketch.
- **Per tracked scope:** one `ScopeState`, dominated by the scope key
  and the peak-reason list.

Both are bounded by `DETECTION_MAX_SCOPES` per dimension. No throughput
figure is published here: none has been measured on representative
hardware, and an invented one is worse than none. See
[capacity-planning.md](capacity-planning.md) for the same caveat applied
to Phase 3.

## See also

- [Detection engine architecture](../architecture/detection-engine.md)
- [Configuring detection policies](../configuration/detection-policies.md)
- [Aggregator monitoring](aggregator-monitoring.md)
