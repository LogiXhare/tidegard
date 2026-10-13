# Detection Policies

Detection is **off** unless `TIDEGARD_COLLECTOR_DETECTION_POLICY_FILE`
points at a policy document. A collector with no policies behaves exactly
as it did before Phase 4.

## Environment variables

All are environment variables on `tidegard-collector` — restart
required to change any of them. Source of truth:
`crates/collector/src/config.rs`.

### `TIDEGARD_COLLECTOR_DETECTION_POLICY_FILE`

| Field | Value |
|---|---|
| Type | Filesystem path, or unset |
| Default | Unset — **detection is entirely off** |
| Security implications | The file is parsed at startup and every bound in [detection-safety.md](../security/detection-safety.md) applies to it. It should be readable only by the collector's service account: it declares which tenants own which prefixes, and whoever can write it controls what the collector alerts on. |
| Related metrics | None directly — if no `tidegard_detector_*` metric exists, detection did not start |
| Verification | `curl -s http://<metrics_bind>/metrics \| grep detector_` returns nothing when detection is off |
| Troubleshooting | A file that cannot be read or compiled disables detection for the run rather than stopping the collector; the reason is logged at `error` level naming the path and the failure |

### `TIDEGARD_COLLECTOR_DETECTION_WINDOW_SECS`

| Field | Value |
|---|---|
| Type | Positive integer (seconds) |
| Default | `5` |
| Security implications | A longer window smooths short bursts, so a threshold tuned for a 1s window under-detects at 30s. Changing it without re-tuning thresholds silently changes detection sensitivity. |
| Related metrics | `tidegard_detector_snapshots_evaluated_total`, `tidegard_detector_snapshots_ignored_total` |
| Verification | `tidegard_detector_snapshots_evaluated_total` should climb once traffic arrives |
| Troubleshooting | **Must equal every policy's `window`.** A mismatch means nothing is evaluated, visible as `snapshots_ignored_total{reason="windowMismatch"}` climbing. That counter should be zero always. |

### `TIDEGARD_COLLECTOR_DETECTION_MAX_SCOPES`

| Field | Value |
|---|---|
| Type | Non-negative integer |
| Default | `100000` |
| Security implications | Bounds worst-case detector memory against a high-cardinality flood. It is also an availability limit: once the state table is full, a real attack on a newly seen address cannot open a detection — see [detection-safety.md](../security/detection-safety.md). |
| Related metrics | `tidegard_detector_tracked_scopes`, `tidegard_detector_scopes_in_state`, `tidegard_detector_state_table_full_total` |
| Verification | `curl -s http://<metrics_bind>/metrics \| grep detector_tracked_scopes` |
| Troubleshooting | `state_table_full_total` increasing means detections are being dropped — raise this, or find out why the distinct-address count grew. Setting it to `0` rejects everything. |

### `TIDEGARD_COLLECTOR_DETECTION_EVENT_BUFFER`

| Field | Value |
|---|---|
| Type | Non-negative integer |
| Default | `10000` |
| Security implications | Bounds memory held between a detection and the ClickHouse export tick. The buffer drops the **oldest** when full: blocking detection until ClickHouse catches up would stop detection during exactly the incident that makes ClickHouse slow. |
| Related metrics | `tidegard_detector_events_failed_total{sink="clickhouse"}` |
| Verification | `tidegard_detector_events_published_total` should track `events_total` for non-observe policies |
| Troubleshooting | Only relevant when ClickHouse export is configured. Persistent drops mean ClickHouse cannot keep up — fix the database, do not just raise this. |

### `TIDEGARD_COLLECTOR_DETECTION_STALE_SECS`

| Field | Value |
|---|---|
| Type | Non-negative integer (seconds) |
| Default | `180` |
| Security implications | This is what stops an exporter failing mid-attack from leaving a detection open forever. Set too low, a brief telemetry gap closes a live detection; set too high, a dead exporter's detections linger. |
| Related metrics | `tidegard_detector_detections_stale_total` |
| Verification | Stop sending traffic for an open detection and watch the counter after this many seconds |
| Troubleshooting | A rising count while traffic looks normal usually means an exporter stopped, not that attacks ended — cross-check `tidegard_collector_flow_datagrams_received_total`. Closes carry reason `stale` and a zeroed rate. |

### `TIDEGARD_COLLECTOR_INCIDENT_DATABASE_URL`

Also: `..._INCIDENT_DATABASE_CA_FILE`, `..._INCIDENT_DATABASE_CLIENT_CERT_FILE`, `..._INCIDENT_DATABASE_CLIENT_KEY_FILE`.

| Field | Value |
|---|---|
| Type | libpq-style connection string; PEM file paths |
| Default | Unset: detection events do not become incidents |
| Security implications | The connection string can carry a password and is never logged. Without a CA file, it must reach only this host; a remote database without TLS is refused, never contacted in plaintext ([ADR 0023](../architecture/decisions/0023-phase5b-postgresql-tls.md)). A client certificate needs its key and a CA file. CA bundles and keys never belong in Git. |
| Related metrics | `tidegard_collector_incident_inbox_queued`, `..._incident_inbox_written_total`, `..._incident_inbox_write_failures_total`, `tidegard_detector_events_failed_total{sink="postgres_inbox"}` |
| Verification | `incident_inbox_written_total` climbs when detections fire, and the incident manager's `tidegard_incident_inbox_events_total{result="processed"}` follows it |
| Troubleshooting | Each policy's tenant gets its own in-memory queue, written to `detection_event_inbox` by its own task ([ADR 0036](../architecture/decisions/0036-phase5c-incident-manager-process.md)). The collector never migrates this database: until the incident manager has run once, writes fail and `write_failures_total` climbs, with the reason logged. A full queue refuses the newest event, counted under `sink="postgres_inbox"`. If the inbox cannot start at all (a bad URL, missing TLS, an unreadable CA file), detection still runs and the error is logged. On shutdown, the queues are flushed for up to 10 seconds; anything left is logged as lost. |

A policy document that cannot be read or compiled **disables detection
for the run** rather than stopping the collector — decoding,
normalizing, and aggregating stay useful, and a collector that refuses to
start over a typo in one policy is a collector that loses telemetry to a
config error. The failure is logged at error level, and that detection is
off is visible in the metrics: no detection counter ever moves.

## The document

JSON, not YAML — see
[ADR 0008](../architecture/decisions/0008-detection-policy-configuration.md)
for why, and for the conditions under which that would change.

```json
{
  "schemaVersion": 1,
  "defaults": {
    "clearPercent": 80,
    "cooldown": "10m",
    "holdDown": "1m",
    "eventUpdateInterval": "5m",
    "severity": "major",
    "executionMode": "alertOnly"
  },
  "tenants": [
    { "tenant": "acme", "prefixes": ["203.0.113.0/24", "2001:db8::/32"] }
  ],
  "policies": [
    {
      "id": "acme-host-inbound-bps",
      "name": "Acme host inbound flood",
      "description": "Raised to 12G after the March transit upgrade.",
      "tenant": "acme",
      "scopeType": "host",
      "direction": "incoming",
      "window": "5s",
      "thresholds": { "bps": "12G", "pps": "2M" },
      "triggerFor": "15s",
      "clearFor": "30s",
      "severity": "critical"
    }
  ]
}
```

### Every field is checked

The document is `deny_unknown_fields` throughout. Writing `trigger_for`
where the schema says `triggerFor` is a **parse error naming the field**,
not a policy that silently takes a default and never fires. This is the
most valuable property of the format and the reason to prefer it over
one that shrugs at unknown keys.

### Durations need units

`"250ms"`, `"30s"`, `"5m"`, `"2h"`, `"1d"`. A bare number is refused:
`triggerFor: 300` reads as five minutes to one operator and three
hundred milliseconds to another, and both are plausible values.

### Thresholds may carry a magnitude

`"12G"` is twelve billion. Decimal, not binary — `k` is a thousand —
because the units being scaled are bits and packets per second, which
are decimal everywhere else in networking. A plain number works too:
`"bps": 12000000000`.

Canonical units: `bps` is bits per second, `pps` packets per second,
`fps` flows per second.

## Policy fields

| Field | Required | Notes |
|---|---|---|
| `id` | yes | Unique. Letters, digits, `-`, `_`, `.`; up to 128 characters. Appears on every event. |
| `name` | yes | Human-readable. |
| `description` | no | Where to record *why* a threshold is what it is. |
| `enabled` | no (`true`) | A disabled policy never wins selection. |
| `tenant` | yes | `"*"` means every tenant, and always loses to a policy naming one. |
| `scopeType` | yes | `host`, `prefix`, `slash24`, `hostgroupTotal`. |
| `selector` | no (`{"kind":"any"}`) | `any`, or `{"kind":"host","addr":…}`, `{"kind":"network","addr":…,"prefixLen":…}`, `{"kind":"hostgroup","name":…}`. Must match `scopeType`. |
| `addressFamily` | no (both) | `ipv4` or `ipv6`. |
| `direction` | yes | `incoming` or `outgoing`. `internal`, `other`, and `unknown` are refused — there is nothing to defend on either side. |
| `window` | yes | Must match the collector's configured detection window. |
| `thresholds` | yes | At least one. Zero is refused: a threshold of zero fires on silence. |
| `clearPercent` | no (`80`) | 1–100. The clear threshold is this percentage of the trigger. |
| `triggerFor` | yes | **Must be at least `window`.** A trigger shorter than the window that feeds it can never be satisfied. |
| `clearFor` | yes | Must be at least `window`, for the same reason. |
| `cooldown` | no (`0`) | Zero returns straight to idle after clearing. |
| `holdDown` | no (`0`) | Minimum open time, measured from when the detection opened. |
| `eventUpdateInterval` | no (`1m`) | Must be non-zero. |
| `severity` | no (`major`) | `info`, `minor`, `major`, `critical`. |
| `executionMode` | no (`alertOnly`) | See below. |
| `priority` | no (`0`) | Breaks a specificity tie; higher wins. |
| `labels` | no | Up to 16 key/value pairs, carried onto every event. |
| `version` | no (`1`) | **Bump this whenever the policy's meaning changes.** |

### Bump `version` when you change a policy

`version` is stamped on every event, so an alert can be traced to the
exact policy text that produced it. It also drives a reset: when a
policy's version changes, open detections under it are closed with
reason `policyChanged` and re-derived under the new thresholds. The
timers they had accumulated were measured against thresholds that no
longer exist.

Changing a policy **without** bumping the version leaves open detections
running under the old timers until they close on their own. That is
occasionally what you want; usually it is not.

### Execution modes

| Mode | Evaluated | Event built | Event published |
|---|---|---|---|
| `disabled` | no | no | no |
| `observe` | yes | yes | **no** |
| `alertOnly` | yes | yes | yes |
| `dryRun` | yes | yes | yes |

`observe` is how you tune a threshold against live traffic without
waking anyone: state advances and metrics move, but no event leaves the
engine.

`dryRun` currently differs from `alertOnly` only in what the event's
`action` field says. There is no mitigation for it to describe — see
[ADR 0007](../architecture/decisions/0007-detection-engine-cannot-mitigate.md).
**No mode can affect traffic.**

## Tenant prefixes

The `tenants` block declares what each tenant owns. A policy aimed at a
range its tenant has no claim to is **refused at load time**, which is
what stops one tenant writing a policy that pages on another tenant's
traffic. Omit the block to skip the check — appropriate when prefix
ownership is not configured, and a real loss of safety when it is not.

## Writing a first policy

Start in `observe` mode with a threshold you are confident is too high,
watch `tidegard_detector_events_total{kind="started"}`, and lower it
until it fires when you expect. Then switch to `alertOnly`.

Set `triggerFor` to at least three windows. Two consecutive over-threshold
windows is the minimum that distinguishes a burst from a flood, and three
gives margin for a window boundary splitting a burst.

Set `cooldown` long enough that one attack cannot produce a stream of
events — several minutes is usually right — and `clearFor` long enough
that a brief dip in an ongoing attack does not close the detection.

## Limits

Bounds exist so a hostile or careless document cannot become a
memory-exhaustion vector: 4 MiB per document, 10,000 policies, 100,000
tenant prefixes, 300-second maximum window, 7-day maximum timer. Each is
refused with a message naming what was exceeded.
