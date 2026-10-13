# Detection Safety

What the detection engine can and cannot do, and which of those claims
are structural rather than behavioural.

## It cannot affect traffic

This is the important one, and it is a property of the dependency graph
rather than a runtime check.

`tidegard-detector` depends on `tidegard-common`,
`tidegard-classifier`, `tidegard-aggregator`, `serde`,
`serde_json`, `thiserror`, and `tracing`. None of these can open a socket
to a network device, execute a command, or announce a route. There is no
flag to flip and no configuration that changes it.

`ExecutionMode` has no mitigation-capable variant. Not one that is
disabled — one that does not exist. A placeholder meaning "not yet"
would be read by the next person as "temporarily off", and the
difference between a system that would have blocked traffic and one that
did would be a single boolean. See
[ADR 0007](../architecture/decisions/0007-detection-engine-cannot-mitigate.md).

A `DetectionEventSink` receives an event and returns. There is no return
channel through which an action could be requested.

Every event carries `executed`, and it is always `false`. It is derived
from `ActionTaken::executed()`, whose match is exhaustive rather than a
catch-all: a later phase adding a variant that *does* act has to come to
that function and say so, rather than inheriting `false` by default and
silently reporting a real mitigation as not having happened. The field is
written onto every event and stored as a column in
`wetechinetmon_detection_events`, so an auditor can filter on it without
needing to know which product version could have acted.

**What `dryRun` means today.** It differs from `alertOnly` only in the
event's `action` field. There is no mitigation for it to describe. It is
a placeholder for a later phase's audit trail, and it is documented as
such rather than dressed up as a safety feature.

**Verification status.** The claim above is currently held by review of
`Cargo.toml`. A `cargo deny`-style check that fails CI if the detector
gains a transport dependency would make it mechanical; recorded in
[follow-ups.md](../development/follow-ups.md).

## What a policy file can do

A policy document is operator-controlled configuration, but it is
parsed, and parsers are where careless input becomes a problem. Every
bound below is enforced before or during parsing:

| Bound | Limit | Checked |
|---|---|---|
| Document size | 4 MiB | On the raw text, before parsing, so a huge file cannot force an allocation its own size |
| Policies | 10,000 | After parse, before compilation |
| Tenant prefixes | 100,000 | Before building the prefix map |
| Policy id | 128 characters | Per policy |
| Labels | 16 per policy | Per policy |
| Window | 300 seconds | Per policy |
| Any timer | 7 days | Per policy |

Unknown fields are rejected rather than ignored, so a document cannot
smuggle in configuration this version does not understand.

A policy aimed at a range outside its tenant's declared prefixes is
refused at load time. This is what stops one tenant writing a policy
that pages on another tenant's traffic. It only works if the `tenants`
block is populated; omitting it skips the check.

## What an attacker can do to the detector

**Exhaust the scope tables.** An attacker sending traffic to many
distinct addresses will fill both the windowing maps and the state
table. Both are bounded and neither grows without limit. The windowing
maps evict; the state table refuses new scopes and counts each refusal
as `tidegard_detector_state_table_full_total`.

**Each refusal is a detection that could not be opened**, so that
counter being non-zero is an availability problem, not a tuning nit.
Alert on it.

**Hide inside a full table.** Following from the above: an attacker who
fills the state table with low-volume traffic to many addresses can
prevent a detection opening for a real target admitted afterwards. The
mitigation is capacity — size `DETECTION_MAX_SCOPES` above your
plausible distinct-address count — and monitoring the counter. This is a
real limitation of a bounded detector and is not solved here.

**Trigger a false positive.** Any threshold-based detector can be made
to fire by sending traffic. Because nothing here can mitigate, the
consequence is an alert, not an outage. That property changes when the
Mitigation Controller lands, and the thresholds that were tolerable for
alerting will need re-examining before they are tolerable for acting.

**Overflow an arithmetic path.** Every rate computation uses `u128`
intermediates and saturates into `u64`. A detector that panics on absurd
input is a detector an attacker can switch off. Property tests drive the
engine with rates up to `u64::MAX` and assert it does not panic.

## Identifiers are not secrets

`event_id`, `detection_id`, and `dedup_key` are **predictable by
design** — see
[ADR 0009](../architecture/decisions/0009-detection-event-identity.md).
The instance component is derived from the process id, the startup wall
clock, and a heap address; it is not random and is not claimed to be.

Nothing may use these as a capability, a token, or anything an attacker
must not guess.

## What ends up in an event

Detection events contain IP addresses, tenant names, hostgroup names,
and traffic volumes. That is operational data about the network being
monitored, and it is the point of the event — but it means events are
not less sensitive than the flow data they came from, and the
`wetechinetmon_detection_events` table deserves the same access controls
as the traffic tables.

Events contain no packet payloads, no ports beyond what the flow record
carried, and no credentials.

The tracing sink logs a summary line per event, at a level matching
severity. That line contains the target address. A deployment shipping
collector logs somewhere less trusted than its ClickHouse instance
should know that.

## Retention

Detection events are kept for 365 days against the traffic tables' 30.
They are the audit trail — what was alerted on, under which policy, and
how bad it got — and they are tiny next to per-window traffic rows.

Rows are written once and never updated. A detection that turns out to
have been wrong is answered with another event, not by editing the
first; an audit trail that can be edited is not evidence.

## See also

- [Security principles](../security-principles.md)
- [Detection engine architecture](../architecture/detection-engine.md)
- [Monitoring detection](../operations/detection-monitoring.md)
