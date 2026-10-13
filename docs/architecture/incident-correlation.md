# Incident Correlation

Status: **Planning only.** Part of the
[Phase 5 plan](phase5-incident-management-plan.md).

Correlation decides, for every arriving detection event, which of six
things happens. It must be **deterministic**: the same event against the
same incident state must always produce the same outcome, on any node, in
any order, however many times it is delivered. Anything less and replaying
the outbox after an outage produces a different incident set than the
original run.

## The six outcomes

| Outcome | When |
|---|---|
| **Create** | No open incident for this key, and the event is not an `Ended` |
| **Update** | An open incident exists for this key |
| **Reopen** | The most recent incident for this key closed within the reopen window |
| **Link only** | An open incident exists, but the event cannot change state (late, out of order) |
| **Duplicate** | This `dedup_key` has already been ingested |
| **Quarantine** | The event is malformed, or its `schema_version` is not supported |

## The correlation key

```text
correlation_key = tenant | target_type | target_id | direction | address_family
```

Five dimensions. Concretely, for an inbound IPv4 flood against a single
host in tenant `wetechi`:

```text
wetechi|host|203.0.113.7|incoming|4
```

`target_id` is the canonical form of `ScopeId`: the address for `Host`,
`addr/prefixLen` for `Network`, the hostgroup name for `Hostgroup`.
Canonical means IPv6 is normalised to its compressed lowercase form
before hashing, so `2001:DB8::1` and `2001:db8:0:0:0:0:0:1` are one key
and not two.

### What is deliberately not in the key

**Policy is not in the key.** This is the most consequential choice here,
so the reasoning is worth stating plainly. If `policy_id` were part of the
key, a single flood matched by both a `bps` policy and a `pps` policy
would open two incidents, and the NOC would acknowledge, assign, and
investigate the same attack twice. One attack against one target in one
direction is one incident, whatever number of policies noticed it. The
policies that contributed are recorded in `policy_refs` on the incident,
so nothing is lost.

The cost is real and should be understood before approving: a
deliberately narrow policy — say, a per-customer SLA threshold — will be
absorbed into the same incident as a broad platform-wide threshold rather
than standing alone. If that turns out to matter operationally, the fix
is a per-policy `correlation_group` opt-out, recorded as **FU-18**, not a
change to the default key.

**Severity is not in the key.** Severity escalates during an attack; if
it were in the key, escalation would split one incident in two.

**Metric and category are not in the key.** A UDP flood that becomes a
multi-vector attack is the same incident with an updated category, not a
new one.

**Scope type *is* in the key.** A `/32` and its parent `/24` produce
**separate incidents**. They are different blast radii and often different
owners: the host incident is "this customer is being attacked", the /24
incident is "our aggregate edge is saturating". Merging them would hide
the second inside the first. They are cross-linked as related incidents
rather than merged.

## Category derivation

Phase 4 has no category field, so Phase 5 derives one from the set of
crossed `MetricKind`s. The derivation is a pure function of the matched
metrics, evaluated in order, first match wins:

| Category | When the matched set includes |
|---|---|
| `tcp_syn_flood` | `TcpSynBps` or `TcpSynPps` |
| `fragmentation_flood` | `FragmentedBps` or `FragmentedPps` |
| `icmp_flood` | `IcmpBps` or `IcmpPps` and no TCP/UDP metric |
| `udp_flood` | `UdpBps` or `UdpPps` and no TCP metric |
| `tcp_flood` | `TcpBps` or `TcpPps` |
| `packet_rate` | `Pps` or `Fps` only |
| `bandwidth` | `Bps` only |
| `drop_pressure` | `DroppedBps` or `DroppedPps` only |
| `multi_vector` | metrics from two or more of the TCP / UDP / ICMP families |
| `unclassified` | anything else |

`multi_vector` is checked before the single-protocol categories. The
category is **recomputed on every linked event** and may change over the
life of an incident; each change writes a timeline entry, so the
progression from `udp_flood` to `multi_vector` is visible in the
narrative rather than only in the final value.

## Decision procedure

Evaluated in this order. The order is the specification — an
implementation that reorders these is wrong even if every individual rule
matches.

1. **Schema gate.** If `schema_version` is greater than the highest
   supported version, quarantine. Do not guess at unknown fields.
2. **Duplicate gate.** If `dedup_key` already exists for this tenant,
   record a duplicate, increment
   `tidegard_incident_events_duplicate_total`, stop. This is the
   at-least-once defence and it runs before anything mutable.
3. **Mode gate.** `Observe` events never open or change an incident. They
   are ingested and counted so tuning is visible, and that is all.
4. **Lookup.** Find the open incident for `correlation_key`, where "open"
   means any state other than `Closed`.
5. **If found** — link the event, update metrics and category, and let the
   [state machine](incident-state-machine.md) decide whether the event
   causes a transition.
6. **If not found** — look for the most recently closed incident with the
   same key.
   - Closed within the **reopen window** → reopen it.
   - Otherwise, or if none exists → create a new incident, unless the
     event `kind` is `Ended`, in which case link nothing and stop. An end
     event with no incident means the incident was already closed or was
     never opened; inventing one and immediately closing it would produce
     a phantom.

### Ordering and lateness

Events are timestamped with `observed_at_ms`. An event whose
`observed_at_ms` is older than the incident's `last_detected_at` is
**late**. Late events may:

- be linked as evidence,
- raise `peak_metrics` (a peak is a maximum; a late higher peak is still
  the true peak),
- extend `policy_refs`,

and may **not**:

- move `last_detected_at` backwards,
- overwrite `current_metrics` (which means *current*, not *most recently
  processed*),
- cause a state transition,
- reopen a closed incident.

The last one deserves emphasis. A late `Started` event arriving after a
resolution — the classic outcome of a queue backlog draining — must not
resurrect an incident an operator has already dealt with. It is linked,
counted in
`tidegard_incident_events_late_total`, and left alone.

## Worked examples

These are the questions from the planning brief, answered concretely.

**Two policies, same target and direction.** One incident.
`policy_refs` holds both. The incident's severity is the highest severity
among contributing policies.

**Mbps and PPS from the same policy.** One incident, one event, two
entries in `matched`. Both appear in the opening reason and both are
tracked in `peak_metrics`.

**TCP SYN and generic PPS together.** One incident, since the key ignores
metric. Category resolves to `tcp_syn_flood`, because the SYN rule is
checked before `packet_rate`.

**A /32 and its parent /24 at the same time.** Two incidents — different
`target_type` and `target_id`. Cross-linked as related. This is
deliberate; see above.

**UDP flood becomes multi-vector.** One incident. Category changes from
`udp_flood` to `multi_vector`, with a timeline entry recording the
change.

**Closes, then recurs after two minutes.** With the recommended 15-minute
reopen window, it reopens the same incident, `reopen_count` increments,
and the timeline shows both the closure and the recurrence. Outside the
window it becomes a new incident that references its predecessor.

**An event delivered twice.** The second is rejected at the duplicate
gate on `dedup_key`. Because `dedup_key` is `{detection_id}:{kind}:{sequence}`
and `sequence` is gapless, redelivery is exactly detectable rather than
heuristically guessed.

**Events arrive out of order.** See "Ordering and lateness" above.

## The restart problem

`detection_id` embeds the detector's `instance_id`, which changes on every
process start. So when the collector restarts during an attack:

1. The detector loses runtime state and starts every scope at `Idle` —
   this is deliberate, see ADR 0010.
2. It re-detects from live traffic and emits a **new** `Started` event
   with a **new** `detection_id`.
3. No `Ended` event is ever emitted for the pre-restart detection.

Correlation handles this correctly *because* the key is scope-based
rather than detection-based: the new `Started` event lands on the same
`correlation_key` and updates the existing open incident instead of
creating a second one. The incident survives a detector restart even
though the detection does not.

The converse case — an incident left open because the detector restarted
and never sent the `Ended` — is handled by the **staleness sweep**: an
incident whose `last_detected_at` is older than the stale threshold moves
to `Recovering` on its own, with reason `detector_silent`. This is not
the same as `ClearSustained`, and the timeline must say so, because "the
attack stopped" and "we stopped hearing about it" are different facts and
an operator needs to know which one happened.

## Limits

- Correlation lookup is a single indexed read on `(tenant_id,
  correlation_key)`, scoped to the active states — open, acknowledged,
  investigating, monitoring, recovering — not `state <> 'closed'`.
  **Corrected 2026-09-05 (Milestone 5B-2):** this line previously read
  `WHERE state <> 'closed'`, which is wrong for the same reason
  [incident-persistence.md](incident-persistence.md)'s "Active-incident
  invariant" section already documents for its own, once-identical
  mistake — `Resolved` is not an active state for correlation, so that
  predicate would still block a legitimate reopen-window recurrence from
  inserting a new incident row for the same key while a `Resolved`
  incident (correctly outside correlation) still occupies it. The lookup
  is backed by three target-type-specific partial unique indexes —
  `incidents_active_host`, `incidents_active_network`,
  `incidents_active_hostgroup`, implemented in
  `crates/incident-postgres/migrations/V10__active_incident_partial_indexes.sql`
  — rather than one index on a single generated `correlation_key` column,
  which makes two active incidents for one correlation key impossible at
  the database level rather than merely unlikely.
- Correlation is **single-node** in Phase 5. Distributed correlation is
  out of scope; the partial unique index means a second node would fail
  loudly on insert rather than silently duplicating, which is the correct
  failure mode to leave behind.
