# Phase 5: Incident Management — Plan

Status: **Planning only.** No Phase 5 production code exists, and none is
written by this document. Everything here is a proposal awaiting owner
review — see
[Phase 5 acceptance criteria](../development/phase5-acceptance-criteria.md)
for what "approved" means.

Phase 4 answers *"is this traffic abnormal?"* and writes an immutable
event saying so. Phase 5 answers the question an operator actually has at
three in the morning: *"what is going on, who is dealing with it, and what
have we already tried?"* Those are different questions with different
lifetimes. A detection event is true forever at one instant; an incident
is a mutable, human-owned workspace that lives for hours.

## The one-paragraph version

Detection events flow from the detector into an incident manager through a
**transactional outbox in PostgreSQL** — durable, at-least-once, and
replayable. A **deterministic correlation key** decides whether an event
opens a new incident, updates one, reopens a recent one, or is discarded
as a duplicate. Incidents move through an **operator-facing state machine**
that deliberately does *not* duplicate the detector's states. Every
mutation writes the incident row, an append-only timeline entry, an audit
record, and an outbox row **in one transaction, or none of them**.
PostgreSQL is the operational source of truth; ClickHouse receives
immutable analytics events only. A REST API and a CLI sit on top. Nothing
notifies anyone and nothing touches a router.

## What Phase 5 is not

Phase 5 adds **no** notification delivery, **no** mitigation, **no** BGP,
RTBH, FlowSpec, firewall, router control, webhook, or script execution.
Those are Phases 6 and 7. Phase 5 plans the *seams* they will attach to —
`notification_status` and `mitigation_status` placeholder columns, and
outbox event types nobody consumes yet — because retrofitting a seam is
far more expensive than leaving one. Planning a seam is not implementing
the thing behind it, and this distinction is enforced by the same rule
Phase 4 lives under: if the crate cannot reach a router, it cannot
mitigate. See [ADR 0011](decisions/0011-incident-domain-boundary.md).

## Documents in this plan

| Document | Answers |
|---|---|
| [Incident domain model](incident-domain-model.md) | What an incident *is*, field by field, with bounds |
| [Incident correlation](incident-correlation.md) | Which event joins which incident, deterministically |
| [Incident state machine](incident-state-machine.md) | Every state, transition, permission, and side effect |
| [Incident persistence](incident-persistence.md) | PostgreSQL schema, transactions, ClickHouse boundary |
| [Incident security model](incident-security-model.md) | Tenancy, permissions, concurrency, idempotency |
| [Incident API plan](incident-api-plan.md) | REST resources, request/response, pagination |
| [Incident CLI plan](incident-cli-plan.md) | The `tidegardctl incidents` command tree |
| [Incident observability](incident-observability.md) | Metrics, logs, capacity bounds |
| [Incident testing plan](incident-testing-plan.md) | What must be proven before Phase 5 ships |
| [Incident threat model](../security/incident-threat-model.md) | 24 threats, controls, residual risk |
| [Implementation plan](../development/phase5-implementation-plan.md) | Milestones 5A–5F |
| [Acceptance criteria](../development/phase5-acceptance-criteria.md) | Definition of done |

Eight decision records: [0011](decisions/0011-incident-domain-boundary.md),
[0012](decisions/0012-incident-event-ingestion.md),
[0013](decisions/0013-incident-identity.md),
[0014](decisions/0014-incident-state-machine.md),
[0015](decisions/0015-incident-operational-storage.md),
[0016](decisions/0016-incident-concurrency-and-idempotency.md),
[0017](decisions/0017-incident-community-enterprise-boundary.md),
[0018](decisions/0018-phase5-dependency-selection.md).

## The Phase 4 event model, as it actually exists

Read from `crates/detector/src/event.rs` at `3f0cf3e`, not from memory.
Phase 5 correlation may only use fields that are really there.

| Group | Field | Type or values |
|---|---|---|
| Identity | `event_id` | `{instance:016x}-{seq:016x}`, unique per event, monotonic per engine |
| Identity | `detection_id` | 32 hex chars, stable start-to-end of one detection |
| Identity | `dedup_key` | `{detection_id}:{kind}:{sequence}` |
| Identity | `sequence` | `u64`, 0 on start, gapless |
| Identity | `schema_version` | `u32`, currently `1` |
| State | `kind` | `Started`, `Updated`, `Ended` |
| State | `previous_state`, `state` | `Idle`, `PendingTrigger`, `Active`, `PendingClear`, `Cooldown` |
| State | `reason` | 12 variants including `TriggerSustained`, `ClearSustained`, `Stale`, `PolicyWithdrawn`, `ManualReset` |
| Tenant | `target.tenant` | `String` |
| Policy | `policy_id`, `policy_name`, `policy_version` | `String`, `String`, `u32` |
| Policy | `severity` | `Info`, `Minor`, `Major`, `Critical` |
| Policy | `labels` | `BTreeMap<String, String>` from the policy |
| Target | `target.scope_type` | `Host`, `Prefix`, `Slash24`, `HostgroupTotal` |
| Target | `target.scope_id` | `Host{addr}`, `Network{addr, prefixLen}`, `Hostgroup{name}` |
| Target | `target.display` | text form of `scope_id` |
| Target | `target.direction` | `Incoming`, `Outgoing`, `Internal`, `Other`, `Unknown` |
| Target | `target.address_family` | `Ipv4`, `Ipv6` |
| Time | `detected_at_ms`, `observed_at_ms` | wall-clock milliseconds since the epoch |
| Time | `duration_ms`, `window_ms` | monotonic-measured, reported directly |
| Reasons | `matched`, `peak` | `Vec<MatchedReason>` with metric, observed, threshold, excess, ratio_percent |
| Reasons | `skipped` | `Vec<SkippedMetric>` with a reason |
| Reasons | `rates` | `MetricRates`, 12 rate fields |
| Execution | `execution_mode` | `Disabled`, `Observe`, `AlertOnly`, `DryRun` |
| Execution | `action` | `Observed`, `Alerted`, `DryRun` |
| Execution | `executed` | `bool`, **always `false`** |
| Confidence | `completeness` | four booleans: protocol, TCP flags, fragmentation, forwarding-status seen |
| Confidence | `sampling` | `corrected`, `used_global_default`, `max_rate` |
| Confidence | `flows_observed`, `exporters_observed`, `snapshots_in_detection` | `u64`, `u32`, `u64` |
| Display | `summary` | one line, safe for a subject header |

`MetricKind` has 15 values: `Bps`, `Pps`, `Fps`, `TcpBps`, `TcpPps`,
`UdpBps`, `UdpPps`, `IcmpBps`, `IcmpPps`, `TcpSynBps`, `TcpSynPps`,
`FragmentedBps`, `FragmentedPps`, `DroppedBps`, `DroppedPps`.

Persisted form: ClickHouse `wetechinetmon_detection_events`, 54 columns,
365-day TTL, positional `clickhouse::Row` mapping.

### Five gaps the plan has to work around

These are consequences of what Phase 4 actually built. Each one changes a
Phase 5 design decision, so they are stated here rather than discovered
during implementation.

1. **`detection_id` is instance-scoped and therefore useless as a
   correlation key.** It is derived from the detector's `instance_id`,
   which is seeded per process from the PID and a hash. Restart the
   collector mid-attack and the same ongoing flood produces a *different*
   `detection_id`. Correlation must key on the scope, not on the
   detection. This single fact is why the design needs a reopen window at
   all — see [ADR 0014](decisions/0014-incident-state-machine.md).
2. **There is no attack-category field.** FR-5.2 wants one. Phase 4 never
   computes one. Phase 5 derives it from the set of crossed `MetricKind`s
   — see [correlation](incident-correlation.md) — which is an
   incident-domain concern and must not be pushed back into the detector.
3. **There is no baseline metric.** Phase 4 compares against static
   thresholds only. The incident model carries nullable baseline columns
   so a future baselining phase has somewhere to put one. They will be
   `NULL` for every Phase 5 incident, and the API must return `null`
   rather than `0`, because "we never measured this" and "this was zero"
   are different facts.
4. **Exporter and interface identity are not on the event.** FR-5.2 asks
   to persist both. Phase 4 carries `exporters_observed`, which is a
   *count*. Recording *which* exporter saw the traffic needs a detector
   change, which Phase 5 is forbidden from making. Deferred as **FU-16**.
5. **Severity has four values, not five.** `Info`, `Minor`, `Major`,
   `Critical`. Phase 5 reuses them exactly rather than inventing a
   parallel scale that would need a lossy mapping in both directions.

## Owner decisions

Three of the five blocking questions were resolved on **2026-08-22**.
Two remain open, and neither blocks implementation.

| # | Question | Outcome |
|---|---|---|
| **BQ-5** | UUID requirement vs the ADR 0009 precedent | **Resolved** — UUIDv7 for internal incident identity, conditional on a dependency and licence review. Phase 4 event IDs unchanged |
| **BQ-6** | Mitigation states in the incident machine | **Resolved** — excluded, with a read-only reference seam. Also: `Reopened` is a transition, and **`Suppressed` became an attribute**, dropping the lifecycle to seven states |
| **BQ-7** | PostgreSQL and HTTP dependencies | **Resolved** — approved architecturally. **No crate is chosen**; selection goes through [ADR 0018](decisions/0018-phase5-dependency-selection.md) |
| **BQ-8** | Manual closure for `critical` | **Resolved** — required by default. `Resolved` and `Closed` are operationally distinct; overrides are permissioned, audited, and visible. Community, not Enterprise |
| **BQ-9** | Default reopen window | **Resolved** — 15 minutes, **inclusive** boundary, range 0–24 h. A technical default, not an SLA |

Full wording, options, and reasoning in
[blocking questions](../blocking-questions.md).

**No Phase 5 planning decision remains outstanding.** All five questions
were resolved on 2026-08-22. What remains before Milestone 5B is crate
selection under
[ADR 0018](decisions/0018-phase5-dependency-selection.md) — an
implementation task with verification requirements, not an open
architectural question.

## Out of scope, explicitly

Email, Teams, Slack, Telegram, PagerDuty, webhooks, BGP RTBH, FlowSpec,
firewall control, router APIs, production mitigation, full RBAC, Entra ID,
a customer portal, PDF reports, ML detection, distributed correlation,
multi-region control planes, SLA billing, and subscription management.
Interfaces may be *planned*; none of this is built in Phase 5. See
[out-of-scope.md](../out-of-scope.md).
