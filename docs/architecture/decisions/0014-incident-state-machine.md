# 0014. The Incident State Machine Does Not Mirror the Detector's

Status: **Accepted.** BQ-6, BQ-8, and BQ-9 all resolved 2026-08-22.
Date: 2026-08-22
Deciders: Repository owner — decided 2026-08-22

## Context

[FR-5.1](../../functional-requirements.md) specifies one state machine:

```text
Normal → Suspected → Confirmed → AwaitingApproval → MitigationPending
       → Mitigating → HoldDown → Recovering → Closed / Failed
```

Two problems make this un-implementable as written in Phase 5.

**First, its opening states already exist in Phase 4.** `Suspected` and
`Confirmed` are `PendingTrigger` and `Active`. The `triggerFor` timer
*is* the suspected-to-confirmed transition, and it is implemented,
tested, and tunable per policy. Re-implementing it in the incident domain
would mean two components deciding the same thing from the same data,
with no rule for which wins when they disagree.

**Second, four of its states are mitigation states.**
`AwaitingApproval`, `MitigationPending`, `Mitigating`, and `HoldDown`
describe a mitigation lifecycle that Phase 5 is explicitly forbidden from
implementing and that Phase 7 will own.

A third, subtler force: incident state is about *human response*, not
traffic. An incident can be acknowledged while the flood continues, and
investigated long after it stops. A machine driven by both traffic and
people needs a clear rule about which drives which, or transitions become
unpredictable.

## Options Considered

### Option A — Implement FR-5.1 literally

- Pros: matches the requirement exactly; no reconciliation needed later.
- Cons: duplicates Phase 4 logic in a second place; requires four states
  Phase 5 must not implement, which would be dead code that lies about
  capability — precisely the failure ADR 0007 and the `executed` field
  exist to prevent.

### Option B — Operator-facing states only, mitigation deferred

Detection keeps `Suspected`/`Confirmed`; incidents model human response;
mitigation states arrive in Phase 7.

- Pros: no duplicated logic; every state is reachable and meaningful; the
  detector stays the single authority on whether traffic is abnormal;
  Phase 7 extends rather than rewrites.
- Cons: deviates from FR-5.1 as written; needs the deviation documented
  and approved; Phase 7 must add states to a live machine.

### Option C — Full machine with unreachable mitigation states

Define all FR-5.1 states, leave the mitigation ones unreachable.

- Pros: FR-5.1 satisfied on paper; no migration in Phase 7.
- Cons: an API that advertises `Mitigating` in its enum while nothing can
  ever mitigate is a capability lie of the same kind the `executed` field
  was added to prevent; consumers write handling for states that never
  occur.

## Decision

**Option B**, with the deviation from FR-5.1 recorded explicitly and
**BQ-6** raised so the owner can accept it or choose Option C.

**Seven states:** `Open`, `Acknowledged`, `Investigating`, `Monitoring`,
`Recovering`, `Resolved`, `Closed`. `Closed` is the only terminal state.
Full matrix in
[the state machine document](../incident-state-machine.md).

Key sub-decisions:

- **`Suspected` and `Confirmed` stay in the detection domain.** An
  incident is created only once the detector has confirmed. There is no
  incident for a suspicion.
- **`Failed` is not an incident state.** In FR-5.1 it means mitigation
  failed — a Phase 7 concept. A *processing* failure is a quarantined
  event plus an alert, not an incident state. Inventing semantics for it
  now would only constrain Phase 7.
- **Automatic and operator transitions are separated** and listed
  separately, so it is always clear whether traffic or a person caused a
  change.
- **Illegal transitions are refused by a guard**, following Phase 4's
  `DetectionState` pattern, so an unreasoned edge fails loudly instead of
  entering a state whose timers mean nothing.
- **Recovery restores the prior state on abort.** An incident that was
  `Investigating` when traffic dipped returns to `Investigating`.
- **The five ways a detection can end are recorded distinctly** —
  `traffic_cleared`, `detector_stale`, `detector_silent`,
  `policy_withdrawn`, `detector_reset`. All converge on `Recovering`, but
  an operator must be able to tell "the attack stopped" from "we stopped
  hearing about it".
- **No transition triggers a notification or a mitigation.** Transitions
  emit outbox events; nothing consumes the notification and mitigation
  types in Phase 5.

Timing defaults were resolved on the same date — see the second owner
decision below.

## Owner Decision — 2026-08-22

**BQ-6 approved.** Mitigation lifecycle stays **outside** the core
incident state machine. Scope:

- The Phase 5 state machine contains **no** mitigation workflow state —
  not `AwaitingApproval`, `MitigationPending`, `Mitigating`,
  `MitigationFailed`, `WithdrawalPending`, `Withdrawing`, or `HoldDown`.
  They are not present-but-unreachable either; Option C was considered
  and rejected, because an enum a client can read still advertises a
  capability that does not exist.
- The incident carries a **read-only, non-authoritative** mitigation
  reference seam: a summary field whose Phase 5 value is always `none`,
  and reserved outbox event types nothing consumes.
- **Mitigation status must never control the incident lifecycle.** The
  two are independently queryable, and a future mitigation domain owns
  its own records, identifiers, and audit history. One incident may
  eventually have several mitigation operations, which is a second reason
  a single status field on the incident could never have been
  authoritative.
- Phase 5 executes no mitigation and defines no production BGP action.

### Two things that are not states

Also decided 2026-08-22, after review:

**`Reopened` is a transition, not a state.** A state describes a durable
condition; "was reopened" is a past event. A reopened incident is `Open`,
with `reopened_at`, `reopen_count`, and a timeline entry carrying the
history. This was already the design and is now recorded as deliberate.

**`Suppressed` is an attribute, not a state.** This *is* a change, and it
fixes a defect rather than tidying the diagram. Suppression is orthogonal
to lifecycle position — it governs whether an incident *alerts*, not
where the human response has reached. Modelled as a state it collided
with the lifecycle: `UnsuppressIncident` had to send the incident
somewhere and sent it to `Open`, **silently discarding the progress of an
incident that had been `Investigating`**. That is exactly the bug
`Recovering` avoids by storing `state_before_recovering`, and needing a
second restoration field was the signal the modelling was wrong. As three
columns — `suppressed_until`, `suppression_reason`, `suppressed_by` —
the lifecycle is untouched and there is nothing to restore. `suppressed`
is *derived* from the expiry, so a suppression cannot outlive its own
deadline through a missed sweep.

The mandatory expiry is unchanged: an indefinite suppression is how a
real attack gets missed.

## Owner Decision — 2026-08-22 (BQ-8): critical incidents close by hand

**Approved: `critical` incidents require manual closure by default.**

**Rationale.** Auto-close is a convenience, and it is reasonable for the
severities where nobody would have reviewed the incident anyway. At
`critical` — a severity that implies customer impact — the convenience
buys very little and risks the one outcome that destroys trust in the
system: an incident that opened, resolved, and closed with no human ever
having seen it. The first anyone hears of it is a customer call.

**Semantics.** Automation still handles the *network* claim; a human
makes the *operational* one:

- `critical` may move automatically to `Recovering` when detection clears.
- `critical` may move automatically from `Recovering` to `Resolved` after
  the recovery confirmation period.
- `critical` **must not** move automatically from `Resolved` to `Closed`.
- An operator holding `incident.close` closes it.
- Automatic closure remains available for non-critical severities.

This rests on `Resolved` and `Closed` being **operationally distinct**:
`Resolved` says the traffic condition recovered, `Closed` says NOC review
and operational handling are complete. They are not two words for
finished, and the gap between them is where the post-incident work
happens.

**Configuration.** `critical_manual_closure_required` defaults to `true`
— the secure default — and is configurable. This replaces the previous
`auto_close_min_severity` threshold with a rule stated plainly rather
than encoded in a comparison. The closure delay for non-critical
incidents also moved from 24 hours to 30 minutes, since it now governs
only incidents nobody was going to review.

**Overrides** must be explicit, tenant-aware, policy-aware where
supported, gated on `incident.closure_policy.override`, immutably
audited, and visible in effective-configuration diagnostics. Unset means
`true`; there is no path by which the protection lapses silently.

**Security impact.** Prevents a critical incident closing unseen, and
composes with suppression — a suppressed critical still cannot auto-close.
The override permission is deliberately outside every default operator
bundle, because the ability to make criticals close themselves is exactly
the capability an attacker with a foothold would want.

**Operational impact.** A resolved-but-unclosed queue now exists and must
be visible; the existing list filters already answer it, and
`tidegard_incidents_active{state="resolved"}` makes it alertable.

**This is Community behaviour.** A correctness and safety default is not
an Enterprise feature, and
[ADR 0017](0017-incident-community-enterprise-boundary.md) already
forbids reserving one.

**No notification and no mitigation** is implied by manual closure.

## Owner Decision — 2026-08-22 (BQ-9): 15-minute reopen window

**Approved: 15 minutes, as the initial technical default.** It is
configurable, and it is **not** a legal, regulatory, contractual, or SLA
requirement.

**The boundary is inclusive.** Elapsed **≤** window reopens; **>** window
creates a new incident. Measured from `resolved_at`, or `closed_at` when
the incident never passed through resolution. Fixing which side the
boundary falls on matters because "15 minutes" has two defensible
readings, and a test written against one with code written against the
other passes review and fails in production.

**Rationale and the two risks.** Too long is the more dangerous
direction: a genuinely distinct second attack gets absorbed into a
resolved incident and is **hidden**. Too short is merely annoying: a
flapping attack becomes a stream of separate incidents, each demanding
acknowledgement — the alert fatigue hysteresis exists to prevent. Fifteen
minutes sits closer to the annoying end on purpose.

**Configuration.** Minimum `0` — recurrence always creates a new
incident, reopening disabled. Default `15m`. Maximum accepted `24h`, a
**validation** bound to stop a typo becoming a month-long window, not an
operational recommendation.

**Transaction implications.** A reopen performs ten effects in the one
authoritative transaction or none of them: transition to `Open`,
increment `reopen_count`, set `reopened_at`, append an immutable
`reopened` timeline entry, append a mandatory audit record, link the new
evidence, preserve all prior timeline and evidence, preserve the original
incident identity, increment `version`, and write the outbox event.

**A reopen must never yield two simultaneously active incidents for one
correlation key.** The partial unique index enforces that at the
database, so concurrent reopens resolve to one winner and one retry.

**Correlation is unchanged**:
`tenant | target_type | target_id | direction | family`. Policy id
excluded; category excluded and mutable; host and parent prefix separate;
incoming and outgoing separate; IPv4 and IPv6 separate. A detector
restart mints a new `detection_id` and must not prevent recurrence
correlating — the key is semantic, never detection-derived.

**Observability.** `tidegard_incidents_reopened_total` by severity,
and the close-to-recurrence gap distribution (**FU-28**) so the value can
eventually be chosen from evidence rather than judgement.

## Consequences

**Easier.** One authority for "is traffic abnormal". Every state is
reachable and means something. The core lifecycle is small and
operationally unambiguous — seven states, one terminal. Suppression and
lifecycle are independently queryable, so "show me suppressed incidents
that are still being investigated" is answerable. Operator workflow is modelled on its own
terms. Phase 7 adds mitigation states without unpicking anything.

**Harder.** A documented deviation from FR-5.1 that needs approval.
Phase 7 will add states to a machine already carrying live incidents,
which means a migration and a version bump on the incident schema.
Reasoning about an incident requires looking at both machines.

**Forecloses.** Little. Adding states later is additive. What it does
foreclose is the incident manager ever deciding on its own that traffic
is abnormal — that stays the detector's job, permanently.

**Security.** Every transition carries a permission and writes an audit
record. Suppression requires a mandatory expiry, because an indefinite
suppression is how a real attack is missed. Severity reduction requires a
reason and is separately permissioned.

**Operational.** Five distinct recovery reasons mean an operator can tell
a genuine recovery from telemetry loss — the difference between closing
an incident correctly and closing one that is still happening.

## Follow-Up

- [x] **BQ-6** — resolved 2026-08-22: mitigation states stay out; a
      read-only reference seam remains.
- [x] **BQ-8** — resolved 2026-08-22: critical incidents require manual
      closure by default.
- [x] **BQ-9** — resolved 2026-08-22: 15-minute reopen window, inclusive
      boundary.
- [ ] **FU-28** — measure the close-to-recurrence gap so the window can
      eventually be chosen from evidence rather than judgement.
- [ ] Update [functional-requirements.md](../../functional-requirements.md)
      FR-5.1 to reference this ADR once approved, so the requirement and
      the design stop disagreeing.
