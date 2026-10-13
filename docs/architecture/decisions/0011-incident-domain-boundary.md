# 0011. The Incident Domain Is Separate From the Detection Domain

Status: **Accepted** — 2026-10-05, as implemented (see [Acceptance](#acceptance))
Date: 2026-08-22
Deciders: Repository owner — accepted 2026-10-05 (Phase 5F) under the owner's standing delegation for Phase 5

## Context

Phase 4 shipped a detector that decides whether traffic is abnormal and
emits an immutable event saying so. Phase 5 must turn those events into
incidents that humans own, annotate, and close.

The tempting shortcut is to let the detector own incidents: it already
holds per-scope state, it already knows when a detection starts and ends,
and it could keep an "incident" field beside its state machine. That
shortcut would be a mistake, and this ADR exists to foreclose it before
someone reaches for it under time pressure.

The forces pulling apart:

- **Lifetime.** Detector state is deliberately ephemeral and rebuilt from
  live traffic after a restart (ADR 0010). An incident must survive a
  restart, a redeployment, and a database failover — it is what an
  operator has been working in for the last hour.
- **Mutability.** Detection events are immutable facts. Incidents are
  mutable workspaces with assignment, notes, and severity overrides.
- **Boundedness.** The detector runs on the flow hot path with bounded
  memory and no I/O. Incident management does transactional database
  writes. Putting the second inside the first would put a database round
  trip on the packet path.
- **Safety.** ADR 0007 established that the detector cannot mitigate,
  verified by its dependency closure containing no transport crate. If
  the detector grew an incident API, it would grow a database driver, and
  the "no transport dependency" property that makes ADR 0007 mechanically
  checkable would be gone.

## Options Considered

### Option A — The detector owns incidents

- Pros: no new component; correlation has direct access to detector
  state; no serialisation boundary.
- Cons: puts database I/O on the flow hot path; destroys the bounded,
  dependency-free property that ADR 0007 relies on; makes incidents
  ephemeral like detector state, or forces the detector to grow
  persistence it deliberately does not have; couples an operator-facing
  workflow to a component that must stay a pure function of traffic.

### Option B — A separate incident domain consuming detection events

- Pros: keeps the detector bounded, dependency-free, and hot-path clean;
  incidents get real persistence; the two evolve independently; the
  detector remains mechanically provable as unable to act.
- Cons: a serialisation and delivery boundary to design (ADR 0012); an
  incident can lag its detection; two state machines to keep coherent.

### Option C — One combined service with internal module boundaries

- Pros: single deployable; no network hop; module boundaries still
  possible.
- Cons: shared dependency graph means the detector inherits the database
  driver and HTTP stack, which is precisely what ADR 0007 forbids;
  "internal boundary" erodes under deadline pressure in a way a crate
  boundary does not.

## Decision

**Option B.** The incident domain is a separate crate, consuming
detection events through a stable interface, with its own persistence and
its own lifecycle.

Eight domains, with explicit rules about who may call whom:

| Domain | Owns | May depend on |
|---|---|---|
| Detection | Thresholds, hysteresis, detection events | Nothing above it |
| Incident | Correlation, state, timeline, notes, assignment | Detection *events* only, never detector internals |
| Notification (Phase 6) | Delivery | Incident events |
| Mitigation (Phase 7) | Router actions | Incident events |
| Reporting | Aggregate measures | ClickHouse analytics events |
| Audit | Authorization records | Its own store |
| AuthN/AuthZ | Identity, permissions | Nothing |
| Analytics | Immutable measures | Outbox |

Dependencies point one way only. The detector must never import the
incident crate. The incident crate must never execute mitigation or
deliver notifications — and, following the pattern ADR 0007 established,
this should be enforced by its dependency closure containing no BGP,
firewall, router, SMTP, or chat-delivery crate, so the property is
checkable rather than merely asserted.

Notification and mitigation, when they arrive, consume **incident-domain
events** from the outbox. They do not reach into incident tables, and the
incident manager does not call them.

## Consequences

**Easier.** The detector stays a pure, bounded function of traffic with a
provable safety property. Incidents get durability without the detector
growing persistence. Phases 6 and 7 attach at a seam that already exists,
so neither requires re-architecting Phase 5.

**Harder.** There is now a delivery boundary with real failure modes —
duplicates, lateness, replay — which ADR 0012 must address. An incident
can lag its detection by the ingestion latency. Two state machines must
stay coherent, which is why
[the state machine](0014-incident-state-machine.md) deliberately does not
mirror the detector's.

**Forecloses.** Any design where the detector knows about incidents.
Reversing this would mean giving the detector a database dependency and
losing the ADR 0007 property, which should be treated as a
project-level decision, not a refactor.

**Security.** Preserves the mechanically checkable claim that the
detection path cannot act on traffic. Extends it: the incident path
cannot act either, by the same means.

**License.** No new dependency is introduced by this ADR itself. The
storage and HTTP dependencies that Phase 5 will need are a separate
decision — see **BQ-7** and
[ADR 0015](0015-incident-operational-storage.md).

## Acceptance

Accepted as implemented in Phase 5:

- `tidegard-incident` is its own crate and consumes the detector's
  `DetectionEvent` only. The detector does not depend on it.
- The safety property is checked, not asserted.
  `crates/incident/tests/dependency_closure.rs` holds the detector's and
  the incident domain's dependency closures to a reviewed allowlist, and
  refuses any routing, device-access, packet, mail or chat crate anywhere
  in the workspace.
- No transition notifies or mitigates. The API reports
  `mitigation_status` and `notification_status` as `none`, and an
  event that claims an executed action is quarantined.

## Follow-Up

- [x] Owner resolves **BQ-6**: FR-5.1 places mitigation states in the
      incident state machine, which this boundary defers to Phase 7.
- [x] Add a dependency-policy check covering the incident crate when
      **FU-9** is implemented for the detector — one mechanism should
      cover both. Done 2026-10-05: one test covers both.
- [x] Link from [risk-register.md](../../risk-register.md) R16.
