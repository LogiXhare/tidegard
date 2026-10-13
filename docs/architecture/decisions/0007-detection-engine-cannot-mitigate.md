# 0007. The Detection Engine Cannot Mitigate

Status: Accepted
Date: 2026-08-22
Deciders: WeTechi Solutions (badshashorif)

## Context

Phase 4 adds the piece of Tidegard that decides traffic is
abnormal. Every product in this category eventually pairs that decision
with an action — a blackhole route, a FlowSpec rule, an RTBH
announcement — and the Mitigation Controller is a later phase in
[roadmap.md](../../roadmap.md).

The question is what the detection engine should be able to do about a
detection *now*, while mitigation is unbuilt.

This matters more than it first appears. A detector that can request
mitigation is a detector that can take a network offline, and it does so
from an automated decision made in milliseconds against thresholds an
operator may have typed a zero too many into. The blast radius of a
false positive is not "a noisy alert" — it is a null-route on a
customer prefix.

There is also a subtler risk. If the code path for "would mitigate"
exists but is disabled by a flag, then the difference between a system
that would have blocked traffic and one that did is one boolean. That
boolean will be flipped by a config change, a merge, or a copy-pasted
environment file, and nothing in the type system will notice.

## Options Considered

### Option A — No mitigation capability in the crate at all

`ExecutionMode` carries `Disabled`, `Observe`, `AlertOnly`, and `DryRun`,
and no variant that could request an action. The crate depends on
nothing that can open a socket to a router, execute a command, or
announce a route. `DryRun` records what a later phase *would* be asked to
do; the reason it does nothing is that there is nothing present that
could do anything.

Mitigation, when it arrives, is a separate component that consumes
detection events. It cannot be reached by editing a flag here.

### Option B — A `Mitigate` variant, disabled by configuration

Add the variant now, refuse it at load time with "not implemented", and
remove the refusal in Phase 7. Keeps the enum stable across phases.

The problem is the one above: a placeholder that means "not yet" is read
by the next person as "temporarily off". It also invites code that
matches on `Mitigate` and does something almost right.

### Option C — A mitigation trait with no implementations

A `Mitigator` trait the engine calls, with only a no-op implementation
shipped. Structurally honest, and makes the seam explicit.

But it puts the call site inside the detection path, so the ordering,
error handling, and failure semantics of mitigation get decided now — by
someone who does not yet know what the mitigation protocol looks like —
and are then hard to change.

## Decision

**Option A.**

- `ExecutionMode` has no mitigation-capable variant, and adding one is a
  later phase's decision rather than a placeholder.
- `tidegard-detector` depends only on `tidegard-common`,
  `tidegard-classifier`, `tidegard-aggregator`, `serde`,
  `serde_json`, `thiserror`, and `tracing`. None of these can reach a
  network device. This is a property of the dependency graph, checkable
  by reading `Cargo.toml`, not a runtime assertion that could be
  bypassed.
- A [`DetectionEventSink`](../detection-engine.md) receives an event and
  returns. It has no return channel through which an action could be
  requested.
- Every event records an `action` of `observed`, `alerted`, or `dryRun`,
  so an audit trail can never confuse "we would have blocked this" with
  "we blocked this".
- Every event also records `executed`, derived from
  `ActionTaken::executed()` and always `false`. That function matches
  exhaustively rather than using a catch-all, so a later phase adding an
  acting variant must come there and state it — it cannot inherit
  `false` and quietly report a real mitigation as not having happened.

## Consequences

**Good.** The strongest possible statement about safety — that the
system *cannot* affect traffic — is true of this phase and verifiable
without reading any logic. An operator can enable detection on a
production collector without a risk assessment about accidental
mitigation.

**Good.** Phase 7 gets to design the mitigation interface with the
detection engine already built and its event schema settled, rather than
guessing at both simultaneously.

**Cost.** `DryRun` currently differs from `AlertOnly` only in what the
event says, because there is no mitigation to describe. That is a real
limitation and is documented as such in
[detection-safety.md](../../security/detection-safety.md) rather than
dressed up.

**Cost.** When mitigation lands, `ExecutionMode` gains a variant, which
is a breaking change to the policy schema. That is the intended shape:
enabling mitigation should require an explicit, visible change to every
policy that wants it, not a default that silently starts applying.

**Follow-up.** The claim "this crate cannot reach a router" is currently
held by review of `Cargo.toml`. A `cargo deny`-style check that fails CI
if the detector gains a transport dependency would make it mechanical.
Recorded in [follow-ups.md](../../development/follow-ups.md).
