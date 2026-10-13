# 0009. Detection Event Identity and Deduplication

Status: Accepted
Date: 2026-08-22
Deciders: WeTechi Solutions (badshashorif)

## Context

A detection produces several events over its life: one when it opens,
periodic updates while it stays open, one when it closes. Anything
consuming them — a ClickHouse table, a future incident tracker, a
notification pipeline — needs to answer three separate questions:

1. Which events describe the same detection?
2. Have I seen this exact event before?
3. Did I miss one?

These are three different jobs and one identifier cannot do all three.
A single UUID per event answers only the second, and only if the
transport never rewrites it.

There is also a practical constraint. `tidegard-detector` has no
random-number dependency, and [ADR 0007](0007-detection-engine-cannot-mitigate.md)
establishes that this crate's dependency list is itself a safety
property worth defending. Adding `uuid` (and transitively `rand`, and
its platform entropy backends) to mint identifiers that are never used
as cryptographic material is a poor trade.

## Options Considered

### Option A — A UUID per event, and nothing else

One `uuid::Uuid` per event. Simple, familiar.

Answers question 2. Does not answer 1 without a separate field, and does
not answer 3 at all. Adds a dependency.

### Option B — Three purpose-built identifiers, no randomness

- **`event_id`** — unique per event. Nothing is keyed on it; it exists
  so two events are never literally identical.
- **`detection_id`** — stable from the start event to the end event of
  one detection. This is the join key.
- **`dedup_key`** — what an at-least-once transport collapses on.
  Redelivering an event produces a byte-identical key.

Plus a **`sequence`** number, zero on the start event and incrementing
for each subsequent event of the same detection, so a gap in the
sequence really does mean a lost event.

`detection_id` is derived from the engine's instance id, the scope, and
the instant the detection opened. A scope cannot open two detections at
the same instant, so the triple is unique without a counter — which is
what makes it reproducible: the end event is minted from the same inputs
as the start event and produces the same string.

The instance id is derived once per process from the process id, the
wall clock at startup, and the address of a fresh heap allocation. This
is **not** a random number and is not claimed to be one; it exists so
two engines processing the same traffic do not mint colliding ids.

### Option C — Content-addressed events

Hash the whole event. Perfect deduplication, no state.

But two genuinely distinct updates with identical rates would collapse
into one, which is exactly the information an operator wants: "it stayed
at 40 Gbps for six minutes" is six events, not one.

## Decision

**Option B.**

Format: `event_id` is `{instance:016x}-{counter:016x}`; `detection_id`
is `{instance:016x}{hash:016x}`; `dedup_key` is
`{detection_id}:{kind}:{sequence}`.

## Consequences

**Good.** Each question has an identifier that answers it exactly, and a
consumer that sees a sequence gap can act on it.

**Good.** No new dependencies, and the instance-id derivation is a dozen
lines with no platform-specific code.

**Cost.** `detection_id` is not globally unique in the mathematical
sense. It is a 64-bit hash of the scope and open-instant, prefixed with
a 64-bit instance id that is *derived, not random*. Two engines started
in the same millisecond, in processes with the same pid, with the same
heap layout, would collide. In a deployment with a handful of collectors
this is not a practical risk; in one with thousands of short-lived
engines it would need revisiting.

**Cost.** The identifiers are not UUIDs and will not parse as such. Any
future integration expecting a UUID column needs a mapping. Recorded in
[follow-ups.md](../../development/follow-ups.md).

**Explicitly not a security property.** These identifiers are
predictable by design. Nothing may use them as a capability, a token, or
anything an attacker must not guess. See
[detection-safety.md](../../security/detection-safety.md).
