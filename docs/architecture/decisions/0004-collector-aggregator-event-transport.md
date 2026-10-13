# 0004. Collector-to-Aggregator Event Transport: In-Process Channel for Phase 3, NATS JetStream Deferred

Status: Accepted
Date: 2026-08-20
Deciders: WeTechi Solutions (badshashorif)

## Context

[docs/architecture-options.md §2](../../architecture-options.md) recorded
a Phase 0 "leaning" toward NATS JetStream as the event transport between
Tidegard services, to be formalized as an ADR "before Phase 3
(aggregation, first real consumer of the transport) begins." This ADR is
that formalization — but the decision reached is narrower than the
original leaning, for reasons specific to what Phase 3 actually needs.

Phase 3's own deliverable list (master prompt §29, and the Phase 3
acceptance criteria this phase was executed against) requires aggregation
and direction classification to work, correctly and with bounded memory —
it does not require the Aggregator to be an independently deployable,
horizontally scalable process yet. Additionally, this development
environment has no Docker and no reachable message-broker infrastructure
to stand up and test a real NATS JetStream deployment against, and
introducing an unverified infrastructure dependency into a security-
relevant data path would work against the "don't fabricate what wasn't
verified" principle this project holds itself to.

## Options Considered

### Option A — NATS JetStream now

Stand up NATS JetStream (via Docker Compose) and have the Collector
publish decoded/normalized flows to a stream that the Aggregator
(a separate process) consumes.

- Pros: matches the original Phase 0 leaning; exercises the real
  multi-process architecture early; aligns with the eventual v2.0.0
  distributed-HA direction.
- Cons: cannot be verified in this environment (no Docker available);
  adds real operational complexity (a broker to deploy, monitor, and
  keep healthy) for a capability — independent scaling of collector vs.
  aggregator — that nothing in Phase 3's scope actually exercises yet;
  would mean claiming a tested integration that was not, in fact, tested
  end-to-end here.

### Option B — In-process bounded channel (`tokio::sync::mpsc`)

Collector, Classifier, and Aggregator run inside the same
`tidegard-collector` binary for Phase 3, connected by a bounded
in-process channel. `crates/aggregator` and `crates/classifier` are
still independent, unit-testable crates with no dependency on how
messages reach them — only the wiring inside the binary is in-process.

- Pros: fully testable in this environment, including real backpressure
  behavior (a bounded channel is itself a queue-depth control, satisfying
  part of FR-2.4/master-prompt §8's "queue limits" requirement); zero new
  infrastructure dependency; zero new license-matrix entries; matches
  "don't add abstractions beyond what's needed" — nothing in Phase 3
  requires the Aggregator to run as a separate OS process.
- Cons: does not by itself validate NATS JetStream's suitability; moving
  to a real message broker later means replacing this wiring, not
  extending it — a known, accepted migration cost, not a hidden one.

## Decision

**Option B for Phase 3**: an in-process, bounded `tokio::sync::mpsc`
channel connects the Collector's decode loop to the Classifier and
Aggregator, all within the `tidegard-collector` binary. NATS
JetStream remains the recorded direction for when the Aggregator (or any
other service) needs to run as an independently deployable, horizontally
scaled process — tracked explicitly below, not silently dropped.

This is a **narrowing, not a reversal**, of the Phase 0 leaning: NATS is
still the answer to "what do we use when we need a real message broker,"
just not yet needed to answer "how does Phase 3's aggregation pipeline
work."

## Consequences

- `crates/aggregator` and `crates/classifier` expose plain Rust APIs
  (`fn classify(...)`, `fn ingest(...)`) with no transport-specific types
  leaking into their public interfaces — swapping the transport later
  (in-process channel → NATS) should not require changing these crates'
  core logic, only the wiring code in `crates/collector`'s binary.
- The channel's bounded capacity is itself the "queue depth" control and
  metric (master prompt §8/§9 — `queue depth` Prometheus metric,
  backpressure) for Phase 3 — no separate backpressure mechanism is
  needed on top of it.
- Multi-process / multi-host deployment of the Aggregator independently
  from the Collector is **not possible** until the NATS (or equivalent)
  transport is actually implemented — this is an explicit scope
  boundary of Phase 3, not an oversight.
- No new license-matrix entries this phase for transport; `tokio` is
  already an approved dependency (Phase 2).

## Follow-Up

- [ ] Before any phase that needs the Aggregator to scale independently
      of the Collector (likely alongside multi-tenancy, Phase 8, or
      earlier if load testing in Phase 9 shows a need), implement the
      NATS JetStream transport and update this ADR's status to
      "Superseded by NNNN" rather than editing this decision in place.
- [ ] Update [architecture-options.md §2](../../architecture-options.md)
      to point at this ADR.
