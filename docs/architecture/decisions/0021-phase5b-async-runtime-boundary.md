# 0021. Phase 5B Async Runtime Boundary

Status: **Accepted** — no new dependency
Date: 2026-08-24
Deciders: Repository owner

## Context

[ADR 0018](0018-phase5-dependency-selection.md) noted the runtime "is a
consequence, not a preference" and must be justified by the frameworks
selected, not chosen first. [ADR 0020](0020-phase5b-postgresql-client.md)
selects `tokio-postgres`, which is Tokio-based. Separately,
`tidegard-incident` (Phase 5A) is entirely synchronous — every
method on `IncidentUnitOfWork` is `pub fn`, not `pub async fn`
(verified against
`crates/incident/src/unit_of_work.rs`) — and
its 531 tests run without an async test harness.

## Verified evidence

`tokio` is **already** a `[workspace.dependencies]` entry — corrected
2026-08-30, both the path and the version claim below were wrong: the
manifest declaring it is the **repository-root** `Cargo.toml` (there is
no `workspace/` directory), at `tokio = { version = "1", features =
[...] }`. That declares a **compatible-range requirement** (`^1`), not
an exact pin — `Cargo.lock` currently resolves it to `1.53.1`, which is
a lockfile resolution, not a manifest commitment to that exact patch
version. `tokio` is used directly by `crates/collector`,
`crates/storage`, and `tools/flow-replay` (verified via `grep
"tokio.workspace = true"` across all crate manifests). Phase 5B
introduces **no new runtime** — it reuses one the workspace has carried
since Phase 2.

## Options Considered

### Option A — Tokio confined to persistence and application adapters

- Pros: `crates/incident` stays synchronous, dependency-free, and
  testable without an async runtime, exactly as Phase 5A shipped it and
  as two adversarial reviews certified; matches the collector's existing
  pattern, where Tokio drives I/O at the edges while inner logic (the
  detector, the aggregator) stays synchronous; no async infects the
  531 existing tests.
- Cons: the adapter layer must bridge sync domain calls into an async
  PostgreSQL client — a real design constraint, not free.

### Option B — Make the incident domain async

- Pros: avoids any bridging code; every layer speaks the same async
  idiom.
- Cons: **directly contradicts** the approved domain boundary
  ([ADR 0011](0011-incident-domain-boundary.md)) and the persistence
  plan's own framing that PostgreSQL is a *store the domain does not
  know about*; would touch all 531 existing tests, both public traits
  (`IncidentGenerator`, `NumberAllocator`) and every call site; makes the
  domain crate impossible to unit test without a runtime, undoing one of
  Phase 5A's most-reviewed properties.

### Option C — `async-std`

- Pros: an alternative async ecosystem.
- Cons: the workspace already has Tokio as a direct dependency in three
  crates; adding a second runtime is the exact "two runtimes in one
  binary is a defect" failure ADR 0018's criteria table names explicitly.
  Not evaluated further.

## Decision

**Option A.** `crates/incident` remains synchronous and
runtime-independent. The future `crates/incident-postgres` adapter
(ADR 0029) and the correlation worker use Tokio internally for
connection I/O, but **no Tokio type and no PostgreSQL type may appear in
`crates/incident`'s public API.** The bridging pattern (how a sync
`IncidentUnitOfWork`-equivalent call is driven from an async adapter) is
Phase 5B-3 implementation detail, constrained but not fully specified by
this ADR — options include a blocking-safe synchronous core invoked from
`tokio::task::spawn_blocking`, or restructuring the adapter so async I/O
happens before and after a synchronous domain call rather than
interleaved with it. That specific mechanism is decided at
implementation time against the actual seam shape ADR 0029 produces.

## Consequences

**Easier.** Zero new runtime dependency. The domain crate's testability
without async infrastructure — a property two adversarial reviews
explicitly verified — survives Phase 5B unchanged.

**Harder.** The adapter must bridge sync and async without either
blocking Tokio's reactor thread pool incorrectly or losing cancellation
and timeout behavior. This is real design work deferred to Phase 5B-3,
not eliminated by this ADR.

**Forecloses.** A fully async domain crate, without a future ADR
explicitly revisiting this one — that would be a large, disruptive
change to code two adversarial reviews have already certified, and this
ADR records that the bar for making it should be high.

**Security.** None distinct from the client/pool ADRs.

**License.** N/A — no new dependency.

## Follow-Up

- [ ] Decide the specific sync/async bridging mechanism at Phase 5B-3,
      against the actual `IncidentGenerator`/`NumberAllocator`-equivalent
      seam ADR 0029 produces.
- [ ] Add a regression test asserting no `tokio` or `tokio_postgres`
      type appears in `crates/incident`'s public API (a `pub use` /
      signature grep, matching the discipline
      [FU-9](../../development/follow-ups.md) already applies to
      transport-capable dependencies in the detector).
