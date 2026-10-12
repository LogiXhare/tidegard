# Phase 7 Acceptance Criteria

Status: **Defined 2026-10-12, before any Phase 7 code.** Part of the
[Phase 7 plan](../architecture/phase7-bgp-mitigation-lab-plan.md).

As in Phases 5 and 6, the criteria are written before the work starts,
so the work is judged against them rather than the other way round. Each
one is assessed at the end of Phase 7 with the test or check that proves
it.

## Gate 1 — Planning accepted

- [x] The owner has decided BQ-4 and BQ-13 to BQ-15
  ([blocking questions](../blocking-questions.md)).
- [x] The plan names each milestone, its exit criterion, and the risks
  (R25 to R29 in the [risk register](../risk-register.md)).
- [x] These criteria exist before any Phase 7 code.

## Gate 2 — Phase 7 complete

### Defaults

- A fresh install is dry-run, and BGP is disabled, each asserted by a
  test of the default configuration.
- With BGP disabled, the mitigator opens no connection to GoBGP.

### The mitigation record (7A)

- Every legal transition works, and every illegal one is refused with a
  stable code.
- Every transition is audited and written to the outbox, atomically with
  the change.
- Nothing is announced before approval. A request cannot be approved by
  its requester unless the deployment allows it, and that choice is
  audited.
- A second active mitigation for the same prefix and action is refused;
  a retried request with the same idempotency key is not duplicated.
- The migration applies on PostgreSQL 15 to 18.

### Safety (7B)

- An unauthorized-prefix suite, with property tests, proves the guard
  refuses every prefix outside the allowlist, outside its tenant, or
  outside its length bounds, for each action.
- The guard runs at request, at approval and immediately before
  announcing, and a test proves each.
- Every mitigation has a maximum duration, and none is permanent.
- The kill switch refuses new announcements and withdraws every active
  one.

### GoBGP (7C, 7D)

- Each action (RTBH IPv4 and IPv6, parent prefix, FlowSpec discard,
  FlowSpec rate-limit) is announced to a real `gobgpd` in CI and
  withdrawn, with its attributes read back.
- Dry-run records the exact path and never calls `AddPath`.
- Every announced path carries the ownership community, and
  reconciliation never withdraws a path without it.
- After a restart, reconciliation withdraws stale routes and restores
  missing ones.
- A mitigation is withdrawn at its maximum duration without anyone
  acting.
- GoBGP's API is reached over loopback, or over TLS with a configured
  CA; plaintext off loopback is refused.

### Interfaces (7E)

- Every new endpoint is in the OpenAPI document and covered by the
  tenant-isolation suite.
- The CLI implements `mitigations list|request|approve|withdraw`, with
  tests.
- The UI drives a mitigation from request to withdrawal against a real
  API and `gobgpd` in CI.
- Approval requested, mitigation started, failed and withdrawn, and BGP
  peer down are notified, tested against local mocks.
- The incident's `mitigation_status` and `notification_status` reflect
  the records (FU-64).

### The lab (7F)

- In CI, a second speaker standing in for the edge router receives
  exactly what was announced, and nothing after withdrawal.
- No test peers with, or announces to, anything CI did not start. Only
  documentation prefixes and private ASNs appear in tests and examples.

### Safety — unchanged

- The detector is unmodified.
- BGP and gRPC crates appear only in `crates/mitigator`, enforced by the
  dependency closure test. The incident domain's closure is unchanged.
- Mitigation never changes an incident's state.

### Process

- All existing tests stay green, on Linux, Windows and PostgreSQL 15
  to 18.
- Every gate exits 0: formatting, lints, tests, docs, secret scan, DCO.
- Each milestone's decisions are recorded in an ADR.
- The threat model covers route leaks, overly broad blackholes, stale
  routes, approval bypass and an exposed GoBGP API, and every new threat
  has a passing test.
- The RTBH guide, the FlowSpec guide, the runbook and the installation
  guide cover the mitigator.
