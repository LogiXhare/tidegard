# Phase 7 Plan: BGP Mitigation Lab

Status: **Planning, accepted by the owner 2026-10-12.** No Phase 7 code
exists yet. The decisions this plan rests on are BQ-4 and BQ-13 to BQ-15
in [blocking questions](../blocking-questions.md). Each milestone records
its own engineering decisions in an ADR when it starts, as Phases 5 and 6
did.

Phase 7 delivers what the master prompt lists for it: GoBGP integration,
dry-run, a prefix allowlist, RTBH, parent-prefix announcement, FlowSpec,
withdrawal, reconciliation, lab tests and safety documentation. It ships
as **v0.9.0** on the [roadmap](../roadmap.md). It is a **lab**: everything
works end to end against BGP speakers that CI starts, and nothing is
pointed at a real network.

## What does not change

- **Production BGP stays off.** A fresh install is dry-run, and the
  mitigator does not even open a connection to GoBGP until an operator
  sets `bgp_enabled` in its configuration. A test asserts both defaults
  (the [acceptance criteria](../acceptance-criteria.md) for Phase 7).
- **Nothing announces without a human.** Detection may *propose* a
  mitigation. Only an approver can start one (BQ-14).
- **Mitigation never drives the incident lifecycle** (BQ-6). A mitigation
  is its own record, linked to an incident, with its own states. An
  incident can close while a mitigation is active, and the reverse.
- **The detector and the incident domain stay as they are.** BGP and
  gRPC crates are allowed only in `crates/mitigator`. The
  [dependency closure test](https://github.com/LogiXhare/wetechi-netmon/blob/main/crates/incident/tests/dependency_closure.rs)
  is narrowed to say so, as it was for the notifier, never widened for
  the domain.
- **No real network, ever.** Tests and examples use the documentation
  prefixes (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  `2001:db8::/32`) and private ASNs. CI peers only with speakers it
  started itself. No attack traffic is generated.

## Decisions taken for this plan

| Question | Decision | Why |
|---|---|---|
| BQ-4 Tenancy and v1.0.0 | Multi-tenancy (Phase 8) ships after v1.0.0 | v1.0.0 is the single-tenant release. Phase 7's allowlist is deployment configuration, each prefix bound to one tenant, until Phase 8 brings prefix ownership |
| BQ-13 GoBGP integration | GoBGP's gRPC API, from Rust (`tonic` and `prost`), to a `gobgpd` the operator runs | FR-6.1's supported, isolated API. One language. GoBGP stays a separate process, so its licence places no obligation here, as with Grafana |
| BQ-14 How a mitigation starts | An operator requests, or detection proposes; an approver starts it | Manual approval before every announcement in the lab. Auto-execute waits for Phase 9 or 10 |
| BQ-15 Actions | RTBH (`/32`, `/128`), parent-prefix announcement, FlowSpec discard and rate-limit, communities, large communities, `NO_EXPORT`, `NO_ADVERTISE` | FlowSpec redirect moves traffic elsewhere and fails badly when misconfigured. It waits for a later phase |

## Milestones

Each milestone ends green and is independently mergeable.

### 7A — The mitigation record

A mitigation is a new aggregate in PostgreSQL, separate from the incident:

- **What:** the action (RTBH, parent prefix, FlowSpec discard, FlowSpec
  rate-limit), the prefix, the tenant, the linked incident if any, the
  attributes (next hop, communities), the requested duration, and whether
  it is dry-run.
- **States:** `proposed`, `requested`, `approved`, `announcing`, `active`,
  `withdrawing`, `withdrawn`, and the ends `rejected`, `expired` and
  `failed`. Every transition is audited and written to the outbox, as
  incident changes are.
- **Permissions:** `mitigation.request`, `mitigation.approve` and
  `mitigation.withdraw`, in the role bundles from `noc_lead` up for
  approval. An approver cannot approve their own request unless the
  deployment turns that rule off, which is audited.
- **Idempotency and concurrency** as the incident API has them: a
  version on every change, and an idempotency key on every request.

**Exit:** the domain's state machine is tested for every legal and
illegal transition, the migration applies on PostgreSQL 15 to 18, and a
duplicate request for the same prefix and action is refused.

**Progress:** 7A ([ADR 0046](decisions/0046-phase7a-mitigation-record.md)) adds `crates/mitigation`, a pure domain crate held to the reviewed allowlist by the dependency closure test, with canonical prefixes, the four actions and their structural checks, the ten states, and every command with its permission. Six permissions join the bundles: `mitigation.read`, `request`, `withdraw` and `approve` for people, `propose` and `execute` for the mitigator alone. V19 adds `mitigations` and `mitigation_history`; audit, outbox and idempotency reuse the polymorphic incident tables. `crates/incident-postgres/tests/mitigations.rs` proves atomic writes, duplicate refusal under a race, idempotent replay, version conflicts, self-approval refusal, denied audits and tenant isolation on PostgreSQL 15 to 18. A request carries no route attributes: those are the mitigator's configuration.

### 7B — The safety guard

A pure, dependency-free check that every path to GoBGP goes through, at
request, at approval and again just before announcing:

- **Allowlist:** a deployment-wide file lists the prefixes that may be
  mitigated, each with its tenant and the actions allowed on it (BQ-4).
  A request outside it is refused, and so is one from another tenant.
- **Scope:** minimum and maximum prefix lengths per family and action. An
  RTBH is a host route (`/32` or `/128`) unless the allowlist entry
  permits a parent prefix, and never shorter than its configured bound.
- **Duration:** every mitigation has a maximum, and nothing is permanent.
- **Kill switch:** one global setting, checked on every action, that
  refuses new announcements and withdraws what is active.
- **Defaults:** dry-run on, BGP off.

**Exit:** an unauthorized-prefix suite, including property tests over
generated prefixes, proves nothing outside the allowlist or its bounds
is ever accepted, and a test asserts the defaults.

**Progress:** 7B ([ADR 0047](decisions/0047-phase7b-safety-guard.md)) adds `Guard` to `crates/mitigation`: a JSON configuration with dry-run on, BGP off and nothing allowlisted by default; floors of `/16` and `/32` no configuration can go below; no overlapping entries of different tenants; and five refusals, each with a stable code. The store runs it at request, at approval and when announcing begins, audits each refusal, and never refuses a withdrawal. `crates/mitigation/tests/unauthorized_prefixes.rs` holds the unauthorized-prefix suite; `crates/incident-postgres/tests/mitigation_guard.rs` proves the three moments against PostgreSQL. The runtime kill switch's storage and endpoint come in 7D and 7E.

### 7C — The GoBGP adapter

The only code that speaks to GoBGP:

- GoBGP's published `.proto` files, vendored from a pinned release with
  their licence, compiled with `tonic` and `prost`.
- **Paths:** RTBH with the configured next hop and the `BLACKHOLE`
  community (RFC 7999) plus `NO_EXPORT`, parent-prefix announcements,
  and FlowSpec rules (RFC 8955) for discard and rate-limit.
- **Ownership:** every path WetechiNetMon announces carries its own large
  community, so it can list exactly its own routes and never touch
  another's.
- **Dry-run** builds the exact path and records it, and never calls
  `AddPath`.
- **Transport:** loopback by default. Off loopback, TLS with a
  configured CA is required, as for every other connection. GoBGP's API
  is unauthenticated, so the runbook says never to expose it.

**Exit:** the adapter is tested against a real `gobgpd` in CI: each
action is announced and withdrawn, and its attributes read back.

**Progress:** 7C ([ADR 0048](decisions/0048-phase7c-gobgp-adapter.md)) adds `crates/mitigator` with GoBGP v4.9.0's `.proto` files vendored and checksummed, compiled by `protox` and `tonic-prost-build` without `protoc`. Paths carry the deployment's attributes and an ownership large community; listing returns only owned paths and reads each back to its mitigation's key. Plain HTTP reaches loopback only; elsewhere, TLS with a CA and an optional client certificate. The dependency closure test confines gRPC to the mitigator. CI starts a pinned, checksummed `gobgpd` on loopback in the `rust` job, and `tests/gobgp_lab.rs` announces, reads back and withdraws every action.

### 7D — The mitigator service

`wetechinetmon-mitigator`, a process like the notifier:

- Starts each approved mitigation, withdraws each one at its end, its
  maximum duration, or a withdrawal request.
- **Reconciliation:** at start and on a timer, it compares the routes
  carrying its ownership community with the active mitigations. It
  withdraws what nothing claims and announces what is missing.
- **Peer state:** monitored and exported as metrics. A mitigation is
  `active` only once GoBGP holds the path.
- **Proposals:** it consumes the incident outbox and, where a policy
  says so, creates a `proposed` mitigation for an incident. A proposal
  announces nothing.
- **Kill switch:** withdraws every active mitigation and refuses new
  ones until it is cleared.

**Exit:** restart reconciliation, stale-route removal, the maximum
duration and the kill switch are each proven against a real `gobgpd`.

**Progress:** 7D ([ADR 0049](decisions/0049-phase7d-mitigator-service.md)) adds the `wetechinetmon-mitigator` binary: one active instance by advisory lock; no GoBGP connection with BGP off; each pass expires, announces (recording the exact route, dry-run or not), withdraws at the duration and under the kill switch, and finishes what a restart left half-way; reconciliation withdraws unclaimed owned routes and restores missing ones; proposals come from the incidents table. V20 adds the runtime kill switch (`mitigation.kill_switch.engage` from `noc_lead`, `release` for platform administrators) and `mitigations.route`. The guard refusing at the last moment now ends a mitigation as `failed`. `tests/mitigator_service.rs` proves all of it against PostgreSQL 15 to 18 and a real `gobgpd`.

### 7E — API, CLI, UI and notifications

- `/api/v1/mitigations` (list, get, request, approve, reject, withdraw),
  `/api/v1/bgp/peers` and `/api/v1/bgp/routes`, in the OpenAPI document
  and the tenant-isolation suite.
- `wetechinetmonctl mitigations list|request|approve|withdraw`.
- A mitigations page in the NOC UI, with approval where the role allows.
- Notifications for approval requested, mitigation started, failed and
  withdrawn, and BGP peer down (FR-7.3).
- The incident's `mitigation_status` and `notification_status` derived
  from the records, replacing the Phase 5 constants (FU-64).

**Exit:** the UI drives a mitigation from request to withdrawal against a
real API and `gobgpd` in CI.

### 7F — The lab, hardening and Gate 2

- **The lab:** CI starts two speakers, WetechiNetMon's `gobgpd` and a
  second one standing in for the edge router, and proves what the router
  receives: the RTBH with its next hop and communities, the FlowSpec
  rule, and nothing after withdrawal.
- **Safety documentation:** an RTBH guide, a FlowSpec guide, the
  runbook (kill switch, stale routes, peer down) and the installation
  guide.
- The threat model gains route leaks, overly broad blackholes, stale
  routes, approval bypass and an exposed GoBGP API.
- A Gate 2 assessment, as Phases 5 and 6 had.

## Risks

| Id | Risk | Response |
|---|---|---|
| R25 | A mitigation blackholes more than the victim, or another network's prefix | The allowlist and prefix bounds, checked at request, approval and announcement, and an unauthorized-prefix suite |
| R26 | An announced route outlives its reason | A maximum duration, automatic withdrawal, reconciliation by ownership community, and the kill switch |
| R27 | GoBGP's gRPC API has no authentication, so anyone who reaches it can announce routes | Loopback by default, TLS required off loopback, and the runbook |
| R28 | gRPC brings a new dependency tree (`tonic`, `prost`, `h2`) | Reviewed in an ADR, confined to `crates/mitigator` by the closure test, and pinned |
| R29 | GoBGP's API changes between releases | The `.proto` files are vendored from one pinned release, and CI runs that release |

## Where to read next

- [Phase 7 acceptance criteria](../development/phase7-acceptance-criteria.md)
- [Blocking questions](../blocking-questions.md): BQ-4 and BQ-13 to BQ-15
- [Security principles](../security-principles.md): the mitigation
  safety controls
- [Phase 6 Gate 2 assessment](../development/phase6-gate2-assessment.md):
  FU-64 is closed in 7E
