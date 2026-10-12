# Phase 7 Gate 2 Assessment

Status: **Assessed 2026-10-12, at the end of Milestone 7F.** Gate 2 is
**passed**. Every criterion is met. One is met as implemented: the
GoBGP API's own listening address is the operator's configuration, which
the installation guide and every CI lab bind to loopback. T-21, from
Phase 5, stays partial and is carried to Phase 8. FU-65 is carried too.

The criteria are those
[defined before the work started](phase7-acceptance-criteria.md), under
Gate 2. Each is assessed against `main` and the checks CI runs on every
pull request:

- Rust on Linux, with the single-speaker GoBGP lab and the two-speaker
  lab, and on Windows;
- PostgreSQL 15, 16, 17 and 18, each with a loopback `gobgpd`;
- **Web UI**, and **Web e2e** with the mitigator and a loopback `gobgpd`;
- the docs build, the secret scan and the DCO check.

| Status | Meaning |
|---|---|
| **Met** | A named test or check proves it |
| **Met, as implemented** | Proven by construction or by a CI process control, not by a test of its own |
| **Partial** | Part is proven, and the rest is a named follow-up |

## Defaults

| Criterion | Status | Evidence |
|---|---|---|
| A fresh install is dry-run with BGP disabled, each asserted by a test of the default configuration | Met | `crates/mitigation/src/guard.rs` `a_fresh_install_is_dry_run_with_bgp_off_and_allows_nothing`; `crates/mitigator/src/config.rs` `a_minimal_file_is_a_safe_install` |
| With BGP disabled, the mitigator opens no connection to GoBGP | Met | `crates/mitigator/tests/mitigator_service.rs`, step "BGP off: no connection, no reconciliation, dry-run only" ([ADR 0049](../architecture/decisions/0049-phase7d-mitigator-service.md)) |

## The mitigation record (7A)

| Criterion | Status | Evidence |
|---|---|---|
| Every legal transition works, and every illegal one is refused with a stable code | Met | `crates/mitigation/src/state.rs` `exactly_the_listed_edges_are_legal`, `terminal_states_have_no_way_out`; `crates/mitigation/src/mitigation.rs` `withdrawal_before_announcing_ends_at_once` (`mitigation.illegal_transition`), `people_cannot_drive_the_mitigators_steps` |
| Every transition is audited and written to the outbox, atomically with the change | Met | `crates/incident-postgres/tests/mitigations.rs` `mitigations_persist_atomically_refuse_duplicates_and_replay_retries`: history, audit and outbox for each of the six steps |
| Nothing is announced before approval; no self-approval unless allowed, and that choice is audited | Met | `state.rs` `nothing_reaches_a_route_without_approval`; `crates/mitigation/src/mitigation.rs` `a_requester_cannot_approve_their_own_unless_allowed`; `tests/mitigations.rs` "Nobody approves their own"; `apps/web/e2e/mitigation.spec.ts` |
| A second active mitigation for the same prefix and action is refused; a retried request is not duplicated | Met | `tests/mitigations.rs`, "Duplicate-action protection, sequential and concurrent" and "A retry replays" |
| The migration applies on PostgreSQL 15 to 18 | Met | `crates/incident-postgres/tests/migration_smoke_test.rs` with V19 to V21, on all four versions |

## Safety (7B)

| Criterion | Status | Evidence |
|---|---|---|
| An unauthorized-prefix suite, with property tests, refuses every prefix outside the allowlist, its tenant or its length bounds, for each action | Met | `crates/mitigation/tests/unauthorized_prefixes.rs` ([ADR 0047](../architecture/decisions/0047-phase7b-safety-guard.md)) |
| The guard runs at request, at approval and immediately before announcing, and a test proves each | Met | `crates/incident-postgres/tests/mitigation_guard.rs` `the_guard_decides_at_request_approval_and_announcing`; `mitigator_service.rs`, "The allowlist changed after approval: refused, failed, audited" |
| Every mitigation has a maximum duration; none is permanent | Met | `guard.rs` `bounds_duration_and_the_kill_switch_refuse`; `mitigator_service.rs`, "At its duration it comes down, without anyone acting" |
| The kill switch refuses new announcements and withdraws every active one | Met | `mitigator_service.rs`, "The kill switch takes down what is up and stops what is next"; `crates/incident-postgres/tests/mitigation_controls.rs`; `unauthorized_prefixes.rs` `the_kill_switch_refuses_everything` |

## GoBGP (7C, 7D)

| Criterion | Status | Evidence |
|---|---|---|
| Each action is announced to a real `gobgpd` in CI and withdrawn, with its attributes read back | Met | `crates/mitigator/tests/gobgp_lab.rs` `every_action_is_announced_read_back_and_withdrawn` ([ADR 0048](../architecture/decisions/0048-phase7c-gobgp-adapter.md)) |
| Dry-run records the exact path and never calls `AddPath` | Met | `mitigator_service.rs`, "Dry-run: recorded, active, and nothing sent" |
| Every announced path carries the ownership community; reconciliation never withdraws a path without it | Met | `crates/mitigator/src/route.rs` `rtbh_carries_the_next_hop_communities_and_ownership`, `another_speakers_route_is_not_ours`; `gobgp_lab.rs` (a foreign route is never listed) |
| After a restart, reconciliation withdraws stale routes and restores missing ones | Met | `mitigator_service.rs`, the two reconciliation steps |
| A mitigation is withdrawn at its maximum duration without anyone acting | Met | `mitigator_service.rs`, "At its duration it comes down" |
| GoBGP's API over loopback, or over TLS with a configured CA; plaintext off loopback refused | Met | `crates/mitigator/src/gobgp.rs` `plain_http_is_refused_off_loopback_and_https_needs_a_bundle` |

## Interfaces (7E)

| Criterion | Status | Evidence |
|---|---|---|
| Every new endpoint is in the OpenAPI document and covered by the tenant-isolation suite | Met | The [OpenAPI document](../api/openapi.json) and its drift test; `apps/api/tests/tenant_isolation.rs` covers the five `{mitigation_id}` operations, the list and the routes ([ADR 0050](../architecture/decisions/0050-phase7e-mitigation-api-cli-ui.md)) |
| The CLI implements `mitigations list\|request\|approve\|withdraw`, with tests | Met | `apps/cli/tests/mitigation_commands.rs`, plus `show`, `history`, `reject`, `kill-switch status\|engage` and `bgp routes\|peers` |
| The UI drives a mitigation from request to withdrawal against a real API and `gobgpd` in CI | Met | **Web e2e** `apps/web/e2e/mitigation.spec.ts`: a senior operator requests, a NOC lead approves, the row turns `active` through the mitigator and `gobgpd`, and the lead withdraws it |
| Approval requested, mitigation started, failed and withdrawn, and BGP peer down are notified, tested against local mocks | Met | `crates/notification/tests/mitigation_notices.rs` `mitigations_the_kill_switch_and_peers_are_told`, against loopback channels |
| The incident's `mitigation_status` and `notification_status` reflect the records (FU-64) | Met | `apps/api/tests/mitigations.rs`; `mitigation_notices.rs` (the incident's message says `withdrawn`) |

## The lab (7F)

| Criterion | Status | Evidence |
|---|---|---|
| A second speaker standing in for the edge router receives exactly what was announced, and nothing after withdrawal | Met | `crates/mitigator/tests/two_speaker_lab.rs` `the_edge_receives_exactly_what_was_announced_and_nothing_after`, in the **Rust** job, which fails if it skips ([ADR 0051](../architecture/decisions/0051-phase7f-two-speaker-lab.md)) |
| No test peers with or announces to anything CI did not start; only documentation prefixes and private ASNs | Met, as implemented | Every `gobgpd` in CI binds loopback (`scripts/start-gobgpd.sh`, `scripts/start-gobgp-lab.sh`); the BGP port of the single one is closed. Review of every test and example: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, AS 64512 to 65534 |

## Safety, unchanged

| Criterion | Status | Evidence |
|---|---|---|
| The detector is unmodified | Met | `git diff d1d5f2c..main -- crates/detector` is empty |
| BGP and gRPC crates appear only in `crates/mitigator`; the incident domain's closure is unchanged | Met | `crates/incident/tests/dependency_closure.rs` `only_the_mitigator_speaks_grpc`, `the_incident_domain_depends_only_on_reviewed_crates`, `the_mitigation_domain_depends_only_on_reviewed_crates` |
| Mitigation never changes an incident's state | Met | `mitigator_service.rs`: the incident's state and version are the same after a proposal; no mitigation code writes to `incidents` |

## Process

| Criterion | Status | Evidence |
|---|---|---|
| All existing tests stay green, on Linux, Windows and PostgreSQL 15 to 18 | Met | CI on `main`. On each PostgreSQL version every database test ran; none printed a skip |
| Every gate exits 0: formatting, lints, tests, docs, secret scan, DCO | Met | CI on every pull request, #109 to the 7F pull requests |
| Each milestone's decisions are recorded in an ADR | Met | ADRs [0046](../architecture/decisions/0046-phase7a-mitigation-record.md) to [0051](../architecture/decisions/0051-phase7f-two-speaker-lab.md), all Accepted |
| The threat model covers route leaks, broad blackholes, stale routes, approval bypass and an exposed GoBGP API, and every new threat has a passing test | Met | T-42 to T-48 in the [threat model](../security/incident-threat-model.md), mapped in the [threat tests](../security/incident-threat-tests.md). T-46 is met as implemented, as above |
| The RTBH guide, the FlowSpec guide, the runbook and the installation guide cover the mitigator | Met | [RTBH](../operations/rtbh-guide.md), [FlowSpec](../operations/flowspec-guide.md), [mitigation runbook](../operations/mitigation-runbook.md), [installation](../installation/mitigation.md) |

## Carried forward

- **T-21** stays partial: an assignee is not checked against a user
  directory until Phase 8 (FU-60).
- **FU-65**: the kill switch and the BGP peers are deployment-wide, and
  any tenant's NOC lead may engage the switch and read the peers. That is
  right for the single-tenant deployments v1.0 targets (BQ-4), and Phase
  8 confines both to the operator's tenant.
- **FlowSpec redirect** stays deferred (BQ-15).
- The lab proves what GoBGP sends, not what a vendor's router does with
  it. Each operator verifies their own edge, as the guides describe.
