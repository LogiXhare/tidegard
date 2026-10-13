# Phase 5 Gate 2 Assessment

Status: **Assessed 2026-10-11, at the end of Milestone 5F.** Gate 2 is
**not passed in full**. Every criterion is met but one: threat
coverage, where T-21 needs a user directory and T-08 needs a UI, each
with its follow-up. One deviation was reviewed and ratified by the
owner.

The criteria are those
[defined before the work started](phase5-acceptance-criteria.md), under Gate 2.
Each is assessed against `main` and the tests CI runs on every pull
request:

- Rust on Linux and on Windows;
- PostgreSQL 15, 16, 17 and 18;
- the docs build;
- the secret scan and the DCO check;
- the backup and restore drill.

| Status | Meaning |
|---|---|
| **Met** | A named test or check proves it |
| **Met, as amended** | Proven. The mechanism changed from the plan, and an accepted ADR records the change |
| **Partial** | Part is proven, and the rest is a named follow-up |
| **Deviation, ratified** | Not met as written. The owner reviewed the outcome and accepted it, on the date given |

## Functional

| Criterion | Status | Evidence |
|---|---|---|
| Events ingest at-least-once, with effectively-once processing | Met, as amended | Through `detection_event_inbox`, not an outbox ([ADR 0012](../architecture/decisions/0012-incident-event-ingestion.md), [ADR 0035](../architecture/decisions/0035-phase5c-detection-event-inbox.md)). `detection_event_inbox.rs`, `inbox_worker_loop.rs`, and the collector's `incident_end_to_end.rs` |
| Correlation is deterministic and order-independent, by property test | Met | `properties.rs` `correlation_and_category_are_order_independent` |
| Duplicates never create a second incident, for any interleaving | Met | `properties.rs` `duplicate_ingestion_never_creates_a_second_incident`; `retry_and_races.rs` (concurrent creates open one incident); `concurrent_races.rs` |
| Every legal transition works; every illegal one is refused with a stable code | Met | `state.rs` `every_legal_automatic_edge_is_accepted`; the guards in `transition.rs`; the API's `transitions.rs`; the error-code registry test |
| The five end reasons are distinguished and surfaced through the API | Met | `domain_end_to_end.rs` `the_five_end_reasons_are_recorded_distinctly`. The cause is on the timeline entry, which the API returns |
| Recovery, abort with prior state restored, auto-close and reopen follow configuration | Met | `recovery_abort_restores_investigating_not_open`, `automatic_closure_waits_for_the_closure_delay`, `critical_incident_does_not_auto_close_but_manual_close_works`, the reopen tests, `maintenance_timers.rs` |
| A detector restart mid-attack yields one incident | Met | `domain_end_to_end.rs` `a_detector_restart_mid_attack_yields_one_incident` |
| A silent detector leaves no incident open forever | Met | `a_silent_detector_moves_an_incident_to_recovering_only_after_the_threshold`; `maintenance_timers.rs` |
| Assignment, notes **with supersession**, severity and priority changes all work and are audited | Met | Severity and priority are audited with before and after (FU-59). An edit appends a note that supersedes the author's own, and a redaction empties a body and records who and why (FU-63): `threats.rs` `an_edit_appends_a_new_note_and_keeps_the_original`, `only_the_author_may_edit_a_note`, `redaction_needs_its_permission_and_a_reason_and_keeps_the_record`; `service_round_trip.rs` (the columns, the stamps kept on a later save, the removed words nowhere in notes, timeline or audit); the API's `transitions.rs`; the CLI's `note_edits_and_redactions_send_what_the_api_takes` |
| The REST API implements every planned endpoint | Met | The [OpenAPI document](../api/openapi.json) is checked against the handlers. `tenant_isolation.rs` exercises every operation in it |
| The CLI implements every planned command, with its tests | Met | `read_commands.rs`, `change_commands.rs` (`every_error_class_has_its_exit_code`, `no_terminal_and_no_yes_is_an_error_never_an_assumed_yes`, `a_retry_reuses_the_key`), `more_commands.rs` |

## Non-functional

| Criterion | Status | Evidence |
|---|---|---|
| Every mutation is atomic across state, timeline, audit and outbox, proven by injected failure at each commit point | Met | `failure_injection.rs` `an_injected_failure_at_any_flush_point_commits_nothing_and_a_transient_one_is_retried`, at every `FlushPoint` |
| An audit write failure rolls back the mutation | Met | The same test, at `FlushPoint::Audit` |
| Optimistic concurrency prevents lost updates | Met | T-13 ([threat tests](../security/incident-threat-tests.md)) |
| Idempotent retries are safe; reuse with another body conflicts | Met | T-14 |
| Tenant isolation on every endpoint; cross-tenant is `404` | Met | `tenant_isolation.rs`, driven by the OpenAPI document |
| Every capacity limit is enforced, with defined breach behaviour | Met | Notes, suppression reasons, policy references, evidence, page sizes, export rows and rate limits are refused or capped, and tested. The timeline's defined breach behaviour is an alert, never truncation ([domain model](../architecture/incident-domain-model.md)): the `timeline_pressure` gauge reports the largest active timeline (`maintenance_timers.rs`, `metrics.rs` `stats_set_the_gauges`), and the [runbook](../operations/incident-runbook.md) alerts at 40,000 of 50,000 |
| The timeline is never truncated | Met | Nothing deletes or caps timeline rows. Retention removes a closed incident whole, after 24 months |
| Prometheus labels are asserted against an allowlist | Met | `metrics.rs` `every_label_is_on_the_allowlist` |
| No note body appears in a log at `INFO` or above | Met | T-23 |
| Benchmarks are run and published with real numbers | Met | [Capacity planning](../operations/capacity-planning.md#incident-persistence-measured), with the run, the machine and the variance |
| Backup and restore are tested, not assumed | Met | The [drill](../operations/backup-and-restore.md) runs on every pull request, on 15 to 18. Point-in-time recovery, cross-version restore and restore into a separate cluster are not drilled yet (FU-61) |

## Safety — the non-negotiables

| Criterion | Status | Evidence |
|---|---|---|
| No notification is delivered by any code path | Met, as implemented | Proven structurally rather than by a recording sink. The workspace contains no mail, chat or webhook crate (`dependency_closure.rs`), and nothing consumes the outbox (FU-62). The collector's `incident_end_to_end.rs` checks that every outbox row is still pending |
| No mitigation is attempted, proven by the dependency closure | Met | `dependency_closure.rs` holds the detector and the incident domain to a reviewed allowlist, and refuses routing and device-access crates anywhere in the workspace |
| `executed` is false on every linked detection event | Met | An event claiming an executed action is quarantined (`an_event_claiming_an_executed_action_is_quarantined_and_never_linked`) |
| `mitigation_status` and `notification_status` are `none` | Met | Constants in the API; `get_incident.rs` |
| Phase 4 detector behaviour is unmodified | Met | `git diff d1d5f2c..main -- crates/detector` is empty. `d1d5f2c` is the first Phase 5 commit |
| ClickHouse stays on `0.13` | Met | `Cargo.lock`: `clickhouse 0.13.3` |
| No Dependabot PR merged as part of Phase 5 | **Deviation, ratified** | Two Dependabot PRs were merged on 2026-10-05, outside the rule: [#52](https://github.com/LogiXhare/tidegard/pull/52), seven GitHub Actions updates, and [#53](https://github.com/LogiXhare/tidegard/pull/53), patch updates to `thiserror` 2.0.21, `uuid` 1.26.1 and `rustls` 0.23.45. Every check passed on both, everything since has been tested on top of them, and neither touches ClickHouse. **The owner ratified both on 2026-10-05: they stay.** The Dependabot PRs opened since (#82, #83, #84, and #21 for ClickHouse) stay unmerged until Phase 5 closes |

## Process

| Criterion | Status | Evidence |
|---|---|---|
| All existing tests green, plus the Phase 5 suite | Met | CI on `main` |
| Every gate exits 0 | Met, since #79 | The History job had failed on every PR since the move to an organisation: `gitleaks-action` needs a paid licence there. Since #79, the free gitleaks binary scans the whole history |
| DCO on every commit | Met | Each PR's commits were checked by hand while the CI check could not run. Since #79, CI checks them again. Dependabot commits are exempt by policy |
| ADRs 0011–0017 Accepted | Met | Each records where the implementation differs ([index](../architecture/decisions/index.md)) |
| FR-5.1 references ADR 0014 | Met | [Functional requirements](../functional-requirements.md) |
| Documentation: installation, configuration, operations, runbook, API reference | Met | [Installation](../installation/incident-management.md), [runbook](../operations/incident-runbook.md), [backup and restore](../operations/backup-and-restore.md), service READMEs, [API reference](../api/openapi.json) |
| Risk register updated; R16–R18 reassessed | Met | [Risk register](../risk-register.md) |
| Every threat has a passing test (5F exit) | **Partial** | 25 Met, 2 Met as implemented, 1 Partial (T-21, which needs a user directory in Phase 8; being named assignee grants nothing, and a test proves it), 1 Deferred (T-08, stored XSS, which needs a UI in Phase 6) ([threat tests](../security/incident-threat-tests.md)) |

## Found and fixed during 5F

- **T-18:** late news reopened resolved incidents (#73).
- **T-07:** a NUL character in text caused a `500` (#74).
- **Raw NUL bytes in source:** they made git treat two files as binary (#76).
- **The History job:** it had enforced nothing since the org move (#79).
- **The safety property:** it was reviewed, never tested (FU-9, #76).
- **T-20:** the audit row lacked before and after (FU-59, #81).
- **The runbook:** it named metrics that were never built (#80).
- **Note supersession and redaction:** the schema had the columns, but
  nothing used them (FU-63).
- **The timeline limit:** its alert was designed but never built
  (FU-32).
- **CI on current stable Rust:** `AtomicU64::fetch_update` became
  deprecated, and with warnings denied every build failed (#85).

## What remains

| Item | Why it is open | Follow-up |
|---|---|---|
| T-21 assignee validation | Needs a user directory | FU-60, Phase 8 |
| T-08 stored XSS | Needs a UI | Phase 6 acceptance, R17 |
| PITR, cross-version and cross-cluster restore drills | Only the logical restore is drilled | FU-61 |
| The outbox has no consumer | `outbox_pending` only rises until Phase 6 | FU-62 |
