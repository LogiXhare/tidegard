# Incident Threat Tests

Status: **Phase 5F security review**, 2026-10-05.

This maps each threat in the [threat model](incident-threat-model.md) to
the tests that prove its control. Gate 2 requires that every threat has a
passing test
([acceptance criteria](../development/phase5-acceptance-criteria.md)).

## How to read this

Test paths are relative to the repository root. Tests named in
`crates/incident-postgres/tests` or `apps/api/tests` need PostgreSQL, and CI
runs them on PostgreSQL 15, 16, 17 and 18. The test log of each of those
jobs must show the test as `ok`, and it must not have skipped.

| Status | Meaning |
|---|---|
| **Met** | A test proves the control as the threat model states it. |
| **Met, as implemented** | A test proves the control. The control differs in form from the planned wording, and the difference is noted. |
| **Partial** | Part of the control is proven, and the rest is a recorded follow-up. |
| **Deferred** | The control belongs to a later phase by design. |

## Findings fixed by this review

- **T-18.** Inside the reopen window, two kinds of event reopened a resolved
  incident:
  - a detection ending;
  - a delayed event of an episode the incident already held.

  Both now link as late evidence and never reopen
  ([#73](https://github.com/LogiXhare/wetechi-netmon/pull/73)).
- **T-07.** A NUL character in any operator text reached PostgreSQL. Text
  columns cannot store NUL, so the request failed as a `500`. The API now
  refuses a NUL in any JSON string or tag key with `400`.

## Traceability

| Threat | Status | Tests |
|---|---|---|
| T-01 Forged detection event | Met | `crates/incident/tests/threats.rs` `every_command_is_allowed_exactly_by_its_permission_for_every_role` (the ingestion credential is refused every operator command); `crates/incident/src/authorization.rs` `ingestion_service_account_permission_is_not_in_any_human_bundle` |
| T-02 Duplicate event flood | Met | `apps/api/tests/threats.rs` (the same event 1,000 times is one incident and one link row); `crates/incident-postgres/tests/detection_event_inbox.rs` |
| T-03 Correlation-key collision | Met, as implemented | `crates/incident/tests/threats.rs` `equal_targets_share_a_key_and_different_ones_never_do` (property test). The key is typed, not a canonicalised string, so there is no string form to collide. `crates/incident/tests/properties.rs` `tenant_a_events_never_correlate_under_tenant_b` |
| T-04 Incident ID enumeration | Met | `apps/api/tests/tenant_isolation.rs` `no_endpoint_crosses_the_tenant_boundary` (every per-incident operation, audit included) |
| T-05 Tenant escape | Met | `apps/api/tests/tenant_isolation.rs` (operations read from the OpenAPI document); `apps/api/tests/list_incidents.rs`; residual risk R16 (no row-level security until Phase 8) |
| T-06 Unauthorized state transition | Met | `crates/incident/tests/threats.rs` `every_command_is_allowed_exactly_by_its_permission_for_every_role` (15 commands × 4 roles plus ingestion; a refusal changes nothing and is audited) |
| T-07 Malicious note content | Met | `apps/api/tests/threats.rs` (markup, SQL, JSON, line breaks, bidi control and a 4,000-character line round-trip byte for byte; NUL is `400`); `apps/cli/src/output.rs` `control_characters_never_reach_the_terminal` |
| T-08 Stored XSS | Deferred | There is no UI in Phase 5. Escaping on output is a Phase 6 acceptance item (R17). The API returns text verbatim as JSON, and the CLI strips control characters. |
| T-09 Audit-log injection | Met | `apps/api/tests/threats.rs` (a reason holding newlines and JSON makes exactly one audit row and one note, stored byte for byte); audit rows are JSONB written from typed values |
| T-10 SQL injection | Met | `apps/api/tests/threats.rs` (payloads in `sort`, `order`, `state`, `cursor`, `incident_number`, the time range and a tag key are refused or stored as data, and the table is intact); `crates/incident-postgres/src/queries.rs` `the_tenant_is_always_the_first_parameter` (parameters, never interpolation) |
| T-11 Query exhaustion | Met | `apps/api/src/list.rs` unit tests (page size capped at 200, 90-day ranges, unknown parameters refused); `apps/api/tests/list_incidents.rs` |
| T-12 Export exhaustion | Met | `apps/api/tests/incident_history.rs` (the export audits itself; viewer `403`; cross-tenant `404`); `EXPORT_MAX_ROWS` caps each history at 5,000 entries; exports have their own limit of 10 per minute (`apps/api/src/rate_limit.rs` tests) |
| T-13 Optimistic-lock bypass | Met | `apps/api/tests/threats.rs` (two conflicting commands on one version: exactly one wins and the other gets `VersionConflict`; a transition without a version is `400`); `crates/incident/tests/threats.rs` `every_transition_needs_the_current_version` |
| T-14 Idempotency-key abuse | Met | `crates/incident/tests/domain_end_to_end.rs` `duplicate_idempotency_key_replays_and_conflicting_body_conflicts`, `idempotency_key_reused_across_two_incidents_conflicts`; `apps/api/tests/threats.rs` (one key in two tenants is two requests); `crates/incident/src/idempotency.rs` `different_tenants_do_not_share_a_record` |
| T-15 Outbox replay | Met | `crates/incident-postgres/tests/detection_event_inbox.rs` `the_inbox_ingests_each_event_once_and_dead_letters_what_it_cannot_process`; `apps/api/tests/threats.rs` (T-02's thousand replays) |
| T-16 Dead-letter poisoning | Met | `crates/incident-postgres/tests/detection_event_inbox.rs`; `crates/incident-postgres/tests/outbox_and_retention.rs` |
| T-17 Clock manipulation | Met | `crates/incident-postgres/tests/clock_skew.rs`; `crates/incident-postgres/tests/maintenance_timers.rs` `timers_advance_incidents_on_database_time_and_never_auto_close_critical`; `crates/incident/src/durable_time.rs` and `reconstitute.rs` (timestamps that run backward are refused) |
| T-18 Stale event reopening | Met, as implemented | `crates/incident/tests/domain_end_to_end.rs` `late_news_about_a_resolved_incident_links_and_never_reopens`; `crates/incident-postgres/tests/clock_skew.rs`. Late is decided by detection identity, not timestamps (see the threat model). |
| T-19 Unauthorized suppression | Met | `crates/incident/tests/threats.rs` `a_suppressed_incident_still_accumulates_events` (it still links and counts; only `noc_lead` may suppress); `apps/api/tests/transitions.rs` (an expiry in the past or more than 30 days away is `422`; `expires_at` is required by the request schema) |
| T-20 Unauthorized severity reduction | Met | `crates/incident/tests/threats.rs` `lowering_severity_needs_a_reason_and_records_both_values`; `apps/api/tests/transitions.rs` (the audit endpoint shows `before`, `after` and the reason for a severity change, and both values for a priority change). The reason is required when lowering. Fixed by FU-59. |
| T-21 Cross-tenant assignment | Partial | `apps/api/tests/threats.rs` (naming another tenant's user as assignee grants that user nothing; their token still gets `404`). There is no user directory in Phase 5, so an assignee id cannot be validated against one (FU-60). |
| T-22 Sensitive evidence leakage | Met | `apps/api/tests/tenant_isolation.rs` (`detections` and `export` are `404` across tenants); residual risk R18 (evidence storage is undesigned) |
| T-23 Log leakage | Met | `apps/api/tests/threats.rs` (no note body, reason or token appears in any log line at `INFO` or above during the run) |
| T-24 Prometheus cardinality explosion | Met | `crates/incident-manager/src/metrics.rs` `every_label_is_on_the_allowlist`, `no_label_can_identify_a_tenant_or_an_incident`. The API exports no metrics. |
| T-25 Clock-skew reopen or duplicate | Met | `crates/incident-postgres/tests/clock_skew.rs`; `crates/incident/src/unit_of_work.rs` `a_recurrence_before_the_reference_time_is_refused_not_duplicated` |
| T-26 Connection-pool exhaustion | Met | `crates/incident-postgres/tests/pool_exhaustion.rs` `an_exhausted_pool_is_unavailable_in_bounded_time_and_dead_connections_are_replaced`; the API maps unavailability to `503` (`apps/api/src/problem.rs`) |
| T-27 Corrupted or hand-crafted row | Met | `crates/incident/src/reconstitute.rs` (table-driven refusals); `crates/incident-postgres/tests/incident_row_mapping.rs` |
| T-28 TLS downgrade | Met | `crates/incident-postgres/tests/tls_connector.rs` `tls_connections_verify_the_chain_and_the_host_name`; `apps/api/src/server.rs` `plaintext_is_refused_off_loopback_and_allowed_on_it`; `apps/cli/src/config.rs` `plaintext_only_to_loopback_and_tls_needs_a_ca` |
| T-29 Outbox lease starvation | Met | `crates/incident-postgres/tests/outbox_and_retention.rs`; `crates/incident-postgres/tests/outbox_concurrency.rs` `outbox_claims_stay_disjoint_survive_crashes_and_count_attempts_once` |

## Summary

| Status | Count |
|---|---|
| Met | 25 |
| Met, as implemented | 2 (T-03, T-18) |
| Partial | 1 (T-21 → FU-60) |
| Deferred | 1 (T-08 → Phase 6, R17) |

One of the 29 threats is partial, so the Gate 2 criterion "every threat
has a passing test" is not fully met. T-21 needs a user directory, which
arrives with Phase 8. Being named as assignee grants nothing, and a test
proves it.
