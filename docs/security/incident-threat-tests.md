# Incident Threat Tests

Status: **Phase 5F security review**, 2026-10-05; Phase 6 threats T-30 to T-41 added, and T-08 updated, 2026-10-12; Phase 7 threats T-42 to T-48 added, 2026-10-12; Phase 9D threats T-49 to T-57 added, 2026-10-13.

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
  ([#73](https://github.com/LogiXhare/tidegard/pull/73)).
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
| T-06 Unauthorized state transition | Met | `crates/incident/tests/threats.rs` `every_command_is_allowed_exactly_by_its_permission_for_every_role` (17 commands × 4 roles plus ingestion; a refusal changes nothing and is audited) |
| T-07 Malicious note content | Met | `apps/api/tests/threats.rs` (markup, SQL, JSON, line breaks, bidi control and a 4,000-character line round-trip byte for byte; NUL is `400`); `apps/cli/src/output.rs` `control_characters_never_reach_the_terminal` |
| T-08 Stored XSS | Met (Phase 6D) | Four layers, each tested ([ADR 0044](../architecture/decisions/0044-phase6d-noc-ui.md)): React renders strings as text; an ESLint rule refuses every way of handing HTML to the DOM, and `apps/web/src/lint.test.ts` proves the rule; component tests render hostile titles, notes, targets and assignees as text (`Incidents.test.tsx`, `IncidentDetail.test.tsx`, `Overview.test.tsx`); and the page's Content-Security-Policy refuses inline script. `apps/web/e2e/lifecycle.spec.ts` stores a hostile note through the real API and checks, in a real browser, that it shows as text and never runs. The API still returns text verbatim, and the CLI strips control characters. |
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
| T-30 Cross-site request forgery | Met (6C) | `apps/api/tests/sessions.rs` (no header or a wrong one is `403 api.csrf_rejected`, audited, and changes nothing); `apps/web/e2e/lifecycle.spec.ts` (a cookie request without the header, in a real browser) |
| T-31 Session fixation and theft | Met (6C) | `apps/api/tests/sessions.rs` (a planted id is never honoured; idle and absolute expiry; revocation and sign-out end it; no secret logged) |
| T-32 Clickjacking | Met (6D) | `apps/api/tests/web.rs`, `apps/api/src/web.rs` (`X-Frame-Options: DENY`, `frame-ancestors 'none'`); `apps/web/e2e/lifecycle.spec.ts` |
| T-33 Path traversal in file serving | Met (6D) | `apps/api/src/web.rs` `pages_get_the_index_and_assets_only_their_own_files`; `apps/api/tests/web.rs` |
| T-34 Compromised npm dependency | Met, as implemented (6D) | A process control rather than a test: the **Web UI** CI job (`npm ci --ignore-scripts`, `npm audit`, the licence check, no inline code) and Dependabot's 14-day cooldown. Residual: a malicious release older than the cooldown and unknown to advisories. |
| T-35 SSRF through a destination | Met (6E) | `crates/notification/src/destination.rs` (every non-public range refused; allowlist exact or true subdomain; plain HTTP refused); `crates/notification/tests/delivery.rs`, `email.rs` (an unlisted host is refused before connecting) |
| T-36 Channel secret leakage | Met (6E) | `crates/notification/tests/delivery.rs` (no secret in the log, in another channel's message, or on the timeline); `destination.rs` (paths redacted) |
| T-37 Notification storm | Met (6E) | `crates/notification/src/limits.rs` `a_burst_is_cut_at_the_limit_and_refills`, `a_duplicate_is_held_back_for_the_window_only` |
| T-38 Forged or replayed webhook | Met (6E) | `crates/notification/src/hmac.rs` (RFC 4231); `crates/notification/tests/delivery.rs` (the receiver verifies the signature) |
| T-39 Content injection into a channel | Met (6E) | `crates/notification/src/message.rs` `hostile_titles_cannot_mention_link_or_format`; `crates/notification/src/email.rs`, `tests/email.rs` (no injected header or recipient) |
| T-40 Cross-tenant traffic disclosure | Met (6B) | `apps/api/tests/tenant_isolation.rs` (another tenant's `noc_lead` gets `404` on every traffic endpoint); `apps/api/tests/traffic.rs` |
| T-41 Query injection into ClickHouse | Met (6B) | `apps/api/src/clickhouse.rs` `every_request_is_read_only_bounded_and_parameterised`; `apps/api/tests/traffic.rs` (hostile dimensions are `400`) |
| T-42 Route leak | Met (7C, 7F) | `crates/mitigator/src/route.rs` `the_configuration_has_safe_defaults_and_strict_parsing`, `rtbh_carries_the_next_hop_communities_and_ownership`; `crates/mitigator/tests/two_speaker_lab.rs` (the edge receives `NO_EXPORT`) |
| T-43 Overly broad blackhole | Met (7B) | `crates/mitigation/tests/unauthorized_prefixes.rs`; `crates/mitigation/src/guard.rs` `a_dangerous_configuration_is_refused`; `crates/mitigation/src/action.rs` `rtbh_is_a_host_route_and_a_parent_is_not`; `crates/incident-postgres/tests/mitigation_guard.rs` |
| T-44 Stale route | Met (7D, 7F) | `crates/mitigator/tests/mitigator_service.rs` (expiry, reconciliation, kill switch); `crates/mitigator/tests/two_speaker_lab.rs` (nothing at the edge after withdrawal) |
| T-45 Approval bypass | Met (7A, 7E) | `crates/mitigation/src/state.rs` `nothing_reaches_a_route_without_approval`; `crates/mitigation/src/mitigation.rs` `a_requester_cannot_approve_their_own_unless_allowed`; `crates/incident/src/authorization.rs` `only_the_mitigator_proposes_or_executes`; `apps/api/tests/mitigations.rs`; `apps/web/e2e/mitigation.spec.ts` |
| T-46 Exposed GoBGP API | Met, as implemented (7C) | `crates/mitigator/src/gobgp.rs` `plain_http_is_refused_off_loopback_and_https_needs_a_bundle`. `gobgpd`'s own listening address is the operator's configuration: the installation guide binds it to loopback, and CI's labs do. |
| T-47 Kill-switch release by a stolen token | Met (7E) | `apps/api/tests/mitigations.rs` (a lead's release is `403`; the host command releases); `apps/cli/tests/mitigation_commands.rs` |
| T-48 Cross-tenant blackhole | Met (7B, 7E) | `crates/mitigation/tests/unauthorized_prefixes.rs` `another_tenants_space_is_refused_with_the_same_answer_as_nobodys`; `apps/api/tests/tenant_isolation.rs` |
| T-49 Hostile flow datagram | Met (9D) | `crates/protocol-ipfix/src/lib.rs` `decode_message_never_panics` and siblings (proptest); `crates/protocol-ipfix/src/decoder.rs` `the_fuzzer_s_out_of_memory_input_ends`, `a_template_of_zero_length_records_is_refused`, `a_huge_field_count_in_a_short_record_is_truncated`; the fuzz workflow on decoder pull requests |
| T-50 Memory exhaustion through spoofed exporters and templates | Met (9D) | `crates/collector/src/exporter.rs` `a_new_exporter_past_the_limit_is_refused_until_one_goes_idle`, `the_allowlist_admits_its_networks_only`; `crates/collector/src/lib.rs` `datagrams_outside_the_exporter_limits_are_refused_before_decoding`; `crates/protocol-ipfix/src/template_cache.rs` `a_template_past_the_count_limit_is_refused_and_the_cache_kept`, `templates_past_the_field_limit_are_refused` |
| T-51 Flow flood | Met (3, 9B) | `crates/aggregator/src/bounded_map.rs` `evicts_least_recently_updated_entry_when_at_capacity`; the benchmark workflow's load test and soak |
| T-52 Forged flows that trigger detection | Met, as implemented (7, 9D) | As T-45 (no route without approval) and T-50 (the allowlist). Nothing mitigates automatically in v1.0.0 (BQ-17) |
| T-53 ClickHouse credential or data exposure | Met (9A) | `crates/storage/src/connection.rs` `plain_http_reaches_loopback_only`, `https_needs_a_ca_bundle`, `credentials_never_ride_in_the_url`, `logs_show_only_scheme_host_and_port`; the Grafana job's export over TLS |
| T-54 A compromised service reaching further | Met (9A) | The package job: `systemd-analyze verify` and `security` on every unit, each image's user, the collector run `--read-only --cap-drop ALL`, hadolint, Trivy |
| T-55 A tampered release | Deferred (10A) | The release pipeline's signatures and provenance, verified on a clean runner, are Phase 10A's exit |
| T-56 A compromised dependency or build tool | Met (9D) | The Rust job's `cargo-deny` step; the web job's `npm audit`; the package job's Trivy scan |
| T-57 A secret in the public history | Met (9D) | The history job's gitleaks scan of the full history |

## Summary

| Status | Count |
|---|---|
| Met | 50 |
| Met, as implemented | 5 (T-03, T-18, T-34, T-46, T-52) |
| Partial | 1 (T-21 → FU-60) |
| Deferred | 1 (T-55 → Phase 10A) |

One of the 57 threats is partial, so the Gate 2 criterion "every threat
has a passing test" is not fully met. T-55 is deferred to the release
pipeline, which does not exist yet; nothing is released until it does. T-21 needs a user directory, which
arrives with Phase 8. Being named as assignee grants nothing, and a test
proves it.
