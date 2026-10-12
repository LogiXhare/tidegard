# Phase 6 Gate 2 Assessment

Status: **Assessed 2026-10-12, at the end of Milestone 6F.** Gate 2 is
**passed**. Every criterion is met. One is met as amended by an accepted
ADR, and one is met by a process control rather than a test. One
earlier threat, T-21, stays partial and is carried to Phase 8, as the
Phase 5 assessment recorded. One gap outside the criteria was found and
filed as FU-64.

The criteria are those
[defined before the work started](phase6-acceptance-criteria.md), under
Gate 2. Each is assessed against `main` and the checks CI runs on every
pull request:

- Rust on Linux and on Windows;
- PostgreSQL 15, 16, 17 and 18, with a ClickHouse service;
- **Grafana dashboards**, which loads every dashboard in a real Grafana;
- **Web UI** and **Web e2e**;
- the docs build, the secret scan and the DCO check.

| Status | Meaning |
|---|---|
| **Met** | A named test or check proves it |
| **Met, as amended** | Proven. The mechanism changed from the plan, and an accepted ADR records the change |
| **Met, as implemented** | Proven by construction or by a CI process control, not by a test of its own |
| **Partial** | Part is proven, and the rest is a named follow-up |

## Dashboards (6A)

| Criterion | Status | Evidence |
|---|---|---|
| Every dashboard is original, with a unique, stable UID | Met | `tools/dashboard-check` `uids_are_checked_for_form_and_uniqueness`; the four dashboards use `wnm-*` UIDs ([ADR 0041](../architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)) |
| Every datasource is a dashboard variable | Met | `a_hard_coded_datasource_is_refused` |
| CI fails on an unknown Prometheus metric or ClickHouse table | Met | `an_unknown_metric_or_table_is_refused`; `tests/dashboards.rs` `every_dashboard_queries_only_what_exists`, which reads the metric names from the code and the tables from the schema |
| The dashboards load in a Grafana started in CI against real datasources | Met | The **Grafana dashboards** job starts Grafana, ClickHouse and Prometheus, provisions the dashboards and runs every panel's query. It caught a query using a column the traffic totals do not have, which the static check cannot see |
| No Grafana binary is bundled or modified (BQ-2) | Met | The repository ships JSON and provisioning files only. CI pulls the stock `grafana/grafana` image |

## Read APIs (6B)

| Criterion | Status | Evidence |
|---|---|---|
| Every new endpoint is in the OpenAPI document and covered by the tenant-isolation suite | Met | `tenant_isolation.rs` is driven by the [OpenAPI document](../api/openapi.json) and covers every per-incident operation and the three traffic endpoints. `/api/v1/session` returns only the caller's own session; `sessions.rs` proves it carries its token's tenant |
| Traffic needs its own deployment-wide permission, which no tenant-scoped default role holds (R21) | Met, as amended | [ADR 0042](../architecture/decisions/0042-phase6b-traffic-read-api.md) puts `traffic.read` in every human role and confines traffic to **one configured traffic tenant** instead. Every other tenant gets `404` before anything is read. This keeps the same guarantee, no tenant sees another's traffic, without a role nobody holds. `tenant_isolation.rs`; `traffic.rs` `traffic_is_read_from_clickhouse_for_the_traffic_tenant_only` |
| Every traffic query is bounded by a time range and a row limit | Met | `traffic.rs` (unit) `ranges_default_to_the_last_hour_and_are_bounded`, `a_summary_never_exceeds_its_point_budget`; `clickhouse.rs` `every_request_is_read_only_bounded_and_parameterised` (`readonly=2`, `max_execution_time`, `max_result_rows`) |

## Sessions (6C)

| Criterion | Status | Evidence |
|---|---|---|
| A session comes only from a valid, unexpired, unrevoked token, with its tenant, actor and role | Met | `apps/api/tests/sessions.rs` `sessions_sign_in_expire_end_and_refuse_forgery` |
| The cookie is `HttpOnly`, `Secure` off loopback, `SameSite=Strict`; only its hash is stored | Met | `session.rs` `the_cookie_is_http_only_strict_and_secure_with_tls`, `session_ids_are_well_formed_distinct_and_hashed`; the e2e test reads the cookie's flags in a real browser |
| Idle and absolute expiry; revocation ends sessions; CSRF refused; fixation refused | Met | `sessions.rs`, each as its own step; `the_csrf_value_belongs_to_one_session`; e2e `a request without the CSRF value is refused even with the cookie` |
| Sign-in, sign-out and refusals are audited; no session id or token is logged | Met | `sessions.rs` checks the audit rows and a captured log ([ADR 0043](../architecture/decisions/0043-phase6c-browser-sessions.md)) |

## The NOC UI (6D)

| Criterion | Status | Evidence |
|---|---|---|
| The UI drives an incident from open to closed, notes included, against a real API in CI | Met | **Web e2e**: `an operator signs in, works an incident to closed, and signs out`, with PostgreSQL, the incident manager and the API serving the built UI |
| T-08 is Met | Met | `lint.test.ts` `refuses every way of handing HTML to the DOM`; `Incidents.test.tsx` and `IncidentDetail.test.tsx` render hostile text as text; `web.rs` `the_page_policy_allows_no_inline_code_and_no_framing`; the e2e test seeds a hostile title and note ([ADR 0044](../architecture/decisions/0044-phase6d-noc-ui.md)) |
| The theme meets FR-10.2: colour-blind-safe, never colour alone | Met, as implemented | The palette is Okabe–Ito (`styles.css`), and every severity shows its word and a shape as well as a colour (`Severity.tsx`). Reviewed, not tested by a tool |
| `package-lock.json` is committed; CI runs `npm ci`, `npm audit` and a licence check (R22) | Met | The **Web UI** job; T-34 |

## Notifications (6E)

| Criterion | Status | Evidence |
|---|---|---|
| Email, Teams, Slack, Telegram and webhook each have an integration test against a local mock; nothing is sent to the internet from CI | Met | `crates/notification/tests/delivery.rs` `the_notifier_delivers_retries_refuses_and_records` (Slack, Teams, webhook, Telegram, on loopback); `tests/email.rs` against a mock SMTP relay. Every destination in both is `127.0.0.1` |
| Webhook destinations pass an allowlist; private and link-local ranges refused by default; redirects not followed (R23) | Met | `destination.rs` `only_public_unicast_addresses_pass`, `the_allowlist_is_exact_or_a_true_subdomain`, `plain_http_private_and_unlisted_hosts_are_refused`; `delivery.rs` refuses an unlisted host and a `302`, and the redirect target is never reached |
| Deduplication and per-channel rate limits are tested under a burst (R24) | Met | `limits.rs` `a_burst_is_cut_at_the_limit_and_refills`, `a_duplicate_is_held_back_for_the_window_only` |
| Each delivery result is on the timeline; repeated failures dead-letter | Met | `delivery.rs`: every attempt is a `notification_result` entry, the incident's version never moves, a failed channel is retried alone, and a restarted notifier at its retry limit moves the message to `incident_dead_letter` |
| Channel secrets never appear in a log, an API response or an export | Met | `delivery.rs` captures the log at `DEBUG` and finds no webhook secret, bot token or Slack or Teams URL in it, nor in any other channel's message; `config.rs` `the_database_url_is_never_debug_printed`. The API serves nothing about channels, so no response or export can hold one |
| Every payload reports `mitigation_status` as `none` | Met | `message.rs` `every_message_says_nothing_was_mitigated`; `delivery.rs` checks the webhook body |

## Safety — unchanged from Phase 5

| Criterion | Status | Evidence |
|---|---|---|
| No code path mitigates; the closure test holds the detector and the domain, and confines notification crates to `crates/notification` | Met | `crates/incident/tests/dependency_closure.rs` `the_detector_depends_only_on_reviewed_crates`, `the_incident_domain_depends_only_on_reviewed_crates`, `no_crate_in_the_workspace_can_route_or_reach_a_device`, `only_the_notifier_can_deliver_a_message` |
| The Phase 4 detector is unmodified | Met | `git diff d1d5f2c..main -- crates/detector` is empty |

## Process

| Criterion | Status | Evidence |
|---|---|---|
| All existing tests stay green, on Linux, Windows and PostgreSQL 15 to 18 | Met | CI on `main`. On each PostgreSQL version every database test ran; none printed a skip |
| Every gate exits 0: formatting, lints, tests, docs, secret scan, DCO | Met | CI on every pull request, #89 to the 6F pull request |
| Each milestone's decisions are recorded in an ADR | Met | ADRs [0041](../architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md) to [0045](../architecture/decisions/0045-phase6e-notification-delivery.md), all Accepted |
| The threat model covers the UI and notifications, and every new threat has a passing test | Met | T-30 to T-41 in the [threat model](../security/incident-threat-model.md), each mapped in the [threat tests](../security/incident-threat-tests.md). T-34, a compromised npm package, is met by the **Web UI** job's controls, not by a test of its own |
| The runbook and installation guide cover Grafana, the UI, sessions and each channel | Met | [Runbook](../operations/incident-runbook.md): notifier alerts, notifications, sessions and the UI, traffic. [Installation](../installation/incident-management.md): sections 6 to 9 |

## Carried forward

- **T-21** stays partial: an assignee is not checked against a user
  directory until Phase 8 (FU-60).
- **FU-64**, found in this assessment: the API still reports
  `notification_status` as `none`, its Phase 5 placeholder, though
  notifications are now delivered. The truth is on the timeline, which
  the UI shows. The field should be derived from the
  `notification_result` entries.
- **FU-6**: ClickHouse stays on `0.13`.
