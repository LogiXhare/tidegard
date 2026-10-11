# Phase 6 Plan: Dashboards, NOC UI and Notifications

Status: **Planning, accepted by the owner 2026-10-11.** No Phase 6 code
exists yet. The decisions this plan rests on are BQ-2 and BQ-10 to BQ-12
in [blocking questions](../blocking-questions.md). Each milestone records
its own engineering decisions in an ADR when it starts, as Phase 5 did.

Phase 6 delivers what the master prompt lists for it: Grafana dashboards,
a native NOC UI, and notifications by email, Microsoft Teams, Slack,
Telegram and webhook. It ships as two releases on the
[roadmap](../roadmap.md): **v0.7.0** (dashboards and UI) and **v0.8.0**
(notifications).

## What does not change

- **Nothing mitigates.** No Phase 6 code path announces a route, touches
  a device, or calls the mitigator. The
  [dependency closure test](https://github.com/LogiXhare/wetechi-netmon/blob/main/crates/incident/tests/dependency_closure.rs)
  keeps refusing routing and device-access crates everywhere.
- **The detector and the incident domain stay as they are.** Notification
  crates are allowed only in `crates/notification`. The closure test is
  narrowed to say so, never widened for the domain.
- **Nothing is sent from CI.** Every channel is tested against a local
  mock endpoint (the [acceptance criteria](../acceptance-criteria.md) for
  Phase 6).
- **Grafana is external** (BQ-2). We ship original dashboard JSON and
  provisioning files. We never bundle or modify a Grafana binary, so its
  AGPLv3 licence places no obligation on this repository.

## Decisions taken for this plan

| Question | Decision | Why |
|---|---|---|
| BQ-2 Grafana | External only: JSON and provisioning | Keeps AGPLv3 obligations out of the repository; operators already run Grafana |
| BQ-10 UI sign-in | An existing API token, exchanged once for a session cookie | No new credential store before Phase 8 brings OIDC and Entra ID |
| BQ-11 UI stack | React, TypeScript and Vite in `apps/web` | Recorded since Phase 1; React escapes output by default (T-08) |
| BQ-12 Scope and order | Dashboards, then the UI, then notifications; no InfluxDB dashboards | Nothing here writes to InfluxDB, and FR-11.2 makes it optional |

## Milestones

Each milestone ends green and is independently mergeable.

### 6A — Grafana dashboards as code (v0.7.0)

Original dashboards in `grafana/dashboards/`, and example provisioning in
`grafana/provisioning/`:

- **Traffic** (ClickHouse): totals by family and direction, top hosts,
  networks, /24s, hostgroups and ASNs, per exporter and interface.
- **Collector and exporters** (Prometheus): datagrams, parser failures,
  templates, sampling, queue depth, ClickHouse writes.
- **Detection** (Prometheus and ClickHouse): scopes in each state,
  transitions, and detection events.
- **Incidents** (Prometheus): inbox, outbox, dead letters, timers, and
  `timeline_pressure`.

Every datasource is a dashboard variable, never a hard-coded UID, so the
JSON works in any Grafana. CI validates each dashboard:

- it parses, and its UID is unique and stable;
- every panel uses a datasource variable;
- **every Prometheus metric it queries is one the code registers**, and
  every ClickHouse table it reads is one the schema creates. A renamed
  metric fails the build instead of leaving an empty panel.

**Exit:** the dashboards load in a Grafana started in CI against the
real datasources, and the validation runs on every pull request.

**Progress:** built in 6A-1 ([ADR 0041](decisions/0041-phase6a-grafana-dashboards-as-code.md)): four dashboards, the static check `tools/dashboard-check`, and the CI job **Grafana dashboards**. One draft query used a column the traffic totals do not have. The static check cannot see columns, which is why the live job runs every query.

### 6B — Read APIs for the UI

The UI uses only the REST API, so what it shows needs endpoints:

- traffic summaries and top talkers, read from ClickHouse;
- exporter and interface health;
- service health and versions.

**Traffic carries no tenant.** The ClickHouse traffic tables have no
tenant column: prefix ownership is Phase 8. So traffic endpoints cannot
be tenant-scoped the way incidents are. They need their own
deployment-wide permission, kept out of the tenant-scoped role bundles
unless a deployment is single-tenant. The 6B ADR decides the exact
permission and bundle, and the tenant-isolation suite must cover it. This
is risk **R21**.

**Exit:** each endpoint is in the OpenAPI document, the tenant-isolation
suite covers it, and a query's cost is bounded by its time range.

**Progress:** 6B-1 ([ADR 0042](decisions/0042-phase6b-traffic-read-api.md)) adds `traffic.read`, the configured traffic tenant, a read-only ClickHouse client over its HTTP interface, and three endpoints: traffic summary, top talkers and exporters. They are tested against a real ClickHouse in CI, and the tenant-isolation suite covers them.

### 6C — Browser sessions (BQ-10)

`POST /api/v1/session` takes an API token once and answers with a
session cookie. The token is never stored in the browser.

- The cookie is `HttpOnly`, `Secure` (except on loopback), and
  `SameSite=Strict`, holding an opaque id. Only its SHA-256 is stored,
  as tokens are.
- The session has the token's tenant, actor and role, an idle timeout,
  and an absolute lifetime. It ends when the token is revoked or expires.
- Every state-changing request also needs a CSRF header. Sign-in, sign-out
  and each refusal are audited.
- Bearer tokens keep working unchanged for the CLI and integrations.

**Exit:** session tests covering fixation, expiry, revocation, CSRF and
cross-tenant access.

**Progress:** built in 6C ([ADR 0043](decisions/0043-phase6c-browser-sessions.md)): `api_sessions` (V18), `POST`, `GET` and `DELETE /api/v1/session`, the cookie path and CSRF check in the authentication middleware, audit rows for sign-in, sign-out and refusals, and retention of expired sessions. `apps/api/tests/sessions.rs` proves fixation, idle and absolute expiry, revocation, sign-out, CSRF, and that no secret is logged.

### 6D — The NOC UI (BQ-11)

`apps/web`: React, TypeScript and Vite, served by the API as static files
from the same origin, so there is no CORS to configure.

- **First pages:** sign-in, NOC overview, incident list, incident detail
  (timeline, notes, detections, actions), and exporter health.
- **Look:** the dark NOC theme of FR-10.2, colour-blind-safe, and never
  colour alone. It has a full-screen mode, refresh and time-range
  controls.
- **Untrusted text is only ever text** (T-08). There is no
  `dangerouslySetInnerHTML`, and a lint rule refuses it. A strict
  Content-Security-Policy allows no inline script. A test renders
  hostile notes and titles and checks that nothing executes.
- **Supply chain:** `package-lock.json` is committed, CI uses `npm ci`
  and `npm audit`, every dependency's licence is checked against the
  [licence matrix](../dependency-license-matrix.md), and versions are
  pinned.

**Exit:** the UI drives the incident lifecycle end to end against a real
API in CI, and T-08 is Met.

**Progress:** 6D-1 ([ADR 0044](decisions/0044-phase6d-noc-ui.md)) builds the scaffold: sign-in and sign-out, the incident list, the API serving the UI from the same origin with a strict Content-Security-Policy and security headers on every response, the T-08 lint rule with a test of the rule itself, a hostile-text component test, and the **Web UI** CI job (lint, types, tests, build, audit, licences). 6D-2 adds the incident page: facts, notes, timeline, and every operator action the role allows, each with the version seen and a fresh idempotency key, a reload on a version conflict, and confirmation where the CLI asks. 6D-3 adds the NOC overview: active incidents by severity, traffic over the last hour as an SVG chart with no inline style, the top hosts, and exporters with silent ones called out; a tenant that is not the traffic tenant sees incidents alone. The end-to-end tests follow.

### 6E — Notifications (v0.8.0)

`crates/notification` becomes the first consumer of the incident outbox
(FU-62):

- **Channels:** email (SMTP over TLS), Microsoft Teams and Slack (incoming
  webhooks), Telegram (bot API), and a generic webhook signed with HMAC.
- **Routing:** per-tenant rules choose a channel by event type and
  severity, with deduplication and a per-channel rate limit, so a
  flapping detection cannot flood a pager.
- **Results:** each delivery is recorded on the incident's timeline
  (`notification_result`, reserved since V4), and a channel that keeps
  failing dead-letters through the outbox's own mechanics.
- **Secrets:** channel secrets come from files or the environment, are
  never logged, and are never returned by the API.
- **Egress:** a webhook URL is server-side request forgery waiting to
  happen. Destinations go through an allowlist, private and link-local
  ranges are refused unless allowed explicitly, and redirects are not
  followed.

**Exit:** each channel is tested against a local mock, nothing reaches the
internet from CI, and `mitigation_status` stays `none` in every payload.

### 6F — Operations and hardening

- The threat model gains the UI (XSS, CSRF, clickjacking, session
  fixation) and notifications (SSRF, secret leakage, flooding,
  spoofed callbacks).
- The runbook and installation guide cover Grafana, the UI, sessions and
  each channel.
- A Gate 2 assessment, as Phase 5 had.

## Risks

| Id | Risk | Response |
|---|---|---|
| R21 | Traffic data has no tenant until Phase 8 | A deployment-wide permission kept out of tenant bundles; documented as single-tenant until Phase 8 |
| R22 | npm brings a large transitive supply chain | Lockfile, `npm ci`, audit and licence checks in CI, and a strict CSP |
| R23 | Webhooks enable SSRF and data exfiltration | Destination allowlist; private ranges refused by default; no redirects |
| R24 | A notification storm during a large attack | Deduplication and per-channel rate limits, both tested |

## Where to read next

- [Phase 6 acceptance criteria](../development/phase6-acceptance-criteria.md)
- [Blocking questions](../blocking-questions.md): BQ-2 and BQ-10 to BQ-12
- [Phase 5 Gate 2 assessment](../development/phase5-gate2-assessment.md):
  it leaves T-08, stored XSS, for the Phase 6 UI to close
