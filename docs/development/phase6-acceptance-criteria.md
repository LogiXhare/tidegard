# Phase 6 Acceptance Criteria

Status: **Defined 2026-10-11, before any Phase 6 code.** Part of the
[Phase 6 plan](../architecture/phase6-dashboards-ui-notifications-plan.md).

As in Phase 5, the criteria are written before the work starts, so the
work is judged against them rather than the other way round. Each one is
assessed at the end of Phase 6 with the test or check that proves it:
see the [Gate 2 assessment](phase6-gate2-assessment.md).

## Gate 1 — Planning accepted

- [x] The owner has decided BQ-2 and BQ-10 to BQ-12
  ([blocking questions](../blocking-questions.md)).
- [x] The plan names each milestone, its exit criterion, and the risks
  (R21 to R24 in the [risk register](../risk-register.md)).
- [x] These criteria exist before any Phase 6 code.

## Gate 2 — Phase 6 complete

### Dashboards (6A)

- Every dashboard is original, with a unique, stable UID.
- Every datasource is a dashboard variable.
- CI fails if a dashboard queries a Prometheus metric the code does not
  register, or a ClickHouse table the schema does not create.
- The dashboards load in a Grafana started in CI against real
  datasources.
- No Grafana binary is bundled or modified (BQ-2).

### Read APIs (6B)

- Every new endpoint is in the OpenAPI document and covered by the
  tenant-isolation suite.
- Traffic endpoints need their own deployment-wide permission, which no
  tenant-scoped default role holds (R21).
- Every traffic query is bounded by a time range and a row limit.

### Sessions (6C)

- A session is created only from a valid, unexpired, unrevoked token,
  and carries that token's tenant, actor and role.
- The cookie is `HttpOnly`, `Secure` off loopback, and
  `SameSite=Strict`; only its hash is stored.
- Tests prove: idle and absolute expiry; revoking the token ends its
  sessions; a state-changing request without the CSRF header is refused;
  a session id fixed before sign-in is never accepted after it.
- Sign-in, sign-out and refusals are audited, and no session id or
  token appears in a log line.

### The NOC UI (6D)

- The UI drives an incident from open to closed, notes included, against
  a real API in CI.
- **T-08 is Met:** hostile titles, notes and reasons render as text, a
  lint rule refuses `dangerouslySetInnerHTML`, and the
  Content-Security-Policy allows no inline script.
- The theme meets FR-10.2: colour-blind-safe, never colour alone.
- `package-lock.json` is committed; CI runs `npm ci`, `npm audit` and a
  licence check (R22).

### Notifications (6E)

- Email, Teams, Slack, Telegram and webhook each have an integration test
  against a local mock. **Nothing is sent to the internet from CI.**
- Webhook destinations pass an allowlist; private and link-local ranges
  are refused by default; redirects are not followed (R23).
- Deduplication and per-channel rate limits are tested under a burst
  (R24).
- Each delivery result is on the incident's timeline, and repeated
  failures dead-letter.
- Channel secrets never appear in a log, an API response, or an export.
- Every payload reports `mitigation_status` as `none`.

### Safety — unchanged from Phase 5

- No code path mitigates; the dependency closure test still holds the
  detector and the incident domain, and confines notification crates
  to `crates/notification`.
- The Phase 4 detector is unmodified.

### Process

- All existing tests stay green, on Linux, Windows and PostgreSQL 15
  to 18.
- Every gate exits 0: formatting, lints, tests, docs, secret scan, DCO.
- Each milestone's decisions are recorded in an ADR.
- The threat model covers the UI and notifications, and every new threat
  has a passing test.
- The runbook and installation guide cover Grafana, the UI, sessions and
  each channel.
