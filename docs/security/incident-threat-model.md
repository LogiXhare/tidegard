# Incident Management Threat Model

Status: **Implemented and tested** through Phase 7, 2026-10-12; Phase 9D
threats added 2026-10-13. Written as the
[Phase 5 plan](../architecture/phase5-incident-management-plan.md)'s
threat model; each threat's test is mapped in the
[threat tests](incident-threat-tests.md).

Fifty-seven threats: twenty-four from Phase 5 planning, five added
2026-08-24 during Phase 5B PostgreSQL-persistence planning (T-25 through
T-29), twelve added in Phase 6 for the UI, sessions, traffic and
notifications (T-30 through T-41), seven added in Phase 7 for BGP
mitigation (T-42 through T-48), and nine added in Phase 9D for the
collector's input, ClickHouse, packaging and the supply chain (T-49
through T-57). Each names the asset, the attacker,
the path, a preventive control, a detective control, the test, and the
residual risk that remains after both controls.

Attacker classes used throughout:

- **EXT** — unauthenticated external
- **TEN** — authenticated user of *another* tenant
- **USR** — authenticated low-privilege user of *this* tenant
- **SVC** — holder of a compromised service credential
- **INS** — insider with database or host access

---

## T-01 Forged detection event

**Asset** incident integrity · **Attacker** EXT, SVC

**Path** An attacker who can write to the outbox or impersonate the
ingestion service injects events, creating incidents that mask a real
attack or exhaust operators with noise.

**Prevent** Ingestion is not an HTTP endpoint — events arrive through the
outbox inside the trust boundary. The ingestion credential holds only
`incident.ingest` and cannot acknowledge, resolve, or close. Database
credentials come from the environment, never source. **Detect**
`events_ingested_total` against detector-side event counts; a divergence
means events from somewhere else. **Test** ingestion credential is
refused for every operator command. **Residual** An attacker with
PostgreSQL write access can forge anything; that is equivalent to owning
the system, and is addressed by host and database hardening, not here.

## T-02 Duplicate event flood

**Asset** availability · **Attacker** EXT, SVC

**Path** Mass redelivery drives correlation work and inflates incidents.

**Prevent** `UNIQUE (tenant_id, dedup_key)` rejects duplicates at the
database before any mutable work; bounded ingestion batches apply
backpressure. **Detect** `events_duplicate_total` rate. **Test** the same
event ingested 1 000 times produces one incident and one link row.
**Residual** Duplicate *processing* still costs a database round trip;
sustained volume is a capacity concern, tracked by the alert on ingestion
lag.

## T-03 Correlation-key collision

**Asset** incident integrity · **Attacker** EXT

**Path** Traffic crafted so unrelated attacks share a correlation key,
merging distinct incidents and hiding one inside another.

**Prevent** The key is composed of five exact, canonicalised values —
tenant, target type, target id, direction, family — not a hash, so
collision requires the values to genuinely be equal. IPv6 is normalised
before comparison so two spellings of one address cannot split or merge
unexpectedly. **Detect** `incidents_opened_total` against detection
volume. **Test** canonicalisation property test: equivalent addresses
produce one key; different addresses never produce one. **Residual** Two
genuinely different attacks on the same target, direction, and family
*are* one incident by design. Accepted, and visible because
`policy_refs` and the category record the multiple vectors.

## T-04 Incident ID enumeration

**Asset** confidentiality · **Attacker** TEN, USR

**Path** Iterating IDs to discover incidents, or their count, in another
tenant.

**Prevent** Non-sequential IDs (ADR 0013); **404 rather than 403** for
another tenant's resource, so existence is never confirmed; incident
numbers are per-tenant, so they leak nothing across tenants. **Detect**
`incident_authz_denied_total` and `404` rate per actor. **Test** a valid
ID from tenant B, requested by tenant A, returns 404 — asserted for every
endpoint including audit. **Residual** Per-tenant numbering leaks that
tenant's own volume to its own users. Accepted.

## T-05 Tenant escape

**Asset** all tenant data · **Attacker** TEN, USR

**Path** A query missing its tenant predicate, or a cursor or ID crossing
the boundary.

**Prevent** `tenant_id` on every table; tenant context is a repository
constructor argument so a tenant-less query cannot be expressed; cursors
are signed and carry the tenant; RLS designed for and enabled in Phase 8.
**Detect** audit records with mismatched tenant; denial counter. **Test**
a dedicated isolation suite running every endpoint as tenant A against
tenant B's data. **Residual** Enforcement is application-level until
Phase 8 RLS. This is the largest residual risk in Phase 5 and is recorded
as **R16**.

## T-06 Unauthorized state transition

**Asset** incident integrity · **Attacker** USR

**Path** A viewer closes an incident, or an operator resolves one they
should not.

**Prevent** Per-transition permissions, checked at the command boundary,
not the handler; guard-refused illegal edges. **Detect** every attempt
audited with `result`. **Test** every command × every role, asserting
allow and deny. **Residual** A correctly-permissioned user acting
maliciously is an insider problem; the audit trail is the control.

## T-07 Malicious note content

**Asset** operators and downstream consumers · **Attacker** USR

**Path** A note containing markup, control characters, or a payload aimed
at whatever renders it.

**Prevent** Stored as text, length-bounded, never interpreted by the API.
**Detect** length and rejection counters. **Test** notes containing
markup, null bytes, and very long lines round-trip byte-identically.
**Residual** Rendering safety belongs to consumers; see T-08.

## T-08 Stored XSS

**Asset** UI users · **Attacker** USR

**Path** Note or title content executes in a future web UI.

**Prevent** The API returns JSON and never HTML; content type is pinned;
notes are documented as untrusted. **Deliberately no input sanitisation**
— it destroys the operator's actual words and gives false assurance. The
control belongs at output, in Phase 6. **Detect** UI-side CSP reporting
when the UI exists. **Test** Phase 6 must escape on output; noted as a
Phase 6 acceptance item. **Residual** Real until a UI exists and escapes
correctly. Carried as **R17**.

## T-09 Audit-log injection

**Asset** audit integrity · **Attacker** USR

**Path** Crafted user agent or reason forges audit lines or breaks
parsers.

**Prevent** Structured JSON logging with escaped values, never
concatenation; client-supplied audit fields length-capped with control
characters stripped. **Detect** parse failures in log ingestion.
**Test** newlines and JSON fragments in a reason produce one well-formed
record. **Residual** Minimal.

## T-10 SQL injection

**Asset** everything · **Attacker** USR, TEN

**Path** Unparameterised query construction.

**Prevent** Parameterised queries only; no string interpolation into SQL,
ever; IDs shape-validated before lookup; sort and filter fields mapped
through an allowlist rather than interpolated. **Detect** database error
rate; query logging. **Test** injection payloads in every string
parameter including sort, filter, tag, and cursor. **Residual** Minimal
with a typed query layer; the allowlist for sort fields is the part most
often got wrong.

## T-11 Query exhaustion

**Asset** availability · **Attacker** USR

**Path** Broad or deep queries consuming database capacity.

**Prevent** Server-enforced maximum page size; 90-day range cap; cursor
pagination so deep paging does not degrade; `q` minimum length with no
leading wildcard; non-indexable combinations rejected as
`incident.query_too_broad`; per-actor rate limits; `total` omitted by
default. **Detect** `command_duration_seconds` and rate-limit counters.
**Test** unbounded and deep-page queries are rejected or bounded.
**Residual** A permitted user can still issue expensive-but-legal
queries; rate limiting bounds the damage.

## T-12 Export exhaustion

**Asset** availability, confidentiality · **Attacker** USR

**Path** Repeated large exports as a bulk-extraction or DoS technique.

**Prevent** Separate `incident.export` permission; 10 000-row cap; 5 per
hour per tenant; every export audited with its filter. **Detect** export
audit records and counter. **Test** cap and rate limit enforced; each
export produces an audit row. **Residual** A permitted user can
legitimately extract a lot over time; the audit trail is the control.

## T-13 Optimistic-lock bypass

**Asset** incident integrity · **Attacker** USR

**Path** Omitting `expected_version` to force a write over another
operator's change.

**Prevent** `expected_version` is **required** for state and
safety-relevant mutations; the request is rejected without it rather than
defaulting to the current version. **Detect**
`command_conflicts_total`. **Test** transitions without
`expected_version` are rejected; concurrent conflicting commands produce
exactly one winner. **Residual** Append-only operations do not use
versions by design and cannot conflict.

## T-14 Idempotency-key abuse

**Asset** integrity · **Attacker** USR, TEN

**Path** Reusing a key with different content to have a change silently
dropped, or guessing another tenant's key.

**Prevent** Fingerprint comparison rejects same-key-different-body with
`409`; records scoped to `(tenant_id, key)` so another tenant's key is
invisible; keys are never credentials; length bounded. **Detect**
`incident.idempotency_key_reuse` counter. **Test** the same key with a
different body conflicts; a key never crosses tenants. **Residual**
Minimal.

## T-15 Outbox replay

**Asset** integrity · **Attacker** INS

**Path** Re-marking published rows pending to reprocess events.

**Prevent** Idempotent consumption via `dedup_key` uniqueness makes
replay a no-op for correlation; published rows are purged after 7 days.
**Detect** duplicate counter rising without a corresponding ingestion
rise. **Test** full outbox replay produces no additional incidents.
**Residual** An attacker with database write access has larger
capabilities; see T-01.

## T-16 Dead-letter poisoning

**Asset** availability · **Attacker** EXT

**Path** Malformed events crafted to fill the dead-letter table or stall
the consumer.

**Prevent** Capped retries then quarantine, so a poison event stops
consuming resources; the consumer continues past it; dead-letter rows are
bounded and alerted. **Never executed, interpolated, or rendered.**
**Detect** `dead_letter_pending` alerts at greater than zero. **Test** a
poison event does not stall the queue and lands in dead-letter exactly
once. **Residual** Sustained malformed input is a capacity concern,
surfaced by the alert.

## T-17 Clock manipulation

**Asset** integrity of timings · **Attacker** INS, SVC

**Path** Skewed clocks cause premature auto-close, wrong reopen decisions,
or misordered timelines.

**Prevent** Ordering uses database sequence, not client time; wall clock
is display-only; durations from Phase 4 are monotonic-measured; all
Phase 5 timing uses an injectable clock. **Detect** events with
`observed_at` far from server time counted as skewed. **Test** skewed and
backwards clocks do not reorder a timeline or trigger early auto-close.
**Residual** Gross NTP failure still affects display timestamps.

## T-18 Stale event reopening

**Asset** operator trust · **Attacker** EXT, or simply a backlog

**Path** A delayed `Started` event arrives after resolution and
resurrects an incident an operator has closed.

**Prevent** Late events — older than `last_detected_at` — may link but
may not transition or reopen; reopen requires an event inside the reopen
window measured on server time. **As implemented (Phase 5F):** "late" is decided by
detection identity, not by timestamp, so the detector's clock never enters
the decision (ADR 0031). Two kinds of event link as late evidence and never
reopen a resolved or closed incident: a detection ending, and any event of a
detection episode the incident already holds. A recurrence is a new episode
with a new detection id (ADR 0009). Only a recurrence reopens, and only inside
the window. Past the evidence cap an old episode id may no longer be retained;
its late event then reopens the incident, which errs toward visibility.
Found during the 5F security review: until then, both kinds of event
reopened an incident inside the window. **Detect** `events_late_total`.
**Test** a late event after resolution links as evidence and does not
reopen. **Residual** An event delayed by less than the reopen window is
indistinguishable from a genuine recurrence. Accepted.

## T-19 Unauthorized suppression

**Asset** detection coverage · **Attacker** USR, INS

**Path** Suppressing an incident to hide a live attack — the highest-value
single action for an attacker who has a foothold.

**Prevent** Separate `incident.suppress` permission, not bundled into
`operator`; **mandatory `expires_at`**, so no suppression is indefinite;
mandatory reason; suppressed incidents still ingest, link, and count.
**Detect** `incidents_suppressed_total`, audit record, and suppressed
incidents remain visible in list views with a distinct state. **Test**
suppression without expiry is rejected; a suppressed incident still
accumulates events and metrics. **Residual** A `noc_lead` can suppress
for the maximum window; audited, and the expiry bounds it.

## T-20 Unauthorized severity reduction

**Asset** operator trust · **Attacker** USR

**Path** Lowering severity to bury an incident below attention
thresholds.

**Prevent** `incident.severity.change` is separate from `incident.update`;
a reason is **required when lowering**; `severity_source` records that a
human overrode the detection, so the next event does not silently restore
it and mask the override. **Detect** severity-change audit records with
before and after. **Test** lowering without a reason is rejected; every
change is audited with both values. **Residual** A permitted user may
legitimately lower severity; the audit trail is the control.

## T-21 Cross-tenant assignment

**Asset** confidentiality · **Attacker** USR

**Path** Assigning an incident to a user in another tenant, exposing it
to them.

**Prevent** The assignee must belong to the incident's tenant or to an
explicitly cross-tenant platform team; validated server-side against the
directory, never trusted from the request. **Detect** denial counter and
audit. **Test** assigning across tenants is refused. **Residual** Depends
on directory correctness, which Phase 8 hardens.

## T-22 Sensitive evidence leakage

**Asset** confidentiality · **Attacker** USR, TEN

**Path** Evidence references or note content exposing data beyond the
tenant boundary.

**Prevent** Evidence is stored as references, never inline binaries;
references are tenant-scoped and authorized on dereference, not only on
creation; `customer_visible` notes are **refused in Phase 5** because
there is no authorization model for publishing to a customer. **Detect**
audit on evidence access. **Test** an evidence reference from another
tenant returns 404. **Residual** Binary evidence storage is out of scope,
so its access model is undesigned — a gap that must be closed before
evidence attachment ships. **FU-23**.

## T-23 Log leakage

**Asset** confidentiality · **Attacker** anyone with log access

**Path** Note bodies, credentials, or PII in logs shipped to a
centralised system with broader access than the incident API.

**Prevent** Note bodies never logged at `INFO`; credentials and auth
headers never logged; raw detection payloads not logged; structured
fields only. **Detect** log-content review as a release checklist item.
**Test** an assertion that no log line at `INFO` or above contains a note
body. **Residual** `DEBUG` may include more; deployments enabling it
accept that.

## T-24 Prometheus cardinality explosion

**Asset** monitoring availability · **Attacker** EXT, or an own goal

**Path** A high-cardinality label — tenant, target, incident ID —
multiplying series until Prometheus degrades, taking monitoring down
during the attack it is meant to observe.

**Prevent** Every label a closed set; **tenant ID explicitly forbidden**
as a label despite looking bounded, because a managed deployment grows
tenants over time; per-tenant analysis belongs in ClickHouse. **Detect**
series count monitoring. **Test** an assertion enumerating every metric's
label set against an allowlist, mirroring Phase 4's metric tests.
**Residual** Minimal if the test exists; without it, one careless label
added later is enough.

---

## Phase 5B additions (2026-08-24 planning)

Five threats specific to durable persistence, none present while the
domain was in-memory-only.

## T-25 Clock-skew-induced reopen or duplicate-incident bypass

**Asset** correctness of the reopen window (BQ-9) · **Attacker** a
misconfigured NTP client, or EXT via a compromised database connection

**Path** A decision timestamp (from `transaction_timestamp()`) earlier
than the persisted reference it is compared against — from clock skew,
not necessarily malice — silently clamped or misinterpreted, incorrectly
reopening an incident outside its true window, or incorrectly creating a
duplicate.

**Prevent** The durable-time contract
([ADR 0031](../architecture/decisions/0031-phase5b-durable-time.md))
never clamps silently, never reopens, and never creates a duplicate
incident on an unreliable comparison — it returns a structured
clock-skew error instead. **Detect** a bounded metric and structured log
entry on every occurrence. **Test** the clock-skew integration test in
[incident-testing-plan.md](../architecture/incident-testing-plan.md).
**Residual** Recurring skew degrades availability (commands failing
closed) rather than correctness — an accepted trade, consistent with
this project's fail-closed posture elsewhere.

## T-26 Connection-pool exhaustion denial of service

**Asset** availability · **Attacker** EXT (via ingestion volume), or an
own goal (a leaked connection)

**Path** Every pooled connection held by slow or stuck queries, or by a
code path that acquires without releasing, starving all subsequent
requests.

**Prevent** Bounded `acquire`/`create` timeouts on the pool
([ADR 0022](../architecture/decisions/0022-phase5b-connection-pool.md))
— an unbounded wait becomes the same `503` backpressure
[incident-persistence.md](../architecture/incident-persistence.md)
already requires for "queue full", never a silent indefinite block.
**Detect** `pool_wait`, `pool_timeout`, `pool_in_use` metrics. **Test** a
pool-exhaustion integration test asserting `503` rather than a hang.
**Residual** A sustained ingestion flood that outpaces the pool still
degrades ingestion latency by design — backpressure, not data loss.

## T-27 Corrupted or hand-crafted row bypassing domain invariants

**Asset** aggregate integrity · **Attacker** an attacker with direct
database write access, or a bug in a future second writer

**Path** A row inserted or edited outside the application's own command
paths — direct SQL, a migration bug, or a future second service writing
to the same tables — produces a structurally invalid `Incident` (e.g.
`ever_critical: false` for a `severity: critical` row) that the
in-memory domain's own construction guards would never have permitted.

**Prevent** `Incident::reconstitute`
([ADR 0030](../architecture/decisions/0030-phase5b-aggregate-reconstitution.md))
is the **only** path from a persisted row to a live `Incident`, and it
validates structural invariants rather than accepting any row shape;
`CHECK` constraints at the database layer reject some invalid states
before they are even stored. **Detect** a `reconstitute` failure is
itself a loggable, alertable event — an aggregate that cannot be loaded
is worse than one that is merely wrong, and must be visible immediately.
**Test** a table-driven test constructing invalid snapshots and asserting
`reconstitute` refuses each one. **Residual** Database-level write access
is already a trusted-boundary assumption (see the "attacker with
database or host access" note in the summary below); this control
narrows what such access can silently corrupt without detection, not
what it can access at all.

## T-28 TLS downgrade or certificate-verification bypass in production

**Asset** confidentiality and integrity of the PostgreSQL connection ·
**Attacker** network-position (MITM)

**Path** A production deployment accidentally configured with
certificate verification disabled, or a code path that falls back to
plaintext on a TLS failure instead of refusing the connection.

**Prevent** [ADR 0023](../architecture/decisions/0023-phase5b-postgresql-tls.md)
requires full certificate and hostname verification in production, with
**no code path** that disables it outside an explicitly isolated test
helper; a TLS handshake failure is classified as a connection failure
(fail closed), never a silent plaintext fallback. **Detect** a TLS
handshake failure is logged and counted, distinguishable from other
connection failures. **Test** a production-configuration test asserting
the connection string always requires `sslmode=verify-full` or
equivalent outside the explicitly loopback-only test path. **Residual**
A deliberately misconfigured deployment (an operator who overrides the
production default) is outside this control's reach — documentation, not
code, is the remaining defense there.

## T-29 Outbox lease starvation or duplicate-delivery abuse

**Asset** availability and correctness of the analytics export path ·
**Attacker** a crashed or slow consumer, or a bug in the lease logic

**Path** A claimed outbox row whose consumer crashes without releasing
it stalls that event indefinitely if no lease-expiry mechanism exists;
conversely, an overly aggressive lease-expiry reclaims a row that is
still being legitimately processed, causing duplicate delivery beyond
what the downstream consumer's own idempotency can absorb.

**Prevent** [ADR 0033](../architecture/decisions/0033-phase5b-transactional-outbox-and-dead-letter.md)'s
lease duration bounds how long a claim is honored before reclaim is
eligible, and the retry-limit-then-dead-letter path bounds how long a
poison event can consume resources. **Detect** `outbox_pending`,
`outbox_retries`, `dead_letter_count` metrics — a zero-threshold alert on
dead-letter, matching the existing runbook posture. **Test** the stale-
lease-reclaim and duplicate-consumer-idempotency integration tests in
[incident-testing-plan.md](../architecture/incident-testing-plan.md).
**Residual** At-least-once delivery is the accepted contract
([incident-persistence.md](../architecture/incident-persistence.md));
the downstream consumer must tolerate a duplicate, which the current
sole consumer (the ClickHouse analytics exporter) already does by
design.

---

## Phase 6 additions (2026-10-12)

Phase 6 added a browser UI, browser sessions, a traffic read API and the
first outbound delivery. Each brings threats the Phase 5 model did not
have. Each entry names its control and the test that proves it; the
[threat tests](incident-threat-tests.md) map them.

## T-30 Cross-site request forgery through the session cookie

**Asset** incident integrity · **Attacker** a page the operator visits

**Path** A page on another site makes the operator's browser send a
state-changing request, and the browser attaches the session cookie.

**Prevent** The cookie is `SameSite=Strict`, and every cookie request
that is not `GET`, `HEAD` or `OPTIONS` must carry `X-WNM-CSRF`,
derived from the session id, which a cross-site page can neither read nor
compute ([ADR 0043](../architecture/decisions/0043-phase6c-browser-sessions.md)).
**Detect** each refusal is audited as `session.csrf_rejected`.
**Test** `apps/api/tests/sessions.rs`; `apps/web/e2e/lifecycle.spec.ts`
in a real browser.

## T-31 Session fixation and session theft

**Asset** an operator's identity · **Attacker** someone who plants or
steals a session id

**Path** A session id set before sign-in is honoured after it; or a stolen
session lives on after the operator stops using it, or after the token
behind it is revoked.

**Prevent** Every sign-in issues a new random id; only its hash is stored;
the cookie is `HttpOnly`; a session ends after 30 minutes idle, 12 hours
in all, at sign-out, and when its token is revoked or expires.
**Test** `apps/api/tests/sessions.rs` (fixation, idle and absolute
expiry, revocation, sign-out, no secret logged).

## T-32 Clickjacking

**Asset** operator actions · **Attacker** a page that frames the UI

**Prevent** `X-Frame-Options: DENY` and `frame-ancestors 'none'` on
every response ([ADR 0044](../architecture/decisions/0044-phase6d-noc-ui.md)).
**Test** `apps/api/tests/web.rs`; `apps/web/e2e/lifecycle.spec.ts`.

## T-33 Path traversal through the UI's file serving

**Asset** files on the API host · **Attacker** anyone who can reach the API

**Prevent** Only `index.html` and allowlisted file names directly under
`assets/` are served; nothing else under the root, and nothing outside it.
**Test** `apps/api/src/web.rs` unit tests; `apps/api/tests/web.rs`
(`..`, encoded `..`, other files and missing files are all `404`).

## T-34 A compromised npm dependency

**Asset** every operator's browser · **Attacker** whoever publishes a
malicious version of a UI dependency (R22)

**Prevent** Exact versions and a committed lockfile; `npm ci`; no install
scripts; `npm audit`; a licence check; Dependabot proposes a release only
once it is 14 days old; and the Content-Security-Policy refuses inline
code and other origins, which limits what injected code could do.
**Test** the **Web UI** CI job runs each of these on every pull request.
**Residual** A malicious release older than the cooldown and unknown to
the advisory database would be installed by a reviewed Dependabot PR.

## T-35 Server-side request forgery through a notification destination

**Asset** the internal network · **Attacker** whoever can edit the
notifier's configuration, or control DNS for a configured host (R23)

**Prevent** The host must be on the allowlist; every resolved address must
be public unless the channel allows private ones; the connection goes to
the checked address; `https` with the configured CA; no redirects; the
response body is discarded ([ADR 0045](../architecture/decisions/0045-phase6e-notification-delivery.md)).
**Test** `crates/notification/src/destination.rs` (ranges, allowlist,
plain HTTP); `crates/notification/tests/delivery.rs` and `email.rs` (an
unlisted host is refused before any connection).

## T-36 Channel secret leakage

**Asset** Slack and Teams webhook URLs, the Telegram token, webhook and
SMTP secrets · **Attacker** anyone who reads logs, the timeline or the API

**Prevent** Secrets live in files the configuration names; a destination
prints without its path; timeline entries carry only the channel's name;
nothing about channels is served by the API.
**Test** `crates/notification/tests/delivery.rs` (no secret in any log
line, in any other channel's message, or on the timeline);
`destination.rs` (the path is redacted).

## T-37 Notification storm

**Asset** the operators' attention, and the channels' own rate limits ·
**Attacker** a flapping detection or a large attack (R24)

**Prevent** One message per channel, incident and event in each window,
and a per-channel token bucket; over it, messages are dropped and counted.
**Test** `crates/notification/src/limits.rs` (a burst of 100 sends 30).

## T-38 Forged or replayed webhook

**Asset** a receiving system that acts on notifications · **Attacker**
anyone who can reach the receiver

**Prevent** Every webhook carries `X-WNM-Timestamp` and an HMAC-SHA-256
signature over the timestamp and the body; receivers are told to refuse a
bad signature or an old timestamp.
**Test** `crates/notification/src/hmac.rs` (RFC 4231 vectors);
`crates/notification/tests/delivery.rs` (the receiver verifies it).

## T-39 Content injection into a channel

**Asset** the channel's readers · **Attacker** whoever controls an
incident's title, such as a policy author or an API caller

**Path** A title that mentions `@channel` in Slack, formats Teams
Markdown, or adds a header or recipient to an email.

**Prevent** Control characters removed; Slack `&<>` and Teams Markdown
escaped; Telegram sent without a parse mode; email headers encoded by the
library. **Test** `crates/notification/src/message.rs`;
`crates/notification/src/email.rs`; `crates/notification/tests/email.rs`.

## T-40 Cross-tenant traffic disclosure

**Asset** one customer's traffic · **Attacker** another tenant's operator
(R21)

**Prevent** Traffic has no tenant until Phase 8, so only the one configured
traffic tenant reaches the traffic endpoints; anyone else gets `404`
before anything is read ([ADR 0042](../architecture/decisions/0042-phase6b-traffic-read-api.md)).
**Test** `apps/api/tests/tenant_isolation.rs`; `apps/api/tests/traffic.rs`.

## T-41 Query injection into ClickHouse

**Asset** the analytics store · **Attacker** an API caller

**Prevent** Fixed query text with server-side parameters; a dimension
selects a query from an allowlist; every request is `readonly=2` and
time- and row-limited.
**Test** `apps/api/src/clickhouse.rs` (a hostile value travels as a
parameter); `apps/api/src/traffic.rs`; `apps/api/tests/traffic.rs` (a
hostile dimension is `400`).

## Phase 7 additions (2026-10-12)

Phase 7 lets WetechiNetMon act on traffic. Through the mitigator it
announces RTBH, parent-prefix and FlowSpec routes to GoBGP, which carries
them to the edge routers
([plan](../architecture/phase7-bgp-mitigation-lab-plan.md)). A wrong route
can take a customer offline, so these threats concern the network rather
than the record. Each entry names its control and the test that proves
it.

## T-42 Route leak

**Asset** the Internet's view of the operator's address space ·
**Attacker** a mistake as much as an adversary

**Path** A blackhole or FlowSpec route reaches a peer outside the
operator's network. Transit providers or peers then drop the victim's
traffic, or the route's attributes reveal the attack.

**Prevent** Every RTBH and parent-prefix route carries `NO_EXPORT` unless
the deployment turns it off. Routes go only to the `gobgpd` the mitigator
names, and that `gobgpd` peers only with what its operator configures
([RTBH guide](../operations/rtbh-guide.md)). The ownership large community
marks every route WetechiNetMon sent.
**Detect** `bgp routes` and the `/bgp/routes` endpoint list what is
announced.
**Test** `crates/mitigator/src/route.rs`
`the_configuration_has_safe_defaults_and_strict_parsing` and
`rtbh_carries_the_next_hop_communities_and_ownership`;
`crates/mitigator/tests/two_speaker_lab.rs` (the edge receives
`BLACKHOLE` and `NO_EXPORT`).

## T-43 Overly broad blackhole

**Asset** every customer behind a prefix · **Attacker** an operator's
typo, or an operator acting in bad faith

**Path** A request for `0.0.0.0/0`, a /8, or a shorter prefix than the
attack needs blackholes far more than the victim.

**Prevent** The guard refuses anything shorter than the floors (/16 for
IPv4, /32 for IPv6) and anything not on the allowlist for this tenant and
this action. RTBH takes host routes only, and a parent prefix must be
explicitly allowed. No configuration can lower the floors
([ADR 0047](../architecture/decisions/0047-phase7b-safety-guard.md)).
**Detect** each refusal is audited.
**Test** `crates/mitigation/tests/unauthorized_prefixes.rs` (property
tests over hostile prefixes); `crates/mitigation/src/guard.rs`
`a_dangerous_configuration_is_refused`; `crates/mitigation/src/action.rs`
`rtbh_is_a_host_route_and_a_parent_is_not`;
`crates/incident-postgres/tests/mitigation_guard.rs`.

## T-44 Stale route

**Asset** the victim's reachability after the attack · **Attacker** time,
a crash, or a lost withdrawal

**Path** A route stays announced after its mitigation expired, was
withdrawn, or the mitigator stopped. The blackhole outlives the attack.

**Prevent** Every mitigation has a bounded duration (one hour at most by
default) and expires by itself. On start, and then periodically, the
mitigator reconciles GoBGP's table with the records by the ownership key.
It withdraws any route of its own that the records do not hold, and
re-announces any that the records hold but GoBGP lost
([ADR 0049](../architecture/decisions/0049-phase7d-mitigator-service.md)).
The kill switch takes everything down.
**Detect** the runbook's stale-route check compares `bgp routes` with
the edge.
**Test** `crates/mitigator/tests/mitigator_service.rs`
`the_mitigator_announces_withdraws_reconciles_and_obeys_the_kill_switch`;
`crates/mitigator/tests/two_speaker_lab.rs` (nothing at the edge after
withdrawal).

## T-45 Approval bypass

**Asset** the four-eyes rule · **Attacker** a requester, a stolen token,
or a compromised mitigator

**Path** Something gets announced without a second person approving it:
the requester approves their own request, the API drives a route
directly, or the mitigator announces what nobody approved.

**Prevent** The state machine has no path to a route except through
`approved`. Approval needs `mitigation.approve` (`noc_lead` and up),
and the requester cannot approve their own unless the deployment allows
it. The mitigator holds `propose` and `execute` and never `approve`. The
API never speaks to GoBGP
([ADR 0046](../architecture/decisions/0046-phase7a-mitigation-record.md),
[ADR 0050](../architecture/decisions/0050-phase7e-mitigation-api-cli-ui.md)).
**Detect** every decision is audited with its actor.
**Test** `crates/mitigation/src/state.rs`
`nothing_reaches_a_route_without_approval`;
`crates/mitigation/src/mitigation.rs`
`a_requester_cannot_approve_their_own_unless_allowed` and
`nothing_announces_before_approval`; `crates/incident/src/authorization.rs`
`only_the_mitigator_proposes_or_executes` and `approval_starts_at_noc_lead`;
`apps/api/tests/mitigations.rs` (`mitigation.self_approval`);
`apps/web/e2e/mitigation.spec.ts` (a senior operator cannot approve).

## T-46 Exposed GoBGP API

**Asset** the operator's routing · **Attacker** anyone who can reach
GoBGP's gRPC port

**Path** GoBGP's gRPC API has no authentication of its own, and
`gobgpd` listens on every interface by default. Anyone who reaches it
can inject or withdraw any route, past every control above.

**Prevent** The mitigator refuses plain HTTP to GoBGP except on loopback.
Anywhere else it needs TLS with a CA bundle, and optionally a client
certificate. The installation guide binds `--api-hosts` to loopback, and
the API never connects to GoBGP
([ADR 0048](../architecture/decisions/0048-phase7c-gobgp-adapter.md),
[installation](../installation/mitigation.md)).
**Test** `crates/mitigator/src/gobgp.rs`
`endpoints_are_scheme_host_and_port_only` and
`plain_http_is_refused_off_loopback_and_https_needs_a_bundle`; CI's labs
bind every `gobgpd` to loopback.

## T-47 Kill-switch release by a stolen token

**Asset** the brake on every announcement · **Attacker** someone holding
a lead's token during an incident

**Path** The kill switch was engaged because something went wrong, and a
stolen or careless token turns it off again.

**Prevent** No token role holds `mitigation.kill_switch.release`.
Releasing takes `wetechinetmon-api kill-switch release` on the API host,
with database access, audited under the actor id given. Engaging is
open to any `noc_lead`, because stopping must be easy.
**Test** `apps/api/tests/mitigations.rs`
`the_mitigation_api_requests_approves_withdraws_and_isolates` (a lead's
release is `403`; the host command releases); `apps/cli/tests/mitigation_commands.rs`
(the CLI has no release).

## T-48 Cross-tenant blackhole

**Asset** another tenant's customers · **Attacker** one tenant's
operator

**Path** A tenant's lead requests a blackhole of another tenant's address
space.

**Prevent** Each allowlist entry binds a prefix to one tenant. Entries of
different tenants may not overlap. Another tenant's prefix gets the same
refusal as a prefix nobody owns, so the allowlist does not leak
([ADR 0047](../architecture/decisions/0047-phase7b-safety-guard.md)).
Another tenant's mitigation is `404`.
**Test** `crates/mitigation/tests/unauthorized_prefixes.rs`
`another_tenants_space_is_refused_with_the_same_answer_as_nobodys`;
`apps/api/tests/tenant_isolation.rs` (every `{mitigation_id}` operation).

## Phase 9D additions (2026-10-13)

Phase 9 makes WetechiNetMon something an operator installs and runs: a
collector on a UDP port, ClickHouse, packages, images and a release. The
9D review extended this model to those parts. Two of its threats
(T-49, T-50) were found open by the review and fixed during it; the
[security review](security-review.md) lists every finding.

## T-49 Hostile flow datagram

**Asset** the collector's availability · **Attacker** EXT (anyone who
can send to the flow port)

**Path** A crafted IPFIX message makes the decoder panic, loop or
allocate without bound. The review found one: a template whose records
were zero bytes long made the decoder produce empty records until the
process ran out of memory, from 46 bytes.

**Prevent** Every malformed case is a `DecodeError`, never a panic. A
template of zero-length records is refused, a record that consumes no
bytes stops decoding, a field-less template record is a withdrawal
(RFC 7011 §8.1), and a template reserves only what its bytes can hold.
**Detect** `parser_failures_total`, and the fuzzer: `cargo fuzz` over
`decode_message` weekly and on every pull request that touches the
decoder. **Test** `crates/protocol-ipfix/src/lib.rs`
`decode_message_never_panics` and its two siblings (proptest);
`crates/protocol-ipfix/src/decoder.rs`
`the_fuzzer_s_out_of_memory_input_ends`,
`a_template_of_zero_length_records_is_refused`,
`a_huge_field_count_in_a_short_record_is_truncated`. **Residual** A
parser bug the fuzzer has not reached. NetFlow v5/v9 and sFlow are not
implemented, so they add no parser.

## T-50 Memory exhaustion through spoofed exporters and templates

**Asset** the collector's memory · **Attacker** EXT

**Path** UDP is unauthenticated. Datagrams from spoofed sources each
created an exporter state that was never forgotten, and one exporter
could cache every template ID with thousands of fields.

**Prevent** `WETECHINETMON_COLLECTOR_ALLOWED_EXPORTERS` drops datagrams
from outside the routers' networks before parsing. At most
`MAX_EXPORTERS` (1,000) exporters are tracked, silent ones are forgotten
after an hour, and each template cache holds at most 512 templates and
8,192 fields: about 125 MiB in all, whatever is sent
([ADR 0056](../architecture/decisions/0056-phase9d-collector-input-bounds.md)).
**Detect** `datagrams_refused_total{reason}`, `active_exporters`,
`template_cache_size`; a startup warning when no allowlist is set.
**Test** `crates/collector/src/exporter.rs`
`a_new_exporter_past_the_limit_is_refused_until_one_goes_idle`,
`the_allowlist_admits_its_networks_only`;
`crates/collector/src/lib.rs`
`datagrams_outside_the_exporter_limits_are_refused_before_decoding`;
`crates/protocol-ipfix/src/template_cache.rs`
`a_template_past_the_count_limit_is_refused_and_the_cache_kept`,
`templates_past_the_field_limit_are_refused`. **Residual** Without an
allowlist, spoofed exporters can fill the 1,000 places and keep a new
router out until they go idle. Set the allowlist and firewall the port.

## T-51 Flow flood

**Asset** the collector's memory and its view of traffic ·
**Attacker** EXT, or a real attack's own volume

**Path** More datagrams than the pipeline can process, or traffic to so
many distinct hosts that the aggregation tables grow without end.

**Prevent** A bounded queue between the socket and the pipeline
(`QUEUE_CAPACITY`, ADR 0004): when it is full the kernel drops
datagrams, and memory does not grow. Every aggregation table has a
maximum (`MAX_HOSTS` and the others) and evicts the least recently
updated entry; detection has `DETECTION_MAX_SCOPES`. **Detect**
`queue_depth`, `evicted_entries_total`. **Test**
`crates/aggregator/src/bounded_map.rs`
`evicts_least_recently_updated_entry_when_at_capacity`; the load test
took 200,000 records a second without loss, and the five-hour soak held
memory flat ([capacity planning](../operations/capacity-planning.md)).
**Residual** A flood past the measured rate loses datagrams, and a
flood of distinct local hosts evicts the least recently updated.

## T-52 Forged flows that trigger detection

**Asset** an innocent host's reachability · **Attacker** EXT inside an
allowed exporter network, or a compromised router

**Path** Forged records describe an attack on a host that is not under
attack, to open an incident and get it blackholed.

**Prevent** Nothing is mitigated automatically in v1.0.0 (BQ-17): every
mitigation needs a person's request and, by default, a second person's
approval (T-45), within the guard's allowlist (T-43), and the mitigator
starts in dry-run with BGP off. The exporter allowlist (T-50) narrows
who can send flows at all. **Detect** The detection event records how many
exporters contributed (`exporters_observed`), but not which: a Low
finding of the review. **Test** As T-45 and T-50. **Residual** A false
incident costs an operator's attention; forged flows from an allowed
router's address can only be stopped at the network edge (BCP 38).

## T-53 ClickHouse credential or data exposure

**Asset** flow history and the collector's ClickHouse credential ·
**Attacker** EXT on the network path, INS reading logs

**Path** The export travels in plaintext, the password rides in a URL
that reaches a log, or a server certificate from any public CA is
accepted.

**Prevent** Plain HTTP is refused except to loopback; HTTPS trusts only
the configured CA bundle; the password comes from a file, and a URL
carrying credentials or a path is refused; logs show scheme, host and
port only
([ADR 0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md)).
The API's ClickHouse queries are read-only and parameterised (T-41).
**Test** `crates/storage/src/connection.rs`
`plain_http_reaches_loopback_only`, `https_needs_a_ca_bundle`,
`credentials_never_ride_in_the_url`,
`logs_show_only_scheme_host_and_port`; the Grafana job exports over TLS
to a real server. **Residual** ClickHouse's own access control is the
operator's. The Compose stack gives the collector and the API one user
between them, so the API's could write: a Low finding of the review.

## T-54 A compromised service reaching further

**Asset** the host and the other services · **Attacker** whoever
exploits a bug in one service

**Path** Code execution in one service, most exposed the collector,
reads another's secrets or takes over the host.

**Prevent** One system user per service, settings files `0600 root`
or `0640 root:<service group>`, and systemd units with
`NoNewPrivileges`, a read-only system and private temporary
directories. The images are distroless, run as `65532:65532`, with a
read-only root filesystem and every capability dropped
([ADR 0052](../architecture/decisions/0052-phase9a-packaging.md)).
**Test** The package job: `systemd-analyze verify` and `security` on
every unit, each image's user checked, the collector run with
`--read-only --cap-drop ALL`, hadolint, and Trivy failing on any
fixable Critical or High. **Residual** A kernel or container runtime
escape is outside this product.

## T-55 A tampered release

**Asset** what operators install · **Attacker** EXT who can replace a
download, or a compromised release process

**Path** A tarball or image is swapped after it is built, or built from
code that is not the tagged commit.

**Prevent** Phase 10A: the release workflow builds from the tag in a
read-only job, publishes only after the owner approves the `release`
environment, and signs `SHA256SUMS`, the SBOMs and every image with
cosign keyless, with GitHub build provenance. **Test** Phase 10A's exit:
a clean runner verifies every checksum, signature and attestation
before installing. **Residual** Until 10A lands, there is no release to
tamper with: v0.9.0 is a tag only.

## T-56 A compromised dependency or build tool

**Asset** everything the build produces · **Attacker** whoever
controls an upstream crate, npm package, action or tool

**Path** A malicious or vulnerable version enters through a dependency
update, a moved action tag or a replaced download.

**Prevent** Every action is pinned by commit SHA. Tools that CI
downloads (gitleaks, Trivy, hadolint, cargo-deny, GoBGP) are pinned by
version and SHA-256. `cargo deny` refuses RustSec advisories, licences
outside the matrix, wildcard versions and sources other than crates.io;
`npm audit` refuses High advisories in the UI; Dependabot waits 14
days before proposing a version, and a new dependency needs a row in
the [licence matrix](../dependency-license-matrix.md). **Detect**
Trivy over every image; Dependabot alerts. **Test** The Rust job's
`cargo-deny` step, the web job's `npm audit`, and the package job's
Trivy scan, on every pull request. **Residual** A malicious version
published and adopted within the cooldown, before any advisory.

## T-57 A secret in the public history

**Asset** any credential ever committed · **Attacker** EXT reading the
repository

**Path** The repository becomes permanently public at v1.0.0 (BQ-16),
and a key, token or password in any past commit becomes everyone's.

**Prevent** TLS keys, CA bundles and passwords are generated at install
time and never committed; examples use `CHANGE_ME` and documentation
ranges. **Detect** gitleaks over the full history on every pull request.
**Test** The history job; a full scan of all 406 commits on
2026-10-13 found nothing. **Residual** A secret in a form gitleaks has
no rule for.

---

## Summary of residual risk

Four carry real residual exposure and are added to the
[risk register](../risk-register.md) — corrected 2026-08-30 from
"Three," stale since R19 was added during the 2026-08-24 Phase 5B
planning pass:

| Risk | Threat | Why it persists |
|---|---|---|
| **R16** | T-05 | Tenant isolation is application-enforced until Phase 8 RLS |
| **R17** | T-08 | Output escaping cannot be proven until a UI exists (Phase 6) |
| **R18** | T-22 | Evidence storage is out of scope, so its access model is undesigned |
| **R19** | T-25 | Recurring clock skew degrades availability by design (fail-closed); eliminating the residual requires infrastructure-level NTP discipline outside this project's control |

The rest reduce to "an attacker with database or host access can do
anything", which is a hardening problem outside this model, or to
"a correctly-permissioned user may act maliciously", for which the audit
trail is the designed control.
