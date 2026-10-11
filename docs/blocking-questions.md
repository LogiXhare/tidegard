# Blocking Questions

Status: Phase 6 planning — **BQ-2 and BQ-10 to BQ-12 resolved**
2026-10-11. No Phase 6 decision remains outstanding.
Last updated: 2026-10-11

## Decision summary

| # | Question | Status | Blocks |
|---|---|---|---|
| BQ-1 | Project licence | Resolved — Apache-2.0 | — |
| BQ-2 | Grafana bundling | **Resolved 2026-10-11** — external only | — |
| BQ-3 | Reference hardware and traffic rates | Open | Benchmarking |
| BQ-4 | Phase 8 before or after v1.0.0 | Open | Phase 7 scheduling |
| BQ-5 | Incident identity (UUID vs ADR 0009) | **Resolved 2026-08-22** — UUIDv7, conditional | Was 5A |
| BQ-6 | Mitigation states in the incident machine | **Resolved 2026-08-22** — excluded | Was 5A |
| BQ-7 | PostgreSQL and HTTP dependencies | **Resolved 2026-08-22** — approved architecturally | Was 5B |
| BQ-8 | Manual closure for critical incidents | **Resolved 2026-08-22** — required by default | — |
| BQ-9 | Default reopen window | **Resolved 2026-08-22** — 15 min, inclusive | — |
| BQ-10 | How the web UI signs in before OIDC | **Resolved 2026-10-11** — API token exchanged for a session | — |
| BQ-11 | Web UI stack | **Resolved 2026-10-11** — React, TypeScript, Vite | — |
| BQ-12 | Phase 6 scope and order | **Resolved 2026-10-11** — dashboards, UI, notifications; no InfluxDB | — |

These are the only questions treated as genuinely blocking for Phase 1+
architecture and legal posture. Per master prompt §31, minor questions are
intentionally excluded — engineering-level choices proceed via ADRs in the
relevant phase instead of stalling here.

## BQ-1: What license should WetechiNetMon itself use?

This determines the Phase 1 `LICENSE` file, the `NOTICE` file, and the
CONTRIBUTING model, and it interacts directly with the Enterprise/Managed
edition strategy in [commercial-boundaries.md](commercial-boundaries.md).

Options to choose between:

- Permissive (Apache-2.0 or MIT) — maximizes community adoption, but a
  competitor could fork and offer a competing managed service on the exact
  same code.
- Source-available / dual-license (e.g., a permissive core with certain
  modules under a more restrictive license, or a BSL-style delayed-open
  model) — protects WeTechi Solutions' commercial tiers, at the cost of not
  being a "pure" open-source project for community-adoption purposes.
- Copyleft (AGPLv3) — strong protection against SaaS competitors reusing
  the code without contributing back, but may deter enterprise adoption and
  needs care given Grafana's own AGPLv3 exposure (see
  [dependency-license-matrix.md](dependency-license-matrix.md)).

**This cannot be defaulted by the agent** — it is a business decision for
WeTechi Solutions.

**Resolved 2026-08-21.** Apache-2.0, with incoming contributions accepted
under the same license via DCO sign-off and no CLA — see
[ADR 0006](architecture/decisions/0006-contribution-licensing-dco-not-cla.md).
The permissive-license fork risk described above was accepted knowingly.

## BQ-2: Is Grafana bundled/modified, or treated strictly as an external, operator-supplied service?

Directly affects whether Grafana's AGPLv3 terms create obligations for
WetechiNetMon's own source availability. Phase 0's working assumption
(stated in the dependency matrix) is "external service only, ship
dashboard JSON/provisioning, never a modified Grafana binary." This needs
explicit confirmation before Phase 6 packaging work begins, since it
constrains how the web app and Grafana integration are packaged together.

**Resolved 2026-10-11: external only.** WetechiNetMon ships original
dashboard JSON and provisioning files, and never bundles or modifies a
Grafana binary. The operator runs their own Grafana. See the
[Phase 6 plan](architecture/phase6-dashboards-ui-notifications-plan.md).

## BQ-3: What are the actual reference/target hardware and traffic-rate expectations?

Non-functional performance targets (NFR-1) currently have no numeric
target because none were supplied. Before Phase 9 (production hardening)
load/soak testing can produce meaningful pass/fail criteria, WeTechi
Solutions needs to supply (or approve a proposed) target flow-record rate,
exporter count, and hardware profile — otherwise "production-ready" at
v1.0.0 has no objective bar.

## BQ-4: Does Phase 8 (multi-tenancy/RBAC) land before or after the v1.0.0 release cut?

Flagged in [roadmap.md](roadmap.md) — the master prompt's phase list
(0–10) places multi-tenancy at Phase 8 of 10, but the version list defines
v1.0.0 as the "production-ready single-tenant release" and v1.1.0/v1.2.0 as
multi-tenancy/enterprise-auth, implying tenancy is post-1.0. Phase 1
sequencing/roadmap planning benefits from an explicit confirmation of the
proposed resolution (tenancy ships after v1.0.0) before Phase 7/8 work is
scheduled. This is lower urgency than BQ-1–BQ-3 since it doesn't block
Phase 0/1 work, but should be confirmed before Phase 7 starts.

## BQ-5: Does FR-5.2's "UUID" requirement override the ADR 0009 no-`uuid` precedent for incidents?

[FR-5.2](functional-requirements.md) requires the incident record to
persist a **UUID**.
[ADR 0009](architecture/decisions/0009-detection-event-identity.md)
deliberately declined the `uuid` crate for *detection events*, because it
would have added a random-number dependency to a hot-path crate that did
not otherwise need one, and because those identifiers are correlation
keys rather than secrets.

That reasoning does not transfer unchanged. The incident manager will
already depend on a database driver and an HTTP stack, so `uuid` costs
proportionally nothing there.
[ADR 0013](architecture/decisions/0013-incident-identity.md) recommends
**UUIDv7** — satisfying FR-5.2 while avoiding UUIDv4's index
fragmentation and a serial key's enumerability. The fallback, if the
dependency is refused, is `BIGSERIAL` plus a random public token, which
is more moving parts and is not recommended.

Also to confirm: should the human-readable incident number
(`WNM-2026-000123`) reset its sequence annually, or run continuously per
tenant?

~~**Blocks** Milestone 5A, since it determines the primary key type.~~

### BQ-5 decision — 2026-08-22

**Approved conditionally: UUIDv7** for the internal `incident_id`,
subject to a focused dependency and licence review during implementation.

- Phase 4 detection-event identifiers are **unchanged**; ADR 0009 stands.
- The human-readable number is a separate database-backed display value.
- Identifiers are **not** authentication secrets, and authorization must
  never depend on their unpredictability.
- The `uuid` crate is **not** added by this decision — it goes through
  [ADR 0018](architecture/decisions/0018-phase5-dependency-selection.md).

**Not decided at the time of this BQ-5 record:** whether the incident
number resets annually or runs continuously per tenant. Affected a
display value, not the primary key, so it did not block 5A. Tracked as
**FU-24**.

**FU-24 resolved 2026-08-24, during Phase 5B planning:** continuous
per-tenant sequence, no annual reset. See
[ADR 0013](architecture/decisions/0013-incident-identity.md#phase-5b-resolution-incident-number-format-2026-08-24)
and [follow-ups.md](development/follow-ups.md).

Recorded in
[ADR 0013](architecture/decisions/0013-incident-identity.md).

## BQ-6: Should the deferred mitigation states be absent from the incident state machine, or present but unreachable?

[FR-5.1](functional-requirements.md) specifies one state machine
including `AwaitingApproval`, `MitigationPending`, `Mitigating`, and
`HoldDown` — all mitigation concepts that Phase 5 is forbidden from
implementing and that Phase 7 will own. FR-5.1 also opens with
`Suspected` and `Confirmed`, which already exist in Phase 4 as
`PendingTrigger` and `Active`.

[ADR 0014](architecture/decisions/0014-incident-state-machine.md)
recommends implementing only the operator-facing states and deferring the
mitigation ones, on the grounds that an API advertising `Mitigating` when
nothing can mitigate is the same kind of capability lie that Phase 4's
`executed` field was added to prevent. The alternative is to define them
now as unreachable, which avoids a Phase 7 migration.

Either way FR-5.1 and the implementation will disagree until FR-5.1 is
updated to reference the ADR.

~~**Blocks** Milestone 5A, since it determines the state set.~~

### BQ-6 decision — 2026-08-22

**Approved: mitigation lifecycle stays outside the core incident state
machine.** Option C (present but unreachable) was considered and
rejected — an enum a client can read still advertises a capability that
does not exist.

- No `AwaitingApproval`, `MitigationPending`, `Mitigating`,
  `MitigationFailed`, `WithdrawalPending`, `Withdrawing`, or `HoldDown`.
- A **read-only, non-authoritative** mitigation reference seam remains:
  a summary field always `none` in Phase 5, plus reserved outbox event
  types nothing consumes.
- Mitigation status must never control the incident lifecycle; the two
  are independently queryable, and one incident may eventually have
  several mitigation operations.

**Two further state-machine decisions taken at the same review:**

- **`Reopened` is a transition, not a state** — already the design, now
  recorded as deliberate.
- **`Suppressed` becomes an attribute, not a state.** This is a change,
  and it fixes a defect: as a state, `UnsuppressIncident` had to send the
  incident somewhere and sent it to `Open`, silently discarding the
  progress of an incident that had been `Investigating`. The core
  lifecycle is now **seven** states.

FR-5.1 still needs updating to reference
[ADR 0014](architecture/decisions/0014-incident-state-machine.md) —
**FU-27**.

## BQ-7: May Phase 5 add PostgreSQL, a database driver, and an HTTP framework as dependencies?

Phase 4 added **zero** third-party crates. Phase 5 as designed cannot:
[ADR 0015](architecture/decisions/0015-incident-operational-storage.md)
selects PostgreSQL for operational state, which needs a driver
(`sqlx` or `tokio-postgres`, both MIT/Apache-2.0), and the REST API needs
an HTTP framework.

This is a genuine change in the project's dependency posture and is not a
decision to make silently inside an implementation commit. Each new crate
needs a
[dependency-license-matrix](dependency-license-matrix.md) row before use.

~~**Blocks** Milestone 5B entirely.~~ Without it there is no persistence
and no API, leaving only the in-memory domain of 5A.

### BQ-7 decision — 2026-08-22

**Approved architecturally.** Phase 5 may introduce PostgreSQL and HTTP
dependencies. This is approval of **capability, not of any crate**.

Before any crate is added, implementation must record a
dependency-selection ADR, **verify actual published package metadata**
rather than the values assumed in these planning documents, update the
licence matrix and `NOTICE`, and validate on both Windows and Linux.
Criteria and shortlist are in
[ADR 0018](architecture/decisions/0018-phase5-dependency-selection.md);
selection itself is **FU-25** and **FU-26**.

No dependency was added during planning or during this review.

## BQ-8: Should `critical` incidents require manual closure?

Auto-close is convenient and prevents a queue filling with resolved
incidents nobody closes. It also means a critical incident can close with
no human ever having looked at it, which for a severity that implies
customer impact may be unacceptable.

[ADR 0014](architecture/decisions/0014-incident-state-machine.md)
proposes `INCIDENT_AUTO_CLOSE_MIN_SEVERITY = critical`, meaning critical
incidents require manual closure and everything below auto-closes after
24 hours. This is a policy question about how the NOC works, not an
engineering one.

**Does not block** implementation — it is a configuration default — but
resolving it alongside BQ-5 to BQ-7 is cheaper than revisiting.

### BQ-8 decision — RESOLVED 2026-08-22

**Critical incidents require manual closure by default.**

Options considered are below; **Option A was approved**.

| Option | Consequence |
|---|---|
| **A. `critical` requires manual closure** (proposed default) | No critical incident closes without a human looking at it. Cost: the queue accumulates resolved-but-unclosed criticals if the team does not triage, and someone must notice |
| **B. Everything auto-closes after the delay** | The queue stays clean with no effort. Cost: a critical incident — a severity that implies customer impact — can open, resolve, and close with **no human ever having seen it**, and the first anyone hears of it is a customer call |
| **C. Manual closure at `major` and above** | Stricter than A; more manual work; more coverage |
| **D. Configurable per tenant** | Most flexible. Cost: more configuration surface, and a per-tenant default is one more thing to get wrong |

**Approved: Option A**, on 2026-08-22.

**Rationale.** Auto-close is a convenience, reasonable at the severities
where nobody would have acted anyway. At `critical` it buys very little
and risks the one outcome that destroys trust — an incident that opened,
resolved, and closed with nobody having seen it.

**Semantics.** Critical may auto-advance to `Recovering` and then to
`Resolved`; it may **not** auto-advance to `Closed`. `Resolved` and
`Closed` are operationally distinct — recovery of the traffic condition
versus completion of NOC review. Non-critical severities may auto-close.

**Configuration.** `INCIDENT_CRITICAL_MANUAL_CLOSURE_REQUIRED=true`
(secure default) replaces the previous `INCIDENT_AUTO_CLOSE_MIN_SEVERITY`
threshold, and `INCIDENT_AUTOMATIC_CLOSURE_DELAY_SECS` drops from 24 h to
30 min. Overrides must be explicit, tenant-aware, policy-aware where
supported, gated on `incident.closure_policy.override`, immutably
audited, and visible in effective-configuration diagnostics.

**Permissions.** Closing requires `incident.close`. Overriding the policy
requires `incident.closure_policy.override`, which is in **no** default
bundle — making criticals close themselves is precisely what an attacker
with a foothold would want.

**Audit.** Every closure and every override writes an immutable record.

**Security impact:** removes the unseen-critical failure mode; composes
with suppression, since a suppressed critical still cannot auto-close.
**Operational impact:** a resolved-but-unclosed queue now exists and must
be watched. **Community, not Enterprise** — a safety default may not be
a paid feature.

**Required tests** (see the [testing plan](architecture/incident-testing-plan.md)):
critical resolves but does not auto-close by default; an authorized
operator can close it; an unauthorized one cannot; the override is
audited; a non-critical incident auto-closes when configured; `Resolved`
and `Closed` remain distinct; a duplicate close is idempotent; concurrent
closes are conflict-safe.

## BQ-9: What should the default reopen window be?

Recurrence inside the window reopens the existing incident; outside it,
a new incident is created referencing its predecessor. The proposed
default is **15 minutes**.

Too short and one attack becomes a stream of separate incidents. Too long
and genuinely distinct attacks are merged into one, hiding the second.
The right value depends on observed attack patterns on this network,
which is operational knowledge rather than an engineering judgement.

**Does not block** implementation.

### BQ-9 decision — RESOLVED 2026-08-22

**15 minutes, as the initial technical default.** Configurable, and
explicitly **not** a legal, regulatory, contractual, or SLA requirement.

Options considered are below; **Option A was approved**.

| Option | Consequence |
|---|---|
| **A. 15 minutes** (proposed default) | Balances the two failure modes. A pause-and-resume attack stays one incident; a genuinely new attack an hour later is separate |
| **B. 5 minutes** | Fewer wrongly-merged incidents. Cost: a flapping attack produces a stream of separate incidents, each needing acknowledgement — the exact alert fatigue hysteresis exists to prevent |
| **C. 60 minutes** | Very few duplicates. Cost: a genuinely distinct second attack within the hour is absorbed into the first and **hidden**, which is the more dangerous direction of error |
| **D. Scale with severity** | Longer window for critical. Cost: reopen behaviour becomes severity-dependent and harder to reason about during an incident |

**Approved: Option A, 15 minutes**, on 2026-08-22 — explicitly a starting
value to be revisited once real recurrence data exists.

**The boundary is inclusive.** Elapsed **≤** window reopens; **>** window
creates a new incident. Measured from `resolved_at`, or `closed_at` when
the incident never passed through resolution. This is stated because "15
minutes" has two defensible readings, and a test written against one with
code against the other passes review and fails in production.

**Configuration.** Minimum `0` (recurrence always creates a new incident,
reopening disabled), default `900` seconds, maximum accepted `86400`. The
24-hour maximum is a **validation bound** against typos, not an
operational recommendation.

**Risk of too long:** a genuinely distinct second attack is absorbed into
a resolved incident and **hidden**. This is the dangerous direction.
**Risk of too short:** a flapping attack becomes a stream of separate
incidents, each demanding acknowledgement — the alert fatigue hysteresis
exists to prevent. Fifteen minutes sits deliberately closer to the second.

**Transaction implications.** A reopen performs ten effects atomically:
transition to `Open`, increment `reopen_count`, set `reopened_at`, append
an immutable timeline entry, append a mandatory audit record, link the new
evidence, preserve all prior history, preserve the original incident
identity, increment `version`, and write the outbox event — in the one
authoritative transaction, or none of them. A reopen may never produce two
simultaneously active incidents for one correlation key; the partial
unique index enforces that at the database.

**Observability.** `wetechinetmon_incidents_reopened_total` by severity,
plus the close-to-recurrence gap distribution (**FU-28**) so the value can
eventually be chosen from evidence.

**Required tests** (see the [testing plan](architecture/incident-testing-plan.md)):
recurrence at 14 m 59 s reopens; recurrence at exactly 15 m reopens, per
the inclusive boundary; recurrence after 15 m creates a new incident; a
zero-minute configuration always creates a new incident; recurrence links
new evidence; `reopen_count` increments; `reopened_at` updates; the
timeline stays append-only; prior history is unchanged; a duplicate
recurrence event is idempotent; concurrent reopens yield one active
incident; cross-tenant recurrence never correlates; different directions
never correlate; host and parent prefix never correlate; a category change
does not split the incident; a policy change does not split the incident.

## Non-Blocking Items (explicitly not asked here)

Collector language split (Rust vs. Go per component), event-transport
choice (NATS vs. Redpanda vs. Kafka), Recharts vs. ECharts, and specific
dependency version pins are **not** blocking questions — they are ADR-level
engineering decisions to be resolved in the phase that needs them, per
master prompt §31 ("do not ask minor questions").

## BQ-10: How does the web UI sign in before Phase 8 brings OIDC?

The API authenticates bearer tokens. A browser should not hold one, and
local passwords would add a credential store, lockout and reset flows
that Phase 8's OIDC and Entra ID work will supersede.

**Resolved 2026-10-11.** An operator signs in once with an existing API
token, and the API answers with a session cookie: `HttpOnly`, `Secure`
and `SameSite=Strict`, stored only as a hash, with idle and absolute
expiry, and ended when the token is revoked. State-changing requests
also need a CSRF header. Local accounts and OIDC remain Phase 8.

## BQ-11: What is the web UI built with?

**Resolved 2026-10-11.** React, TypeScript and Vite, as `apps/web`
has recorded since Phase 1. React escapes output by default, which is
the first control against T-08. The npm supply chain is managed with a
committed lockfile, `npm ci`, `npm audit` and a licence check (R22).

## BQ-12: What does Phase 6 cover, and in what order?

**Resolved 2026-10-11.** Grafana dashboards first, then the read APIs,
sessions and the UI (v0.7.0), then notifications by email, Teams,
Slack, Telegram and webhook (v0.8.0). InfluxDB dashboards are dropped:
nothing in WetechiNetMon writes to InfluxDB, and FR-11.2 makes it
optional.
