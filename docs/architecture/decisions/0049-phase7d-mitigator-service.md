# 0049. Phase 7D The Mitigator Service

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-14, 2026-10-12); the details under the
delegation of 2026-10-05 to industry practice

## Context

7A gave a mitigation its record, 7B the guard, 7C a way to reach GoBGP.
7D is the process that joins them: it carries approved mitigations to
GoBGP and takes them down at their end, keeps GoBGP and the records in
step across restarts, honours a kill switch an operator can pull without
a restart, and proposes mitigations for incidents
([Phase 7 plan](../phase7-bgp-mitigation-lab-plan.md), 7D). The risks it
answers are stale routes (R26) and an announcement nobody approved.

## Decision

### `wetechinetmon-mitigator`

A binary in `crates/mitigator`, like the notifier: the environment says
where the database is (`WETECHINETMON_MITIGATOR_DATABASE_URL`, with an
optional CA file) and where its file is (`WETECHINETMON_MITIGATOR_CONFIG`).
The file holds the guard (ADR 0047), the route attributes and the GoBGP
endpoint (ADR 0048), the proposal policy and two intervals. Unknown keys
are errors. Metrics on `127.0.0.1:9094` by default, with closed label
sets.

**One at a time.** It takes a PostgreSQL advisory lock at start and
holds it for its life. A second mitigator waits as a standby, so two
processes never write to GoBGP at once.

**BGP off means no connection.** With `bgp_enabled` false it never
connects to GoBGP: it runs every mitigation through its states in
dry-run. With BGP on but `dry_run` true, it connects, so it can withdraw
and reconcile what an earlier live run announced, and it announces
nothing.

### One pass

Every two seconds by default, over every live mitigation:

| State | What happens |
|---|---|
| `proposed`, `requested`, past the approval window | `expired` |
| `approved` | The route is built and recorded (V20's `mitigations.route`). `announcing` begins, and the guard decides once more in that transaction. Then the route is announced and the mitigation is `active`, or in dry-run it is only recorded and `active` |
| `approved`, refused by the guard at that moment | `failed`, with the refusal; nothing is sent. The new `approved → failed` edge exists for this |
| `active` past `expires_at` | `withdrawing` (duration reached), the route withdrawn, `withdrawn` |
| anything up, while the kill switch is on | taken down with the cause `kill_switch`; an approved one ends at once |
| `withdrawing` | the route withdrawn, then `withdrawn`; a failure is retried next pass |
| `announcing`, left by a restart | announced again (AddPath with the same NLRI replaces) and `active` |

A failure to announce takes down anything partial, then marks the
mitigation `failed`. A step that fails for any other reason is logged,
counted and retried on the next pass.

### Reconciliation

At start and every minute by default, when BGP is enabled: the routes in
GoBGP that carry the ownership community are compared with the
mitigations that were announced live and are `announcing` or `active`.

- A route that no mitigation claims is **withdrawn**: left behind by a
  crash, or by a withdrawal that never completed.
- An active mitigation without its route is **restored**: `gobgpd`
  restarted and lost its table.

A route without the ownership community is never seen, so
reconciliation cannot touch another speaker's or an operator's route.
A dry-run mitigation never claims a route.

### The kill switch at runtime

V20 adds `mitigation_controls`, one row. Turning the switch on needs
`mitigation.kill_switch.engage`, held by `noc_lead` and above: stopping
every mitigation is always safe to ask for. Turning it off needs
`mitigation.kill_switch.release`, held by platform administrators only.
Each change needs a reason, is audited, and emits
`mitigation.kill_switch_engaged` or `_released`. Setting it to what it
already is writes nothing.

The store reads the switch in the same transaction as every guard check,
so a request, an approval or an announcement that races the switch
loses. The mitigator reads it at the start of every pass.

### Proposals

Off by default. When enabled, each pass looks for incidents that are an
incoming attack on one host, still open, of a configured severity,
opened within a window, and with no mitigation yet, and proposes an RTBH
for that host for the configured duration. Candidates outside the
allowlist are skipped before the store is asked, so the audit trail
records real attempts only. A proposal announces nothing until an
approver approves it (BQ-14). The mitigator reads the `incidents` table
for this rather than the outbox, which stays the notifier's alone
(ADR 0045).

## Consequences

- `crates/mitigator/tests/mitigator_service.rs` runs the whole service
  against PostgreSQL and a real `gobgpd` on 15 to 18: announcing,
  the duration, an operator's withdrawal, the kill switch, stale and
  missing routes, dry-run, BGP off, approval expiry, a refusal at the
  last moment, and proposals. The `postgres` job now starts `gobgpd`
  too, from the same pinned, checksummed script as the `rust` job.
- `crates/incident-postgres/tests/mitigation_controls.rs` proves the
  switch's permissions, audit and events, the work list and the
  proposal candidates.
- The API, CLI and UI for mitigations and the kill switch are 7E.

## Alternatives considered

- **A process per tenant.** Tenants share GoBGP; one writer is simpler
  and safe. Rejected.
- **The outbox as the mitigator's queue.** It has one status per row and
  the notifier consumes it (ADR 0045). The table is the queue.
- **Withdraw everything on shutdown.** A restart of the mitigator would
  then drop every blackhole mid-attack. Rejected: routes outlive the
  process, and reconciliation and the duration keep them honest.
- **Kill switch release by `noc_lead`.** Rejected: whoever stops
  mitigation in an emergency should not be the only check on starting
  it again.
