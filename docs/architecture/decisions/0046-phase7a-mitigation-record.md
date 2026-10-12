# 0046. Phase 7A The Mitigation Record

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-6 2026-08-22, BQ-14 and BQ-15 2026-10-12);
the details under the delegation of 2026-10-05 to industry practice

## Context

Phase 7 announces routes. Before any code talks to GoBGP, a mitigation
needs a record: what it does, who asked, who approved, what state it is
in, and a history that cannot be rewritten
([Phase 7 plan](../phase7-bgp-mitigation-lab-plan.md), 7A). BQ-6 settled
that this record is not part of the incident's state machine. BQ-14
settled that nothing is announced without an approver. BQ-15 settled the
actions.

## Decision

### A domain crate of its own

`crates/mitigation` holds the record, its states and its commands. Like
the incident domain it is pure: no database, no BGP, no network. The
dependency closure test holds it to the same reviewed allowlist, so GoBGP
and gRPC can only ever enter through `crates/mitigator` (7C). It depends
on `crates/incident` for the tenant, actor and permission types alone, so
a mitigation is authorized exactly as an incident is.

### What a request says, and what it cannot

A request names a prefix, an action (RTBH, parent prefix, FlowSpec
discard, FlowSpec rate-limit), a FlowSpec match where it applies, a
reason, a duration and, optionally, the incident it answers. It does
**not** carry a next hop or communities. Those are deployment
configuration the mitigator applies (7C), so no API caller can steer
traffic with a crafted attribute.

The domain checks what needs no configuration: a prefix is canonical
(`192.0.2.1/24` is refused, not rounded); RTBH is a `/32` or `/128`; a
parent prefix is not; ports need TCP or UDP; a rate is above zero and at
most 100 Gbit/s; a reason is 1 to 1000 characters without control
characters; a duration is between one minute and seven days. The
allowlist and the per-deployment bounds are the guard's (7B).

### States

`proposed` and `requested` wait for an approver. `approved` is the only
way to `announcing`, then `active`, `withdrawing` and `withdrawn`.
`rejected`, `expired` (nobody approved in time) and `failed` end it. A
test enumerates every pair of states. Another proves that every path
into a state that may hold a route passes through `approved`, and every
path out ends in `withdrawn` or `failed`.

The duration runs from activation: `expires_at` is set when GoBGP holds
the route, not when someone asked.

### Who may do what

| Permission | Held by |
|---|---|
| `mitigation.read` | `viewer` and up |
| `mitigation.request`, `mitigation.withdraw` | `senior_operator` and up |
| `mitigation.approve` | `noc_lead` and up |
| `mitigation.propose`, `mitigation.execute` | The mitigator's service account only |

A requester cannot approve their own mitigation: two people for every
announcement. A deployment with one person on shift may turn that off;
every approval is audited either way. The mitigator can propose and carry
out, and never approve. People can approve, and never carry out. Another
tenant's mitigation does not exist: `not_found`, without its version.

### Persistence

In the incident database, as V19: `mitigations` and an append-only
`mitigation_history`. Audit rows, outbox events and idempotency records
reuse `incident_audit`, `incident_outbox` and `incident_idempotency`,
which are polymorphic by design, with type `mitigation`. Each change
writes the state, the history, the audit row and the outbox event in one
transaction. A refusal of permission is audited as `denied` after the
transaction rolls back.

- **Duplicate-action protection** (FR-6.4) is a partial unique index on
  a key of action, prefix and match, over live states. Two concurrent
  requests for the same thing cannot both succeed. A test races them.
- **Lost updates:** the row is locked and the update matches the loaded
  version. An operator's change carries the version they saw.
- **Retries** replay by idempotency key; the same key with another
  request is refused.
- **Defence in depth:** `CIDR` refuses bits below the length, and a
  check refuses an RTBH wider than a host route, whatever the
  application does.

No foreign key ties a mitigation to an incident: a mitigation outlives
the incident it answered, and retention removes closed incidents whole.

### Events

Each change emits `mitigation.<state>` to the outbox, with the prefix,
the action, the states and the reason, and no route attributes. The
notifier, the outbox's one consumer, already skips aggregates it does
not know; 7E teaches it these. The mitigator does not consume the
outbox: it works from the `mitigations` table, which keeps the outbox a
single-consumer queue (ADR 0045).

## Consequences

- Mitigations can be requested, approved, rejected and withdrawn, and
  the mitigator's steps are ready for 7D. Nothing announces yet: no code
  talks to GoBGP.
- The incident's `mitigation_status` is still the Phase 5 constant until
  7E derives it (FU-64).
- FlowSpec redirect is not representable (BQ-15). Adding it later is a
  new action kind and a migration.

## Alternatives considered

- **Mitigation states inside the incident machine.** Rejected by BQ-6.
- **Route attributes in the request.** Flexible, and it lets any
  requester choose where traffic goes. Rejected: attributes are
  configuration.
- **A separate database or schema.** Rejected: a mitigation's audit and
  events belong in the same transaction as its state, and the incident
  database already has the polymorphic tables and the operations around
  them.
- **Self-approval always allowed.** Simpler, and it makes approval a
  formality. Rejected as the default; available as a deployment choice.
