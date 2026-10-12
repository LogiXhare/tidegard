# 0047. Phase 7B The Safety Guard

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-4, BQ-14 and BQ-15, 2026-10-12); the
details under the delegation of 2026-10-05 to industry practice

## Context

A mitigation that blackholes the wrong prefix takes a customer, or
someone else's network, off the internet (R25). FR-6.4 asks for an
authorized-prefix allowlist, tenant prefix ownership, a maximum
announcement scope, minimum and maximum prefix lengths, a maximum
duration and an emergency global disable. Phase 8 will bring prefix
ownership; until then, BQ-4 makes the allowlist deployment
configuration ([Phase 7 plan](../phase7-bgp-mitigation-lab-plan.md), 7B).

## Decision

### One pure check, three moments

`Guard::check` in `crates/mitigation` answers one question: may this
tenant have this action on this prefix for this long, now? It is pure
and has no configuration of its own beyond what it is built with.

It runs three times:

1. when a mitigation is requested or proposed;
2. when it is approved;
3. when announcing begins.

Each time under the configuration in force at that moment, so a narrowed
allowlist or the kill switch stops a mitigation that was fine an hour
ago. Taking a mitigation down is never refused. Every refusal is audited
as `denied`, like a missing permission: an attempt on a prefix the
tenant does not own is a security event.

### What it refuses

| Rule | Code |
|---|---|
| The kill switch is on, in the file or at runtime | `mitigation.kill_switch` |
| No allowlist entry covers the prefix, or the covering entry is another tenant's | `mitigation.not_allowlisted` |
| The covering entry does not permit the action | `mitigation.action_not_allowed` |
| A non-host prefix shorter than the configured minimum, or a FlowSpec source of `/0` | `mitigation.too_wide` |
| A duration over the configured maximum | `mitigation.too_long` |

Another tenant's prefix gets the same answer as a prefix nobody owns, so
the guard does not reveal who owns what.

### The configuration

A JSON file, like the notifier's. Unknown keys are errors, so a misspelt
switch is never silently ignored. An empty file is the fresh install:

```json
{
  "dry_run": true,
  "bgp_enabled": false,
  "kill_switch": false,
  "max_duration_seconds": 3600,
  "approval_window_seconds": 900,
  "allow_self_approval": false,
  "min_length": { "ipv4": 24, "ipv6": 48 },
  "allowlist": [
    {
      "prefix": "192.0.2.0/24",
      "tenant": "acme",
      "actions": ["rtbh", "flowspec_discard", "flowspec_rate_limit"]
    }
  ]
}
```

- **Dry-run on, BGP off** by default. The mitigator announces only when
  both `bgp_enabled` is true and `dry_run` is false.
- **Nothing is allowlisted** by default, so a fresh install cannot
  mitigate anything.
- **Floors** that no configuration can go below: an allowlist entry or a
  minimum length wider than `/16` for IPv4 or `/32` for IPv6 is refused
  when the file is loaded. A typo must not allow blackholing a `/8`.
- **Entries of different tenants may not overlap.** The most specific
  covering entry decides, and it can only ever name one tenant.
- **The maximum duration** is at most seven days, the domain's ceiling.

### Where the kill switch lives

The file's `kill_switch` is honoured at every check. A runtime switch,
which an operator can turn on through the API without a restart, is the
check's other input; 7D and 7E add its storage and its endpoint.

## Consequences

- The unauthorized-prefix suite (`crates/mitigation/tests/unauthorized_prefixes.rs`)
  proves the refusals over fixed hostile cases and 2,000 generated
  prefixes per property, for every action and both families.
- `crates/incident-postgres/tests/mitigation_guard.rs` proves the guard
  runs at each of the three moments against PostgreSQL, that a refusal
  writes nothing but its audit row, and that withdrawal is never refused.
- `MitigationStore::new` takes the guard, and takes the approval policy
  from it.

## Alternatives considered

- **The allowlist in the database, managed through the API.** It is
  Phase 8's prefix ownership in all but name, and it would let anyone
  who can call that API widen what can be blackholed. Rejected for
  Phase 7: a file changes through the deployment's own review.
- **Checking only at request.** Simpler, and blind to a configuration
  that changed while a request waited. Rejected.
- **Rounding a prefix to its length.** Rejected in 7A: the guard sees
  only canonical prefixes.
