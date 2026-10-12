# Mitigation Runbook

Status: Phase 7F.

Operating BGP mitigation: the mitigator, its `gobgpd`, the kill switch,
and what to do when a route is wrong. The
[incident runbook](incident-runbook.md) covers the rest of the stack. The
[RTBH guide](rtbh-guide.md) and the [FlowSpec guide](flowspec-guide.md)
explain the routes themselves.

## The parts

| Part | Does | Where |
|---|---|---|
| API | Records requests and decisions, and checks the guard. Never speaks to GoBGP | `wetechinetmon-api` |
| Mitigator | Announces what was approved, withdraws what ended, reconciles, proposes, and records peers. The only process that speaks to GoBGP | `wetechinetmon-mitigator`, metrics on `127.0.0.1:9094` |
| `gobgpd` | WetechiNetMon's BGP speaker. Its gRPC API must listen on loopback only | beside the mitigator |
| Edge routers | Act on the routes: discard, rate limit | yours |

One mitigator acts at a time. A second one waits as a standby on a
PostgreSQL advisory lock and takes over if the first one's connection
ends.

## Alerts

| Alert on | Meaning | Do |
|---|---|---|
| `wetechinetmon_mitigator_kill_switch == 1` | Nothing may be announced | Find out who engaged it and why (`kill-switch status`). Release it only when that is settled |
| `wetechinetmon_mitigator_bgp_peers{state="other"} > 0` | An iBGP session with an edge router is down | See [A peer is down](#a-peer-is-down) |
| `increase(wetechinetmon_mitigator_actions_total{result="failed"}[10m]) > 0` | A mitigation could not be announced | `mitigations show ID` gives `last_error` |
| `increase(wetechinetmon_mitigator_actions_total{result="error"}[10m]) > 0` | The mitigator's pass failed: the database or GoBGP | The mitigator's log |
| `increase(wetechinetmon_mitigator_reconcile_total[1h]) > 0` | Reconciliation withdrew a stale route or restored a lost one | See [Stale routes](#stale-routes) |
| The metrics endpoint is down | No mitigator is running: approved mitigations wait | Start it; nothing is lost |

The notifier tells channels about `mitigation.failed`,
`mitigation.kill_switch_engaged` and `bgp.peer_down` if routes send
those events there. See the
[notifier README](https://github.com/LogiXhare/wetechi-netmon/tree/main/crates/notification).

## The kill switch

Engage it when an announcement is wrong and you cannot yet tell which:
a route leak, a blackhole that is too broad, or a misbehaving edge.

```sh
wetechinetmonctl kill-switch engage --reason "route leak suspected"   # any noc_lead
```

The UI's Mitigations page does the same. Within one poll interval (2 s
by default) the mitigator withdraws everything live, and the guard
refuses every new request and approval. It is deployment-wide: it stops
every tenant's mitigations (FU-65).

To release it, decide first what was wrong. Then, **on the API host**:

```sh
wetechinetmon-api kill-switch release --actor-id <you> --reason "<what was fixed>"
```

No API token can release it, by design (T-47). The release is audited
under the actor id you give. Mitigations withdrawn by the switch stay
withdrawn. Request again what is still needed.

The guard file has its own `"kill_switch": true`, which survives a
database restore. Use it when the database itself is in doubt.

## Stale routes

A stale route is announced with no live mitigation behind it. A crash,
or a withdrawal that never completed, can leave one. The mitigator
reconciles at start and every `reconcile_interval_seconds` (60 by
default). It withdraws every route carrying its ownership community that
no `announcing` or `active` mitigation claims, and it restores routes
that live mitigations have lost. Each step is counted in
`wetechinetmon_mitigator_reconcile_total`.

To check by hand, compare the three views:

```sh
wetechinetmonctl bgp routes                    # what WetechiNetMon says is announced
gobgp -p 50051 global rib                      # what gobgpd holds (on the mitigator's host)
gobgp -p 50051 global rib -a ipv4-flowspec
# and on each edge router, the routes received from WetechiNetMon's gobgpd
```

If the mitigator is down and a route must go now, withdraw it with the
`gobgp` CLI on the mitigator's host:

```sh
gobgp -p 50051 global rib del 203.0.113.9/32
```

Then mark the mitigation withdrawn with `wetechinetmonctl mitigations
withdraw`. Never add routes to WetechiNetMon's `gobgpd` by hand. A route
without the ownership community is invisible to reconciliation and is
never withdrawn for you.

## A peer is down

`bgp.peer_down` names the neighbour and its state. `wetechinetmonctl bgp
peers` shows every session as the mitigator last saw it. **If `SEEN` is
old, the mitigator has stopped**, and the states shown may no longer be
true.

1. Check the session on both sides: `gobgp -p 50051 neighbor` on the
   mitigator's host, and the router's BGP summary.
2. While it is down, that router has none of WetechiNetMon's routes.
   When a BGP session ends, the router drops what it learned over it,
   unless graceful restart keeps it for a while. Active mitigations stop
   working on that router.
3. When the session returns, the routes are sent again. `bgp.peer_up`
   says so.

## A mitigation failed

`mitigations show ID` gives `last_error`:

| Error mentions | Cause | Do |
|---|---|---|
| a guard refusal (`not_allowlisted`, `too_wide`, `kill_switch`, ...) | The guard changed between approval and announcing | Correct the guard file if it is wrong, and request again |
| GoBGP, `unavailable`, a deadline | `gobgpd` is down or unreachable | Start `gobgpd`. Reconciliation catches up |
| anything else | A bug | Keep the mitigator's log and report it |

A failed mitigation never comes back by itself. Request it again.

## Dry-run and BGP off

`bgp_enabled: false` (the default) means the mitigator never connects to
GoBGP. `dry_run: true` (also the default) means mitigations go `active`
with `dry_run` set, and nothing is announced. The UI marks them
`(dry-run)`, and notifications say so. If an operator believes a
blackhole is in place and traffic still arrives, check this first:

```sh
wetechinetmonctl mitigations show <id>   # "Dry run  true" means nothing was announced
```

## Changing the guard

The API and the mitigator read the same guard file. They read it at
start, so restart **both** after a change. Validate the file first,
because a bad file stops the service rather than loading a weaker
guard. Lowering the floors below /16 and /32 is refused whatever the
file says.

## What operators cannot do here

- Set a route's next hop, communities or AS path from a request: these
  come from the deployment's configuration only.
- Approve their own request, unless `allow_self_approval` is on.
- Release the kill switch with a token.
- Make the API speak to GoBGP. Only the mitigator does.
