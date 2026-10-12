# RTBH Guide

Status: Phase 7F.

Remotely triggered blackhole (RTBH) routing, as WetechiNetMon does it. Read
this before the
[installation guide](../installation/mitigation.md), and agree the edge
router side with whoever runs your routers.

## What RTBH does

During an attack on one address, RTBH has your edge routers drop all
traffic **to** that address, attack and legitimate alike. The victim goes
offline, but the rest of the network keeps working. It is the bluntest
tool. Use it when the attack threatens the network and FlowSpec cannot
separate the attack from good traffic (see the
[FlowSpec guide](flowspec-guide.md)).

WetechiNetMon never decides to blackhole by itself. Someone requests it,
or the mitigator proposes it for a critical incident. Then a NOC lead
approves it, and only then is anything announced
([ADR 0046](../architecture/decisions/0046-phase7a-mitigation-record.md)).

## The route

The mitigator announces one route per mitigation to the `gobgpd` beside
it. That `gobgpd` peers over iBGP with your edge routers.

| | RTBH | Parent prefix |
|---|---|---|
| Prefix | the victim only: a /32 or a /128 | an allowlisted covering prefix, such as a /24 |
| Next hop | `rtbh_next_hop_ipv4` or `rtbh_next_hop_ipv6` | the same |
| Communities | `65535:666` (`BLACKHOLE`, RFC 7999), any you add, and `NO_EXPORT` | the same |
| Ownership | the large community `<local ASN>:5721677:1` | the same |
| Lasts | the requested duration, at most `max_duration_seconds` (1 hour by default) | the same |

All route attributes come from the deployment's configuration. A
request cannot set any of them
([ADR 0048](../architecture/decisions/0048-phase7c-gobgp-adapter.md)).

**The parent prefix** blackholes a whole block. It is for an attack
spread across many addresses, when dropping the block at the edge
protects the rest of the network. The guard allows it only where the
allowlist lists `parent_prefix` for that prefix and tenant, and never
shorter than the guard's `min_length` (see below).

## What your edge routers must do

The lab in CI proves what GoBGP sends
([ADR 0051](../architecture/decisions/0051-phase7f-two-speaker-lab.md)).
What your routers do with it is your configuration. Every router that
should drop the traffic needs four things:

1. **A discard route for the next hop.** Point `rtbh_next_hop_ipv4` and
   `rtbh_next_hop_ipv6` at a null interface on every edge router. The
   blackholed traffic then follows the BGP route there and is dropped.
   Use an address from your own space that is used for nothing else.
2. **An iBGP session with WetechiNetMon's `gobgpd`**, with an import
   policy that accepts **only**:
   - routes carrying `BLACKHOLE`;
   - routes whose prefix length is /32 or /128, plus the parent prefixes
     you have allowlisted;
   - routes inside your own address space.

   Reject everything else from this session. Do not trust the guard
   alone; this is defence in depth.
3. **No re-advertisement.** `NO_EXPORT` keeps the route inside your AS.
   Make sure no export policy strips it, and never send these routes to
   a transit provider or a peer unless you mean to ask them to blackhole
   it too. That is a separate, upstream-specific arrangement (RFC 7999),
   and WetechiNetMon does not do it.
4. **Unicast RPF on customer edges, if you use source-based RTBH.**
   WetechiNetMon only does destination-based RTBH.

Check the policy before going live, with BGP on and dry-run off, in a
maintenance window. Request an RTBH for a test address in your own space
that carries no traffic. Then see it arrive at each edge router with
`BLACKHOLE` and `NO_EXPORT`, see traffic to it dropped, withdraw it, and
see it go. The [installation guide](../installation/mitigation.md) walks
through this.

## Limits that hold whatever the configuration says

- **Floors:** nothing shorter than `min_length` is announced: /24 for
  IPv4 and /48 for IPv6 by default, and never shorter than /16 and /32
  whatever the configuration says. RTBH is a host route only.
- **Allowlist:** each prefix is bound to one tenant and to the actions
  allowed on it. With an empty allowlist, nothing is allowed.
- **Duration:** every mitigation ends. Expiry withdraws it.
- **Four eyes:** the requester cannot approve their own request unless
  `allow_self_approval` is on.
- **Kill switch:** any NOC lead can engage it. It withdraws everything
  live and refuses new mitigations until released on the API host.

## Watching it

- `wetechinetmonctl mitigations list --live` or the UI's Mitigations page
  shows what is requested and what is active.
- `wetechinetmonctl bgp routes` shows what was announced, with the route
  recorded at announcement.
- `wetechinetmonctl bgp peers` shows the iBGP sessions as the mitigator
  last saw them. A peer that goes down is notified as `bgp.peer_down`.
- The [mitigation runbook](mitigation-runbook.md) covers what to do when
  something goes wrong.
