# FlowSpec Guide

Status: Phase 7F.

BGP FlowSpec (RFC 8955 for IPv4, RFC 8956 for IPv6), as Tidegard uses
it. FlowSpec tells your edge routers to drop or rate-limit only the
traffic that matches a rule, such as UDP from port 53 to one host, so the
victim stays reachable. Read the [RTBH guide](rtbh-guide.md) first: the
approval, the guard and the kill switch are the same.

## The two actions

| Action | Effect at the edge | Extended community |
|---|---|---|
| `flowspec_discard` | Matching traffic is dropped | `traffic-rate` 0 |
| `flowspec_rate_limit` | Matching traffic is limited to a rate, given in **bytes per second** | `traffic-rate` *N* |

`traffic-rate` is in bytes per second, as RFC 8955 defines it. For
100 Mbit/s, ask for 12,500,000. FlowSpec redirect (to a VRF or a next hop)
is not offered. It was deferred (BQ-15).

## The match

The destination is always the mitigation's prefix, and the guard checks
it as for any other action. The other components are optional. Each one
must match exactly, and they are sent in type order, as the RFC requires:

| Component | CLI flag | UI field |
|---|---|---|
| Destination prefix | `--prefix` | Prefix |
| Source prefix | `--source` | Source prefix |
| IP protocol (17 is UDP, 6 is TCP) | `--protocol` | Protocol |
| Destination port | `--destination-port` | Destination port |
| Source port | `--source-port` | Source port |

For example, to rate-limit DNS reflection towards one host to
1 Mbit/s:

```sh
tidegardctl mitigations request --prefix 203.0.113.9/32 \
  --action flowspec_rate_limit --protocol 17 --source-port 53 \
  --rate 125000 --for 30m --reason "DNS reflection, WNM-2026-000123"
```

A NOC lead then approves it. The mitigator announces it in the IPv4 or
IPv6 FlowSpec family, with the ownership large community and the
unspecified next hop, as GoBGP requires. FlowSpec rules never carry
`BLACKHOLE`. The two-speaker lab in CI proves the edge receives the rule
with its `traffic-rate`, and nothing after withdrawal
([ADR 0051](../architecture/decisions/0051-phase7f-two-speaker-lab.md)).

## What your edge routers must do

1. **Negotiate FlowSpec** (`ipv4-flowspec` and, if you use it,
   `ipv6-flowspec`) on the iBGP session with Tidegard's `gobgpd`.
2. **Install FlowSpec rules in the forwarding plane** on the interfaces
   that face your upstreams. Many platforms need this turned on per
   interface or globally, and some limit how many rules the hardware
   holds. Know that limit.
3. **Validation.** RFC 8955's validation compares a rule with the best
   unicast route to its destination. Platforms differ in how they apply
   it to rules from an iBGP peer that does not carry the unicast route.
   Configure the session so that rules from Tidegard are accepted,
   and import **only** rules whose destination is inside your own space.
4. **Never send these rules to another AS** unless you have arranged it
   with that network.

Test it as you would RTBH. In a maintenance window, rate-limit a test
flow to a test address in your own space, see the rule on each edge
router, measure the limit, withdraw it, and see it go.

## Choosing between them

- **FlowSpec discard** when the attack has a clear signature, such as a
  protocol and a port, that legitimate traffic to the victim does not
  share. The victim stays online.
- **FlowSpec rate limit** when the signature is shared with legitimate
  traffic, such as DNS to a resolver. Some good traffic is lost, and the
  link survives.
- **RTBH** when nothing separates the attack from good traffic, or the
  routers cannot install the rule. The victim goes offline, and the
  network is saved.
