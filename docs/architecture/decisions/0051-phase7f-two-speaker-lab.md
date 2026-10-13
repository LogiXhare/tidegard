# 0051. Phase 7F The Two-Speaker BGP Lab

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-13, 2026-10-12); the details under the
delegation of 2026-10-05 to industry practice

## Context

So far every test has asked Tidegard's own `gobgpd` what it holds
(ADRs 0048 and 0049). An operator cares about something else: what the
edge router receives. That covers the route, its next hop and
communities, the FlowSpec action, and that it is gone after withdrawal
([Phase 7 plan](../phase7-bgp-mitigation-lab-plan.md), 7F). Proving this
needs a second BGP speaker in CI that stands in for the router, without
peering with anything CI did not start.

## Decision

### Two `gobgpd`, peered over iBGP on loopback

`scripts/start-gobgp-lab.sh` starts two instances of the pinned GoBGP
v4.9.0. The script shares its version and checksum with
`start-gobgpd.sh` through `scripts/gobgp-version.sh`.

| | Speaker (ours) | Edge (the router's stand-in) |
|---|---|---|
| AS | 65001 | 65001 |
| Router id | 192.0.2.252 | 192.0.2.253 |
| BGP | 127.0.0.1:10179 | 127.0.0.2:10179 |
| gRPC API | 127.0.0.1:50061 | 127.0.0.1:50062 |

- **iBGP**, because an RTBH trigger router peers with its edge routers
  inside the AS. The next hop and the communities arrive unchanged, and
  `NO_EXPORT` is legitimate within the AS.
- **IPv4 and IPv6 unicast and FlowSpec** are negotiated, the four
  families the mitigator announces.
- **Loopback only.** Each instance binds its own loopback address and
  names only the other as a neighbour, so no route can leave the runner.
  The unprivileged port 10179 means neither needs root.
- The single `gobgpd` of `start-gobgpd.sh`, with its BGP port closed,
  stays as it is. The mitigator's service test counts its peers as none.

### The test

`crates/mitigator/tests/two_speaker_lab.rs` waits for the session to be
established. It then announces each action through the speaker:

- RTBH, for IPv4 and IPv6;
- a parent prefix;
- FlowSpec discard, for IPv4 and IPv6;
- a FlowSpec rate limit with a source prefix.

It reads the edge's table with the same `owned_routes` the mitigator
uses for reconciliation. The ownership large community is transitive,
so the edge sees exactly Tidegard's routes. The test checks:

- **exactly** as many routes as were announced, each reading back to its
  own prefix and action;
- the configured RTBH next hop, and both `BLACKHOLE` and `NO_EXPORT`;
- `traffic-rate` 0 for a discard, and the bytes per second for a limit;
- **nothing** at the edge once each route is withdrawn.

The test needs `TIDEGARD_GOBGP_LAB_SPEAKER` and
`TIDEGARD_GOBGP_LAB_EDGE`. Without them it says why and passes. The
CI rust job and each PostgreSQL job start the lab and fail if the test
skipped, as they do for the single-speaker test.

## Consequences

- The Phase 7 lab criterion is checked in CI on every pull request: the
  edge receives exactly what was announced, and nothing after withdrawal.
- T-42 (route leak) and T-44 (stale route) gain a test at the edge
  router's side.
- The lab proves what GoBGP sends, not what a vendor's router does with
  it. The RTBH and FlowSpec guides say what an edge router must be
  configured to do, and the operator verifies that on their own
  equipment.

## Alternatives considered

- **A containerised router OS (FRR, BIRD) as the edge.** It would be
  closer to a real router, but it adds an image to pin and trust, and
  its FlowSpec support differs from what most edge routers run. Rejected
  for CI. An operator may still run their own lab.
- **eBGP between the two.** `NO_EXPORT` would rightly stop the routes at
  the boundary, and RTBH is not deployed that way. Rejected.
- **Checking only the speaker's own table.** That is what 7C and 7D
  already do. It cannot show what a peer receives. Rejected.
