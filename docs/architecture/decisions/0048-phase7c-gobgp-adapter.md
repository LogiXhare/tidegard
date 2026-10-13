# 0048. Phase 7C The GoBGP Adapter

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-13 and BQ-15, 2026-10-12); the details
under the delegation of 2026-10-05 to industry practice

## Context

BQ-13 chose GoBGP's gRPC API, from Rust, to a `gobgpd` the operator
runs. This is the first code in Tidegard that can change what the
internet routes, so the plan names its risks: an exposed, unauthenticated
API (R27), a new dependency tree (R28), and an API that changes between
releases (R29) ([Phase 7 plan](../phase7-bgp-mitigation-lab-plan.md),
7C).

## Decision

### The crate, and only the crate

`crates/mitigator` holds the generated client, the path builder and the
connection. The dependency closure test proves that gRPC (`tonic`,
`prost`, `h2`) appears nowhere else in the workspace and that no other
crate depends on the mitigator. No crate embeds a BGP speaker: GoBGP
stays a separate process, so its Apache-2.0 licence places no obligation
on this repository beyond keeping its notice with the vendored files.

### The API, vendored and pinned (R29)

GoBGP **v4.9.0** (tag commit `96ef11aedd066031f1bacb2c587baaa769ba07eb`,
released 2026-09-01). Its six `.proto` files are copied unmodified into
`crates/mitigator/proto/api/`, with GoBGP's `LICENSE` beside them and
their SHA-256 sums in `proto/README.md`. v4.10.0 was eight days old on
the day of this decision and was passed over under the two-week rule.

`build.rs` compiles them with `protox`, a protobuf compiler written in
Rust, and `tonic-prost-build`. No `protoc` binary is needed on any
machine or in CI. Only the client is generated.

| Crate | Version | Licence | Why |
|---|---|---|---|
| `tonic` | 0.14.6 | MIT | The gRPC client. Features `codegen`, `channel` and `tls-aws-lc` only: no server, no router |
| `tonic-prost`, `prost`, `prost-types` | 0.14.6, 0.14.4, 0.14.4 | MIT, Apache-2.0 | Messages and their encoding |
| `tonic-prost-build`, `protox` | 0.14.6, 0.9.1 | MIT, MIT or Apache-2.0 | Build time only |

`protox` 0.10.0 was five days old and was passed over for 0.9.1.

### The connection (R27)

GoBGP's API has no authentication of its own, and `gobgpd` listens on
every interface by default (`--api-hosts :50051`). So:

- **Plain HTTP reaches loopback only.** The mitigator refuses
  `http://` to any other host.
- **Off loopback, TLS** verified against a configured CA bundle, with an
  optional client certificate for a `gobgpd` started with
  `--tls-client-ca-file`, so only the mitigator may call it.
- **Every call has a deadline**, five seconds by default.
- The runbook (7F) tells operators to start `gobgpd` with
  `--api-hosts 127.0.0.1:50051`.

### Paths

The route attributes are the deployment's `RouteConfig`, never the
request's (ADR 0046): the local ASN, the IPv4 and IPv6 RTBH next hops,
standard communities (by default `BLACKHOLE`, RFC 7999), large
communities, `NO_EXPORT` (on by default) and `NO_ADVERTISE`.

- **RTBH and parent prefix:** a unicast path. IPv4 uses `NEXT_HOP`;
  IPv6 uses `MP_REACH_NLRI`, as GoBGP requires.
- **FlowSpec** (RFC 8955): destination prefix, then source prefix,
  protocol, destination port and source port, in type order, each an
  equality; `traffic-rate` 0 to discard, or the bytes per second to
  limit. No blackhole community. GoBGP wants a next hop in
  `MP_REACH_NLRI`; the unspecified address is the convention.
- **Ownership:** every path carries the large community
  `<local ASN>:5721677:1` ("WNM" as a number). Listing returns only
  paths carrying it, so reconciliation (7D) can never see, let alone
  withdraw, a route another speaker or an operator added.
- **Read-back:** a listed path is parsed back into the prefix and action
  it implements, and so into the same duplicate key a live mitigation
  has. One route per key is what reconciliation compares.

## Consequences

- `crates/mitigator/tests/gobgp_lab.rs` announces every action to a real
  `gobgpd` in CI, reads back the next hop, communities and traffic rate,
  checks that a route without the ownership community is never listed,
  and withdraws everything. The `rust` job starts that `gobgpd` from the
  pinned release, checked by SHA-256, with its BGP port closed, and fails
  if the test skips.
- Nothing calls the adapter yet. The mitigator service (7D) does, after
  the guard.
- Upgrading GoBGP means replacing the vendored files, their sums, the CI
  pin and its checksum together, in one reviewed change.

## Alternatives considered

- **`protoc` at build time.** Every developer and CI job would need the
  right `protoc`. Rejected for `protox`.
- **Generated code committed.** No build step, and a second copy of the
  API to keep in step with the `.proto` files. Rejected.
- **The `gobgp` command line.** Text output is not an API. Rejected by
  BQ-13.
- **Trusting the network around GoBGP.** Rejected: an unauthenticated
  route-injection API must not depend on a firewall someone else
  maintains.
