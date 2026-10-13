# 0042. Phase 6B Traffic Read API

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner, under the delegation of 2026-10-05 to
industry practice

## Context

The NOC UI (6D) talks only to the REST API, so the traffic it shows needs
endpoints ([Phase 6 plan](../phase6-dashboards-ui-notifications-plan.md),
6B). The traffic lives in ClickHouse, and three facts constrain how the
API reads it:

- **The traffic tables carry no tenant** (R21). Prefix ownership arrives
  in Phase 8. Until then, traffic is deployment-wide, unlike incidents.
- **API tokens are tenant-scoped.** No token holds a platform role, so a
  platform-only permission would leave the traffic unreadable.
- **The `clickhouse` crate in the tree is 0.13, built without TLS**, and
  its upgrade is FU-6. The API must not send plaintext off loopback, as
  for its own listener and the database.

## Decision

### Who may read traffic

- A new permission, **`traffic.read`**, is in every human role bundle,
  from `viewer` up.
- **One tenant is the traffic tenant**, named by
  `TIDEGARD_API_TRAFFIC_TENANT`. Only its callers can reach the
  traffic endpoints. Every other tenant gets `404`, the same answer as
  for an endpoint that does not exist, checked before anything is read.
  If the variable is unset, traffic is off and everyone gets `404`.
- This is correct for the single-tenant deployments v1.0 targets, and
  safe for a multi-tenant one: traffic stays with the operator's own
  tenant. Phase 8 replaces it with prefix ownership.

### How the API reads ClickHouse

Through ClickHouse's HTTP interface, with the hyper client and
`tokio-rustls` the CLI already uses. **No new crates**, and no dependency
on the 0.13 crate.

- **Queries are fixed text with server-side parameters** (`{from:UInt32}`).
  No caller value is ever spliced into SQL. A dimension such as `host`
  selects a table and key from an allowlist in the code.
- **Every request is read-only and bounded:** `readonly=2`,
  `max_execution_time=10`, `max_result_rows=10000` with
  `result_overflow_mode=throw`, and a capped response size. Operators
  should also give the API a ClickHouse user that can only `SELECT`.
- **TLS off loopback**, verified against a configured CA bundle, as for
  the database. `http://` is accepted only for a loopback host.
- **Credentials** are a user name and a password read from a file. The
  password is never logged and is sent as a sensitive header.
- **Times are Unix seconds**, so neither side's time zone matters.

### Endpoints

| Endpoint | Returns |
|---|---|
| `GET /api/v1/traffic/summary` | Bits and packets per second over time, IPv4 and IPv6 |
| `GET /api/v1/traffic/top` | The top hosts, networks, /24s, hostgroups, ASNs, interfaces or exporters by bytes |
| `GET /api/v1/exporters` | Each exporter seen in the last day, when it last reported, and its rate over the last five minutes |

A range is at most 30 days, the ClickHouse retention, and a summary has at
most 500 points. Reads share the per-actor read rate limit.

## Consequences

- A deployment that wants traffic in the UI sets two things: the traffic
  tenant and the ClickHouse connection.
- The tenant-isolation suite covers the new endpoints: another tenant's
  noc_lead gets `404`.
- The API gains a second datastore. It answers `503` when ClickHouse is
  unreachable, and incidents keep working.

## Alternatives considered

- **A platform role for traffic.** No token can hold one before Phase 8,
  so traffic would be unreadable from the UI.
- **Every tenant reads all traffic.** That leaks one customer's traffic
  to another in a multi-tenant deployment (R21).
- **Upgrade the `clickhouse` crate and enable its TLS.** That is FU-6's
  breaking-change review, and the collector's write path would move with
  it. The HTTP interface needs nothing new.
