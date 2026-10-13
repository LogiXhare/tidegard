# Migration Notes

Status: **v1.0.0**, 2026-10-13.

What each release does to the two databases. Read the entries between
your version and the new one before you [upgrade](../operations/upgrading.md).

## How migrations work

- **PostgreSQL**, the incident database: the incident manager applies the
  migrations in `crates/incident-postgres/migrations` when it starts,
  before it reports ready, with refinery. They only move forward: none is
  ever edited once released, and none has an inverse (ADR 0024). Rolling
  back is restoring a backup.
- **ClickHouse**, the flow and detection history: the collector creates
  any missing table when its export starts. A table is never altered in
  place.
- The migration and the application roles are separate (V11): the
  migration role owns the schema, and the services' role
  `wetechinetmon_app` can only read and write rows. Restore the roles
  before the database, as the [disaster recovery runbook](../operations/disaster-recovery.md)
  says, or V11's grants fail.

## v1.0.0

**No migration.** v1.0.0 has the same 21 PostgreSQL migrations as
v0.9.0, and the same ten ClickHouse tables. An upgrade from v0.9.0
changes no schema; CI proves it on every pull request with a database
v0.9.0 filled.

## v0.9.0: V1 to V21

| Migration | Phase | What it adds |
|---|---|---|
| V1 | 5B | Extensions |
| V2 | 5B | `incidents`: one versioned row per incident |
| V3 | 5B | `incident_detection_events`: the events linked to each incident, unique per tenant and deduplication key |
| V4 | 5B | `incident_timeline`: append-only |
| V5 | 5B | `incident_audit`: every authorization decision, denials included |
| V6 | 5B | Notes, tags and assignment history |
| V7 | 5B | Policy references and per-tenant incident number allocators |
| V8 | 5B | `incident_idempotency`: the durable idempotency store |
| V9 | 5B | `incident_outbox` and its dead letters |
| V10 | 5B | Partial unique indexes: one active incident per target |
| V11 | 5B | The migration and application roles (ADR 0032) |
| V12 | 5B | The order of an incident's policy references |
| V13 | 5B | A count of policy references past the cap |
| V14 | 5C | `detection_event_inbox`: what the collector hands the incident manager |
| V15 | 5D | `api_tokens`: SHA-256 of each token, never the token |
| V16 | 5D | Keyset pagination indexes for the incident list |
| V17 | 5F | The `note_redacted` timeline entry |
| V18 | 6C | `api_sessions`: the NOC UI's browser sessions |
| V19 | 7A | `mitigations` and their history |
| V20 | 7D | The kill switch, and the exact route each mitigation announced |
| V21 | 7E | `bgp_peers`: GoBGP's peers as the mitigator last saw them |

The ClickHouse tables: total IPv4 and IPv6 traffic, and traffic per host,
network, /24, hostgroup, ASN, exporter and interface, kept 30 days; and
detection events, kept 365 days.
