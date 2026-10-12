# 0050. Phase 7E Mitigations in the API, CLI and UI

Status: **Accepted** (7E-1, the API; 7E-2, the CLI); the UI and
notifications follow in this ADR's later sections as they are built
Date: 2026-10-12
Deciders: Repository owner (BQ-14, 2026-10-12); the details under the
delegation of 2026-10-05 to industry practice

## Context

Mitigations exist (ADR 0046), are guarded (ADR 0047) and are carried to
GoBGP (ADRs 0048 and 0049), but nobody can request or approve one except
through the database. 7E gives people the API, the CLI and the UI, tells
them about mitigations through the notifier, and replaces the incident's
constant `mitigation_status` and `notification_status` with the truth
(FU-64) ([Phase 7 plan](../phase7-bgp-mitigation-lab-plan.md), 7E).

## Decision

### The API (7E-1)

| Endpoint | Permission |
|---|---|
| `GET /api/v1/mitigations` (`limit`, `live`) | `mitigation.read` |
| `POST /api/v1/mitigations` (`Idempotency-Key` required) | `mitigation.request` |
| `GET /api/v1/mitigations/{id}` and `/history` | `mitigation.read` |
| `POST /api/v1/mitigations/{id}/approve` | `mitigation.approve` |
| `POST /api/v1/mitigations/{id}/reject` | `mitigation.approve` |
| `POST /api/v1/mitigations/{id}/withdraw` | `mitigation.withdraw` |
| `GET` and `PUT /api/v1/mitigation-controls/kill-switch` | `mitigation.read`; engage or release |
| `GET /api/v1/bgp/routes` | `mitigation.read` |
| `GET /api/v1/bgp/peers` | `mitigation.kill_switch.engage` |

- **The API never speaks to GoBGP.** It records and decides; the
  mitigator announces. `/bgp/routes` lists the tenant's mitigations that
  were announced live, with the route recorded when announcing began.
  `/bgp/peers` reads a snapshot the mitigator writes at every
  reconciliation (V21); its `updated_at` shows how old it is, so a
  stopped mitigator never looks like a healthy session.
- **The guard is checked in the API too,** from
  `WETECHINETMON_API_MITIGATION_GUARD_FILE`, the same file the mitigator
  can name as `guard_file`: one allowlist for both. Without the file
  nothing is allowlisted and every request is refused.
- **A request cannot carry route attributes.** Unknown fields are
  refused, so a `next_hop` in the body is `400 api.unknown_field`, never
  silently ignored.
- **Another tenant's mitigation does not exist:** `404
  mitigation.not_found`, identical to an id nobody has. The
  tenant-isolation suite covers every `{mitigation_id}` operation.
- **Errors** are thirteen new `mitigation.*` codes in the registry. The
  guard's refusals keep their codes; another tenant's prefix is
  `mitigation.not_allowlisted`, as a prefix nobody owns.

### The CLI (7E-2)

`wetechinetmonctl` gains three nouns, each one or two API requests and
nothing more:

| Command | API |
|---|---|
| `mitigations list [--live] [--limit N]` | `GET /mitigations` |
| `mitigations show` and `history MITIGATION` | `GET /mitigations/{id}` and `/history` |
| `mitigations request --prefix --action --reason --for [--incident] [flow flags] [--rate]` | `POST /mitigations` |
| `mitigations approve`, `reject` and `withdraw MITIGATION` | `POST /mitigations/{id}/...` |
| `kill-switch status` and `engage --reason` | `GET` and `PUT /mitigation-controls/kill-switch` |
| `bgp routes` and `bgp peers` | `GET /bgp/routes` and `/bgp/peers` |

- **Asking first:** approving (it will be announced), withdrawing (the
  protection ends) and engaging the kill switch. These follow ADR 0040's
  rules: `--yes` answers in advance, and with no terminal and no `--yes`
  nothing is sent. Requesting and rejecting announce nothing, so they
  do not ask.
- **Versions:** a decision reads the mitigation's version, and the
  question shows its action, prefix and requester, unless
  `--expected-version` pins the version and `--yes` answers in advance. A
  retried decision the server already applied is refused as a `409`,
  never applied twice.
- **No route attributes:** there are no flags for them, and an unknown
  flag is a usage error.
- **A mitigation id must be a UUID** before it is put in a URL. An
  incident number given to `--incident` is resolved in the caller's
  tenant first.
- **`kill-switch release`** is a usage error that names the host command.
- **`bgp peers`** writes a warning to stderr when the newest snapshot is
  more than five minutes old. That is five times the mitigator's default
  reconciliation interval. JSON output stays verbatim.

### Releasing the kill switch is host-only

API tokens carry the four token roles, up to `noc_lead`, so no token
holds `mitigation.kill_switch.release`. Any `noc_lead` can engage the
switch through the API or the UI. Releasing it takes
`wetechinetmon-api kill-switch release --actor-id ID --reason TEXT` on
the API host, with database access: break-glass, audited under the
given id. `status` and `engage` are there too.

### The incident's statuses (FU-64)

- `mitigation_status`: the incident's most live mitigation, or else the
  one that ended last: `none`, `pending_approval`, `approved`, `active`,
  `dry_run`, `withdrawing`, `withdrawn`, `rejected`, `expired` or
  `failed`.
- `notification_status`: each channel's latest outcome on the timeline:
  `none`, `delivered` (every channel), `partial`, or `failed` (none
  delivered).

Both are read within the incident's tenant, on every response that
returns the incident.

## Consequences

- `apps/api/tests/mitigations.rs` proves the whole API against
  PostgreSQL, the kill switch's host-only release, and both statuses.
  `tenant_isolation.rs` covers the five `{mitigation_id}` operations.
- `apps/cli/tests/mitigation_commands.rs` pins the CLI against a
  stand-in API, which records every request. A request carries one
  key and a resolved incident. A decision is never sent unconfirmed, a
  conflict is not re-issued, and an old peer snapshot is called out.
- **FU-65:** the kill switch and the BGP peers are deployment-wide, and
  any tenant's `noc_lead` may engage the switch and read the peers.
  Right for the single-tenant deployments v1.0 targets (BQ-4); Phase 8
  confines both to the operator's own tenant.
- The notifier still says `mitigation_status: none` in incident
  messages; 7E-4 corrects it along with mitigation notifications.

## Alternatives considered

- **The API reading GoBGP directly.** A second client of an
  unauthenticated route-injection API. Rejected: the mitigator stays the
  only one.
- **A `platform_admin` token role to release the switch.** It would put
  the most dangerous release on a bearer token that can leak. Rejected
  for host access.
- **Leaving the statuses as `none` until Phase 9.** They would be wrong
  from the first mitigation. Rejected.
