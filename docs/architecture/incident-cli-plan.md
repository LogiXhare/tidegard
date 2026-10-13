# Incident CLI — Plan

Status: **Planning only.** Part of the
[Phase 5 plan](phase5-incident-management-plan.md). No CLI exists.

`tidegardctl` is an API client. It holds no business logic, talks to
no database, and every command maps to an endpoint in the
[API plan](incident-api-plan.md). A second implementation of the state
machine living in a CLI is a guarantee that the two will disagree.

The command tree is original to this project, derived from the resource
model rather than borrowed from another product's syntax.

## Shape

```text
tidegardctl incidents <verb> [INCIDENT] [flags]
```

`INCIDENT` accepts either the internal ID or the human number, so an
operator can paste `WNM-2026-000123` straight from a bridge call.

| Command | Endpoint |
|---|---|
| `incidents list` | `GET /incidents` |
| `incidents show INCIDENT` | `GET /incidents/{id}` |
| `incidents timeline INCIDENT` | `GET /incidents/{id}/timeline` |
| `incidents detections INCIDENT` | `GET /incidents/{id}/detections` |
| `incidents audit INCIDENT` | `GET /incidents/{id}/audit` |
| `incidents acknowledge INCIDENT` | `POST .../acknowledge` |
| `incidents assign INCIDENT --user U` | `POST .../assign` |
| `incidents assign INCIDENT --team T` | `POST .../assign` |
| `incidents unassign INCIDENT` | `POST .../unassign` |
| `incidents claim INCIDENT` | `POST .../assign` with the caller |
| `incidents release INCIDENT` | `POST .../unassign` |
| `incidents investigate INCIDENT` | `POST .../investigate` |
| `incidents monitor INCIDENT` | `POST .../monitor` |
| `incidents note add INCIDENT` | `POST .../notes` |
| `incidents note list INCIDENT` | `GET .../notes` |
| `incidents severity set INCIDENT LEVEL` | `POST .../severity` |
| `incidents priority set INCIDENT LEVEL` | `POST .../priority` |
| `incidents resolve INCIDENT` | `POST .../resolve` |
| `incidents close INCIDENT` | `POST .../close` |
| `incidents reopen INCIDENT` | `POST .../reopen` |
| `incidents suppress INCIDENT` | `POST .../suppress` |
| `incidents unsuppress INCIDENT` | `POST .../unsuppress` |
| `incidents export INCIDENT` | `POST .../export` |

`note add` and `note list` are subcommands rather than flags because
notes are a collection with their own operations, and `--note` on a dozen
commands would blur "annotate" with "acknowledge and annotate".

## Output

`--output` accepts `table` (default), `json`, and `wide`.

- **`table`** is for humans: aligned columns, colour when the terminal
  supports it and never when piped, relative times (`4m ago`), truncated
  titles.
- **`json`** is the API response verbatim — not a reshaped version.
  Anything a script needs must be obtainable from `json`, so a change to
  the human table never breaks automation.
- **`wide`** is `table` with more columns.

**YAML output is not offered.** ADR 0008 declined YAML for policy
configuration because no maintained Rust YAML crate exists, and adding
one for CLI output would contradict that on weaker grounds. If FU-15 ever
lands a maintained crate, `--output yaml` becomes trivial.

```text
$ tidegardctl incidents list --state open,acknowledged --severity critical

NUMBER            SEVERITY  PRI  STATE         TARGET         CATEGORY     AGE    ASSIGNED
WNM-2026-000123   critical  P1   acknowledged  203.0.113.7    udp_flood    6m     j.rahman
WNM-2026-000122   critical  P1   open          198.51.100.0/24 multi_vector 19m    —
```

## Safety

| Concern | Behaviour |
|---|---|
| Confirmation | `close`, `reopen`, `suppress`, and lowering severity prompt unless `--yes` |
| Non-interactive | `--yes` required; a prompt with no TTY is an **error**, never an assumed yes |
| Expected version | Read automatically before mutating; `--expected-version` to pin explicitly |
| Idempotency | A key is generated per logical command and **reused across retries** |
| Retries | Only on network errors and `5xx`; never on `4xx` |
| Conflict | `409` prints the current state and version and exits `4`; no automatic re-issue |
| Tenant | From the profile; `--tenant` needs a platform permission |
| Credentials | From config file or environment, never a flag — flags land in shell history |

The idempotency behaviour is the point of the whole table. Because the
key is generated once per logical command and reused on retry, a `close`
that times out can be retried safely: the server replays the original
result rather than closing twice.

Automatic re-read-and-retry on `409` is deliberately **not** done. A
version conflict means someone else changed the incident, and re-issuing
blindly would overwrite their change — which is the exact failure
optimistic concurrency exists to prevent. The operator sees what changed
and decides.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic failure |
| `2` | Usage error |
| `3` | Authentication or authorization failure |
| `4` | Conflict — version, illegal transition, idempotency reuse |
| `5` | Not found |
| `6` | Rate limited |
| `7` | Server or storage unavailable |

Distinct codes let a wrapper script distinguish "retry later" (`6`, `7`)
from "your input is wrong" (`2`, `4`) without parsing text.

## Errors

```text
$ tidegardctl incidents close WNM-2026-000123
Error: the incident was modified by another actor (incident.version_conflict)

  expected version 6, current version 8
  current state:   resolved
  last updated by: u_5190 at 14:22:07Z

Re-read the incident and try again:
  tidegardctl incidents show WNM-2026-000123
```

Errors name the stable `error` code, state what was expected against what
is true, and suggest the next command. `--output json` emits the API
problem document unchanged so scripts switch on `error`.

## What the CLI does not do

- No notification, no mitigation — there is no `mitigate` verb, and there
  will not be one in Phase 5.
- No direct database access. Every command goes through the API, so
  authorization and audit cannot be bypassed by using the CLI.
- No local caching of incident state, which would go stale exactly when
  it matters.
- No bulk mutation across a filter — deferred with **FU-22**, since it
  needs its own authorization design.
