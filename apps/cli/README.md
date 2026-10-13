# tidegardctl

The incident CLI ([Milestone 5E](../../docs/development/phase5-implementation-plan.md),
[ADR 0040](../../docs/architecture/decisions/0040-phase5e-cli-client.md)).

It is an API client and nothing more. Every command maps to an
[API endpoint](../api/README.md). It holds no business logic and never
touches the database, so authorization and audit cannot be bypassed by
using it.

## Status

Every command in the [CLI plan](../../docs/architecture/incident-cli-plan.md) is implemented. The CLI also covers opening an incident and tags, which the API gained in 5D.

## Connecting

Credentials are **never** command-line flags, because flags land in shell
history. The environment overrides the config file, field by field.

| Setting | Environment | Profile field |
|---|---|---|
| API URL | `TIDEGARD_API_URL` | `url` |
| Token | `TIDEGARD_API_TOKEN` | `token` |
| CA bundle (PEM) | `TIDEGARD_API_CA_FILE` | `ca_file` |

The config file is JSON, at `$TIDEGARD_CONFIG`. By default it is at
`~/.config/tidegard/cli.json`, or `%APPDATA%\tidegard\cli.json`
on Windows.

```json
{
  "default_profile": "noc",
  "profiles": {
    "noc": {
      "url": "https://wnm-api.example.net:8443",
      "ca_file": "/etc/tidegard/ca.pem",
      "token": "wnm_..."
    }
  }
}
```

Keep the file readable only by you, because it holds a token.
`--profile NAME` picks a profile.

- **`https://` needs a CA bundle.** TLS verification cannot be turned off.
  On Linux, the system bundle works, for example
  `/etc/ssl/certs/ca-certificates.crt`.
- **`http://` is accepted only for a loopback API.**

## Commands

```text
tidegardctl [--output table|wide|json] [--profile NAME] <noun> <verb> ...

incidents list [--state S] [--severity S] [--priority P] [--direction D]
               [--target-type T] [--sort opened_at|last_detected_at]
               [--order desc|asc] [--limit N] [--cursor C]
               [--opened-from TIME --opened-to TIME]
incidents show INCIDENT
incidents timeline INCIDENT [--limit N] [--cursor C]
incidents detections INCIDENT [--limit N] [--cursor C]
incidents audit INCIDENT [--limit N] [--cursor C]
incidents note list INCIDENT

incidents acknowledge | investigate | monitor | unassign | release | unsuppress INCIDENT
incidents assign INCIDENT --user U | --team T
incidents resolve INCIDENT [--note TEXT]
incidents close INCIDENT --reason R [--detail TEXT]           (confirms)
incidents reopen INCIDENT --reason TEXT                       (confirms)
incidents suppress INCIDENT (--until TIME | --for 2h) --reason TEXT   (confirms)
incidents severity set INCIDENT LEVEL [--reason TEXT]    (confirms when lowering)
incidents priority set INCIDENT LEVEL
incidents note add INCIDENT --message TEXT
incidents note edit INCIDENT INDEX --message TEXT      (your own note)
incidents note redact INCIDENT INDEX --reason TEXT     (confirms)
incidents claim INCIDENT                    (assign to yourself)
incidents tag set INCIDENT KEY VALUE
incidents tag remove INCIDENT KEY
incidents export INCIDENT [--file PATH]     (a new file; never overwritten)
incidents open --title T --severity S --target-scope host|prefix|slash24|hostgroup_total
               --target X --direction incoming|outgoing|internal
               [--priority P] [--description TEXT] [--address-family 4|6]

mitigations list [--live] [--limit N]
mitigations show MITIGATION
mitigations history MITIGATION
mitigations request --prefix P --reason TEXT --for 30m
                    --action rtbh|parent_prefix|flowspec_discard|flowspec_rate_limit
                    [--incident INCIDENT] [--protocol N] [--source P]
                    [--source-port N] [--destination-port N] [--rate BYTES_PER_SECOND]
mitigations approve MITIGATION                 (confirms)
mitigations reject MITIGATION --reason TEXT
mitigations withdraw MITIGATION --reason TEXT  (confirms)
kill-switch status
kill-switch engage --reason TEXT               (confirms)
bgp routes
bgp peers
```

### Changing an incident safely

- **The version is read first.** A change sends the version it read, so if someone else changed the incident in between, the API refuses with `409`. `--expected-version N` pins the version instead of reading it.
- **A `409` is never re-issued.** It exits `4` and shows the current version and state. Someone else changed the incident, so you decide again.
- **One `Idempotency-Key` per command, reused on every retry.** A change that timed out and was retried is replayed by the server, never applied twice.
- **Some changes ask first:** closing, reopening, suppressing, lowering severity, and redacting a note. `--yes` answers in advance. With no terminal and no `--yes` the command is an error and sends nothing. Missing confirmation is never taken as a yes.

`INCIDENT` is the incident's id or its number, such as `WNM-2026-000123`.
A number is looked up in your tenant.

### Mitigations

BGP mitigations are described in
[ADR 0050](../../docs/architecture/decisions/0050-phase7e-mitigation-api-cli-ui.md).
The CLI talks only to the API. It never talks to GoBGP.

- **A request announces nothing.** A `noc_lead` approves it, and then the
  mitigator announces it. Unless the deployment allows it, you cannot
  approve your own request. There is no flag for a next hop or a
  community, because route attributes are the deployment's.
- **Approving, withdrawing and engaging the kill switch ask first.** They
  follow the same rules as an incident: `--yes` answers in advance, the
  version is read unless `--expected-version` pins it, and a `409` exits `4`.
- **Releasing the kill switch is not a CLI command.** No API token may
  release it. On the API host, run
  `tidegard-api kill-switch release --actor-id ID --reason TEXT`.
- **`bgp peers` warns when the snapshot is old.** The mitigator records
  its peers each time it reconciles. If the newest record is more than
  five minutes old, the mitigator has probably stopped, and the sessions
  shown may no longer be up.

`MITIGATION` is a mitigation id, as shown by `mitigations list`.

### Output formats

| Format | What it prints |
|---|---|
| `table` | For people. |
| `wide` | `table` with more columns. |
| `json` | The API's response body, **verbatim**. Errors are the API's problem document, so scripts switch on its `error` code. |

Text from the API, such as titles and notes, has its control characters
replaced before it reaches the terminal.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic failure |
| `2` | Usage error, or input the API refused as malformed (`400`, `413`, `415`, `422`) |
| `3` | Authentication or authorization (`401`, `403`) |
| `4` | Conflict (`409`) |
| `5` | Not found (`404`) |
| `6` | Rate limited (`429`) |
| `7` | Unreachable, or the server failed after retries (`5xx`) |

Requests are retried only after a connection error or a `5xx`, at most
three times, and never after a `4xx`.
