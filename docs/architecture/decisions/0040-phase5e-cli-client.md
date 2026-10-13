# 0040. Phase 5E CLI Client

Status: **Accepted**
Date: 2026-10-05
Deciders: Repository owner

## Context

Milestone 5E builds `tidegardctl`, the incident CLI described in the
[CLI plan](../incident-cli-plan.md). The CLI is an API client and nothing
more. It holds no business logic and never touches the database, so
authorization and audit cannot be bypassed by using it.

The plan fixes behaviour but not means. Four choices were open:

- how the CLI speaks HTTP and TLS;
- how it parses its arguments;
- where its credentials come from;
- how it resolves the human incident number an operator pastes from a
  bridge call.

The project weighs every new dependency against the
[dependency criteria](0018-phase5-dependency-selection.md). It hand-writes
small things a crate would bring in bulk: the RFC 3339 formatter, and
the GCRA limiter after `governor` was rejected
([ADR 0038](0038-phase5d-api-boundary.md)). On 5 Oct 2026 the owner
delegated these gate decisions to industry practice.

## Decision

**No new crates.** Everything the CLI needs is already in `Cargo.lock`
and already reviewed.

- **HTTP:** `hyper` 1.x, with its `client` and `http1` features, over one
  connection per request. axum already depends on hyper, so this adds
  code but no crates. A CLI issues a handful of requests and needs no
  connection pool, so `hyper-util`'s pooled client is not used.
- **TLS:** `tokio-rustls` with the crypto provider the API server and the database connector already use. The
  CLI never disables verification. There is no `--insecure`, and no
  setting turns verification off.
- **JSON:** `serde_json`.
- **TTY detection:** `std::io::IsTerminal`.

**Trust comes from an explicit CA bundle.** An `https://` endpoint needs
`ca_file`, a PEM bundle. On Linux that can be the system bundle, such as
`/etc/ssl/certs/ca-certificates.crt`. A NOC deployment with a private CA
points it at that CA. Reading the operating system's trust store needs a
platform crate, `rustls-native-certs` or `rustls-platform-verifier`. That
is deferred, with its own dependency review, as FU-57.

**Plain HTTP is allowed only to a loopback address,** mirroring the
server, which refuses plaintext off loopback (ADR 0038). A token is
never sent in plaintext across a network.

**Arguments are parsed by hand.** The tree is fixed and small:
`incidents <verb> [INCIDENT] [flags]`, roughly twenty verbs and a dozen
flags. `clap` would add about a dozen crates for parsing that fits in one
reviewed module with exhaustive unit tests. Unknown flags and stray
arguments are usage errors (exit `2`), never ignored. This mirrors the
API's refusal of unknown fields.

**Credentials never come from a flag,** because flags land in shell
history:

- The token comes from `TIDEGARD_API_TOKEN` or from a profile in the
  config file.
- The config file is JSON, because `serde_json` is already in the tree
  and no TOML or YAML crate is (see [ADR 0008](0008-detection-policy-configuration.md)).
- The file is at `$TIDEGARD_CONFIG`, or by default at
  `~/.config/tidegard/cli.json` (`%APPDATA%\tidegard\cli.json`
  on Windows).
- `--profile` picks a profile in the file.
- The endpoint and the CA bundle may also come from the environment
  (`TIDEGARD_API_URL`, `TIDEGARD_API_CA_FILE`).
- The environment overrides the file.

**Incident numbers are resolved through the API.** `GET /api/v1/incidents`
gains an exact `incident_number` filter, served by the existing unique
index on `(tenant_id, incident_number)`. A command given `WNM-2026-000123`
lists by number, takes the one incident's id, and continues. The lookup
is scoped to the caller's tenant like every other read.

**Retries reuse the idempotency key.** A mutating command generates one
`Idempotency-Key` per logical command, from UUIDv7, and sends the same key
on every retry. Retries happen only on connection errors and `5xx`
responses, up to three attempts with backoff, and never on a `4xx`. A
`409` is printed with the current version and state, and the command
exits `4`. The CLI does not re-read and re-issue; the plan explains why.

## Consequences

- `apps/cli` becomes the workspace member `tidegard-cli`, with the
  binary `tidegardctl`.
- No licence-matrix rows and no NOTICE entries are added.
- Using a public CA from Windows or macOS needs an exported PEM bundle
  until FU-57 lands.
- The parser is ours to maintain. Its tests are the contract: every verb,
  every flag, and every refusal.
