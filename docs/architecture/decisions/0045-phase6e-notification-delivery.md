# 0045. Phase 6E Notification Delivery

Status: **Accepted**
Date: 2026-10-12
Deciders: Repository owner (BQ-12, 2026-10-11); the details under the
delegation of 2026-10-05 to industry practice

## Context

Every incident change writes an outbox row, and until now nothing read
them (FU-62). Phase 6E delivers notifications by webhook, Slack,
Microsoft Teams, Telegram and email
([Phase 6 plan](../phase6-dashboards-ui-notifications-plan.md)). This is
the first code in WetechiNetMon that sends anything to another system, so
the plan names its risks: server-side request forgery through a webhook
URL (R23), a storm of messages during a large attack (R24), and leaked
channel secrets.

## Decision

### A separate process

`wetechinetmon-notifier` (`crates/notification`) is the outbox's first
consumer. It claims messages with the existing lease-based consumer
(ADR 0033), delivers them, and marks each one published or failed. The
detector and the incident domain gain no network code. The dependency
closure test keeps proving it.

Phase 7 will need the same events for mitigation. The outbox has one
status per row, so a second consumer then needs a per-consumer cursor.
That is Phase 7's change, recorded here so it is not a surprise.

### What is delivered, and to whom

A JSON configuration file (`WETECHINETMON_NOTIFY_CONFIG`) names the
channels and the routes. A route names a tenant, event types, a minimum
severity and channels. A message no route matches is marked published
and sent nowhere.

Each message carries the incident's number, title, severity, state,
target, direction and a link to it in the UI, and always says
**mitigation: none**. Untrusted text such as titles has its control
characters removed and is escaped for each channel's markup: Slack's
`&`, `<` and `>`, and Teams' Markdown. Telegram gets plain text with no
parse mode.

### Server-side request forgery (R23)

- **Every destination host must be on the configuration's allowlist**
  (`api.telegram.org`, `hooks.slack.com`, `*.webhook.office.com`, and
  so on).
- **The host is resolved once, and every address is checked:** loopback,
  private, link-local, carrier-grade NAT, unique-local, multicast and
  unspecified addresses are refused, unless the channel says
  `allow_private`. The connection then goes to the checked address, so a
  second DNS answer cannot redirect it (DNS rebinding).
- `https` is required unless `allow_private` is set. Certificates are
  verified against a configured CA bundle. Redirects are never followed.
- The response body is capped and never shown.

### Storms (R24)

- **Deduplication:** a channel gets the same event for the same incident
  at most once in a window (5 minutes by default).
- **A per-channel rate limit** (30 a minute by default). Over it, a
  message is dropped and counted, never queued without bound.
- Both are in memory. A restart forgets them, and may resend once.

### Delivery, retries and the record

- A channel that answers `2xx` has delivered. A `5xx`, a `429`, a timeout
  or a connection failure is transient: the whole message is retried
  through the outbox's own backoff and dead-letters at its limit.
  Channels that already succeeded for that message are not sent again
  while the process runs. A `4xx` is permanent: it is recorded and not
  retried.
- **Every delivery attempt is recorded on the incident's timeline** as
  `notification_result`: the channel's name, the event, and the outcome.
  It changes no field and does not bump the version, so it never causes
  an operator a version conflict. The notifier records with a dedicated
  permission, `incident.notification.record`, which no human role holds.

### Secrets

Slack and Teams webhook URLs, the Telegram bot token, webhook signing
secrets and SMTP passwords are read from files named in the
configuration. They are never logged, never put in a timeline entry,
and never returned by the API. The generic webhook signs each body with
HMAC-SHA-256 over the timestamp and the body (`X-WNM-Timestamp`,
`X-WNM-Signature`), so a receiver can refuse forgeries and replays.

### No new crates for HTTP

The HTTP channels use the hyper client and `tokio-rustls` already in the
tree (ADR 0040). HMAC is the RFC 2104 construction over `sha2`, tested
against RFC 4231's vectors.

### Email (6E-2): `lettre`

SMTP is a protocol whose mistakes are header injection and silent
downgrade, so it uses a maintained library rather than a hand-written
client: `lettre` 0.11.23 (MIT), with only `builder`, `smtp-transport`,
`tokio1-rustls` and `aws-lc-rs`. It adds seven crates, all permissive.

- The relay is vetted like every destination, and the connection goes to
  the checked address. TLS verifies the relay's own name against the
  configured CA bundle alone (`CertificateStore::None`). `webpki-roots`
  is compiled in only because `lettre` requires a root-store feature; it
  is never used.
- **STARTTLS is required by default** (`Tls::Required`), so a relay that
  cannot upgrade is refused rather than used in plain text. Implicit TLS
  on port 465 is the alternative. Plain SMTP needs `allow_private`.
- Headers are built and encoded by `lettre`: a title cannot add a header
  or a recipient, which a test checks.
- An SMTP 5xx is permanent; a 4xx or a connection failure is retried.

The dependency closure test changes with it. Routing and device-access
crates stay forbidden everywhere. Mail and chat crates are allowed only in
the notifier's own closure, and no other crate may depend on the
notifier.

## Consequences

- An operator configures routes and channels, and points the notifier at
  a CA bundle. Nothing is sent until a route matches.
- CI tests every channel against local mock servers on loopback, with
  `allow_private`. **Nothing leaves the runner.**
- The timeline shows who was told what, and whether it worked.

## Alternatives considered

- **Deliver from the incident manager.** It would put network delivery in
  the process that owns incident state, and a slow Slack would slow
  correlation.
- **A notification table instead of the timeline.** Operators already
  read the timeline, and the entry type was reserved there in V4.
- **Trust DNS at connect time.** A host can resolve to a public address
  when checked and a private one when used.
