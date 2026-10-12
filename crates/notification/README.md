# Notifier

`wetechinetmon-notifier` tells people about incidents by generic webhook,
Slack, Microsoft Teams and Telegram
([ADR 0045](../../docs/architecture/decisions/0045-phase6e-notification-delivery.md)).
It is the incident outbox's first consumer. Every attempt is recorded on
the incident's timeline as `notification_result`, and every message says
**mitigation: none**, because WetechiNetMon does not act on traffic.

**Status:** Phase 6E: webhook, Slack, Teams, Telegram and email.

## Running it

| Variable | Default | Meaning |
|---|---|---|
| `WETECHINETMON_NOTIFY_DATABASE_URL` | required | The incident database. Never logged. |
| `WETECHINETMON_NOTIFY_DATABASE_CA_FILE` | unset | Database TLS, as for the incident manager |
| `WETECHINETMON_NOTIFY_CONFIG` | required | The channels-and-routes file below |
| `WETECHINETMON_NOTIFY_CONSUMER_ID` | `notifier-1` | This process's outbox lease name; one per process |
| `WETECHINETMON_NOTIFY_METRICS_BIND` | `127.0.0.1:9093` | Prometheus metrics |

Run the incident manager first: it applies the migrations.

## The configuration file

Secrets are never in the file. It names the files that hold them: Slack
and Teams webhook URLs (the URL is the secret), the Telegram bot token,
and the webhook signing secret.

```json
{
  "channels": {
    "noc-slack": { "kind": "slack", "url_file": "/run/secrets/slack-url" },
    "noc-teams": { "kind": "teams", "url_file": "/run/secrets/teams-url" },
    "noc-telegram": {
      "kind": "telegram",
      "bot_token_file": "/run/secrets/telegram-token",
      "chat_id": "-1001234567890"
    },
    "noc-mail": {
      "kind": "email",
      "smtp_host": "smtp.example.net",
      "smtp_tls": "starttls",
      "username": "wnm-notifier",
      "password_file": "/run/secrets/smtp-password",
      "from": "WetechiNetMon <noc@example.net>",
      "to": ["oncall@example.net"]
    },
    "ticketing": {
      "kind": "webhook",
      "url": "https://tickets.example.net/hooks/wnm",
      "secret_file": "/run/secrets/ticketing-hmac"
    }
  },
  "routes": [
    {
      "tenant": "acme",
      "events": ["incident.opened", "incident.reopened", "incident.severity_changed"],
      "min_severity": "major",
      "channels": ["noc-slack", "noc-telegram"]
    },
    {
      "tenant": "acme",
      "events": ["incident.opened", "incident.resolved", "incident.closed"],
      "channels": ["ticketing"]
    }
  ],
  "allowed_hosts": ["hooks.slack.com", "*.webhook.office.com", "api.telegram.org", "tickets.example.net", "smtp.example.net"],
  "ca_file": "/etc/ssl/certs/ca-certificates.crt",
  "ui_base_url": "https://noc.example.net",
  "rate_limit_per_minute": 30,
  "dedup_seconds": 300
}
```

Events are the outbox's: `incident.opened`, `incident.reopened`,
`incident.acknowledged`, `incident.recovering`, `incident.resolved`,
`incident.closed`, `incident.severity_changed`, `incident.priority_changed`,
`incident.assignment_changed`, `incident.state_changed` and
`incident.suppression_changed`. A message no route matches is sent
nowhere.

## Safety

- **Destinations (R23):** the host must be on `allowed_hosts`; every
  address it resolves to must be public; the connection goes to the
  checked address; `https` with the configured CA bundle; no redirects.
  `"allow_private": true` on a channel permits plain HTTP and private
  addresses, for a receiver inside your own network.
- **Storms (R24):** one message per channel, incident and event in each
  `dedup_seconds` window, and at most `rate_limit_per_minute` per
  channel. Over the limit, messages are dropped and counted.
- **Retries:** a timeout, a connection failure, `429` or `5xx` retries
  the message through the outbox's backoff, to the failed channels only,
  and dead-letters at the limit. A `4xx` is recorded and not retried.
- **Escaping:** untrusted titles cannot ping `@channel` in Slack, format
  Markdown in Teams, use a parse mode in Telegram, or add a header or a
  recipient to an email.
- **Email:** STARTTLS is required by default (port 587); `"smtp_tls":
  "implicit"` is port 465. The relay's certificate is checked against
  `ca_file` only. `"smtp_tls": "none"` needs `allow_private`.
- **Signed webhooks:** `X-WNM-Timestamp` and
  `X-WNM-Signature: sha256=<hex HMAC-SHA-256 of "{timestamp}.{body}">`.
  Check the signature, and refuse a timestamp more than five minutes old.

## Metrics

`wetechinetmon_notifier_notifications_total{result}`: `delivered`,
`failed`, `refused`, `duplicate`, `rate_limited`.
`wetechinetmon_notifier_messages_total{result}`: `published`, `retrying`,
`dead_lettered`.
