# Incident Management Runbook

Status: **Phase 5F**, 2026-10-05. Promoted from the planning draft, and
checked against the code. Every metric, table and setting named here
exists.

This runbook covers operating **the incident manager itself**. It is not
a guide to handling network incidents, which is what the product is for.

## The parts

| Part | Does | Where to look |
|---|---|---|
| Collector | Runs the detector. Writes each detection event to `detection_event_inbox` through a bounded queue that never blocks detection ([ADR 0035](../architecture/decisions/0035-phase5c-detection-event-inbox.md)) | Its log; the detector's metrics ([detection monitoring](detection-monitoring.md)) |
| `wetechinetmon-incident-manager` | The correlation worker (inbox to incidents), the incident timers, retention, and the depth gauges | `/metrics`, `/healthz` and `/readyz` (ready while correlation batches succeed) on `WETECHINETMON_INCIDENT_METRICS_BIND` (default `0.0.0.0:9091`); JSON logs |
| `wetechinetmon-api` | The REST API | `GET /healthz` (process up), `GET /readyz` (database answers); JSON logs with `X-Request-Id` |
| `wetechinetmonctl` | The CLI, which goes through the API only | — |
| NOC UI (`apps/web`) | The browser UI, served by the API from `WETECHINETMON_API_WEB_ROOT`; signs in with a token, then a session cookie | The browser console; the API's log |
| `wetechinetmon-notifier` | Consumes the outbox and delivers notifications ([ADR 0045](../architecture/decisions/0045-phase6e-notification-delivery.md)) | `/metrics`, `/healthz` and `/readyz` (ready while outbox batches succeed) on `WETECHINETMON_NOTIFY_METRICS_BIND` (default `127.0.0.1:9093`); JSON logs |
| Grafana | Your own; the dashboards in `grafana/dashboards` | The **WetechiNetMon** folder |
| PostgreSQL | All incident state | `pg_stat_activity`, its own log |

Configuration for each part is in its README:

- [incident manager](https://github.com/LogiXhare/wetechi-netmon/tree/main/crates/incident-manager)
- [API](https://github.com/LogiXhare/wetechi-netmon/tree/main/apps/api)
- [CLI](https://github.com/LogiXhare/wetechi-netmon/tree/main/apps/cli)
- [notifier](https://github.com/LogiXhare/wetechi-netmon/tree/main/crates/notification)
- [NOC UI](https://github.com/LogiXhare/wetechi-netmon/tree/main/apps/web)
- [Grafana provisioning](https://github.com/LogiXhare/wetechi-netmon/tree/main/grafana/provisioning)

## Health

All metrics are `wetechinetmon_incident_*`, from the incident manager.

| Metric | Healthy |
|---|---|
| `inbox_pending` | Low, and back near zero after each burst |
| `dead_letter_pending` | **Zero** |
| `inbox_events_total{result}` | `processed` tracks detection volume; `dead_lettered` stays flat |
| `inbox_batches_total{result="failed"}` | Flat |
| `clock_skew_total` | Flat (see [Clock skew](#clock-skew)) |
| `maintenance_incident_failures_total` | Flat |
| `job_runs_total{job, result="failed"}` | Flat for `stats`, `maintenance` and `retention` |
| `outbox_pending` | **Rises in Phase 5, and that is expected** (see [Outbox](#outbox)) |
| `timeline_pressure` | Far below 50,000, the per-incident timeline limit |

Suggested Prometheus alerts:

```yaml
groups:
  - name: wetechinetmon-incident
    rules:
      - alert: IncidentDeadLetter
        expr: wetechinetmon_incident_dead_letter_pending > 0
        for: 1m
      - alert: IncidentInboxBacklog
        expr: wetechinetmon_incident_inbox_pending > 1000
        for: 10m
      - alert: IncidentWorkerFailing
        expr: increase(wetechinetmon_incident_inbox_batches_total{result="failed"}[10m]) > 0
      - alert: IncidentJobFailing
        expr: increase(wetechinetmon_incident_job_runs_total{result="failed"}[30m]) > 0
      - alert: IncidentManagerDown
        expr: up{job="wetechinetmon-incident-manager"} == 0
        for: 2m
      - alert: NotificationsFailing
        expr: increase(wetechinetmon_notifier_notifications_total{result="failed"}[15m]) > 0
      - alert: NotificationsRefused
        expr: increase(wetechinetmon_notifier_notifications_total{result="refused"}[15m]) > 0
      - alert: NotifierDown
        expr: up{job="wetechinetmon-notifier"} == 0
        for: 2m
      - alert: IncidentTimelinePressure
        expr: wetechinetmon_incident_timeline_pressure > 40000
        for: 15m
```

The timeline is never truncated, so nothing stops an incident at 50,000
entries. One that gets near it is almost always a detection flapping
against its threshold: find the incident with the longest timeline,
and fix the policy's hysteresis or suppress the incident while you do.

```sql
SELECT i.incident_number, count(*) AS entries
FROM incidents i JOIN incident_timeline t USING (incident_id)
WHERE i.state NOT IN ('resolved', 'closed')
GROUP BY i.incident_number ORDER BY entries DESC LIMIT 5;
```

The 1,000-event backlog threshold is a starting point. Tune it to your
detection volume.

## Inbox backlog

**Alert:** `inbox_pending > 1000` for 10 minutes.

Detection events are arriving faster than the worker turns them into
incidents, or the worker has stopped. Detection itself is unaffected:
the events are safe in PostgreSQL. But incidents now lag reality, and an
attack is exactly when that hurts.

1. Is the incident manager running? Check its supervisor and its log.
2. Is it failing? Look at `inbox_batches_total{result="failed"}` and the
   log for database errors.
3. Is PostgreSQL slow? Check `pg_stat_activity` for long transactions and
   lock waits.
4. Is one detection flooding? Group the pending rows:

   ```sql
   SELECT tenant_id, detection_id, count(*)
   FROM detection_event_inbox WHERE status IN ('pending', 'retrying')
   GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10;
   ```

5. Is it draining at all? Compare the depth over five minutes.

**Do not delete pending inbox rows** to clear the alert. They are
detection events, and deleting them loses incidents silently.

## Dead letters

**Alert:** any unreviewed row.

A dead-lettered inbox event is a detection that could not become an
incident. Each one may be a missed attack, which is why the threshold is
zero rather than a number.

1. Read the rows:

   ```sql
   SELECT dead_letter_id, tenant_id, failure_reason, attempts, first_seen_at
   FROM incident_dead_letter WHERE reviewed_at IS NULL ORDER BY first_seen_at;
   SELECT inbox_id, tenant_id, detection_id, attempts, last_error
   FROM detection_event_inbox WHERE status = 'dead_letter';
   ```

2. Classify each one:
   - malformed input;
   - an unsupported schema version;
   - a bug;
   - a transient failure that outlasted the retry cap.
3. **A bug:** fix it, then replay. Replay is safe, because a duplicate
   cannot create a second incident:

   ```sql
   UPDATE detection_event_inbox
   SET status = 'pending', attempts = 0, available_at = now(), last_error = NULL
   WHERE inbox_id = <id> AND status = 'dead_letter';
   ```

4. **Malformed input from the detector:** this is a Phase 4 bug. Report it
   as one.
5. **An unsupported schema version:** the incident manager is older than
   the collector. Upgrade it. Do not loosen the schema check.
6. Record the review, which also lets retention purge the row after 90
   days:

   ```sql
   UPDATE incident_dead_letter
   SET reviewed_at = now(), reviewed_by_type = 'operator', reviewed_by_id = '<you>'
   WHERE dead_letter_id = <id>;
   ```

**Never bulk-delete unreviewed dead letters.** Retention never deletes
them either.

### Quarantined events

Some events are quarantined, which is not the same as dead-lettered:

- events with a newer schema version;
- events claiming an executed mitigation, which nothing in Phase 5 can
  perform;
- an `Ended` event with nothing to attach to.

A quarantined event is processed, with the outcome `quarantined`, and
creates no incident. Find recent ones with:

```sql
SELECT inbox_id, tenant_id, detection_id, processed_at
FROM detection_event_inbox WHERE outcome = 'quarantined'
ORDER BY processed_at DESC LIMIT 50;
```

## Outbox

Every incident change writes an `incident_outbox` row. The notifier is
its consumer: it marks each row published once every channel the routes
name has it, or retrying while one fails. Without a notifier running,
`outbox_pending` only rises, and retention removes published rows only.
With one running, a pending count that keeps rising means the notifier is
down or stuck: check `NotifierDown` and its log.

## Notifications

Each attempt is on the incident's timeline as `notification_result`,
with the channel's name and `delivered`, `failed` or `refused`.

| You see | Meaning | Do |
|---|---|---|
| `failed` | A timeout, a connection failure, `429` or `5xx`. Retried through the outbox backoff, to that channel only | Check the service's status. At the retry limit the message dead-letters: see [Dead letters](#dead-letters) |
| `refused` | A `4xx`, or the destination failed the SSRF checks | The log says which. A webhook URL that was revoked, a host not on `allowed_hosts`, or a host that resolves to a private address |
| `duplicate` (metric only) | The same event for the same incident went to that channel in the dedup window | Nothing |
| `rate_limited` (metric only) | The channel's per-minute limit was reached; the message was dropped | A storm. Look at what is flapping. Raise the limit only if the channel can take it |

**Rotating a secret.** Write the new Slack or Teams URL, Telegram token,
webhook secret or SMTP password to its file, then restart the notifier.
Nothing else holds a copy.

**A receiver asks whether a webhook is genuine.** It should compute
`sha256=` and the HMAC-SHA-256 of `"{X-WNM-Timestamp}.{body}"` with the
shared secret, compare it to `X-WNM-Signature` in constant time, and
refuse a timestamp more than five minutes old.

## Sessions and the UI

- **Sign someone out everywhere:** revoke their token
  (`wetechinetmon-api token revoke --token-id ...`). Every session made
  from it ends at its next request.
- **Sign everyone out:** `DELETE FROM api_sessions;`. Tokens are
  untouched; people sign in again.
- A session ends after 30 minutes idle or 12 hours, whichever is first.
- `403 api.csrf_rejected` in the API log, or `session.csrf_rejected` in
  `incident_audit`, means a cookie request without the page's CSRF
  value. From the UI that is a bug; from elsewhere, a forgery attempt.
- A blank page with Content-Security-Policy errors in the browser console
  means the build holds inline code or the UI is served from another
  origin. Serve `apps/web/dist` through the API, as built.

## Traffic in the UI

Only the tenant named by `WETECHINETMON_API_TRAFFIC_TENANT` sees traffic
([ADR 0042](../architecture/decisions/0042-phase6b-traffic-read-api.md)).
Anyone else gets `404` and an overview with incidents alone. `503` from
`/api/v1/traffic/*` means ClickHouse is unreachable; incidents keep
working.

## PostgreSQL unavailable

The system fails closed:

- the API answers `503 api.unavailable`, and `/readyz` fails;
- the worker stops claiming;
- no partial state is written.

1. Restore PostgreSQL.
2. The worker resumes from `pending` on its own. No manual replay is
   needed.
3. Expect a burst of backlog, and watch it drain.
4. While the database was down, the collector's queue held events in
   memory. If the queue filled, the detector counted the events it
   refused ([ADR 0035](../architecture/decisions/0035-phase5c-detection-event-inbox.md)).
   An attack still in progress shows up again with its next update.

## Clock skew

`clock_skew_total` counts events refused because the database's
transaction time ran backward relative to the incident
([ADR 0031](../architecture/decisions/0031-phase5b-durable-time.md)). An
occasional increment after a failover is expected. A steady rise means
the database host's clock is being stepped. Fix NTP on that host. Do not
work around it in the application.

## Timers

The incident timers do three things:

- move silent incidents to `Recovering`;
- confirm recovery;
- close resolved incidents once the closure policy allows it.

**Critical incidents never close automatically.**

`maintenance_transitions_total{transition}` shows what the timers did.
`maintenance_incident_failures_total` counts incidents a timer step could
not advance. That incident's error is in the log, and the timers retry it
on their next run.

## Backup and restore

See [Backup and Restore](backup-and-restore.md). CI tests the procedure on
every pull request. Take a backup before every upgrade.

## Upgrades

1. Back up PostgreSQL, and check that the archive reads back
   (`pg_restore --list`).
2. Upgrade the incident manager first. On startup it applies new
   migrations under an advisory lock, so two instances never migrate at
   once. Migrations are **forward-only**
   ([ADR 0024](../architecture/decisions/0024-phase5b-migration-framework.md)).
   To roll back, either restore the backup or apply a corrective
   migration.
3. Upgrade the API.
4. Upgrade the collector last. A newer event schema must never reach an
   older incident manager. If it does, the events are quarantined, not
   lost, and can be replayed after the upgrade.

If startup hangs at the migration step, a previous instance may have died
holding the lock. Confirm no other instance is migrating before
intervening. **Never** mark a migration as applied by hand.

## Connection pool

Each process has its own pool:

- `WETECHINETMON_INCIDENT_POOL_MAX_SIZE` for the incident manager;
- `WETECHINETMON_API_POOL_MAX_SIZE` for the API.

Both default to 16. An exhausted pool returns `503` within a bounded
time, never an indefinite hang
([ADR 0022](../architecture/decisions/0022-phase5b-connection-pool.md)).
Before raising the size, check that PostgreSQL's `max_connections` can
hold the total across all processes. A larger pool against an undersized
database only moves the bottleneck.

## What operators cannot do here

- **Mitigate.** Phase 5 has no such capability, and a test proves that
  no crate in the workspace could do it.
- **Notify anywhere not configured.** The notifier sends only to the
  channels and hosts its file allows.
- **Edit history.** The timeline and the audit trail are append-only.
- **Delete one tenant's audit trail.** There is no such operation.
