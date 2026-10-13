# 0036. Phase 5C Incident Manager Process

Status: **Accepted**
Date: 2026-10-05
Deciders: Repository owner

## Context

Milestone 5C built the parts of event ingestion as library code in
`crates/incident-postgres`:

- the inbox and its worker loop ([ADR 0035](0035-phase5c-detection-event-inbox.md)),
- the detector-side producer,
- the incident timers (`run_maintenance`),
- retention, and the inbox and outbox depth queries.

Nothing ran them. The plan's remaining 5C work was "wiring the producer,
worker and timers into a running binary with a schedule, metrics,
logging, and the end-to-end test". Which process runs which part had not
been decided.

The constraints:

- **The producer must sit with the detector.** Its sink is called on the
  detection tick, which runs in the collector.
- **The worker and the timers need no flow data.** They need PostgreSQL
  and a platform authority ([ADR 0032](0032-phase5b-tenant-isolation-and-rls-readiness.md)).
- **The collector's job is telemetry.** It already keeps running when
  ClickHouse or a policy file is unavailable. It should not also stop
  ingesting flows because an incident database migration failed.
- `crates/incident-manager` has been reserved since Phase 1 for "incident
  state machine and lifecycle".

## Decision

**Two processes.**

| Process | Runs |
|---|---|
| `tidegard-collector` | the producer: the inbox sink on the detection tick, and its drain task |
| `tidegard-incident-manager` (new) | the correlation worker, the incident timers, retention, and the depth gauges |

The incident manager is `crates/incident-manager`:

- **Startup.** It reads environment variables, builds the pool, and
  applies migrations under a session advisory lock (ADR 0024's
  concurrency requirement). Then it starts work. A startup failure exits
  non-zero for the supervisor to restart. After startup, a database error
  is logged, counted and retried, and never stops the process.
- **TLS** ([ADR 0023](0023-phase5b-postgresql-tls.md)). With a CA file,
  connections use the verifying rustls connector. Off loopback,
  `sslmode=require` is required. Without a CA file, the connection string
  must reach only the local host. Startup refuses anything else and logs
  which mode it chose. A remote database never falls back to plaintext
  silently. The connection string is never logged, and neither is a parse
  error that could quote it.
- **Schedule.** The worker runs continuously. Separate intervals run the
  depth gauges (15 s), the timers (60 s) and retention (1 h). Each
  interval fires once at startup, so a restart catches up on overdue
  timers at once. A slow run delays the next one rather than bunching
  missed runs together. Every interval can be configured.
- **Shutdown** ([ADR 0012](0012-incident-event-ingestion.md)). On Ctrl+C
  or SIGTERM, the worker finishes the batch it is processing and claims
  no more. A scheduled job that is already running finishes, and no new
  one starts.
- **Authority.** One `PlatformAuthority` for the process: actor
  `Platform { id: "incident-manager" }`, holding only
  `PlatformIncidentAdmin`. The worker and the timers still act on each
  incident as that tenant's `system:correlator`.
- **Metrics** follow [incident-observability.md](../incident-observability.md).
  The names are `tidegard_incident_*`. Every label value is a
  constant in `src/metrics.rs`, listed in `LABEL_ALLOWLIST`, and a test
  fails on any label outside the list. No label carries a tenant, an
  incident, a scope or error text. The endpoint is the collector's
  hand-rolled `/metrics` server, moved to `tidegard-common` behind a
  `metrics-server` feature so both binaries share it.
- **Nothing is published.** The outbox is only filled. Notification
  (Phase 6) and mitigation (Phase 7) consume it later.

## Alternatives considered

- **Everything in the collector.** One binary to deploy, but a database
  outage or a failed migration would compete with flow ingestion. The
  worker could also not be scaled, or restarted, apart from the UDP
  listener.
- **One process per job** (worker, timers, retention). Three deployments
  for work that shares one pool and one authority, with nothing gained at
  this scale. The timers and the worker can still be split later: the
  library calls take their pool and authority as arguments.
- **Migrations only from a separate tool.** Safer where the application
  role must not hold DDL rights. That remains possible: set
  `TIDEGARD_INCIDENT_MIGRATE=false` and run them separately. It is
  not the default, because the reference deployment is one host.

## Consequences

**Easier.** Detection events now become incidents, and incidents move
through their timers, in a running system. The inbox, outbox and
dead-letter backlogs can be scraped and alerted on.

**Harder.** One more process to install and supervise. The collector
side, attaching the inbox sink to the detection stage, is a separate
change: the producer serves one tenant, and the collector's prefixes name
their tenants.

## Follow-ups

- [x] Attach the inbox producer to the collector's detection stage.
- [x] The end-to-end test from synthetic IPFIX bytes to an incident
      (`crates/collector/tests/incident_end_to_end.rs`).
- [ ] `tidegard_incident_events_ingested_total{result}` by ingest
      outcome (FU-52).
- [ ] Per-policy staleness timeout for the timers (FU-51).
