# Capacity Planning

Status: The flow-rate target **was measured on 2026-10-13** (Phase 9B)
and met: see [Flow pipeline, measured](#flow-pipeline-measured). The
incident database **was benchmarked on 2026-10-05** (Phase 5F); see
[Incident persistence, measured](#incident-persistence-measured).

## Performance Target

> Sustain at least 100,000 normalized flow records per second on the
> documented test machine, without packet generation over public
> networks.

Phase 3 set this target; Phase 9B measured it, with pass criteria
written before the first run
([ADR 0054](../architecture/decisions/0054-phase9b-load-and-soak.md)).

## Flow pipeline, measured

Two runs on GitHub's `ubuntu-latest` runner (BQ-3): AMD EPYC 7763,
4 cores, 15.6 GiB, image `ubuntu24 20261004.327.1`, kernel
6.17.0-1022-azure. Run
[38295046486](https://github.com/LogiXhare/wetechi-netmon/actions/runs/38295046486),
repeated from
[38293786205](https://github.com/LogiXhare/wetechi-netmon/actions/runs/38293786205)
with the same results. Each step lasted 60 seconds.

| Records/s | Sent | Parsed | Loss | Classified incoming | Hosts tracked | Peak RSS | CPU (cores) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 25,000 | 1,499,952 | 1,499,952 | 0% | 1,499,952 | 1,050 | 10 MiB | 0.06 |
| 50,000 | 2,999,860 | 2,999,860 | 0% | 2,999,860 | 1,050 | 11 MiB | 0.12 |
| **100,000** | 5,999,749 | 5,999,749 | **0%** | 5,999,749 | 1,050 | **11 MiB** | **0.24** |
| 150,000 | 8,999,733 | 8,999,733 | 0% | 8,999,733 | 1,050 | 12 MiB | 0.33 |
| 200,000 | 11,999,452 | 11,999,452 | 0% | 11,999,452 | 1,050 | 13 MiB | 0.41 |

The 100,000 step meets every ADR 0054 criterion: no loss (at most 0.1%
allowed), aggregation latency p99 in the first histogram bucket (at most
5 ms; 1 s allowed), 11 MiB peak resident memory (1 GiB allowed), no
error and no restart. 200,000, the highest step, is not a ceiling: the
collector used under half a core there.

What the run was, so it is not read as more:

- **The whole collector**: decoding, classification, aggregation, the
  detector evaluating one policy on every host, the incident inbox and
  ClickHouse export (about 4,200 rows a minute), with PostgreSQL and
  ClickHouse as local service containers.
- **One exporter, 40 records to a datagram, 1,000 local hosts and 50
  remote ones, IPv4 only**, from `flow-replay --rate` on the same
  runner. Real exporters send fewer records to a datagram, from many
  sources, over more hosts; those cost more per record. No threshold
  was crossed, so no incident was created during the run.
- **Loss** is `1 - parsed / sent`, so it includes anything the kernel
  dropped before the collector read it.
- **A floor, not a promise** for other hardware. Measure your own with
  `scripts/load_test.py`, as the
  [benchmark workflow](https://github.com/LogiXhare/wetechi-netmon/blob/main/.github/workflows/benchmark.yml)
  does.

## API latency, measured

Run [38298540619](https://github.com/LogiXhare/wetechi-netmon/actions/runs/38298540619)
on the same runner type, 2026-10-13 (ADR 0054, 9B-2). The database held
10,000 incidents, made by the pipeline itself: a flood to 10,000 hosts
through the collector, the inbox and the incident manager. Sixteen
clients, each a different actor, called the API for 60 seconds, each
just under its read quota of 120 a minute.

| Endpoint | Requests | Errors | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| Incident list (100 a page) | 583 | 0 | 5.7 ms | 11.9 ms | 23.4 ms |
| Incident detail | 588 | 0 | 11.6 ms | 23.9 ms | 107.1 ms |
| Mitigation list | 589 | 0 | 4.2 ms | 8.2 ms | 20.4 ms |

Every p99 is under ADR 0054's 250 ms, with no error response. The
request rate is what the quota allows 16 actors, about 32 a second, not
the API's ceiling; PostgreSQL ran beside the API on the same machine.

## Soak, measured

Run [38298282358](https://github.com/LogiXhare/wetechi-netmon/actions/runs/38298282358)
on the same runner type, 2026-10-12 to 13 (ADR 0054, 9B-3): the
collector, with detection, ClickHouse export and the incident manager,
took 50,000 records a second for five hours.

| Measure | Result | ADR 0054 limit |
|---|---:|---:|
| Records sent / parsed | 899,999,914 / 899,999,914 | — |
| Loss | 0.000% | ≤ 0.1% |
| Deepest queue | 57 of 10,000 | below capacity |
| Mean RSS, hour 1 → hour 5 | 11.16 → 11.55 MiB (+3.5%) | ≤ +10% |
| Peak RSS | 11.6 MiB | — |
| Error lines in the log, restarts | 0, 0 | 0 |

| Hour | 1 | 2 | 3 | 4 | 5 |
|---|---:|---:|---:|---:|---:|
| Mean RSS (MiB) | 11.16 | 11.38 | 11.51 | 11.55 | 11.55 |

Memory rose by 0.4 MiB over the first three hours and then stayed flat:
caches filling, not a leak. One shape of traffic again (one exporter,
1,000 hosts), and five hours, not the weeks a production collector runs.

## Memory Sizing (Aggregator)

Each aggregation dimension's worst-case memory is bounded by
`max_entries × (key size + TrafficCounters size)`. `TrafficCounters` is
12 × `u64` = 96 bytes. Approximate per-entry overhead (key + `HashMap`/
tracking overhead) varies by dimension:

| Dimension | Key | Approx. bytes/entry | Default `max_entries` | Approx. worst case |
|---|---|---|---|---|
| Hosts (v4+v6 combined) | `IpAddr` (up to 17 bytes) + counters | ~150 | 100,000 | ~15 MB |
| Networks (all prefix dimensions) | `(IpAddr, u8)` + counters | ~160 | 50,000 | ~8 MB |
| Hostgroups | `String` + counters | ~180 (varies with name length) | 1,000 | ~0.2 MB |
| ASNs | `u32` + counters | ~140 | 10,000 | ~1.4 MB |
| Exporters | `IpAddr` + counters | ~150 | 1,000 (default, not yet env-configurable) | ~0.15 MB |

These are architectural estimates from struct sizes, not measured
allocations — a real memory-under-load measurement is part of the Phase
9 benchmark, not asserted here as fact.

## Queue Memory

`WETECHINETMON_COLLECTOR_QUEUE_CAPACITY` (default 10,000) bounds the
in-process channel between UDP receive and classify/aggregate. Each
queued item is a raw datagram (`Vec<u8>`, up to `MAX_DATAGRAM_SIZE` =
65,535 bytes) plus a `SocketAddr`. Worst case: 10,000 × ~65KB ≈ 640MB if
every datagram were maximum-sized and the queue were completely full —
in practice, real IPFIX datagrams are far smaller (well under the 1500
byte path MTU), so actual queue memory under backpressure is expected to
be much lower. Not measured; documented as an upper bound from the
configuration, not an observed value.

## ClickHouse Export Data-Loss Trade-off

Per [ADR 0005](../architecture/decisions/0005-clickhouse-batching-and-retry.md):
under prolonged ClickHouse unavailability, this project **loses data by
design** rather than growing memory without bound. Specifically:

- The retry queue holds at most `RetryConfig::default().max_pending_batches`
  (100) batches. Once full, the **oldest** pending batch is dropped to
  make room for a new failure — not the newest.
- Each batch is retried at most `max_attempts` (5) times with exponential
  backoff (1s → 2s → 4s → 8s → 16s, capped at 60s) before being
  permanently dropped.
- At default settings (10,000 rows or 5s per batch, 100 pending batches),
  roughly 8–9 minutes of accumulated failed writes can be held before the
  oldest starts being dropped — a rough arithmetic estimate from the
  configured limits, not a measured outage-tolerance figure.

**Operator guidance:** if ClickHouse outages longer than this are
expected in your environment, either increase `RetryConfig`'s
`max_pending_batches` (accepting higher worst-case memory use during an
outage) or treat ClickHouse analytics data as best-effort and rely on
Prometheus metrics (which are not subject to this trade-off) for
operational alerting during an outage.

## Incident persistence, measured

Measured 2026-10-05 by the Benchmark workflow,
[run 37316065893](https://github.com/LogiXhare/wetechi-netmon/actions/runs/37316065893),
at commit `0f0dd71`. The harness is
`crates/incident-postgres/tests/benchmark.rs`. Anyone can rerun it from
the Actions tab.

**Machine.** A GitHub-hosted `ubuntu-latest` runner:

- AMD EPYC 9V74, 4 vCPUs;
- 15 GiB of memory;
- Linux 6.17 (Azure).

**Database.** PostgreSQL 17.11 (`postgres:17-alpine`) on the same host:

- default settings;
- data on the runner's disk, so every commit pays for a real fsync;
- client and server talk over loopback TCP.

**Method.** The service is wired as the API wires it, with UUIDv7 ids and
the system clock. Each operation is called 300 times in sequence on one
connection. Latency is the whole call, measured at the client, including
every round trip the service makes.

### Latency at 10,000 incidents of history

| Operation | p50 ms | p95 ms | p99 ms | max ms |
|---|---:|---:|---:|---:|
| Create an incident (opening event) | 11.39 | 12.25 | 14.40 | 17.18 |
| Link an update to an open incident | 8.84 | 9.39 | 10.91 | 16.91 |
| Refuse a duplicate event | 1.06 | 1.12 | 1.16 | 1.17 |
| Acknowledge (versioned, with an idempotency key) | 9.23 | 10.77 | 16.59 | 26.73 |
| Replay an idempotent request | 5.07 | 5.52 | 5.97 | 6.10 |
| Add a note | 8.99 | 10.47 | 13.07 | 22.68 |
| List the newest 50 incidents | 0.88 | 0.93 | 1.09 | 2.02 |
| List 50 acknowledged incidents | 1.44 | 1.53 | 2.18 | 2.85 |
| Read an incident's timeline | 1.15 | 1.27 | 1.42 | 1.70 |
| Claim and publish an outbox batch of up to 100 | 4.19 | 73.45 | 78.97 | 158.33 |

At 1,000 incidents of history, every p50 was lower than these, by up to
about 20%. The outbox figure is the exception (see below). The full tables for both sizes are in the run's job
summary.

### Concurrent incident creation in one tenant

| Writers | Incidents | Seconds | Incidents/s |
|---:|---:|---:|---:|
| 1 | 200 | 2.1 | 95 |
| 4 | 800 | 7.0 | 114 |
| 8 | 1,600 | 14.9 | 108 |

### What the numbers say

- **A write is about 9–11 ms, and a read about 1 ms.** Each write is one
  transaction holding several statements: the incident, the timeline, the
  audit trail and the outbox (ADR 0034). It ends in one fsync.
- **History matters little at this size.** Growing from 1,000 to 10,000
  incidents slowed writes by about 15–20%, and reads by at most a few
  tenths of a millisecond. The list
  and timeline queries use their indexes.
- **New incidents in one tenant top out near 100–115 per second, whatever
  the number of writers.** Each new incident takes the next number from
  that tenant's allocator row, under a row lock. The design wants this:
  numbers are gapless and per tenant
  ([ADR 0013](../architecture/decisions/0013-incident-identity.md)).
  Updates to existing incidents do not take that lock. A real attack wave
  opens incidents in the tens, not thousands per second, so the ceiling
  leaves wide headroom.
- **The outbox figure is bimodal.** A claim that finds a full batch
  publishes 100 rows, one acknowledgement each, which takes about 70 ms.
  A claim that finds nothing takes about 1 ms. The p50 is mostly the
  second case. No consumer exists in Phase 5 (FU-62).
- **Pool sizing.** One tenant gains nothing past about four concurrent
  writers. The default pool of 16 per process is therefore enough for a
  single node. Raise it only for many busy tenants, and only if
  `max_connections` has room.

### How far to trust them

- **Shared runners vary.** An earlier run of the same code on another
  runner ([run 37314862055](https://github.com/LogiXhare/wetechi-netmon/actions/runs/37314862055))
  was 30–40% faster on writes: about 5–7 ms at p50, with 149–186
  incidents/s. Read the numbers as an order of magnitude and as a
  baseline for regressions, not as a guarantee.
- **They are not a production figure.** A database on another host adds
  the network round trip to every statement. A tuned server, faster
  storage or `synchronous_commit` settings move the write numbers in
  either direction.
- The API's own HTTP, authentication and JSON costs are not included.

## PostgreSQL planning inputs (Phase 5B)

Added 2026-08-24 during Phase 5B PostgreSQL-persistence planning. Every
figure here is a **planning input**, not a benchmark result — the
performance-test plan in
[phase5b-postgresql-persistence-plan.md](../architecture/phase5b-postgresql-persistence-plan.md)
defines what will actually be measured at Milestone 5B-5.

- **Row-count growth is unbounded by design** for `incidents` (retained
  indefinitely while open, 24 months after close),
  `incident_detection_events` (one row per linked event), and
  `incident_timeline`/`incident_audit` (append-only and never truncated;
  an active incident nearing `TIMELINE_ENTRY_LIMIT` raises the
  `timeline_pressure` alert in the
  [runbook](incident-runbook.md) instead). Real growth depends entirely on
  attack volume and tenant count, neither of which this planning pass
  has a production figure for.
- **Connection-pool sizing** (`max_size`, `create_timeout`,
  `wait_timeout` on `deadpool-postgres`,
  [ADR 0022](../architecture/decisions/0022-phase5b-connection-pool.md))
  has **no default asserted here** — sizing must be informed by the
  Milestone 5B-5 performance tests, not guessed at in planning.
- **Outbox lease duration**
  ([ADR 0033](../architecture/decisions/0033-phase5b-transactional-outbox-and-dead-letter.md))
  is similarly deferred to implementation time, informed by measured
  consumer processing latency once a consumer exists.
- **Index growth:** three target-specific partial unique indexes
  (`incidents_active_host`, `incidents_active_network`,
  `incidents_active_hostgroup`) are bounded by the *active* incident
  count, not the historical total — partial indexes only index rows
  matching their predicate, so this stays small relative to the
  full-table row count regardless of history depth.
- **RPO/RTO** technical design targets (15 minutes / 4 hours,
  [phase5b-postgresql-persistence-plan.md](../architecture/phase5b-postgresql-persistence-plan.md))
  inform backup frequency and restore-procedure scope, not a capacity
  figure directly.

## What This Document Does Not Claim

- The flow pipeline **is** measured, above, for one shape of traffic.
  Many exporters, small datagrams, IPv6 and high host cardinality are
  not yet.
- API latency **is** measured, above, at the request rate the quotas
  allow.
- The soak **is** measured, above, for five hours at half the target
  rate. Runs of days or weeks are not.
- PostgreSQL latency and throughput for the incident database **are**
  measured, above. Index growth beyond 10,000 incidents is not.
