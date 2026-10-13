# 0005. ClickHouse Batching and Retry Behavior

Status: Accepted
Date: 2026-08-20
Deciders: WeTechi Solutions (badshashorif)

## Context

FR-2 and master prompt §12 require ClickHouse as the primary analytics
store, written to from the Aggregator. Writing one row per aggregation
update would be both inefficient (ClickHouse is optimized for batched
inserts) and would couple the aggregation hot path directly to ClickHouse
write latency/availability. This ADR covers how writes are batched and
how transient ClickHouse unavailability is handled.

## Options Considered

### Option A — Bounded in-memory batch queue, size-or-time flush, bounded retry queue with backoff, drop-oldest-on-overflow

Aggregated rows accumulate in a bounded in-memory queue. A flush is
triggered when the queue reaches a configurable size **or** a configurable
time interval elapses, whichever comes first. On write failure, failed
batches move to a separate bounded retry queue with exponential backoff;
if the retry queue itself is full, the **oldest** pending batch is
dropped (and counted via a Prometheus metric), not the newest — analytics
data favors recency for operational dashboards, and an unbounded retry
queue would itself become a memory-growth risk (the same class of problem
FR-2.4 already required solving for in-memory aggregation — see
[ADR 0003](0003-in-memory-aggregation-structure.md)).

- Pros: bounded memory under sustained ClickHouse unavailability;
  predictable batch sizes tuned for ClickHouse's bulk-insert strengths;
  failure is observable (metrics), not silent.
- Cons: under prolonged ClickHouse downtime, older data is genuinely lost
  once the retry queue fills — this is a deliberate, documented trade-off
  (bounded memory over unbounded data retention), not an oversight.

### Option B — Unbounded retry queue / disk-backed write-ahead log

Never drop data on ClickHouse failure; spill to disk if needed.

- Pros: no data loss during outages.
- Cons: unbounded (or disk-bounded, which just moves the same problem)
  growth risk; a disk-backed WAL is a meaningfully larger engineering
  effort (crash recovery, disk-space management, corruption handling)
  than Phase 3's scope justifies. Worth revisiting for Phase 9 production
  hardening if operational experience shows data loss during ClickHouse
  outages is unacceptable — not decided against permanently, just
  deferred.

### Option C — Synchronous writes, no batching

Write each aggregation update directly and synchronously.

- Pros: simplest possible code, no queue to reason about.
- Cons: couples aggregation throughput to ClickHouse write latency;
  directly contradicts ClickHouse's own guidance to batch inserts; no
  resilience to transient ClickHouse unavailability at all. Rejected.

## Decision

**Option A.** Implemented in `crates/storage`: a bounded batch queue
(configurable max rows and max flush interval), a bounded retry queue
with exponential backoff, and drop-oldest-on-overflow for the retry queue
specifically — never for the primary batch queue, which instead applies
backpressure (the aggregator's channel send blocks/rejects) rather than
silently dropping fresh data.

## Consequences

- ClickHouse write failures are visible via Prometheus metrics
  (`tidegard_storage_clickhouse_write_failures_total`,
  `tidegard_storage_clickhouse_retry_queue_dropped_total`), not
  silent.
- Data loss is possible under prolonged ClickHouse outages by design —
  this must be called out in operator-facing documentation
  (docs/operations/capacity-planning.md), not left implicit.
- The batch writer's public API accepts already-aggregated rows (not raw
  flows), keeping ClickHouse-specific concerns out of
  `crates/aggregator`.
- No new third-party dependency beyond the ClickHouse client itself,
  which needs its own docs/dependency-license-matrix.md row before use.

## Follow-Up

- [ ] Revisit Option B (durable spillover) as part of Phase 9 production
      hardening if load/soak testing or real operational experience shows
      the current data-loss trade-off is unacceptable.
- [ ] Document the drop-oldest behavior prominently in
      docs/operations/capacity-planning.md — an operator sizing the retry
      queue needs to understand what they're trading off.
