# 0054. Phase 9B Load and Soak Tests

Status: **Accepted**
Date: 2026-10-13
Deciders: Repository owner (BQ-3, 2026-10-12); the details under the
delegation of 2026-10-05 to industry practice

## Context

NFR-1 asks for high flow-record rates without unbounded memory growth,
and BQ-3 set the target: 100,000 normalized flow records a second,
measured on GitHub's `ubuntu-latest` runner. No throughput figure has
ever been published, deliberately
([capacity planning](../../operations/capacity-planning.md)).
The Phase 9 acceptance criteria require the pass criteria to be written
down before the first measured run, so the numbers are judged against
them rather than the reverse. This ADR is that record. It is written
before any 9B measurement exists.

## Decision

### What is measured

The whole collector process: UDP receive, IPFIX decoding,
normalization, direction classification, aggregation, the detector, the
incident inbox and the ClickHouse export, all as a deployment runs them.
PostgreSQL and ClickHouse run beside it as service containers.

- **The load generator** is `tools/flow-replay` in a new rate mode: IPv4
  records, 40 to a datagram, spread over 1,000 local hosts and 50
  remote ones, at a fixed record rate held by a 10 ms pacing tick. It
  prints how many records it sent. Synthetic only, to a collector the
  job started on loopback.
- **Loss** is `1 - parsed / sent`, where `parsed` is the collector's
  `tidegard_collector_parsed_flow_records_total` after the run
  settles. It counts every record lost anywhere, the kernel's socket
  buffer included, which the collector cannot see.
- **Memory** is the collector's peak resident set (`VmHWM`) and its
  current one (`VmRSS`), read from `/proc`.
- **Latency** is the collector's own
  `tidegard_collector_aggregation_latency_seconds` histogram, as a
  p99.
- **The machine** is recorded with every run: the runner image, CPU
  model, core count and memory, from the runner itself. The generator
  shares that machine, so the figures are a floor for the collector.

### Pass criteria

**Load (9B-1).** Steps of 60 seconds at 25,000, 50,000, 100,000,
150,000 and 200,000 records a second, each reported. The test passes when
the **100,000 step** has:

| Measure | Pass |
|---|---|
| Loss | at most 0.1% |
| Aggregation latency p99 | at most 1 second |
| Peak resident memory | at most 1 GiB |
| Collector restarts or errors | none |

The steps above 100,000 find the ceiling; they are reported, never
failed.

**API latency (9B-2).** With 10,000 incidents in the database and 16
concurrent clients for 60 seconds: the incident list, an incident's
detail and the mitigation list each have a p99 of at most 250 ms and no
error responses. These become NFR-1's API budgets.

**Soak (9B-3).** Five hours at 50,000
records a second with the same stack. It passes when:

| Measure | Pass |
|---|---|
| Loss over the whole run | at most 0.1% |
| Resident memory | hour 5 at most 10% above hour 1 |
| Queue depth | never at its capacity |
| Collector restarts or errors | none |

The soak is five hours, not the six BQ-3 named, because a hosted job
may run six hours **including** checking out, building and starting
the stack. This was settled before any soak ran.

### When a target is missed

The report says so, with the numbers. A pass criterion is not changed
after a run to fit its result. If one turns out to be wrong for a reason
other than the result, the change is a new decision recorded here,
before the next run.

### Where it runs

`.github/workflows/benchmark.yml`, on demand and on pull requests that
change the load tooling, as the incident benchmark already does. The
soak runs on demand only. Results go to the job summary, and the
published figures in capacity planning link the run they came from.

## Consequences

- The first published throughput figures for Tidegard come from
  this, with their machine and run.
- A missed target is a finding for 9D's review, not a reason to delay
  the report.

## Alternatives considered

- **Counting loss inside the collector.** It cannot see what the kernel
  drops before `recv`. Comparing with the sender counts everything.
- **An external generator such as nfgen or softflowd.** Another
  dependency to pin and review, with no rate control beyond what
  `flow-replay` gains in a few dozen lines, and no record of what was
  sent.
- **A separate machine for the generator.** Free hosted runners cannot
  talk to each other, and a lab machine would not be reproducible by
  anyone else (BQ-3).
