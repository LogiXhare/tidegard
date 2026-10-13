# Phase 9D Security Review

Status: **In progress**, 2026-10-13. The supply chain checks, the
threat model's extension and the first findings are done; the fuzzing
report (FU-3) and the independent adversarial review of the release
candidate are still to come
([plan](../architecture/phase9-10-production-release-plan.md), 9D).

Phase 9's exit needs every finding listed with its severity and
disposition, and none rated Critical or High open. This page is that
list.

## Scope

What Phases 2 to 7 left outside the [threat model](incident-threat-model.md)
and what Phase 9 added:

- the collector's UDP input: the IPFIX decoder, template caches and
  exporter tracking;
- the aggregator and detector's bounds;
- ClickHouse: the collector's export and the API's queries;
- packaging: the tarball, the systemd units and the images;
- the build and release pipeline, and the repository's history before it
  becomes permanently public (BQ-16).

The review read the code against these, ran the IPFIX fuzzer, scanned
the history and the dependencies, and extended the threat model with
T-49 to T-57.

## Severity

- **Critical**: remote, unauthenticated, and it reaches routing or data
  integrity.
- **High**: remote and unauthenticated, and it stops a service or
  exposes a credential.
- **Medium**: needs a position on the network path or a configuration
  mistake, or it degrades rather than stops.
- **Low**: defence in depth, or it needs access an attacker would
  already be past.

## Findings

| # | Finding | Severity | Disposition |
|---|---|---|---|
| 1 | A 46-byte IPFIX message, a template whose records are zero bytes long, made the decoder produce empty records until the collector ran out of memory | High | Fixed, [#133](https://github.com/LogiXhare/wetechi-netmon/pull/133); T-49 |
| 2 | UDP senders could grow the collector's memory without bound: an exporter state per spoofed source, never forgotten, and up to 65,280 templates per exporter | High | Fixed, [#136](https://github.com/LogiXhare/wetechi-netmon/pull/136), [ADR 0056](../architecture/decisions/0056-phase9d-collector-input-bounds.md); T-50 |
| 3 | The collector exported to ClickHouse in plain HTTP to any host, with no CA pinning and credentials allowed in the URL | Medium | Fixed, [#123](https://github.com/LogiXhare/wetechi-netmon/pull/123), [ADR 0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md); T-53 |
| 4 | Exporters were keyed by socket alone, not by observation domain: a multi-domain exporter's templates collided and its domains looked like restarts | Medium | Fixed, #136 |
| 5 | The collector's ClickHouse writer panicked on its first row: the client refuses the map that `#[serde(flatten)]` serialises to | Medium | Fixed, [#124](https://github.com/LogiXhare/wetechi-netmon/pull/124) |
| 6 | The weekly fuzz run had failed for weeks without anyone seeing it, and pull requests that changed the decoder never ran the fuzzer | Medium | Fixed, #133: the fuzzer now runs on those pull requests too |
| 7 | The shipped detection policy's window (10 s) differed from the collector's (5 s), so a fresh install never evaluated it, silently | Medium | Fixed, #124: the example matches, and the collector logs an error for each policy it cannot evaluate |
| 8 | The distroless base image carried a fixable High (CVE-2026-84782, `libssl3t64`) | Medium | Fixed, #124: a newer digest, and Trivy fails CI on any fixable Critical or High |
| 9 | No tool enforced the dependency policy: licences, advisories and sources were checked by hand when a dependency was added | Low | Fixed, [#135](https://github.com/LogiXhare/wetechi-netmon/pull/135): `cargo deny` on every pull request; T-56 |
| 10 | The Compose stack's collector and API share one ClickHouse user, so the API's could write | Low | Open, [FU-66](../development/follow-ups.md) |
| 11 | A detection event counts the exporters behind it but does not name them, which slows tracing forged flows | Low | Open, [FU-67](../development/follow-ups.md); T-52 |

No Critical finding. No High finding is open.

## Supply chain

| Check | Where | Result, 2026-10-13 |
|---|---|---|
| `cargo deny`: advisories, licences, bans, sources | Rust job, every pull request | All pass; ten duplicate-version pairs, all from upstream crates, warn |
| `npm audit --audit-level=high` | Web job, every pull request | Pass |
| Trivy, fixable Critical and High | Package job, every image, both architectures | Pass |
| gitleaks, full history | History job, every pull request | No leak in 406 commits |
| Actions pinned by commit SHA, downloaded tools by SHA-256 | Every workflow | Yes |

## Still to do

- **Fuzzing report (FU-3):** the IPFIX decoder fuzzed for a stated
  time, with coverage. NetFlow and sFlow have no parser to fuzz: their
  crates are empty, and v1.0.0 collects IPFIX only.
- **Independent adversarial review** of the release candidate, as
  Phase 5's code had, with every finding added here.
