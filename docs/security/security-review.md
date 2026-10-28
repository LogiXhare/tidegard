# Phase 9D Security Review

Status: **Done**, 2026-10-28. The supply chain checks, the threat
model's extension, the findings, the fuzzing report and the
independent review of release candidate 1.0.0-rc.2 are done
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
| 1 | A 46-byte IPFIX message, a template whose records are zero bytes long, made the decoder produce empty records until the collector ran out of memory | High | Fixed, [#133](https://github.com/LogiXhare/tidegard/pull/133); T-49 |
| 2 | UDP senders could grow the collector's memory without bound: an exporter state per spoofed source, never forgotten, and up to 65,280 templates per exporter | High | Fixed, [#136](https://github.com/LogiXhare/tidegard/pull/136), [ADR 0056](../architecture/decisions/0056-phase9d-collector-input-bounds.md); T-50 |
| 3 | The collector exported to ClickHouse in plain HTTP to any host, with no CA pinning and credentials allowed in the URL | Medium | Fixed, [#123](https://github.com/LogiXhare/tidegard/pull/123), [ADR 0053](../architecture/decisions/0053-phase9a-collector-clickhouse-tls.md); T-53 |
| 4 | Exporters were keyed by socket alone, not by observation domain: a multi-domain exporter's templates collided and its domains looked like restarts | Medium | Fixed, #136 |
| 5 | The collector's ClickHouse writer panicked on its first row: the client refuses the map that `#[serde(flatten)]` serialises to | Medium | Fixed, [#124](https://github.com/LogiXhare/tidegard/pull/124) |
| 6 | The weekly fuzz run had failed for weeks without anyone seeing it, and pull requests that changed the decoder never ran the fuzzer | Medium | Fixed, #133: the fuzzer now runs on those pull requests too |
| 7 | The shipped detection policy's window (10 s) differed from the collector's (5 s), so a fresh install never evaluated it, silently | Medium | Fixed, #124: the example matches, and the collector logs an error for each policy it cannot evaluate |
| 8 | The distroless base image carried a fixable High (CVE-2026-84782, `libssl3t64`) | Medium | Fixed, #124: a newer digest, and Trivy fails CI on any fixable Critical or High |
| 9 | No tool enforced the dependency policy: licences, advisories and sources were checked by hand when a dependency was added | Low | Fixed, [#135](https://github.com/LogiXhare/tidegard/pull/135): `cargo deny` on every pull request; T-56 |
| 10 | The Compose stack's collector and API share one ClickHouse user, so the API's could write | Low | Open, [FU-66](../development/follow-ups.md) |
| 11 | A detection event counts the exporters behind it but does not name them, which slows tracing forged flows | Low | Open, [FU-67](../development/follow-ups.md); T-52 |

No Critical finding. No High finding is open.

## Release candidate review

An independent review of everything since v0.9.0, as of 1.0.0-rc.2
(`4c54be5`), on 2026-10-28. It was split into four parts, each a draft
pull request against v0.9.0 that was never merged:
[#164](https://github.com/LogiXhare/tidegard/pull/164) (collector, storage and detection),
[#165](https://github.com/LogiXhare/tidegard/pull/165) (incidents, API, mitigation and notification),
[#166](https://github.com/LogiXhare/tidegard/pull/166) (CI and the release pipeline) and
[#167](https://github.com/LogiXhare/tidegard/pull/167) (scripts and deployments). Each part was read for
correctness, security and needless complexity by reviewers that had not
written the code.

| # | Finding | Severity | Disposition |
|---|---|---|---|
| R-1 | An Options Template Withdrawal (four bytes, RFC 7011 §8.1) was parsed with the six-byte options header: the message was refused and the template stayed | Medium | Fixed, [#168](https://github.com/LogiXhare/tidegard/pull/168) |
| R-2 | An exporter took a place from a 16-byte header alone, and past the limit new ones were refused: without an allowlist, spoofed headers could keep every router out | High | Fixed, #168: a place is kept only once a datagram decodes, and a new exporter replaces the longest-silent one that defined no template; T-50 |
| R-3 | A withdrawal of Template ID 2 or 3 cleared both kinds of template and the learned sampling interval, undercounting traffic | Medium | Fixed, #168 |
| R-4 | The collector reported ready before its ClickHouse migrations, which had no timeout | Medium | Fixed, #168: ready once startup is over; 30 seconds for the migrations |
| R-5 | An unreadable ClickHouse CA or password file disabled export, and the log blamed reachability | Medium | Fixed, #168: it stops the collector |
| R-6 | Anything after an IPv6 host's closing bracket that was not a port was ignored; IPv4-mapped loopback was not loopback | Low | Fixed, #168 |
| R-7 | flow-replay's rate mode sent its template once, so one lost datagram spoiled a load test; `--exporters` was ignored | Low | Fixed, #168 |
| R-8 | `TIDEGARD_COLLECTOR_EXPORTER_IDLE_SECS=0` forgot every exporter at each sweep | Medium | Fixed, #168: refused |
| R-9 | Four copies of prefix masking across the collector, detector, aggregator and mitigation | Low | Open, [FU-68](../development/follow-ups.md) |
| R-10 | The template gauge summed every exporter's cache on every datagram | Low | Fixed, #168 |
| R-11 | The mitigator never checked that it still held the single-mitigator lock: after a database restart a standby could act alongside it | Medium | Fixed, [#169](https://github.com/LogiXhare/tidegard/pull/169): it checks before every pass, and stops when the lock's session is gone |
| R-12 | The mitigator reported ready while every GoBGP call failed | Medium | Fixed, #169 |
| R-13 | The webhook body's `schema` and `product` changed with the rename, undocumented | Low | Fixed, #169: in the upgrade notes |
| R-14 | `tidegardctl` no longer found a profile file written before the rename | Low | Fixed, #169 |
| R-15 | A blank `TIDEGARD_X` hid a set `WETECHINETMON_X` | Medium | Fixed, #169 |
| R-16 | The deprecated-name warning was a bare line among the JSON logs | Low | Fixed, #169 |
| R-17 | A web UI page left open across the upgrade had its every change refused (CSRF) | Low | Fixed, #169: the pre-rename value is still accepted for the same session |
| R-18 | The incident export's `format` changed with the rename, undocumented | Low | Fixed, #169: in the upgrade notes |
| R-19 | The GoBGP endpoint had its own copy of the URL parser | Low | Fixed, #168 |
| R-20 | A dead error arm; a non-UTF-8 setting's error named the new variable only | Low | Fixed, #169 |
| R-21 | `! grep -q` cannot fail a bash step: a skipped TLS test and a second install that recreated a setting both passed CI | Medium | Fixed, [#170](https://github.com/LogiXhare/tidegard/pull/170) |
| R-22 | The acceptance test's own-approval check was refused by the role, never reaching the self-approval rule | Medium | Fixed, #170: a lead requests, and the same lead's approval must fail with `mitigation.self_approval` |
| R-23 | A benchmark run cancelled a soak in progress on the same ref | Low | Fixed, #170 |
| R-24 | The release's verify job signed in to GHCR, so private images passed | Medium | Fixed, #170: it pulls as an operator does |
| R-25 | The release is public before the clean-runner verify job has run | Medium | Open, [FU-69](../development/follow-ups.md) |
| R-26 | Release binaries were built with whatever Rust the runner had, and an unverified rustup script on arm64 | Medium | Fixed, #170: Rust 1.99.1 on both, rustup-init by SHA-256 |
| R-27 | A failed poll in a retry loop aborted the step | Low | Fixed, #170 |
| R-28 | `soak_hours` was free text that could skip every job or outrun the timeout | Low | Fixed, #170: a choice from 0 to 5 |
| R-29 | Workflow blocks copied three or four times: cosign, cargo-about, the readiness helper, the service list | Low | Open, [FU-70](../development/follow-ups.md) |
| R-30 | ClickHouse 26.8.14.3 in Compose and the acceptance test, 26.8.24.9 everywhere else | Low | Fixed, #170: 26.8.24.9 everywhere, by digest |
| R-31 | The soak waited out the replay's whole duration after the collector died | Low | Fixed, #170 |
| R-32 | The documented rotation of the Compose PostgreSQL password did not rotate it | Medium | Fixed, #170: a procedure that does, in the Compose README |
| R-33 | A new Compose CA kept the certificates the old one signed, and the stack went down | Medium | Fixed, #170: `setup.sh` issues them again |
| R-34 | Compose starts the services before the incident manager has migrated a new database | Low | Open, [FU-71](../development/follow-ups.md) |
| R-35 | `journalctl` piped to `grep -q` under `pipefail` could fail on SIGPIPE | Low | Fixed, #170 |
| R-36 | The Compose certificates expire after 825 days and nothing renewed them | Medium | Fixed, #170: `setup.sh` renews within 30 days of expiry |
| R-37 | The load test's CPU figure was divided by the send time only | Low | Fixed, #170 |
| R-38 | The disaster recovery drill went on when a server never became ready | Low | Fixed, #170 |
| R-39 | Five systemd units repeat the same hardening block | Low | Open, [FU-72](../development/follow-ups.md) |
| R-40 | `about.toml` keeps its own copy of `deny.toml`'s licence list | Low | Open, [FU-73](../development/follow-ups.md) |

One finding was High, R-2, and it is fixed. Six Low or Medium findings
stay open as follow-ups; none blocks v1.0.0. Release candidate
1.0.0-rc.3 carries the fixes.

## Supply chain

| Check | Where | Result, 2026-10-13 |
|---|---|---|
| `cargo deny`: advisories, licences, bans, sources | Rust job, every pull request | All pass; ten duplicate-version pairs, all from upstream crates, warn |
| `npm audit --audit-level=high` | Web job, every pull request | Pass |
| Trivy, fixable Critical and High | Package job, every image, both architectures | Pass |
| gitleaks, full history | History job, every pull request | No leak in 406 commits |
| Actions pinned by commit SHA, downloaded tools by SHA-256 | Every workflow | Yes |

## Fuzzing report (FU-3)

The IPFIX decoder's fuzz target (`crates/protocol-ipfix/fuzz`,
`decode_message`: an empty template cache, then arbitrary bytes as a
message) ran for three hours on `main` at `39959e9`, which includes the
input bounds of finding 2: run
[38350471775](https://github.com/LogiXhare/tidegard/actions/runs/38350471775),
2026-10-13, libFuzzer on a nightly toolchain, one GitHub-hosted runner.

| Measure | Result |
|---|---|
| Time | 10,801 s |
| Executions | 957,841,448 (88,680 a second) |
| Coverage | 457 edges, 1,942 features |
| Corpus at the end | 400 inputs, 42 KB, the longest 640 bytes |
| Crashes, timeouts, out-of-memory | **None** |
| Peak memory (the fuzzer's process) | 631 MiB, within libFuzzer's 2 GiB limit |

Coverage grew in the first minutes and then only slowly, which a
decoder of this size (a header, three set kinds, template and data
records) is expected to show. The fuzz workflow keeps running weekly and
on every pull request that changes the decoder, for five minutes each.

What it does not cover: the collector around the decoder (exporter
tracking, normalisation, aggregation), which proptest and the unit tests
of finding 2 cover instead; and NetFlow and sFlow, which v1.0.0 does not
parse.

## Still to do

Nothing for v1.0.0. The open findings are follow-ups FU-66 to FU-73.
