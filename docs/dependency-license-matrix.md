# Dependency License Matrix

Status: Phase 5B-1 dependency probe passed 2026-09-03 (Windows-GNU +
Linux builds, `cargo tree`, `unsafe` inventory, `cargo audit` — 0
vulnerabilities) — rows 32–37 moved from Conditionally Approved to
Approved. See FU-42 in [follow-ups.md](development/follow-ups.md)
Last updated: 2026-09-03

No dependency is approved for use until this matrix has a completed row for
it with an explicit Approved/Rejected decision. License fields that are not
independently and currently verified by the reader are marked **REQUIRES
VERIFICATION** rather than guessed — do not treat unmarked license values
below as legally confirmed; they reflect commonly known licensing at time
of writing and must be re-verified against the actual version selected
before any commercial distribution.

| # | Project | Purpose | Known/likely license | Copyleft implications | Commercial distribution | Status |
|---|---|---|---|---|---|---|
| 1 | Rust toolchain | Core language | MIT / Apache-2.0 dual | None | Safe | REQUIRES VERIFICATION (version pin) |
| 2 | tokio | Async runtime | MIT (verified via `cargo metadata` against v1.53.1) | None | Safe | **Approved** — vendored in `crates/collector`, `tools/flow-replay` (Phase 2) |
| 3 | axum | REST API framework | MIT | None | Safe | REQUIRES VERIFICATION (version pin) |
| 4 | tonic (with tonic-prost, prost, prost-types; build-time tonic-prost-build, protox) | gRPC client to GoBGP | MIT (tonic, tonic-prost, tonic-prost-build); Apache-2.0 (prost, prost-types); MIT or Apache-2.0 (protox) | None | Safe | **Approved** 2026-10-12 — tonic 0.14.6, prost 0.14.4, protox 0.9.1, in `crates/mitigator` only, enforced by the dependency closure test ([ADR 0048](architecture/decisions/0048-phase7c-gobgp-adapter.md)) |
| 5 | serde / serde_json / serde_yaml | Serialization | MIT / Apache-2.0 dual | None | Safe | REQUIRES VERIFICATION (version pin) |
| 6 | clap | CLI argument parsing | MIT / Apache-2.0 dual | None | Safe | REQUIRES VERIFICATION (version pin) |
| 7 | sqlx | PostgreSQL client | MIT / Apache-2.0 dual | None | Safe | REQUIRES VERIFICATION (version pin) |
| 8 | tracing / tracing-subscriber | Structured logging/tracing | MIT (verified via `cargo metadata` against v0.1.44 / v0.3.23) | None | Safe | **Approved** — vendored in `crates/common` (Phase 2) |
| 9 | prometheus (Rust crate) | Metrics | Apache-2.0 (verified via `cargo metadata` against v0.14.0) | None | Safe | **Approved** — vendored in `crates/collector` (Phase 2) |
| 10 | GoBGP | BGP speaker (external process, reached over its gRPC API, not linked) | Apache-2.0 (verified at v4.9.0) | None: only its `.proto` files are vendored, unmodified, with its `LICENSE` beside them in `crates/mitigator/proto/` | Safe; the operator runs `gobgpd` | **Approved** 2026-10-12 — v4.9.0 pinned by version and checksum in CI ([ADR 0048](architecture/decisions/0048-phase7c-gobgp-adapter.md)) |
| 11 | ClickHouse (server, external service) | Analytics storage | Apache-2.0 — REQUIRES VERIFICATION | None expected | Safe as external service dependency | REQUIRES VERIFICATION — integration code written (Phase 3, `crates/storage`) and unit-tested, but no live ClickHouse server was reachable in this environment to verify the actual write path end to end; see docs/integrations/clickhouse.md |
| 12 | PostgreSQL (server, external service) | Config/metadata storage | PostgreSQL License (permissive) — REQUIRES VERIFICATION | None | Safe | REQUIRES VERIFICATION |
| 13 | Prometheus (server) | Metrics collection | Apache-2.0 — REQUIRES VERIFICATION | None | Safe | REQUIRES VERIFICATION |
| 14 | Grafana | Dashboards | AGPLv3 for core Grafana (post-2021 relicensing) | **None for this repository: BQ-2 resolved 2026-10-11, external only.** WetechiNetMon ships original dashboard JSON and provisioning files and never bundles, modifies or redistributes a Grafana binary. CI runs the unmodified official `grafana/grafana` 13.2.3 image as a throwaway test service ([ADR 0041](architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)) | Operator-supplied | **Resolved** — external service; revisit only if a release would ever bundle Grafana |
| 15 | NATS JetStream (candidate transport) | Event transport | Apache-2.0 — REQUIRES VERIFICATION | None expected | Safe | REQUIRES VERIFICATION |
| 16 | Redpanda (candidate transport) | Event transport | **Business Source License (BSL) for some components — REQUIRES VERIFICATION**, converts to Apache-2.0 after a time delay per version | Commercial-use restrictions possible under BSL depending on version/edition | **Needs legal check before selection** if BSL-covered version is used | REQUIRES VERIFICATION — flagged as risk |
| 17 | Kafka (candidate transport) | Event transport | Apache-2.0 — REQUIRES VERIFICATION | None | Safe | REQUIRES VERIFICATION |
| 18 | React | Web app framework | MIT | None | Safe | REQUIRES VERIFICATION (version pin) |
| 19 | Vite | Build tool | MIT | None | Safe | REQUIRES VERIFICATION (version pin) |
| 20 | Tailwind CSS | CSS framework | MIT | None | Safe | REQUIRES VERIFICATION (version pin) |
| 21 | shadcn/ui | UI components | MIT | None | Safe | REQUIRES VERIFICATION (version pin) |
| 22 | Recharts | Charting | MIT | None | Safe | REQUIRES VERIFICATION (version pin) |
| 23 | Apache ECharts | Charting | Apache-2.0 | None | Safe | REQUIRES VERIFICATION (version pin) |
| 24 | InfluxDB (v1-compatible target, external service) | Legacy metrics output | MIT (v1.x) / varies by version — REQUIRES VERIFICATION | Verify per version | Safe if MIT-era version targeted | REQUIRES VERIFICATION |
| 25 | MkDocs Material | Documentation site | MIT | None | Safe | REQUIRES VERIFICATION (version pin) |
| 26 | thiserror | Error-type derive macro | MIT OR Apache-2.0 (verified via `cargo metadata` against v2.0.20) | None | Safe | **Approved** — vendored in `crates/protocol-ipfix`, `crates/common`, `crates/collector` (Phase 2) |
| 27 | proptest | Property-based testing | MIT OR Apache-2.0 (verified via `cargo metadata` against v1.11.0) | None | Safe, dev-dependency only (not shipped in release binaries) | **Approved** — dev-dependency in `crates/protocol-ipfix` (Phase 2) |
| 28 | clickhouse (Rust client crate) | ClickHouse HTTP client/writer | MIT OR Apache-2.0 (verified via `cargo metadata` against v0.13.3) | None | Safe | **Approved** — vendored in `crates/storage` (Phase 3) |
| 29 | time | Date/time handling for ClickHouse row timestamps | MIT OR Apache-2.0 (verified via `cargo metadata` against v0.3.55) | None | Safe | **Approved** — vendored in `crates/storage`, `crates/collector` (Phase 3) |
| 30 | serde (direct use) | Row serialization for `clickhouse::Row` | MIT OR Apache-2.0 (verified via `cargo metadata` against v1.0.229) | None | Safe | **Approved** — vendored in `crates/storage` (Phase 3; already a transitive dependency since Phase 2, now a direct one) |
| 31 | libfuzzer-sys | libFuzzer bindings for the cargo-fuzz target | MIT OR Apache-2.0 (commonly known; **not independently verified via `cargo metadata`** — the fuzz crate is its own standalone Cargo workspace, per `crates/protocol-ipfix/fuzz/Cargo.toml`, so it doesn't appear in the main workspace's dependency graph) | None expected | Safe; dev/tooling-only, never shipped in a release binary | REQUIRES VERIFICATION — **not yet run in CI or locally in this environment** (no nightly toolchain here); verify before first real `cargo fuzz run` |
| 32 | uuid | UUIDv7 incident-identity generation (Phase 5B, `crates/incident-postgres` only) | Apache-2.0 OR MIT — re-verified 2026-09-03 against the actually-resolved v1.26.0 (the `"1.25"` requirement's newest compatible patch), reading `Cargo.toml`'s `license` field directly in the vendored source, not crates.io API | None expected | Safe — `features = ["v7"], default-features = false`, no `uuid::Uuid` type crosses `crates/incident`'s public API (it is used only inside the new probe stub, `crates/incident-postgres`) | **Approved** — [ADR 0019](architecture/decisions/0019-phase5b-uuidv7-identity-generation.md); Windows-GNU and Linux (ubuntu-latest) builds both green, cargo tree/audit/unsafe inventory verified 2026-09-03 (PR #23), see [FU-42](development/follow-ups.md) |
| 33 | tokio-postgres | PostgreSQL async client (Phase 5B, `crates/incident-postgres`) | MIT OR Apache-2.0 — re-verified 2026-09-03 against the resolved v0.7.18 (exact ADR-pinned version) | None | Safe — 1 advisory found (RUSTSEC-2026-0178), **patched at the selected version 0.7.18**; `cargo audit` against the full resulting `Cargo.lock` (252 crates) found **0 vulnerabilities** | **Approved** — [ADR 0020](architecture/decisions/0020-phase5b-postgresql-client.md); Windows-GNU and Linux (ubuntu-latest) builds both green, cargo tree/audit/unsafe inventory verified 2026-09-03 (PR #23), see [FU-42](development/follow-ups.md) |
| 34 | deadpool-postgres | Connection pool for `tokio-postgres` (Phase 5B) | MIT OR Apache-2.0 — re-verified 2026-09-03 against the actually-resolved v0.14.2 (the `"0.14.1"` requirement's newest compatible patch) | None expected | Safe — no advisories found in RustSec advisory-db | **Approved** — [ADR 0022](architecture/decisions/0022-phase5b-connection-pool.md); Windows-GNU and Linux (ubuntu-latest) builds both green, cargo tree/audit/unsafe inventory verified 2026-09-03 (PR #23), see [FU-42](development/follow-ups.md) |
| 35 | rustls | TLS backend for the PostgreSQL connection (Phase 5B) | Apache-2.0 OR ISC OR MIT — re-verified 2026-09-03 against the resolved v0.23.43 (exact ADR-pinned version) | None | Safe — 2 advisories found (RUSTSEC-2024-0336, RUSTSEC-2024-0399), **both patched** well below the selected version. **New finding, not in ADR 0023:** rustls 0.23.x's default crypto provider pulls in `aws-lc-rs`/`aws-lc-sys` (a vendored, compiled-from-C fork of BoringSSL, compound-licensed ISC/Apache-2.0/MIT/BSD-3-Clause, requiring a C compiler + `cmake` at build time) as a **transitive** dependency — 73 crates and ~14,300 `unsafe`-keyword occurrences added to the workspace's dependency closure, of which `aws-lc-sys` alone accounts for ~87%. This does not change the license or advisory verdict (`cargo audit` found 0 vulnerabilities, and NOTICE only tracks direct dependencies per its own stated convention), but it is a materially larger and more C-toolchain-dependent closure than choosing rustls's alternative `ring` crypto provider would have produced — recorded as a fact for whoever designs the actual TLS wiring in Milestone 5B-2, not acted on here. | **Approved** — [ADR 0023](architecture/decisions/0023-phase5b-postgresql-tls.md); Windows-GNU and Linux (ubuntu-latest) builds both green, cargo tree/audit/unsafe inventory verified 2026-09-03 (PR #23), see [FU-42](development/follow-ups.md) |
| 36 | tokio-postgres-rustls | Bridges `tokio-postgres` to `rustls` (Phase 5B) | MIT — re-verified 2026-09-03 against the resolved v0.14.0 (exact ADR-pinned version) | None expected | Safe — no advisories found in RustSec advisory-db | **Approved** — [ADR 0023](architecture/decisions/0023-phase5b-postgresql-tls.md); Windows-GNU and Linux (ubuntu-latest) builds both green, cargo tree/audit/unsafe inventory verified 2026-09-03 (PR #23), see [FU-42](development/follow-ups.md) |
| 37 | refinery | Forward-only PostgreSQL migrations (Phase 5B) | MIT — re-verified 2026-10-12 for v0.10.0 (Dependabot #84; MSRV 1.92); first verified 2026-09-03 for v0.9.2, `default-features = false, features = ["tokio-postgres"]` | None expected | Safe — no advisories found in RustSec advisory-db | **Approved** — [ADR 0024](architecture/decisions/0024-phase5b-migration-framework.md); Windows-GNU and Linux (ubuntu-latest) builds both green, cargo tree/audit/unsafe inventory verified 2026-09-03 (PR #23), see [FU-42](development/follow-ups.md) |
| 38 | axum | HTTP framework for the incident API (Phase 5D, `apps/api`) | MIT — re-verified 2026-10-05 against the vendored `Cargo.toml` of the resolved v0.8.9 (`axum-core` 0.5.6, `tower` 0.5.3, `tower-layer` 0.3.3 also MIT) | None. One transitive crate, `matchit` 0.8.4, is **MIT AND BSD-3-Clause** (httprouter-derived): binary redistribution must carry the BSD notice — recorded in `NOTICE`, FU-53 | Safe — `cargo audit` over the full lock (270 crates): 0 vulnerabilities, 0 warnings. `axum-core` RUSTSEC-2022-0055 long patched | **Approved** — 5D gate-8 probe (2026-10-05): 16 new third-party crates together with `utoipa`; `unsafe` keyword count 0 in axum, axum-core, tower, tower-layer; Windows-GNU build clean; Linux via CI |
| 39 | utoipa | OpenAPI document generated from the API code (Phase 5D) | MIT OR Apache-2.0 — re-verified 2026-10-05 against the vendored v6.0.0 (`utoipa-gen` 6.0.1, same licence) | None | Safe — no advisories; `cargo audit` clean | **Approved** — 5D probe: `unsafe` count 0 in utoipa and utoipa-gen; brings `indexmap` and `hashbrown` (both MIT OR Apache-2.0) |
| 40 | governor | GCRA rate limiting (Phase 5D) | MIT — verified 2026-10-05 on crates.io for v0.10.4 | None | Safe — no advisories | **Rejected** — 5D probe (2026-10-05): even with `default-features = false, features = ["std"]` it adds 8 more crates and about 920 `unsafe` occurrences (`portable-atomic` 727, `hashbrown` 0.16 with `allocator-api2`) — about 1 420 of the 1 477 the API closure would otherwise carry — for an algorithm whose state is one timestamp per key. GCRA is implemented in `apps/api` on `std` instead; see [ADR 0038](architecture/decisions/0038-phase5d-api-boundary.md) |
| 41 | getrandom (direct use) | OS CSPRNG for API token generation (Phase 5D); already a transitive dependency | MIT OR Apache-2.0 — verified 2026-10-05 for v0.4.3, already in `Cargo.lock` | None | Safe — no advisories; `cargo audit` clean | **Approved** — 5D probe: adds no crate (already resolved transitively) |
| 42 | tokio-rustls (direct use) | TLS listener for the incident API off loopback (Phase 5D, ADR 0038 gate 3); already a transitive dependency through `tokio-postgres-rustls` | MIT OR Apache-2.0 — verified 2026-10-05 against the vendored `Cargo.toml` of the resolved v0.26.4 | None | Safe — 1 advisory found (RUSTSEC-2020-0019), patched at ≥ 0.13.1, far below 0.26.4; `cargo audit` clean | **Approved** — adds no crate (already resolved) |
| 43 | sha2 (direct use) | SHA-256 of API tokens, so only the hash is stored (Phase 5D, ADR 0038 gate 4); already a transitive dependency through the PostgreSQL SCRAM client | MIT OR Apache-2.0 — verified 2026-10-05 against the vendored `Cargo.toml` of the resolved v0.11.0 | None | Safe — 1 advisory found (RUSTSEC-2021-0100, affecting only 0.9.7), patched at ≥ 0.9.8; `cargo audit` clean | **Approved** — adds no crate (already resolved) |
| 44 | grafana-clickhouse-datasource (Grafana plugin) | ClickHouse datasource for the traffic and detection dashboards (Phase 6A) | Apache-2.0 — verified 2026-10-12 against the `LICENSE` at tag v4.21.3; signed by Grafana Labs | None: installed by the operator into their own Grafana, and by CI into a throwaway one; not shipped | Version pinned in CI (4.21.3) | **Approved** — CI and operator use only ([ADR 0041](architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)) |
| 45 | react, react-dom (npm) | The NOC UI (Phase 6D) | MIT — verified 2026-10-12 for v19.3.0 from the npm registry | None | Pinned exactly; `npm audit` and the licence check in CI | **Approved** — ships in the UI bundle ([ADR 0044](architecture/decisions/0044-phase6d-noc-ui.md)) |
| 46 | react-router-dom (npm) | Routing in the NOC UI (Phase 6D) | MIT — verified 2026-10-12 for v7.18.4 | None | Pinned exactly; audited in CI | **Approved** — ships in the UI bundle ([ADR 0044](architecture/decisions/0044-phase6d-noc-ui.md)) |
| 47 | UI build and test tools (npm): vite, @vitejs/plugin-react, typescript, typescript-eslint, eslint, @eslint/js, eslint-plugin-react-hooks, globals, vitest, jsdom, @testing-library/react, @testing-library/dom | Build, lint and test the NOC UI; never shipped | MIT or Apache-2.0 for each, verified 2026-10-12; transitive build tools checked by `npm run licences`, which also admits MPL-2.0 for build-only packages (`lightningcss`) | None: build time only | Installed with `--ignore-scripts`; `npm audit` in CI | **Approved** — build only ([ADR 0044](architecture/decisions/0044-phase6d-noc-ui.md)) |
| 48 | lettre | SMTP for the notifier's email channel (Phase 6E-2) | MIT — verified 2026-10-12 for v0.11.23 | None | `cargo audit` clean 2026-10-12; features limited to `builder`, `smtp-transport`, `tokio1-rustls`, `aws-lc-rs`, `webpki-roots` (no native-tls, no pool) | **Approved** — the notifier only; the dependency closure test refuses it anywhere else ([ADR 0045](architecture/decisions/0045-phase6e-notification-delivery.md)) |
| 49 | email-encoding, email_address, nom, quoted_printable, base64 | lettre's own dependencies | MIT OR Apache-2.0 (email-encoding 0.4.2, base64 0.22.1), MIT (email_address 0.2.9, nom 8.0.0), 0BSD (quoted_printable 0.5.2) — verified 2026-10-12 | None | `cargo audit` clean | **Approved** — through lettre, notifier only |
| 50 | webpki-roots | Satisfies lettre's compile-time requirement for a root store | CDLA-Permissive-2.0 — verified 2026-10-12 for v1.0.9; a permissive data licence | None | Compiled in but **never used**: every SMTP connection is built with `CertificateStore::None` and the configured CA bundle alone | **Approved** — notifier only ([ADR 0045](architecture/decisions/0045-phase6e-notification-delivery.md)) |
| 51 | hyper-rustls | TLS from the collector to ClickHouse, verified against the configured CA bundle (Phase 9A-3a); the `clickhouse` crate accepts only a hyper-util client, and this is its TLS connector | Apache-2.0 OR ISC OR MIT — verified 2026-10-12 for v0.27.10 (released 2026-09-20) | None | `cargo audit` clean 2026-10-12; `default-features = false` with `http1`, `tls12` and `aws-lc-rs` only: no native or webpki roots, the CA bundle alone | **Approved** — `crates/storage` only, the one new crate in `Cargo.lock` ([ADR 0053](architecture/decisions/0053-phase9a-collector-clickhouse-tls.md)) |
| 52 | gcr.io/distroless/cc-debian13 (base image) | The base of every WetechiNetMon container image (Phase 9A-3b): glibc, libgcc, CA certificates and time zone data, no shell or package manager | Distroless itself Apache-2.0; its Debian 13 packages under their own free licences (glibc LGPL-2.1+, libgcc GPL-3.0+ with the GCC Runtime Library Exception, ca-certificates MPL-2.0 and GPL-2.0+, tzdata public domain) — shipped as separate, unmodified system libraries, which these licences allow; the image carries their copyright files | None | Trivy in CI fails on any fixable Critical or High finding; pinned by digest (`sha256:e792ab3d…`, published 2026-10-01: newer than the 14-day rule allows, because the 2026-09-13 digest carried a fixable High in `libssl3t64`, CVE-2026-84782, and a security fix overrides the wait), updated by Dependabot after 14 days | **Approved** — container images only, never linked into the source ([ADR 0052](architecture/decisions/0052-phase9a-packaging.md)) |

## Toolchain-Only, Not Shipped in Any Binary

The Rust GNU toolchain requires a MinGW-w64 build environment (binutils —
`as`, `ar`, `dlltool`, `ld` — plus `gcc.exe` used only as a linker driver)
to link `windows-sys`-dependent crates on Windows dev machines. Installed
locally via winget (`BrechtSanders.WinLibs.POSIX.UCRT`, multiple licenses
— see <https://winlibs.com/#license>). This is **build tooling only**
— none of it is linked into or distributed with WetechiNetMon binaries, so
it carries no distribution obligations for the product itself. Not added
as a numbered row above since it is not a dependency of the product in any
license-relevant sense; noted here for engineering-environment
reproducibility (see docs/development/local-setup.md).

## Process

Each row above is a **candidate**, not an approval. Before a dependency is
actually added to `Cargo.toml`, `package.json`, or a deployment manifest:

1. Verify the license of the exact version pinned (not just "the project").
2. Fill in copyright notice requirements and record them for NOTICE file
   generation (Phase 1 deliverable).
3. Record integration method (linked library vs. external service/process
   boundary vs. build-time-only tool) — this materially changes copyleft
   exposure (e.g. GoBGP and ClickHouse as separate processes/services carry
   different obligations than a statically linked GPL library would).
4. Record security maintenance status (actively maintained? recent CVEs?).
5. Mark Approved or Rejected explicitly — "REQUIRES VERIFICATION" is not a
   valid terminal state for anything actually shipped.

**"Conditionally Approved"** was a distinct, non-terminal state used for
the Phase 5B candidates while the crate's version, license, and advisory
history were independently verified against live sources but the crate
was not yet added to any `Cargo.toml`. Rows 32–37 carried that state
until the Phase 5B-1 probe (2026-09-03, [PR #23](https://github.com/LogiXhare/wetechi-netmon/pull/23))
added all six to `crates/incident-postgres` and measured transitive
closure, `cargo audit`, `unsafe` inventory, a Windows-GNU build locally,
and a Linux build via that PR's own required Rust check on
`ubuntu-latest` — all clean, `cargo audit` finding 0 vulnerabilities
across the full 252-crate `Cargo.lock`. No row currently carries
"Conditionally Approved"; the state remains available for a future
candidate that needs the same two-step review.

## Known Legal Flags Raised in Phase 0

- **Grafana AGPLv3 relicensing (2021)**: if WetechiNetMon bundles or
  modifies Grafana itself (rather than shipping original dashboard JSON
  that an operator loads into their own separately-installed Grafana),
  AGPLv3's network-copyleft terms could require WetechiNetMon's own source
  to be made available. Recommended default posture: ship Grafana
  dashboard JSON and provisioning config only, treat Grafana server as an
  operator-supplied external dependency (like PostgreSQL), never bundle a
  modified Grafana binary. This must be confirmed as a blocking question
  before Phase 6 — see [blocking-questions.md](blocking-questions.md).
- **Redpanda BSL**: if Redpanda is selected as the event transport instead
  of NATS or Kafka, its license terms must be re-checked per version before
  any commercial/managed-service use, since BSL is not OSI-approved
  open-source and can carry field-of-use restrictions.

## Out of Scope for Phase 0

Actually running `cargo deny`, `cargo audit`, or SBOM tooling — that is a
Phase 1 CI deliverable once there is a real `Cargo.toml` to scan.
