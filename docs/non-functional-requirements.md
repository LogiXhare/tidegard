# Non-Functional Requirements

Status: Phase 0 draft
Last updated: 2026-08-20

## NFR-1 Performance

- Collector must sustain high flow-record ingest rates on commodity
  hardware without unbounded memory growth (specific target pps/fps to be
  set once reference hardware is confirmed — see
  [blocking-questions.md](blocking-questions.md)).
- Aggregation and detection latency must be bounded and observable via
  Prometheus metrics (`aggregation_latency`, `detection_latency`).
- API latency budget (Phase 9B, ADR 0054): with 10,000 incidents and 16
  concurrent clients, the incident list, an incident's detail and the
  mitigation list each answer within 250 ms at p99, with no error
  response. Measured on 2026-10-13 at 23, 107 and 20 ms
  ([capacity planning](operations/capacity-planning.md#api-latency-measured)).

## NFR-2 Reliability and Availability

- Every service exposes health and readiness endpoints.
- Collector must tolerate exporter restarts, template changes, and
  sequence-number resets without data corruption.
- Mitigation controller must reconcile BGP state after its own restart
  (no orphaned or duplicate routes).
- Backup and restore must be tested, not assumed to work.

## NFR-3 Scalability

- Aggregation must support configurable top-N limits and high-cardinality
  protection so a single noisy exporter or attack cannot exhaust memory.
- Architecture must support horizontal partitioning of collectors and
  eventual distributed/HA deployment (v2.0.0 milestone).
- Multi-tenancy must not require re-architecture — tenant scoping is a
  first-class dimension from the schema level up, even though RBAC/tenancy
  ships in later phases.

## NFR-4 Security

- Least privilege, rootless services where practical, dedicated service
  accounts, read-only filesystems, seccomp/AppArmor where applicable.
- TLS required for all external interfaces; optional mTLS internally.
- No secrets in Git, ever — environment variables, secret managers, or
  platform secret stores only.
- Full detail in [security-principles.md](security-principles.md).

## NFR-5 Safety (mitigation-specific)

- BGP mitigation is dry-run and disabled by default at every layer.
- No automatic enabling of production BGP by the software itself.
- Authorized-prefix allowlists and tenant prefix ownership are mandatory
  before any real announcement, even in dry-run-tested lab environments.
- No real DDoS traffic generation, ever, in any test or demo.

## NFR-6 Maintainability

- Each service has a clear, single responsibility, versioned interfaces,
  and its own configuration reference and failure-mode documentation.
- Conventional Commits and small, focused commits are required.
- Documentation is updated in the same pull request as the corresponding
  feature — it is not a follow-up task.

## NFR-7 Portability / Deployment

- Must run via Docker Compose, Kubernetes (Helm), and bare-metal
  systemd on Ubuntu 22.04/24.04 LTS.
- No hardcoded customer domains, passwords, addresses, ASNs, SMTP
  credentials, API keys, or private keys in application code, under any
  deployment target.

## NFR-8 Observability

- Every service ships Prometheus metrics and structured JSON logs from its
  first working version, not retrofitted later.
- Correlation IDs, trace IDs, incident IDs, and tenant IDs must be
  threadable through logs and traces end to end.

## NFR-9 Testability

- Protocol parsers must be fuzz-testable and property-testable from the
  start (Rust, no `unsafe` without a documented, reviewed reason).
- A safe synthetic/sanitized telemetry generator and replay tool is a
  required deliverable of Phase 2, not optional tooling.

## NFR-10 Licensing and Compliance

- Every third-party dependency must have a completed license record before
  it is added to the build (see
  [dependency-license-matrix.md](dependency-license-matrix.md)).
- No proprietary dependency may be combined with copyleft code without the
  legal/distribution implications being documented first.

## NFR-11 Internationalization / Accessibility

- Web UI must use a color-blind-safe, accessible palette; threshold status
  must never depend on color alone.
- No specific i18n/l10n requirement is set in Phase 0; treat English-only
  as the MVP default unless a blocking question surfaces a real need.

## NFR-12 Auditability

- Every operator and automation action affecting incidents, mitigations,
  configuration, or BGP state must be captured in an immutable audit trail,
  queryable per tenant.
