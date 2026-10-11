# Functional Requirements

Status: Phase 0 draft
Last updated: 2026-08-20

Requirements are grouped by logical service (section 5 of the master
prompt). Each is stated as a capability, not an implementation. IDs are
stable identifiers for future traceability from tests and acceptance
criteria.

## FR-1 Telemetry Collector

- FR-1.1 Receive and decode IPFIX (priority 1), NetFlow v9 (priority 2),
  NetFlow v5 (priority 3), sFlow v5 (priority 4)
- FR-1.2 Bind to configurable interfaces and UDP ports
- FR-1.3 Decode template records, data records, and option templates
- FR-1.4 Cache templates per exporter; handle exporter restarts, template
  changes, and sequence-number resets
- FR-1.5 Recognize observation domains and track exporter uptime
- FR-1.6 Apply sampling correction using exporter-declared sampling rate
- FR-1.7 Record active/inactive timeout metadata
- FR-1.8 Detect and count malformed packets, unknown templates, unsupported
  fields, parser failures, and socket receive-buffer drops
- FR-1.9 Support exporter allowlists and exporter authentication where
  technically possible
- FR-1.10 Support multiple collector instances and horizontal partitioning
- FR-1.11 Support packet replay for testing

## FR-2 Traffic Aggregation

- FR-2.1 Compute bps, pps, fps, total bytes/packets/flows, and per-protocol
  (TCP/UDP/ICMP), fragmented, and TCP-SYN traffic
- FR-2.2 Aggregate along: source host, destination host, IPv4/IPv6 prefix
  (configurable length, incl. /24 and /48), hostgroup, ASN, exporter,
  input/output interface, protocol, TCP flags, tenant, customer, site, data
  center
- FR-2.3 Support time windows: 1s, 5s, 15s, 30s, 1m, 5m, 15m, 1h
- FR-2.4 Bounded memory, deterministic expiration, backpressure,
  high-cardinality protection, configurable top-N limits
- FR-2.5 Exporter-specific sampling correction, late-record handling,
  clock-skew handling

## FR-3 Direction Classification

- FR-3.1 Classify each flow as Incoming, Outgoing, Internal, or Other using
  configured local network prefixes and longest-prefix matching
- FR-3.2 Support IPv4 and IPv6, tenant-aware prefix ownership, prefix
  conflict/duplicate detection
- FR-3.3 Expose a diagnostic endpoint that explains a given classification
  decision

## FR-4 Detection Engine

- FR-4.1 Static threshold detection across Mbps/PPS/FPS and per-protocol
  (TCP/UDP/ICMP/TCP-SYN/Fragmented/Dropped) variants
- FR-4.2 Threshold scopes: per-host, per-prefix, total hostgroup, total
  network, per-ASN, per-exporter-interface, per-tenant, per-customer
- FR-4.3 Directional thresholds: incoming, outgoing, both, independent
- FR-4.4 Minimum trigger duration, hysteresis, cooldown, hold-down,
  re-trigger suppression, maximum alert frequency, maintenance windows,
  allowlist/denylist
- FR-4.5 Operating modes: dry-run, alert-only, manual mitigation, automatic
  mitigation
- FR-4.6 (Later) statistical detection: EWMA, MAD, hour-of-day/day-of-week/
  seasonal baselines, minimum training period, cold-start protection,
  explainable anomaly score, confidence score, baseline versioning
- FR-4.7 Classify attack category (UDP flood, TCP SYN flood, TCP flood,
  ICMP flood, fragmentation flood, DNS/NTP/SSDP/CLDAP amplification
  indicators, multi-vector, distributed subnet, carpet-bomb) without
  claiming definitive attribution when telemetry is insufficient

## FR-5 Incident Management

- FR-5.1 Explicit state machines, one per domain
  ([ADR 0014](architecture/decisions/0014-incident-state-machine.md),
  BQ-6, 2026-08-22):
  - Detection (Phase 4): Normal → Suspected → Confirmed.
  - Incident (Phase 5): Open, Acknowledged, Investigating, Monitoring,
    Recovering, Resolved, Closed. Closed is the only terminal state
    ([state machine](architecture/incident-state-machine.md)).
  - Mitigation (Phase 7): AwaitingApproval → MitigationPending →
    Mitigating → HoldDown, and mitigation failure. These are not incident
    states.

  As first written, this was a single machine,
  `Normal → … → Closed / Failed`. ADR 0014 records why it was split.
- FR-5.2 Persist UUID, tenant, customer, victim, prefix, direction, attack
  category, triggered policy, detection/baseline metrics, threshold,
  exporter, interface, timestamps, mitigation/notification history,
  operator/automation actions, BGP result, rollback result, audit records
- FR-5.3 Deduplication, event correlation, escalation, operator notes,
  evidence attachment, timeline, status history
- FR-5.4 Manual close, automatic recovery, reopen behavior, search, export

## FR-6 Mitigation Controller

- FR-6.1 Integrate with GoBGP via a supported, isolated API
- FR-6.2 Support IPv4 RTBH (/32), IPv6 RTBH (/128), configurable
  parent-prefix announcement, BGP FlowSpec (discard/rate-limit/redirect),
  standard and large communities, configurable next hop, NO_EXPORT,
  NO_ADVERTISE, AS-path prepend, announce/withdraw
- FR-6.3 Restart reconciliation, route ownership, stale-route recovery,
  peer-state monitoring
- FR-6.4 Safety: dry-run by default, BGP disabled by default, authorized-
  prefix allowlist, tenant prefix ownership, max announcement scope, min/max
  prefix lengths, manual approval for first production mitigation,
  emergency global disable, max mitigation duration, automatic withdrawal,
  duplicate-action protection, idempotency, full audit trail

## FR-7 Notification Service

- FR-7.1 Channels: SMTP, Microsoft Teams, Slack, Telegram, PagerDuty,
  generic webhook, Prometheus Alertmanager, optional SMS plugin
- FR-7.2 Notification payload includes product name, incident ID, customer,
  tenant, victim, prefix, direction, attack category, Mbps/Gbps, PPS, FPS,
  baseline, threshold, exporter, interface, mitigation status, BGP state,
  incident/dashboard links, timestamp, recovery status
- FR-7.3 Event types: suspected/confirmed attack, approval requested,
  mitigation started/failed/withdrawn, attack recovered, incident closed,
  exporter unavailable, collector unhealthy, database write failure, BGP
  peer down

## FR-8 Public REST API / Internal gRPC API

- FR-8.1 Versioned REST API with the resource set enumerated in the master
  prompt section 13 (health, readiness, version, exporters, traffic/*,
  incidents, mitigations, bgp/*, policies, tenants, customers, users, roles,
  audit, reports, system/diagnostics)
- FR-8.2 OpenAPI specification and generated client
- FR-8.3 Authentication, authorization, rate limiting, pagination,
  filtering, sorting, idempotency keys, structured errors, request
  correlation IDs
- FR-8.4 Internal gRPC API for service-to-service communication

## FR-9 CLI (`wetechinetmonctl`)

- FR-9.1 Original command surface (see master prompt section 14) covering
  health, version, exporters, traffic, incidents, mitigations, bgp,
  policies, config, backup, diagnostics
- FR-9.2 Human-readable, JSON, and YAML output; machine-friendly exit
  codes; shell completion; secure token handling; non-interactive mode;
  context profiles; tenant selection; API endpoint selection; TLS
  verification

## FR-10 Web Application

- FR-10.1 NOC-focused pages per master prompt section 15 (login, NOC
  overview, traffic breakdowns, exporter health, incidents, mitigations,
  BGP, policies, customers, tenants, users, roles, audit, reports, system
  health, settings, backup/restore, diagnostics)
- FR-10.2 Professional dark NOC theme, accessible/color-blind-safe palette,
  threshold-based coloring not relying solely on red/green, responsive
  layout, full-screen NOC mode, configurable refresh, time-range selector,
  CSV/JSON/PDF export, tenant-filtered views

## FR-11 Grafana Integration

- FR-11.1 Original dashboards (not copied layouts) covering traffic
  totals/direction/protocol, top hosts/networks/hostgroups/ASNs, exporter
  and interface health, collector error metrics, database health,
  incidents, mitigations, BGP, notifications, platform health
- FR-11.2 ClickHouse and Prometheus datasources, optional InfluxDB;
  dashboard JSON validated in CI; original dashboard UIDs and panel layouts

## FR-12 Authentication and RBAC

- FR-12.1 Local auth, OIDC, Microsoft Entra ID, optional LDAP, MFA
  compatibility, API tokens, service accounts, session/password/token
  rotation and expiration, account disablement, audit trail
- FR-12.2 Roles: SuperAdmin, PlatformAdmin, NOCAdmin, NOCOperator,
  SecurityAnalyst, CustomerAdmin, CustomerOperator, CustomerViewer,
  ReadOnlyAuditor, AutomationService
- FR-12.3 Tenant isolation enforced in API, database, web app, CLI,
  reports, dashboards, notifications, and audit records

## FR-13 Multi-Tenancy

- FR-13.1 Per-tenant: ID, customer metadata, authorized prefixes,
  hostgroups, detection/mitigation policies, BGP attributes, notification
  targets, dashboards, incidents, users, roles, retention, API/export
  quotas, audit data
- FR-13.2 Support both single-tenant appliance and multi-tenant managed
  service deployment modes

## FR-14 Observability

- FR-14.1 Prometheus metrics across collector, aggregation, detection,
  storage, BGP, notification, and API layers (full list in master prompt
  section 20)
- FR-14.2 Structured JSON logs with correlation/trace/incident/tenant IDs,
  OpenTelemetry traces, configurable log levels, sensitive-value redaction

## FR-15 Configuration, Audit, Reporting, Backup/Restore Services

- FR-15.1 Central configuration service with validation
- FR-15.2 Audit service capturing operator and automation actions
- FR-15.3 Reporting service (CSV/JSON/PDF) and backup/restore service for
  PostgreSQL, ClickHouse, and configuration state

## Traceability

Each FR ID above must map to acceptance criteria in
[acceptance-criteria.md](acceptance-criteria.md) and to test cases when the
owning phase is implemented. FRs not scheduled for the MVP are flagged in
[mvp-scope.md](mvp-scope.md) / [out-of-scope.md](out-of-scope.md).
