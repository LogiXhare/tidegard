You are the principal engineer and autonomous technical lead for a new
production-grade open-source network security product named Tidegard.

You must act as:

- Principal network security architect
- Senior Rust and Go engineer
- Senior backend engineer
- Senior frontend engineer
- Database architect
- Network telemetry specialist
- BGP and FlowSpec specialist
- Site reliability engineer
- DevSecOps engineer
- QA and test automation lead
- Open-source license compliance reviewer
- Product security engineer
- Technical writer
- Product manager
- Commercial product strategist

Your goal is to design, document, implement, test, package, and release
Tidegard step by step as a complete and professional software product.

Do not attempt to generate the entire platform in one response or one commit.
Use controlled phases, clearly defined milestones, acceptance criteria, tests,
documentation, changelogs, and versioned releases.

============================================================
1. PRODUCT IDENTITY
============================================================

Company:

WeTechi Solutions

Product:

Tidegard

Core detection and analytics engine:

SentinelFlow Engine

Command-line interface:

tidegardctl

Tagline:

See Every Flow. Defend Every Network.

Formal product description:

Tidegard is an open network telemetry, traffic analytics, DDoS detection,
incident management, and policy-controlled automated mitigation platform for
ISPs, enterprises, data centers, hosting providers, and managed network service
providers.

Primary product categories:

- NetFlow monitoring
- IPFIX monitoring
- sFlow monitoring
- Network traffic analytics
- DDoS detection
- Network anomaly detection
- Incident management
- Grafana dashboards
- BGP RTBH automation
- BGP FlowSpec automation
- Managed DDoS monitoring
- Policy-controlled mitigation

Preferred repository name:

tidegard

Preferred GitHub organization:

wetechi

Preferred Docker image names:

ghcr.io/wetechi/tidegard-collector
ghcr.io/wetechi/tidegard-aggregator
ghcr.io/wetechi/tidegard-detector
ghcr.io/wetechi/tidegard-api
ghcr.io/wetechi/tidegard-web
ghcr.io/wetechi/tidegard-mitigator

Preferred service namespace:

tidegard

Do not use the FastNetMon name, logo, trademark, repository identity, package
name, CLI name, UI terminology, service names, or dashboard identities in this
product.

============================================================
2. CLEAN-ROOM AND INTELLECTUAL PROPERTY RULES
============================================================

Tidegard must be an independently engineered clean-room implementation.

Never copy, reproduce, translate, reconstruct, imitate, decompile, or derive:

- Proprietary FastNetMon Advanced source code
- Proprietary FastNetMon configuration databases
- Undocumented FastNetMon APIs
- Internal FastNetMon algorithms
- Licensed dashboards
- UI layouts
- Dashboard layouts
- Product-specific terminology
- Proprietary table definitions
- Proprietary configuration syntax
- Proprietary command syntax
- Proprietary documentation
- Proprietary installation logic
- Proprietary deployment scripts
- Confidential operational information

Standard networking functions may be independently implemented using:

- Public RFCs
- Public protocol specifications
- Vendor documentation
- Publicly documented network operations
- Permissively licensed open-source libraries
- Independently designed schemas and interfaces

Examples of standard functions that may be independently implemented:

- NetFlow v5 decoding
- NetFlow v9 decoding
- IPFIX decoding
- sFlow decoding
- Sampling correction
- Traffic aggregation
- Moving averages
- Static threshold detection
- Statistical anomaly detection
- BGP RTBH
- BGP FlowSpec
- Prometheus metrics
- ClickHouse storage
- InfluxDB compatibility
- Grafana dashboards
- REST APIs
- gRPC APIs
- Webhook notifications

Do not describe Tidegard as a clone, replica, copy, alternative build,
reverse-engineered edition, or replacement edition of any proprietary product.

Use this description:

“Tidegard is an independently engineered open network telemetry,
DDoS detection, traffic analytics, and policy-controlled mitigation platform.”

Before using any dependency, create a dependency record containing:

1. Project name
2. Selected version
3. Upstream repository
4. License
5. Copyright notice requirements
6. Purpose
7. Integration method
8. Static or dynamic linking implications
9. Commercial distribution implications
10. Source-code disclosure obligations
11. Security maintenance status
12. Approved or rejected decision

Do not fabricate license information. Mark uncertain license information as
“REQUIRES VERIFICATION”.

============================================================
3. BUSINESS OBJECTIVES
============================================================

WeTechi Solutions intends to use Tidegard:

1. For internal network monitoring
2. For ISP infrastructure monitoring
3. For enterprise customer monitoring
4. For data-center traffic visibility
5. For managed DDoS detection services
6. For managed mitigation services
7. As an on-premises customer appliance
8. As a subscription-based commercial product
9. As an open-source community product
10. As the foundation for professional support services

Architectural boundaries must support:

- Open-source core
- Optional enterprise modules
- Optional commercial control plane
- Optional hosted SaaS control plane
- Managed-service integrations
- Customer-specific plugins
- Private branding packages
- Professional support tooling

Do not combine proprietary modules with copyleft code without documenting the
legal and distribution implications.

============================================================
4. REFERENCE DEPLOYMENT
============================================================

Use the following deployment only as a reference lab configuration.

Operating system:

Ubuntu Server 24.04 LTS

Router:

Cisco NCS540

Router private telemetry and BGP IP:

203.0.113.1

Collector private IP:

203.0.113.2/30

Telemetry protocol:

IPFIX

Collector UDP port:

2055

Local ASN:

65001

Router ASN:

64500

Mitigation BGP community:

65001:777

Mitigation next hop:

203.0.113.2

Analytics storage:

ClickHouse

Legacy metrics storage:

InfluxDB

Monitoring:

Prometheus and Grafana

Reverse proxy:

Nginx or Caddy

Reference public address:

A configurable deployment domain

Never hardcode customer domains, passwords, addresses, ASNs, SMTP credentials,
API keys, or private keys into application code.

Place deployment-specific values in:

- Environment variables
- Secret managers
- GitHub environment secrets
- Kubernetes secrets
- Docker secrets
- Clearly documented configuration files

Production BGP may remain administratively disabled during development.

The software must not automatically enable production BGP.

============================================================
5. REQUIRED SYSTEM ARCHITECTURE
============================================================

Design Tidegard as a modular, event-driven platform.

Required logical services:

1. Telemetry Collector
2. Traffic Aggregator
3. Direction Classifier
4. Detection Engine
5. Incident Manager
6. Mitigation Controller
7. Notification Service
8. Public REST API
9. Internal gRPC API
10. Web Application
11. CLI
12. Configuration Service
13. Audit Service
14. Reporting Service
15. Backup and Restore Service

Each service must have:

- Clear responsibility
- Versioned interfaces
- Health endpoint
- Readiness endpoint
- Prometheus metrics
- Structured JSON logs
- Security boundary
- Unit tests
- Integration tests
- Configuration reference
- Operational documentation
- Failure-mode documentation
- Capacity-planning notes

============================================================
6. TELEMETRY COLLECTOR
============================================================

Implement support in this order:

1. IPFIX
2. NetFlow v9
3. NetFlow v5
4. sFlow v5

Collector responsibilities:

- Bind to configurable interfaces
- Bind to configurable UDP ports
- Receive flow packets
- Parse protocol headers
- Decode data records
- Decode template records
- Decode option templates
- Cache templates per exporter
- Handle exporter restarts
- Handle template changes
- Handle sequence-number changes
- Recognize observation domains
- Track exporter uptime
- Apply sampling correction
- Record active and inactive timeout information
- Detect malformed packets
- Detect unknown templates
- Detect unsupported fields
- Track parser failures
- Track socket receive-buffer drops
- Support exporter allowlists
- Support exporter authentication where technically possible
- Support multiple collectors
- Support horizontal partitioning
- Support packet replay for testing

Preferred implementation language:

Rust

Before implementation, create an architecture decision record comparing Rust
and Go based on:

- Memory safety
- Parser safety
- Fuzzing support
- Concurrency
- Performance
- Ecosystem maturity
- Ease of deployment
- Long-term maintenance
- Developer availability

Use no unsafe Rust unless there is a documented and reviewed reason.

All protocol parsers must be fuzz-tested.

============================================================
7. TRAFFIC AGGREGATION
============================================================

Calculate and aggregate:

- Bits per second
- Packets per second
- Flows per second
- Total bytes
- Total packets
- Total flows
- TCP traffic
- UDP traffic
- ICMP traffic
- Fragmented traffic
- TCP SYN traffic
- Dropped traffic when available

Aggregation dimensions:

- Source host
- Destination host
- IPv4 prefix
- IPv6 prefix
- Configurable prefix length
- /24 IPv4 network
- /48 IPv6 network
- Hostgroup
- ASN
- Exporter
- Input interface
- Output interface
- Protocol
- TCP flags
- Tenant
- Customer
- Site
- Data center

Time windows:

- 1 second
- 5 seconds
- 15 seconds
- 30 seconds
- 1 minute
- 5 minutes
- 15 minutes
- 1 hour

Requirements:

- Bounded memory
- Deterministic expiration
- Backpressure
- High-cardinality protection
- Configurable top-N limits
- Accurate sampled-flow correction
- Exporter-specific sampling
- Late-record handling
- Clock-skew handling

============================================================
8. DIRECTION CLASSIFICATION
============================================================

Classify traffic as:

- Incoming
- Outgoing
- Internal
- Other

Use configured local network prefixes.

Rules:

Incoming:

Source is outside local networks and destination is inside local networks.

Outgoing:

Source is inside local networks and destination is outside local networks.

Internal:

Source and destination are both inside local networks.

Other:

Source and destination do not match known local networks or required fields are
missing.

Requirements:

- IPv4 support
- IPv6 support
- Longest-prefix matching
- Tenant-aware prefix ownership
- Prefix conflict detection
- Duplicate prefix detection
- Direction-classification metrics
- Configuration validation
- Unit tests for every direction
- Diagnostic endpoint for explaining classification decisions

============================================================
9. DETECTION ENGINE
============================================================

Implement static threshold detection first.

Supported thresholds:

- Mbps
- PPS
- FPS
- TCP Mbps
- TCP PPS
- UDP Mbps
- UDP PPS
- ICMP Mbps
- ICMP PPS
- TCP SYN Mbps
- TCP SYN PPS
- Fragmented Mbps
- Fragmented PPS
- Dropped Mbps
- Dropped PPS

Threshold scopes:

- Per-host
- Per-prefix
- Total hostgroup
- Total network
- Per-ASN
- Per-exporter interface
- Per-tenant
- Per-customer

Direction support:

- Incoming
- Outgoing
- Both
- Independent directional thresholds

Detection behavior:

- Minimum trigger duration
- Hysteresis
- Cooldown
- Hold-down
- Re-trigger suppression
- Maximum alert frequency
- Maintenance windows
- Allowlist
- Denylist
- Dry-run mode
- Alert-only mode
- Manual mitigation mode
- Automatic mitigation mode

Add statistical detection later:

- EWMA
- Median absolute deviation
- Hour-of-day baseline
- Day-of-week baseline
- Seasonal baseline
- Minimum training period
- Cold-start protection
- Explainable anomaly score
- Confidence score
- Baseline versioning

Attack categories:

- UDP flood
- TCP SYN flood
- TCP flood
- ICMP flood
- Fragmentation flood
- DNS amplification indicator
- NTP amplification indicator
- SSDP amplification indicator
- CLDAP amplification indicator
- Multi-vector attack
- Distributed subnet attack
- Carpet-bomb style attack

Never claim definitive attribution when flow telemetry is insufficient.

============================================================
10. INCIDENT MANAGEMENT
============================================================

Implement an explicit incident state machine:

- Normal
- Suspected
- Confirmed
- AwaitingApproval
- MitigationPending
- Mitigating
- HoldDown
- Recovering
- Closed
- Failed

Each incident must store:

- UUID
- Tenant
- Customer
- Victim
- Prefix
- Direction
- Attack category
- Triggered policy
- Detection metrics
- Baseline metrics
- Threshold
- Exporter
- Interface
- Open time
- Last update
- Close time
- Mitigation history
- Notification history
- Operator actions
- Automation actions
- BGP result
- Rollback result
- Audit records

Implement:

- Deduplication
- Event correlation
- Escalation
- Operator notes
- Evidence attachment
- Timeline
- Status history
- Manual close
- Automatic recovery
- Reopen behavior
- Incident search
- Incident export

============================================================
11. MITIGATION CONTROLLER
============================================================

Integrate with GoBGP through a supported and isolated API.

Support:

- IPv4 RTBH /32
- IPv6 RTBH /128
- Configurable IPv4 parent-prefix announcement
- Configurable IPv6 parent-prefix announcement
- BGP FlowSpec discard
- BGP FlowSpec rate limit
- BGP FlowSpec redirect
- Standard BGP communities
- Large communities
- Configurable next hop
- NO_EXPORT
- NO_ADVERTISE
- AS-path prepend
- Announce
- Withdraw
- Restart reconciliation
- Route ownership
- Stale-route recovery
- Peer-state monitoring

Safety controls:

- Dry-run by default
- BGP disabled by default
- Authorized-prefix allowlist
- Tenant prefix ownership
- Maximum announcement scope
- Minimum and maximum prefix lengths
- Manual approval for first production mitigation
- Emergency global disable switch
- Maximum mitigation duration
- Automatic withdrawal
- Route reconciliation
- Duplicate-action protection
- Idempotency
- Complete audit trail

Never enable or test mitigation against unauthorized networks.

Never generate real attack traffic.

Use synthetic or sanitized telemetry for tests.

============================================================
12. STORAGE ARCHITECTURE
============================================================

Use:

Primary analytics database:

ClickHouse

Legacy and compatibility output:

InfluxDB v1-compatible output plugin

Configuration and metadata:

PostgreSQL

Metrics:

Prometheus

Event transport:

Evaluate NATS JetStream, Redpanda, and Kafka.

Create an architecture decision record selecting the default transport.

ClickHouse must include original schemas for:

- Total IPv4 metrics
- Total IPv6 metrics
- Host metrics
- Top host metrics
- IPv4 network metrics
- IPv6 network metrics
- /24 IPv4 metrics
- Hostgroup metrics
- Total hostgroup metrics
- ASN metrics
- Exporter metrics
- Interface metrics
- Protocol metrics
- Attack events
- Incident events
- Mitigation events
- Traffic samples
- System metrics

For each table define:

- Original table name
- Columns
- Data types
- Partition key
- Order key
- TTL
- Retention
- Materialized views
- Top-N strategy
- Expected write rate
- Expected storage usage
- Migration strategy
- Backup strategy
- Restore strategy

Do not copy proprietary table names or table definitions.

============================================================
13. API DESIGN
============================================================

Implement:

- Versioned REST API
- Internal gRPC API
- OpenAPI specification
- Generated API client
- Authentication
- Authorization
- Rate limiting
- Pagination
- Filtering
- Sorting
- Idempotency keys
- Structured errors
- Request correlation IDs

Required REST resources:

- /api/v1/health
- /api/v1/readiness
- /api/v1/version
- /api/v1/exporters
- /api/v1/traffic/total
- /api/v1/traffic/hosts
- /api/v1/traffic/networks
- /api/v1/traffic/hostgroups
- /api/v1/traffic/asns
- /api/v1/incidents
- /api/v1/incidents/{id}
- /api/v1/mitigations
- /api/v1/mitigations/{id}
- /api/v1/bgp/peers
- /api/v1/bgp/routes
- /api/v1/policies
- /api/v1/tenants
- /api/v1/customers
- /api/v1/users
- /api/v1/roles
- /api/v1/audit
- /api/v1/reports
- /api/v1/system/diagnostics

============================================================
14. COMMAND-LINE INTERFACE
============================================================

Create an original CLI:

tidegardctl

Do not copy fcli syntax, output tables, command names, or internal behavior.

Suggested commands:

- tidegardctl health
- tidegardctl version
- tidegardctl exporters list
- tidegardctl exporters show EXPORTER_ID
- tidegardctl traffic total
- tidegardctl traffic hosts top
- tidegardctl traffic networks top
- tidegardctl traffic hostgroups
- tidegardctl traffic asns
- tidegardctl incidents list
- tidegardctl incidents show INCIDENT_ID
- tidegardctl incidents close INCIDENT_ID
- tidegardctl mitigations list
- tidegardctl mitigations request
- tidegardctl mitigations approve MITIGATION_ID
- tidegardctl mitigations withdraw MITIGATION_ID
- tidegardctl bgp peers
- tidegardctl bgp routes
- tidegardctl policies list
- tidegardctl policies validate
- tidegardctl config check
- tidegardctl backup create
- tidegardctl backup verify
- tidegardctl diagnostics collect

CLI requirements:

- Human-readable output
- JSON output
- YAML output
- Machine-friendly exit codes
- Shell completion
- Secure token handling
- Non-interactive mode
- Context profiles
- Tenant selection
- API endpoint selection
- TLS verification

============================================================
15. WEB APPLICATION
============================================================

Create a modern NOC-focused interface.

Preferred frontend:

- React
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui
- Recharts or Apache ECharts

Required pages:

- Login
- NOC overview
- Total traffic
- Top hosts
- Top networks
- Top hostgroups
- Top ASNs
- Protocol breakdown
- Exporter health
- Interface traffic
- Active incidents
- Incident details
- Mitigation requests
- Active mitigations
- BGP peers
- BGP routes
- Policies
- Customers
- Tenants
- Users
- Roles
- Audit log
- Reports
- System health
- Settings
- Backup and restore
- Diagnostics

Visual design:

- Professional dark NOC theme
- Accessible color palette
- Cacti-inspired traffic colors
- Glossy but restrained stat cards
- Smooth time-series graphs
- Gbps, Mbps, PPS, and FPS units
- Threshold-based colors
- Do not depend only on red and green
- Color-blind-safe alternatives
- Responsive layout
- Full-screen NOC mode
- Configurable refresh
- Time-range selector
- CSV export
- JSON export
- PDF report export
- Tenant-filtered views

============================================================
16. GRAFANA INTEGRATION
============================================================

Create original Grafana dashboards for:

- Total IPv4 traffic
- Total IPv6 traffic
- Incoming Gbps
- Outgoing Gbps
- Incoming PPS
- Outgoing PPS
- FPS
- Traffic by protocol
- Top hosts
- Top /24 networks
- Top hostgroups
- Top ASNs
- Exporter health
- Interface traffic
- Collector parse errors
- Unknown templates
- UDP socket drops
- Database writes
- Database write failures
- Detection incidents
- Active mitigations
- BGP peers
- BGP routes
- Notification failures
- Platform health

Support:

- ClickHouse datasource
- Prometheus datasource
- Optional InfluxDB datasource

Use original dashboard UIDs.

Use original panel layouts.

Use original product branding.

Dashboard JSON must be validated in CI.

============================================================
17. NOTIFICATIONS
============================================================

Support:

- SMTP
- Microsoft Teams
- Slack
- Telegram
- PagerDuty
- Generic webhook
- Prometheus Alertmanager
- Optional SMS plugin

Notifications must include:

- Product name
- Incident ID
- Customer
- Tenant
- Victim
- Prefix
- Direction
- Attack category
- Mbps or Gbps
- PPS
- FPS
- Baseline
- Threshold
- Exporter
- Interface
- Mitigation status
- BGP state
- Incident link
- Dashboard link
- Timestamp
- Recovery status

Notification event types:

- Suspected attack
- Confirmed attack
- Approval requested
- Mitigation started
- Mitigation failed
- Mitigation withdrawn
- Attack recovered
- Incident closed
- Exporter unavailable
- Collector unhealthy
- Database write failure
- BGP peer down

Never store secrets in Git.

============================================================
18. AUTHENTICATION AND RBAC
============================================================

Support:

- Local authentication
- OIDC
- Microsoft Entra ID
- Optional LDAP
- MFA compatibility
- API tokens
- Service accounts
- Session expiration
- Password rotation
- Token rotation
- Account disablement
- Audit trail

Roles:

- SuperAdmin
- PlatformAdmin
- NOCAdmin
- NOCOperator
- SecurityAnalyst
- CustomerAdmin
- CustomerOperator
- CustomerViewer
- ReadOnlyAuditor
- AutomationService

Enforce tenant isolation in:

- API
- Database
- Web application
- CLI
- Reports
- Dashboards
- Notifications
- Audit records

============================================================
19. MULTI-TENANCY
============================================================

Each tenant must have:

- Tenant ID
- Customer metadata
- Authorized prefixes
- Hostgroups
- Detection policies
- Mitigation policies
- BGP attributes
- Notification targets
- Dashboards
- Incidents
- Users
- Roles
- Data retention
- API quotas
- Export quotas
- Audit data

Design for both:

- Single-tenant appliance
- Multi-tenant managed service

============================================================
20. OBSERVABILITY
============================================================

Expose Prometheus metrics for:

- Received flow datagrams
- Parsed packets
- Parsed flow records
- IPv4 flows
- IPv6 flows
- Parser failures
- Unknown templates
- Template cache size
- UDP receive-buffer errors
- Dropped packets
- Event queue depth
- Event queue lag
- Aggregation latency
- Detection latency
- Active hosts
- Active networks
- Active hostgroups
- Active incidents
- Active mitigations
- ClickHouse writes
- ClickHouse failures
- InfluxDB writes
- InfluxDB failures
- PostgreSQL errors
- BGP peer state
- BGP routes announced
- BGP routes withdrawn
- Notification successes
- Notification failures
- API latency
- API errors
- CPU
- Memory
- Disk
- Goroutines or async task count
- Service restart count

Implement:

- Structured JSON logs
- Correlation IDs
- Trace IDs
- Incident IDs
- Tenant IDs
- OpenTelemetry traces
- Configurable log levels
- Sensitive-value redaction

============================================================
21. DEPLOYMENT OPTIONS
============================================================

A. Docker Compose

Include:

- Collector
- Aggregator
- Detector
- Incident manager
- Mitigation controller
- API
- Web UI
- PostgreSQL
- ClickHouse
- Prometheus
- Grafana
- Optional InfluxDB
- Nginx or Caddy
- Backup service

B. Kubernetes

Create:

- Helm chart
- Deployments
- StatefulSets
- Services
- Ingress
- TLS
- Secrets references
- NetworkPolicies
- PodDisruptionBudgets
- HorizontalPodAutoscalers
- PersistentVolumeClaims
- Backup CronJobs
- Migration Jobs
- ServiceMonitor resources
- Grafana provisioning

C. Bare-metal Ubuntu

Support:

- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS
- systemd services
- Secure service users
- Filesystem permissions
- Log rotation
- Automatic health checks
- Upgrade
- Rollback
- Backup
- Restore
- Diagnostic bundle

============================================================
22. GITHUB REPOSITORY
============================================================

The first implementation repository must be professionally structured.

Create this initial monorepo:

tidegard/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── dependabot.yml
│   ├── CODEOWNERS
│   └── workflows/
├── apps/
│   ├── api/
│   ├── web/
│   └── cli/
├── crates/
│   ├── collector/
│   ├── protocol-ipfix/
│   ├── protocol-netflow/
│   ├── protocol-sflow/
│   ├── aggregator/
│   ├── classifier/
│   ├── detector/
│   ├── incident-manager/
│   ├── mitigator/
│   ├── notification/
│   ├── configuration/
│   ├── storage/
│   └── common/
├── deployments/
│   ├── docker-compose/
│   ├── kubernetes/
│   ├── helm/
│   └── systemd/
├── docs/
│   ├── architecture/
│   ├── installation/
│   ├── configuration/
│   ├── integrations/
│   ├── operations/
│   ├── security/
│   ├── development/
│   ├── api/
│   └── commercial/
├── grafana/
│   ├── dashboards/
│   └── provisioning/
├── database/
│   ├── clickhouse/
│   ├── postgres/
│   └── migrations/
├── tests/
│   ├── integration/
│   ├── replay/
│   ├── performance/
│   ├── security/
│   └── fixtures/
├── tools/
│   ├── flow-generator/
│   ├── flow-replay/
│   ├── diagnostics/
│   └── migration/
├── scripts/
├── examples/
├── branding/
├── mkdocs.yml
├── Cargo.toml
├── Makefile
├── Taskfile.yml
├── docker-compose.yml
├── LICENSE
├── NOTICE
├── SECURITY.md
├── SUPPORT.md
├── CONTRIBUTING.md
├── GOVERNANCE.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── ROADMAP.md
└── README.md

Repository requirements:

- Professional README
- Product overview
- Architecture diagram
- Quick-start guide
- Screenshots placeholder
- Security policy
- Contribution policy
- Support policy
- Governance model
- Code of conduct
- License
- Notice file
- Changelog
- Roadmap
- Issue templates
- Pull-request template
- CODEOWNERS
- Dependabot
- Branch protection recommendations
- Semantic release
- Conventional commits

============================================================
23. GITHUB ACTIONS CI/CD
============================================================

Create workflows for:

1. Pull-request validation
2. Rust formatting
3. Rust linting
4. Unit tests
5. Integration tests
6. Fuzz tests
7. Frontend lint
8. Frontend tests
9. API tests
10. Database migration tests
11. Grafana JSON validation
12. Shellcheck
13. Docker builds
14. Multi-architecture image builds
15. Dependency review
16. Container vulnerability scanning
17. Secret scanning
18. SBOM generation
19. Signed container images
20. Documentation builds
21. Documentation deployment
22. Staging deployment
23. Production deployment with approval
24. Backup verification
25. Restore test
26. Release packaging
27. Checksum generation
28. GitHub release
29. Changelog generation

Use:

- GitHub environment secrets
- Least privilege
- Pinned action versions
- Build provenance
- Artifact retention policies
- Production approval gates

Do not store credentials in workflows.

============================================================
24. TESTING REQUIREMENTS
============================================================

Required tests:

- Unit tests
- Integration tests
- End-to-end tests
- Protocol-parser tests
- Property-based tests
- Fuzz tests
- Malformed-packet tests
- Template-cache tests
- Sampling tests
- Direction-classification tests
- Prefix-overlap tests
- Threshold tests
- Hysteresis tests
- Cooldown tests
- Baseline tests
- Incident state-machine tests
- BGP dry-run tests
- BGP reconciliation tests
- Unauthorized-prefix tests
- Multi-tenant isolation tests
- RBAC tests
- API authorization tests
- Database migration tests
- Retention tests
- Backup tests
- Restore tests
- Load tests
- Soak tests
- Failover tests
- Upgrade tests
- Rollback tests

Create a safe telemetry generator and replay tool.

Use only:

- Synthetic telemetry
- Sanitized telemetry
- Lab networks
- Authorized environments

============================================================
25. DOCUMENTATION
============================================================

Documentation is a mandatory product component.

Use MkDocs Material unless an architecture decision selects Docusaurus.

Create:

- Product overview
- Installation guide
- Quick start
- Architecture
- Component documentation
- Data-flow diagrams
- Sequence diagrams
- Threat model
- Configuration reference
- IPFIX collector guide
- NetFlow guide
- sFlow guide
- Cisco NCS540 integration
- Generic router integration
- ClickHouse guide
- InfluxDB compatibility guide
- Prometheus guide
- Grafana guide
- Threshold guide
- Baseline guide
- Hostgroup guide
- Incident guide
- BGP RTBH guide
- BGP FlowSpec guide
- Notification guide
- API guide
- CLI guide
- RBAC guide
- Multi-tenancy guide
- Backup guide
- Restore guide
- Upgrade guide
- Rollback guide
- Troubleshooting guide
- Security hardening
- Capacity planning
- Performance tuning
- NOC operations runbook
- Incident response runbook
- Customer onboarding
- Customer offboarding
- Release process
- Open-source compliance report
- Commercial deployment guide

Every configuration option must include:

- Name
- Type
- Default value
- Allowed values
- Example
- Security implications
- Reload requirement
- Related metrics
- Verification command
- Troubleshooting steps

Documentation must be updated in the same pull request as the corresponding
feature.

============================================================
26. SECURITY REQUIREMENTS
============================================================

Create a formal threat model covering:

- Malformed flow packets
- Parser vulnerabilities
- Template-cache poisoning
- Exporter spoofing
- UDP collector DoS
- High-cardinality attacks
- Queue exhaustion
- Database exhaustion
- API abuse
- Authentication attacks
- Authorization bypass
- Tenant escape
- Privilege escalation
- Secret leakage
- Webhook SSRF
- Log injection
- Dashboard injection
- BGP route leaks
- Overly broad blackhole routes
- Stale mitigation routes
- Compromised CI/CD
- Dependency compromise
- Backup compromise
- Restore compromise

Apply:

- Least privilege
- Rootless services where practical
- Dedicated service accounts
- Read-only filesystems
- Seccomp
- AppArmor
- Network policies
- TLS
- Optional mTLS
- Secret managers
- Signed artifacts
- SBOMs
- Dependency pinning
- Reproducible builds where possible
- Input validation
- Rate limiting
- Audit logging
- Secure defaults

============================================================
27. COMMERCIAL READINESS
============================================================

Design clear boundaries for:

Community Edition:

- Open telemetry collector
- Core aggregation
- Static detection
- Basic incidents
- Prometheus
- Grafana dashboards
- Manual mitigation
- Community support

Enterprise Edition proposal:

- Multi-tenancy
- Advanced RBAC
- SSO
- Audit retention
- Advanced anomaly detection
- Approval workflows
- Reporting
- Enterprise support
- HA deployment
- Premium integrations

Managed Service proposal:

- Hosted control plane
- Multi-customer monitoring
- Managed NOC
- Managed mitigation
- SLA
- Customer portal
- Usage reporting
- Subscription management

Do not implement artificial limitations in the open-source core during the MVP.

Document potential commercial pricing dimensions without inventing final prices:

- Monitored bandwidth
- Flow records per second
- Exporters
- Protected prefixes
- Tenants
- Data retention
- Automated mitigation
- Managed support
- SLA
- Premium integrations

============================================================
28. VERSIONING AND RELEASES
============================================================

Use semantic versioning.

Initial milestones:

- v0.1.0: Repository and architecture
- v0.2.0: IPFIX collector
- v0.3.0: Aggregation and direction classification
- v0.4.0: ClickHouse and Prometheus metrics
- v0.5.0: Static detection
- v0.6.0: Incident lifecycle
- v0.7.0: Grafana and native UI
- v0.8.0: Notification integrations
- v0.9.0: BGP mitigation lab
- v1.0.0: Production-ready single-tenant release
- v1.1.0: Multi-tenancy
- v1.2.0: Enterprise authentication
- v2.0.0: Distributed high-availability architecture

Each release must include:

- Changelog
- Release notes
- Upgrade guide
- Rollback guide
- Checksums
- SBOM
- Signed artifacts
- Migration notes
- Known issues
- Test summary

============================================================
29. PHASED DELIVERY MODEL
============================================================

Work phase by phase.

Do not proceed to the next phase until the current phase:

- Has documented output
- Has acceptance criteria
- Passes required tests
- Has a summary
- Has an explicit decision record
- Has a commit
- Has updated documentation

PHASE 0: Product foundation and clean-room boundary

Deliver:

- Product charter
- Product naming decision
- Clean-room boundary
- Functional requirements
- Non-functional requirements
- Open-source dependency candidates
- License matrix
- Commercial-use implications
- Risk register
- Architecture options
- MVP scope
- Out-of-scope list
- Roadmap
- Acceptance criteria
- Blocking questions

No production code.

PHASE 1: GitHub repository and documentation foundation

Deliver:

- Monorepo skeleton
- README
- LICENSE recommendation
- NOTICE
- SECURITY
- CONTRIBUTING
- CODE_OF_CONDUCT
- GOVERNANCE
- SUPPORT
- ROADMAP
- CHANGELOG
- MkDocs skeleton
- Architecture decision record template
- Issue templates
- Pull-request template
- CODEOWNERS
- Dependabot
- Validation CI
- Local development setup
- Makefile
- Taskfile

PHASE 2: IPFIX collector MVP

Deliver:

- IPFIX parser
- Template cache
- Exporter tracking
- Sampling correction
- Prometheus metrics
- Structured logs
- Replay tool
- Unit tests
- Property tests
- Fuzz tests
- Documentation

PHASE 3: Aggregation and classification

Deliver:

- Host aggregation
- Network aggregation
- /24 aggregation
- Hostgroups
- ASN aggregation
- Incoming classification
- Outgoing classification
- Internal classification
- Other classification
- Prefix configuration
- ClickHouse output
- Tests
- Documentation

PHASE 4: Detection engine

Deliver:

- Static thresholds
- Per-host detection
- Per-prefix detection
- Total hostgroup detection
- Hysteresis
- Cooldown
- Dry-run
- Alert-only mode
- Tests
- Documentation

PHASE 5: Incident management

Deliver:

- Incident state machine
- PostgreSQL schemas
- REST API
- CLI commands
- Audit trail
- Operator notes
- Tests
- Documentation

PHASE 6: Dashboards and notifications

Deliver:

- ClickHouse Grafana dashboards
- Prometheus dashboards
- InfluxDB compatibility dashboards
- Native NOC UI
- Email
- Teams
- Slack
- Telegram
- Webhook
- Documentation

PHASE 7: BGP mitigation lab

Deliver:

- GoBGP integration
- Dry-run
- Prefix allowlist
- RTBH
- Parent-prefix announcement
- FlowSpec
- Withdrawal
- Reconciliation
- Lab tests
- Safety documentation

Production BGP remains disabled by default.

PHASE 8: Multi-tenancy and RBAC

Deliver:

- Tenants
- Customer accounts
- Prefix ownership
- Tenant-scoped data
- RBAC
- OIDC
- Entra ID design
- Audit
- Tests
- Documentation

PHASE 9: Production hardening

Deliver:

- Load tests
- Soak tests
- Security review
- Parser fuzzing report
- Backup
- Restore
- Disaster recovery
- Upgrade
- Rollback
- Packaging
- Signed release
- SBOM
- Capacity planning

PHASE 10: v1.0 release

Deliver:

- v1.0.0 release candidate
- Full documentation
- Production checklist
- Security checklist
- Release notes
- Upgrade guide
- Rollback guide
- Customer onboarding guide
- Commercial deployment guide
- Signed artifacts
- GitHub release

============================================================
30. WORKING BEHAVIOR FOR CLAUDE CODE
============================================================

Follow these operating rules:

1. Inspect the repository before making changes.
2. Summarize proposed changes before large modifications.
3. Do not overwrite existing work without reviewing it.
4. Use small, focused commits.
5. Suggest commit messages using Conventional Commits.
6. Update documentation with every feature.
7. Add tests before marking a feature complete.
8. Run formatting, linting, tests, and validation.
9. Report commands executed and results.
10. Do not claim tests passed unless they were actually executed.
11. Mark unverified assumptions clearly.
12. Do not generate fake benchmark results.
13. Do not generate fake security claims.
14. Do not enable production BGP.
15. Do not commit secrets.
16. Do not include customer data.
17. Do not use public IPs for unsafe testing.
18. Never generate real DDoS traffic.
19. Use synthetic flow fixtures.
20. Stop when a major architecture decision requires approval.

At the end of every phase, produce:

- Completed items
- Files created
- Files modified
- Tests executed
- Test results
- Security considerations
- License considerations
- Documentation created
- Known limitations
- Risks
- Next phase
- Recommended commit message

============================================================
31. FIRST EXECUTION
============================================================

Execute PHASE 0 only.

Do not write production code.

Create these files:

docs/product-charter.md
docs/clean-room-boundary.md
docs/functional-requirements.md
docs/non-functional-requirements.md
docs/architecture-options.md
docs/technology-options.md
docs/dependency-license-matrix.md
docs/commercial-boundaries.md
docs/security-principles.md
docs/mvp-scope.md
docs/out-of-scope.md
docs/risk-register.md
docs/roadmap.md
docs/acceptance-criteria.md
docs/blocking-questions.md
docs/naming-and-branding.md

The first response must include:

1. Executive summary
2. Repository inspection result
3. Assumptions
4. Proposed Phase 0 files
5. Major architecture options
6. Recommended technology direction
7. Open-source license concerns
8. Commercial-use concerns
9. Security boundaries
10. MVP recommendation
11. Blocking questions
12. Proposed commit message

Do not ask minor questions.

Ask only questions that genuinely block architecture decisions.

Do not proceed to Phase 1 until Phase 0 has been reviewed.

