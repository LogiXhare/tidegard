//! WetechiNetMon Telemetry Collector.
//!
//! Binds a UDP socket, decodes incoming IPFIX messages via
//! `wetechinetmon-protocol-ipfix`, normalizes Data Records into
//! `NormalizedFlow`s (Phase 3), classifies their direction
//! (`wetechinetmon-classifier`), and aggregates them
//! (`wetechinetmon-aggregator`). Exposes Prometheus metrics on a
//! separate HTTP port. See docs/functional-requirements.md (FR-1, FR-2,
//! FR-3) — NetFlow v9/v5 and sFlow v5 support are later phases.
//!
//! **Pipeline shape (ADR 0004):** the UDP receive loop and the
//! classify/aggregate stage run as two tasks connected by a bounded
//! in-process channel — not a separate OS process, not NATS (yet). The
//! channel's bounded capacity is both the backpressure control and the
//! `queue_depth` metric.

pub mod clickhouse_export;
pub mod config;
pub mod detection;
pub mod exporter;
pub mod incident_inbox;
pub mod metrics;
pub mod normalize;
pub mod pipeline;

/// The name of every metric the collector's `/metrics` endpoint can
/// export, Vec metrics included before they have a label value. The
/// Grafana dashboard check (ADR 0041) refuses a panel that queries
/// anything else.
pub fn metric_names() -> Vec<String> {
    let (metrics, registry) = metrics::Metrics::new().expect("a fresh registry has no collisions");
    let mut names = metrics.metric_names();
    names.extend(
        detection::DetectionPrometheusMetrics::new(&registry)
            .expect("a fresh registry has no collisions")
            .metric_names(),
    );
    names.extend(incident_inbox::metric_names());
    names
}

/// Kept at its old path; the endpoint now lives in `wetechinetmon-common`.
pub use wetechinetmon_common::metrics_server;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::time::SystemTime;

use tokio::net::UdpSocket;
use wetechinetmon_classifier::{build_registry, classify, Direction};
use wetechinetmon_protocol_ipfix::{decode_message, DecodedSet};

pub use config::Config;
pub use exporter::ExporterRegistry;
pub use metrics::Metrics;
pub use pipeline::{Pipeline, SamplingConfig};

/// Maximum UDP datagram size we'll attempt to read. IPFIX messages are
/// bounded by the 16-bit Length field in the header (max 65535), and
/// real-world exporters targeting UDP stay well under the common 1500
/// byte path MTU to avoid IP fragmentation — 65535 is a safe upper bound
/// that costs one fixed-size buffer per receive, not a per-connection
/// allocation.
const MAX_DATAGRAM_SIZE: usize = 65535;

/// How often the aggregator sweeps for inactivity expiration.
const EXPIRATION_INTERVAL: Duration = Duration::from_secs(30);

/// How often the aggregator's current state is snapshotted and pushed
/// toward ClickHouse (only relevant when ClickHouse export is
/// configured).
const CLICKHOUSE_EXPORT_INTERVAL: Duration = Duration::from_secs(15);

/// Runs the collector until the process is asked to stop (Ctrl+C or, on
/// Unix, SIGTERM) or an unrecoverable I/O error occurs binding a socket.
pub async fn run(config: Config) -> std::io::Result<()> {
    run_until(config, std::future::pending()).await
}

/// [`run`], also stopping when `shutdown` completes, so a test can run the
/// real collector in-process and stop it cleanly.
pub async fn run_until(
    config: Config,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    tokio::pin!(shutdown);
    let (metrics, registry) =
        Metrics::new().expect("metric registration should never collide at startup");
    let metrics_registry = registry.clone();
    let registry = Arc::new(registry);

    let metrics_addr = config.metrics_bind;
    let readiness = metrics_server::Readiness::new();
    let served = readiness.clone();
    let metrics_server = tokio::spawn(async move {
        if let Err(err) = metrics_server::serve(metrics_addr, registry, served).await {
            tracing::error!(error = %err, "metrics server exited with an error");
        }
    });

    let socket = Arc::new(UdpSocket::bind(config.bind).await?);
    tracing::info!(bind = %config.bind, "IPFIX collector listening");
    // Bound means flows are received; nothing later in startup can fail.
    readiness.set(true);

    let prefix_report = build_registry(&config.local_prefixes).unwrap_or_else(|errors| {
        // A prefix-config error is a startup-quality problem, but Phase 3
        // treats it as "run with an empty registry" (Direction::Unknown
        // for everything) rather than refusing to start entirely — the
        // collector's job (decode/normalize/aggregate) is still useful
        // even with direction classification degraded. Every error is
        // still logged loudly.
        for e in &errors {
            tracing::error!(error = %e, "invalid local-prefix configuration entry, ignoring it");
        }
        wetechinetmon_classifier::build_registry(&[]).expect("empty prefix list always validates")
    });
    for warning in &prefix_report.warnings {
        tracing::warn!(message = %warning.message, "local-prefix overlap");
    }

    let aggregator_config = wetechinetmon_aggregator::AggregatorConfig {
        max_hosts: config.max_hosts,
        max_networks: config.max_networks,
        max_hostgroups: config.max_hostgroups,
        max_asns: config.max_asns,
        inactivity_ttl: Duration::from_secs(config.inactivity_ttl_secs),
        ..Default::default()
    };
    let sampling_config = SamplingConfig {
        global_default: config.sampling_global_default,
        per_exporter: Default::default(),
    };
    let mut pipeline = Pipeline::new(
        prefix_report.registry,
        aggregator_config,
        sampling_config,
        Instant::now(),
    );

    // Detection is off unless a policy document is configured. A
    // failure to read or compile it disables detection for this run
    // rather than stopping the collector: decode/normalize/aggregate
    // stays useful, and a collector that refuses to start over a typo in
    // one policy is a collector that loses telemetry to a config error.
    // The incident inbox (ADR 0036) follows the same rule: if it cannot
    // start, detection still runs and the error says incidents will not be
    // opened.
    let mut incident_inbox: Option<incident_inbox::IncidentInbox> = None;
    let mut detection = match &config.detection_policy_file {
        Some(path) => match detection::load_policy_file(path) {
            Ok(policies) => {
                let count = policies.policies.len();
                // A policy whose window differs from the collector's is never
                // evaluated (the detector counts it as windowMismatch). Say so
                // at startup, by name, rather than detect nothing quietly.
                let window = Duration::from_secs(config.detection_window_secs);
                for policy in policies.policies.iter().filter(|p| p.window != window) {
                    tracing::error!(
                        policy = %policy.id,
                        policy_window_secs = policy.window.as_secs_f64(),
                        collector_window_secs = config.detection_window_secs,
                        "this policy will never be evaluated: its window differs from WETECHINETMON_COLLECTOR_DETECTION_WINDOW_SECS"
                    );
                }
                let extra_sinks = match &config.incident_database {
                    Some(database) => {
                        let tenants: std::collections::BTreeSet<String> = policies
                            .policies
                            .iter()
                            .map(|policy| policy.tenant.clone())
                            .collect();
                        start_incident_inbox(database, tenants, &metrics_registry)
                            .map(|inbox| {
                                let sink = inbox.sink();
                                incident_inbox = Some(inbox);
                                vec![sink]
                            })
                            .unwrap_or_default()
                    }
                    None => Vec::new(),
                };
                let clickhouse_sink = config.clickhouse.as_ref().map(|_| {
                    Arc::new(detection::ClickHouseEventSink::new(
                        config.detection_event_buffer,
                    ))
                });
                match detection::DetectionPrometheusMetrics::new(&metrics_registry) {
                    Ok(detection_metrics) => {
                        tracing::info!(path, policies = count, "detection engine enabled");
                        Some(detection::DetectionStage::new(
                            detection::DetectionStageConfig {
                                window: wetechinetmon_detector::WindowConfig {
                                    window: Duration::from_secs(config.detection_window_secs),
                                    max_hosts: config.detection_max_scopes,
                                    max_networks: config.detection_max_scopes,
                                    max_slash24: config.detection_max_scopes,
                                    max_hostgroups: config.max_hostgroups,
                                },
                                engine: wetechinetmon_detector::EngineConfig {
                                    state: wetechinetmon_detector::StateTableConfig {
                                        max_entries: config.detection_max_scopes,
                                        idle_ttl: Duration::from_secs(config.inactivity_ttl_secs),
                                        stale_after: Duration::from_secs(
                                            config.detection_stale_secs,
                                        ),
                                    },
                                },
                                event_buffer: config.detection_event_buffer,
                            },
                            policies,
                            Arc::new(detection_metrics),
                            clickhouse_sink,
                            extra_sinks,
                            Instant::now(),
                        ))
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "detection metrics failed to register; detection disabled for this run");
                        None
                    }
                }
            }
            Err(err) => {
                tracing::error!(path, error = %err, "detection policies could not be loaded; detection disabled for this run");
                None
            }
        },
        None => {
            tracing::info!("no detection policy file configured; detection is off");
            if config.incident_database.is_some() {
                tracing::warn!("an incident database is configured but detection is off, so no detection events will reach it");
            }
            None
        }
    };
    let mut detection_interval = tokio::time::interval(detection::TICK_INTERVAL);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(config.queue_capacity);

    let receiver_task = tokio::spawn(receive_loop(
        Arc::clone(&socket),
        tx,
        metrics.datagrams_received_total.clone(),
        metrics.queue_depth.clone(),
    ));

    let mut exporters = ExporterRegistry::new();
    let mut expire_interval = tokio::time::interval(EXPIRATION_INTERVAL);

    // ClickHouse export is entirely optional — see
    // docs/integrations/clickhouse.md. A connection/migration failure at
    // startup disables export for this run rather than crashing the
    // collector; decode/normalize/aggregate remains useful without it.
    let mut clickhouse_exporters = match &config.clickhouse {
        Some(settings) => {
            let url = settings.display_url();
            match settings.connect() {
                Err(err) => {
                    tracing::error!(url, error = %err, "ClickHouse cannot be reached; export disabled for this run");
                    None
                }
                Ok(client) => match wetechinetmon_storage::run_migrations(&client).await {
                    Ok(()) => {
                        tracing::info!(url, "ClickHouse export enabled, migrations applied");
                        Some(clickhouse_export::ClickHouseExporters::new(
                            client,
                            Instant::now(),
                        ))
                    }
                    Err(err) => {
                        tracing::error!(url, error = %err, "ClickHouse migration failed; export disabled for this run");
                        None
                    }
                },
            }
        }
        None => None,
    };
    let mut clickhouse_interval = tokio::time::interval(CLICKHOUSE_EXPORT_INTERVAL);

    loop {
        tokio::select! {
            received = rx.recv() => {
                match received {
                    Some((bytes, src)) => {
                        metrics.queue_depth.dec();
                        process_datagram(
                            &bytes,
                            src,
                            &mut exporters,
                            &mut pipeline,
                            detection.as_mut(),
                            &metrics,
                        );
                    }
                    None => {
                        tracing::warn!("UDP receive task ended; stopping collector");
                        break;
                    }
                }
            }
            _ = expire_interval.tick() => {
                let expired = pipeline.aggregator.expire_inactive(Instant::now());
                if expired > 0 {
                    metrics.expired_entries_total.inc_by(expired as u64);
                    tracing::debug!(expired, "swept inactive aggregation entries");
                }
            }
            _ = detection_interval.tick(), if detection.is_some() => {
                if let Some(stage) = detection.as_mut() {
                    let report = stage.tick(Instant::now(), SystemTime::now());
                    if let Some(inbox) = incident_inbox.as_ref() {
                        inbox.refresh();
                    }
                    if report.events_built > 0 {
                        tracing::debug!(
                            opened = report.detections_opened,
                            closed = report.detections_closed,
                            built = report.events_built,
                            published = report.events_published,
                            failed = report.events_failed,
                            "detection cycle produced events"
                        );
                    }
                }
            }
            _ = clickhouse_interval.tick(), if clickhouse_exporters.is_some() => {
                if let Some(exporters) = clickhouse_exporters.as_mut() {
                    let now = Instant::now();
                    let ts = time::OffsetDateTime::now_utc();
                    exporters.snapshot(&pipeline.aggregator, ts);
                    if let Some(stage) = detection.as_ref() {
                        for row in stage.drain_rows() {
                            exporters.push_detection_event(row);
                        }
                    }
                    let report = exporters.tick(now).await;
                    metrics.clickhouse_rows_written_total.inc_by(report.rows_written as u64);
                    metrics.clickhouse_write_failures_total.inc_by(report.write_failures as u64);
                    metrics.clickhouse_retry_queue_dropped_total.inc_by(report.retry_queue_dropped as u64);
                    if report.permanently_dropped_batches > 0 {
                        tracing::error!(
                            batches = report.permanently_dropped_batches,
                            "ClickHouse batches permanently dropped after exhausting retries"
                        );
                    }
                }
            }
            () = &mut shutdown => {
                tracing::info!("shutdown requested, shutting down");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Ctrl+C received, shutting down");
                break;
            }
            _ = wait_for_terminate() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
        }
    }

    if let Some(inbox) = incident_inbox.take() {
        let report = inbox.shutdown().await;
        if report.abandoned > 0 {
            tracing::error!(
                abandoned = report.abandoned,
                "detection events could not be written to the incident inbox before shutdown and are lost"
            );
        }
        tracing::info!(
            enqueued = report.enqueued,
            failed_writes = report.failed_writes,
            "incident inbox flushed"
        );
    }
    receiver_task.abort();
    metrics_server.abort();
    Ok(())
}

/// Starts the incident inbox, logging how it connects or why it could not
/// start.
fn start_incident_inbox(
    database: &config::IncidentDatabase,
    tenants: std::collections::BTreeSet<String>,
    registry: &prometheus::Registry,
) -> Option<incident_inbox::IncidentInbox> {
    let count = tenants.len();
    match incident_inbox::IncidentInbox::start(database, tenants, registry) {
        Ok((inbox, transport)) => {
            match transport {
                wetechinetmon_incident_postgres::connect::Transport::VerifiedTls => {
                    tracing::info!(tenants = count, "incident inbox enabled over verified TLS")
                }
                wetechinetmon_incident_postgres::connect::Transport::LoopbackPlaintext => {
                    tracing::warn!(
                        tenants = count,
                        "incident inbox enabled without TLS, allowed only because the database is on this host"
                    )
                }
            }
            Some(inbox)
        }
        Err(err) => {
            tracing::error!(error = %err, "incident inbox could not start; detection events will not become incidents this run");
            None
        }
    }
}

async fn receive_loop(
    socket: Arc<UdpSocket>,
    tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    datagrams_received_total: prometheus::IntCounter,
    queue_depth: prometheus::IntGauge,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                datagrams_received_total.inc();
                queue_depth.inc();
                // A bounded channel makes `send` apply real backpressure
                // (ADR 0004 / FR-2.4 "queue limits"): if the
                // classify/aggregate stage falls behind, this await
                // blocks here rather than growing memory without bound.
                if tx.send((buf[..len].to_vec(), src)).await.is_err() {
                    break; // receiver dropped — shutting down
                }
            }
            Err(err) => {
                tracing::error!(error = %err, "UDP recv_from failed");
            }
        }
    }
}

/// On Unix, resolves when SIGTERM is received (the signal container
/// runtimes and systemd send for graceful shutdown). On other platforms,
/// never resolves — Ctrl+C handling above is the only shutdown signal
/// there. Platform-specific by necessity (Phase 2 follow-up item).
#[cfg(unix)]
async fn wait_for_terminate() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to install SIGTERM handler");
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_terminate() {
    std::future::pending::<()>().await;
}

/// Decodes one received datagram, normalizes/classifies/aggregates any
/// Data Records within it, and updates metrics/logs accordingly. Split
/// out from `run` specifically so it can be unit-tested without a real
/// socket (see the tests below).
fn process_datagram(
    bytes: &[u8],
    src: std::net::SocketAddr,
    registry: &mut ExporterRegistry,
    pipeline: &mut Pipeline,
    mut detection: Option<&mut detection::DetectionStage>,
    metrics: &Metrics,
) {
    // Peek the header first (cheap — 16 bytes, no allocation) purely to
    // get the sequence number for restart detection *before* we hand the
    // (possibly stale) template cache to the full decoder.
    let header = match wetechinetmon_protocol_ipfix::MessageHeader::parse(bytes) {
        Ok(h) => h,
        Err(err) => {
            metrics.parser_failures_total.inc();
            tracing::warn!(%src, error = %err, "failed to parse IPFIX message header");
            return;
        }
    };

    let exporter = registry.get_or_create(src);
    if exporter.observe_sequence(header.sequence_number) {
        metrics.exporter_restarts_total.inc();
        tracing::warn!(%src, sequence_number = header.sequence_number, "exporter restart detected, template cache cleared");
    }

    match decode_message(bytes, &mut exporter.template_cache) {
        Ok(message) => {
            for set in &message.sets {
                match set {
                    DecodedSet::Templates(templates) => {
                        metrics
                            .sets_by_kind_total
                            .with_label_values(&["templates"])
                            .inc();
                        tracing::debug!(%src, count = templates.len(), "received Template Set");
                    }
                    DecodedSet::OptionsTemplates(templates) => {
                        metrics
                            .sets_by_kind_total
                            .with_label_values(&["options_templates"])
                            .inc();
                        tracing::debug!(%src, count = templates.len(), "received Options Template Set");
                    }
                    DecodedSet::Data { records, .. } => {
                        metrics
                            .sets_by_kind_total
                            .with_label_values(&["data"])
                            .inc();
                        metrics
                            .parsed_flow_records_total
                            .inc_by(records.len() as u64);

                        let options_sampling = exporter.template_cache.sampling();
                        let external_sampling = pipeline.sampling.for_exporter(src.ip());

                        for record in records {
                            if record.fields.iter().any(|f| f.value.len() == 4) {
                                metrics.ipv4_flows_total.inc();
                            }
                            if record.fields.iter().any(|f| f.value.len() == 16) {
                                metrics.ipv6_flows_total.inc();
                            }

                            let start = Instant::now();
                            match normalize::normalize_ipfix_record(
                                record,
                                src.ip(),
                                header.observation_domain_id,
                                options_sampling,
                                external_sampling,
                            ) {
                                Ok(outcome) => {
                                    metrics.normalized_flows_total.inc();
                                    if outcome.flow.sampling_rate.get() > 1 {
                                        metrics.corrected_samples_total.inc();
                                    }
                                    if outcome.zero_rate_skipped {
                                        metrics.sampling_errors_total.inc();
                                    }
                                    if matches!(
                                        outcome.flow.protocol,
                                        Some(wetechinetmon_common::Protocol::Other(_))
                                    ) {
                                        metrics.unsupported_protocol_fields_total.inc();
                                    }

                                    let classification =
                                        classify(&pipeline.prefixes, &outcome.flow);
                                    let direction_label = match classification.direction {
                                        Direction::Incoming => "incoming",
                                        Direction::Outgoing => "outgoing",
                                        Direction::Internal => "internal",
                                        Direction::Other => "other",
                                        Direction::Unknown => "unknown",
                                    };
                                    metrics
                                        .classified_flows_by_direction_total
                                        .with_label_values(&[direction_label])
                                        .inc();
                                    if classification.direction == Direction::Unknown {
                                        metrics.prefix_lookup_failures_total.inc();
                                    }

                                    let now = Instant::now();
                                    if let Some(stage) = detection.as_deref_mut() {
                                        stage.ingest(
                                            &pipeline.prefixes,
                                            &outcome.flow,
                                            &classification,
                                            now,
                                        );
                                    }
                                    let ingest_report = pipeline.aggregator.ingest(
                                        &outcome.flow,
                                        &classification,
                                        now,
                                    );
                                    metrics
                                        .evicted_entries_total
                                        .inc_by(ingest_report.evictions as u64);

                                    metrics
                                        .aggregation_latency_seconds
                                        .observe(start.elapsed().as_secs_f64());
                                }
                                Err(err) => {
                                    metrics.incomplete_records_total.inc();
                                    tracing::debug!(%src, error = %err, "record could not be normalized");
                                }
                            }
                        }
                    }
                    DecodedSet::UnknownTemplate { template_id } => {
                        metrics
                            .sets_by_kind_total
                            .with_label_values(&["unknown_template"])
                            .inc();
                        metrics.unknown_templates_total.inc();
                        tracing::debug!(%src, template_id, "data set references unknown template");
                    }
                    DecodedSet::ReservedSetId { set_id } => {
                        metrics
                            .sets_by_kind_total
                            .with_label_values(&["reserved_set_id"])
                            .inc();
                        metrics.reserved_set_id_total.inc();
                        tracing::warn!(%src, set_id, "received reserved/invalid Set ID");
                    }
                }
            }
        }
        Err(err) => {
            metrics.parser_failures_total.inc();
            tracing::warn!(%src, error = %err, "failed to decode IPFIX message body");
        }
    }

    metrics
        .template_cache_size
        .set(registry.total_template_count() as i64);
    metrics
        .active_exporters
        .set(registry.exporter_count() as i64);
    metrics
        .active_hosts
        .set(pipeline.aggregator.active_hosts() as i64);
    metrics
        .active_networks
        .set(pipeline.aggregator.active_networks() as i64);
    metrics
        .active_hostgroups
        .set(pipeline.aggregator.active_hostgroups() as i64);
    metrics
        .active_asns
        .set(pipeline.aggregator.active_asns() as i64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use wetechinetmon_classifier::PrefixConfigEntry;

    /// Every metric is named once, under the product prefix, and the
    /// three groups (collector, detector, incident inbox) are all there.
    #[test]
    fn metric_names_are_unique_and_prefixed() {
        let names = metric_names();
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "{names:?}");
        assert!(names.iter().all(|name| name.starts_with("wetechinetmon_")));
        for name in [
            "wetechinetmon_collector_flow_datagrams_received_total",
            "wetechinetmon_detector_scopes_in_state",
            "wetechinetmon_collector_incident_inbox_queued",
        ] {
            assert!(names.iter().any(|n| n == name), "{name}");
        }
    }

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    fn message_header_bytes(length: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x000au16.to_be_bytes());
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&7u32.to_be_bytes());
        b
    }

    fn test_pipeline() -> Pipeline {
        let report = build_registry(&[PrefixConfigEntry {
            network: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            tenant: "wetechi".to_string(),
            hostgroup: Some("core".to_string()),
        }])
        .unwrap();
        Pipeline::new(
            report.registry,
            wetechinetmon_aggregator::AggregatorConfig::default(),
            SamplingConfig::default(),
            Instant::now(),
        )
    }

    fn template_set_bytes(ie_len_pairs: &[(u16, u16)]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&256u16.to_be_bytes());
        record.extend_from_slice(&(ie_len_pairs.len() as u16).to_be_bytes());
        for (ie, len) in ie_len_pairs {
            record.extend_from_slice(&ie.to_be_bytes());
            record.extend_from_slice(&len.to_be_bytes());
        }
        let mut set = Vec::new();
        set.extend_from_slice(&2u16.to_be_bytes());
        set.extend_from_slice(&((4 + record.len()) as u16).to_be_bytes());
        set.extend_from_slice(&record);
        set
    }

    #[test]
    fn malformed_header_increments_parser_failures_without_panicking() {
        let (metrics, _registry) = Metrics::new().unwrap();
        let mut exporters = ExporterRegistry::new();
        let mut pipeline = test_pipeline();
        process_datagram(
            &[0xFF, 0xFF, 0xFF],
            addr(),
            &mut exporters,
            &mut pipeline,
            None,
            &metrics,
        );
        assert_eq!(metrics.parser_failures_total.get(), 1);
    }

    #[test]
    fn a_full_ipfix_flow_is_normalized_classified_and_aggregated() {
        let (metrics, _registry) = Metrics::new().unwrap();
        let mut exporters = ExporterRegistry::new();
        let mut pipeline = test_pipeline();

        // Template: sourceIPv4Address(8,4), destinationIPv4Address(12,4),
        // octetDeltaCount(1,8), packetDeltaCount(2,8).
        let set = template_set_bytes(&[(8, 4), (12, 4), (1, 8), (2, 8)]);
        let mut msg1 = message_header_bytes((16 + set.len()) as u16);
        msg1.extend_from_slice(&set);
        process_datagram(&msg1, addr(), &mut exporters, &mut pipeline, None, &metrics);
        assert_eq!(metrics.parser_failures_total.get(), 0);

        // Data: source 203.0.113.1 (external) -> destination 10.0.0.5 (local) => Incoming.
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[203, 0, 113, 1]);
        record_bytes.extend_from_slice(&[10, 0, 0, 5]);
        record_bytes.extend_from_slice(&1000u64.to_be_bytes());
        record_bytes.extend_from_slice(&10u64.to_be_bytes());
        let mut data_set = Vec::new();
        data_set.extend_from_slice(&256u16.to_be_bytes());
        data_set.extend_from_slice(&((4 + record_bytes.len()) as u16).to_be_bytes());
        data_set.extend_from_slice(&record_bytes);
        let mut msg2 = message_header_bytes((16 + data_set.len()) as u16);
        msg2.extend_from_slice(&data_set);

        process_datagram(&msg2, addr(), &mut exporters, &mut pipeline, None, &metrics);

        assert_eq!(metrics.normalized_flows_total.get(), 1);
        assert_eq!(metrics.incomplete_records_total.get(), 0);
        assert_eq!(
            metrics
                .classified_flows_by_direction_total
                .with_label_values(&["incoming"])
                .get(),
            1
        );
        assert_eq!(pipeline.aggregator.total_counters().bytes, 1000);
        assert_eq!(pipeline.aggregator.active_hosts(), 2); // source + destination
    }

    /// The whole Phase 4 chain, from bytes on the wire to a detection
    /// event: synthetic IPFIX datagram, decoded, normalized, direction
    /// classified, aggregated, windowed, evaluated against a policy, and
    /// emitted as a dry-run event.
    ///
    /// It asserts on the event's contents rather than merely that one
    /// appeared, because every field here is something an operator acts
    /// on at three in the morning and every one of them crosses a crate
    /// boundary to get there.
    #[test]
    fn synthetic_ipfix_produces_a_dry_run_detection_event_end_to_end() {
        use std::sync::Arc;
        use wetechinetmon_detector::{ActionTaken, ScopeType, TrafficDirection};

        const POLICY_DOC: &str = r#"{
          "schemaVersion": 1,
          "tenants": [ { "tenant": "wetechi", "prefixes": ["10.0.0.0/8"] } ],
          "policies": [
            {
              "id": "e2e-host-inbound",
              "name": "end-to-end host inbound bps",
              "tenant": "wetechi",
              "scopeType": "host",
              "direction": "incoming",
              "window": "1s",
              "thresholds": { "bps": "500k" },
              "triggerFor": "2s",
              "clearFor": "2s",
              "cooldown": "10s",
              "severity": "critical",
              "executionMode": "dryRun"
            }
          ]
        }"#;

        let (metrics, registry) = Metrics::new().unwrap();
        // The real Prometheus implementation, on the collector's own
        // registry, so the metric assertions below exercise the
        // production path rather than a test double.
        let detector_metrics =
            Arc::new(detection::DetectionPrometheusMetrics::new(&registry).expect("registers"));
        let sink = Arc::new(detection::ClickHouseEventSink::new(64));
        let policies = wetechinetmon_detector::load_policies(POLICY_DOC).expect("valid policies");

        let start = Instant::now();
        let mut stage = detection::DetectionStage::new(
            detection::DetectionStageConfig {
                window: wetechinetmon_detector::WindowConfig {
                    window: Duration::from_secs(1),
                    ..wetechinetmon_detector::WindowConfig::default()
                },
                engine: wetechinetmon_detector::EngineConfig::default(),
                event_buffer: 64,
            },
            policies,
            detector_metrics.clone(),
            Some(sink.clone()),
            Vec::new(),
            start,
        );

        let mut exporters = ExporterRegistry::new();
        let mut pipeline = test_pipeline();

        // Template: sourceIPv4Address(8,4), destinationIPv4Address(12,4),
        // octetDeltaCount(1,8), packetDeltaCount(2,8), protocolIdentifier(4,1).
        let set = template_set_bytes(&[(8, 4), (12, 4), (1, 8), (2, 8), (4, 1)]);
        let mut template_msg = message_header_bytes((16 + set.len()) as u16);
        template_msg.extend_from_slice(&set);
        process_datagram(
            &template_msg,
            addr(),
            &mut exporters,
            &mut pipeline,
            Some(&mut stage),
            &metrics,
        );
        assert_eq!(metrics.parser_failures_total.get(), 0);

        // 125_000 bytes in a one-second window is 1_000_000 bps, twice
        // the policy threshold.
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[203, 0, 113, 1]); // external source
        record_bytes.extend_from_slice(&[10, 0, 0, 5]); // local destination
        record_bytes.extend_from_slice(&125_000u64.to_be_bytes());
        record_bytes.extend_from_slice(&100u64.to_be_bytes());
        record_bytes.push(17); // UDP
        let mut data_set = Vec::new();
        data_set.extend_from_slice(&256u16.to_be_bytes());
        data_set.extend_from_slice(&((4 + record_bytes.len()) as u16).to_be_bytes());
        data_set.extend_from_slice(&record_bytes);
        let mut data_msg = message_header_bytes((16 + data_set.len()) as u16);
        data_msg.extend_from_slice(&data_set);

        // Four one-second windows above threshold. The first opens
        // PendingTrigger; the third satisfies the two-second triggerFor.
        let mut opened = 0;
        for second in 0..4u64 {
            process_datagram(
                &data_msg,
                addr(),
                &mut exporters,
                &mut pipeline,
                Some(&mut stage),
                &metrics,
            );
            let report = stage.tick(
                start + Duration::from_secs(second + 1),
                std::time::SystemTime::UNIX_EPOCH,
            );
            opened += report.detections_opened;
        }

        // --- the Phase 3 half still behaves ---
        assert_eq!(metrics.normalized_flows_total.get(), 4);
        assert_eq!(metrics.incomplete_records_total.get(), 0);
        assert_eq!(
            metrics
                .classified_flows_by_direction_total
                .with_label_values(&["incoming"])
                .get(),
            4
        );

        // --- exactly one detection opened ---
        assert_eq!(
            opened, 1,
            "a sustained flood must open exactly one detection"
        );
        assert_eq!(stage.open_detections(), 1);

        // --- the event says what it should ---
        let rows = stage.drain_rows();
        assert_eq!(rows.len(), 1, "one start event should have been stored");
        let row = &rows[0];
        assert_eq!(row.kind, "started");
        assert_eq!(row.tenant, "wetechi");
        assert_eq!(row.scope_type, ScopeType::Host.as_str());
        assert_eq!(row.target, "10.0.0.5");
        assert_eq!(row.direction, TrafficDirection::Incoming.as_str());
        assert_eq!(row.policy_id, "e2e-host-inbound");
        assert_eq!(row.policy_version, 1);
        assert_eq!(row.severity, "critical");
        assert_eq!(row.execution_mode, "dryRun");
        assert_eq!(row.action, ActionTaken::DryRun.as_str());
        assert_eq!(row.state, "active");
        assert_eq!(row.previous_state, "pendingTrigger");
        assert_eq!(row.reason, "triggerSustained");
        assert_eq!(row.window_ms, 1000);
        assert_eq!(row.family, 4);

        // Observed and threshold values, and the reason list.
        assert_eq!(row.bps, 1_000_000, "125000 bytes over one second");
        assert_eq!(row.pps, 100);
        assert_eq!(row.udp_bps, 1_000_000, "the record declared UDP");
        assert_eq!(row.top_metric, "bps");
        assert_eq!(row.top_observed, 1_000_000);
        assert_eq!(row.top_threshold, 500_000);
        assert_eq!(row.top_ratio_percent, 200);
        assert!(
            row.matched_json.contains("\"bps\"") && row.matched_json.contains("1000000"),
            "every matching reason must be preserved: {}",
            row.matched_json
        );
        assert_eq!(row.flows_observed, 1);
        assert_eq!(row.exporters_observed, 1);

        // --- and above all, that nothing was done about it ---
        assert_eq!(
            row.executed, 0,
            "a dry-run event must record that no action was taken"
        );

        // --- the detector's metrics moved, as scraped from /metrics ---
        let text = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encodes");
        for expected in [
            "wetechinetmon_detector_events_total{kind=\"started\"} 1",
            "wetechinetmon_detector_events_published_total{kind=\"started\"} 1",
            "wetechinetmon_detector_scopes_in_state{state=\"active\"} 1",
            "wetechinetmon_detector_snapshots_evaluated_total{scope_type=\"host\"} 4",
            "wetechinetmon_detector_state_transitions_total{from=\"pendingTrigger\",reason=\"triggerSustained\",to=\"active\"} 1",
        ] {
            assert!(text.contains(expected), "missing from /metrics: {expected}");
        }
        assert!(
            !text.contains("wetechinetmon_detector_events_failed_total"),
            "no publish should have failed"
        );
        assert!(
            text.contains("wetechinetmon_collector_normalized_flows_total 4"),
            "the Phase 3 metrics must still be on the same endpoint"
        );
    }

    #[test]
    fn a_record_missing_addresses_increments_incomplete_records() {
        let (metrics, _registry) = Metrics::new().unwrap();
        let mut exporters = ExporterRegistry::new();
        let mut pipeline = test_pipeline();

        // Template with only octetDeltaCount — no address fields.
        let set = template_set_bytes(&[(1, 8)]);
        let mut msg1 = message_header_bytes((16 + set.len()) as u16);
        msg1.extend_from_slice(&set);
        process_datagram(&msg1, addr(), &mut exporters, &mut pipeline, None, &metrics);

        let record_bytes = 100u64.to_be_bytes().to_vec();
        let mut data_set = Vec::new();
        data_set.extend_from_slice(&256u16.to_be_bytes());
        data_set.extend_from_slice(&((4 + record_bytes.len()) as u16).to_be_bytes());
        data_set.extend_from_slice(&record_bytes);
        let mut msg2 = message_header_bytes((16 + data_set.len()) as u16);
        msg2.extend_from_slice(&data_set);

        process_datagram(&msg2, addr(), &mut exporters, &mut pipeline, None, &metrics);
        assert_eq!(metrics.incomplete_records_total.get(), 1);
        assert_eq!(metrics.normalized_flows_total.get(), 0);
    }

    #[test]
    fn sequence_number_regression_increments_restart_metric() {
        let (metrics, _registry) = Metrics::new().unwrap();
        let mut exporters = ExporterRegistry::new();
        let mut pipeline = test_pipeline();

        let mut msg1 = message_header_bytes(16);
        msg1[8..12].copy_from_slice(&100u32.to_be_bytes());
        process_datagram(&msg1, addr(), &mut exporters, &mut pipeline, None, &metrics);

        let mut msg2 = message_header_bytes(16);
        msg2[8..12].copy_from_slice(&3u32.to_be_bytes());
        process_datagram(&msg2, addr(), &mut exporters, &mut pipeline, None, &metrics);

        assert_eq!(metrics.exporter_restarts_total.get(), 1);
    }

    #[test]
    fn unknown_template_data_set_increments_unknown_template_metric() {
        let (metrics, _registry) = Metrics::new().unwrap();
        let mut exporters = ExporterRegistry::new();
        let mut pipeline = test_pipeline();

        let mut data_set = Vec::new();
        data_set.extend_from_slice(&999u16.to_be_bytes());
        data_set.extend_from_slice(&8u16.to_be_bytes());
        data_set.extend_from_slice(&[0, 0, 0, 0]);
        let mut msg = message_header_bytes((16 + data_set.len()) as u16);
        msg.extend_from_slice(&data_set);

        process_datagram(&msg, addr(), &mut exporters, &mut pipeline, None, &metrics);
        assert_eq!(metrics.unknown_templates_total.get(), 1);
        assert_eq!(metrics.parser_failures_total.get(), 0);
    }

    #[test]
    fn empty_prefix_registry_classifies_as_unknown_and_counts_lookup_failure() {
        let (metrics, _registry) = Metrics::new().unwrap();
        let mut exporters = ExporterRegistry::new();
        let mut pipeline = Pipeline::new(
            build_registry(&[]).unwrap().registry,
            wetechinetmon_aggregator::AggregatorConfig::default(),
            SamplingConfig::default(),
            Instant::now(),
        );

        let set = template_set_bytes(&[(8, 4), (12, 4), (1, 8), (2, 8)]);
        let mut msg1 = message_header_bytes((16 + set.len()) as u16);
        msg1.extend_from_slice(&set);
        process_datagram(&msg1, addr(), &mut exporters, &mut pipeline, None, &metrics);

        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[203, 0, 113, 1]);
        record_bytes.extend_from_slice(&[10, 0, 0, 5]);
        record_bytes.extend_from_slice(&1000u64.to_be_bytes());
        record_bytes.extend_from_slice(&10u64.to_be_bytes());
        let mut data_set = Vec::new();
        data_set.extend_from_slice(&256u16.to_be_bytes());
        data_set.extend_from_slice(&((4 + record_bytes.len()) as u16).to_be_bytes());
        data_set.extend_from_slice(&record_bytes);
        let mut msg2 = message_header_bytes((16 + data_set.len()) as u16);
        msg2.extend_from_slice(&data_set);
        process_datagram(&msg2, addr(), &mut exporters, &mut pipeline, None, &metrics);

        assert_eq!(metrics.prefix_lookup_failures_total.get(), 1);
        assert_eq!(
            metrics
                .classified_flows_by_direction_total
                .with_label_values(&["unknown"])
                .get(),
            1
        );
    }
}
