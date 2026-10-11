//! Wiring the detection engine into the collector.
//!
//! Three things live here that cannot live in `wetechinetmon-detector`
//! itself: the Prometheus implementation of its metrics trait (the
//! collector owns this project's registry), the sink that hands events
//! to ClickHouse (the detector does not depend on storage), and the
//! stage that runs the windowing layer and the engine on the collector's
//! clock.
//!
//! **Off by default.** Detection runs only when a policy document is
//! configured. A collector with no policies behaves exactly as it did
//! before Phase 4 — no extra counters, no extra allocations per flow.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use prometheus::core::Collector;
use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts, Registry};
use wetechinetmon_classifier::{ClassificationResult, PrefixRegistry};
use wetechinetmon_common::NormalizedFlow;
use wetechinetmon_detector::config::CompiledPolicies;
use wetechinetmon_detector::{
    DetectionEngine, DetectionEvent, DetectionEventSink, DetectionMetrics, DetectionState,
    DetectionWindows, EngineConfig, EngineReport, EventKind, ScopeType, SinkError, StepIgnored,
    Suppression, ThresholdDetectionEngine, TransitionReason, WindowConfig,
};
use wetechinetmon_storage::DetectionEventRow;

/// Prometheus counters and gauges for the detection engine.
///
/// Registered into the collector's existing registry, so `/metrics`
/// stays one endpoint. Every label value comes from a closed set — a
/// state, a reason, a kind — never an address, tenant, or policy id.
pub struct DetectionPrometheusMetrics {
    snapshots_evaluated_total: IntCounterVec,
    snapshots_unmatched_total: IntCounter,
    snapshots_ignored_total: IntCounterVec,
    transitions_total: IntCounterVec,
    suppressed_total: IntCounterVec,
    events_total: IntCounterVec,
    events_published_total: IntCounterVec,
    events_failed_total: IntCounterVec,
    metrics_skipped_total: IntCounter,
    scopes_in_state: prometheus::IntGaugeVec,
    tracked_scopes: IntGauge,
    state_table_full_total: IntCounter,
    detections_stale_total: IntCounter,
}

impl DetectionPrometheusMetrics {
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let counter_vec = |name: &str, help: &str, labels: &[&str]| {
            IntCounterVec::new(Opts::new(name, help), labels)
        };

        let snapshots_evaluated_total = counter_vec(
            "wetechinetmon_detector_snapshots_evaluated_total",
            "Traffic snapshots handed to the detection engine, by scope type.",
            &["scope_type"],
        )?;
        let snapshots_unmatched_total = IntCounter::new(
            "wetechinetmon_detector_snapshots_unmatched_total",
            "Traffic snapshots for which no detection policy applied.",
        )?;
        let snapshots_ignored_total = counter_vec(
            "wetechinetmon_detector_snapshots_ignored_total",
            "Traffic snapshots the state machine refused, by reason.",
            &["reason"],
        )?;
        let transitions_total = counter_vec(
            "wetechinetmon_detector_state_transitions_total",
            "Detection state machine transitions, by source state, target state, and reason.",
            &["from", "to", "reason"],
        )?;
        let suppressed_total = counter_vec(
            "wetechinetmon_detector_suppressed_total",
            "Threshold crossings that deliberately produced no detection, by reason.",
            &["reason"],
        )?;
        let events_total = counter_vec(
            "wetechinetmon_detector_events_total",
            "Detection events built, by kind. Includes observe-mode events, which are never published.",
            &["kind"],
        )?;
        let events_published_total = counter_vec(
            "wetechinetmon_detector_events_published_total",
            "Detection events accepted by every sink, by kind.",
            &["kind"],
        )?;
        let events_failed_total = counter_vec(
            "wetechinetmon_detector_events_failed_total",
            "Detection events at least one sink refused, by kind and sink.",
            &["kind", "sink"],
        )?;
        let metrics_skipped_total = IntCounter::new(
            "wetechinetmon_detector_thresholds_skipped_total",
            "Thresholds not evaluated because the flow data never carried their source field.",
        )?;
        let scopes_in_state = prometheus::IntGaugeVec::new(
            Opts::new(
                "wetechinetmon_detector_scopes_in_state",
                "Scopes currently in each detection state.",
            ),
            &["state"],
        )?;
        let tracked_scopes = IntGauge::new(
            "wetechinetmon_detector_tracked_scopes",
            "Scopes the windowing layer is currently accumulating counters for.",
        )?;
        let state_table_full_total = IntCounter::new(
            "wetechinetmon_detector_state_table_full_total",
            "Scopes refused admission because the detection state table is full. Each one is a detection that cannot be opened.",
        )?;
        let detections_stale_total = IntCounter::new(
            "wetechinetmon_detector_detections_stale_total",
            "Open detections force-closed because their snapshots stopped arriving.",
        )?;

        let metrics = DetectionPrometheusMetrics {
            snapshots_evaluated_total,
            snapshots_unmatched_total,
            snapshots_ignored_total,
            transitions_total,
            suppressed_total,
            events_total,
            events_published_total,
            events_failed_total,
            metrics_skipped_total,
            scopes_in_state,
            tracked_scopes,
            state_table_full_total,
            detections_stale_total,
        };
        for collector in metrics.collectors() {
            registry.register(collector)?;
        }
        Ok(metrics)
    }
}

impl DetectionMetrics for DetectionPrometheusMetrics {
    fn snapshot_evaluated(&self, scope_type: ScopeType) {
        self.snapshots_evaluated_total
            .with_label_values(&[scope_type.as_str()])
            .inc();
    }

    fn snapshot_unmatched(&self, _scope_type: ScopeType) {
        self.snapshots_unmatched_total.inc();
    }

    fn snapshot_ignored(&self, reason: StepIgnored) {
        self.snapshots_ignored_total
            .with_label_values(&[reason.as_str()])
            .inc();
    }

    fn transition(&self, from: DetectionState, to: DetectionState, reason: TransitionReason) {
        self.transitions_total
            .with_label_values(&[from.as_str(), to.as_str(), reason.as_str()])
            .inc();
    }

    fn suppressed(&self, reason: Suppression) {
        self.suppressed_total
            .with_label_values(&[reason.as_str()])
            .inc();
    }

    fn event_built(&self, kind: EventKind) {
        self.events_total.with_label_values(&[kind.as_str()]).inc();
    }

    fn event_published(&self, kind: EventKind) {
        self.events_published_total
            .with_label_values(&[kind.as_str()])
            .inc();
    }

    fn event_failed(&self, kind: EventKind, sink: &'static str) {
        self.events_failed_total
            .with_label_values(&[kind.as_str(), sink])
            .inc();
    }

    fn metric_skipped(&self) {
        self.metrics_skipped_total.inc();
    }

    fn scopes_in_state(&self, state: DetectionState, count: usize) {
        self.scopes_in_state
            .with_label_values(&[state.as_str()])
            .set(count as i64);
    }

    fn tracked_scopes(&self, count: usize) {
        self.tracked_scopes.set(count as i64);
    }

    fn state_table_full(&self) {
        self.state_table_full_total.inc();
    }

    fn detection_stale(&self) {
        self.detections_stale_total.inc();
    }
}

/// Buffers detection events as ClickHouse rows for the export tick to
/// drain.
///
/// Bounded, dropping the oldest. The alternative — blocking the
/// detection path until ClickHouse catches up — would stop detection
/// during exactly the incident that makes ClickHouse slow.
pub struct ClickHouseEventSink {
    capacity: usize,
    rows: Mutex<Vec<DetectionEventRow>>,
    dropped: Mutex<u64>,
}

impl ClickHouseEventSink {
    pub fn new(capacity: usize) -> Self {
        ClickHouseEventSink {
            capacity,
            rows: Mutex::new(Vec::new()),
            dropped: Mutex::new(0),
        }
    }

    /// Takes everything buffered, leaving the sink empty.
    pub fn drain(&self) -> Vec<DetectionEventRow> {
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *rows)
    }

    /// How many rows were discarded to stay within capacity.
    pub fn dropped(&self) -> u64 {
        *self
            .dropped
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl DetectionEventSink for ClickHouseEventSink {
    fn publish(&self, event: &DetectionEvent) -> Result<(), SinkError> {
        if self.capacity == 0 {
            return Err(SinkError::Full { sink: "clickhouse" });
        }
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if rows.len() >= self.capacity {
            rows.remove(0);
            let mut dropped = self
                .dropped
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *dropped = dropped.saturating_add(1);
        }
        rows.push(DetectionEventRow::from(event));
        Ok(())
    }

    fn name(&self) -> &'static str {
        "clickhouse"
    }
}

/// How the collector's detection stage is shaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionStageConfig {
    pub window: WindowConfig,
    pub engine: EngineConfig,
    /// How many events may wait for the ClickHouse export tick.
    pub event_buffer: usize,
}

/// The windowing layer plus the engine, driven by the collector's loop.
pub struct DetectionStage {
    windows: DetectionWindows,
    engine: ThresholdDetectionEngine,
    metrics: Arc<dyn DetectionMetrics>,
    clickhouse: Option<Arc<ClickHouseEventSink>>,
}

impl DetectionStage {
    pub fn new(
        config: DetectionStageConfig,
        policies: CompiledPolicies,
        metrics: Arc<dyn DetectionMetrics>,
        clickhouse: Option<Arc<ClickHouseEventSink>>,
        extra_sinks: Vec<Box<dyn DetectionEventSink>>,
        now: Instant,
    ) -> Self {
        let mut sinks: Vec<Box<dyn DetectionEventSink>> =
            vec![Box::new(wetechinetmon_detector::TracingSink)];
        if let Some(sink) = clickhouse.clone() {
            sinks.push(Box::new(SharedSink(sink)));
        }
        sinks.extend(extra_sinks);
        let engine = ThresholdDetectionEngine::new(config.engine)
            .with_policies(policies.policies)
            .with_sink(Arc::new(wetechinetmon_detector::FanOutSink::new(sinks)))
            .with_metrics(metrics.clone());
        DetectionStage {
            windows: DetectionWindows::new(config.window, now),
            engine,
            metrics,
            clickhouse,
        }
    }

    /// Counts one classified flow. Called for every normalized flow, so
    /// it does no allocation beyond what the windowing layer needs.
    pub fn ingest(
        &mut self,
        registry: &PrefixRegistry,
        flow: &NormalizedFlow,
        classification: &ClassificationResult,
        now: Instant,
    ) {
        self.windows.ingest(registry, flow, classification, now);
    }

    /// Closes the window if due, evaluates whatever it produced, and
    /// sweeps. Safe to call more often than the window length.
    pub fn tick(&mut self, now: Instant, wall: SystemTime) -> EngineReport {
        self.metrics.tracked_scopes(self.windows.tracked());
        let snapshots = self.windows.tick(now, wall);
        wetechinetmon_detector::cycle(&mut self.engine, &snapshots, now, wall)
    }

    pub fn open_detections(&self) -> usize {
        self.engine.open_detections()
    }

    /// Rows waiting for the ClickHouse export tick, if that sink is
    /// attached.
    pub fn drain_rows(&self) -> Vec<DetectionEventRow> {
        match &self.clickhouse {
            Some(sink) => sink.drain(),
            None => Vec::new(),
        }
    }
}

/// Lets the stage keep a handle to a sink the fan-out owns.
struct SharedSink(Arc<ClickHouseEventSink>);

impl DetectionEventSink for SharedSink {
    fn publish(&self, event: &DetectionEvent) -> Result<(), SinkError> {
        self.0.publish(event)
    }

    fn name(&self) -> &'static str {
        "clickhouse"
    }
}

/// Reads and compiles a policy document from disk.
///
/// A failure here disables detection for the run rather than stopping
/// the collector: decoding, normalizing, and aggregating are still
/// useful, and a collector that refuses to start because one policy has
/// a typo is a collector that loses telemetry over a config error. The
/// failure is logged at error level, and detection being off is visible
/// in the metrics — no detection counters ever move.
pub fn load_policy_file(path: &str) -> Result<CompiledPolicies, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    wetechinetmon_detector::load_policies(&text).map_err(|e| e.to_string())
}

/// How often the detection stage is ticked.
///
/// A second, regardless of the configured window: `tick` returns
/// immediately when the window is not yet due, and a short tick means a
/// window closes within a second of its actual end rather than up to one
/// tick late.
pub const TICK_INTERVAL: Duration = Duration::from_secs(1);

impl DetectionPrometheusMetrics {
    /// Every metric this owns. `new` registers exactly these and
    /// `metric_names` reads them, so `/metrics` and the Grafana dashboard
    /// check (ADR 0041) cannot disagree about what exists.
    fn collectors(&self) -> Vec<Box<dyn Collector>> {
        vec![
            Box::new(self.snapshots_evaluated_total.clone()),
            Box::new(self.snapshots_unmatched_total.clone()),
            Box::new(self.snapshots_ignored_total.clone()),
            Box::new(self.transitions_total.clone()),
            Box::new(self.suppressed_total.clone()),
            Box::new(self.events_total.clone()),
            Box::new(self.events_published_total.clone()),
            Box::new(self.events_failed_total.clone()),
            Box::new(self.metrics_skipped_total.clone()),
            Box::new(self.scopes_in_state.clone()),
            Box::new(self.tracked_scopes.clone()),
            Box::new(self.state_table_full_total.clone()),
            Box::new(self.detections_stale_total.clone()),
        ]
    }

    /// The fully qualified name of every metric this owns.
    pub fn metric_names(&self) -> Vec<String> {
        self.collectors()
            .iter()
            .flat_map(|collector| {
                collector
                    .desc()
                    .into_iter()
                    .map(|desc| desc.fq_name.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use wetechinetmon_classifier::classify;
    use wetechinetmon_common::{NormalizedFlowBuilder, Protocol, SamplingRate, SamplingSource};
    use wetechinetmon_detector::{CountingMetrics, StateTableConfig};

    use super::*;

    const POLICIES: &str = r#"{
      "schemaVersion": 1,
      "tenants": [ { "tenant": "acme", "prefixes": ["203.0.113.0/24"] } ],
      "policies": [
        {
          "id": "p-host-bps",
          "name": "host inbound bps",
          "tenant": "acme",
          "scopeType": "host",
          "direction": "incoming",
          "window": "1s",
          "thresholds": { "bps": "1M" },
          "triggerFor": "2s",
          "clearFor": "2s",
          "cooldown": "10s"
        }
      ]
    }"#;

    fn registry() -> PrefixRegistry {
        let mut registry = PrefixRegistry::new();
        registry
            .insert(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
                24,
                "acme",
                Some("edge".to_string()),
            )
            .expect("valid prefix");
        registry
    }

    fn flow(bytes: u64) -> NormalizedFlow {
        NormalizedFlowBuilder {
            source_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
            destination_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            source_port: Some(51000),
            destination_port: Some(443),
            protocol: Some(Protocol::Udp),
            tcp_flags: None,
            raw_bytes: bytes,
            raw_packets: 1000,
            input_interface: Some(1),
            output_interface: Some(2),
            source_asn: None,
            destination_asn: None,
            exporter: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            observation_domain_id: 0,
            start_time: None,
            end_time: None,
            fragmented: false,
            dropped: false,
            forwarding_status_known: true,
        }
        .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
        .expect("valid flow")
    }

    fn stage(now: Instant, clickhouse: Option<Arc<ClickHouseEventSink>>) -> DetectionStage {
        let policies = wetechinetmon_detector::load_policies(POLICIES).expect("valid policies");
        DetectionStage::new(
            DetectionStageConfig {
                window: WindowConfig {
                    window: Duration::from_secs(1),
                    ..WindowConfig::default()
                },
                engine: EngineConfig {
                    state: StateTableConfig::default(),
                },
                event_buffer: 64,
            },
            policies,
            Arc::new(CountingMetrics::new()),
            clickhouse,
            Vec::new(),
            now,
        )
    }

    #[test]
    fn a_sustained_flood_produces_a_start_row() {
        let sink = Arc::new(ClickHouseEventSink::new(64));
        let start = Instant::now();
        let mut stage = stage(start, Some(sink.clone()));
        let registry = registry();
        let heavy = flow(1_250_000);
        let classification = classify(&registry, &heavy);

        // Three one-second windows above the threshold: window one opens
        // pendingTrigger, window three completes the two-second trigger.
        let mut opened = 0;
        for second in 0..4 {
            let at = start + Duration::from_secs(second);
            stage.ingest(&registry, &heavy, &classification, at);
            let report = stage.tick(
                start + Duration::from_secs(second + 1),
                SystemTime::UNIX_EPOCH,
            );
            opened += report.detections_opened;
        }
        assert_eq!(opened, 1, "one detection should have opened");
        assert_eq!(stage.open_detections(), 1);

        let rows = stage.drain_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "started");
        assert_eq!(rows[0].policy_id, "p-host-bps");
        assert_eq!(rows[0].target, "203.0.113.7");
        assert_eq!(rows[0].direction, "incoming");
        assert!(rows[0].bps >= 10_000_000);
        assert!(stage.drain_rows().is_empty(), "draining is destructive");
    }

    #[test]
    fn quiet_traffic_produces_no_rows() {
        let sink = Arc::new(ClickHouseEventSink::new(64));
        let start = Instant::now();
        let mut stage = stage(start, Some(sink));
        let registry = registry();
        let light = flow(1000);
        let classification = classify(&registry, &light);
        for second in 0..6 {
            let at = start + Duration::from_secs(second);
            stage.ingest(&registry, &light, &classification, at);
            stage.tick(
                start + Duration::from_secs(second + 1),
                SystemTime::UNIX_EPOCH,
            );
        }
        assert_eq!(stage.open_detections(), 0);
        assert!(stage.drain_rows().is_empty());
    }

    #[test]
    fn a_stage_without_clickhouse_still_detects() {
        let start = Instant::now();
        let mut stage = stage(start, None);
        let registry = registry();
        let heavy = flow(1_250_000);
        let classification = classify(&registry, &heavy);
        for second in 0..4 {
            let at = start + Duration::from_secs(second);
            stage.ingest(&registry, &heavy, &classification, at);
            stage.tick(
                start + Duration::from_secs(second + 1),
                SystemTime::UNIX_EPOCH,
            );
        }
        assert_eq!(stage.open_detections(), 1);
        assert!(stage.drain_rows().is_empty());
    }

    #[test]
    fn a_tick_before_the_window_is_due_evaluates_nothing() {
        let start = Instant::now();
        let mut stage = stage(start, None);
        let report = stage.tick(start + Duration::from_millis(100), SystemTime::UNIX_EPOCH);
        assert_eq!(report.snapshots_seen, 0);
    }

    #[test]
    fn the_event_buffer_drops_the_oldest_rather_than_growing() {
        let sink = ClickHouseEventSink::new(1);
        let event = sample_event("e1");
        sink.publish(&event).expect("accepted");
        let mut second = sample_event("e2");
        second.event_id = "e2".to_string();
        sink.publish(&second).expect("accepted");
        let rows = sink.drain();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_id, "e2");
        assert_eq!(sink.dropped(), 1);
    }

    #[test]
    fn a_zero_capacity_buffer_reports_full() {
        let sink = ClickHouseEventSink::new(0);
        assert!(sink.publish(&sample_event("e1")).is_err());
    }

    #[test]
    fn every_detection_metric_registers_without_colliding() {
        let registry = Registry::new();
        let metrics = DetectionPrometheusMetrics::new(&registry).expect("registers");
        // A labelled metric with no observed label values reports no
        // family at all, so every one is touched before gathering.
        record_one_of_each(&metrics);
        let families = registry.gather();
        assert_eq!(families.len(), 13);
        for family in families {
            assert!(
                family.name().starts_with("wetechinetmon_detector_"),
                "unexpected metric name {}",
                family.name()
            );
        }
    }

    fn record_one_of_each(metrics: &DetectionPrometheusMetrics) {
        metrics.snapshot_evaluated(ScopeType::Host);
        metrics.snapshot_unmatched(ScopeType::Prefix);
        metrics.snapshot_ignored(StepIgnored::Duplicate);
        metrics.transition(
            DetectionState::Idle,
            DetectionState::PendingTrigger,
            TransitionReason::ThresholdCrossed,
        );
        metrics.suppressed(Suppression::Cooldown);
        metrics.event_built(EventKind::Started);
        metrics.event_published(EventKind::Started);
        metrics.event_failed(EventKind::Ended, "clickhouse");
        metrics.metric_skipped();
        metrics.scopes_in_state(DetectionState::Active, 4);
        metrics.tracked_scopes(9);
        metrics.state_table_full();
        metrics.detection_stale();
    }

    #[test]
    fn detection_metrics_can_be_recorded_through_the_trait() {
        let registry = Registry::new();
        let metrics = DetectionPrometheusMetrics::new(&registry).expect("registers");
        record_one_of_each(&metrics);

        let text = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encodes");
        assert!(text.contains("wetechinetmon_detector_scopes_in_state{state=\"active\"} 4"));
        assert!(text.contains("wetechinetmon_detector_tracked_scopes 9"));
        assert!(text.contains("wetechinetmon_detector_detections_stale_total 1"));
    }

    #[test]
    fn a_missing_policy_file_is_reported_rather_than_panicking() {
        let error = load_policy_file("does-not-exist.json").expect_err("must fail");
        assert!(error.contains("does-not-exist.json"), "{error}");
    }

    fn sample_event(id: &str) -> DetectionEvent {
        use std::collections::BTreeMap;
        use wetechinetmon_detector::{
            ActionTaken, AddressFamily, DataCompleteness, EventTarget, ExecutionMode, MetricRates,
            SamplingStatus, ScopeId, Severity, TrafficDirection,
        };
        DetectionEvent {
            schema_version: 1,
            event_id: id.to_string(),
            detection_id: "d1".to_string(),
            sequence: 0,
            kind: EventKind::Started,
            dedup_key: format!("d1:started:{id}"),
            policy_id: "p1".to_string(),
            policy_name: "p".to_string(),
            policy_version: 1,
            severity: Severity::Major,
            execution_mode: ExecutionMode::AlertOnly,
            action: ActionTaken::Alerted,
            labels: BTreeMap::new(),
            target: EventTarget {
                tenant: "acme".to_string(),
                scope_type: ScopeType::Host,
                scope_id: ScopeId::Host {
                    addr: "203.0.113.7".parse().expect("valid"),
                },
                display: "203.0.113.7".to_string(),
                direction: TrafficDirection::Incoming,
                address_family: AddressFamily::Ipv4,
            },
            previous_state: DetectionState::PendingTrigger,
            state: DetectionState::Active,
            reason: TransitionReason::TriggerSustained,
            detected_at_ms: 0,
            observed_at_ms: 0,
            duration_ms: 0,
            window_ms: 1000,
            matched: Vec::new(),
            peak: Vec::new(),
            skipped: Vec::new(),
            rates: MetricRates::default(),
            completeness: DataCompleteness::default(),
            sampling: SamplingStatus::default(),
            flows_observed: 0,
            exporters_observed: 0,
            snapshots_in_detection: 0,
            executed: false,
            summary: "test".to_string(),
        }
    }
}
