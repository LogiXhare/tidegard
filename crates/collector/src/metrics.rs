//! Prometheus metrics for the Telemetry Collector and its Phase 3
//! aggregation pipeline.
//!
//! Names and the set of metrics tracked here follow
//! docs/functional-requirements.md (FR-1.8, FR-2) and the
//! collector/aggregator-relevant subset of the metric list in
//! `prompts/CLAUDE_MASTER_PROMPT.md` §20.
//!
//! **Known limitation:** `udp_receive_buffer_errors_total` from the
//! master-prompt list is not implemented — reading the kernel's UDP
//! socket drop counter portably (Windows vs. Linux) needs
//! platform-specific code. Tracked as a follow-up rather than faked with
//! a metric that never increments.

use prometheus::core::Collector;
use prometheus::{Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry};

pub struct Metrics {
    // --- Phase 2: IPFIX collector ---
    pub datagrams_received_total: IntCounter,
    pub parsed_flow_records_total: IntCounter,
    pub ipv4_flows_total: IntCounter,
    pub ipv6_flows_total: IntCounter,
    pub parser_failures_total: IntCounter,
    pub unknown_templates_total: IntCounter,
    pub exporter_restarts_total: IntCounter,
    pub reserved_set_id_total: IntCounter,
    pub template_cache_size: IntGauge,
    pub active_exporters: IntGauge,
    /// Labeled by decoded Set kind (`templates`, `options_templates`,
    /// `data`, `unknown_template`, `reserved_set_id`) — lets an operator
    /// see the traffic mix without needing per-kind counters wired up by
    /// hand for every future Set kind.
    pub sets_by_kind_total: IntCounterVec,
    /// Datagrams dropped before decoding (Phase 9D, ADR 0056), labeled by
    /// `reason`: `not_allowed` (the source is outside
    /// `WETECHINETMON_COLLECTOR_ALLOWED_EXPORTERS`) or `exporter_limit`
    /// (a new exporter while `WETECHINETMON_COLLECTOR_MAX_EXPORTERS` are
    /// already tracked). Two fixed values, never an address.
    pub datagrams_refused_total: IntCounterVec,

    // --- Phase 3: normalization, sampling, classification, aggregation ---
    pub normalized_flows_total: IntCounter,
    pub incomplete_records_total: IntCounter,
    pub unsupported_protocol_fields_total: IntCounter,
    pub corrected_samples_total: IntCounter,
    pub sampling_errors_total: IntCounter,
    /// Labeled by `Direction` (`incoming`, `outgoing`, `internal`,
    /// `other`, `unknown`) — bounded label cardinality (5 fixed values),
    /// never a raw address or tenant name (see module docs / Phase 3
    /// objective 9 "no unbounded Prometheus labels").
    pub classified_flows_by_direction_total: IntCounterVec,
    pub prefix_lookup_failures_total: IntCounter,
    pub active_hosts: IntGauge,
    pub active_networks: IntGauge,
    pub active_hostgroups: IntGauge,
    pub active_asns: IntGauge,
    pub queue_depth: IntGauge,
    pub aggregation_latency_seconds: Histogram,
    pub expired_entries_total: IntCounter,
    pub evicted_entries_total: IntCounter,

    // --- Phase 3: ClickHouse export (only active when configured) ---
    pub clickhouse_rows_written_total: IntCounter,
    pub clickhouse_write_failures_total: IntCounter,
    pub clickhouse_retry_queue_dropped_total: IntCounter,
}

impl Metrics {
    /// Builds every collector metric and registers it with a fresh
    /// `Registry`, returned separately so callers can move `Metrics`
    /// into their receive loop and the `Registry` into the metrics HTTP
    /// server independently (see `metrics_server::serve`).
    pub fn new() -> Result<(Self, Registry), prometheus::Error> {
        let registry = Registry::new();

        let datagrams_received_total = IntCounter::new(
            "wetechinetmon_collector_flow_datagrams_received_total",
            "Total UDP datagrams received by the collector, before parsing.",
        )?;
        let parsed_flow_records_total = IntCounter::new(
            "wetechinetmon_collector_parsed_flow_records_total",
            "Total Data Records successfully decoded across all exporters.",
        )?;
        let ipv4_flows_total = IntCounter::new(
            "wetechinetmon_collector_ipv4_flows_total",
            "Total decoded Data Records containing at least one IPv4 address field.",
        )?;
        let ipv6_flows_total = IntCounter::new(
            "wetechinetmon_collector_ipv6_flows_total",
            "Total decoded Data Records containing at least one IPv6 address field.",
        )?;
        let parser_failures_total = IntCounter::new(
            "wetechinetmon_collector_parser_failures_total",
            "Total datagrams that failed to decode as a valid IPFIX message.",
        )?;
        let unknown_templates_total = IntCounter::new(
            "wetechinetmon_collector_unknown_templates_total",
            "Total Data Sets received referencing a template not yet known for that exporter.",
        )?;
        let exporter_restarts_total = IntCounter::new(
            "wetechinetmon_collector_exporter_restarts_total",
            "Total detected exporter restarts (sequence-number regression), which clear that exporter's template cache.",
        )?;
        let reserved_set_id_total = IntCounter::new(
            "wetechinetmon_collector_reserved_set_id_total",
            "Total Sets received using a reserved (invalid) Set ID.",
        )?;
        let template_cache_size = IntGauge::new(
            "wetechinetmon_collector_template_cache_size",
            "Current total number of cached templates across all known exporters.",
        )?;
        let active_exporters = IntGauge::new(
            "wetechinetmon_collector_active_exporters",
            "Current number of exporters tracked: source address and observation domain pairs.",
        )?;
        let sets_by_kind_total = IntCounterVec::new(
            Opts::new(
                "wetechinetmon_collector_sets_by_kind_total",
                "Total decoded Sets, labeled by kind.",
            ),
            &["kind"],
        )?;
        let datagrams_refused_total = IntCounterVec::new(
            Opts::new(
                "wetechinetmon_collector_datagrams_refused_total",
                "Total datagrams dropped before decoding, labeled by reason (not_allowed, exporter_limit).",
            ),
            &["reason"],
        )?;

        let normalized_flows_total = IntCounter::new(
            "wetechinetmon_collector_normalized_flows_total",
            "Total Data Records successfully converted into a NormalizedFlow.",
        )?;
        let incomplete_records_total = IntCounter::new(
            "wetechinetmon_collector_incomplete_records_total",
            "Total Data Records rejected during normalization for missing required fields (e.g. no address).",
        )?;
        let unsupported_protocol_fields_total = IntCounter::new(
            "wetechinetmon_collector_unsupported_protocol_fields_total",
            "Total normalized flows whose IP protocol number is not one of the well-known ones this project names (TCP/UDP/ICMP/ICMPv6).",
        )?;
        let corrected_samples_total = IntCounter::new(
            "wetechinetmon_collector_corrected_samples_total",
            "Total normalized flows that had a sampling rate greater than 1 applied.",
        )?;
        let sampling_errors_total = IntCounter::new(
            "wetechinetmon_collector_sampling_errors_total",
            "Total flows where a declared sampling rate of zero had to be skipped, or sampling correction overflowed.",
        )?;
        let classified_flows_by_direction_total = IntCounterVec::new(
            Opts::new(
                "wetechinetmon_collector_classified_flows_by_direction_total",
                "Total normalized flows, labeled by classified direction.",
            ),
            &["direction"],
        )?;
        let prefix_lookup_failures_total = IntCounter::new(
            "wetechinetmon_collector_prefix_lookup_failures_total",
            "Total flows classified as Unknown direction because no local prefixes are configured.",
        )?;
        let active_hosts = IntGauge::new(
            "wetechinetmon_collector_active_hosts",
            "Current number of distinct hosts (IPv4 + IPv6) tracked by the aggregator.",
        )?;
        let active_networks = IntGauge::new(
            "wetechinetmon_collector_active_networks",
            "Current number of distinct networks (all prefix-length dimensions combined) tracked by the aggregator.",
        )?;
        let active_hostgroups = IntGauge::new(
            "wetechinetmon_collector_active_hostgroups",
            "Current number of distinct hostgroups tracked by the aggregator.",
        )?;
        let active_asns = IntGauge::new(
            "wetechinetmon_collector_active_asns",
            "Current number of distinct ASNs tracked by the aggregator.",
        )?;
        let queue_depth = IntGauge::new(
            "wetechinetmon_collector_queue_depth",
            "Current number of datagrams queued between the UDP receive loop and the classify/aggregate stage.",
        )?;
        let aggregation_latency_seconds = Histogram::with_opts(HistogramOpts::new(
            "wetechinetmon_collector_aggregation_latency_seconds",
            "Time to normalize, classify, and aggregate one Data Record.",
        ))?;
        let expired_entries_total = IntCounter::new(
            "wetechinetmon_collector_expired_entries_total",
            "Total aggregation entries removed by inactivity expiration, across all dimensions.",
        )?;
        let evicted_entries_total = IntCounter::new(
            "wetechinetmon_collector_evicted_entries_total",
            "Total aggregation entries removed to stay within a dimension's configured capacity, across all dimensions.",
        )?;

        let clickhouse_rows_written_total = IntCounter::new(
            "wetechinetmon_collector_clickhouse_rows_written_total",
            "Total rows successfully written to ClickHouse across all tables. Always zero if ClickHouse export is not configured.",
        )?;
        let clickhouse_write_failures_total = IntCounter::new(
            "wetechinetmon_collector_clickhouse_write_failures_total",
            "Total ClickHouse batch write attempts that failed and were queued for retry.",
        )?;
        let clickhouse_retry_queue_dropped_total = IntCounter::new(
            "wetechinetmon_collector_clickhouse_retry_queue_dropped_total",
            "Total ClickHouse batches permanently lost because the bounded retry queue was full (see ADR 0005).",
        )?;

        let metrics = Metrics {
            datagrams_received_total,
            parsed_flow_records_total,
            ipv4_flows_total,
            ipv6_flows_total,
            parser_failures_total,
            unknown_templates_total,
            exporter_restarts_total,
            reserved_set_id_total,
            template_cache_size,
            active_exporters,
            sets_by_kind_total,
            datagrams_refused_total,
            normalized_flows_total,
            incomplete_records_total,
            unsupported_protocol_fields_total,
            corrected_samples_total,
            sampling_errors_total,
            classified_flows_by_direction_total,
            prefix_lookup_failures_total,
            active_hosts,
            active_networks,
            active_hostgroups,
            active_asns,
            queue_depth,
            aggregation_latency_seconds,
            expired_entries_total,
            evicted_entries_total,
            clickhouse_rows_written_total,
            clickhouse_write_failures_total,
            clickhouse_retry_queue_dropped_total,
        };
        for collector in metrics.collectors() {
            registry.register(collector)?;
        }

        Ok((metrics, registry))
    }
}

impl Metrics {
    /// Every metric this owns. `new` registers exactly these and
    /// `metric_names` reads them, so `/metrics` and the Grafana dashboard
    /// check (ADR 0041) cannot disagree about what exists.
    fn collectors(&self) -> Vec<Box<dyn Collector>> {
        vec![
            Box::new(self.datagrams_received_total.clone()),
            Box::new(self.parsed_flow_records_total.clone()),
            Box::new(self.ipv4_flows_total.clone()),
            Box::new(self.ipv6_flows_total.clone()),
            Box::new(self.parser_failures_total.clone()),
            Box::new(self.unknown_templates_total.clone()),
            Box::new(self.exporter_restarts_total.clone()),
            Box::new(self.reserved_set_id_total.clone()),
            Box::new(self.template_cache_size.clone()),
            Box::new(self.active_exporters.clone()),
            Box::new(self.sets_by_kind_total.clone()),
            Box::new(self.datagrams_refused_total.clone()),
            Box::new(self.normalized_flows_total.clone()),
            Box::new(self.incomplete_records_total.clone()),
            Box::new(self.unsupported_protocol_fields_total.clone()),
            Box::new(self.corrected_samples_total.clone()),
            Box::new(self.sampling_errors_total.clone()),
            Box::new(self.classified_flows_by_direction_total.clone()),
            Box::new(self.prefix_lookup_failures_total.clone()),
            Box::new(self.active_hosts.clone()),
            Box::new(self.active_networks.clone()),
            Box::new(self.active_hostgroups.clone()),
            Box::new(self.active_asns.clone()),
            Box::new(self.queue_depth.clone()),
            Box::new(self.aggregation_latency_seconds.clone()),
            Box::new(self.expired_entries_total.clone()),
            Box::new(self.evicted_entries_total.clone()),
            Box::new(self.clickhouse_rows_written_total.clone()),
            Box::new(self.clickhouse_write_failures_total.clone()),
            Box::new(self.clickhouse_retry_queue_dropped_total.clone()),
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
    use super::*;

    #[test]
    fn registers_without_error_and_starts_at_zero() {
        let (metrics, registry) = Metrics::new().expect("metric registration should not collide");
        assert_eq!(metrics.datagrams_received_total.get(), 0);
        assert_eq!(metrics.template_cache_size.get(), 0);
        assert_eq!(metrics.active_hosts.get(), 0);
        assert!(!registry.gather().is_empty());
    }

    #[test]
    fn counters_are_independently_incrementable() {
        let (metrics, _registry) = Metrics::new().unwrap();
        metrics.datagrams_received_total.inc();
        metrics.parser_failures_total.inc_by(3);
        metrics
            .sets_by_kind_total
            .with_label_values(&["data"])
            .inc();
        metrics
            .classified_flows_by_direction_total
            .with_label_values(&["incoming"])
            .inc();
        assert_eq!(metrics.datagrams_received_total.get(), 1);
        assert_eq!(metrics.parser_failures_total.get(), 3);
        assert_eq!(
            metrics
                .sets_by_kind_total
                .with_label_values(&["data"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .classified_flows_by_direction_total
                .with_label_values(&["incoming"])
                .get(),
            1
        );
    }

    #[test]
    fn aggregation_latency_histogram_observes_values() {
        let (metrics, _registry) = Metrics::new().unwrap();
        metrics.aggregation_latency_seconds.observe(0.001);
        assert_eq!(metrics.aggregation_latency_seconds.get_sample_count(), 1);
    }
}
