//! Periodically snapshots the Aggregator's dimensions into ClickHouse
//! rows and pushes them through `wetechinetmon-storage`'s batch/retry
//! writers (Phase 3 objective 10).
//!
//! **Optional and off by default:** only active when
//! `WETECHINETMON_COLLECTOR_CLICKHOUSE_URL` is set — see
//! docs/integrations/clickhouse.md. `crates/storage`'s writer/batch/
//! retry/schema logic is unit-tested (see that crate), but this specific
//! wiring has not been exercised against a live ClickHouse server in
//! this environment (no Docker/server available here) — flagged, not
//! hidden.
//!
//! **Known limitation:** interface-traffic export (`interface_traffic`
//! table) is not wired here. `crates/aggregator`'s interface dimension
//! is keyed by interface index alone, not `(exporter, interface index)`
//! — exporting it now would silently merge same-numbered interfaces
//! across different exporters. The ClickHouse schema and table exist and
//! are ready; wiring is deferred until the aggregator's interface
//! dimension is made exporter-scoped.

use time::OffsetDateTime;
use wetechinetmon_aggregator::Aggregator;
use wetechinetmon_storage::writer::ClickHouseWriter;
use wetechinetmon_storage::{
    schema::{
        AsnTrafficRow, DetectionEventRow, ExporterTrafficRow, HostTrafficRow, HostgroupTrafficRow,
        NetworkTrafficRow, Slash24TrafficRow, TotalTrafficRow,
    },
    BatchConfig, Client, RetryConfig,
};

pub struct ClickHouseExporters {
    total_ipv4: ClickHouseWriter<TotalTrafficRow>,
    total_ipv6: ClickHouseWriter<TotalTrafficRow>,
    host: ClickHouseWriter<HostTrafficRow>,
    network: ClickHouseWriter<NetworkTrafficRow>,
    slash24: ClickHouseWriter<Slash24TrafficRow>,
    hostgroup: ClickHouseWriter<HostgroupTrafficRow>,
    asn: ClickHouseWriter<AsnTrafficRow>,
    exporter: ClickHouseWriter<ExporterTrafficRow>,
    /// Detection events. Unlike the traffic writers, this one is not fed
    /// from a snapshot of current state — events are pushed as they
    /// happen and drained here, because an event that was true for two
    /// seconds between snapshots still has to reach the table.
    detection_events: ClickHouseWriter<DetectionEventRow>,
}

#[derive(Debug, Default)]
pub struct ExportReport {
    pub rows_written: usize,
    pub write_failures: u32,
    pub retry_queue_dropped: u32,
    pub permanently_dropped_batches: u32,
}

impl ExportReport {
    fn merge(&mut self, other: wetechinetmon_storage::FlushReport) {
        self.rows_written += other.rows_written;
        self.write_failures += other.write_failures;
        self.retry_queue_dropped += other.retry_queue_dropped;
        self.permanently_dropped_batches += other.permanently_dropped_batches;
    }
}

impl ClickHouseExporters {
    pub fn new(client: Client, now: std::time::Instant) -> Self {
        let batch = BatchConfig::default();
        let retry = RetryConfig::default();
        ClickHouseExporters {
            total_ipv4: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_total_ipv4_traffic",
                batch,
                retry,
                now,
            ),
            total_ipv6: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_total_ipv6_traffic",
                batch,
                retry,
                now,
            ),
            host: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_host_traffic",
                batch,
                retry,
                now,
            ),
            network: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_network_traffic",
                batch,
                retry,
                now,
            ),
            slash24: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_slash24_network_traffic",
                batch,
                retry,
                now,
            ),
            hostgroup: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_hostgroup_traffic",
                batch,
                retry,
                now,
            ),
            asn: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_asn_traffic",
                batch,
                retry,
                now,
            ),
            exporter: ClickHouseWriter::new(
                client.clone(),
                "wetechinetmon_exporter_traffic",
                batch,
                retry,
                now,
            ),
            detection_events: ClickHouseWriter::new(
                client,
                "wetechinetmon_detection_events",
                batch,
                retry,
                now,
            ),
        }
    }

    /// Queues one detection event row.
    ///
    /// Separate from [`ClickHouseExporters::snapshot`] because an event
    /// is not a sample of current state — it happened at an instant, and
    /// a snapshot taken later would miss it entirely.
    pub fn push_detection_event(&mut self, row: DetectionEventRow) {
        self.detection_events.push(row);
    }

    /// Reads a full snapshot of `aggregator`'s current state and queues
    /// one row per tracked entry, per dimension, timestamped `now`.
    pub fn snapshot(&mut self, aggregator: &Aggregator, now: OffsetDateTime) {
        self.total_ipv4.push(TotalTrafficRow::new(
            now,
            aggregator.total_ipv4_counters().into(),
        ));
        self.total_ipv6.push(TotalTrafficRow::new(
            now,
            aggregator.total_ipv6_counters().into(),
        ));

        for (addr, counters) in aggregator.ipv4_hosts() {
            self.host.push(HostTrafficRow::new(
                now,
                addr.to_string(),
                4,
                (*counters).into(),
            ));
        }
        for (addr, counters) in aggregator.ipv6_hosts() {
            self.host.push(HostTrafficRow::new(
                now,
                addr.to_string(),
                6,
                (*counters).into(),
            ));
        }

        for ((addr, len), counters) in aggregator.ipv4_networks() {
            self.network.push(NetworkTrafficRow::new(
                now,
                addr.to_string(),
                *len,
                4,
                (*counters).into(),
            ));
        }
        for ((addr, len), counters) in aggregator.ipv6_networks() {
            self.network.push(NetworkTrafficRow::new(
                now,
                addr.to_string(),
                *len,
                6,
                (*counters).into(),
            ));
        }

        for (addr, counters) in aggregator.ipv4_slash24() {
            self.slash24.push(Slash24TrafficRow::new(
                now,
                addr.to_string(),
                (*counters).into(),
            ));
        }

        for (hg, counters) in aggregator.hostgroups() {
            self.hostgroup.push(HostgroupTrafficRow::new(
                now,
                hg.clone(),
                (*counters).into(),
            ));
        }

        for (asn, counters) in aggregator.asns() {
            self.asn
                .push(AsnTrafficRow::new(now, *asn, (*counters).into()));
        }

        for (exporter, counters) in aggregator.exporters() {
            self.exporter.push(ExporterTrafficRow::new(
                now,
                exporter.to_string(),
                (*counters).into(),
            ));
        }
    }

    /// Flushes/retries every writer. Real network I/O.
    pub async fn tick(&mut self, now: std::time::Instant) -> ExportReport {
        let mut report = ExportReport::default();
        report.merge(self.total_ipv4.tick(now).await);
        report.merge(self.total_ipv6.tick(now).await);
        report.merge(self.host.tick(now).await);
        report.merge(self.network.tick(now).await);
        report.merge(self.slash24.tick(now).await);
        report.merge(self.hostgroup.tick(now).await);
        report.merge(self.asn.tick(now).await);
        report.merge(self.exporter.tick(now).await);
        report.merge(self.detection_events.tick(now).await);
        report
    }
}
