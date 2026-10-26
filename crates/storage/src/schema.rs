//! Original ClickHouse row types and table DDL for Tidegard
//! analytics. Table names, columns, and layout are designed
//! independently for this project — see docs/clean-room-boundary.md. Do
//! not copy any proprietary product's table names or definitions.
//!
//! **Deliberate simplification, documented not hidden:** IP addresses
//! are stored as `String` (their text representation), not ClickHouse's
//! native `IPv4`/`IPv6` column types. This sidesteps needing to verify
//! this environment's `clickhouse` Rust crate version handles native IP
//! type (de)serialization correctly without a live server to test
//! against (none is available here — see docs/integrations/clickhouse.md).
//! Revisit once integration-tested against a real server.

use serde::Serialize;

/// Every table's DDL, using `MergeTree` with daily partitioning and a
/// retention TTL — see docs/architecture/aggregation.md /
/// docs/integrations/clickhouse.md for the retention rationale.
pub const CREATE_TABLE_STATEMENTS: &[(&str, &str)] = &[
    ("wetechinetmon_total_ipv4_traffic", DDL_TOTAL_IPV4),
    ("wetechinetmon_total_ipv6_traffic", DDL_TOTAL_IPV6),
    ("wetechinetmon_host_traffic", DDL_HOST_TRAFFIC),
    ("wetechinetmon_network_traffic", DDL_NETWORK_TRAFFIC),
    (
        "wetechinetmon_slash24_network_traffic",
        DDL_SLASH24_NETWORK_TRAFFIC,
    ),
    ("wetechinetmon_hostgroup_traffic", DDL_HOSTGROUP_TRAFFIC),
    ("wetechinetmon_asn_traffic", DDL_ASN_TRAFFIC),
    ("wetechinetmon_exporter_traffic", DDL_EXPORTER_TRAFFIC),
    ("wetechinetmon_interface_traffic", DDL_INTERFACE_TRAFFIC),
    ("wetechinetmon_detection_events", DDL_DETECTION_EVENTS),
];

/// Default retention: 30 days, matching the `TTL ... INTERVAL 30 DAY`
/// clause in every DDL statement below. Configurable per-deployment only
/// by altering the DDL/TTL clause directly; not exposed as a runtime
/// config option in Phase 3 — see docs/integrations/clickhouse.md "Known
/// limitations." Public so callers (and docs generation) can reference
/// the documented default without duplicating the magic number `30`.
pub const RETENTION_DAYS: u32 = 30;

/// Detection events are kept for a year, not thirty days.
///
/// They are the audit trail — "what did we alert on, under which policy,
/// and how bad was it" — and they are tiny compared to per-window
/// traffic rows. Aging them out on the same schedule as raw counters
/// would mean losing the record of an incident long before anyone
/// finished arguing about it.
pub const EVENT_RETENTION_DAYS: u32 = 365;

macro_rules! counter_columns {
    () => {
        "bytes UInt64, \
         packets UInt64, \
         flows UInt64, \
         tcp_bytes UInt64, \
         tcp_packets UInt64, \
         udp_bytes UInt64, \
         udp_packets UInt64, \
         icmp_bytes UInt64, \
         icmp_packets UInt64, \
         tcp_syn_packets UInt64, \
         fragmented_packets UInt64, \
         dropped_packets UInt64"
    };
}

const DDL_TOTAL_IPV4: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_total_ipv4_traffic ( \
        timestamp DateTime, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY timestamp \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_TOTAL_IPV6: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_total_ipv6_traffic ( \
        timestamp DateTime, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY timestamp \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_HOST_TRAFFIC: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_host_traffic ( \
        timestamp DateTime, \
        address String, \
        family UInt8, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, family, address) \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_NETWORK_TRAFFIC: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_network_traffic ( \
        timestamp DateTime, \
        address String, \
        prefix_len UInt8, \
        family UInt8, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, family, prefix_len, address) \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_SLASH24_NETWORK_TRAFFIC: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_slash24_network_traffic ( \
        timestamp DateTime, \
        address String, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, address) \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_HOSTGROUP_TRAFFIC: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_hostgroup_traffic ( \
        timestamp DateTime, \
        hostgroup String, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, hostgroup) \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_ASN_TRAFFIC: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_asn_traffic ( \
        timestamp DateTime, \
        asn UInt32, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, asn) \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_EXPORTER_TRAFFIC: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_exporter_traffic ( \
        timestamp DateTime, \
        exporter String, ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, exporter) \
     TTL timestamp + INTERVAL 30 DAY"
);

const DDL_INTERFACE_TRAFFIC: &str = concat!(
    "CREATE TABLE IF NOT EXISTS wetechinetmon_interface_traffic ( \
        timestamp DateTime, \
        exporter String, \
        interface_index UInt32, \
        direction Enum8('input' = 1, 'output' = 2), ",
    counter_columns!(),
    " ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, exporter, interface_index, direction) \
     TTL timestamp + INTERVAL 30 DAY"
);

/// Detection events, written once and never updated.
///
/// Every enumerated value is a plain `String` rather than `Enum8` or
/// `LowCardinality(String)`. The module docs already record why: without
/// a live server to test against, a column type whose Rust-side
/// (de)serialization is unverified is a liability, and a string column
/// is trivially convertible later. `matched_json` and `peak_json` hold
/// the full reason lists as JSON text for the same reason — ClickHouse
/// can query into them with the JSON functions, and no array
/// (de)serialization has to be taken on trust.
const DDL_DETECTION_EVENTS: &str = "CREATE TABLE IF NOT EXISTS wetechinetmon_detection_events ( \
        timestamp DateTime, \
        detected_at DateTime, \
        schema_version UInt32, \
        event_id String, \
        detection_id String, \
        dedup_key String, \
        sequence UInt64, \
        kind String, \
        policy_id String, \
        policy_name String, \
        policy_version UInt32, \
        severity String, \
        execution_mode String, \
        action String, \
        tenant String, \
        scope_type String, \
        target String, \
        direction String, \
        family UInt8, \
        previous_state String, \
        state String, \
        reason String, \
        duration_ms UInt64, \
        window_ms UInt64, \
        top_metric String, \
        top_observed UInt64, \
        top_threshold UInt64, \
        top_ratio_percent UInt64, \
        matched_json String, \
        peak_json String, \
        bps UInt64, \
        pps UInt64, \
        fps UInt64, \
        tcp_bps UInt64, \
        tcp_pps UInt64, \
        udp_bps UInt64, \
        udp_pps UInt64, \
        icmp_bps UInt64, \
        icmp_pps UInt64, \
        tcp_syn_pps UInt64, \
        fragmented_pps UInt64, \
        dropped_pps UInt64, \
        protocol_seen UInt8, \
        tcp_flags_seen UInt8, \
        fragmentation_seen UInt8, \
        forwarding_status_seen UInt8, \
        sampling_corrected UInt8, \
        sampling_used_global_default UInt8, \
        sampling_max_rate UInt32, \
        flows_observed UInt64, \
        exporters_observed UInt32, \
        snapshots_in_detection UInt64, \
        executed UInt8, \
        summary String \
     ) ENGINE = MergeTree \
     PARTITION BY toYYYYMMDD(timestamp) \
     ORDER BY (timestamp, tenant, policy_id, detection_id) \
     TTL timestamp + INTERVAL 365 DAY";

/// A row's traffic counters, as the aggregator keeps them.
///
/// Not a column group: each row struct below repeats these twelve fields
/// itself, through `traffic_row!`. The `clickhouse` crate maps a struct's
/// own fields to columns, and RowBinary cannot encode
/// `#[serde(flatten)]`, which serde writes as a map: the collector
/// panicked on its first export to a real server until Phase 9A-3
/// (ADR 0053).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CounterFields {
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
    pub tcp_bytes: u64,
    pub tcp_packets: u64,
    pub udp_bytes: u64,
    pub udp_packets: u64,
    pub icmp_bytes: u64,
    pub icmp_packets: u64,
    pub tcp_syn_packets: u64,
    pub fragmented_packets: u64,
    pub dropped_packets: u64,
}

impl From<tidegard_aggregator::TrafficCounters> for CounterFields {
    fn from(c: tidegard_aggregator::TrafficCounters) -> Self {
        CounterFields {
            bytes: c.bytes,
            packets: c.packets,
            flows: c.flows,
            tcp_bytes: c.tcp_bytes,
            tcp_packets: c.tcp_packets,
            udp_bytes: c.udp_bytes,
            udp_packets: c.udp_packets,
            icmp_bytes: c.icmp_bytes,
            icmp_packets: c.icmp_packets,
            tcp_syn_packets: c.tcp_syn_packets,
            fragmented_packets: c.fragmented_packets,
            dropped_packets: c.dropped_packets,
        }
    }
}

/// A traffic row: `timestamp`, the row's own key columns, then the twelve
/// counter columns, all as plain fields, with `new` to fill them.
macro_rules! traffic_row {
    ($(#[$meta:meta])* $name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Serialize, clickhouse::Row)]
        pub struct $name {
            #[serde(with = "clickhouse::serde::time::datetime")]
            pub timestamp: time::OffsetDateTime,
            $(pub $field: $ty,)*
            pub bytes: u64,
            pub packets: u64,
            pub flows: u64,
            pub tcp_bytes: u64,
            pub tcp_packets: u64,
            pub udp_bytes: u64,
            pub udp_packets: u64,
            pub icmp_bytes: u64,
            pub icmp_packets: u64,
            pub tcp_syn_packets: u64,
            pub fragmented_packets: u64,
            pub dropped_packets: u64,
        }

        impl $name {
            pub fn new(
                timestamp: time::OffsetDateTime,
                $($field: $ty,)*
                counters: CounterFields,
            ) -> Self {
                $name {
                    timestamp,
                    $($field,)*
                    bytes: counters.bytes,
                    packets: counters.packets,
                    flows: counters.flows,
                    tcp_bytes: counters.tcp_bytes,
                    tcp_packets: counters.tcp_packets,
                    udp_bytes: counters.udp_bytes,
                    udp_packets: counters.udp_packets,
                    icmp_bytes: counters.icmp_bytes,
                    icmp_packets: counters.icmp_packets,
                    tcp_syn_packets: counters.tcp_syn_packets,
                    fragmented_packets: counters.fragmented_packets,
                    dropped_packets: counters.dropped_packets,
                }
            }

            /// The counter columns, read back.
            pub fn counters(&self) -> CounterFields {
                CounterFields {
                    bytes: self.bytes,
                    packets: self.packets,
                    flows: self.flows,
                    tcp_bytes: self.tcp_bytes,
                    tcp_packets: self.tcp_packets,
                    udp_bytes: self.udp_bytes,
                    udp_packets: self.udp_packets,
                    icmp_bytes: self.icmp_bytes,
                    icmp_packets: self.icmp_packets,
                    tcp_syn_packets: self.tcp_syn_packets,
                    fragmented_packets: self.fragmented_packets,
                    dropped_packets: self.dropped_packets,
                }
            }
        }
    };
}

traffic_row!(TotalTrafficRow {});

traffic_row!(HostTrafficRow {
    address: String,
    family: u8,
});

traffic_row!(NetworkTrafficRow {
    address: String,
    prefix_len: u8,
    family: u8,
});

traffic_row!(Slash24TrafficRow { address: String });

traffic_row!(HostgroupTrafficRow { hostgroup: String });

traffic_row!(AsnTrafficRow { asn: u32 });

traffic_row!(ExporterTrafficRow { exporter: String });

/// The `direction` column, an `Enum8('input' = 1, 'output' = 2)`.
/// RowBinary carries an `Enum8` as its `Int8` value, and the `clickhouse`
/// crate refuses serde's unit variants, so it is written as that number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum InterfaceDirection {
    Input = 1,
    Output = 2,
}

impl Serialize for InterfaceDirection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i8(*self as i8)
    }
}

traffic_row!(InterfaceTrafficRow {
    exporter: String,
    interface_index: u32,
    direction: InterfaceDirection,
});

/// One detection event, as one ClickHouse row of plain columns.
///
/// Written once. Nothing updates a detection event row: an event
/// describes what was true at one instant, and correcting it after the
/// fact would make the audit trail unusable as evidence. A detection
/// that turns out to be wrong is answered with another event, not by
/// editing the first.
#[derive(Debug, Clone, Serialize, clickhouse::Row)]
pub struct DetectionEventRow {
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub timestamp: time::OffsetDateTime,
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub detected_at: time::OffsetDateTime,
    pub schema_version: u32,
    pub event_id: String,
    pub detection_id: String,
    pub dedup_key: String,
    pub sequence: u64,
    pub kind: String,
    pub policy_id: String,
    pub policy_name: String,
    pub policy_version: u32,
    pub severity: String,
    pub execution_mode: String,
    pub action: String,
    pub tenant: String,
    pub scope_type: String,
    pub target: String,
    pub direction: String,
    pub family: u8,
    pub previous_state: String,
    pub state: String,
    pub reason: String,
    pub duration_ms: u64,
    pub window_ms: u64,
    pub top_metric: String,
    pub top_observed: u64,
    pub top_threshold: u64,
    pub top_ratio_percent: u64,
    pub matched_json: String,
    pub peak_json: String,
    pub bps: u64,
    pub pps: u64,
    pub fps: u64,
    pub tcp_bps: u64,
    pub tcp_pps: u64,
    pub udp_bps: u64,
    pub udp_pps: u64,
    pub icmp_bps: u64,
    pub icmp_pps: u64,
    pub tcp_syn_pps: u64,
    pub fragmented_pps: u64,
    pub dropped_pps: u64,
    pub protocol_seen: u8,
    pub tcp_flags_seen: u8,
    pub fragmentation_seen: u8,
    pub forwarding_status_seen: u8,
    pub sampling_corrected: u8,
    pub sampling_used_global_default: u8,
    pub sampling_max_rate: u32,
    pub flows_observed: u64,
    pub exporters_observed: u32,
    pub snapshots_in_detection: u64,
    /// Whether anything was actually done to the traffic. Always `0` in
    /// Phase 4 — the detector has no means to act. Stored anyway so an
    /// auditor can filter on it rather than having to know which
    /// product version could have acted.
    pub executed: u8,
    pub summary: String,
}

/// Milliseconds since the epoch as an `OffsetDateTime`, falling back to
/// the epoch itself rather than failing a write over a clock that was
/// set wrong. Losing one row to a bad timestamp is worse than storing a
/// visibly wrong one.
fn from_unix_millis(millis: u64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp((millis / 1000) as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

impl From<&tidegard_detector::DetectionEvent> for DetectionEventRow {
    fn from(event: &tidegard_detector::DetectionEvent) -> Self {
        // The worst crossing of the whole detection, which is what a
        // dashboard sorts by. Falls back to the current crossings when a
        // detection has no recorded peak yet.
        let top = event
            .peak
            .iter()
            .chain(event.matched.iter())
            .max_by_key(|reason| reason.ratio_percent);
        let rates = event.rates;
        DetectionEventRow {
            timestamp: from_unix_millis(event.observed_at_ms),
            detected_at: from_unix_millis(event.detected_at_ms),
            schema_version: event.schema_version,
            event_id: event.event_id.clone(),
            detection_id: event.detection_id.clone(),
            dedup_key: event.dedup_key.clone(),
            sequence: event.sequence,
            kind: event.kind.as_str().to_string(),
            policy_id: event.policy_id.clone(),
            policy_name: event.policy_name.clone(),
            policy_version: event.policy_version,
            severity: event.severity.as_str().to_string(),
            execution_mode: event.execution_mode.as_str().to_string(),
            action: event.action.as_str().to_string(),
            tenant: event.target.tenant.clone(),
            scope_type: event.target.scope_type.as_str().to_string(),
            target: event.target.display.clone(),
            direction: event.target.direction.as_str().to_string(),
            family: match event.target.address_family {
                tidegard_detector::AddressFamily::Ipv4 => 4,
                tidegard_detector::AddressFamily::Ipv6 => 6,
            },
            previous_state: event.previous_state.as_str().to_string(),
            state: event.state.as_str().to_string(),
            reason: event.reason.as_str().to_string(),
            duration_ms: event.duration_ms,
            window_ms: event.window_ms,
            top_metric: top
                .map(|r| r.metric.as_str().to_string())
                .unwrap_or_default(),
            top_observed: top.map(|r| r.observed).unwrap_or_default(),
            top_threshold: top.map(|r| r.threshold).unwrap_or_default(),
            top_ratio_percent: top.map(|r| r.ratio_percent).unwrap_or_default(),
            // A serialization failure here cannot happen for these
            // types, and an empty array is a far better outcome than
            // dropping the row.
            matched_json: serde_json::to_string(&event.matched)
                .unwrap_or_else(|_| "[]".to_string()),
            peak_json: serde_json::to_string(&event.peak).unwrap_or_else(|_| "[]".to_string()),
            bps: rates.bps,
            pps: rates.pps,
            fps: rates.fps,
            tcp_bps: rates.tcp_bps,
            tcp_pps: rates.tcp_pps,
            udp_bps: rates.udp_bps,
            udp_pps: rates.udp_pps,
            icmp_bps: rates.icmp_bps,
            icmp_pps: rates.icmp_pps,
            tcp_syn_pps: rates.tcp_syn_pps,
            fragmented_pps: rates.fragmented_pps,
            dropped_pps: rates.dropped_pps,
            protocol_seen: u8::from(event.completeness.protocol_seen),
            tcp_flags_seen: u8::from(event.completeness.tcp_flags_seen),
            fragmentation_seen: u8::from(event.completeness.fragmentation_seen),
            forwarding_status_seen: u8::from(event.completeness.forwarding_status_seen),
            sampling_corrected: u8::from(event.sampling.corrected),
            sampling_used_global_default: u8::from(event.sampling.used_global_default),
            sampling_max_rate: event.sampling.max_rate,
            flows_observed: event.flows_observed,
            exporters_observed: event.exporters_observed,
            snapshots_in_detection: event.snapshots_in_detection,
            executed: u8::from(event.executed),
            summary: event.summary.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_has_a_create_statement() {
        assert_eq!(CREATE_TABLE_STATEMENTS.len(), 10);
        for (name, ddl) in CREATE_TABLE_STATEMENTS {
            assert!(
                ddl.contains(name),
                "DDL for {name} should reference its own table name"
            );
            assert!(ddl.contains("MergeTree"), "{name} should use MergeTree");
            assert!(ddl.contains("TTL"), "{name} should declare a retention TTL");
        }
    }

    #[test]
    fn retention_constant_matches_documented_ddl() {
        assert_eq!(RETENTION_DAYS, 30);
        assert_eq!(EVENT_RETENTION_DAYS, 365);
        assert!(
            DDL_DETECTION_EVENTS.contains("INTERVAL 365 DAY"),
            "the events DDL must match EVENT_RETENTION_DAYS"
        );
    }

    #[test]
    fn traffic_tables_keep_the_shorter_retention() {
        for (name, ddl) in CREATE_TABLE_STATEMENTS {
            if *name == "wetechinetmon_detection_events" {
                continue;
            }
            assert!(
                ddl.contains("INTERVAL 30 DAY"),
                "{name} should keep the 30-day traffic retention"
            );
        }
    }

    #[test]
    fn traffic_rows_are_plain_columns() {
        use clickhouse::Row;
        // ADR 0053: no nested group, which RowBinary cannot encode.
        for columns in [
            TotalTrafficRow::COLUMN_NAMES,
            HostTrafficRow::COLUMN_NAMES,
            InterfaceTrafficRow::COLUMN_NAMES,
        ] {
            assert_eq!(columns[0], "timestamp");
            assert!(!columns.contains(&"counters"), "{columns:?}");
            assert!(columns.ends_with(&["fragmented_packets", "dropped_packets"]));
        }
        let counters = CounterFields {
            bytes: 7,
            dropped_packets: 3,
            ..Default::default()
        };
        let row = HostTrafficRow::new(
            time::OffsetDateTime::UNIX_EPOCH,
            "192.0.2.1".into(),
            4,
            counters,
        );
        assert_eq!(row.counters(), counters);
    }

    #[test]
    fn a_detection_event_becomes_a_row() {
        use std::collections::BTreeMap;
        use tidegard_detector::{
            ActionTaken, AddressFamily, DataCompleteness, DetectionEvent, DetectionState,
            EventKind, EventTarget, ExecutionMode, MatchedReason, MetricKind, MetricRates,
            SamplingStatus, ScopeId, ScopeType, Severity, TrafficDirection, TransitionReason,
        };

        let event = DetectionEvent {
            schema_version: 1,
            event_id: "e1".to_string(),
            detection_id: "d1".to_string(),
            sequence: 0,
            kind: EventKind::Started,
            dedup_key: "d1:started:0".to_string(),
            policy_id: "p1".to_string(),
            policy_name: "host bps".to_string(),
            policy_version: 3,
            severity: Severity::Critical,
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
            detected_at_ms: 1_700_000_000_000,
            observed_at_ms: 1_700_000_002_000,
            duration_ms: 2000,
            window_ms: 5000,
            matched: vec![MatchedReason {
                metric: MetricKind::Bps,
                observed: 5_000_000,
                threshold: 1_000_000,
                excess: 4_000_000,
                ratio_percent: 500,
            }],
            peak: vec![MatchedReason {
                metric: MetricKind::Bps,
                observed: 9_000_000,
                threshold: 1_000_000,
                excess: 8_000_000,
                ratio_percent: 900,
            }],
            skipped: Vec::new(),
            rates: MetricRates {
                bps: 5_000_000,
                pps: 4000,
                ..MetricRates::default()
            },
            completeness: DataCompleteness {
                protocol_seen: true,
                tcp_flags_seen: false,
                fragmentation_seen: false,
                forwarding_status_seen: true,
            },
            sampling: SamplingStatus {
                corrected: true,
                used_global_default: false,
                max_rate: 1000,
            },
            flows_observed: 42,
            exporters_observed: 2,
            snapshots_in_detection: 3,
            executed: false,
            summary: "critical started".to_string(),
        };

        let row = DetectionEventRow::from(&event);
        assert_eq!(row.kind, "started");
        assert_eq!(row.severity, "critical");
        assert_eq!(row.execution_mode, "alertOnly");
        assert_eq!(row.action, "alerted");
        assert_eq!(row.previous_state, "pendingTrigger");
        assert_eq!(row.state, "active");
        assert_eq!(row.reason, "triggerSustained");
        assert_eq!(row.family, 4);
        assert_eq!(row.target, "203.0.113.7");
        assert_eq!(row.policy_version, 3);
        assert_eq!(row.bps, 5_000_000);
        assert_eq!(row.pps, 4000);
        assert_eq!(row.protocol_seen, 1);
        assert_eq!(row.tcp_flags_seen, 0);
        assert_eq!(row.sampling_corrected, 1);
        assert_eq!(row.sampling_max_rate, 1000);
        assert_eq!(row.exporters_observed, 2);
        assert_eq!(row.snapshots_in_detection, 3);
        assert_eq!(
            row.top_observed, 9_000_000,
            "the peak, not the current rate, is what a dashboard sorts by"
        );
        assert_eq!(row.top_ratio_percent, 900);
        assert!(row.matched_json.contains("5000000"));
        assert!(row.peak_json.contains("9000000"));
        assert_eq!(row.timestamp.unix_timestamp(), 1_700_000_002);
        assert_eq!(row.detected_at.unix_timestamp(), 1_700_000_000);
        assert_eq!(
            row.executed, 0,
            "a Phase 4 row must never record that traffic was acted on"
        );
    }

    #[test]
    fn the_detection_events_table_records_whether_anything_was_executed() {
        assert!(
            DDL_DETECTION_EVENTS.contains("executed UInt8"),
            "the audit table must carry the executed column"
        );
    }

    #[test]
    fn an_impossible_timestamp_falls_back_rather_than_failing_the_write() {
        assert_eq!(
            from_unix_millis(u64::MAX).unix_timestamp(),
            time::OffsetDateTime::UNIX_EPOCH.unix_timestamp()
        );
        assert_eq!(from_unix_millis(0), time::OffsetDateTime::UNIX_EPOCH);
    }

    #[test]
    fn counter_fields_convert_from_aggregator_traffic_counters() {
        let counters = tidegard_aggregator::TrafficCounters {
            bytes: 100,
            packets: 10,
            flows: 1,
            tcp_bytes: 100,
            tcp_packets: 10,
            udp_bytes: 0,
            udp_packets: 0,
            icmp_bytes: 0,
            icmp_packets: 0,
            tcp_syn_packets: 1,
            fragmented_packets: 0,
            dropped_packets: 0,
        };
        let row_fields: CounterFields = counters.into();
        assert_eq!(row_fields.bytes, 100);
        assert_eq!(row_fields.tcp_syn_packets, 1);
    }
}
