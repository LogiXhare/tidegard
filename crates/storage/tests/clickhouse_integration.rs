//! Every ClickHouse row type, written to a real server and read back.
//!
//! Until Phase 9A-3 this test read a variable CI never set, so it always
//! skipped, and the traffic rows' `#[serde(flatten)]` panicked the
//! collector on its first export to a real server (ADR 0053). It now
//! reads the PostgreSQL job's ClickHouse settings and prints the standard
//! skip line, which that job refuses:
//!
//! - `TIDEGARD_CLICKHOUSE_TEST_URL` (plain HTTP, loopback);
//! - `TIDEGARD_CLICKHOUSE_TEST_USER` and `_PASSWORD`.

use std::time::{Duration, Instant};

use serde::Serialize;
use tidegard_storage::schema::{
    AsnTrafficRow, CounterFields, DetectionEventRow, ExporterTrafficRow, HostTrafficRow,
    HostgroupTrafficRow, InterfaceDirection, InterfaceTrafficRow, NetworkTrafficRow,
    Slash24TrafficRow, TotalTrafficRow,
};
use tidegard_storage::{run_migrations, BatchConfig, ClickHouseWriter, Client, RetryConfig};
use time::OffsetDateTime;

/// Writes one row through the collector's own writer and counts it back.
async fn write_one<T>(client: &Client, table: &'static str, row: T, marker: &str)
where
    T: clickhouse::Row + Serialize + Clone + Send + Sync + 'static,
{
    let start = Instant::now();
    let mut writer = ClickHouseWriter::new(
        client.clone(),
        table,
        BatchConfig {
            max_rows: 1,
            max_interval: Duration::from_millis(1),
        },
        RetryConfig::default(),
        start,
    );
    writer.push(row);
    let report = writer.tick(start + Duration::from_millis(10)).await;
    assert_eq!(report.write_failures, 0, "{table}: the write failed");
    assert_eq!(report.rows_written, 1, "{table}");
    let found: u64 = client
        .query(&format!(
            "SELECT count() FROM {table} WHERE {marker} SETTINGS select_sequential_consistency = 1"
        ))
        .fetch_one()
        .await
        .unwrap_or_else(|error| panic!("{table}: {error}"));
    assert!(found >= 1, "{table}: the row was not read back");
}

#[tokio::test]
async fn every_row_type_round_trips_against_a_real_server() {
    let Ok(url) = std::env::var("TIDEGARD_CLICKHOUSE_TEST_URL") else {
        eprintln!(
            "skipping every_row_type_round_trips_against_a_real_server: \
             TIDEGARD_CLICKHOUSE_TEST_URL is not set"
        );
        return;
    };
    let mut client = Client::default().with_url(&url);
    if let Ok(user) = std::env::var("TIDEGARD_CLICKHOUSE_TEST_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("TIDEGARD_CLICKHOUSE_TEST_PASSWORD") {
        client = client.with_password(password);
    }
    run_migrations(&client)
        .await
        .expect("the migrations apply against a real server");

    let now = OffsetDateTime::now_utc();
    // Distinct values, so each check finds this run's row.
    let tag = u64::from(now.nanosecond()) + 1;
    let counters = CounterFields {
        bytes: tag,
        packets: 12,
        flows: 1,
        tcp_bytes: 3,
        tcp_packets: 4,
        udp_bytes: 5,
        udp_packets: 6,
        icmp_bytes: 7,
        icmp_packets: 8,
        tcp_syn_packets: 9,
        fragmented_packets: 10,
        dropped_packets: 11,
    };
    let marker = format!("bytes = {tag} AND dropped_packets = 11");

    write_one(
        &client,
        "wetechinetmon_total_ipv4_traffic",
        TotalTrafficRow::new(now, counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_total_ipv6_traffic",
        TotalTrafficRow::new(now, counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_host_traffic",
        HostTrafficRow::new(now, "203.0.113.7".into(), 4, counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_network_traffic",
        NetworkTrafficRow::new(now, "2001:db8::".into(), 32, 6, counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_slash24_network_traffic",
        Slash24TrafficRow::new(now, "198.51.100.0".into(), counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_hostgroup_traffic",
        HostgroupTrafficRow::new(now, "core".into(), counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_asn_traffic",
        AsnTrafficRow::new(now, 64512, counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_exporter_traffic",
        ExporterTrafficRow::new(now, "192.0.2.1".into(), counters),
        &marker,
    )
    .await;
    write_one(
        &client,
        "wetechinetmon_interface_traffic",
        InterfaceTrafficRow::new(
            now,
            "192.0.2.1".into(),
            7,
            InterfaceDirection::Output,
            counters,
        ),
        &format!("{marker} AND direction = 'output'"),
    )
    .await;

    let event_id = format!("integration-{tag}");
    write_one(
        &client,
        "wetechinetmon_detection_events",
        DetectionEventRow {
            timestamp: now,
            detected_at: now,
            schema_version: 1,
            event_id: event_id.clone(),
            detection_id: "d1".into(),
            dedup_key: "d1:started:0".into(),
            sequence: 0,
            kind: "started".into(),
            policy_id: "p1".into(),
            policy_name: "host bps".into(),
            policy_version: 1,
            severity: "critical".into(),
            execution_mode: "dryRun".into(),
            action: "wouldMitigate".into(),
            tenant: "acme".into(),
            scope_type: "host".into(),
            target: "203.0.113.7".into(),
            direction: "incoming".into(),
            family: 4,
            previous_state: "pendingTrigger".into(),
            state: "active".into(),
            reason: "triggerSustained".into(),
            duration_ms: 2000,
            window_ms: 1000,
            top_metric: "bps".into(),
            top_observed: 2_000_000,
            top_threshold: 1_000_000,
            top_ratio_percent: 200,
            matched_json: "[]".into(),
            peak_json: "[]".into(),
            bps: 2_000_000,
            pps: 200,
            fps: 10,
            tcp_bps: 0,
            tcp_pps: 0,
            udp_bps: 2_000_000,
            udp_pps: 200,
            icmp_bps: 0,
            icmp_pps: 0,
            tcp_syn_pps: 0,
            fragmented_pps: 0,
            dropped_pps: 0,
            protocol_seen: 1,
            tcp_flags_seen: 0,
            fragmentation_seen: 0,
            forwarding_status_seen: 0,
            sampling_corrected: 0,
            sampling_used_global_default: 0,
            sampling_max_rate: 1,
            flows_observed: 10,
            exporters_observed: 1,
            snapshots_in_detection: 2,
            executed: 0,
            summary: "integration".into(),
        },
        &format!("event_id = '{event_id}'"),
    )
    .await;
}
