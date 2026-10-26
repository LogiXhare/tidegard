//! Milestone 5C's end-to-end test: synthetic IPFIX bytes in, an incident
//! out, through the real processes.
//!
//! The real collector (`run_until`) receives IPFIX over UDP, decodes,
//! classifies, aggregates and detects, and its inbox producer writes the
//! detection events to PostgreSQL. The real incident manager (`run`)
//! migrates the database, ingests the events and opens one incident. Then:
//!
//! - **Nothing was notified:** every outbox row is still `pending`; no
//!   process publishes it in this phase.
//! - **Nothing was mitigated:** the policy is `dryRun`, and every event
//!   says its action was not executed.
//! - **Replay is safe:** enqueueing the same events again adds nothing, and
//!   replaying them after the inbox rows are gone is processed as
//!   duplicates, with no new incident and no new outbox row.
//! - **Both processes stop cleanly**, and the collector's final flush loses
//!   nothing.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tidegard_classifier::PrefixConfigEntry;
use tidegard_collector::config::IncidentDatabase;
use tidegard_collector::Config as CollectorConfig;
use tidegard_detector::DetectionEvent;
use tidegard_incident::correlation::TenantId;
use tidegard_incident_manager::config::{
    Config as ManagerConfig, DATABASE_URL_ENV_VAR, MAINTENANCE_INTERVAL_SECS_ENV_VAR,
    METRICS_BIND_ENV_VAR, STATS_INTERVAL_SECS_ENV_VAR, WORKER_IDLE_MS_ENV_VAR, WORKER_ID_ENV_VAR,
};
use tidegard_incident_postgres::inbox::enqueue;
use tokio::net::UdpSocket;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const TENANT: &str = "acme";

const POLICY_DOC: &str = r#"{
  "schemaVersion": 1,
  "tenants": [ { "tenant": "acme", "prefixes": ["10.0.0.0/8"] } ],
  "policies": [
    {
      "id": "e2e-host-inbound",
      "name": "end-to-end host inbound bps",
      "tenant": "acme",
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

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("must be able to connect to the configured ephemeral test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection closed: {error}");
        }
    });
    client
}

async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.expect("count").get(0)
}

async fn wait_for(client: &Client, sql: &str, expected: i64) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while count(client, sql).await != expected {
        assert!(
            Instant::now() < deadline,
            "`{sql}` never reached {expected}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn stop_signal(flag: &Arc<AtomicBool>) -> impl std::future::Future<Output = ()> + Send + 'static {
    let flag = Arc::clone(flag);
    async move {
        while !flag.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// An IPFIX message header (RFC 7011 §3.1).
fn message(sequence: u32, sets: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&10u16.to_be_bytes());
    bytes.extend_from_slice(&((16 + sets.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&7u32.to_be_bytes());
    bytes.extend_from_slice(sets);
    bytes
}

/// Template 256: sourceIPv4Address, destinationIPv4Address,
/// octetDeltaCount, packetDeltaCount, protocolIdentifier.
fn template_set() -> Vec<u8> {
    let fields: [(u16, u16); 5] = [(8, 4), (12, 4), (1, 8), (2, 8), (4, 1)];
    let mut record = Vec::new();
    record.extend_from_slice(&256u16.to_be_bytes());
    record.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for (element, length) in fields {
        record.extend_from_slice(&element.to_be_bytes());
        record.extend_from_slice(&length.to_be_bytes());
    }
    let mut set = Vec::new();
    set.extend_from_slice(&2u16.to_be_bytes());
    set.extend_from_slice(&((4 + record.len()) as u16).to_be_bytes());
    set.extend_from_slice(&record);
    set
}

/// One UDP flow record from an external source to a local host.
fn data_set(octets: u64) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&[203, 0, 113, 1]);
    record.extend_from_slice(&[10, 0, 0, 5]);
    record.extend_from_slice(&octets.to_be_bytes());
    record.extend_from_slice(&100u64.to_be_bytes());
    record.push(17);
    let mut set = Vec::new();
    set.extend_from_slice(&256u16.to_be_bytes());
    set.extend_from_slice(&((4 + record.len()) as u16).to_be_bytes());
    set.extend_from_slice(&record);
    set
}

fn free_udp_port() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a free local port");
    socket.local_addr().unwrap()
}

fn collector_config(url: &str, bind: SocketAddr, policy_file: &std::path::Path) -> CollectorConfig {
    CollectorConfig {
        bind,
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        queue_capacity: 1_000,
        local_prefixes: vec![PrefixConfigEntry {
            network: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            tenant: TENANT.to_string(),
            hostgroup: None,
        }],
        exporters: tidegard_collector::ExporterLimits::default(),
        max_hosts: 1_000,
        max_networks: 1_000,
        max_hostgroups: 100,
        max_asns: 100,
        inactivity_ttl_secs: 300,
        sampling_global_default: None,
        clickhouse: None,
        detection_policy_file: Some(policy_file.display().to_string()),
        detection_window_secs: 1,
        detection_max_scopes: 1_000,
        detection_event_buffer: 64,
        detection_stale_secs: 180,
        incident_database: Some(IncidentDatabase {
            url: url.to_string(),
            tls: None,
        }),
    }
}

fn manager_config(url: &str) -> ManagerConfig {
    let env: HashMap<&str, String> = HashMap::from([
        (DATABASE_URL_ENV_VAR, url.to_string()),
        (METRICS_BIND_ENV_VAR, "127.0.0.1:0".to_string()),
        (WORKER_ID_ENV_VAR, "manager-end-to-end".to_string()),
        (WORKER_IDLE_MS_ENV_VAR, "50".to_string()),
        (STATS_INTERVAL_SECS_ENV_VAR, "1".to_string()),
        (MAINTENANCE_INTERVAL_SECS_ENV_VAR, "1".to_string()),
    ]);
    ManagerConfig::from_lookup(|var| Ok(env.get(var).cloned())).expect("a valid test configuration")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn synthetic_ipfix_becomes_one_incident_and_nothing_is_notified_or_mitigated() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping incident_end_to_end: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };
    let admin = connect(&url).await;
    admin
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");

    // --- The incident manager starts, and migrates the database ---
    let manager_stop = Arc::new(AtomicBool::new(false));
    let manager = tokio::spawn(tidegard_incident_manager::run(
        manager_config(&url),
        stop_signal(&manager_stop),
    ));
    wait_for(
        &admin,
        "SELECT count(*) FROM pg_tables WHERE tablename = 'detection_event_inbox'",
        1,
    )
    .await;

    // --- The collector starts with detection and the inbox producer on ---
    let policy_file =
        std::env::temp_dir().join(format!("tidegard-e2e-policy-{}.json", std::process::id()));
    std::fs::write(&policy_file, POLICY_DOC).expect("the policy file is written");
    let bind = free_udp_port();
    let collector_stop = Arc::new(AtomicBool::new(false));
    let collector = tokio::spawn(tidegard_collector::run_until(
        collector_config(&url, bind, &policy_file),
        stop_signal(&collector_stop),
    ));

    // --- Synthetic IPFIX until an incident opens ---
    // 25 000 bytes every 200 ms is 1 Mbit/s into 10.0.0.5, twice the
    // policy's threshold. The template is resent with every batch, so
    // datagrams sent before the collector bound its socket cost nothing.
    let exporter = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut sequence: u32 = 0;
    while count(&admin, "SELECT count(*) FROM incidents").await == 0 {
        assert!(
            Instant::now() < deadline,
            "no incident was opened within 30 seconds of synthetic traffic"
        );
        exporter
            .send_to(&message(sequence, &template_set()), bind)
            .await
            .unwrap();
        exporter
            .send_to(&message(sequence, &data_set(25_000)), bind)
            .await
            .unwrap();
        sequence += 1;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // --- One incident, for the right tenant and host ---
    assert_eq!(count(&admin, "SELECT count(*) FROM incidents").await, 1);
    let incident = admin
        .query_one(
            "SELECT tenant_id, state, host(target_addr) AS host FROM incidents",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(incident.get::<_, String>("tenant_id"), TENANT);
    assert_eq!(incident.get::<_, String>("state"), "open");
    assert_eq!(incident.get::<_, String>("host"), "10.0.0.5");

    // --- Stop the traffic and both processes ---
    collector_stop.store(true, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(15), collector)
        .await
        .expect("the collector stops within fifteen seconds")
        .unwrap()
        .expect("the collector ran");
    let _ = std::fs::remove_file(&policy_file);
    let enqueued = count(&admin, "SELECT count(*) FROM detection_event_inbox").await;
    assert!(enqueued >= 1);
    wait_for(
        &admin,
        "SELECT count(*) FROM detection_event_inbox WHERE status <> 'processed'",
        0,
    )
    .await;

    // --- Nothing notified, nothing mitigated ---
    let outbox = count(&admin, "SELECT count(*) FROM incident_outbox").await;
    assert!(outbox > 0, "opening the incident filled the outbox");
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM incident_outbox WHERE status <> 'pending'"
        )
        .await,
        0,
        "no process publishes the outbox in this phase"
    );
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM detection_event_inbox
             WHERE payload->>'executionMode' <> 'dryRun'
                OR (payload->>'executed')::boolean"
        )
        .await,
        0,
        "every event is a dry run whose action was not executed"
    );

    // --- Replay is safe ---
    let payloads: Vec<DetectionEvent> = admin
        .query(
            "SELECT payload::text AS payload FROM detection_event_inbox ORDER BY inbox_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| serde_json::from_str(row.get::<_, &str>("payload")).expect("a stored event"))
        .collect();
    let tenant = TenantId::new(TENANT);
    assert_eq!(
        enqueue(&admin, &tenant, &payloads).await.unwrap(),
        0,
        "the same events enqueued again add nothing"
    );
    admin
        .batch_execute("DELETE FROM detection_event_inbox")
        .await
        .unwrap();
    assert_eq!(
        enqueue(&admin, &tenant, &payloads).await.unwrap(),
        enqueued as u64,
        "with the inbox emptied, the replay is accepted"
    );
    wait_for(
        &admin,
        "SELECT count(*) FROM detection_event_inbox WHERE status <> 'processed'",
        0,
    )
    .await;
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM detection_event_inbox WHERE outcome <> 'duplicate'"
        )
        .await,
        0,
        "every replayed event is recognised as a duplicate"
    );
    assert_eq!(count(&admin, "SELECT count(*) FROM incidents").await, 1);
    assert_eq!(
        count(&admin, "SELECT count(*) FROM incident_outbox").await,
        outbox,
        "a replay writes no outbox message"
    );

    manager_stop.store(true, Ordering::Release);
    let report = tokio::time::timeout(Duration::from_secs(5), manager)
        .await
        .expect("the manager stops within five seconds")
        .unwrap()
        .expect("the manager started");
    assert_eq!(report.worker.dead_lettered, 0, "{report:?}");
    assert_eq!(
        report.worker.processed as i64,
        2 * enqueued,
        "every original and every replayed event was processed once"
    );
}
