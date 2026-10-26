//! Milestone 5C: the detector-side producer (ADR 0035).
//! - While the inbox cannot be written, published events stay queued and
//!   the drain keeps retrying; none is lost.
//! - Once writes succeed again, every event reaches the inbox, and a
//!   re-published event is not added twice.
//! - On shutdown the sink stops accepting and the drain flushes what is
//!   left. What it cannot write in its bounded final flush is reported.
//! - The worker then turns the inbox into one incident.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{event, host_scope};
use tidegard_detector::{
    DetectionEvent, DetectionEventSink, EventKind, MetricKind, SinkError, TestClock,
};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident_postgres::inbox::{InboxPolicy, InboxWorker};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::pool::{build_pool, PoolPolicy};
use tidegard_incident_postgres::producer::{inbox_producer, DrainReport, ProducerPolicy};
use tidegard_incident_postgres::retry::RetryPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const ROWS: &str = "SELECT count(*) FROM detection_event_inbox";
const TAKE_OFFLINE: &str =
    "ALTER TABLE detection_event_inbox RENAME TO detection_event_inbox_offline";
const BRING_ONLINE: &str =
    "ALTER TABLE detection_event_inbox_offline RENAME TO detection_event_inbox";

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

async fn rows(client: &Client) -> i64 {
    client.query_one(ROWS, &[]).await.expect("count").get(0)
}

async fn wait_for_rows(client: &Client, expected: i64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while rows(client).await != expected {
        assert!(
            Instant::now() < deadline,
            "the inbox never reached {expected} rows"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn detection(sequence: u64) -> DetectionEvent {
    let kind = if sequence == 1 {
        EventKind::Started
    } else {
        EventKind::Updated
    };
    event(&host_scope(), sequence, kind, "p-producer", MetricKind::Bps)
}

fn fast_policy() -> ProducerPolicy {
    ProducerPolicy {
        capacity: 100,
        batch_size: 2,
        flush_interval: Duration::from_millis(20),
        retry: RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(50),
        },
    }
}

fn signal(flag: &Arc<AtomicBool>) -> impl Future<Output = ()> + Send + 'static {
    let flag = Arc::clone(flag);
    async move {
        while !flag.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn platform_admin() -> PlatformAuthority {
    let context = AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Operator {
            id: "platform-admin".to_string(),
        },
        FixedBundleResolver.permissions_for("platform_admin"),
    );
    PlatformAuthority::from_context(&context).expect("a platform admin is authorized")
}

#[tokio::test]
async fn queued_events_survive_an_unwritable_inbox_and_are_flushed_on_shutdown() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping inbox_producer: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };
    let mut admin = connect(&url).await;
    admin
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut admin)
        .await
        .expect("migrations must apply");
    let pool = build_pool(
        url.parse()
            .expect("the test URL is a valid connection string"),
        tokio_postgres::NoTls,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();
    let tenant = TenantId::new(host_scope().tenant);

    // --- The inbox cannot be written: events stay queued, nothing is lost ---
    admin.batch_execute(TAKE_OFFLINE).await.unwrap();
    let (sink, mut drain) = inbox_producer(tenant.clone(), fast_policy());
    for sequence in 1..=5 {
        sink.publish(&detection(sequence)).unwrap();
    }
    let stop = Arc::new(AtomicBool::new(false));
    let task = {
        let pool = pool.clone();
        let shutdown = signal(&stop);
        tokio::spawn(async move { drain.run(&pool, shutdown).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sink.queued(), 5, "a failed write keeps its events");

    // --- Writable again: everything arrives, a re-published event once ---
    admin.batch_execute(BRING_ONLINE).await.unwrap();
    wait_for_rows(&admin, 5).await;
    sink.publish(&detection(5)).unwrap();
    sink.publish(&detection(6)).unwrap();
    wait_for_rows(&admin, 6).await;

    // --- Shutdown: the sink stops accepting, the drain finishes cleanly ---
    stop.store(true, Ordering::Release);
    let report: DrainReport = task.await.unwrap();
    assert_eq!(report.enqueued, 6, "{report:?}");
    assert!(report.failed_writes >= 1, "{report:?}");
    assert_eq!(report.abandoned, 0, "{report:?}");
    assert_eq!(
        sink.publish(&detection(7)),
        Err(SinkError::Closed {
            sink: "postgres_inbox"
        })
    );
    assert_eq!(sink.dropped_full(), 0);

    // --- A final flush that cannot write reports what it abandons ---
    admin.batch_execute(TAKE_OFFLINE).await.unwrap();
    let (late_sink, mut late_drain) = inbox_producer(tenant.clone(), fast_policy());
    late_sink.publish(&detection(8)).unwrap();
    let already_stopped = async {};
    let late = late_drain.run(&pool, already_stopped).await;
    assert_eq!(late.abandoned, 1, "{late:?}");
    assert_eq!(late.enqueued, 0, "{late:?}");
    assert!(late.failed_writes >= 3, "{late:?}");
    admin.batch_execute(BRING_ONLINE).await.unwrap();
    assert_eq!(rows(&admin).await, 6);

    // --- The worker turns the six events into one incident ---
    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    );
    let worker = InboxWorker::new(&platform_admin(), "worker-a", InboxPolicy::default());
    let report = worker.process_batch(&service, &mut admin).await.unwrap();
    assert_eq!(report.processed, 6, "{report:?}");
    let incidents: i64 = admin
        .query_one("SELECT count(*) FROM incidents", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(incidents, 1);
}
