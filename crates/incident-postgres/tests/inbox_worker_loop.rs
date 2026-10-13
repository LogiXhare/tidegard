//! Milestone 5C: the correlation worker loop and its shutdown drain
//! (ADR 0012, ADR 0035).
//! - A running worker processes every event enqueued while it runs, in
//!   batches, into one incident.
//! - A database failure does not stop the loop: it backs off and resumes.
//! - Shutdown cuts an idle wait short, and nothing is claimed afterwards:
//!   an event enqueued after shutdown stays pending.
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
use tidegard_detector::{DetectionEvent, EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident_postgres::inbox::{enqueue, InboxPolicy, InboxWorker};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::pool::{build_pool, PoolPolicy};
use tidegard_incident_postgres::retry::RetryPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

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
    let deadline = Instant::now() + Duration::from_secs(10);
    while count(client, sql).await != expected {
        assert!(
            Instant::now() < deadline,
            "`{sql}` never reached {expected}"
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
    event(&host_scope(), sequence, kind, "p-loop", MetricKind::Bps)
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
async fn the_worker_loop_processes_until_shutdown_and_survives_a_failing_database() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping inbox_worker_loop: {TEST_DATABASE_URL_VAR} is not set. \
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
    let service = Arc::new(IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    ));
    let worker = InboxWorker::new(
        &platform_admin(),
        "worker-loop",
        InboxPolicy {
            batch_size: 2,
            retry: RetryPolicy {
                max_attempts: 10,
                base_delay: Duration::from_millis(20),
                max_delay: Duration::from_millis(50),
            },
            ..InboxPolicy::starting_default()
        },
    );
    const PROCESSED: &str = "SELECT count(*) FROM detection_event_inbox WHERE status = 'processed'";

    // --- Events enqueued while the loop runs are all processed ---
    let stop = Arc::new(AtomicBool::new(false));
    // Between empty claims the loop waits this long; shutdown cuts it short.
    let idle_wait = Duration::from_millis(100);
    let task = {
        let pool = pool.clone();
        let service = Arc::clone(&service);
        let shutdown = signal(&stop);
        tokio::spawn(async move { worker.run(&service, &pool, idle_wait, shutdown).await })
    };
    let first: Vec<DetectionEvent> = (1..=5).map(detection).collect();
    assert_eq!(enqueue(&admin, &tenant, &first).await.unwrap(), 5);
    wait_for(&admin, PROCESSED, 5).await;

    // --- The inbox cannot be read: the loop backs off and carries on ---
    admin
        .batch_execute("ALTER TABLE detection_event_inbox RENAME TO detection_event_inbox_offline")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    admin
        .batch_execute("ALTER TABLE detection_event_inbox_offline RENAME TO detection_event_inbox")
        .await
        .unwrap();
    assert!(
        !task.is_finished(),
        "a failing database never ends the loop"
    );
    assert_eq!(enqueue(&admin, &tenant, &[detection(6)]).await.unwrap(), 1);
    wait_for(&admin, PROCESSED, 6).await;
    assert_eq!(count(&admin, "SELECT count(*) FROM incidents").await, 1);

    // --- Shutdown is prompt, and nothing is claimed after it ---
    let stopping = Instant::now();
    stop.store(true, Ordering::Release);
    let report = task.await.unwrap();
    assert!(
        stopping.elapsed() < Duration::from_secs(2),
        "shutdown took {:?}",
        stopping.elapsed()
    );
    assert_eq!(report.processed, 6, "{report:?}");
    assert!(report.failed_batches >= 1, "{report:?}");
    assert_eq!(enqueue(&admin, &tenant, &[detection(7)]).await.unwrap(), 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM detection_event_inbox
             WHERE status = 'pending' AND locked_by IS NULL"
        )
        .await,
        1,
        "a stopped worker claims nothing"
    );
}
