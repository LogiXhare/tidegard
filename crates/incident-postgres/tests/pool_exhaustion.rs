//! The persistence plan's pool-exhaustion test (5B-5), against ADR 0022's
//! requirements for the pool:
//! - With every connection in use, acquiring fails within its wait timeout
//!   as `Unavailable`, rather than blocking, and is not retried.
//! - A released connection is reused.
//! - A connection that died while idle is verified, replaced, and never
//!   handed to a call.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{event, host_scope};
use tidegard_detector::{EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::unit_of_work::IngestOutcomeKind;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::pool::{acquire, build_pool, PoolPolicy};
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

async fn backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("backend pid")
        .get(0)
}

#[tokio::test]
async fn an_exhausted_pool_is_unavailable_in_bounded_time_and_dead_connections_are_replaced() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping pool_exhaustion: {TEST_DATABASE_URL_VAR} is not set. \
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
            max_size: 1,
            wait_timeout: Duration::from_millis(300),
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();
    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    );
    let scope = host_scope();
    let auth = AuthorizationContext::correlator(TenantId::new(scope.tenant));

    // --- Every connection in use: acquiring fails in bounded time, unretried ---
    let mut held = acquire(&pool).await.unwrap();
    let started = Instant::now();
    let exhausted = acquire(&pool)
        .await
        .expect_err("the only connection is in use");
    let waited = started.elapsed();
    assert!(
        matches!(exhausted, PersistError::Unavailable(_)),
        "got {exhausted:?}"
    );
    assert!(!exhausted.is_retryable());
    assert!(
        waited >= Duration::from_millis(250) && waited < Duration::from_secs(5),
        "waited {waited:?}: the wait timeout bounds it"
    );

    let created = service
        .ingest_detection_event(
            &mut held,
            &auth,
            &event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.outcome_kind, IngestOutcomeKind::Created);
    let pid = backend_pid(&held).await;
    drop(held);

    // --- Released, the connection is reused ---
    let reused = acquire(&pool)
        .await
        .expect("a released connection is available again");
    assert_eq!(
        backend_pid(&reused).await,
        pid,
        "the idle connection is reused"
    );
    drop(reused);

    // --- A connection that died while idle is replaced, never handed out ---
    let terminated: bool = admin
        .query_one("SELECT pg_terminate_backend($1, 5000)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(terminated);
    let mut replaced = acquire(&pool)
        .await
        .expect("verification replaces the dead connection");
    assert_ne!(backend_pid(&replaced).await, pid, "a new connection");
    let linked = service
        .ingest_detection_event(
            &mut replaced,
            &auth,
            &event(&scope, 2, EventKind::Updated, "p-opening", MetricKind::Bps),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(linked.outcome_kind, IngestOutcomeKind::Updated);
    assert_eq!(linked.incident_id, created.incident_id);
}
