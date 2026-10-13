//! Milestone 5C: the incident manager as a running service (ADR 0036).
//! - Two instances migrating at once apply every migration exactly once
//!   (ADR 0024's advisory lock).
//! - Detection events in the inbox become one incident while the service
//!   runs, and its timers move the incident on schedule.
//! - Nothing is published from the outbox: no notification, no
//!   mitigation.
//! - Shutdown is prompt and reports what the worker did.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

#[path = "../../incident-postgres/tests/support/mod.rs"]
mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{event, host_scope};
use tidegard_detector::{EventKind, MetricKind};
use tidegard_incident::correlation::TenantId;
use tidegard_incident_manager::config::{
    Config, DATABASE_URL_ENV_VAR, MAINTENANCE_INTERVAL_SECS_ENV_VAR, METRICS_BIND_ENV_VAR,
    MIGRATE_ENV_VAR, STATS_INTERVAL_SECS_ENV_VAR, WORKER_IDLE_MS_ENV_VAR, WORKER_ID_ENV_VAR,
};
use tidegard_incident_manager::database;
use tidegard_incident_postgres::inbox::enqueue;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

const AGE: &str = "\
UPDATE incidents SET
    first_detected_at = first_detected_at - $1::text::interval,
    opened_at = opened_at - $1::text::interval,
    last_detected_at = last_detected_at - $1::text::interval,
    last_updated_at = last_updated_at - $1::text::interval";

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
    let deadline = Instant::now() + Duration::from_secs(15);
    while count(client, sql).await != expected {
        assert!(
            Instant::now() < deadline,
            "`{sql}` never reached {expected}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn config(url: &str, migrate: bool) -> Config {
    let env: HashMap<&str, String> = HashMap::from([
        (DATABASE_URL_ENV_VAR, url.to_string()),
        (MIGRATE_ENV_VAR, migrate.to_string()),
        (METRICS_BIND_ENV_VAR, "127.0.0.1:0".to_string()),
        (WORKER_ID_ENV_VAR, "manager-under-test".to_string()),
        (WORKER_IDLE_MS_ENV_VAR, "50".to_string()),
        (STATS_INTERVAL_SECS_ENV_VAR, "1".to_string()),
        (MAINTENANCE_INTERVAL_SECS_ENV_VAR, "1".to_string()),
    ]);
    Config::from_lookup(|var| Ok(env.get(var).cloned())).expect("a valid test configuration")
}

#[tokio::test]
async fn the_manager_ingests_runs_timers_and_stops_cleanly() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping service_lifecycle: {TEST_DATABASE_URL_VAR} is not set. \
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

    // --- Two instances migrating together apply each migration once ---
    let (pool, _) = database::connect(&config(&url, true)).expect("a loopback test database");
    let (first, second) = tokio::join!(database::migrate(&pool), database::migrate(&pool));
    let expected = tidegard_incident_postgres::migrations::migrations::runner()
        .get_migrations()
        .len();
    assert_eq!(first.unwrap() + second.unwrap(), expected);
    assert_eq!(
        database::migrate(&pool).await.unwrap(),
        0,
        "a later start finds nothing to apply"
    );
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'"
        )
        .await,
        0,
        "the migration lock is released"
    );

    // --- Running: inbox events become one incident ---
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = {
        let stop = Arc::clone(&stop);
        async move {
            while !stop.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    let service = tokio::spawn(tidegard_incident_manager::run(config(&url, true), shutdown));
    let tenant = TenantId::new(host_scope().tenant);
    let events = [
        event(
            &host_scope(),
            1,
            EventKind::Started,
            "p-manager",
            MetricKind::Bps,
        ),
        event(
            &host_scope(),
            2,
            EventKind::Updated,
            "p-manager",
            MetricKind::Bps,
        ),
    ];
    assert_eq!(enqueue(&admin, &tenant, &events).await.unwrap(), 2);
    wait_for(
        &admin,
        "SELECT count(*) FROM detection_event_inbox WHERE status = 'processed'",
        2,
    )
    .await;
    assert_eq!(count(&admin, "SELECT count(*) FROM incidents").await, 1);
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM incidents WHERE state = 'open'"
        )
        .await,
        1
    );

    // --- The timers run on schedule: a silent incident starts recovering ---
    admin.execute(AGE, &[&"6 minutes"]).await.unwrap();
    wait_for(
        &admin,
        "SELECT count(*) FROM incidents WHERE state = 'recovering'",
        1,
    )
    .await;

    // --- Nothing notified, nothing mitigated: the outbox is only filled ---
    assert!(count(&admin, "SELECT count(*) FROM incident_outbox").await > 0);
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM incident_outbox WHERE status <> 'pending'"
        )
        .await,
        0,
        "the manager never publishes the outbox"
    );

    // --- Shutdown is prompt ---
    let stopping = Instant::now();
    stop.store(true, Ordering::Release);
    let report = tokio::time::timeout(Duration::from_secs(5), service)
        .await
        .expect("the manager stops within five seconds")
        .unwrap()
        .expect("the manager started");
    assert!(
        stopping.elapsed() < Duration::from_secs(5),
        "shutdown took {:?}",
        stopping.elapsed()
    );
    assert_eq!(report.migrations_applied, 0);
    assert_eq!(report.worker.processed, 2, "{report:?}");
    assert_eq!(report.worker.dead_lettered, 0, "{report:?}");
}
