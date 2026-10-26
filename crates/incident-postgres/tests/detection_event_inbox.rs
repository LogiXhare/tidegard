//! Milestone 5C: the detection-event inbox (ADR 0035).
//! - Enqueue is idempotent per `(tenant_id, dedup_key)` and refuses a batch
//!   holding another tenant's event.
//! - A batch is ingested in order and each row records its outcome.
//! - A payload that cannot be read is dead-lettered at once; an event with a
//!   newer schema is recorded as quarantined by the domain.
//! - A worker that ingested an event but crashed before marking it leaves it
//!   to be reclaimed, and the second ingest is a duplicate: one incident.
//! - A failing event backs off and is dead-lettered at the retry limit.
//! - Retention purges old processed rows.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{event, host_scope};
use tidegard_detector::{EventKind, MetricKind, TestClock, EVENT_SCHEMA_VERSION};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::correlation::TenantId;
use tidegard_incident::error::IncidentError;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::unit_of_work::IngestOutcomeKind;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::inbox::{
    enqueue, inbox_stats, BatchReport, InboxPolicy, InboxStats, InboxWorker,
};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::retention::{run_retention, RetentionPolicy};
use tidegard_incident_postgres::retry::RetryPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const ROWS: &str = "SELECT count(*) FROM detection_event_inbox";
const INCIDENTS: &str = "SELECT count(*) FROM incidents";

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

async fn scalar(client: &Client, sql: &str, params: &[&(dyn ToSql + Sync)]) -> i64 {
    client
        .query_one(sql, params)
        .await
        .expect("scalar query")
        .get(0)
}

async fn outcome_of(client: &Client, dedup_key: &str) -> (String, Option<String>) {
    let row = client
        .query_one(
            "SELECT status, outcome FROM detection_event_inbox WHERE dedup_key = $1",
            &[&dedup_key],
        )
        .await
        .expect("inbox row");
    (row.get(0), row.get(1))
}

fn processed(outcome: &str) -> (String, Option<String>) {
    ("processed".to_string(), Some(outcome.to_string()))
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

/// No backoff, so a retried row is claimable again at once.
fn policy(max_attempts: u32, lease: Duration) -> InboxPolicy {
    InboxPolicy {
        batch_size: 10,
        lease,
        retry: RetryPolicy {
            max_attempts,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        },
    }
}

#[tokio::test]
async fn the_inbox_ingests_each_event_once_and_dead_letters_what_it_cannot_process() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping detection_event_inbox: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };
    let mut client = connect(&url).await;
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("migrations must apply");

    let platform = platform_admin();
    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    );
    let scope = host_scope();
    let tenant = TenantId::new(scope.tenant);
    let started = event(&scope, 1, EventKind::Started, "p-inbox", MetricKind::Bps);
    let updated = event(&scope, 2, EventKind::Updated, "p-inbox", MetricKind::Bps);
    let batch = [started.clone(), updated.clone()];

    // --- Enqueue is idempotent, and refuses another tenant's event ---
    assert_eq!(enqueue(&client, &tenant, &batch).await.unwrap(), 2);
    assert_eq!(
        enqueue(&client, &tenant, &batch).await.unwrap(),
        0,
        "a re-sent batch adds nothing"
    );
    let mut foreign = event(&scope, 9, EventKind::Updated, "p-inbox", MetricKind::Bps);
    foreign.target.tenant = "globex".to_string();
    let refused = enqueue(&client, &tenant, &[foreign])
        .await
        .expect_err("another tenant's event");
    assert!(matches!(
        refused,
        PersistError::Rejected(IncidentError::TenantMismatch)
    ));
    assert_eq!(scalar(&client, ROWS, &[]).await, 2);

    // --- A payload that cannot be read, and an event from a newer schema ---
    client
        .execute(
            "INSERT INTO detection_event_inbox (
                tenant_id, dedup_key, detection_id, event_id, schema_version, payload
             ) VALUES ('acme', 'poison-1', 'det-x', 'ev-x', 1, '{\"garbage\": true}')",
            &[],
        )
        .await
        .unwrap();
    let mut newer = event(&scope, 3, EventKind::Updated, "p-inbox", MetricKind::Bps);
    newer.schema_version = EVENT_SCHEMA_VERSION + 1;
    newer.dedup_key = "det-row:updated:3:newer".to_string();
    assert_eq!(enqueue(&client, &tenant, &[newer]).await.unwrap(), 1);

    // --- One batch: in order, outcomes recorded, the poison dead-lettered ---
    let worker = InboxWorker::new(&platform, "worker-a", policy(3, Duration::from_secs(60)));
    let report = worker.process_batch(&service, &mut client).await.unwrap();
    assert_eq!(
        report,
        BatchReport {
            claimed: 4,
            processed: 3,
            dead_lettered: 1,
            ..BatchReport::default()
        }
    );
    assert_eq!(
        outcome_of(&client, &started.dedup_key).await,
        processed("created")
    );
    assert_eq!(
        outcome_of(&client, &updated.dedup_key).await,
        processed("updated")
    );
    assert_eq!(
        outcome_of(&client, "det-row:updated:3:newer").await,
        processed("quarantined")
    );
    assert_eq!(outcome_of(&client, "poison-1").await.0, "dead_letter");
    let dead = client
        .query_one(
            "SELECT tenant_id, aggregate_type, attempts, failure_reason, reviewed_at IS NULL
             FROM incident_dead_letter WHERE aggregate_id = 'poison-1'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(dead.get::<_, String>(0), "acme");
    assert_eq!(dead.get::<_, String>(1), "detection_event");
    assert_eq!(dead.get::<_, i32>(2), 1, "dead-lettered without retries");
    assert!(dead
        .get::<_, String>(3)
        .starts_with("incident.inbox_unreadable_payload"));
    assert!(dead.get::<_, bool>(4), "awaiting review");
    assert_eq!(scalar(&client, INCIDENTS, &[]).await, 1);
    assert_eq!(
        worker.process_batch(&service, &mut client).await.unwrap(),
        BatchReport::default(),
        "nothing is left to claim"
    );

    // --- Ingested, then crashed before marking: reclaimed, a duplicate ---
    let resent = event(&scope, 4, EventKind::Updated, "p-inbox", MetricKind::Bps);
    assert_eq!(
        enqueue(&client, &tenant, std::slice::from_ref(&resent))
            .await
            .unwrap(),
        1
    );
    let short_lease = policy(3, Duration::from_millis(200));
    let crashing = InboxWorker::new(&platform, "worker-crashing", short_lease);
    let claimed = crashing.claim(&client).await.unwrap();
    assert_eq!(claimed.len(), 1);
    let auth = AuthorizationContext::correlator(tenant.clone());
    let first = service
        .ingest_detection_event(&mut client, &auth, &resent)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.outcome_kind, IngestOutcomeKind::Updated);
    assert!(
        worker.claim(&client).await.unwrap().is_empty(),
        "the lease still holds"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    let takeover = InboxWorker::new(&platform, "worker-b", short_lease);
    let report = takeover.process_batch(&service, &mut client).await.unwrap();
    assert_eq!(report.processed, 1, "{report:?}");
    assert_eq!(
        outcome_of(&client, &resent.dedup_key).await,
        processed("duplicate")
    );
    assert!(
        !crashing
            .mark_processed(&client, claimed[0].inbox_id, IngestOutcomeKind::Updated)
            .await
            .unwrap(),
        "the crashed worker no longer holds the row"
    );
    assert_eq!(
        scalar(&client, INCIDENTS, &[]).await,
        1,
        "still one incident"
    );

    // --- A failing event backs off, then is dead-lettered at the limit ---
    // The row claims tenant globex, but its event targets acme, so the
    // domain refuses the ingest every time.
    let payload = serde_json::to_string(&event(
        &scope,
        5,
        EventKind::Updated,
        "p-inbox",
        MetricKind::Bps,
    ))
    .unwrap();
    client
        .execute(
            "INSERT INTO detection_event_inbox (
                tenant_id, dedup_key, detection_id, event_id, schema_version, payload
             ) VALUES ('globex', 'mismatch-1', 'det-row', 'det-row-5', 1, $1::text::jsonb)",
            &[&payload],
        )
        .await
        .unwrap();
    let limited = InboxWorker::new(&platform, "worker-c", policy(2, Duration::from_secs(60)));
    let first_try = limited.process_batch(&service, &mut client).await.unwrap();
    assert_eq!(first_try.retrying, 1, "{first_try:?}");
    let last_error: String = client
        .query_one(
            "SELECT last_error FROM detection_event_inbox WHERE dedup_key = 'mismatch-1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        last_error.starts_with("incident.tenant_mismatch"),
        "{last_error}"
    );
    let second_try = limited.process_batch(&service, &mut client).await.unwrap();
    assert_eq!(second_try.dead_lettered, 1, "{second_try:?}");
    assert_eq!(outcome_of(&client, "mismatch-1").await.0, "dead_letter");
    assert_eq!(
        inbox_stats(&platform, &client).await.unwrap(),
        InboxStats {
            pending: 0,
            retrying: 0,
            dead_letter: 2,
        }
    );

    // --- Retention purges processed rows past their age, nothing else ---
    client
        .execute(
            "UPDATE detection_event_inbox SET processed_at = now() - interval '8 days'
             WHERE status = 'processed'",
            &[],
        )
        .await
        .unwrap();
    let retention = run_retention(&platform, &client, &RetentionPolicy::engineering_default())
        .await
        .unwrap();
    assert_eq!(retention.processed_inbox, 4);
    assert_eq!(scalar(&client, ROWS, &[]).await, 2, "dead-letter rows stay");
}
