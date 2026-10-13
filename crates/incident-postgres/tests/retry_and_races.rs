//! Milestone 5B-3(c): real PostgreSQL failures are classified the way
//! ADR 0026 says, and two concurrent first detections for one target open
//! exactly one incident.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;

use support::{event, host_scope, Scope};
use tidegard_detector::{EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::incident::Incident;
use tidegard_incident::number::InMemoryNumberAllocator;
use tidegard_incident::unit_of_work::{IncidentUnitOfWork, IngestOutcomeKind};
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_incident_postgres::sql::insert_incident;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

const BUMP_ALLOCATOR: &str =
    "UPDATE incident_number_allocators SET next_value = next_value + 1 WHERE tenant_id = $1";

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

fn constraint_of(error: &PersistError) -> Option<String> {
    match error {
        PersistError::Database(error) => error
            .as_db_error()
            .and_then(|db| db.constraint())
            .map(str::to_string),
        _ => None,
    }
}

/// An incident opened by a first detection, built in memory only.
fn opened_incident(scope: &Scope, seed: u64, allocation_year: u32) -> Incident {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(seed)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    )
    .with_number_allocation_year(allocation_year);
    let correlator = AuthorizationContext::correlator(TenantId::new(scope.tenant));
    let started = event(scope, 1, EventKind::Started, "p-opening", MetricKind::Bps);
    let id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();
    uow.get(&id).unwrap().clone()
}

#[tokio::test]
async fn transient_failures_are_classified_and_concurrent_creates_open_one_incident() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping retry_and_races: {TEST_DATABASE_URL_VAR} is not set. \
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
    let mut other = connect(&url).await;

    // --- A lost creation race: 23505 on an active-incident index ---
    let scope = host_scope();
    let winner = opened_incident(&scope, 100, 2026);
    // A different id and number, but the same open target.
    let loser = opened_incident(&scope, 200, 2027);
    insert_incident(&client, &winner)
        .await
        .expect("the first active incident for a target inserts");
    let lost = insert_incident(&client, &loser)
        .await
        .expect_err("a second active incident for the same target must be refused");
    assert_eq!(
        constraint_of(&lost).as_deref(),
        Some("incidents_active_host"),
        "got {lost:?}"
    );
    assert!(lost.is_retryable());

    // --- The same event linked twice: 23505 on the dedup constraint ---
    const LINK: &str = "\
        INSERT INTO incident_detection_events (
            incident_id, detection_event_id, tenant_id, dedup_key, detection_id, policy_id,
            policy_version, kind, severity, observed_at, detected_at, matched, rates, link_type
        ) VALUES (
            $1::text::uuid, $2, 'acme', 'same-dedup-key', 'det', 'p',
            1, 'started', 'major', now(), now(), '[]', '{}', 'opening'
        )";
    let winner_id = winner.incident_id.to_canonical_string();
    client
        .execute(LINK, &[&winner_id, &"event-a"])
        .await
        .unwrap();
    let duplicate = PersistError::from(
        client
            .execute(LINK, &[&winner_id, &"event-b"])
            .await
            .expect_err("a second link with the same dedup key must be refused"),
    );
    assert_eq!(
        constraint_of(&duplicate).as_deref(),
        Some("incident_detection_events_tenant_id_dedup_key_key"),
        "got {duplicate:?}"
    );
    assert!(duplicate.is_retryable());

    // --- A deadlock: 40P01 ---
    client
        .batch_execute(
            "INSERT INTO incident_number_allocators (tenant_id) VALUES ('lock-a'), ('lock-b')",
        )
        .await
        .unwrap();
    {
        let a = client.transaction().await.unwrap();
        let b = other.transaction().await.unwrap();
        a.execute(BUMP_ALLOCATOR, &[&"lock-a"]).await.unwrap();
        b.execute(BUMP_ALLOCATOR, &[&"lock-b"]).await.unwrap();
        // Each now waits for the row the other holds; PostgreSQL's deadlock
        // detector aborts one of them after `deadlock_timeout`.
        let (left, right) = tokio::join!(
            a.execute(BUMP_ALLOCATOR, &[&"lock-b"]),
            b.execute(BUMP_ALLOCATOR, &[&"lock-a"]),
        );
        let failures: Vec<PersistError> = [left, right]
            .into_iter()
            .filter_map(Result::err)
            .map(PersistError::from)
            .collect();
        assert_eq!(failures.len(), 1, "exactly one side is the deadlock victim");
        let code = match &failures[0] {
            PersistError::Database(error) => error.code().cloned(),
            _ => None,
        };
        assert_eq!(
            code,
            Some(SqlState::T_R_DEADLOCK_DETECTED),
            "got {:?}",
            failures[0]
        );
        assert!(failures[0].is_retryable());
        // Dropping both transactions rolls them back.
    }

    // --- Two concurrent first detections for one target open one incident ---
    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(5_000)),
        Arc::new(TestClock::new()),
    );
    let race_scope = Scope {
        tenant: "racer",
        scope_type: scope.scope_type,
        scope_id: scope.scope_id.clone(),
    };
    let racer = AuthorizationContext::correlator(TenantId::new("racer"));
    let first = event(
        &race_scope,
        1,
        EventKind::Started,
        "p-opening",
        MetricKind::Bps,
    );
    let second = event(
        &race_scope,
        2,
        EventKind::Updated,
        "p-opening",
        MetricKind::Bps,
    );
    let (first_result, second_result) = tokio::join!(
        service.ingest_detection_event(&mut client, &racer, &first),
        service.ingest_detection_event(&mut other, &racer, &second),
    );
    let outcomes = [
        first_result
            .expect("the first ingest commits")
            .expect("the domain accepts it")
            .outcome_kind,
        second_result
            .expect("the second ingest commits")
            .expect("the domain accepts it")
            .outcome_kind,
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|kind| **kind == IngestOutcomeKind::Created)
            .count(),
        1,
        "exactly one call creates the incident, got {outcomes:?}"
    );
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incidents WHERE tenant_id = 'racer'",
            &[]
        )
        .await,
        1
    );
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_detection_events WHERE tenant_id = 'racer'",
            &[]
        )
        .await,
        2,
        "both events are linked to the one incident"
    );
    assert_eq!(
        scalar(
            &client,
            "SELECT next_value FROM incident_number_allocators WHERE tenant_id = 'racer'",
            &[]
        )
        .await,
        2,
        "only one incident number was consumed"
    );
}
