//! 5B-5's required race tests (phase5b-postgresql-persistence-plan.md): each
//! of the three active-incident partial unique indexes, individually, under
//! concurrent creates, and concurrent reopen races.
//!
//! `tests/retry_and_races.rs` covers the host index. This binary checks
//! each of the three indexes on its own:
//! - A second active incident is refused on that index, and the refusal
//!   is retryable.
//! - Two connections ingesting the first detections for one target at once
//!   open exactly one incident.
//!
//! It also checks that two recurrences racing on one resolved incident
//! reopen it exactly once, and that the second links to it rather than
//! opening a duplicate.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;

use support::{all_scopes, event, host_scope, in_episode, Scope};
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
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

/// The V10 index each scope in `all_scopes()` is guarded by, in its order.
const ACTIVE_INDEXES: [&str; 3] = [
    "incidents_active_host",
    "incidents_active_network",
    "incidents_active_hostgroup",
];

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

/// The same target under another tenant, so each section has its own rows.
fn under_tenant(scope: &Scope, tenant: &'static str) -> Scope {
    Scope {
        tenant,
        scope_type: scope.scope_type,
        scope_id: scope.scope_id.clone(),
    }
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
    uow.get(&id).expect("the incident was created").clone()
}

fn count_kind(kinds: &[IngestOutcomeKind], kind: IngestOutcomeKind) -> usize {
    kinds.iter().filter(|k| **k == kind).count()
}

#[tokio::test]
async fn each_active_index_holds_under_concurrent_creates_and_a_reopen_race_reopens_once() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping concurrent_races: {TEST_DATABASE_URL_VAR} is not set. \
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

    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(50_000)),
        Arc::new(TestClock::new()),
    );

    for (((scope, seed), index), (index_tenant, race_tenant)) in
        all_scopes().into_iter().zip(ACTIVE_INDEXES).zip([
            ("index-host", "race-host"),
            ("index-network", "race-network"),
            ("index-hostgroup", "race-hostgroup"),
        ])
    {
        // --- A second active incident for the target is refused on its own index ---
        let target = under_tenant(&scope, index_tenant);
        insert_incident(&client, &opened_incident(&target, seed, 2026))
            .await
            .expect("the first active incident for a target inserts");
        let lost = insert_incident(&client, &opened_incident(&target, seed + 100, 2027))
            .await
            .expect_err("a second active incident for the same target must be refused");
        assert_eq!(constraint_of(&lost).as_deref(), Some(index), "got {lost:?}");
        assert!(
            lost.is_retryable(),
            "{index}: a lost create race is retried"
        );

        // --- Two first detections at once, on two connections, open one incident ---
        let racing = under_tenant(&scope, race_tenant);
        let auth = AuthorizationContext::correlator(TenantId::new(race_tenant));
        let first = event(&racing, 1, EventKind::Started, "p-opening", MetricKind::Bps);
        let second = event(&racing, 2, EventKind::Updated, "p-opening", MetricKind::Bps);
        let (left, right) = tokio::join!(
            service.ingest_detection_event(&mut client, &auth, &first),
            service.ingest_detection_event(&mut other, &auth, &second),
        );
        let (left, right) = (
            left.expect("the first ingest commits")
                .expect("the domain accepts it"),
            right
                .expect("the second ingest commits")
                .expect("the domain accepts it"),
        );
        let kinds = [left.outcome_kind, right.outcome_kind];
        assert_eq!(
            count_kind(&kinds, IngestOutcomeKind::Created),
            1,
            "{index}: exactly one call creates, got {kinds:?}"
        );
        assert_eq!(
            left.incident_id, right.incident_id,
            "{index}: both link one incident"
        );
        for (what, sql, expected) in [
            (
                "incidents",
                "SELECT count(*) FROM incidents WHERE tenant_id = $1",
                1,
            ),
            (
                "detection links",
                "SELECT count(*) FROM incident_detection_events WHERE tenant_id = $1",
                2,
            ),
        ] {
            assert_eq!(
                scalar(&client, sql, &[&race_tenant]).await,
                expected,
                "{index}: {what}"
            );
        }
    }

    // --- Two recurrences racing on one resolved incident reopen it once ---
    let scope = under_tenant(&host_scope(), "reopener");
    let auth = AuthorizationContext::correlator(TenantId::new("reopener"));
    let incident_id = service
        .ingest_detection_event(
            &mut client,
            &auth,
            &event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps),
        )
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .unwrap();
    let id = incident_id.to_canonical_string();
    // Resolved a minute ago on the database's clock, inside the 15-minute
    // reopen window. Earlier lifecycle times move back to stay consistent.
    client
        .execute(
            "UPDATE incidents SET state = 'resolved',
                first_detected_at = transaction_timestamp() - interval '10 minutes',
                opened_at = transaction_timestamp() - interval '10 minutes',
                last_detected_at = transaction_timestamp() - interval '10 minutes',
                last_updated_at = transaction_timestamp() - interval '10 minutes',
                resolved_at = transaction_timestamp() - interval '1 minute'
             WHERE incident_id = $1::text::uuid",
            &[&id],
        )
        .await
        .unwrap();

    // Recurrences are new detection episodes (T-18).
    let recur_a = in_episode(
        event(&scope, 2, EventKind::Started, "p-opening", MetricKind::Bps),
        "det-recur",
    );
    let recur_b = in_episode(
        event(&scope, 3, EventKind::Started, "p-opening", MetricKind::Bps),
        "det-recur",
    );
    let (left, right) = tokio::join!(
        service.ingest_detection_event(&mut client, &auth, &recur_a),
        service.ingest_detection_event(&mut other, &auth, &recur_b),
    );
    let (left, right) = (
        left.expect("the first recurrence commits")
            .expect("the domain accepts it"),
        right
            .expect("the second recurrence commits")
            .expect("the domain accepts it"),
    );
    let kinds = [left.outcome_kind, right.outcome_kind];
    assert_eq!(
        count_kind(&kinds, IngestOutcomeKind::Reopened),
        1,
        "exactly one recurrence reopens, got {kinds:?}"
    );
    // Whichever recurrence loses the race links to the reopened incident: as
    // an update, or as a late link when it carries the older timestamp.
    assert_eq!(
        count_kind(&kinds, IngestOutcomeKind::Updated)
            + count_kind(&kinds, IngestOutcomeKind::LinkedLate),
        1,
        "the other links to the reopened incident, got {kinds:?}"
    );
    assert_eq!(left.incident_id, Some(incident_id));
    assert_eq!(right.incident_id, Some(incident_id));
    for (what, sql, expected) in [
        (
            "no duplicate incident",
            "SELECT count(*) FROM incidents WHERE tenant_id = 'reopener'",
            1,
        ),
        (
            "reopened exactly once and active",
            "SELECT count(*) FROM incidents WHERE tenant_id = 'reopener' \
             AND reopen_count = 1 AND state NOT IN ('resolved', 'closed')",
            1,
        ),
        (
            "all three events linked",
            "SELECT count(*) FROM incident_detection_events WHERE tenant_id = 'reopener'",
            3,
        ),
    ] {
        assert_eq!(scalar(&client, sql, &[]).await, expected, "{what}");
    }
}
