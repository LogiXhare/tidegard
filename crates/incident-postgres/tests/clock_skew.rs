//! ADR 0031's clock-skew integration test (5B-5).
//!
//! Decisions are made at PostgreSQL's `transaction_timestamp()`. A
//! recurrence whose decision time precedes the persisted `resolved_at` is
//! refused with a structured `ClockSkew`. It neither reopens nor opens a
//! duplicate incident. Once the reference is in the database's past, the same
//! event reopens. A late event of the resolved episode links as evidence
//! and does not reopen (T-18). The injected test clock sits at 1970, so that reopen
//! proves the decision time came from the database.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;

use support::{event, host_scope, in_episode};
use tidegard_detector::{EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::error::IncidentError;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::unit_of_work::IngestOutcomeKind;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::types::ToSql;
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

async fn scalar(client: &Client, sql: &str, params: &[&(dyn ToSql + Sync)]) -> i64 {
    client
        .query_one(sql, params)
        .await
        .expect("scalar query")
        .get(0)
}

#[tokio::test]
async fn a_recurrence_before_the_persisted_reference_is_refused_and_time_comes_from_the_database() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping clock_skew: {TEST_DATABASE_URL_VAR} is not set. \
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

    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    );
    let scope = host_scope();
    let tenant = TenantId::new(scope.tenant);
    let auth = AuthorizationContext::correlator(tenant.clone());

    let opening = event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps);
    let incident_id = service
        .ingest_detection_event(&mut client, &auth, &opening)
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .unwrap();
    let id = incident_id.to_canonical_string();
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incidents WHERE incident_id = $1::text::uuid \
             AND opened_at > transaction_timestamp() - interval '1 hour'",
            &[&id]
        )
        .await,
        1,
        "opened_at is the database's time, not the test clock's 1970"
    );

    // Resolved at a time the database clock has not reached yet. Earlier
    // lifecycle times move back so the row stays consistent.
    client
        .execute(
            "UPDATE incidents SET state = 'resolved',
                first_detected_at = transaction_timestamp() - interval '10 minutes',
                opened_at = transaction_timestamp() - interval '10 minutes',
                last_detected_at = transaction_timestamp() - interval '10 minutes',
                last_updated_at = transaction_timestamp() - interval '10 minutes',
                resolved_at = transaction_timestamp() + interval '1 hour'
             WHERE incident_id = $1::text::uuid",
            &[&id],
        )
        .await
        .unwrap();

    // A new detection episode (T-18): only that may reopen.
    let recurrence = in_episode(
        event(&scope, 2, EventKind::Started, "p-opening", MetricKind::Bps),
        "det-recur",
    );
    let refused = service
        .ingest_detection_event(&mut client, &auth, &recurrence)
        .await
        .expect("a domain refusal is not a persistence failure");
    assert!(
        matches!(refused, Err(IncidentError::ClockSkew { .. })),
        "got {refused:?}"
    );
    const RESOLVED_UNTOUCHED: &str = "SELECT count(*) FROM incidents \
         WHERE incident_id = $1::text::uuid AND state = 'resolved' AND reopen_count = 0";
    for (what, sql, params, expected) in [
        (
            "no duplicate incident",
            "SELECT count(*) FROM incidents",
            &[][..],
            1,
        ),
        (
            "the incident did not reopen",
            RESOLVED_UNTOUCHED,
            &[&id as &(dyn ToSql + Sync)][..],
            1,
        ),
        (
            "the refused event was not linked",
            "SELECT count(*) FROM incident_detection_events",
            &[][..],
            1,
        ),
    ] {
        assert_eq!(scalar(&client, sql, params).await, expected, "{what}");
    }

    // The reference is now a minute in the database's past.
    client
        .execute(
            "UPDATE incidents SET resolved_at = transaction_timestamp() - interval '1 minute'
             WHERE incident_id = $1::text::uuid",
            &[&id],
        )
        .await
        .unwrap();

    // On the injected 1970 clock that same comparison would be skew.
    let on_injected_time = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(100)),
        Arc::new(TestClock::new()),
    )
    .with_injected_decision_time();
    let injected = on_injected_time
        .ingest_detection_event(&mut client, &auth, &recurrence)
        .await
        .unwrap();
    assert!(
        matches!(injected, Err(IncidentError::ClockSkew { .. })),
        "got {injected:?}"
    );

    // T-18: a late event of the resolved episode links and does not reopen.
    let late = service
        .ingest_detection_event(
            &mut client,
            &auth,
            &event(&scope, 9, EventKind::Updated, "p-opening", MetricKind::Bps),
        )
        .await
        .unwrap()
        .expect("a late event is accepted");
    assert_eq!(late.outcome_kind, IngestOutcomeKind::LinkedLate);
    assert_eq!(late.incident_id, Some(incident_id));
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incidents WHERE state = 'resolved' AND reopen_count = 0",
            &[],
        )
        .await,
        1,
        "still resolved"
    );
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_detection_events WHERE link_type = 'late'",
            &[],
        )
        .await,
        1,
        "linked as late evidence"
    );

    // On database time, it reopens.
    let reopened = service
        .ingest_detection_event(&mut client, &auth, &recurrence)
        .await
        .unwrap()
        .expect("the recurrence reopens the incident");
    assert_eq!(reopened.outcome_kind, IngestOutcomeKind::Reopened);
    assert_eq!(reopened.incident_id, Some(incident_id));
    assert_eq!(
        scalar(&client, "SELECT count(*) FROM incidents", &[]).await,
        1
    );
}
