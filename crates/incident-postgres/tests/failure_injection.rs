//! Milestone 5B-5: atomicity proven by injected failure, not by observing
//! success (ADR 0034), and the retry loop exercised end to end (ADR 0026).
//!
//! Uses the `fault-injection` feature, which this crate's dev-dependency on
//! itself turns on for tests. Like the other PostgreSQL tests, this only
//! connects to the opt-in, ephemeral database named by
//! `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`, skips with a message when it
//! is unset, and fails CI if it skips there (FU-46). One test function,
//! because it resets the `public` schema and the armed fault is
//! process-wide.

mod support;

use std::sync::Arc;

use support::{event, host_scope, operator, Scope};
use tidegard_detector::{DetectionEvent, EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::command::Command;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::idempotency::IdempotencyKey;
use tidegard_incident::unit_of_work::IngestOutcomeKind;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::fault::{self, FlushPoint};
use tidegard_incident_postgres::retry::RetryPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_incident_postgres::sql::{load_incident, Locking};
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

/// Every table an ingest writes for its tenant.
const TENANT_TABLES: [&str; 6] = [
    "incidents",
    "incident_detection_events",
    "incident_timeline",
    "incident_audit",
    "incident_outbox",
    "incident_number_allocators",
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

fn started_for(tenant: &'static str) -> (Scope, DetectionEvent) {
    let base = host_scope();
    let scope = Scope {
        tenant,
        scope_type: base.scope_type,
        scope_id: base.scope_id,
    };
    let started = event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps);
    (scope, started)
}

#[tokio::test]
async fn an_injected_failure_at_any_flush_point_commits_nothing_and_a_transient_one_is_retried() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping failure_injection: {TEST_DATABASE_URL_VAR} is not set. \
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
    fault::disarm();

    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    );

    // --- A failure at every flush point of a creating ingest commits nothing ---
    for point in FlushPoint::ALL {
        let tenant: &'static str =
            Box::leak(format!("fault-{point:?}").to_lowercase().into_boxed_str());
        let (_, started) = started_for(tenant);
        let auth = AuthorizationContext::correlator(TenantId::new(tenant));

        fault::arm(point, false);
        let failed = service
            .ingest_detection_event(&mut client, &auth, &started)
            .await;
        assert!(
            matches!(failed, Err(PersistError::InjectedFault { point: p, .. }) if p == point),
            "{point:?}: got {:?}",
            failed.as_ref().err()
        );
        assert!(!fault::is_armed(), "{point:?} must have been reached");
        for table in TENANT_TABLES {
            let rows = scalar(
                &client,
                &format!("SELECT count(*) FROM {table} WHERE tenant_id = $1"),
                &[&tenant],
            )
            .await;
            assert_eq!(rows, 0, "a failure at {point:?} left rows in {table}");
        }

        let created = service
            .ingest_detection_event(&mut client, &auth, &started)
            .await
            .expect("the clean rerun commits")
            .expect("the domain accepts the event");
        assert_eq!(created.outcome_kind, IngestOutcomeKind::Created);
        let incident = load_incident(
            &client,
            &TenantId::new(tenant),
            &created.incident_id.unwrap(),
            Locking::NoLock,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            incident.incident_number.as_str(),
            "WNM-2026-000001",
            "a failure at {point:?} must not consume an incident number"
        );
    }

    // --- A failure while a command updates an incident commits nothing ---
    let (_, started) = started_for("commanded");
    let tenant = TenantId::new("commanded");
    let id = service
        .ingest_detection_event(
            &mut client,
            &AuthorizationContext::correlator(tenant.clone()),
            &started,
        )
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .unwrap();
    let noc = operator("commanded");
    let key = IdempotencyKey::new("fault-request-key-01").unwrap();
    const TIMELINE: &str = "SELECT count(*) FROM incident_timeline WHERE tenant_id = 'commanded'";
    let timeline_before = scalar(&client, TIMELINE, &[]).await;
    fault::arm(FlushPoint::Idempotency, false);
    let failed = service
        .handle_command(
            &mut client,
            &noc,
            id,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            Some(key.clone()),
        )
        .await;
    assert!(
        matches!(
            failed,
            Err(PersistError::InjectedFault {
                point: FlushPoint::Idempotency,
                ..
            })
        ),
        "got {:?}",
        failed.as_ref().err()
    );
    let unchanged = load_incident(&client, &tenant, &id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.version, 1, "the incident update was rolled back");
    assert_eq!(scalar(&client, TIMELINE, &[]).await, timeline_before);
    assert_eq!(
        scalar(&client, "SELECT count(*) FROM incident_idempotency", &[]).await,
        0
    );
    let acknowledged = service
        .handle_command(
            &mut client,
            &noc,
            id,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            Some(key),
        )
        .await
        .unwrap();
    assert_eq!(
        acknowledged,
        Ok(2),
        "the key was never recorded, so it runs"
    );

    // --- A transient failure is rerun from a fresh load and commits once ---
    let (_, started) = started_for("retried");
    fault::arm(FlushPoint::Outbox, true);
    let retried = service
        .ingest_detection_event(
            &mut client,
            &AuthorizationContext::correlator(TenantId::new("retried")),
            &started,
        )
        .await
        .expect("the rerun commits")
        .expect("the domain accepts the event");
    assert_eq!(retried.outcome_kind, IngestOutcomeKind::Created);
    assert!(!fault::is_armed(), "the first attempt reached the fault");
    for (sql, expected) in [
        (
            "SELECT count(*) FROM incidents WHERE tenant_id = 'retried'",
            1,
        ),
        (
            "SELECT count(*) FROM incident_outbox WHERE tenant_id = 'retried'",
            1,
        ),
        (
            "SELECT next_value FROM incident_number_allocators WHERE tenant_id = 'retried'",
            2,
        ),
    ] {
        assert_eq!(scalar(&client, sql, &[]).await, expected, "{sql}");
    }

    // --- With retries off, the same transient failure is returned ---
    let unretried = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(9_000)),
        Arc::new(TestClock::new()),
    )
    .with_retry_policy(RetryPolicy::no_retries());
    let (_, started) = started_for("unretried");
    fault::arm(FlushPoint::Outbox, true);
    let refused = unretried
        .ingest_detection_event(
            &mut client,
            &AuthorizationContext::correlator(TenantId::new("unretried")),
            &started,
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(PersistError::InjectedFault {
                transient: true,
                ..
            })
        ),
        "got {:?}",
        refused.as_ref().err()
    );
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incidents WHERE tenant_id = 'unretried'",
            &[]
        )
        .await,
        0
    );
    fault::disarm();
}
