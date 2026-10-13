//! FU-34 and the persistence plan's required test: a 65th distinct policy on
//! one incident is recorded, never silently omitted. The domain keeps at
//! most `POLICY_REFS_MAX` references and counts the rest in
//! `policy_refs_omitted` (V13). This test checks that the count is written,
//! survives a reload, and that the omitted policy stays on its
//! detection-event link.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;

use support::{event, host_scope};
use tidegard_detector::{EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::limits::POLICY_REFS_MAX;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_incident_postgres::sql::{load_incident, Locking};
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
async fn a_policy_past_the_cap_is_counted_and_survives_a_reload() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping policy_reference_overflow: {TEST_DATABASE_URL_VAR} is not set. \
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
    let cap = POLICY_REFS_MAX as u64;

    let ingest = |sequence: u64, policy: String| {
        let kind = if sequence == 1 {
            EventKind::Started
        } else {
            EventKind::Updated
        };
        event(&scope, sequence, kind, &policy, MetricKind::Bps)
    };

    // Policies p-1 .. p-64 fill the cap; p-65 is the first one past it.
    let mut incident_id = None;
    for n in 1..=cap + 1 {
        let outcome = service
            .ingest_detection_event(&mut client, &auth, &ingest(n, format!("p-{n}")))
            .await
            .expect("the ingest commits")
            .expect("the domain accepts the event");
        incident_id = incident_id.or(outcome.incident_id);
    }
    let incident_id = incident_id.expect("the first event opened an incident");

    let reloaded = load_incident(&client, &tenant, &incident_id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.policy_refs.len(), POLICY_REFS_MAX);
    assert_eq!(
        reloaded.policy_refs_omitted, 1,
        "the 65th distinct policy is counted, not silently dropped"
    );
    assert!(reloaded.policy_refs.iter().all(|p| p.policy_id != "p-65"));

    let id = incident_id.to_canonical_string();
    const REFERENCES: &str =
        "SELECT count(*) FROM incident_policy_references WHERE incident_id = $1::text::uuid";
    const OMITTED: &str =
        "SELECT policy_refs_omitted FROM incidents WHERE incident_id = $1::text::uuid";
    assert_eq!(
        scalar(&client, REFERENCES, &[&id]).await,
        POLICY_REFS_MAX as i64
    );
    assert_eq!(scalar(&client, OMITTED, &[&id]).await, 1);
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_detection_events \
             WHERE incident_id = $1::text::uuid AND policy_id = 'p-65'",
            &[&id]
        )
        .await,
        1,
        "the omitted policy stays on its detection-event link"
    );

    // A recorded policy still updates in place; another unseen one counts again.
    service
        .ingest_detection_event(&mut client, &auth, &ingest(cap + 2, "p-3".to_string()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(scalar(&client, OMITTED, &[&id]).await, 1);
    service
        .ingest_detection_event(&mut client, &auth, &ingest(cap + 3, "p-66".to_string()))
        .await
        .unwrap()
        .unwrap();
    let reloaded = load_incident(&client, &tenant, &incident_id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.policy_refs_omitted, 2);
    assert_eq!(
        reloaded
            .policy_refs
            .iter()
            .find(|p| p.policy_id == "p-3")
            .expect("p-3 is recorded")
            .last_seen_sequence,
        cap + 2
    );
    assert_eq!(
        scalar(&client, REFERENCES, &[&id]).await,
        POLICY_REFS_MAX as i64
    );
}
