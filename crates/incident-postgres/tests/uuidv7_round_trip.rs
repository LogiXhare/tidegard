//! The persistence plan's UUIDv7 round trip (5B-5). An id from the
//! production generator is stored in PostgreSQL's native `uuid` column and
//! comes back unchanged: the same bytes, the same text, still version 7. The
//! server's own ordering of the column matches the order the ids were
//! generated in.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;

use support::{all_scopes, event};
use tidegard_detector::{EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_incident_postgres::sql::{load_incident, Locking};
use tokio_postgres::Client;
use uuid::Uuid;

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

#[tokio::test]
async fn uuidv7_incident_ids_round_trip_through_the_native_uuid_column() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping uuidv7_round_trip: {TEST_DATABASE_URL_VAR} is not set. \
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
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(TestClock::new()),
    );

    let mut issued = Vec::new();
    for (scope, _) in all_scopes() {
        let tenant = TenantId::new(scope.tenant);
        let id = service
            .ingest_detection_event(
                &mut client,
                &AuthorizationContext::correlator(tenant.clone()),
                &event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps),
            )
            .await
            .unwrap()
            .unwrap()
            .incident_id
            .unwrap();

        let stored: String = client
            .query_one(
                "SELECT incident_id::text FROM incidents WHERE tenant_id = $1",
                &[&scope.tenant],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(stored, id.to_canonical_string(), "the server's text form");
        let parsed = Uuid::parse_str(&stored).unwrap();
        assert_eq!(parsed.get_version_num(), 7, "still a version 7 UUID");
        assert_eq!(*parsed.as_bytes(), id.as_bytes(), "the same 16 bytes");

        let loaded = load_incident(&client, &tenant, &id, Locking::NoLock)
            .await
            .unwrap()
            .expect("the incident loads by its UUIDv7 id");
        assert_eq!(loaded.incident_id, id);
        issued.push(id.to_canonical_string());
    }

    let server_order: Vec<String> = client
        .query(
            "SELECT incident_id::text FROM incidents ORDER BY incident_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        server_order, issued,
        "the uuid column sorts UUIDv7 ids in generation order"
    );
}
