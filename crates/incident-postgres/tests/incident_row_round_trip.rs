//! Milestone 5B-3(b): one incident through real PostgreSQL and back.
//!
//! Covers insert then load for every scope kind, an update under a row
//! lock inside a transaction, the version guard refusing a stale update
//! without touching the row, and tenant scoping on load.
//!
//! Like `migration_smoke_test.rs`, this only ever connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). Everything runs in one test function because the test resets
//! the `public` schema, which parallel tests in the same binary would race.

mod support;

use support::{all_scopes, host_scope, operator, run, worked_incident};
use tidegard_incident::command::Command;
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::sql::{insert_incident, load_incident, update_incident, Locking};

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

#[tokio::test]
async fn incidents_round_trip_through_postgres_under_the_version_guard() {
    let Some(connection_string) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping incident_row_round_trip: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };

    let (mut client, connection) =
        tokio_postgres::connect(&connection_string, tokio_postgres::NoTls)
            .await
            .expect("must be able to connect to the configured ephemeral test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection error: {error}");
        }
    });
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("migrations must apply");

    // --- Insert, then load, for every scope kind ---
    for (scope, seed) in all_scopes() {
        let (uow, id) = worked_incident(&scope, seed);
        let incident = uow.get(&id).unwrap();
        insert_incident(&client, incident).await.expect("insert");
        let loaded = load_incident(&client, &TenantId::new(scope.tenant), &id, Locking::NoLock)
            .await
            .expect("load")
            .expect("the inserted incident is found");
        assert_eq!(
            &loaded, incident,
            "{} scope must round-trip exactly",
            scope.scope_id
        );
    }

    // The network target is stored normalised, while the key keeps the
    // exact prefix the policy named.
    let (network_uow, network_id) =
        worked_incident(&support::network_scope_with_host_bits(), 1_000);
    let stored = client
        .query_one(
            "SELECT target_type, target_network::text FROM incidents WHERE incident_id = $1::text::uuid",
            &[&network_uow.get(&network_id).unwrap().to_snapshot().incident_id.to_canonical_string()],
        )
        .await
        .unwrap();
    assert_eq!(stored.get::<_, String>(0), "network");
    assert_eq!(stored.get::<_, String>(1), "203.0.113.0/24");

    // --- Update under a row lock, inside a transaction ---
    let scope = host_scope();
    let tenant = TenantId::new(scope.tenant);
    let (mut uow, id) = worked_incident(&scope, 1);
    let before = uow.get(&id).unwrap().clone();
    let loaded_version = before.version;

    let operator = operator(scope.tenant);
    run(&mut uow, &operator, id, |_| Command::AddNote {
        body: "second look".to_string(),
        visibility: tidegard_incident::incident::NoteVisibility::Internal,
    });
    run(&mut uow, &operator, id, |_| Command::RemoveTag {
        key: "site".to_string(),
    });
    run(&mut uow, &operator, id, |v| Command::UnsuppressIncident {
        expected_version: v,
    });
    let after = uow.get(&id).unwrap().clone();
    assert_ne!(after.version, loaded_version);

    let transaction = client.transaction().await.unwrap();
    let locked = load_incident(&transaction, &tenant, &id, Locking::ForUpdate)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(locked, before);
    update_incident(&transaction, &after, loaded_version)
        .await
        .expect("an update at the loaded version succeeds");
    transaction.commit().await.unwrap();

    let reloaded = load_incident(&client, &tenant, &id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded, after);
    assert_eq!(reloaded.notes.len(), 2);
    assert!(reloaded.suppression.is_none());

    // --- A stale update is refused and changes nothing ---
    let stale = update_incident(&client, &before, loaded_version).await;
    assert!(
        matches!(stale, Err(PersistError::VersionConflict { loaded_version: v, .. }) if v == loaded_version),
        "expected a version conflict, got {stale:?}"
    );
    let unchanged = load_incident(&client, &tenant, &id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged, after);

    // --- Another tenant cannot load it ---
    assert!(load_incident(
        &client,
        &TenantId::new("other-tenant"),
        &id,
        Locking::NoLock
    )
    .await
    .unwrap()
    .is_none());
}
