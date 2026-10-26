//! Two of the persistence plan's required integration tests (5B-5): a
//! statement timeout, and service-restart recovery.
//!
//! - **Statement timeout.** A call whose statement times out on a lock another
//!   session holds fails with `57014`. The failure is not retried, commits
//!   nothing, and the same command succeeds once the lock is gone.
//! - **Service restart.** incident-persistence.md's failure table: "Uncommitted
//!   work is lost by construction; the outbox is re-read from `pending`". A new
//!   service on a new connection keeps no state from the old one:
//!   - messages left pending are claimable
//!   - a replayed event is still a duplicate
//!   - a later event links to the open incident
//!   - numbering continues from the database's allocator
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use support::{event, host_scope, operator, Scope};
use tidegard_detector::{EventKind, MetricKind, ScopeId, ScopeType, TestClock};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::command::Command;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::unit_of_work::IngestOutcomeKind;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::outbox::{OutboxConsumer, OutboxPolicy};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_incident_postgres::sql::{load_incident, Locking};
use tokio_postgres::error::SqlState;
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
async fn a_statement_timeout_commits_nothing_and_a_restarted_service_recovers_from_the_database() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping timeouts_and_restart: {TEST_DATABASE_URL_VAR} is not set. \
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
    let correlator = AuthorizationContext::correlator(tenant.clone());
    let opening = event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps);
    let incident_id = service
        .ingest_detection_event(&mut client, &correlator, &opening)
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .unwrap();
    let id = incident_id.to_canonical_string();
    let noc = operator(scope.tenant);
    const TIMELINE: &str =
        "SELECT count(*) FROM incident_timeline WHERE incident_id = $1::text::uuid";
    let timeline_before = scalar(&client, TIMELINE, &[&id]).await;

    // --- A statement timeout on a held lock fails the call, unretried, committing nothing ---
    let mut holder = connect(&url).await;
    let held = holder.transaction().await.unwrap();
    held.execute(
        "SELECT 1 FROM incidents WHERE incident_id = $1::text::uuid FOR UPDATE",
        &[&id],
    )
    .await
    .unwrap();
    client
        .batch_execute("SET statement_timeout = '300ms'")
        .await
        .unwrap();
    let acknowledge = Command::AcknowledgeIncident {
        expected_version: 1,
    };
    let error = service
        .handle_command(&mut client, &noc, incident_id, acknowledge.clone(), None)
        .await
        .expect_err("a statement timeout is a persistence failure, not a domain outcome");
    let code = match &error {
        PersistError::Database(database) => database.code().cloned(),
        _ => None,
    };
    assert_eq!(code, Some(SqlState::QUERY_CANCELED), "got {error:?}");
    assert!(
        !error.is_retryable(),
        "ADR 0026 retries only the listed transient failures"
    );
    held.rollback().await.unwrap();
    client
        .batch_execute("SET statement_timeout = 0")
        .await
        .unwrap();

    let unchanged = load_incident(&client, &tenant, &incident_id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.version, 1, "the timed-out call committed nothing");
    assert_eq!(scalar(&client, TIMELINE, &[&id]).await, timeline_before);
    assert_eq!(
        service
            .handle_command(&mut client, &noc, incident_id, acknowledge, None)
            .await
            .unwrap(),
        Ok(2),
        "the same command succeeds once the lock is released"
    );

    // --- A restart: nothing survives in the process, everything in the database ---
    const PENDING: &str = "SELECT count(*) FROM incident_outbox WHERE status = 'pending'";
    let pending_before = scalar(&client, PENDING, &[]).await;
    // Opening writes `IncidentOpened`; acknowledging writes no outbox event.
    assert!(
        pending_before >= 1,
        "the opening's message is still pending"
    );
    drop(service);
    drop(client);

    let mut client = connect(&url).await;
    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(9_000)),
        Arc::new(TestClock::new()),
    );

    let platform = PlatformAuthority::from_context(&AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Operator {
            id: "platform-admin".to_string(),
        },
        FixedBundleResolver.permissions_for("platform_admin"),
    ))
    .expect("a platform admin is authorized");
    let claimed = OutboxConsumer::new(&platform, "after-restart", OutboxPolicy::starting_default())
        .claim(&client)
        .await
        .unwrap();
    assert_eq!(
        claimed.len() as i64,
        pending_before,
        "every message left pending before the restart is claimable after it"
    );

    let replayed = service
        .ingest_detection_event(&mut client, &correlator, &opening)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        replayed.outcome_kind,
        IngestOutcomeKind::Duplicate,
        "de-duplication is durable"
    );

    let later = event(&scope, 2, EventKind::Updated, "p-opening", MetricKind::Bps);
    let linked = service
        .ingest_detection_event(&mut client, &correlator, &later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(linked.outcome_kind, IngestOutcomeKind::Updated);
    assert_eq!(
        linked.incident_id,
        Some(incident_id),
        "the open incident is found in the database"
    );

    let neighbour = Scope {
        tenant: scope.tenant,
        scope_type: ScopeType::Host,
        scope_id: ScopeId::Host {
            addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 91)),
        },
    };
    let created = service
        .ingest_detection_event(
            &mut client,
            &correlator,
            &event(
                &neighbour,
                10,
                EventKind::Started,
                "p-opening",
                MetricKind::Bps,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(created.outcome_kind, IngestOutcomeKind::Created);
    let numbered = load_incident(
        &client,
        &tenant,
        &created.incident_id.unwrap(),
        Locking::NoLock,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        numbered.incident_number.as_str(),
        "WNM-2026-000002",
        "numbering continues from the database's allocator"
    );
}
