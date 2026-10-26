//! Milestone 5C: the incident timers against PostgreSQL time.
//! - A silent detector moves an open incident to `Recovering` only after
//!   `silent_after`.
//! - `Recovering` becomes `Resolved` after `recovery_confirmation`.
//! - `Resolved` becomes `Closed` after the closure delay (FU-40), and a
//!   critical incident is never closed automatically (BQ-8).
//! - The domain re-checks each timer: asked directly, an incident that is
//!   not yet silent stays open.
//!
//! Time passes by moving an incident's own timestamps back together, so
//! their order, which reconstitution checks, is kept.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;

use support::{event, host_scope, hostgroup_scope, network_scope_with_host_bits, Scope};
use tidegard_detector::{EventKind, MetricKind, Severity, TestClock};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::{IncidentId, TestIncidentGenerator};
use tidegard_incident_postgres::maintenance::{
    run_maintenance, timeline_pressure, MaintenancePolicy, MaintenanceReport,
};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

const AGE: &str = "\
UPDATE incidents SET
    first_detected_at = first_detected_at - $1::text::interval,
    opened_at = opened_at - $1::text::interval,
    last_detected_at = last_detected_at - $1::text::interval,
    last_updated_at = last_updated_at - $1::text::interval,
    acknowledged_at = acknowledged_at - $1::text::interval,
    recovering_since = recovering_since - $1::text::interval,
    resolved_at = resolved_at - $1::text::interval,
    closed_at = closed_at - $1::text::interval,
    reopened_at = reopened_at - $1::text::interval,
    suppressed_until = suppressed_until - $1::text::interval
WHERE incident_id = $2::text::uuid";

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

async fn age(client: &Client, id: IncidentId, by: &str) {
    let updated = client
        .execute(AGE, &[&by, &id.to_string()])
        .await
        .expect("age the incident");
    assert_eq!(updated, 1);
}

async fn state(client: &Client, id: IncidentId) -> String {
    client
        .query_one(
            "SELECT state FROM incidents WHERE incident_id = $1::text::uuid",
            &[&id.to_string()],
        )
        .await
        .expect("incident row")
        .get(0)
}

async fn open_incident(
    service: &IncidentPersistence,
    client: &mut Client,
    scope: &Scope,
    detection: &str,
    severity: Severity,
) -> IncidentId {
    let mut started = event(scope, 1, EventKind::Started, "p-timers", MetricKind::Bps);
    started.detection_id = detection.to_string();
    started.event_id = format!("{detection}-1");
    started.dedup_key = format!("{detection}:started:1");
    started.severity = severity;
    let auth = AuthorizationContext::correlator(TenantId::new(scope.tenant));
    service
        .ingest_detection_event(client, &auth, &started)
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .expect("a first detection opens an incident")
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

#[tokio::test]
async fn timers_advance_incidents_on_database_time_and_never_auto_close_critical() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping maintenance_timers: {TEST_DATABASE_URL_VAR} is not set. \
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
    let policy = MaintenancePolicy::documented_default();
    let major = open_incident(
        &service,
        &mut client,
        &host_scope(),
        "det-major",
        Severity::Major,
    )
    .await;
    let critical = open_incident(
        &service,
        &mut client,
        &hostgroup_scope(),
        "det-critical",
        Severity::Critical,
    )
    .await;
    let recent = open_incident(
        &service,
        &mut client,
        &network_scope_with_host_bits(),
        "det-recent",
        Severity::Minor,
    )
    .await;

    // --- The largest active timeline is the pressure gauge's value ---
    const LARGEST_ACTIVE: &str = "SELECT max(c) FROM (SELECT count(*) AS c FROM incident_timeline \
         t JOIN incidents i USING (incident_id) WHERE i.state NOT IN ('resolved', 'closed') \
         GROUP BY incident_id) s";
    let largest: i64 = client.query_one(LARGEST_ACTIVE, &[]).await.unwrap().get(0);
    assert!(largest > 0);
    assert_eq!(
        timeline_pressure(&platform, &client).await.unwrap(),
        largest
    );

    // --- Nothing is due yet ---
    assert_eq!(
        run_maintenance(&platform, &service, &mut client, &policy)
            .await
            .unwrap(),
        MaintenanceReport::default()
    );
    let auth =
        AuthorizationContext::correlator(TenantId::new(network_scope_with_host_bits().tenant));
    assert!(
        !service
            .enter_recovering_if_silent(&mut client, &auth, recent, policy.silent_after)
            .await
            .unwrap()
            .unwrap(),
        "the domain re-checks silence itself"
    );

    // --- Silent past the threshold: Recovering ---
    for id in [major, critical] {
        age(&client, id, "6 minutes").await;
    }
    let pass = run_maintenance(&platform, &service, &mut client, &policy)
        .await
        .unwrap();
    assert_eq!(pass.entered_recovering, 2, "{pass:?}");
    assert_eq!(pass.failed, 0, "{pass:?}");
    assert_eq!(state(&client, major).await, "recovering");
    assert_eq!(state(&client, recent).await, "open");

    // --- Recovering held for the confirmation period: Resolved ---
    for id in [major, critical] {
        age(&client, id, "6 minutes").await;
    }
    let pass = run_maintenance(&platform, &service, &mut client, &policy)
        .await
        .unwrap();
    assert_eq!(pass.resolved, 2, "{pass:?}");
    assert_eq!(pass.closed, 0, "{pass:?}");
    assert_eq!(state(&client, major).await, "resolved");

    // --- Short of the closure delay: still Resolved ---
    for id in [major, critical] {
        age(&client, id, "29 minutes").await;
    }
    let pass = run_maintenance(&platform, &service, &mut client, &policy)
        .await
        .unwrap();
    assert_eq!(pass, MaintenanceReport::default());

    // --- Past the delay: the major one closes, the critical one never ---
    for id in [major, critical] {
        age(&client, id, "2 minutes").await;
    }
    let pass = run_maintenance(&platform, &service, &mut client, &policy)
        .await
        .unwrap();
    assert_eq!(pass.closed, 1, "{pass:?}");
    assert_eq!(pass.failed, 0, "{pass:?}");
    assert_eq!(state(&client, major).await, "closed");
    assert_eq!(state(&client, critical).await, "resolved");
    assert_eq!(state(&client, recent).await, "open");

    // Resolved and closed incidents no longer count.
    let recent_entries: i64 = client
        .query_one(
            "SELECT count(*) FROM incident_timeline WHERE incident_id = $1::text::uuid",
            &[&recent.to_canonical_string()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        timeline_pressure(&platform, &client).await.unwrap(),
        recent_entries
    );
}
