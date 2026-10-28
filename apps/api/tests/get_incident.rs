//! Milestone 5D-3: `GET /api/v1/incidents/{id}` against PostgreSQL.
//! - The owner's token reads the incident in the planned representation.
//! - **Another tenant's token gets exactly the 404 a missing id gets**:
//!   same status, same code, and no field that tells them apart (ADR 0038).
//! - A malformed id is 400 before any query; no token is 401.
//! - The read service refuses a context without `incident.read`.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

#[path = "../../../crates/incident-postgres/tests/support/mod.rs"]
mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use support::{event, host_scope, network_scope_with_host_bits};
use tidegard_api::auth::Role;
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_api::{router, AppState};
use tidegard_detector::{EventKind, MetricKind};
use tidegard_incident::authorization::{Actor, AuthorizationContext, Permission};
use tidegard_incident::clock::SystemClock;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::error::IncidentError;
use tidegard_incident::id::IncidentId;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::queries;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::Client;
use tower::ServiceExt;

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

async fn token(client: &Client, tenant: &str, role: Role) -> String {
    // A token names a registered tenant (ADR 0060).
    tidegard_incident_postgres::tenants::ensure(client, tenant)
        .await
        .unwrap();
    token_admin::create(
        client,
        &NewToken {
            tenant: tenant.to_string(),
            actor_type: ActorType::Operator,
            actor_id: format!("{tenant}-{}", role.as_str()),
            role,
            lifetime_days: 1,
            description: String::new(),
        },
    )
    .await
    .unwrap()
    .secret
}

async fn get(app: &axum::Router, path: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder().uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The members a client could use to tell two errors apart.
fn shape(body: &Value) -> (Value, Value, Value, Value) {
    (
        body["status"].clone(),
        body["error"].clone(),
        body["title"].clone(),
        body.get("detail").cloned().unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn an_incident_is_readable_by_its_tenant_and_invisible_to_others() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping get_incident: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };
    let mut admin = connect(&url).await;
    admin
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut admin)
        .await
        .expect("migrations must apply");

    // --- One incident in acme, one in globex ---
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    let acme_event = event(
        &host_scope(),
        1,
        EventKind::Started,
        "p-api",
        MetricKind::Bps,
    );
    let globex_event = event(
        &network_scope_with_host_bits(),
        1,
        EventKind::Started,
        "p-api",
        MetricKind::Bps,
    );
    let acme_id = service
        .ingest_detection_event(
            &mut admin,
            &AuthorizationContext::correlator(TenantId::new("acme")),
            &acme_event,
        )
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .expect("the event opened an incident");
    service
        .ingest_detection_event(
            &mut admin,
            &AuthorizationContext::correlator(TenantId::new("globex")),
            &globex_event,
        )
        .await
        .unwrap()
        .unwrap();

    let (pool, _) = tidegard_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .expect("a loopback test database");
    let app = router(AppState::new(pool));
    let acme_viewer = token(&admin, "acme", Role::Viewer).await;
    let globex_operator = token(&admin, "globex", Role::Operator).await;
    let path = format!("/api/v1/incidents/{}", acme_id.to_canonical_string());

    // --- The owner reads it, in the planned representation ---
    let (status, body) = get(&app, &path, Some(&acme_viewer)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["incident_id"], acme_id.to_canonical_string());
    assert_eq!(body["tenant_id"], "acme");
    assert_eq!(body["state"], "open");
    assert_eq!(body["severity"], "major");
    assert_eq!(body["target_type"], "host");
    assert_eq!(body["target_id"], "203.0.113.90");
    assert_eq!(body["direction"], "incoming");
    assert_eq!(body["address_family"], 4);
    assert_eq!(body["mitigation_status"], "none");
    assert_eq!(body["notification_status"], "none");
    assert_eq!(body["created_by"], "system:correlator");
    assert_eq!(body["version"], 1);
    assert!(
        body["opened_at"].as_str().unwrap().ends_with('Z'),
        "RFC 3339 UTC: {}",
        body["opened_at"]
    );

    // --- Another tenant: the same 404 as an id that does not exist ---
    let (cross_status, cross_body) = get(&app, &path, Some(&globex_operator)).await;
    let missing = format!(
        "/api/v1/incidents/{}",
        IncidentId::parse("0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d")
            .unwrap()
            .to_canonical_string()
    );
    let (missing_status, missing_body) = get(&app, &missing, Some(&globex_operator)).await;
    assert_eq!(cross_status, StatusCode::NOT_FOUND);
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(cross_body["error"], "incident.not_found");
    assert_eq!(
        shape(&cross_body),
        shape(&missing_body),
        "a client cannot tell another tenant's incident from no incident"
    );
    assert!(!cross_body.to_string().contains("acme"));

    // --- Malformed id: 400; no token: 401 ---
    let (status, body) = get(&app, "/api/v1/incidents/not-a-uuid", Some(&acme_viewer)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "api.invalid_request");
    let (status, body) = get(&app, &path, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "api.unauthenticated");

    // --- The read service itself refuses a context without incident.read ---
    let no_read = AuthorizationContext::new(
        TenantId::new("acme"),
        Actor::Operator {
            id: "auditor".to_string(),
        },
        vec![Permission::IncidentList],
    );
    assert_eq!(
        queries::get_incident(&mut admin, &no_read, &acme_id)
            .await
            .unwrap()
            .unwrap_err(),
        IncidentError::Unauthorized
    );
}
