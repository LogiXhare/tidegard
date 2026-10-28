//! Milestone 5D-9: an operator opens an incident (ADR 0039), against
//! PostgreSQL.
//! - `senior_operator` may, `operator` may not.
//! - **The same `Idempotency-Key` and body answer with the same incident**;
//!   the same key with another body is `409 incident.idempotency_key_reuse`.
//! - **A second incident for an active target is refused**, naming the
//!   active one, and a later detection for the target **attaches** to the
//!   manual incident instead of opening another.
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
use serde_json::{json, Value};
use support::{event, host_scope};
use tidegard_api::auth::Role;
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_api::{router, AppState};
use tidegard_detector::{EventKind, MetricKind};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::clock::SystemClock;
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::pool::PoolPolicy;
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

/// `POST /api/v1/incidents`: the status, the body, and `Location`.
async fn create(
    app: &axum::Router,
    token: &str,
    key: Option<&str>,
    body: Value,
) -> (StatusCode, Value, Option<String>) {
    let mut request = Request::post("/api/v1/incidents")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .map(|value| value.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        location,
    )
}

#[tokio::test]
async fn operators_open_incidents_that_detections_then_attach_to() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping manual_create: {TEST_DATABASE_URL_VAR} is not set. \
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
    let operator = token(&admin, "acme", Role::Operator).await;
    let senior = token(&admin, "acme", Role::SeniorOperator).await;

    // The same target the support event names, so a detection correlates.
    let body = json!({
        "title": "Transit provider reports spoofed sources",
        "description": "Seen upstream, below our thresholds",
        "severity": "major",
        "target_scope": "host",
        "target": "203.0.113.90",
        "direction": "incoming",
    });

    // --- Refused before anything is written ---
    let (status, problem, _) = create(&app, &senior, None, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no key: {problem}");
    let (status, problem, _) = create(
        &app,
        &operator,
        Some("manual-create-operator"),
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    assert_eq!(problem["error"], "incident.forbidden");
    let (status, problem, _) = create(
        &app,
        &senior,
        Some("manual-create-hostgroup"),
        json!({"title": "x", "severity": "minor", "target_scope": "hostgroup_total",
               "target": "edge", "direction": "incoming"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "hostgroup needs a family: {problem}"
    );
    let (status, problem, _) = create(
        &app,
        &senior,
        Some("manual-create-blank-title"),
        json!({"title": "  ", "severity": "minor", "target_scope": "host",
               "target": "203.0.113.91", "direction": "incoming"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");

    // --- Opened, then replayed, then the key reused ---
    let (status, incident, location) =
        create(&app, &senior, Some("manual-create-first"), body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{incident}");
    let id = incident["incident_id"].as_str().unwrap().to_string();
    assert_eq!(
        location.as_deref(),
        Some(format!("/api/v1/incidents/{id}").as_str())
    );
    assert_eq!(incident["state"], "open");
    assert_eq!(incident["version"], 1);
    assert_eq!(incident["priority"], "P2");
    assert_eq!(incident["severity_source"], "operator");
    assert_eq!(incident["created_by"], "acme-senior_operator");
    assert_eq!(incident["category"], "unclassified");

    let (status, replay, _) =
        create(&app, &senior, Some("manual-create-first"), body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert_eq!(
        replay["incident_id"],
        id.as_str(),
        "a replay opens nothing new"
    );
    let mut changed = body.clone();
    changed["title"] = json!("A different request");
    let (status, problem, _) = create(&app, &senior, Some("manual-create-first"), changed).await;
    assert_eq!(status, StatusCode::CONFLICT, "{problem}");
    assert_eq!(problem["error"], "incident.idempotency_key_reuse");

    // --- A second one for the same active target names the first ---
    let (status, problem, _) = create(&app, &senior, Some("manual-create-second"), body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{problem}");
    assert_eq!(problem["error"], "incident.duplicate_active");
    assert_eq!(problem["incident_id"], id.as_str());

    let opened: i64 = admin
        .query_one("SELECT count(*) FROM incidents", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(opened, 1, "nothing but the one incident was written");

    // --- A detection for the target attaches to the manual incident ---
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    let linked = service
        .ingest_detection_event(
            &mut admin,
            &AuthorizationContext::correlator(TenantId::new("acme")),
            &event(
                &host_scope(),
                1,
                EventKind::Started,
                "p-manual",
                MetricKind::Bps,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        linked.incident_id.map(|i| i.to_canonical_string()),
        Some(id),
        "the detection attached instead of opening a second incident"
    );
}
