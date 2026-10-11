//! Milestones 5D-6 to 5D-8: state transitions, notes and tags over HTTP
//! against PostgreSQL.
//! - One incident walks the whole lifecycle through the API, every step
//!   under the role that holds its permission.
//! - **The same `Idempotency-Key` and body replays**; the same key with a
//!   different body is `409 incident.idempotency_key_reuse`.
//! - **A stale `expected_version` is `409 incident.version_conflict`**,
//!   with the current version and state.
//! - **Another tenant gets 404**, identical to a missing incident, and a
//!   role without the permission gets 403.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

#[path = "../../../crates/incident-postgres/tests/support/mod.rs"]
mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::{json, Value};
use support::{event, host_scope};
use tokio_postgres::Client;
use tower::ServiceExt;
use wetechinetmon_api::auth::Role;
use wetechinetmon_api::token_admin::{self, ActorType, NewToken};
use wetechinetmon_api::{router, AppState};
use wetechinetmon_detector::{EventKind, MetricKind};
use wetechinetmon_incident::authorization::AuthorizationContext;
use wetechinetmon_incident::clock::SystemClock;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::pool::PoolPolicy;
use wetechinetmon_incident_postgres::service::IncidentPersistence;

const TEST_DATABASE_URL_VAR: &str = "WETECHINETMON_INCIDENT_POSTGRES_TEST_URL";

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

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A JSON `POST` with an optional `Idempotency-Key`.
async fn post(
    app: &axum::Router,
    path: &str,
    token: &str,
    key: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    send(app, request.body(Body::from(body.to_string())).unwrap()).await
}

/// A fresh, valid idempotency key per step.
fn key(step: &str) -> String {
    format!("transitions-test-{step}")
}

fn shape(body: &Value) -> (Value, Value, Value) {
    (
        body["status"].clone(),
        body["error"].clone(),
        body["title"].clone(),
    )
}

#[tokio::test]
async fn transitions_are_idempotent_versioned_and_tenant_scoped() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping transitions: {TEST_DATABASE_URL_VAR} is not set. \
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
    wetechinetmon_incident_postgres::migrations::migrations::runner()
        .run_async(&mut admin)
        .await
        .expect("migrations must apply");

    // --- One open acme incident ---
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    let acme = AuthorizationContext::correlator(TenantId::new("acme"));
    let id = service
        .ingest_detection_event(
            &mut admin,
            &acme,
            &event(
                &host_scope(),
                1,
                EventKind::Started,
                "p-transitions",
                MetricKind::Bps,
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .unwrap()
        .to_canonical_string();

    let (pool, _) = wetechinetmon_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .expect("a loopback test database");
    let app = router(AppState::new(pool));
    let viewer = token(&admin, "acme", Role::Viewer).await;
    let operator = token(&admin, "acme", Role::Operator).await;
    let senior = token(&admin, "acme", Role::SeniorOperator).await;
    let lead = token(&admin, "acme", Role::NocLead).await;
    let outsider = token(&admin, "globex", Role::NocLead).await;
    let base = format!("/api/v1/incidents/{id}");

    let (status, incident) = send(
        &app,
        Request::get(&base)
            .header(header::AUTHORIZATION, format!("Bearer {viewer}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{incident}");
    assert_eq!(incident["state"], "open");
    let mut version = incident["version"].as_u64().unwrap();

    // --- Requests refused before the domain sees them ---
    let ack = format!("{base}/acknowledge");
    let (status, body) = post(
        &app,
        &ack,
        &operator,
        None,
        json!({"expected_version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "api.invalid_request");
    let (status, body) = post(
        &app,
        &ack,
        &operator,
        Some(&key("unknown")),
        json!({"expected_version": version, "note": "not a field yet"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "api.unknown_field");
    let (status, body) = send(
        &app,
        Request::post(&ack)
            .header(header::AUTHORIZATION, format!("Bearer {operator}"))
            .header(header::CONTENT_TYPE, "text/plain")
            .header("Idempotency-Key", key("media"))
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");

    // --- Permission and tenant ---
    let (status, body) = post(
        &app,
        &ack,
        &viewer,
        Some(&key("viewer")),
        json!({"expected_version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "incident.forbidden");
    let missing = "/api/v1/incidents/0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d/acknowledge";
    let (status, cross) = post(
        &app,
        &ack,
        &outsider,
        Some(&key("outsider")),
        json!({"expected_version": version}),
    )
    .await;
    let (_, absent) = post(
        &app,
        missing,
        &outsider,
        Some(&key("absent")),
        json!({"expected_version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{cross}");
    assert_eq!(cross["error"], "incident.not_found");
    assert_eq!(shape(&cross), shape(&absent));

    // --- Acknowledge, then replay it, then reuse its key ---
    let body = json!({"expected_version": version});
    let (status, acked) = post(&app, &ack, &operator, Some(&key("ack")), body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{acked}");
    assert_eq!(acked["state"], "acknowledged");
    assert_eq!(acked["version"].as_u64().unwrap(), version + 1);
    version += 1;
    let (status, replay) = post(&app, &ack, &operator, Some(&key("ack")), body).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(
        replay["version"].as_u64().unwrap(),
        version,
        "a replay changes nothing"
    );
    let (status, reuse) = post(
        &app,
        &ack,
        &operator,
        Some(&key("ack")),
        json!({"expected_version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{reuse}");
    assert_eq!(reuse["error"], "incident.idempotency_key_reuse");

    // --- A stale version names the current one ---
    let (status, stale) = post(
        &app,
        &format!("{base}/investigate"),
        &operator,
        Some(&key("stale")),
        json!({"expected_version": version - 1}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    assert_eq!(stale["error"], "incident.version_conflict");
    assert_eq!(stale["current_version"].as_u64().unwrap(), version);
    assert_eq!(stale["current_state"], "acknowledged");

    // --- Notes: no version, the key optional, replayed when given ---
    let notes = format!("{base}/notes");
    let (status, body) = post(&app, &notes, &viewer, None, json!({"body": "seen"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = post(
        &app,
        &notes,
        &operator,
        None,
        json!({"body": "upstream confirms spoofing"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["version"].as_u64().unwrap(), version + 1);
    version += 1;
    let keyed = json!({"body": "scrubbing requested", "visibility": "internal"});
    let (status, body) = post(&app, &notes, &operator, Some(&key("note")), keyed.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    version += 1;
    let (status, body) = post(&app, &notes, &operator, Some(&key("note")), keyed).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["version"].as_u64().unwrap(),
        version,
        "a replayed note is not added twice"
    );
    let (status, body) = post(
        &app,
        &notes,
        &operator,
        None,
        json!({"body": "x", "visibility": "customer_visible"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
    assert_eq!(body["error"], "incident.customer_visible_unsupported");
    let (status, body) = send(
        &app,
        Request::get(&notes)
            .header(header::AUTHORIZATION, format!("Bearer {viewer}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 2, "{body}");

    // --- Tags: PUT sets, DELETE removes, only with incident.update ---
    let tag = format!("{base}/tags/env");
    let put_tag = |token: &str, value: &str| {
        Request::put(&tag)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "value": value }).to_string()))
            .unwrap()
    };
    let (status, body) = send(&app, put_tag(&senior, "prod")).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "senior_operator lacks incident.update: {body}"
    );
    let (status, body) = send(&app, put_tag(&lead, "prod")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tags"]["env"], "prod");
    version += 1;
    let (status, body) = send(&app, put_tag(&outsider, "prod")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    for _ in 0..2 {
        let (status, body) = send(
            &app,
            Request::delete(&tag)
                .header(header::AUTHORIZATION, format!("Bearer {lead}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "removing twice succeeds: {body}");
        assert_eq!(body["tags"].get("env"), None);
        version = body["version"].as_u64().unwrap();
    }

    // --- Every other transition, each under its own role ---
    let step = |path: &'static str, token: &str, body: Value| {
        let app = app.clone();
        let token = token.to_string();
        let path = format!("{base}/{path}");
        async move {
            let (status, incident) = post(&app, &path, &token, Some(&key(&path)), body).await;
            (status, incident)
        }
    };

    let (status, body) = step(
        "assign",
        &operator,
        json!({"expected_version": version, "user_id": "u_4821"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["assigned_user_id"], "u_4821");
    version += 1;
    let (status, body) = step("unassign", &operator, json!({"expected_version": version})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["assigned_user_id"], Value::Null);
    version += 1;

    let (status, body) = step(
        "severity",
        &senior,
        json!({"expected_version": version, "severity": "minor"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "lowering needs a reason: {body}"
    );
    assert_eq!(body["error"], "incident.validation_failed");
    let (status, body) = send(
        &app,
        Request::post(format!("{base}/severity"))
            .header(header::AUTHORIZATION, format!("Bearer {senior}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", key("severity-with-reason"))
            .body(Body::from(
                json!({"expected_version": version, "severity": "minor", "reason": "host stable"})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["severity"], "minor");
    version += 1;
    let (status, body) = step(
        "priority",
        &senior,
        json!({"expected_version": version, "priority": "P4"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["priority"], "P4");
    version += 1;

    // T-20: the audit trail alone shows each change, with both values.
    let (status, audit) = send(
        &app,
        Request::get(format!("{base}/audit?limit=200"))
            .header(header::AUTHORIZATION, format!("Bearer {lead}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    let allowed = |action: &str| {
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["action"] == action && entry["result"] == "allowed")
            .cloned()
            .unwrap_or_else(|| panic!("no allowed {action} entry: {audit}"))
    };
    let severity = allowed("incident_severity_change");
    assert_eq!(severity["after"], json!({"severity": "minor"}));
    assert!(severity["before"]["severity"].is_string(), "{severity}");
    assert_ne!(severity["before"], severity["after"]);
    assert_eq!(severity["reason"], "host stable");
    let priority = allowed("incident_priority_change");
    assert_eq!(priority["after"], json!({"priority": "P4"}));
    assert!(priority["before"]["priority"].is_string(), "{priority}");

    let (status, body) = step(
        "investigate",
        &operator,
        json!({"expected_version": version}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "investigating");
    version += 1;
    let (status, body) = step("monitor", &operator, json!({"expected_version": version})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "monitoring");
    version += 1;

    let (status, body) = step(
        "suppress",
        &lead,
        json!({"expected_version": version, "reason": "backup window", "expires_at": "2020-01-01T00:00:00Z"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "past expiry: {body}"
    );
    let (status, body) = send(
        &app,
        Request::post(format!("{base}/suppress"))
            .header(header::AUTHORIZATION, format!("Bearer {lead}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", key("suppress-future"))
            .body(Body::from(
                json!({"expected_version": version, "reason": "backup window", "expires_at": "2099-01-01T00:00:00Z"})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    // Beyond the 30-day bound is refused, the same as the past.
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let soon = wetechinetmon_api::time::rfc3339(
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3_600)
            * 1_000_000,
    );
    let (status, body) = send(
        &app,
        Request::post(format!("{base}/suppress"))
            .header(header::AUTHORIZATION, format!("Bearer {lead}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", key("suppress-hour"))
            .body(Body::from(
                json!({"expected_version": version, "reason": "backup window", "expires_at": soon})
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["suppression"]["reason"], "backup window");
    version += 1;
    let (status, body) = step("unsuppress", &lead, json!({"expected_version": version})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["suppression"], Value::Null);
    version += 1;

    let (status, body) = step(
        "resolve",
        &senior,
        json!({"expected_version": version, "resolution_note": "attack ended"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "resolved");
    version += 1;
    let (status, body) = step(
        "close",
        &senior,
        json!({"expected_version": version, "closure_reason": "resolved"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "closed");
    assert_eq!(body["closure_reason"], "resolved");
    version += 1;
    let (status, body) = step(
        "reopen",
        &senior,
        json!({"expected_version": version, "reason": "recurred"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "open");

    // --- An illegal edge: a reopened incident cannot be closed directly ---
    let version = body["version"].as_u64().unwrap();
    let (status, body) = send(
        &app,
        Request::post(format!("{base}/close"))
            .header(header::AUTHORIZATION, format!("Bearer {senior}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", key("close-from-open"))
            .body(Body::from(
                json!({"expected_version": version, "closure_reason": "resolved"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "incident.illegal_transition");
}
