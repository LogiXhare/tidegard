//! Milestone 5D-5: an incident's timeline, notes, detections and audit
//! against PostgreSQL.
//! - Walking each history page by page returns every row exactly once,
//!   in order.
//! - Audit needs `incident.audit.read`: a viewer gets 403, a NOC lead 200.
//! - **Another tenant gets 404 on every sub-resource**, identical to a
//!   missing incident (ADR 0038).
//! - The export (5D-10) carries the same histories in one document, needs
//!   `incident.export`, and audits itself before it reads.
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

async fn get(app: &axum::Router, path: &str, token: &str) -> (StatusCode, Value) {
    send(
        app,
        Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
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

/// Every item of a paged history, following `next_cursor`.
async fn walk(app: &axum::Router, base: &str, token: &str, id_field: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut path = format!("{base}?limit=1");
    loop {
        let (status, body) = get(app, &path, token).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        for item in body["items"].as_array().unwrap() {
            ids.push(item[id_field].as_str().unwrap().to_string());
        }
        match body["next_cursor"].as_str() {
            Some(cursor) => path = format!("{base}?limit=1&cursor={cursor}"),
            None => return ids,
        }
    }
}

fn shape(body: &Value) -> (Value, Value, Value) {
    (
        body["status"].clone(),
        body["error"].clone(),
        body["title"].clone(),
    )
}

#[tokio::test]
async fn histories_page_completely_and_stay_inside_the_tenant() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping incident_history: {TEST_DATABASE_URL_VAR} is not set. \
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

    // --- One acme incident with three linked events ---
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    let acme = AuthorizationContext::correlator(TenantId::new("acme"));
    let mut incident_id = None;
    for (sequence, kind) in [
        (1, EventKind::Started),
        (2, EventKind::Updated),
        (3, EventKind::Updated),
    ] {
        let result = service
            .ingest_detection_event(
                &mut admin,
                &acme,
                &event(&host_scope(), sequence, kind, "p-history", MetricKind::Bps),
            )
            .await
            .unwrap()
            .unwrap();
        incident_id = incident_id.or(result.incident_id);
    }
    let id = incident_id.unwrap().to_canonical_string();

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
    let viewer = token(&admin, "acme", Role::Viewer).await;
    let lead = token(&admin, "acme", Role::NocLead).await;
    let outsider = token(&admin, "globex", Role::NocLead).await;
    let base = format!("/api/v1/incidents/{id}");

    // --- Timeline: one entry per page, every entry once, in order ---
    let timeline = walk(&app, &format!("{base}/timeline"), &viewer, "timeline_id").await;
    let stored: i64 = admin
        .query_one(
            "SELECT count(*) FROM incident_timeline WHERE incident_id = $1::text::uuid",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(timeline.len() as i64, stored);
    assert!(stored >= 3, "opened plus linked events: {stored}");
    let numbers: Vec<i64> = timeline.iter().map(|t| t.parse().unwrap()).collect();
    assert!(
        numbers.windows(2).all(|pair| pair[0] < pair[1]),
        "oldest first"
    );

    // --- Detections: all three links, once each ---
    let detections = walk(
        &app,
        &format!("{base}/detections"),
        &viewer,
        "detection_event_id",
    )
    .await;
    assert_eq!(detections.len(), 3, "{detections:?}");
    let mut unique = detections.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 3);

    // --- Notes: none yet, and that is a 200 ---
    let (status, body) = get(&app, &format!("{base}/notes"), &viewer).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    // --- Audit: the NOC lead may read it, the viewer may not ---
    let (status, body) = get(&app, &format!("{base}/audit"), &viewer).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "incident.forbidden");
    let (status, _) = get(&app, &format!("{base}/audit"), &lead).await;
    assert_eq!(status, StatusCode::OK);

    // --- Another tenant: 404 everywhere, the same as a missing incident ---
    let missing = "/api/v1/incidents/0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";
    for sub in ["timeline", "notes", "detections", "audit"] {
        let (status, cross) = get(&app, &format!("{base}/{sub}"), &outsider).await;
        let (_, absent) = get(&app, &format!("{missing}/{sub}"), &outsider).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{sub}: {cross}");
        assert_eq!(cross["error"], "incident.not_found", "{sub}");
        assert_eq!(shape(&cross), shape(&absent), "{sub}");
    }

    // --- Export: incident.export only, audited, one bundle ---
    let export = |token: &str, path: String| {
        Request::post(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let (status, body) = send(&app, export(&viewer, format!("{base}/export"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(&app, export(&outsider, format!("{base}/export"))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let response = app
        .clone()
        .oneshot(export(&lead, format!("{base}/export")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let disposition = response.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .to_string();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    let bundle: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bundle["format"], "tidegard.incident-export");
    assert_eq!(bundle["incident"]["incident_id"], id.as_str());
    let number = bundle["incident"]["incident_number"].as_str().unwrap();
    assert!(
        disposition.contains(&format!("{number}.json")),
        "{disposition}"
    );
    assert_eq!(bundle["timeline"].as_array().unwrap().len() as i64, stored);
    assert_eq!(bundle["detections"].as_array().unwrap().len(), 3);
    assert_eq!(bundle["truncated"]["timeline"], false);
    let audit = bundle["audit"].as_array().unwrap();
    assert!(
        audit
            .iter()
            .any(|entry| entry["action"] == "incident_export"),
        "the export audited itself before reading: {audit:?}"
    );

    // --- Bad cursors and unknown parameters are refused ---
    let (status, _) = get(&app, &format!("{base}/timeline?cursor=abc"), &viewer).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = get(&app, &format!("{base}/notes?limit=5"), &viewer).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "api.unknown_field");
}
