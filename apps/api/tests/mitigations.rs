//! Phase 7E (ADR 0050): the mitigation API against PostgreSQL. Requesting
//! with an idempotency key, the guard's refusals, approval and its rules,
//! withdrawal, history, the kill switch (engaged through the API, released
//! only on the host), BGP routes and peers, tenant isolation, and the
//! incident's mitigation and notification status (FU-64).
//!
//! Needs `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`, an ephemeral database
//! this test wipes. Without it the test says why and passes; CI sets it and
//! fails on the skip message.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use tidegard_api::auth::Role;
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_api::{router, AppState};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::clock::SystemClock;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::IncidentId;
use tidegard_incident::timeline::NotificationOutcome;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_mitigation::guard::AllowlistEntry;
use tidegard_mitigation::{ActionKind, Guard, GuardConfig};
use tokio_postgres::Client;
use tower::ServiceExt;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const MISSING: &str = "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";

async fn token(client: &Client, tenant: &str, role: Role, id: &str) -> String {
    // A token names a registered tenant (ADR 0060).
    tidegard_incident_postgres::tenants::ensure(client, tenant)
        .await
        .unwrap();
    token_admin::create(
        client,
        &NewToken {
            tenant: tenant.to_string(),
            actor_type: ActorType::Operator,
            actor_id: id.to_string(),
            role,
            lifetime_days: 1,
            description: String::new(),
        },
    )
    .await
    .unwrap()
    .secret
}

async fn send(
    app: &axum::Router,
    method: Method,
    path: &str,
    token: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(key) = key {
        request = request.header("Idempotency-Key", key);
    }
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn rtbh(host: &str) -> Value {
    json!({"prefix": format!("{host}/32"), "action": "rtbh",
           "reason": "UDP flood", "duration_seconds": 600})
}

#[tokio::test]
async fn the_mitigation_api_requests_approves_withdraws_and_isolates() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping mitigations: {TEST_DATABASE_URL_VAR} is not set. This test requires a real, \
             ephemeral, local-or-CI-only PostgreSQL instance."
        );
        return;
    };
    let (mut admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    admin
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .unwrap();
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut admin)
        .await
        .unwrap();
    let (pool, _) = tidegard_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 4,
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();
    let guard = Guard::new(GuardConfig {
        allowlist: vec![AllowlistEntry {
            prefix: "192.0.2.0/24".parse().unwrap(),
            tenant: "acme".into(),
            actions: vec![ActionKind::Rtbh],
        }],
        ..GuardConfig::default()
    })
    .unwrap();
    let app = router(AppState::new(pool.clone()).with_guard(guard));
    let viewer = token(&admin, "acme", Role::Viewer, "vic").await;
    let senior = token(&admin, "acme", Role::SeniorOperator, "alice").await;
    let lead = token(&admin, "acme", Role::NocLead, "lead").await;
    let outsider = token(&admin, "globex", Role::NocLead, "eve").await;

    // --- Request: key required, unknown fields refused, the guard decides ---
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        None,
        Some(rtbh("192.0.2.10")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let mut smuggled = rtbh("192.0.2.10");
    smuggled["next_hop"] = json!("198.51.100.1");
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-smuggled-0001"),
        Some(smuggled),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("api.unknown_field")),
        "{body}"
    );
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-outside-00001"),
        Some(rtbh("198.51.100.1")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mitigation.not_allowlisted")),
        "{body}"
    );
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &viewer,
        Some("key-viewer-000001"),
        Some(rtbh("192.0.2.10")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mitigation.forbidden")),
        "{body}"
    );
    let (status, first) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-first-0000001"),
        Some(rtbh("192.0.2.10")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_eq!(first["state"], "requested");
    assert_eq!(first["requested_by"], "alice");
    let id = first["mitigation_id"].as_str().unwrap().to_string();
    let (status, replay) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-first-0000001"),
        Some(rtbh("192.0.2.10")),
    )
    .await;
    assert_eq!(
        (status, &replay["mitigation_id"]),
        (StatusCode::CREATED, &first["mitigation_id"])
    );
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-first-0000001"),
        Some(rtbh("192.0.2.11")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (
            StatusCode::CONFLICT,
            Some("mitigation.idempotency_key_reuse")
        ),
        "{body}"
    );
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-duplicate-001"),
        Some(rtbh("192.0.2.10")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("mitigation.duplicate")),
        "{body}"
    );

    // --- Another tenant: not found, the same as a missing id; empty lists ---
    let path = format!("/api/v1/mitigations/{id}");
    let (status, theirs) = send(&app, Method::GET, &path, &outsider, None, None).await;
    let (_, missing) = send(
        &app,
        Method::GET,
        &format!("/api/v1/mitigations/{MISSING}"),
        &outsider,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        (&theirs["error"], &theirs["title"]),
        (&missing["error"], &missing["title"])
    );
    assert_eq!(theirs["error"], "mitigation.not_found");
    for op in ["approve", "reject", "withdraw"] {
        let (status, body) = send(
            &app,
            Method::POST,
            &format!("{path}/{op}"),
            &outsider,
            None,
            Some(json!({"expected_version": 1, "reason": "x"})),
        )
        .await;
        let expected = if op == "approve" {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::NOT_FOUND
        };
        // approve takes no reason: a strict body refuses the extra field first.
        assert_eq!(status, expected, "{op}: {body}");
    }
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{path}/approve"),
        &outsider,
        None,
        Some(json!({"expected_version": 1})),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("mitigation.not_found"))
    );
    let (_, theirs) = send(
        &app,
        Method::GET,
        "/api/v1/mitigations",
        &outsider,
        None,
        None,
    )
    .await;
    assert!(theirs["items"].as_array().unwrap().is_empty());
    let (_, ours) = send(
        &app,
        Method::GET,
        "/api/v1/mitigations?live=true",
        &viewer,
        None,
        None,
    )
    .await;
    assert_eq!(ours["items"].as_array().unwrap().len(), 1);

    // --- Approval: noc_lead, the current version, never your own ---
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{path}/approve"),
        &senior,
        None,
        Some(json!({"expected_version": 1})),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mitigation.forbidden"))
    );
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{path}/approve"),
        &lead,
        None,
        Some(json!({"expected_version": 9})),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("mitigation.version_conflict"))
    );
    assert_eq!(body["current_version"], 1);
    let (status, approved) = send(
        &app,
        Method::POST,
        &format!("{path}/approve"),
        &lead,
        None,
        Some(json!({"expected_version": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(
        (approved["state"].as_str(), approved["approved_by"].as_str()),
        (Some("approved"), Some("lead"))
    );
    let (_, own) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &lead,
        Some("key-own-00000001"),
        Some(rtbh("192.0.2.20")),
    )
    .await;
    let own_path = format!(
        "/api/v1/mitigations/{}",
        own["mitigation_id"].as_str().unwrap()
    );
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{own_path}/approve"),
        &lead,
        None,
        Some(json!({"expected_version": 1})),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mitigation.self_approval"))
    );
    let (status, rejected) = send(
        &app,
        Method::POST,
        &format!("{own_path}/reject"),
        &lead,
        None,
        Some(json!({"expected_version": 1, "reason": "duplicate effort"})),
    )
    .await;
    assert_eq!(
        (status, rejected["state"].as_str()),
        (StatusCode::OK, Some("rejected"))
    );

    // --- Withdrawal and history ---
    let (status, withdrawn) = send(
        &app,
        Method::POST,
        &format!("{path}/withdraw"),
        &senior,
        None,
        Some(json!({"expected_version": 2, "reason": "false positive"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{withdrawn}");
    assert_eq!(
        (
            withdrawn["state"].as_str(),
            withdrawn["withdrawal_cause"].as_str()
        ),
        (Some("withdrawn"), Some("operator"))
    );
    let (status, history) = send(
        &app,
        Method::GET,
        &format!("{path}/history"),
        &viewer,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let steps: Vec<&str> = history["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["to_state"].as_str().unwrap())
        .collect();
    assert_eq!(steps, ["requested", "approved", "withdrawn"]);
    let (status, _) = send(
        &app,
        Method::GET,
        &format!("{path}/history"),
        &outsider,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- The kill switch: on through the API, off only on the host ---
    let ks = "/api/v1/mitigation-controls/kill-switch";
    let (status, state) = send(&app, Method::GET, ks, &viewer, None, None).await;
    assert_eq!((status, &state["engaged"]), (StatusCode::OK, &json!(false)));
    let (status, body) = send(
        &app,
        Method::PUT,
        ks,
        &senior,
        None,
        Some(json!({"engaged": true, "reason": "panic"})),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mitigation.forbidden"))
    );
    let (status, state) = send(
        &app,
        Method::PUT,
        ks,
        &lead,
        None,
        Some(json!({"engaged": true, "reason": "route leak"})),
    )
    .await;
    assert_eq!(
        (status, &state["engaged"], state["changed_by"].as_str()),
        (StatusCode::OK, &json!(true), Some("lead"))
    );
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-killed-000001"),
        Some(rtbh("192.0.2.30")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::CONFLICT, Some("mitigation.kill_switch"))
    );
    let (status, body) = send(
        &app,
        Method::PUT,
        ks,
        &lead,
        None,
        Some(json!({"engaged": false, "reason": "all clear"})),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mitigation.forbidden")),
        "no token may release it"
    );
    {
        let mut client = pool.get().await.unwrap();
        let released = AppState::new(pool.clone())
            .mitigations
            .set_kill_switch(
                &mut client,
                &tidegard_api::mitigations::host_admin_context("root"),
                false,
                "all clear",
            )
            .await
            .unwrap();
        assert!(!released.engaged);
    }

    // --- BGP: the tenant's routed mitigations; peers for leads only ---
    let (status, routes) = send(&app, Method::GET, "/api/v1/bgp/routes", &viewer, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        routes["items"].as_array().unwrap().is_empty(),
        "nothing was announced live"
    );
    admin
        .batch_execute("INSERT INTO bgp_peers (neighbor_address, peer_asn, session_state) VALUES ('192.0.2.1', 64500, 'established')")
        .await
        .unwrap();
    let (status, body) = send(&app, Method::GET, "/api/v1/bgp/peers", &viewer, None, None).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("mitigation.forbidden"))
    );
    let (status, peers) = send(&app, Method::GET, "/api/v1/bgp/peers", &lead, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(peers["items"][0]["session_state"], "established");
    assert_eq!(peers["items"][0]["peer_asn"], 64500);

    // --- FU-64: the incident's mitigation and notification status ---
    let (status, incident) = send(
        &app,
        Method::POST,
        "/api/v1/incidents",
        &senior,
        Some("key-incident-0001"),
        Some(
            json!({"title": "Flood on a customer host", "severity": "major",
                    "target_scope": "host", "target": "192.0.2.40", "direction": "incoming"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{incident}");
    assert_eq!(
        (
            incident["mitigation_status"].as_str(),
            incident["notification_status"].as_str()
        ),
        (Some("none"), Some("none"))
    );
    let incident_id = incident["incident_id"].as_str().unwrap().to_string();
    let mut linked = rtbh("192.0.2.40");
    linked["incident_id"] = json!(incident_id);
    let (status, _) = send(
        &app,
        Method::POST,
        "/api/v1/mitigations",
        &senior,
        Some("key-linked-000001"),
        Some(linked),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    let notifier = AuthorizationContext::notifier(TenantId::new("acme"), "notifier-test");
    for (channel, outcome) in [
        ("noc-slack", NotificationOutcome::Delivered),
        ("ops-hook", NotificationOutcome::Failed),
    ] {
        service
            .record_notification_result(
                &mut admin,
                &notifier,
                IncidentId::parse(&incident_id).unwrap(),
                channel,
                "incident.opened",
                outcome,
            )
            .await
            .unwrap()
            .unwrap();
    }
    let (_, seen) = send(
        &app,
        Method::GET,
        &format!("/api/v1/incidents/{incident_id}"),
        &viewer,
        None,
        None,
    )
    .await;
    assert_eq!(seen["mitigation_status"], "pending_approval");
    assert_eq!(seen["notification_status"], "partial");
}
