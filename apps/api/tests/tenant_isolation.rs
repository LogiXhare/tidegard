//! The Milestone 5D exit criterion: tenant isolation on **every**
//! endpoint, against PostgreSQL (ADR 0038).
//!
//! The endpoints are not listed by hand. They are read from the committed
//! OpenAPI document, which a drift test ties to the router, so an endpoint
//! added without a case here fails this test rather than going untested.
//!
//! For every operation on one incident, another tenant's `noc_lead` (the
//! broadest token role) sends a request the endpoint would accept, and
//! gets a `404 incident.not_found` identical in status, code and title to
//! the answer for an incident that does not exist. Afterwards the incident
//! is unchanged, the other tenant's list does not show it, and the other
//! tenant may open its own incident on the same address, because the
//! correlation key includes the tenant.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

#[path = "../../../crates/incident-postgres/tests/support/mod.rs"]
mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
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
const OPENAPI: &str = include_str!("../../../docs/api/openapi.json");
const MISSING: &str = "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";

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

async fn send(
    app: &axum::Router,
    method: &Method,
    path: &str,
    token: &str,
    key: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if *method != Method::GET {
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

/// A request body each per-incident operation would accept from its own
/// tenant, so the refusal tested is the tenant boundary and not a parse
/// error. `None` is "no body"; a missing entry fails the test.
fn accepted_body(method: &str, last_segment: &str, soon: &str) -> Option<Option<Value>> {
    let version = json!({"expected_version": 1});
    Some(match (method, last_segment) {
        ("get", _) | ("delete", _) | ("post", "export") => None,
        (
            "post",
            "acknowledge" | "investigate" | "monitor" | "unsuppress" | "unassign" | "resolve",
        ) => Some(version),
        ("post", "close") => Some(json!({"expected_version": 1, "closure_reason": "resolved"})),
        ("post", "reopen") => Some(json!({"expected_version": 1, "reason": "recurred"})),
        ("post", "suppress") => {
            Some(json!({"expected_version": 1, "reason": "maintenance", "expires_at": soon}))
        }
        ("post", "assign") => Some(json!({"expected_version": 1, "user_id": "u_1"})),
        ("post", "severity") => {
            Some(json!({"expected_version": 1, "severity": "minor", "reason": "subsided"}))
        }
        ("post", "priority") => Some(json!({"expected_version": 1, "priority": "P3"})),
        ("post", "notes") => Some(json!({"body": "a note"})),
        ("post", "edit") => Some(json!({"body": "an edit"})),
        ("post", "redact") => Some(json!({"reason": "a reason"})),
        ("put", "{key}") => Some(json!({"value": "prod"})),
        _ => return None,
    })
}

fn shape(body: &Value) -> (Value, Value, Value) {
    (
        body["status"].clone(),
        body["error"].clone(),
        body["title"].clone(),
    )
}

#[tokio::test]
async fn no_endpoint_crosses_the_tenant_boundary() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping tenant_isolation: {TEST_DATABASE_URL_VAR} is not set. \
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

    // --- One acme incident, with a note and a tag, so every history has rows ---
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    let id = service
        .ingest_detection_event(
            &mut admin,
            &AuthorizationContext::correlator(TenantId::new("acme")),
            &event(
                &host_scope(),
                1,
                EventKind::Started,
                "p-isolation",
                MetricKind::Bps,
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .unwrap()
        .to_canonical_string();

    let (pool, _) = tidegard_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .expect("a loopback test database");
    // Traffic is served to acme only, from a ClickHouse that is not
    // there: acme's callers reach ClickHouse and get 503, while another
    // tenant is refused before anything is read (ADR 0042).
    let unreachable =
        tidegard_api::clickhouse::ClickHouse::new(tidegard_api::clickhouse::Endpoint {
            scheme: tidegard_api::clickhouse::Scheme::Http,
            host: "127.0.0.1".into(),
            port: 9,
            user: "default".into(),
            password_file: None,
            ca_file: None,
        })
        .unwrap();
    // acme may mitigate its own 203.0.113.0/24 (ADR 0050).
    let guard = tidegard_mitigation::Guard::new(tidegard_mitigation::GuardConfig {
        allowlist: vec![tidegard_mitigation::guard::AllowlistEntry {
            prefix: "203.0.113.0/24".parse().unwrap(),
            tenant: "acme".into(),
            actions: vec![tidegard_mitigation::ActionKind::Rtbh],
        }],
        ..tidegard_mitigation::GuardConfig::default()
    })
    .unwrap();
    let app = router(
        AppState::new(pool)
            .with_traffic(tidegard_api::traffic::TrafficSource {
                tenant: TenantId::new("acme"),
                clickhouse: unreachable,
            })
            .with_guard(guard),
    );
    let owner = token(&admin, "acme", Role::NocLead).await;
    let outsider = token(&admin, "globex", Role::NocLead).await;
    let base = format!("/api/v1/incidents/{id}");
    let (status, _) = send(
        &app,
        &Method::POST,
        &format!("{base}/notes"),
        &owner,
        "isolation-setup-note",
        Some(&json!({"body": "owner note"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &app,
        &Method::PUT,
        &format!("{base}/tags/env"),
        &owner,
        "isolation-setup-tag0",
        Some(&json!({"value": "prod"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, before) = send(&app, &Method::GET, &base, &owner, "", None).await;

    let soon = tidegard_api::time::rfc3339(
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3_600)
            * 1_000_000,
    );

    // --- Every per-incident operation in the OpenAPI document ---
    let document: Value = serde_json::from_str(OPENAPI).unwrap();
    let mut checked = 0;
    for (template, operations) in document["paths"].as_object().unwrap() {
        if !template.contains("{incident_id}") {
            continue;
        }
        let last = template.rsplit('/').next().unwrap();
        for (method_name, _) in operations.as_object().unwrap() {
            let body = accepted_body(method_name, last, &soon).unwrap_or_else(|| {
                panic!("no isolation case for {method_name} {template}: add one to accepted_body")
            });
            let method = Method::from_bytes(method_name.to_uppercase().as_bytes()).unwrap();
            let cross_path = template
                .replace("{incident_id}", &id)
                .replace("{key}", "env")
                .replace("{note_index}", "0");
            let missing_path = template
                .replace("{incident_id}", MISSING)
                .replace("{key}", "env")
                .replace("{note_index}", "0");
            let (status, cross) = send(
                &app,
                &method,
                &cross_path,
                &outsider,
                &format!("isolation-cross-{checked:04}"),
                body.as_ref(),
            )
            .await;
            let (_, absent) = send(
                &app,
                &method,
                &missing_path,
                &outsider,
                &format!("isolation-absent-{checked:04}"),
                body.as_ref(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{method} {template}: {cross}"
            );
            assert_eq!(cross["error"], "incident.not_found", "{method} {template}");
            assert_eq!(shape(&cross), shape(&absent), "{method} {template}");
            checked += 1;
        }
    }
    assert!(
        checked >= 20,
        "only {checked} operations were found in the OpenAPI document"
    );

    // --- Deployment-wide traffic: the traffic tenant only (ADR 0042) ---
    let mut traffic_checked = 0;
    for (template, operations) in document["paths"].as_object().unwrap() {
        let is_traffic = operations
            .as_object()
            .unwrap()
            .values()
            .any(|operation| operation["tags"][0] == "traffic");
        if !is_traffic {
            continue;
        }
        let path = if template.ends_with("/top") {
            format!("{template}?dimension=host")
        } else {
            template.clone()
        };
        let (status, theirs) = send(&app, &Method::GET, &path, &outsider, "", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {theirs}");
        assert_eq!(theirs["error"], "api.not_found", "{path}");
        let (status, ours) = send(&app, &Method::GET, &path, &owner, "", None).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the traffic tenant reaches ClickHouse: {path}: {ours}"
        );
        traffic_checked += 1;
    }
    assert_eq!(traffic_checked, 3, "summary, top and exporters");

    // --- Mitigations: another tenant's do not exist (ADR 0050) ---
    let (status, mine) = send(
        &app,
        &Method::POST,
        "/api/v1/mitigations",
        &owner,
        "isolation-mitigation",
        Some(&json!({"prefix": "203.0.113.90/32", "action": "rtbh",
                     "reason": "isolation", "duration_seconds": 600})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{mine}");
    let mitigation = mine["mitigation_id"].as_str().unwrap().to_string();
    let mut mitigation_checked = 0;
    for (template, operations) in document["paths"].as_object().unwrap() {
        if !template.contains("{mitigation_id}") {
            continue;
        }
        let last = template.rsplit('/').next().unwrap();
        for (method_name, _) in operations.as_object().unwrap() {
            let body = match (method_name.as_str(), last) {
                ("get", _) => None,
                ("post", "approve") => Some(json!({"expected_version": 1})),
                ("post", "reject" | "withdraw") => {
                    Some(json!({"expected_version": 1, "reason": "isolation"}))
                }
                _ => panic!("no isolation case for {method_name} {template}"),
            };
            let method = Method::from_bytes(method_name.to_uppercase().as_bytes()).unwrap();
            let (status, cross) = send(
                &app,
                &method,
                &template.replace("{mitigation_id}", &mitigation),
                &outsider,
                &format!("isolation-mitigation-cross-{mitigation_checked:02}"),
                body.as_ref(),
            )
            .await;
            let (_, absent) = send(
                &app,
                &method,
                &template.replace("{mitigation_id}", MISSING),
                &outsider,
                &format!("isolation-mitigation-absent-{mitigation_checked:02}"),
                body.as_ref(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{method} {template}: {cross}"
            );
            assert_eq!(
                cross["error"], "mitigation.not_found",
                "{method} {template}"
            );
            assert_eq!(shape(&cross), shape(&absent), "{method} {template}");
            mitigation_checked += 1;
        }
    }
    assert_eq!(
        mitigation_checked, 5,
        "get, history, approve, reject and withdraw"
    );
    let (_, listed) = send(
        &app,
        &Method::GET,
        "/api/v1/mitigations",
        &outsider,
        "",
        None,
    )
    .await;
    assert!(listed["items"].as_array().unwrap().is_empty(), "{listed}");
    let (_, routes) = send(
        &app,
        &Method::GET,
        "/api/v1/bgp/routes",
        &outsider,
        "",
        None,
    )
    .await;
    assert!(routes["items"].as_array().unwrap().is_empty(), "{routes}");
    // Another tenant's lead cannot approve it either: still requested.
    let (_, still) = send(
        &app,
        &Method::GET,
        &format!("/api/v1/mitigations/{mitigation}"),
        &owner,
        "",
        None,
    )
    .await;
    assert_eq!(still["state"], "requested");

    // --- Nothing changed, and nothing shows in the other tenant's list ---
    let (_, after) = send(&app, &Method::GET, &base, &owner, "", None).await;
    assert_eq!(
        before, after,
        "another tenant's requests changed the incident"
    );
    let (status, listed) = send(&app, &Method::GET, "/api/v1/incidents", &outsider, "", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["incident_id"] != id.as_str()),
        "{listed}"
    );

    // --- The other tenant's own incident on the same address is its own ---
    let (status, theirs) = send(
        &app,
        &Method::POST,
        "/api/v1/incidents",
        &outsider,
        "isolation-globex-create",
        Some(
            &json!({"title": "Same address, other tenant", "severity": "minor",
                     "target_scope": "host", "target": "203.0.113.90", "direction": "incoming"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the correlation key includes the tenant: {theirs}"
    );
    assert_ne!(theirs["incident_id"], id.as_str());
    assert_eq!(theirs["tenant_id"], "globex");

    // --- whoami answers with the token's own identity, never another's ---
    let (status, me) = send(&app, &Method::GET, "/api/v1/whoami", &outsider, "", None).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["tenant_id"], "globex");
    assert_eq!(me["actor_type"], "operator");
    assert_eq!(me["actor_id"], "globex-noc_lead");
    assert_eq!(me["role"], "noc_lead");
    let permissions: Vec<&str> = me["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(permissions.contains(&"incident.export"), "{permissions:?}");
    assert!(!permissions.contains(&"incident.closure_policy.override"));
}
