//! Milestone 5D-4: `GET /api/v1/incidents` against PostgreSQL.
//! - Walking every page by cursor returns each of the tenant's incidents
//!   exactly once, in order, and never another tenant's.
//! - `include_total` counts; filters narrow; an unknown parameter is 400.
//! - A cursor issued to one tenant is refused for another.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

#[path = "../../../crates/incident-postgres/tests/support/mod.rs"]
mod support;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use support::{event, Scope};
use tidegard_api::auth::Role;
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_api::{router, AppState};
use tidegard_detector::{EventKind, MetricKind, ScopeId, ScopeType};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::clock::SystemClock;
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::Client;
use tower::ServiceExt;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const ACME_INCIDENTS: u8 = 5;

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

fn host(tenant: &'static str, last_octet: u8) -> Scope {
    Scope {
        tenant,
        scope_type: ScopeType::Host,
        scope_id: ScopeId::Host {
            addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet)),
        },
    }
}

async fn open_incident(service: &IncidentPersistence, client: &mut Client, scope: &Scope, n: u8) {
    let mut started = event(scope, 1, EventKind::Started, "p-list", MetricKind::Bps);
    // Each incident is its own detection, so none is a duplicate of another.
    started.detection_id = format!("det-list-{n}");
    started.event_id = format!("det-list-{n}-1");
    started.dedup_key = format!("det-list-{n}:started:1");
    service
        .ingest_detection_event(
            client,
            &AuthorizationContext::correlator(TenantId::new(scope.tenant)),
            &started,
        )
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .expect("the event opened an incident");
}

async fn token(client: &Client, tenant: &str) -> String {
    token_admin::create(
        client,
        &NewToken {
            tenant: tenant.to_string(),
            actor_type: ActorType::Operator,
            actor_id: format!("{tenant}-viewer"),
            role: Role::Viewer,
            lifetime_days: 1,
            description: String::new(),
        },
    )
    .await
    .unwrap()
    .secret
}

async fn get(app: &axum::Router, path: &str, token: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
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

#[tokio::test]
async fn cursor_pages_cover_the_tenant_exactly_once_and_nothing_else() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping list_incidents: {TEST_DATABASE_URL_VAR} is not set. \
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

    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    for n in 1..=ACME_INCIDENTS {
        open_incident(&service, &mut admin, &host("acme", n), n).await;
    }
    open_incident(&service, &mut admin, &host("globex", 200), 200).await;

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
    let acme = token(&admin, "acme").await;
    let globex = token(&admin, "globex").await;

    // --- Two per page: three pages, every acme incident exactly once ---
    let mut seen = Vec::new();
    let mut opened = Vec::new();
    let mut path = "/api/v1/incidents?limit=2&include_total=true".to_string();
    let mut first_cursor = None;
    for page in 1.. {
        let (status, body) = get(&app, &path, &acme).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], i64::from(ACME_INCIDENTS));
        for item in body["items"].as_array().unwrap() {
            assert_eq!(item["target_type"], "host");
            seen.push(item["incident_id"].as_str().unwrap().to_string());
            opened.push(item["opened_at"].as_str().unwrap().to_string());
        }
        match body["next_cursor"].as_str() {
            Some(cursor) => {
                assert_eq!(body["has_more"], true);
                first_cursor.get_or_insert_with(|| cursor.to_string());
                path = format!("/api/v1/incidents?limit=2&include_total=true&cursor={cursor}");
            }
            None => {
                assert_eq!(body["has_more"], false);
                assert_eq!(page, 3, "5 incidents at 2 per page is 3 pages");
                break;
            }
        }
    }
    assert_eq!(seen.len(), usize::from(ACME_INCIDENTS));
    assert_eq!(
        seen.iter().collect::<HashSet<_>>().len(),
        seen.len(),
        "no incident repeats across pages"
    );
    let mut sorted = opened.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(opened, sorted, "newest first");

    // --- globex sees only its own, and cannot use acme's cursor ---
    let (status, body) = get(&app, "/api/v1/incidents", &globex).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(!seen.contains(&items[0]["incident_id"].as_str().unwrap().to_string()));
    let stolen = format!("/api/v1/incidents?limit=2&cursor={}", first_cursor.unwrap());
    let (status, body) = get(&app, &stolen, &globex).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "api.invalid_request");

    // --- Filters narrow; unknown parameters are refused ---
    let (_, body) = get(&app, "/api/v1/incidents?state=acknowledged", &acme).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    let (_, body) = get(
        &app,
        "/api/v1/incidents?state=open&state=acknowledged&severity=major&direction=incoming&sort=last_detected_at&order=asc",
        &acme,
    )
    .await;
    assert_eq!(
        body["items"].as_array().unwrap().len(),
        usize::from(ACME_INCIDENTS)
    );
    // --- An exact incident number finds that one, and only in the tenant ---
    let (_, all) = get(&app, "/api/v1/incidents?limit=1", &acme).await;
    let number = all["items"][0]["incident_number"]
        .as_str()
        .unwrap()
        .to_string();
    let by_number = format!("/api/v1/incidents?incident_number={number}");
    let (status, body) = get(&app, &by_number, &acme).await;
    assert_eq!(status, StatusCode::OK);
    let found = body["items"].as_array().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["incident_number"], number.as_str());
    let (_, body) = get(&app, &by_number, &globex).await;
    // Numbers are per tenant, so globex may hold the same number for its
    // own incident; it must never get acme's.
    let theirs = body["items"].as_array().unwrap();
    assert!(
        theirs
            .iter()
            .all(|item| item["incident_id"] != found[0]["incident_id"]),
        "a number never reaches across tenants: {body}"
    );
    let (status, _) = get(&app, "/api/v1/incidents?incident_number=WNM%27%3B", &acme).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = get(&app, "/api/v1/incidents?tenant_id=globex", &acme).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "api.unknown_field");
}
