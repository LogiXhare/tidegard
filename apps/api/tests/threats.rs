//! The Phase 5F security review, against PostgreSQL through the API: the
//! tests the [threat model](../../../docs/security/incident-threat-model.md)
//! names that need a database. One section per threat;
//! `docs/security/incident-threat-tests.md` maps every threat to its tests.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema and
//! installs the process-wide log capture.

#[path = "../../../crates/incident-postgres/tests/support/mod.rs"]
mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{event, host_scope, Scope};
use tidegard_api::auth::Role;
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_api::{router, AppState};
use tidegard_detector::{EventKind, MetricKind};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::clock::SystemClock;
use tidegard_incident::command::Command;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::error::IncidentError;
use tidegard_incident::id::IncidentId;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::Client;
use tower::ServiceExt;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

/// Everything logged at INFO and above, for T-23.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

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

async fn scalar(
    client: &Client,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> i64 {
    client.query_one(sql, params).await.unwrap().get(0)
}

fn scope(tenant: &'static str) -> Scope {
    let base = host_scope();
    Scope {
        tenant,
        scope_type: base.scope_type,
        scope_id: base.scope_id,
    }
}

#[tokio::test]
async fn the_threat_model_holds_against_postgresql() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping threats: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };
    let logs = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    )
    .expect("the only subscriber in this test binary");

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

    // --- T-02: the same event a thousand times is one incident, one link ---
    let dupe = event(
        &scope("dupe"),
        1,
        EventKind::Started,
        "p-dupe",
        MetricKind::Bps,
    );
    let dupe_auth = AuthorizationContext::correlator(TenantId::new("dupe"));
    for _ in 0..1_000 {
        service
            .ingest_detection_event(&mut admin, &dupe_auth, &dupe)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        scalar(
            &admin,
            "SELECT count(*) FROM incidents WHERE tenant_id = 'dupe'",
            &[]
        )
        .await,
        1
    );
    assert_eq!(
        scalar(
            &admin,
            "SELECT count(*) FROM incident_detection_events WHERE tenant_id = 'dupe'",
            &[]
        )
        .await,
        1
    );

    // --- One acme and one globex incident, and the API ---
    let mut ids = Vec::new();
    for tenant in ["acme", "globex"] {
        let id = service
            .ingest_detection_event(
                &mut admin,
                &AuthorizationContext::correlator(TenantId::new(tenant)),
                &event(
                    &scope(tenant),
                    1,
                    EventKind::Started,
                    "p-threats",
                    MetricKind::Bps,
                ),
            )
            .await
            .unwrap()
            .unwrap()
            .incident_id
            .unwrap();
        ids.push(id);
    }
    let (acme_id, globex_id) = (ids[0], ids[1]);
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
    let lead = token(&admin, "acme", Role::NocLead).await;
    let outsider = token(&admin, "globex", Role::NocLead).await;
    let base = format!("/api/v1/incidents/{}", acme_id.to_canonical_string());

    // --- T-07: hostile note text round-trips byte for byte; NUL is refused ---
    let bodies = [
        "<script>alert(document.cookie)</script>",
        "line one\nline two\r\n\tindented",
        "'; DROP TABLE incidents; --",
        "{\"injected\": true}",
        "ঢাকা ✓ \u{202e}reversed",
        &"x".repeat(4_000),
    ];
    for (n, text) in bodies.iter().enumerate() {
        let (status, body) = send(
            &app,
            Method::POST,
            &format!("{base}/notes"),
            &lead,
            Some(&format!("threats-note-{n:04}")),
            Some(json!({"body": text})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{text:?}: {body}");
    }
    let (_, notes) = send(
        &app,
        Method::GET,
        &format!("{base}/notes"),
        &lead,
        None,
        None,
    )
    .await;
    let stored: Vec<&str> = notes["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["body"].as_str().unwrap())
        .collect();
    assert_eq!(stored, bodies, "every byte comes back as it went in");
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{base}/notes"),
        &lead,
        Some("threats-note-nul0"),
        Some(json!({"body": "a\u{0}b"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a NUL is refused up front, not a 500: {body}"
    );

    // --- T-10: injection payloads are refused or stored as data ---
    let incidents_before = scalar(&admin, "SELECT count(*) FROM incidents", &[]).await;
    for query in [
        "sort=opened_at%3BDROP%20TABLE%20incidents",
        "order=desc%3B--",
        "state=open%27%20OR%20%271%27%3D%271",
        "cursor=%27%3B%20DROP%20TABLE%20incidents%3B--",
        "incident_number=WNM%27%20OR%201%3D1--",
        "opened_from=2026-01-01T00%3A00%3A00Z%27%20OR%201%3D1&opened_to=2026-01-02T00%3A00%3A00Z",
    ] {
        let (status, body) = send(
            &app,
            Method::GET,
            &format!("/api/v1/incidents?{query}"),
            &lead,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
    }
    let hostile_key = "env'; DROP TABLE incidents;--";
    let encoded: String = hostile_key.bytes().map(|b| format!("%{b:02X}")).collect();
    let (status, body) = send(
        &app,
        Method::PUT,
        &format!("{base}/tags/{encoded}"),
        &lead,
        Some("threats-tag-0001"),
        Some(json!({"value": "x' OR '1'='1"})),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::UNPROCESSABLE_ENTITY,
        "stored as data or refused as invalid, never executed: {status} {body}"
    );
    if status == StatusCode::OK {
        assert_eq!(
            body["tags"][hostile_key], "x' OR '1'='1",
            "stored literally"
        );
    }
    assert_eq!(
        scalar(&admin, "SELECT count(*) FROM incidents", &[]).await,
        incidents_before
    );

    // --- T-13: two conflicting commands on one version: exactly one wins ---
    let mut left_client = connect(&url).await;
    let mut right_client = connect(&url).await;
    let lead_context = AuthorizationContext::new(
        TenantId::new("globex"),
        Actor::Operator {
            id: "globex-lead".into(),
        },
        FixedBundleResolver.permissions_for("noc_lead"),
    );
    let version: i64 = scalar(
        &admin,
        "SELECT version FROM incidents WHERE incident_id = $1::text::uuid",
        &[&globex_id.to_canonical_string()],
    )
    .await;
    let version = version as u64;
    let (left, right) = tokio::join!(
        service.handle_command(
            &mut left_client,
            &lead_context,
            globex_id,
            Command::AcknowledgeIncident {
                expected_version: version
            },
            None
        ),
        service.handle_command(
            &mut right_client,
            &lead_context,
            globex_id,
            Command::BeginInvestigation {
                expected_version: version
            },
            None
        ),
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes.iter().filter(|o| o.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Err(IncidentError::VersionConflict { .. }))),
        "the loser sees the conflict: {outcomes:?}"
    );
    // A transition without a version never reaches the domain.
    let (status, _) = send(
        &app,
        Method::POST,
        &format!("{base}/reopen"),
        &lead,
        Some("threats-noversion"),
        Some(json!({"reason": "r"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- T-14: an idempotency key never crosses tenants ---
    let shared_key = "threats-shared-key-0001";
    let globex_base = format!("/api/v1/incidents/{}", globex_id.to_canonical_string());
    let (_, theirs) = send(&app, Method::GET, &globex_base, &outsider, None, None).await;
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{globex_base}/notes"),
        &outsider,
        Some(shared_key),
        Some(json!({"body": "globex note"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(theirs["version"].as_u64().is_some());
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{base}/notes"),
        &lead,
        Some(shared_key),
        Some(json!({"body": "acme note"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the same key in another tenant is a new request: {body}"
    );
    assert_eq!(body["tenant_id"], "acme");

    // --- T-21: assignment confers no access across tenants ---
    let (_, current) = send(&app, Method::GET, &base, &lead, None, None).await;
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{base}/assign"),
        &lead,
        Some("threats-assign-01"),
        Some(json!({"expected_version": current["version"], "user_id": "globex-noc_lead"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = send(&app, Method::GET, &base, &outsider, None, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "being named as assignee grants nothing"
    );

    // --- T-09: newlines and JSON in a reason make one well-formed record ---
    let audits_before = scalar(
        &admin,
        "SELECT count(*) FROM incident_audit WHERE action = 'incident_resolve'",
        &[],
    )
    .await;
    let (_, current) = send(&app, Method::GET, &base, &lead, None, None).await;
    let hostile_reason = "done\n\"}],\"forged\":{\"result\":\"denied\"}\r\n--";
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{base}/resolve"),
        &lead,
        Some("threats-resolve-01"),
        Some(json!({"expected_version": current["version"], "resolution_note": hostile_reason})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        scalar(
            &admin,
            "SELECT count(*) FROM incident_audit WHERE action = 'incident_resolve'",
            &[]
        )
        .await,
        audits_before + 1,
        "exactly one audit record"
    );
    let (_, notes) = send(
        &app,
        Method::GET,
        &format!("{base}/notes"),
        &lead,
        None,
        None,
    )
    .await;
    let last = notes["items"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        last["body"], hostile_reason,
        "kept as one value, byte for byte"
    );
    let (_, audit) = send(
        &app,
        Method::GET,
        &format!("{base}/audit?limit=200"),
        &lead,
        None,
        None,
    )
    .await;
    let text = audit.to_string();
    assert!(
        !text.contains("forged"),
        "the reason never reaches the audit structure"
    );

    // --- T-23: no note body, nor any token, appears in a log line ---
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for text in bodies
        .iter()
        .chain([&"globex note", &"acme note", &hostile_reason])
    {
        assert!(!logged.contains(*text), "a note body was logged: {text:?}");
    }
    assert!(
        !logged.contains(&lead) && !logged.contains(&outsider),
        "a token was logged"
    );
    let _ = IncidentId::parse(&acme_id.to_canonical_string()).unwrap();
}
