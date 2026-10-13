//! Milestone 6C: browser sessions against PostgreSQL (ADR 0043).
//!
//! Signing in with a token gives a session cookie; the cookie then works
//! like the token, with a CSRF value on every change. A planted id is
//! never honoured, a session ends when idle, when old, when signed out and
//! when its token is revoked, and no session id, CSRF value or token is
//! ever logged.
//!
//! Like the other PostgreSQL tests, this connects only to the opt-in,
//! throwaway database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there.
//! One test function, because it resets the `public` schema.

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use tidegard_api::auth::Role;
use tidegard_api::session::csrf_token;
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_api::{router, AppState};
use tidegard_incident_postgres::pool::PoolPolicy;
use tokio_postgres::Client;
use tower::ServiceExt;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

/// Everything logged at INFO and above.
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

async fn token(client: &Client, tenant: &str, role: Role) -> (String, String) {
    let created = token_admin::create(
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
    .unwrap();
    (created.secret, created.token_id.to_string())
}

struct Reply {
    status: StatusCode,
    cookie: Option<String>,
    body: Value,
}

async fn send(
    app: &axum::Router,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: Option<Value>,
) -> Reply {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        request = request.header("X-WNM-CSRF", csrf);
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
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|value| value.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    Reply {
        status,
        cookie,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    }
}

/// `wnm_session=<id>` from a `Set-Cookie` value.
fn session_of(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("wnm_session=")
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn sessions_sign_in_expire_end_and_refuse_forgery() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping sessions: {TEST_DATABASE_URL_VAR} is not set. \
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
        .unwrap();
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut admin)
        .await
        .unwrap();
    let (senior, senior_id) = token(&admin, "acme", Role::SeniorOperator).await;
    let (viewer, viewer_id) = token(&admin, "acme", Role::Viewer).await;
    let (pool, _) = tidegard_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();
    let app = router(AppState::new(pool));
    let mut secrets = vec![senior.clone(), viewer.clone()];

    // --- Sign-in: a new id whatever was planted; the cookie's attributes ---
    let planted = format!("wns_{}", "ab".repeat(32));
    let signed_in = send(
        &app,
        Method::POST,
        "/api/v1/session",
        Some(&format!("wnm_session={planted}")),
        None,
        Some(json!({ "token": senior })),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::CREATED, "{}", signed_in.body);
    let set_cookie = signed_in.cookie.expect("a session cookie");
    for attribute in ["HttpOnly", "SameSite=Strict", "Secure", "Path=/"] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }
    let id = session_of(&set_cookie);
    assert_ne!(id, planted, "a planted id is never honoured");
    let cookie = format!("wnm_session={id}");
    let csrf = signed_in.body["csrf_token"].as_str().unwrap().to_string();
    assert_eq!(csrf, csrf_token(&id));
    assert_eq!(signed_in.body["role"], "senior_operator");
    assert_eq!(signed_in.body["idle_timeout_seconds"], 1800);
    secrets.extend([id.clone(), csrf.clone()]);
    let planted_cookie = format!("wnm_session={planted}");
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/incidents",
        Some(&planted_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    // --- The cookie works like the token; the session answers its CSRF ---
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/incidents",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/session",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body["csrf_token"], csrf.as_str());
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/whoami",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.body["actor_id"], "acme-senior_operator");

    // --- A change needs the CSRF value; without it, refused and audited ---
    let incident = json!({
        "title": "Spoofed sources", "severity": "major", "target_scope": "host",
        "target": "203.0.113.90", "direction": "incoming",
    });
    let open = |csrf: Option<&str>, key: &str| {
        let mut request = Request::post("/api/v1/incidents")
            .header(header::COOKIE, cookie.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", key);
        if let Some(csrf) = csrf {
            request = request.header("X-WNM-CSRF", csrf);
        }
        request.body(Body::from(incident.to_string())).unwrap()
    };
    for (presented, key) in [
        (None, "session-open-no-csrf-0"),
        (Some("0".repeat(64)), "session-open-bad-csrf-0"),
    ] {
        let response = app
            .clone()
            .oneshot(open(presented.as_deref(), key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"], "api.csrf_rejected");
    }
    let refused: i64 = admin
        .query_one(
            "SELECT count(*) FROM incident_audit WHERE action = 'session.csrf_rejected' \
             AND result = 'denied' AND resource_id = $1",
            &[&senior_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(refused, 2);
    let response = app
        .clone()
        .oneshot(open(Some(&csrf), "session-open-with-csrf"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let incident_id = created["incident_id"].as_str().unwrap().to_string();
    let opened: i64 = admin
        .query_one("SELECT count(*) FROM incidents", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        opened, 1,
        "only the request with the CSRF value changed anything"
    );

    // --- A bearer token wins over a cookie ---
    let request = Request::get("/api/v1/whoami")
        .header(header::AUTHORIZATION, format!("Bearer {viewer}"))
        .header(header::COOKIE, cookie.clone())
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["role"], "viewer");

    // --- Idle too long, or past the absolute expiry: refused ---
    let hash = tidegard_api::session::session_hash(&id);
    admin
        .execute(
            "UPDATE api_sessions SET created_at = now() - interval '31 minutes', \
             last_seen_at = now() - interval '31 minutes', \
             expires_at = now() + interval '11 hours' WHERE session_hash = $1",
            &[&hash],
        )
        .await
        .unwrap();
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/incidents",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "idle");
    admin
        .execute(
            "UPDATE api_sessions SET created_at = now() - interval '12 hours', \
             last_seen_at = now(), expires_at = now() - interval '1 second' WHERE session_hash = $1",
            &[&hash],
        )
        .await
        .unwrap();
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/incidents",
        Some(&cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "expired");

    // --- Revoking the token ends its sessions ---
    let viewer_in = send(
        &app,
        Method::POST,
        "/api/v1/session",
        None,
        None,
        Some(json!({ "token": viewer })),
    )
    .await;
    let viewer_id_cookie = viewer_in.cookie.unwrap();
    let viewer_session = session_of(&viewer_id_cookie);
    secrets.push(viewer_session.clone());
    let viewer_cookie = format!("wnm_session={viewer_session}");
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/incidents",
        Some(&viewer_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    admin
        .execute(
            "UPDATE api_tokens SET revoked_at = now() WHERE token_id = $1::text::uuid",
            &[&viewer_id],
        )
        .await
        .unwrap();
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/incidents",
        Some(&viewer_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "revoked");

    // --- Signing in with a revoked or unknown token is refused ---
    for token in [
        viewer.clone(),
        format!("wnm_{}", "0".repeat(64)),
        "not-a-token".into(),
    ] {
        let reply = send(
            &app,
            Method::POST,
            "/api/v1/session",
            None,
            None,
            Some(json!({ "token": token })),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{token}");
        assert!(reply.cookie.is_none());
    }

    // --- Signing out needs the CSRF value, ends the session, clears it ---
    let fresh = send(
        &app,
        Method::POST,
        "/api/v1/session",
        None,
        None,
        Some(json!({ "token": senior })),
    )
    .await;
    let fresh_id = session_of(&fresh.cookie.unwrap());
    let fresh_csrf = fresh.body["csrf_token"].as_str().unwrap().to_string();
    secrets.extend([fresh_id.clone(), fresh_csrf.clone()]);
    let fresh_cookie = format!("wnm_session={fresh_id}");
    let reply = send(
        &app,
        Method::DELETE,
        "/api/v1/session",
        Some(&fresh_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = send(
        &app,
        Method::DELETE,
        "/api/v1/session",
        Some(&fresh_cookie),
        Some(&fresh_csrf),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.cookie.unwrap().contains("Max-Age=0"));
    let reply = send(
        &app,
        Method::GET,
        "/api/v1/incidents",
        Some(&fresh_cookie),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "signed out");
    let reply = send(&app, Method::GET, "/api/v1/session", None, None, None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    // --- A session is its token's tenant: another tenant's incident is 404 ---
    let (outsider, _) = token(&admin, "globex", Role::NocLead).await;
    secrets.push(outsider.clone());
    let theirs = send(
        &app,
        Method::POST,
        "/api/v1/session",
        None,
        None,
        Some(json!({ "token": outsider })),
    )
    .await;
    let theirs_id = session_of(&theirs.cookie.unwrap());
    secrets.push(theirs_id.clone());
    let reply = send(
        &app,
        Method::GET,
        &format!("/api/v1/incidents/{incident_id}"),
        Some(&format!("wnm_session={theirs_id}")),
        None,
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{}", reply.body);
    assert_eq!(reply.body["error"], "incident.not_found");

    // --- Audited, and nothing secret in any log line ---
    let audited: Vec<(String, String)> = admin
        .query(
            "SELECT action, result FROM incident_audit WHERE resource_type = 'session' ORDER BY audit_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let count = |action: &str| audited.iter().filter(|(a, _)| a == action).count();
    assert_eq!(count("session.create"), 4, "{audited:?}");
    assert_eq!(count("session.delete"), 1, "{audited:?}");
    assert_eq!(count("session.csrf_rejected"), 3, "{audited:?}");
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("a CSRF check failed"), "the capture works");
    for secret in &secrets {
        assert!(
            !logged.contains(secret.as_str()),
            "a secret reached the log"
        );
    }
}
