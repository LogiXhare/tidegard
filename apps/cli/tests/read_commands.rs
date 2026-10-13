//! The read commands end to end against a stand-in API on loopback.
//!
//! The stand-in answers like the real API, so these tests cover what the
//! CLI owns: the request it sends, number resolution, `--output json`
//! printing the body verbatim, an exit code per error class, and retries
//! only where they are safe. The real API's behaviour is covered by its
//! own PostgreSQL tests.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use tidegard_cli::config::{Environment, TOKEN_VAR, URL_VAR};
use tidegard_cli::{exit, run_with, Io};

const ID: &str = "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";
const NUMBER: &str = "WNM-2026-000123";
const TOKEN: &str = "wnm_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NOW: i64 = 1_700_000_000_000_000;

#[derive(Default)]
struct Seen {
    authorizations: Mutex<Vec<String>>,
    flaky_calls: AtomicUsize,
    broken_calls: AtomicUsize,
}

type Shared = Arc<Seen>;

fn problem(status: StatusCode, code: &str) -> Response {
    (
        status,
        [("content-type", "application/problem+json")],
        json!({"type": "x", "title": code, "status": status.as_u16(), "error": code}).to_string(),
    )
        .into_response()
}

fn incident() -> Value {
    json!({
        "incident_id": ID, "incident_number": NUMBER, "title": "UDP flood",
        "state": "open", "severity": "major", "priority": "P2", "category": "udp_flood",
        "direction": "incoming", "address_family": 4, "target_type": "host",
        "target_id": "203.0.113.7", "opened_at": "2023-11-14T22:07:20Z",
        "last_detected_at": "2023-11-14T22:13:00Z", "version": 3,
        "assigned_user_id": null, "assigned_team_id": null, "tags": {}
    })
}

async fn list(
    State(seen): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<Vec<(String, String)>>,
) -> Response {
    if let Some(value) = headers.get("authorization") {
        seen.authorizations
            .lock()
            .unwrap()
            .push(value.to_str().unwrap().to_string());
    }
    let number = query.iter().find(|(k, _)| k == "incident_number");
    let items = match number {
        Some((_, n)) if n == NUMBER => vec![incident()],
        Some(_) => vec![],
        None => vec![incident()],
    };
    Json(json!({"items": items, "next_cursor": null, "has_more": false, "total": null}))
        .into_response()
}

async fn show(axum::extract::Path(id): axum::extract::Path<String>) -> Response {
    if id == ID {
        Json(incident()).into_response()
    } else {
        problem(StatusCode::NOT_FOUND, "incident.not_found")
    }
}

/// 503 twice, then an answer: a retry must get through.
async fn flaky(State(seen): State<Shared>) -> Response {
    if seen.flaky_calls.fetch_add(1, Ordering::SeqCst) < 2 {
        problem(StatusCode::SERVICE_UNAVAILABLE, "api.unavailable")
    } else {
        Json(json!({"items": [], "next_cursor": null, "has_more": false})).into_response()
    }
}

/// Always 503.
async fn broken(State(seen): State<Shared>) -> Response {
    seen.broken_calls.fetch_add(1, Ordering::SeqCst);
    problem(StatusCode::SERVICE_UNAVAILABLE, "api.unavailable")
}

async fn forbidden() -> Response {
    problem(StatusCode::FORBIDDEN, "incident.forbidden")
}

async fn limited() -> Response {
    problem(StatusCode::TOO_MANY_REQUESTS, "api.rate_limited")
}

async fn serve(seen: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/incidents", get(list))
        .route("/api/v1/incidents/{id}", get(show))
        .route("/api/v1/incidents/{id}/timeline", get(flaky))
        .route("/api/v1/incidents/{id}/detections", get(broken))
        .route("/api/v1/incidents/{id}/audit", get(forbidden))
        .route("/api/v1/incidents/{id}/notes", get(limited))
        .with_state(seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

struct TestEnvironment(Vec<(&'static str, String)>);

impl Environment for TestEnvironment {
    fn var(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    }

    fn read_file(&self, _: &Path) -> std::io::Result<String> {
        Err(std::io::ErrorKind::NotFound.into())
    }
}

struct Outcome {
    code: i32,
    out: String,
    err: String,
}

async fn cli(url: &str, line: &str) -> Outcome {
    let env = TestEnvironment(vec![
        (URL_VAR, url.to_string()),
        (TOKEN_VAR, TOKEN.to_string()),
    ]);
    let args: Vec<String> = line.split_whitespace().map(String::from).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut io = Io {
        out: &mut out,
        err: &mut err,
        input: None,
        now_micros: NOW,
    };
    let code = run_with(&args, &env, &mut io, |client| client.without_backoff()).await;
    Outcome {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

#[tokio::test]
async fn reads_print_tables_and_json_verbatim() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;

    let listed = cli(&url, "incidents list --state open").await;
    assert_eq!(listed.code, exit::SUCCESS, "{}", listed.err);
    assert!(listed.out.starts_with("NUMBER"), "{}", listed.out);
    assert!(
        listed.out.contains("WNM-2026-000123  major"),
        "{}",
        listed.out
    );

    let json = cli(&url, "incidents list -o json").await;
    let body: Value = serde_json::from_str(&json.out).unwrap();
    assert_eq!(
        body["items"][0]["incident_id"], ID,
        "the API's body, unchanged"
    );

    let authorizations = seen.authorizations.lock().unwrap().clone();
    assert!(authorizations
        .iter()
        .all(|a| a == &format!("Bearer {TOKEN}")));
    assert!(!listed.out.contains(TOKEN) && !listed.err.contains(TOKEN));
}

#[tokio::test]
async fn an_incident_number_is_resolved_in_the_tenant() {
    let url = serve(Shared::default()).await;
    let shown = cli(&url, &format!("incidents show {NUMBER}")).await;
    assert_eq!(shown.code, exit::SUCCESS, "{}", shown.err);
    assert!(shown.out.contains("Title"), "{}", shown.out);
    assert!(shown.out.contains(ID), "{}", shown.out);

    let missing = cli(&url, "incidents show WNM-2026-999999").await;
    assert_eq!(missing.code, exit::NOT_FOUND);
    assert!(
        missing.err.contains("no incident numbered"),
        "{}",
        missing.err
    );

    let unknown_id = cli(&url, "incidents show 0192f3c4-0000-7e1f-9c2d-3e4f5a6b7c8d").await;
    assert_eq!(unknown_id.code, exit::NOT_FOUND);
    assert!(
        unknown_id.err.contains("incident.not_found"),
        "{}",
        unknown_id.err
    );

    let hostile = cli(&url, "incidents show WNM;rm").await;
    assert_eq!(hostile.code, exit::USAGE, "refused before any request");
}

#[tokio::test]
async fn every_error_class_has_its_exit_code() {
    let url = serve(Shared::default()).await;
    let forbidden = cli(&url, &format!("incidents audit {ID}")).await;
    assert_eq!(forbidden.code, exit::AUTH);
    let limited = cli(&url, &format!("incidents note list {ID}")).await;
    assert_eq!(limited.code, exit::RATE_LIMITED);
    let json = cli(&url, &format!("incidents audit {ID} -o json")).await;
    let document: Value = serde_json::from_str(&json.out).unwrap();
    assert_eq!(
        document["error"], "incident.forbidden",
        "the problem document, verbatim"
    );
    let usage = cli(&url, "incidents list --bogus").await;
    assert_eq!(usage.code, exit::USAGE);
    let token_flag = cli(&url, "incidents list --token wnm_x").await;
    assert_eq!(token_flag.code, exit::USAGE);
}

#[tokio::test]
async fn retries_only_where_safe_and_give_up_with_7() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let flaky = cli(&url, &format!("incidents timeline {ID}")).await;
    assert_eq!(flaky.code, exit::SUCCESS, "{}", flaky.err);
    assert_eq!(
        seen.flaky_calls.load(Ordering::SeqCst),
        3,
        "two 503s, then the answer"
    );

    let broken = cli(&url, &format!("incidents detections {ID}")).await;
    assert_eq!(broken.code, exit::UNAVAILABLE);
    assert_eq!(
        seen.broken_calls.load(Ordering::SeqCst),
        3,
        "at most three attempts"
    );

    let refused = cli(&url, &format!("incidents audit {ID}")).await;
    assert_eq!(refused.code, exit::AUTH, "a 4xx is never retried");
}

#[tokio::test]
async fn nothing_listening_is_unavailable() {
    // Bind and drop, so the port is closed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let outcome = cli(&url, "incidents list").await;
    assert_eq!(outcome.code, exit::UNAVAILABLE, "{}", outcome.err);
}
