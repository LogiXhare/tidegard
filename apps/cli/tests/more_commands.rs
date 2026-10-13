//! `claim`, `open`, `export` and tags, against a stand-in API that
//! records every request.

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::{json, Value};
use tidegard_cli::config::{Environment, TOKEN_VAR, URL_VAR};
use tidegard_cli::{exit, run_with, Io};

const ID: &str = "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";
const NOW: i64 = 1_700_000_000_000_000;

#[derive(Debug, Clone)]
struct Seen {
    method: Method,
    path: String,
    key: Option<String>,
    body: Value,
}

type Shared = Arc<Mutex<Vec<Seen>>>;

fn incident() -> Value {
    json!({"incident_id": ID, "incident_number": "WNM-2026-000123", "state": "open",
           "severity": "major", "version": 3, "tags": {}})
}

async fn whoami(headers: HeaderMap) -> Json<Value> {
    let bearer = headers["authorization"].to_str().unwrap();
    if bearer.contains("svc") {
        Json(json!({"tenant_id": "acme", "actor_type": "service_account", "actor_id": "ci"}))
    } else {
        Json(json!({"tenant_id": "acme", "actor_type": "operator", "actor_id": "u_4821"}))
    }
}

async fn anything(
    State(seen): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        key: headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_string()),
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    });
    if path.ends_with("/export") {
        return (
            StatusCode::OK,
            json!({"format": "tidegard.incident-export", "incident": incident()}).to_string(),
        )
            .into_response();
    }
    if method == Method::POST && path == "/api/v1/incidents" {
        return (StatusCode::CREATED, Json(incident())).into_response();
    }
    Json(incident()).into_response()
}

async fn serve(seen: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/whoami", get(whoami))
        .fallback(any(anything))
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

async fn cli_as(url: &str, token: &str, args: &[&str]) -> Outcome {
    let env = TestEnvironment(vec![
        (URL_VAR, url.to_string()),
        (TOKEN_VAR, token.to_string()),
    ]);
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
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

async fn cli(url: &str, line: &str) -> Outcome {
    let args: Vec<&str> = line.split_whitespace().collect();
    cli_as(url, "wnm_operator", &args).await
}

fn requests(seen: &Shared, method: Method, suffix: &str) -> Vec<Seen> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|s| s.method == method && s.path.ends_with(suffix))
        .cloned()
        .collect()
}

#[tokio::test]
async fn claim_assigns_to_the_caller_and_only_an_operator() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let claimed = cli(&url, &format!("incidents claim {ID}")).await;
    assert_eq!(claimed.code, exit::SUCCESS, "{}", claimed.err);
    let sent = requests(&seen, Method::POST, "/assign");
    assert_eq!(
        sent[0].body,
        json!({"expected_version": 3, "user_id": "u_4821"})
    );

    let service = cli_as(&url, "wnm_svc", &["incidents", "claim", ID]).await;
    assert_eq!(service.code, exit::USAGE);
    assert!(service.err.contains("assign --user"), "{}", service.err);
    assert_eq!(
        requests(&seen, Method::POST, "/assign").len(),
        1,
        "nothing more was sent"
    );
}

#[tokio::test]
async fn open_sends_the_request_with_a_key() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let opened = cli_as(
        &url,
        "wnm_operator",
        &[
            "incidents",
            "open",
            "--title",
            "Transit reports spoofing",
            "--severity",
            "major",
            "--target-scope",
            "host",
            "--target",
            "203.0.113.5",
            "--direction",
            "incoming",
        ],
    )
    .await;
    assert_eq!(opened.code, exit::SUCCESS, "{}", opened.err);
    assert!(
        opened.out.contains("Opened WNM-2026-000123"),
        "{}",
        opened.out
    );
    let sent = &requests(&seen, Method::POST, "/api/v1/incidents")[0];
    assert_eq!(
        sent.body,
        json!({"title": "Transit reports spoofing", "severity": "major", "target_scope": "host",
               "target": "203.0.113.5", "direction": "incoming"})
    );
    assert!(sent.key.is_some());
}

#[tokio::test]
async fn export_writes_a_new_file_and_never_overwrites() {
    let url = serve(Shared::default()).await;
    let printed = cli(&url, &format!("incidents export {ID}")).await;
    assert_eq!(printed.code, exit::SUCCESS, "{}", printed.err);
    let document: Value = serde_json::from_str(&printed.out).unwrap();
    assert_eq!(document["format"], "tidegard.incident-export");

    let path = std::env::temp_dir().join(format!("wnmctl-export-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let file = path.to_str().unwrap();
    let written = cli_as(
        &url,
        "wnm_operator",
        &["incidents", "export", ID, "--file", file],
    )
    .await;
    assert_eq!(written.code, exit::SUCCESS, "{}", written.err);
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved, document);

    std::fs::write(&path, "keep me").unwrap();
    let again = cli_as(
        &url,
        "wnm_operator",
        &["incidents", "export", ID, "--file", file],
    )
    .await;
    assert_eq!(again.code, exit::USAGE);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "keep me",
        "never overwritten"
    );
    std::fs::remove_file(&path).unwrap();
}

#[tokio::test]
async fn tags_are_put_and_deleted() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let set = cli(&url, &format!("incidents tag set {ID} env prod")).await;
    assert_eq!(set.code, exit::SUCCESS, "{}", set.err);
    assert!(set.out.contains("tag env set"), "{}", set.out);
    let put = &requests(&seen, Method::PUT, "/tags/env")[0];
    assert_eq!(put.body, json!({"value": "prod"}));
    assert!(put.key.is_some());

    let removed = cli(&url, &format!("incidents tag remove {ID} env")).await;
    assert_eq!(removed.code, exit::SUCCESS, "{}", removed.err);
    assert_eq!(requests(&seen, Method::DELETE, "/tags/env").len(), 1);
}
