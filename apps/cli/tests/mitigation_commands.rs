//! `mitigations`, `kill-switch` and `bgp`, against a stand-in API that
//! records every request (ADR 0050).
//!
//! What the CLI owns, and these tests pin:
//! - A request carries no route attribute and one idempotency key, and
//!   an incident number is resolved to its id first.
//! - **Approving, withdrawing and engaging the kill switch ask first.**
//!   With no terminal and no `--yes` that is an error and nothing is sent.
//! - The version is read before a decision unless `--expected-version`
//!   pins it; a `409` exits `4` and is not re-issued.
//! - An old peer snapshot is called out, never shown as a live session.

use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, RawQuery, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tidegard_cli::config::{Environment, TOKEN_VAR, URL_VAR};
use tidegard_cli::{exit, run_with, Io};

const MITIGATION: &str = "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";
/// The stand-in answers 409 to any decision on this one.
const CONTESTED: &str = "0192f3c4-8a7b-7e1f-9c2d-000000000409";
const INCIDENT: &str = "0192f3c4-0000-7e1f-9c2d-3e4f5a6b7c8d";
const NOW: i64 = 1_700_000_000_000_000; // 2023-11-14T22:13:20Z

#[derive(Debug, Clone)]
struct Sent {
    method: String,
    path: String,
    query: Option<String>,
    key: Option<String>,
    body: Value,
}

#[derive(Default)]
struct Seen {
    sent: Mutex<Vec<Sent>>,
}

type Shared = Arc<Seen>;

fn mitigation(state: &str, version: u64) -> Value {
    json!({
        "mitigation_id": MITIGATION, "tenant_id": "acme", "incident_id": null,
        "prefix": "203.0.113.9/32", "action": "rtbh", "flow": null,
        "bytes_per_second": null, "reason": "udp flood", "duration_seconds": 1800,
        "state": state, "version": version, "requested_by": "operator:u_1",
        "approved_by": null, "dry_run": null, "withdrawal_cause": null,
        "last_error": null, "created_at": "2023-11-14T22:07:20Z",
        "updated_at": "2023-11-14T22:07:20Z", "approved_at": null,
        "active_since": null, "expires_at": null, "ended_at": null, "route": null
    })
}

fn record(
    seen: &Shared,
    method: Method,
    path: String,
    query: Option<String>,
    headers: &HeaderMap,
    body: &Bytes,
) {
    seen.sent.lock().unwrap().push(Sent {
        method: method.to_string(),
        path,
        query,
        key: headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_string()),
        body: serde_json::from_slice(body).unwrap_or(Value::Null),
    });
}

async fn list(State(seen): State<Shared>, RawQuery(query): RawQuery) -> Json<Value> {
    record(
        &seen,
        Method::GET,
        "mitigations".into(),
        query,
        &HeaderMap::new(),
        &Bytes::new(),
    );
    Json(json!({"items": [mitigation("requested", 1)]}))
}

async fn request(State(seen): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    record(
        &seen,
        Method::POST,
        "mitigations".into(),
        None,
        &headers,
        &body,
    );
    (StatusCode::CREATED, Json(mitigation("requested", 1))).into_response()
}

async fn read(State(seen): State<Shared>, UrlPath(id): UrlPath<String>) -> Json<Value> {
    record(
        &seen,
        Method::GET,
        format!("mitigations/{id}"),
        None,
        &HeaderMap::new(),
        &Bytes::new(),
    );
    Json(mitigation("requested", 3))
}

async fn decide(
    State(seen): State<Shared>,
    UrlPath((id, verb)): UrlPath<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    record(
        &seen,
        Method::POST,
        format!("mitigations/{id}/{verb}"),
        None,
        &headers,
        &body,
    );
    if id == CONTESTED {
        return (
            StatusCode::CONFLICT,
            [("content-type", "application/problem+json")],
            json!({"type": "x", "title": "Version conflict", "status": 409,
                   "error": "mitigation.version_conflict", "expected_version": 3,
                   "current_version": 5})
            .to_string(),
        )
            .into_response();
    }
    Json(mitigation("approved", 4)).into_response()
}

async fn kill_switch(
    State(seen): State<Shared>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    record(&seen, method, "kill-switch".into(), None, &headers, &body);
    Json(
        json!({"engaged": true, "version": 2, "changed_at": "2023-11-14T22:13:00Z",
                "changed_by": "operator:lead", "reason": "storm"}),
    )
}

async fn incidents(State(seen): State<Shared>, RawQuery(query): RawQuery) -> Json<Value> {
    record(
        &seen,
        Method::GET,
        "incidents".into(),
        query,
        &HeaderMap::new(),
        &Bytes::new(),
    );
    Json(json!({"items": [{"incident_id": INCIDENT}]}))
}

async fn peers() -> Json<Value> {
    // Seen an hour ago: the mitigator has stopped.
    Json(
        json!({"items": [{"neighbor_address": "192.0.2.254", "peer_asn": 64512,
                           "session_state": "established",
                           "updated_at": "2023-11-14T21:13:20Z"}]}),
    )
}

async fn routes() -> Json<Value> {
    Json(
        json!({"items": [{"mitigation_id": MITIGATION, "state": "active",
                           "prefix": "203.0.113.9/32", "action": "rtbh",
                           "route": {"next_hop": "192.0.2.1"}, "expires_at": null}]}),
    )
}

async fn serve(seen: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/mitigations", get(list).post(request))
        .route("/api/v1/mitigations/{id}", get(read))
        .route("/api/v1/mitigations/{id}/{verb}", post(decide))
        .route(
            "/api/v1/mitigation-controls/kill-switch",
            get(kill_switch).put(kill_switch),
        )
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/bgp/peers", get(peers))
        .route("/api/v1/bgp/routes", get(routes))
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

/// Runs `line`. `answer` is what a person at a terminal types; `None` is
/// no terminal at all.
async fn cli(url: &str, line: &str, answer: Option<&str>) -> Outcome {
    let env = TestEnvironment(vec![
        (URL_VAR, url.to_string()),
        (TOKEN_VAR, "wnm_test".to_string()),
    ]);
    let args: Vec<String> = line.split_whitespace().map(String::from).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut terminal = answer.map(|text| Cursor::new(text.as_bytes().to_vec()));
    let mut io = Io {
        out: &mut out,
        err: &mut err,
        input: terminal
            .as_mut()
            .map(|cursor| cursor as &mut dyn std::io::BufRead),
        now_micros: NOW,
    };
    let code = run_with(&args, &env, &mut io, |client| client.without_backoff()).await;
    Outcome {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

fn sent(seen: &Shared, method: &str, path: &str) -> Vec<Sent> {
    seen.sent
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.method == method && s.path == path)
        .cloned()
        .collect()
}

#[tokio::test]
async fn reads_list_show_and_pass_filters_through() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let listed = cli(&url, "mitigations list --live --limit 5", None).await;
    assert_eq!(listed.code, exit::SUCCESS, "{}", listed.err);
    assert!(listed.out.starts_with("ID  "), "{}", listed.out);
    assert!(listed.out.contains(MITIGATION), "{}", listed.out);
    assert_eq!(
        sent(&seen, "GET", "mitigations")[0].query.as_deref(),
        Some("live=true&limit=5")
    );

    let shown = cli(&url, &format!("mitigations show {MITIGATION}"), None).await;
    assert_eq!(shown.code, exit::SUCCESS, "{}", shown.err);
    assert!(
        shown.out.contains("State         requested"),
        "{}",
        shown.out
    );

    let json_out = cli(&url, "-o json bgp routes", None).await;
    let body: Value = serde_json::from_str(&json_out.out).unwrap();
    assert_eq!(body["items"][0]["prefix"], "203.0.113.9/32");
    let table = cli(&url, "bgp routes", None).await;
    assert!(
        table.out.contains("203.0.113.9/32  rtbh    active"),
        "{}",
        table.out
    );
}

#[tokio::test]
async fn a_request_resolves_the_incident_and_carries_one_key() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let done = cli(
        &url,
        "mitigations request --prefix 203.0.113.9/32 --action flowspec_rate_limit \
         --reason flood --for 30m --incident WNM-2026-000123 --protocol 17 \
         --destination-port 53 --rate 125000",
        None,
    )
    .await;
    assert_eq!(done.code, exit::SUCCESS, "{}", done.err);
    assert!(done.out.contains("must approve it"), "{}", done.out);
    assert_eq!(
        sent(&seen, "GET", "incidents")[0].query.as_deref(),
        Some("incident_number=WNM-2026-000123&limit=1")
    );
    let posted = sent(&seen, "POST", "mitigations");
    assert_eq!(posted.len(), 1);
    assert_eq!(
        posted[0].body,
        json!({
            "prefix": "203.0.113.9/32", "action": "flowspec_rate_limit",
            "reason": "flood", "duration_seconds": 1800, "incident_id": INCIDENT,
            "bytes_per_second": 125000,
            "flow": {"protocol": 17, "destination_port": 53}
        })
    );
    assert!(posted[0].key.as_deref().unwrap().starts_with("wnmctl-"));
}

#[tokio::test]
async fn approving_asks_first_and_never_assumes_yes() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let approve = format!("mitigations approve {MITIGATION}");
    let path = format!("mitigations/{MITIGATION}/approve");

    let refused = cli(&url, &approve, None).await;
    assert_eq!(refused.code, exit::USAGE, "{}", refused.err);
    assert!(refused
        .err
        .contains("mitigations approve asks for confirmation"));
    assert!(sent(&seen, "POST", &path).is_empty(), "nothing was sent");

    let declined = cli(&url, &approve, Some("n\n")).await;
    assert_eq!(declined.code, exit::FAILURE);
    assert!(
        declined.err.contains("Approve rtbh of 203.0.113.9/32"),
        "{}",
        declined.err
    );
    assert!(
        declined.err.contains("requested by operator:u_1"),
        "{}",
        declined.err
    );
    assert!(sent(&seen, "POST", &path).is_empty(), "nothing was sent");

    let approved = cli(&url, &approve, Some("y\n")).await;
    assert_eq!(approved.code, exit::SUCCESS, "{}", approved.err);
    assert!(
        approved
            .out
            .contains("approve done; state approved, version 4"),
        "{}",
        approved.out
    );
    let posts = sent(&seen, "POST", &path);
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0].body,
        json!({"expected_version": 3}),
        "the version was read"
    );
}

#[tokio::test]
async fn decisions_pin_versions_and_report_conflicts() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;

    // Pinned and confirmed in advance: no read at all.
    let withdrawn = cli(
        &url,
        &format!("mitigations withdraw {MITIGATION} --reason over --expected-version 7 --yes"),
        None,
    )
    .await;
    assert_eq!(withdrawn.code, exit::SUCCESS, "{}", withdrawn.err);
    assert!(sent(&seen, "GET", &format!("mitigations/{MITIGATION}")).is_empty());
    assert_eq!(
        sent(&seen, "POST", &format!("mitigations/{MITIGATION}/withdraw"))[0].body,
        json!({"expected_version": 7, "reason": "over"})
    );

    // Rejecting does not ask: nothing is announced either way.
    let rejected = cli(
        &url,
        &format!("mitigations reject {MITIGATION} --reason dup"),
        None,
    )
    .await;
    assert_eq!(rejected.code, exit::SUCCESS, "{}", rejected.err);
    assert_eq!(
        sent(&seen, "POST", &format!("mitigations/{MITIGATION}/reject"))[0].body,
        json!({"expected_version": 3, "reason": "dup"})
    );

    let conflict = cli(
        &url,
        &format!("mitigations approve {CONTESTED} --yes"),
        None,
    )
    .await;
    assert_eq!(conflict.code, exit::CONFLICT);
    assert!(
        conflict.err.contains("current version: 5"),
        "{}",
        conflict.err
    );
    assert!(
        conflict.err.contains("mitigations show"),
        "{}",
        conflict.err
    );
    assert_eq!(
        sent(&seen, "POST", &format!("mitigations/{CONTESTED}/approve")).len(),
        1,
        "a conflict is not re-issued"
    );
}

#[tokio::test]
async fn the_kill_switch_engages_only_when_confirmed() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let refused = cli(&url, "kill-switch engage --reason storm", None).await;
    assert_eq!(refused.code, exit::USAGE);
    assert!(
        sent(&seen, "PUT", "kill-switch").is_empty(),
        "nothing was sent"
    );

    let engaged = cli(&url, "kill-switch engage --reason storm", Some("yes\n")).await;
    assert_eq!(engaged.code, exit::SUCCESS, "{}", engaged.err);
    assert!(engaged.out.contains("ENGAGED"), "{}", engaged.out);
    assert_eq!(
        sent(&seen, "PUT", "kill-switch")[0].body,
        json!({"engaged": true, "reason": "storm"})
    );

    let release = cli(&url, "kill-switch release --reason over", None).await;
    assert_eq!(release.code, exit::USAGE);
    assert!(release.err.contains("host-only"), "{}", release.err);
    assert_eq!(
        sent(&seen, "PUT", "kill-switch").len(),
        1,
        "release sent nothing"
    );
}

#[tokio::test]
async fn an_old_peer_snapshot_is_called_out() {
    let seen = Shared::default();
    let url = serve(seen).await;
    let peers = cli(&url, "bgp peers", None).await;
    assert_eq!(peers.code, exit::SUCCESS, "{}", peers.err);
    assert!(
        peers.out.contains("192.0.2.254  64512  established  1h"),
        "{}",
        peers.out
    );
    assert!(peers.err.contains("may have stopped"), "{}", peers.err);
    let json_out = cli(&url, "-o json bgp peers", None).await;
    assert!(
        json_out.err.is_empty(),
        "JSON output stays clean: {}",
        json_out.err
    );
}
