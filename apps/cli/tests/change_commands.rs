//! The commands that change an incident, against a stand-in API that
//! records every request.
//!
//! What the CLI owns, and these tests pin:
//! - The version is read before a change, unless `--expected-version` pins it.
//! - **One idempotency key per command, reused on every retry.**
//! - Close, reopen, suppress and lowering severity ask first. **With no
//!   terminal and no `--yes` that is an error and nothing is sent**, never
//!   an assumed yes.
//! - A `409` exits `4`, shows the current version and state, and is not
//!   re-issued.

use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use wetechinetmon_cli::config::{Environment, TOKEN_VAR, URL_VAR};
use wetechinetmon_cli::{exit, run_with, Io};
use wetechinetmon_common::rfc3339::rfc3339;

const ID: &str = "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";
const NOW: i64 = 1_700_000_000_000_000;

#[derive(Debug, Clone)]
struct Posted {
    action: String,
    key: Option<String>,
    body: Value,
}

#[derive(Default)]
struct Seen {
    reads: Mutex<usize>,
    posts: Mutex<Vec<Posted>>,
}

type Shared = Arc<Seen>;

fn incident(version: u64, state: &str) -> Value {
    json!({
        "incident_id": ID, "incident_number": "WNM-2026-000123", "title": "UDP flood",
        "state": state, "severity": "major", "priority": "P2", "version": version
    })
}

async fn read(State(seen): State<Shared>) -> Json<Value> {
    *seen.reads.lock().unwrap() += 1;
    Json(incident(3, "resolved"))
}

async fn act(
    State(seen): State<Shared>,
    UrlPath((_, action)): UrlPath<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let posted = Posted {
        action: action.clone(),
        key: headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_string()),
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    };
    let attempts = {
        let mut posts = seen.posts.lock().unwrap();
        posts.push(posted);
        posts.iter().filter(|p| p.action == action).count()
    };
    match action.as_str() {
        "investigate" => (
            StatusCode::CONFLICT,
            [("content-type", "application/problem+json")],
            json!({"type": "x", "title": "Version conflict", "status": 409,
                   "error": "incident.version_conflict", "expected_version": 3,
                   "current_version": 8, "current_state": "resolved"})
            .to_string(),
        )
            .into_response(),
        // The first attempt fails as an outage; the retry must carry the same key.
        "resolve" if attempts == 1 => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        "notes" => (StatusCode::CREATED, Json(incident(4, "resolved"))).into_response(),
        _ => Json(incident(4, "acknowledged")).into_response(),
    }
}

/// `.../notes/{index}/edit` and `.../redact`, recorded as
/// `notes/{index}/{action}`.
async fn act_on_note(
    State(seen): State<Shared>,
    UrlPath((_, index, action)): UrlPath<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    seen.posts.lock().unwrap().push(Posted {
        action: format!("notes/{index}/{action}"),
        key: headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_string()),
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    });
    Json(incident(4, "resolved")).into_response()
}

async fn serve(seen: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/incidents/{id}", get(read))
        .route("/api/v1/incidents/{id}/{action}", post(act))
        .route(
            "/api/v1/incidents/{id}/notes/{index}/{action}",
            post(act_on_note),
        )
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

fn posts(seen: &Shared, action: &str) -> Vec<Posted> {
    seen.posts
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.action == action)
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_change_reads_the_version_and_sends_one_key() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let done = cli(&url, &format!("incidents acknowledge {ID}"), None).await;
    assert_eq!(done.code, exit::SUCCESS, "{}", done.err);
    assert!(
        done.out
            .contains("WNM-2026-000123: acknowledge done; state acknowledged, version 4"),
        "{}",
        done.out
    );
    let sent = posts(&seen, "acknowledge");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].body, json!({"expected_version": 3}));
    assert!(sent[0].key.as_deref().unwrap().starts_with("wnmctl-"));
    assert_eq!(*seen.reads.lock().unwrap(), 1, "the version was read first");

    // Pinned: no read, and the pinned version is sent.
    let pinned = cli(
        &url,
        &format!("incidents unassign {ID} --expected-version 9"),
        None,
    )
    .await;
    assert_eq!(pinned.code, exit::SUCCESS, "{}", pinned.err);
    assert_eq!(
        posts(&seen, "unassign")[0].body,
        json!({"expected_version": 9})
    );
    assert_eq!(*seen.reads.lock().unwrap(), 1);

    // JSON output is the API's body, verbatim.
    let json_out = cli(&url, &format!("-o json incidents monitor {ID}"), None).await;
    let body: Value = serde_json::from_str(&json_out.out).unwrap();
    assert_eq!(body["version"], 4);
}

#[tokio::test]
async fn a_retry_reuses_the_key() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let done = cli(&url, &format!("incidents resolve {ID} --note ended"), None).await;
    assert_eq!(done.code, exit::SUCCESS, "{}", done.err);
    let sent = posts(&seen, "resolve");
    assert_eq!(sent.len(), 2, "one 503, then the retry");
    assert_eq!(sent[0].key, sent[1].key, "the same key on the retry");
    assert_eq!(
        sent[1].body,
        json!({"expected_version": 3, "resolution_note": "ended"})
    );

    let other = cli(&url, &format!("incidents acknowledge {ID}"), None).await;
    assert_eq!(other.code, exit::SUCCESS);
    assert_ne!(
        posts(&seen, "acknowledge")[0].key,
        sent[0].key,
        "a new command, a new key"
    );
}

#[tokio::test]
async fn a_conflict_exits_4_and_is_not_reissued() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let refused = cli(&url, &format!("incidents investigate {ID}"), None).await;
    assert_eq!(refused.code, exit::CONFLICT);
    assert!(
        refused.err.contains("incident.version_conflict"),
        "{}",
        refused.err
    );
    assert!(
        refused.err.contains("current version: 8"),
        "{}",
        refused.err
    );
    assert!(
        refused.err.contains("current state: resolved"),
        "{}",
        refused.err
    );
    assert!(
        refused.err.contains("wetechinetmonctl incidents show"),
        "{}",
        refused.err
    );
    assert_eq!(posts(&seen, "investigate").len(), 1, "never re-issued");
}

#[tokio::test]
async fn no_terminal_and_no_yes_is_an_error_never_an_assumed_yes() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    for line in [
        format!("incidents close {ID} --reason resolved"),
        format!("incidents reopen {ID} --reason recurred"),
        format!("incidents suppress {ID} --for 2h --reason backup"),
        format!("incidents severity set {ID} minor --reason subsided"),
    ] {
        let refused = cli(&url, &line, None).await;
        assert_eq!(refused.code, exit::USAGE, "{line}: {}", refused.err);
        assert!(refused.err.contains("--yes"), "{line}: {}", refused.err);
    }
    assert!(seen.posts.lock().unwrap().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn a_person_confirms_or_declines() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let declined = cli(
        &url,
        &format!("incidents close {ID} --reason resolved"),
        Some("n\n"),
    )
    .await;
    assert_eq!(declined.code, exit::FAILURE);
    assert!(
        declined
            .err
            .contains("Close WNM-2026-000123, now resolved as resolved? [y/N]"),
        "{}",
        declined.err
    );
    assert!(posts(&seen, "close").is_empty());

    let confirmed = cli(
        &url,
        &format!("incidents close {ID} --reason resolved"),
        Some("y\n"),
    )
    .await;
    assert_eq!(confirmed.code, exit::SUCCESS, "{}", confirmed.err);
    assert_eq!(
        posts(&seen, "close")[0].body,
        json!({"expected_version": 3, "closure_reason": "resolved"})
    );

    let in_advance = cli(
        &url,
        &format!("incidents reopen {ID} --reason recurred --yes"),
        None,
    )
    .await;
    assert_eq!(in_advance.code, exit::SUCCESS, "{}", in_advance.err);
}

#[tokio::test]
async fn only_lowering_severity_asks() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let raised = cli(&url, &format!("incidents severity set {ID} critical"), None).await;
    assert_eq!(
        raised.code,
        exit::SUCCESS,
        "raising needs no confirmation: {}",
        raised.err
    );
    assert_eq!(
        posts(&seen, "severity")[0].body,
        json!({"expected_version": 3, "severity": "critical"})
    );
}

#[tokio::test]
async fn suppression_and_notes_send_what_the_api_takes() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let suppressed = cli(
        &url,
        &format!("incidents suppress {ID} --for 2h --reason backup --yes"),
        None,
    )
    .await;
    assert_eq!(suppressed.code, exit::SUCCESS, "{}", suppressed.err);
    assert_eq!(
        posts(&seen, "suppress")[0].body,
        json!({"expected_version": 3, "reason": "backup",
               "expires_at": rfc3339(NOW + 7_200_000_000)})
    );
    let bad = cli(
        &url,
        &format!("incidents suppress {ID} --until tomorrow --reason r --yes"),
        None,
    )
    .await;
    assert_eq!(bad.code, exit::USAGE);

    let reads = *seen.reads.lock().unwrap();
    let noted = cli(
        &url,
        &format!("incidents note add {ID} --message spoofed"),
        None,
    )
    .await;
    assert_eq!(noted.code, exit::SUCCESS, "{}", noted.err);
    let note = &posts(&seen, "notes")[0];
    assert_eq!(
        note.body,
        json!({"body": "spoofed"}),
        "a note carries no version"
    );
    assert!(
        note.key.is_some(),
        "a key, so a retried note is not added twice"
    );
    assert_eq!(
        *seen.reads.lock().unwrap(),
        reads,
        "a note reads nothing first"
    );
}

#[tokio::test]
async fn note_edits_and_redactions_send_what_the_api_takes() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let reads = *seen.reads.lock().unwrap();
    let edited = cli(
        &url,
        &format!("incidents note edit {ID} 2 --message better"),
        None,
    )
    .await;
    assert_eq!(edited.code, exit::SUCCESS, "{}", edited.err);
    let edit = &posts(&seen, "notes/2/edit")[0];
    assert_eq!(edit.body, json!({"body": "better"}), "no version");
    assert!(edit.key.is_some(), "a retried edit is not applied twice");
    assert_eq!(
        *seen.reads.lock().unwrap(),
        reads,
        "an edit reads nothing first"
    );

    let line = format!("incidents note redact {ID} #1 --reason pasted-a-key");
    let refused = cli(&url, &line, None).await;
    assert_eq!(refused.code, exit::USAGE, "{}", refused.err);
    assert!(refused.err.contains("--yes"), "{}", refused.err);
    let declined = cli(&url, &line, Some("n\n")).await;
    assert_eq!(declined.code, exit::FAILURE);
    assert!(
        declined.err.contains("Redact note #1 on"),
        "{}",
        declined.err
    );
    assert!(
        posts(&seen, "notes/1/redact").is_empty(),
        "nothing was sent"
    );

    let redacted = cli(&url, &format!("{line} --yes"), None).await;
    assert_eq!(redacted.code, exit::SUCCESS, "{}", redacted.err);
    assert_eq!(
        posts(&seen, "notes/1/redact")[0].body,
        json!({"reason": "pasted-a-key"})
    );
}
