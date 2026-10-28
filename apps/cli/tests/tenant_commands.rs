//! `tenants` and `tokens`, and the tenant a request acts in, against a
//! stand-in API that records every request (ADR 0060).
//!
//! What the CLI owns, and these tests pin:
//! - `--tenant`, `TIDEGARD_TENANT` and nothing else send `Tidegard-Tenant`,
//!   the flag winning.
//! - A prefix is removed by its address and length as two path segments.
//! - Suspending a tenant and revoking a token ask first; with no terminal
//!   and no `--yes` that is an error and nothing is sent.
//! - An issued token's secret is printed once, with the warning.

use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use serde_json::{json, Value};
use tidegard_cli::config::{Environment, TENANT_VAR, TOKEN_VAR, URL_VAR};
use tidegard_cli::{exit, run_with, Io};

const TOKEN_ID: &str = "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d";
const NOW: i64 = 1_700_000_000_000_000;

#[derive(Debug, Clone)]
struct Sent {
    method: String,
    path: String,
    tenant: Option<String>,
    body: Value,
}

type Shared = Arc<Mutex<Vec<Sent>>>;

fn tenant(id: &str, status: &str) -> Value {
    json!({"tenant_id": id, "display_name": "Acme Networks", "status": status,
           "created_at": "2023-11-14T22:00:00Z", "updated_at": "2023-11-14T22:00:00Z"})
}

/// Answers every path the commands use, and records what was sent.
async fn answer(
    State(seen): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    seen.lock().unwrap().push(Sent {
        method: method.to_string(),
        path: path.clone(),
        tenant: headers
            .get("tidegard-tenant")
            .map(|v| v.to_str().unwrap().to_string()),
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    });
    let reply = match (method.as_str(), path.as_str()) {
        ("GET", "/api/v1/platform/tenants") => {
            json!({"tenants": [tenant("acme", "active"), tenant("globex", "suspended")]})
        }
        ("GET", "/api/v1/platform/tenants/acme") => {
            let mut one = tenant("acme", "active");
            one["prefixes"] = json!(["192.0.2.0/24", "2001:db8:a::/48"]);
            one
        }
        ("POST", "/api/v1/platform/tenants") => {
            return (StatusCode::CREATED, axum::Json(tenant("initech", "active"))).into_response()
        }
        ("POST", "/api/v1/platform/tenants/acme/suspend") => tenant("acme", "suspended"),
        ("POST", "/api/v1/platform/tenants/acme/prefixes") => {
            return (
                StatusCode::CONFLICT,
                [("content-type", "application/problem+json")],
                json!({"type": "x", "title": "Prefix overlaps a registered prefix",
                       "status": 409, "error": "tenant.prefix_overlap",
                       "detail": "192.0.2.128/25 overlaps 192.0.2.0/24, registered to tenant \"acme\""})
                .to_string(),
            )
                .into_response()
        }
        ("DELETE", _) => return StatusCode::NO_CONTENT.into_response(),
        ("GET", "/api/v1/tokens") => json!({"tokens": [{
            "token_id": TOKEN_ID, "actor_type": "operator", "actor_id": "dave",
            "role": "operator", "description": "", "created_at": "2023-11-14T22:00:00Z",
            "expires_at": "2024-02-12T22:00:00Z"}]}),
        ("POST", "/api/v1/tokens") => {
            return (
                StatusCode::CREATED,
                axum::Json(json!({"token_id": TOKEN_ID, "token": "wnm_secret",
                                  "expires_at": "2024-02-12T22:00:00Z"})),
            )
                .into_response()
        }
        ("POST", _) if path.ends_with("/revoke") => return StatusCode::NO_CONTENT.into_response(),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    axum::Json(reply).into_response()
}

async fn serve(seen: Shared) -> String {
    let app = Router::new().fallback(answer).with_state(seen);
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

async fn cli(url: &str, args: &[&str], tenant_env: Option<&str>, answer: Option<&str>) -> Outcome {
    let mut vars = vec![
        (URL_VAR, url.to_string()),
        (TOKEN_VAR, "wnm_test".to_string()),
    ];
    if let Some(tenant) = tenant_env {
        vars.push((TENANT_VAR, tenant.to_string()));
    }
    let env = TestEnvironment(vars);
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
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

fn last(seen: &Shared) -> Sent {
    seen.lock().unwrap().last().cloned().expect("a request")
}

#[tokio::test]
async fn the_tenant_acted_in_comes_from_the_flag_then_the_environment() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let done = cli(&url, &["tokens", "list"], None, None).await;
    assert_eq!(done.code, exit::SUCCESS, "{}", done.err);
    assert_eq!(last(&seen).tenant, None, "nothing named, nothing sent");
    assert!(done.out.starts_with("ID  "), "{}", done.out);
    assert!(done.out.contains("operator:dave"), "{}", done.out);
    assert!(done.out.contains("live"), "{}", done.out);

    cli(&url, &["tokens", "list"], Some("globex"), None).await;
    assert_eq!(last(&seen).tenant.as_deref(), Some("globex"));
    cli(
        &url,
        &["--tenant", "acme", "tokens", "list"],
        Some("globex"),
        None,
    )
    .await;
    assert_eq!(last(&seen).tenant.as_deref(), Some("acme"), "the flag wins");
    cli(&url, &["tokens", "list", "--tenant=initech"], None, None).await;
    assert_eq!(last(&seen).tenant.as_deref(), Some("initech"));
}

#[tokio::test]
async fn the_registry_commands_send_what_the_api_takes() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;

    let listed = cli(&url, &["tenants", "list"], None, None).await;
    assert_eq!(listed.code, exit::SUCCESS, "{}", listed.err);
    assert!(listed.out.starts_with("TENANT  STATUS"), "{}", listed.out);
    assert!(listed.out.contains("globex  suspended"), "{}", listed.out);

    let shown = cli(&url, &["tenants", "show", "acme"], None, None).await;
    assert!(
        shown
            .out
            .contains("Prefixes 192.0.2.0/24\n         2001:db8:a::/48"),
        "{}",
        shown.out
    );

    let created = cli(
        &url,
        &["tenants", "create", "initech", "--name", "Initech Ltd"],
        None,
        None,
    )
    .await;
    assert_eq!(created.code, exit::SUCCESS, "{}", created.err);
    let sent = last(&seen);
    assert_eq!(
        (sent.method.as_str(), sent.path.as_str()),
        ("POST", "/api/v1/platform/tenants")
    );
    assert_eq!(
        sent.body,
        json!({"tenant_id": "initech", "display_name": "Initech Ltd"})
    );

    let overlap = cli(
        &url,
        &["tenants", "prefix", "add", "acme", "192.0.2.128/25"],
        None,
        None,
    )
    .await;
    assert_eq!(overlap.code, exit::CONFLICT, "{}", overlap.err);
    assert!(
        overlap.err.contains("registered to tenant"),
        "{}",
        overlap.err
    );
    assert_eq!(last(&seen).body, json!({"prefix": "192.0.2.128/25"}));

    for (prefix, path) in [
        (
            "192.0.2.0/24",
            "/api/v1/platform/tenants/acme/prefixes/192.0.2.0/24",
        ),
        (
            "2001:db8:a::/48",
            "/api/v1/platform/tenants/acme/prefixes/2001%3Adb8%3Aa%3A%3A/48",
        ),
    ] {
        let removed = cli(
            &url,
            &["tenants", "prefix", "remove", "acme", prefix],
            None,
            None,
        )
        .await;
        assert_eq!(removed.code, exit::SUCCESS, "{}", removed.err);
        assert_eq!(removed.out, format!("{prefix} removed from acme\n"));
        let sent = last(&seen);
        assert_eq!(sent.method, "DELETE");
        assert_eq!(sent.path, path);
    }
    let not_a_prefix = cli(
        &url,
        &["tenants", "prefix", "remove", "acme", "192.0.2.0"],
        None,
        None,
    )
    .await;
    assert_eq!(not_a_prefix.code, exit::USAGE);
}

#[tokio::test]
async fn suspending_and_revoking_ask_first() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let before = seen.lock().unwrap().len();
    let refused = cli(&url, &["tenants", "suspend", "acme"], None, None).await;
    assert_eq!(refused.code, exit::USAGE, "{}", refused.err);
    assert!(refused.err.contains("--yes"), "{}", refused.err);
    let declined = cli(&url, &["tenants", "suspend", "acme"], None, Some("n\n")).await;
    assert_eq!(declined.code, exit::FAILURE);
    let revoke_refused = cli(&url, &["tokens", "revoke", TOKEN_ID], None, None).await;
    assert_eq!(revoke_refused.code, exit::USAGE);
    assert_eq!(seen.lock().unwrap().len(), before, "nothing was sent");

    let suspended = cli(&url, &["tenants", "suspend", "acme"], None, Some("y\n")).await;
    assert_eq!(suspended.code, exit::SUCCESS, "{}", suspended.err);
    assert!(
        suspended.out.contains("Status   suspended"),
        "{}",
        suspended.out
    );
    let revoked = cli(&url, &["tokens", "revoke", TOKEN_ID, "--yes"], None, None).await;
    assert_eq!(revoked.code, exit::SUCCESS, "{}", revoked.err);
    assert_eq!(revoked.out, format!("revoked {TOKEN_ID}\n"));
    assert_eq!(
        last(&seen).path,
        format!("/api/v1/tokens/{TOKEN_ID}/revoke")
    );
    let activated = cli(&url, &["tenants", "activate", "acme", "--yes"], None, None).await;
    assert_eq!(
        activated.code,
        exit::USAGE,
        "activating asks nothing, so --yes is refused"
    );
}

#[tokio::test]
async fn a_token_is_issued_once_with_its_warning() {
    let seen = Shared::default();
    let url = serve(seen.clone()).await;
    let issued = cli(
        &url,
        &[
            "--tenant",
            "acme",
            "tokens",
            "create",
            "--actor-id",
            "soar",
            "--role",
            "automation",
            "--actor-type",
            "service_account",
            "--days",
            "30",
        ],
        None,
        None,
    )
    .await;
    assert_eq!(issued.code, exit::SUCCESS, "{}", issued.err);
    assert!(
        issued.out.contains("token:      wnm_secret"),
        "{}",
        issued.out
    );
    assert!(issued.out.contains("not shown again"), "{}", issued.out);
    let sent = last(&seen);
    assert_eq!(sent.tenant.as_deref(), Some("acme"));
    assert_eq!(
        sent.body,
        json!({"actor_id": "soar", "role": "automation",
               "actor_type": "service_account", "lifetime_days": 30})
    );
    for args in [
        &["tokens", "create", "--role", "viewer"][..],
        &[
            "tokens",
            "create",
            "--actor-id",
            "x",
            "--role",
            "viewer",
            "--days",
            "soon",
        ],
        &["tokens", "revoke", "not-a-uuid"],
        &["tenants", "create"],
        &["tenants", "list", "--name", "x"],
    ] {
        let refused = cli(&url, args, None, None).await;
        assert_eq!(refused.code, exit::USAGE, "{args:?}: {}", refused.err);
    }
}
