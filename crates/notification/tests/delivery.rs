//! Milestone 6E: the notifier against PostgreSQL and local mock channels
//! (ADR 0045). An ingested detection opens an incident; the notifier
//! delivers its `incident.opened` to Slack, Teams, Telegram and a signed
//! webhook, all mocked on loopback, so nothing leaves the machine. A
//! failing channel is retried alone, a destination off the allowlist is
//! refused, and every attempt is on the incident's timeline.
//!
//! Like the other PostgreSQL tests, this connects only to the opt-in,
//! throwaway database named by `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there.

#[path = "../../incident-postgres/tests/support/mod.rs"]
mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use serde_json::Value;
use support::{event, host_scope};
use wetechinetmon_detector::{EventKind, MetricKind, TestClock};
use wetechinetmon_incident::authorization::AuthorizationContext;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::outbox::{OutboxConsumer, OutboxPolicy};
use wetechinetmon_incident_postgres::pool::PoolPolicy;
use wetechinetmon_incident_postgres::service::IncidentPersistence;
use wetechinetmon_notification::config::parse_file;
use wetechinetmon_notification::hmac::signature;
use wetechinetmon_notification::metrics::NotifierMetrics;
use wetechinetmon_notification::worker::Notifier;

const TEST_DATABASE_URL_VAR: &str = "WETECHINETMON_INCIDENT_POSTGRES_TEST_URL";
const HOOK_SECRET: &str = "a-test-signing-secret";
const BOT_TOKEN: &str = "123456:test-token";

#[derive(Clone, Default)]
struct Mock {
    received: Arc<Mutex<Vec<(String, HeaderMap, Bytes)>>>,
    flaky_down: Arc<AtomicBool>,
}

async fn receive(
    State(mock): State<Mock>,
    Path(channel): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if channel == "flaky" && mock.flaky_down.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    mock.received.lock().unwrap().push((channel, headers, body));
    StatusCode::OK
}

async fn serve(mock: Mock) -> u16 {
    let app = Router::new()
        .route("/{channel}", post(receive))
        .route("/{bot}/{method}", post(telegram))
        .with_state(mock);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

async fn telegram(
    State(mock): State<Mock>,
    Path((bot, method)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    mock.received
        .lock()
        .unwrap()
        .push((format!("telegram:{bot}:{method}"), headers, body));
    StatusCode::OK
}

fn json(body: &Bytes) -> Value {
    serde_json::from_slice(body).unwrap()
}

#[tokio::test]
async fn the_notifier_delivers_retries_refuses_and_records() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping delivery: {TEST_DATABASE_URL_VAR} is not set. This test requires a real, \
             ephemeral, local-or-CI-only PostgreSQL instance."
        );
        return;
    };
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .unwrap();
    wetechinetmon_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .unwrap();

    // --- One incident, opened by a detection ---
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(TestClock::new()),
    );
    let scope = host_scope();
    let opened = service
        .ingest_detection_event(
            &mut client,
            &AuthorizationContext::correlator(TenantId::new(scope.tenant)),
            &event(&scope, 1, EventKind::Started, "p-notify", MetricKind::Bps),
        )
        .await
        .unwrap()
        .unwrap();
    let incident_id = opened.incident_id.unwrap().to_canonical_string();
    let version_before: i64 = client
        .query_one("SELECT version FROM incidents", &[])
        .await
        .unwrap()
        .get(0);

    // --- Channels, all on loopback ---
    let mock = Mock::default();
    mock.flaky_down.store(true, Ordering::SeqCst);
    let port = serve(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("wnm-notify-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = |name: &str, value: String| {
        let path = dir.join(name);
        std::fs::write(&path, value).unwrap();
        path.display().to_string().replace('\\', "/")
    };
    let slack = secret("slack", format!("http://127.0.0.1:{port}/slack"));
    let teams = secret("teams", format!("http://127.0.0.1:{port}/teams"));
    let flaky = secret("flaky", format!("http://127.0.0.1:{port}/flaky"));
    let hook = secret("hook", HOOK_SECRET.to_string());
    let bot = secret("bot", BOT_TOKEN.to_string());
    let file = parse_file(&format!(
        r#"{{
            "channels": {{
                "noc-slack": {{"kind": "slack", "url_file": "{slack}", "allow_private": true}},
                "noc-teams": {{"kind": "teams", "url_file": "{teams}", "allow_private": true}},
                "ops-hook": {{"kind": "webhook", "url": "http://127.0.0.1:{port}/hook", "secret_file": "{hook}", "allow_private": true}},
                "noc-tg": {{"kind": "telegram", "bot_token_file": "{bot}", "chat_id": "-1001", "api_base": "http://127.0.0.1:{port}", "allow_private": true}},
                "flaky": {{"kind": "slack", "url_file": "{flaky}", "allow_private": true}},
                "outsider": {{"kind": "webhook", "url": "http://localhost:{port}/hook", "secret_file": "{hook}", "allow_private": true}}
            }},
            "routes": [{{"tenant": "{tenant}", "events": ["incident.opened"], "min_severity": "minor",
                         "channels": ["noc-slack", "noc-teams", "ops-hook", "noc-tg", "flaky", "outsider"]}}],
            "allowed_hosts": ["127.0.0.1"],
            "ca_file": "/nonexistent/unused-for-http.pem",
            "ui_base_url": "https://noc.example.net"
        }}"#,
        tenant = scope.tenant
    ))
    .unwrap();

    let (pool, _) = wetechinetmon_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();
    let platform = wetechinetmon_notification::platform_authority();
    let policy = OutboxPolicy {
        lease: Duration::from_secs(30),
        ..OutboxPolicy::default()
    };
    let (metrics, _) = NotifierMetrics::new().unwrap();
    let mut notifier = Notifier::new(
        "notifier-test".into(),
        OutboxConsumer::new(&platform, "notifier-test", policy),
        IncidentPersistence::new(
            Arc::new(UuidV7IncidentGenerator::new()),
            Arc::new(TestClock::new()),
        ),
        file,
        Duration::from_secs(300),
        metrics,
    )
    .unwrap();

    // --- First pass: four delivered, one failing, one refused ---
    let report = notifier.run_once(&pool).await.unwrap();
    assert_eq!(report.delivered, 4, "{report:?}");
    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(
        report.refused, 1,
        "localhost is not on the allowlist: {report:?}"
    );
    assert_eq!(
        report.retrying, 1,
        "the message waits for the flaky channel"
    );

    let received = mock.received.lock().unwrap().clone();
    let by = |name: &str| {
        received
            .iter()
            .find(|(channel, _, _)| channel.starts_with(name))
            .unwrap_or_else(|| panic!("no {name} delivery"))
            .clone()
    };
    let (_, _, slack_body) = by("slack");
    let text = json(&slack_body)["text"].as_str().unwrap().to_string();
    assert!(text.contains("opened"), "{text}");
    assert!(text.contains("Mitigation: none"), "{text}");
    assert!(text.contains(&format!("https://noc.example.net/incidents/{incident_id}")));
    let (_, _, teams_body) = by("teams");
    assert_eq!(
        json(&teams_body)["attachments"][0]["contentType"],
        "application/vnd.microsoft.card.adaptive"
    );
    let (path, _, telegram_body) = by("telegram:");
    assert_eq!(path, format!("telegram:bot{BOT_TOKEN}:sendMessage"));
    let telegram = json(&telegram_body);
    assert_eq!(telegram["chat_id"], "-1001");
    assert!(telegram.get("parse_mode").is_none());
    let (_, hook_headers, hook_body) = by("hook");
    let timestamp: u64 = hook_headers["x-wnm-timestamp"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        hook_headers["x-wnm-signature"].to_str().unwrap(),
        signature(HOOK_SECRET.as_bytes(), timestamp, &hook_body),
        "the receiver can verify the body"
    );
    let hook = json(&hook_body);
    assert_eq!(hook["mitigation_status"], "none");
    assert_eq!(hook["incident"]["incident_id"], incident_id.as_str());
    for (_, headers, body) in &received {
        let all = format!("{headers:?}{}", String::from_utf8_lossy(body));
        assert!(!all.contains(HOOK_SECRET), "a secret was sent");
    }

    // --- The retry goes to the failed channel only, then publishes ---
    mock.flaky_down.store(false, Ordering::SeqCst);
    client
        .execute(
            "UPDATE incident_outbox SET available_at = now() WHERE status = 'retrying'",
            &[],
        )
        .await
        .unwrap();
    let before = mock.received.lock().unwrap().len();
    let report = notifier.run_once(&pool).await.unwrap();
    assert_eq!(report.delivered, 1, "{report:?}");
    assert_eq!(report.published, 1, "{report:?}");
    let after = mock.received.lock().unwrap().clone();
    assert_eq!(after.len(), before + 1, "nothing was sent twice");
    assert_eq!(after.last().unwrap().0, "flaky");
    let status: String = client
        .query_one(
            "SELECT status FROM incident_outbox WHERE event_type = 'incident.opened'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "published");

    // --- Every attempt is on the timeline, and the version never moved ---
    let outcomes: Vec<String> = client
        .query(
            "SELECT payload::text FROM incident_timeline              WHERE entry_type = 'notification_result' ORDER BY timeline_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    let count = |outcome: &str| {
        outcomes
            .iter()
            .filter(|payload| payload.contains(&format!("\"{outcome}\"")))
            .count()
    };
    assert_eq!(outcomes.len(), 7, "{outcomes:?}");
    assert_eq!(count("delivered"), 5, "{outcomes:?}");
    assert_eq!(count("failed"), 1, "{outcomes:?}");
    assert_eq!(count("refused"), 1, "{outcomes:?}");
    let version: i64 = client
        .query_one("SELECT version FROM incidents", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        version, version_before,
        "a notification record bumps no version"
    );

    // --- Nothing more to do ---
    let report = notifier.run_once(&pool).await.unwrap();
    assert_eq!(report.claimed, 0);
    std::fs::remove_dir_all(dir).unwrap();
}
