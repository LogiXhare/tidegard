//! Phase 7E-4 (ADR 0050): the notifier tells of mitigations, the kill
//! switch and BGP sessions, against PostgreSQL and local mock channels.
//!
//! A mitigation requested for an incident reaches Slack and a signed
//! webhook and is recorded on that incident's timeline; the kill switch
//! reaches the webhook; a BGP session that goes down is told under the
//! `platform` tenant; and an incident message now says where its
//! mitigation stands. Nothing leaves the machine.
//!
//! Needs `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`, an ephemeral database
//! this test wipes. Without it the test says why and passes; CI sets it and
//! fails on the skip message.

#[path = "../../incident-postgres/tests/support/mod.rs"]
mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use serde_json::Value;
use support::{event, host_scope};
use wetechinetmon_detector::{EventKind, MetricKind, TestClock};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::mitigation::{MitigationStore, PEER_EVENT_TENANT};
use wetechinetmon_incident_postgres::outbox::{OutboxConsumer, OutboxPolicy};
use wetechinetmon_incident_postgres::pool::PoolPolicy;
use wetechinetmon_incident_postgres::service::IncidentPersistence;
use wetechinetmon_mitigation::guard::AllowlistEntry;
use wetechinetmon_mitigation::{Action, ActionKind, Guard, GuardConfig, MitigationRequest};
use wetechinetmon_notification::config::parse_file;
use wetechinetmon_notification::metrics::NotifierMetrics;
use wetechinetmon_notification::worker::Notifier;

const TEST_DATABASE_URL_VAR: &str = "WETECHINETMON_INCIDENT_POSTGRES_TEST_URL";

type Received = Arc<Mutex<Vec<(String, Value)>>>;

async fn receive(
    State(received): State<Received>,
    Path(channel): Path<String>,
    body: Bytes,
) -> StatusCode {
    received
        .lock()
        .unwrap()
        .push((channel, serde_json::from_slice(&body).unwrap()));
    StatusCode::OK
}

async fn serve(received: Received) -> u16 {
    let app = Router::new()
        .route("/{channel}", post(receive))
        .with_state(received);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

fn person(tenant: &str, id: &str, role: &str) -> AuthorizationContext {
    AuthorizationContext::new(
        TenantId::new(tenant),
        Actor::Operator { id: id.into() },
        FixedBundleResolver.permissions_for(role),
    )
}

#[tokio::test]
async fn mitigations_the_kill_switch_and_peers_are_told() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping mitigation_notices: {TEST_DATABASE_URL_VAR} is not set. This test requires \
             a real, ephemeral, local-or-CI-only PostgreSQL instance."
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

    // --- An incident, and a mitigation requested for it ---
    let scope = host_scope();
    let tenant = scope.tenant;
    let incidents = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(TestClock::new()),
    );
    let opened = incidents
        .ingest_detection_event(
            &mut client,
            &AuthorizationContext::correlator(TenantId::new(tenant)),
            &event(&scope, 1, EventKind::Started, "p-mitigate", MetricKind::Bps),
        )
        .await
        .unwrap()
        .unwrap();
    let incident_id = opened.incident_id.unwrap().to_canonical_string();
    let store = MitigationStore::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(
            Guard::new(GuardConfig {
                allowlist: vec![AllowlistEntry {
                    prefix: "203.0.113.0/24".parse().unwrap(),
                    tenant: tenant.into(),
                    actions: vec![ActionKind::Rtbh],
                }],
                ..GuardConfig::default()
            })
            .unwrap(),
        ),
    );
    store
        .request(
            &mut client,
            &person(tenant, "alice", "senior_operator"),
            MitigationRequest {
                prefix: "203.0.113.90/32".parse().unwrap(),
                action: Action::Rtbh,
                reason: "<!channel> UDP flood".into(),
                duration: Duration::from_secs(600),
                incident_id: Some(incident_id.clone()),
            },
            Some("notify-request-0001"),
        )
        .await
        .unwrap();
    store
        .set_kill_switch(
            &mut client,
            &person(tenant, "lead", "noc_lead"),
            true,
            "route leak suspected",
        )
        .await
        .unwrap();

    // --- A BGP session goes down between two snapshots ---
    let platform = wetechinetmon_notification::platform_authority();
    let first = store
        .record_peers(
            &platform,
            &mut client,
            &[("192.0.2.254".into(), 64512, "established")],
        )
        .await
        .unwrap();
    assert!(
        first.is_empty(),
        "a peer seen for the first time is not news"
    );
    let second = store
        .record_peers(
            &platform,
            &mut client,
            &[("192.0.2.254".into(), 64512, "idle")],
        )
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].event_type, "bgp.peer_down");

    // --- Channels on loopback; routes by tenant and event ---
    let received = Received::default();
    let port = serve(received.clone()).await;
    let dir = std::env::temp_dir().join(format!("wnm-mitigation-notices-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = dir.join("hook");
    std::fs::write(&secret, "a-test-signing-secret").unwrap();
    let secret = secret.display().to_string().replace('\\', "/");
    let config = format!(
        r#"{{
            "channels": {{
                "noc-slack": {{"kind": "slack", "url": "http://127.0.0.1:{port}/slack", "allow_private": true}},
                "ops-hook": {{"kind": "webhook", "url": "http://127.0.0.1:{port}/hook", "secret_file": "{secret}", "allow_private": true}}
            }},
            "routes": [
                {{"tenant": "{tenant}", "events": ["mitigation.requested"], "min_severity": "major",
                  "channels": ["noc-slack", "ops-hook"]}},
                {{"tenant": "{tenant}", "events": ["mitigation.kill_switch_engaged", "incident.opened"],
                  "channels": ["ops-hook"]}},
                {{"tenant": "{PEER_EVENT_TENANT}", "events": ["bgp.peer_down"], "min_severity": "critical",
                  "channels": ["ops-hook"]}}
            ],
            "allowed_hosts": ["127.0.0.1"],
            "ca_file": "/nonexistent/unused-for-http.pem",
            "ui_base_url": "https://noc.example.net"
        }}"#
    );
    let (pool, _) = wetechinetmon_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();
    let (metrics, _) = NotifierMetrics::new().unwrap();
    let mut notifier = Notifier::new(
        "notifier-test".into(),
        OutboxConsumer::new(
            &platform,
            "notifier-test",
            OutboxPolicy {
                lease: Duration::from_secs(30),
                ..OutboxPolicy::default()
            },
        ),
        IncidentPersistence::new(
            Arc::new(UuidV7IncidentGenerator::new()),
            Arc::new(TestClock::new()),
        ),
        parse_file(&config).unwrap(),
        Duration::from_secs(300),
        metrics,
    )
    .unwrap();

    let mut delivered = 0;
    for _ in 0..5 {
        let report = notifier.run_once(&pool).await.unwrap();
        delivered += report.delivered;
        if report.claimed == 0 {
            break;
        }
    }
    assert_eq!(
        delivered, 5,
        "requested to two channels; the kill switch, the peer and the incident to one"
    );

    let received = received.lock().unwrap().clone();
    let hooks: Vec<&Value> = received
        .iter()
        .filter(|(channel, _)| channel == "hook")
        .map(|(_, body)| body)
        .collect();
    let hook = |event: &str| {
        *hooks
            .iter()
            .find(|body| body["event_type"] == event)
            .unwrap_or_else(|| panic!("no {event} webhook in {hooks:?}"))
    };

    // The request: who must act, on what, with hostile text neutralised.
    let (_, slack) = received
        .iter()
        .find(|(channel, _)| channel == "slack")
        .unwrap();
    let text = slack["text"].as_str().unwrap();
    assert!(
        text.starts_with("[MITIGATION] Approval needed: rtbh of 203.0.113.90/32"),
        "{text}"
    );
    assert!(text.contains("&lt;!channel&gt; UDP flood"), "{text}");
    assert!(
        text.contains("https://noc.example.net/mitigations"),
        "{text}"
    );
    let requested = hook("mitigation.requested");
    assert_eq!(requested["mitigation"]["incident_id"], incident_id.as_str());
    assert!(requested["mitigation"].get("next_hop").is_none());

    // The kill switch, and the peer under the platform tenant.
    assert_eq!(
        hook("mitigation.kill_switch_engaged")["kill_switch"]["reason"],
        "route leak suspected"
    );
    let down = hook("bgp.peer_down");
    assert_eq!(down["tenant"], PEER_EVENT_TENANT);
    assert_eq!(down["bgp_peer"]["neighbor_address"], "192.0.2.254");
    assert_eq!(down["bgp_peer"]["session_state"], "idle");

    // The incident's message says where its mitigation stands (FU-64).
    assert_eq!(
        hook("incident.opened")["mitigation_status"],
        "pending_approval"
    );

    // The request's deliveries are on the incident's timeline.
    let recorded: Vec<String> = client
        .query(
            "SELECT payload::text FROM incident_timeline WHERE entry_type = 'notification_result' \
             AND payload::text LIKE '%mitigation.requested%'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(recorded.len(), 2, "{recorded:?}");

    // Every message was published; nothing waits.
    let waiting: i64 = client
        .query_one(
            "SELECT count(*) FROM incident_outbox WHERE status <> 'published'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(waiting, 0);
    std::fs::remove_dir_all(dir).unwrap();
}
