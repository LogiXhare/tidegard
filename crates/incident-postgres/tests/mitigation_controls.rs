//! Phase 7D (ADR 0049): the runtime kill switch, the mitigator's work list
//! and the incidents it may propose for, against a real PostgreSQL.
//!
//! Needs `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`, an ephemeral database
//! this test wipes. Without it the test says why and passes; CI sets it and
//! fails on the skip message.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{event, host_scope};
use tokio_postgres::{Client, NoTls};
use wetechinetmon_detector::{EventKind, MetricKind, TestClock};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, Permission, PermissionResolver,
};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::mitigation::{MitigationStore, MitigationStoreError};
use wetechinetmon_incident_postgres::platform::PlatformAuthority;
use wetechinetmon_incident_postgres::service::IncidentPersistence;
use wetechinetmon_mitigation::guard::AllowlistEntry;
use wetechinetmon_mitigation::{
    Action, ActionKind, Guard, GuardConfig, GuardRefusal, MitigationError, MitigationRequest,
    MitigationState,
};

const TEST_DATABASE_URL_VAR: &str = "WETECHINETMON_INCIDENT_POSTGRES_TEST_URL";

fn person(id: &str, role: &str) -> AuthorizationContext {
    AuthorizationContext::new(
        TenantId::new("acme"),
        Actor::Operator { id: id.into() },
        FixedBundleResolver.permissions_for(role),
    )
}

fn rtbh(host: &str) -> MitigationRequest {
    MitigationRequest {
        prefix: format!("{host}/32").parse().unwrap(),
        action: Action::Rtbh,
        reason: "controls test".into(),
        duration: Duration::from_secs(600),
        incident_id: None,
    }
}

fn platform() -> PlatformAuthority {
    PlatformAuthority::from_context(&AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Platform {
            id: "mitigator".into(),
        },
        vec![Permission::PlatformIncidentAdmin],
    ))
    .unwrap()
}

async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn the_kill_switch_work_list_and_candidates_behave() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping mitigation_controls: {TEST_DATABASE_URL_VAR} is not set. This test requires \
             a real, ephemeral, local-or-CI-only PostgreSQL instance."
        );
        return;
    };
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
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

    let store = MitigationStore::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(
            Guard::new(GuardConfig {
                approval_window_seconds: 600,
                allowlist: vec![AllowlistEntry {
                    prefix: "203.0.113.0/24".parse().unwrap(),
                    tenant: "acme".into(),
                    actions: vec![ActionKind::Rtbh],
                }],
                ..GuardConfig::default()
            })
            .unwrap(),
        ),
    );
    let senior = person("alice", "senior_operator");
    let lead = person("lead", "noc_lead");
    let admin = person("root", "platform_admin");
    let mitigator = AuthorizationContext::mitigator(TenantId::new("acme"), "mitigator-1");

    // --- Off by default; a senior operator cannot turn it on ---
    assert!(!store.kill_switch(&client).await.unwrap().engaged);
    assert!(matches!(
        store
            .set_kill_switch(&mut client, &senior, true, "panic")
            .await,
        Err(MitigationStoreError::Mitigation(
            MitigationError::Forbidden(Permission::MitigationKillSwitchEngage)
        ))
    ));
    assert_eq!(
        count(
            &client,
            "SELECT count(*) FROM incident_audit WHERE resource_type = 'mitigation_controls' \
             AND result = 'denied'"
        )
        .await,
        1
    );

    // --- A lead turns it on; it is audited, emitted, and refuses requests ---
    let on = store
        .set_kill_switch(&mut client, &lead, true, "route leak suspected")
        .await
        .unwrap();
    assert!(on.engaged);
    assert_eq!(on.version, 2);
    assert_eq!(on.changed_by, Some(lead.actor().clone()));
    let again = store
        .set_kill_switch(&mut client, &lead, true, "again")
        .await
        .unwrap();
    assert_eq!(again.version, 2, "turning it on twice changes nothing");
    assert_eq!(
        count(
            &client,
            "SELECT count(*) FROM incident_outbox WHERE aggregate_type = 'mitigation_controls' \
             AND event_type = 'mitigation.kill_switch_engaged'"
        )
        .await,
        1
    );
    assert!(matches!(
        store
            .request(&mut client, &senior, rtbh("203.0.113.5"), None)
            .await,
        Err(MitigationStoreError::Mitigation(MitigationError::Refused(
            GuardRefusal::KillSwitch
        )))
    ));

    // --- Only a platform administrator turns it off ---
    assert!(matches!(
        store
            .set_kill_switch(&mut client, &lead, false, "all clear")
            .await,
        Err(MitigationStoreError::Mitigation(
            MitigationError::Forbidden(Permission::MitigationKillSwitchRelease)
        ))
    ));
    let off = store
        .set_kill_switch(&mut client, &admin, false, "all clear")
        .await
        .unwrap();
    assert!(!off.engaged);
    assert_eq!(off.version, 3);

    // --- The work list: an expired request, a due active one ---
    let waiting = store
        .request(&mut client, &senior, rtbh("203.0.113.5"), None)
        .await
        .unwrap();
    let running = store
        .request(&mut client, &senior, rtbh("203.0.113.6"), None)
        .await
        .unwrap();
    store
        .approve(&mut client, &lead, &running.id, 1)
        .await
        .unwrap();
    store
        .begin_announcing(
            &mut client,
            &mitigator,
            &running.id,
            true,
            &serde_json::json!({"nlri": "203.0.113.6/32"}),
        )
        .await
        .unwrap();
    store
        .mark_active(&mut client, &mitigator, &running.id)
        .await
        .unwrap();
    let route: String = client
        .query_one(
            "SELECT route::text FROM mitigations WHERE mitigation_id = $1::text::uuid",
            &[&running.id.as_str()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(route.contains("203.0.113.6/32"), "the route is recorded");

    let work = store.work(&platform(), &client, 100).await.unwrap();
    assert_eq!(work.len(), 2);
    assert!(work
        .iter()
        .all(|w| !w.approval_expired && !w.duration_reached));
    client
        .batch_execute(&format!(
            "UPDATE mitigations SET created_at = created_at - interval '11 minutes' \
             WHERE mitigation_id = '{}';
             UPDATE mitigations SET expires_at = transaction_timestamp() - interval '1 second' \
             WHERE mitigation_id = '{}';",
            waiting.id, running.id
        ))
        .await
        .unwrap();
    let work = store.work(&platform(), &client, 100).await.unwrap();
    let find = |id| work.iter().find(|w| w.record.id == id).unwrap();
    assert!(find(waiting.id.clone()).approval_expired);
    assert!(find(running.id.clone()).duration_reached);
    assert_eq!(
        find(running.id.clone()).record.state,
        MitigationState::Active
    );

    // --- Proposal candidates: an incoming attack on a host, unmitigated ---
    let scope = host_scope();
    IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(TestClock::new()),
    )
    .ingest_detection_event(
        &mut client,
        &AuthorizationContext::correlator(TenantId::new(scope.tenant)),
        &event(&scope, 1, EventKind::Started, "p-propose", MetricKind::Bps),
    )
    .await
    .unwrap()
    .unwrap();
    client
        .batch_execute("UPDATE incidents SET opened_at = transaction_timestamp()")
        .await
        .unwrap();
    let severities = vec!["major".to_string(), "critical".to_string()];
    let candidates = store
        .proposal_candidates(
            &platform(),
            &client,
            &severities,
            Duration::from_secs(600),
            10,
        )
        .await
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].target.to_string(), "203.0.113.90/32");
    assert_eq!(candidates[0].tenant.as_str(), "acme");
    let none = store
        .proposal_candidates(
            &platform(),
            &client,
            &["critical".to_string()],
            Duration::from_secs(600),
            10,
        )
        .await
        .unwrap();
    assert!(none.is_empty(), "below the severity");

    // Once a mitigation answers it, it is no longer a candidate.
    store
        .propose(
            &mut client,
            &mitigator,
            MitigationRequest {
                incident_id: Some(candidates[0].incident_id.clone()),
                ..rtbh("203.0.113.90")
            },
        )
        .await
        .unwrap();
    let after = store
        .proposal_candidates(
            &platform(),
            &client,
            &severities,
            Duration::from_secs(600),
            10,
        )
        .await
        .unwrap();
    assert!(after.is_empty());
}
