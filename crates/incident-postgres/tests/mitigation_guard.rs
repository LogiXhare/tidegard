//! Phase 7B (ADR 0047): the safety guard decides at request, at approval
//! and when announcing begins, under the configuration in force at each
//! moment, and every refusal is audited and changes nothing.
//!
//! Needs `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`, an ephemeral database
//! this test wipes. Without it the test says why and passes; CI sets it and
//! fails on the skip message.

use std::sync::Arc;
use std::time::Duration;

use tokio_postgres::{Client, NoTls};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::mitigation::{MitigationStore, MitigationStoreError};
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

fn rtbh(prefix: &str) -> MitigationRequest {
    MitigationRequest {
        prefix: prefix.parse().unwrap(),
        action: Action::Rtbh,
        reason: "guard test".into(),
        duration: Duration::from_secs(600),
        incident_id: None,
    }
}

fn store(config: GuardConfig) -> MitigationStore {
    MitigationStore::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(Guard::new(config).unwrap()),
    )
}

fn allowing_acme() -> GuardConfig {
    GuardConfig {
        allowlist: vec![AllowlistEntry {
            prefix: "192.0.2.0/24".parse().unwrap(),
            tenant: "acme".into(),
            actions: vec![ActionKind::Rtbh],
        }],
        ..GuardConfig::default()
    }
}

fn refusal(result: Result<impl std::fmt::Debug, MitigationStoreError>) -> GuardRefusal {
    match result {
        Err(MitigationStoreError::Mitigation(MitigationError::Refused(refusal))) => refusal,
        other => panic!("expected a guard refusal, got {other:?}"),
    }
}

async fn denied(client: &Client, code: &str) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM incident_audit WHERE resource_type = 'mitigation' \
             AND result = 'denied' AND reason = $1",
            &[&code],
        )
        .await
        .unwrap()
        .get(0)
}

async fn state(
    store: &MitigationStore,
    client: &Client,
    id: &wetechinetmon_mitigation::MitigationId,
) -> MitigationState {
    store
        .get(client, &person("alice", "senior_operator"), id)
        .await
        .unwrap()
        .state
}

#[tokio::test]
async fn the_guard_decides_at_request_approval_and_announcing() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping mitigation_guard: {TEST_DATABASE_URL_VAR} is not set. This test requires a \
             real, ephemeral, local-or-CI-only PostgreSQL instance."
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

    let alice = person("alice", "senior_operator");
    let lead = person("lead", "noc_lead");
    let mitigator = AuthorizationContext::mitigator(TenantId::new("acme"), "mitigator-1");
    let open = store(allowing_acme());
    let switched_off = store(GuardConfig {
        kill_switch: true,
        ..allowing_acme()
    });
    let emptied = store(GuardConfig::default());

    // --- At request: outside the allowlist, nothing is written ---
    assert!(matches!(
        refusal(
            open.request(&mut client, &alice, rtbh("198.51.100.1/32"), None)
                .await
        ),
        GuardRefusal::NotAllowlisted(_)
    ));
    assert!(matches!(
        refusal(
            open.request(
                &mut client,
                &alice,
                MitigationRequest {
                    duration: Duration::from_secs(7200),
                    ..rtbh("192.0.2.1/32")
                },
                None
            )
            .await
        ),
        GuardRefusal::TooLong(3600)
    ));
    let none: i64 = client
        .query_one("SELECT count(*) FROM mitigations", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(none, 0);
    assert_eq!(denied(&client, "mitigation.not_allowlisted").await, 1);
    assert_eq!(denied(&client, "mitigation.too_long").await, 1);

    // --- At approval: the configuration in force now decides ---
    let first = open
        .request(&mut client, &alice, rtbh("192.0.2.1/32"), None)
        .await
        .unwrap();
    assert_eq!(
        refusal(switched_off.approve(&mut client, &lead, &first.id, 1).await),
        GuardRefusal::KillSwitch
    );
    assert!(matches!(
        refusal(emptied.approve(&mut client, &lead, &first.id, 1).await),
        GuardRefusal::NotAllowlisted(_)
    ));
    assert_eq!(
        state(&open, &client, &first.id).await,
        MitigationState::Requested
    );
    assert_eq!(denied(&client, "mitigation.kill_switch").await, 1);

    // --- When announcing begins, it decides once more ---
    open.approve(&mut client, &lead, &first.id, 1)
        .await
        .unwrap();
    assert_eq!(
        refusal(
            switched_off
                .begin_announcing(
                    &mut client,
                    &mitigator,
                    &first.id,
                    true,
                    &serde_json::json!({"lab": true})
                )
                .await
        ),
        GuardRefusal::KillSwitch
    );
    assert_eq!(
        state(&open, &client, &first.id).await,
        MitigationState::Approved
    );
    assert_eq!(denied(&client, "mitigation.kill_switch").await, 2);
    open.begin_announcing(
        &mut client,
        &mitigator,
        &first.id,
        true,
        &serde_json::json!({"lab": true}),
    )
    .await
    .unwrap();
    assert_eq!(
        state(&open, &client, &first.id).await,
        MitigationState::Announcing
    );

    // --- Taking a mitigation down is never refused by the guard ---
    switched_off
        .begin_withdrawal(
            &mut client,
            &mitigator,
            &first.id,
            wetechinetmon_mitigation::WithdrawalCause::KillSwitch,
        )
        .await
        .unwrap();
    switched_off
        .mark_withdrawn(&mut client, &mitigator, &first.id)
        .await
        .unwrap();
    assert_eq!(
        state(&open, &client, &first.id).await,
        MitigationState::Withdrawn
    );
}
