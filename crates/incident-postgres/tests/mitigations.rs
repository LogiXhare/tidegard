//! Phase 7A (ADR 0046): mitigations persist atomically, refuse duplicates
//! and lost updates, replay retries, and audit refusals, against a real
//! PostgreSQL.
//!
//! Needs `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`, an ephemeral database
//! this test wipes. Without it the test says why and passes; CI sets it and
//! fails on the skip message.

use std::sync::Arc;
use std::time::Duration;

use tokio_postgres::{Client, NoTls};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, Permission, PermissionResolver,
};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::mitigation::{MitigationStore, MitigationStoreError};
use wetechinetmon_mitigation::guard::AllowlistEntry;
use wetechinetmon_mitigation::{
    Action, ActionKind, FlowMatch, Guard, GuardConfig, MitigationError, MitigationRequest,
    MitigationState, WithdrawalCause,
};

const TEST_DATABASE_URL_VAR: &str = "WETECHINETMON_INCIDENT_POSTGRES_TEST_URL";
const INCIDENT: &str = "01900000-0000-7000-8000-0000000000AA";

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

fn person(tenant: &str, id: &str, role: &str) -> AuthorizationContext {
    AuthorizationContext::new(
        TenantId::new(tenant),
        Actor::Operator { id: id.into() },
        FixedBundleResolver.permissions_for(role),
    )
}

fn rtbh(host: &str) -> MitigationRequest {
    MitigationRequest {
        prefix: format!("{host}/32").parse().unwrap(),
        action: Action::Rtbh,
        reason: "UDP flood toward a customer host".into(),
        duration: Duration::from_secs(600),
        incident_id: Some(INCIDENT.into()),
    }
}

fn mitigation_error(result: Result<impl std::fmt::Debug, MitigationStoreError>) -> MitigationError {
    match result {
        Err(MitigationStoreError::Mitigation(error)) => error,
        other => panic!("expected a mitigation error, got {other:?}"),
    }
}

async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn mitigations_persist_atomically_refuse_duplicates_and_replay_retries() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping mitigations: {TEST_DATABASE_URL_VAR} is not set. This test requires a real, \
             ephemeral, local-or-CI-only PostgreSQL instance."
        );
        return;
    };
    let mut client = connect(&url).await;
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .unwrap();
    wetechinetmon_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .unwrap();

    // acme may mitigate its own 192.0.2.0/24; the guard has its own suite.
    let guard = Guard::new(GuardConfig {
        allowlist: vec![AllowlistEntry {
            prefix: "192.0.2.0/24".parse().unwrap(),
            tenant: "acme".into(),
            actions: vec![ActionKind::Rtbh, ActionKind::FlowspecDiscard],
        }],
        ..GuardConfig::default()
    })
    .unwrap();
    let store = MitigationStore::new(Arc::new(UuidV7IncidentGenerator::new()), Arc::new(guard));
    let alice = person("acme", "alice", "senior_operator");
    let lead = person("acme", "lead", "noc_lead");
    let outsider = person("other", "lead", "noc_lead");
    let mitigator = AuthorizationContext::mitigator(TenantId::new("acme"), "mitigator-1");

    // --- A request writes the record, its history, audit and outbox ---
    let key = "request-0001-retry-safe";
    let first = store
        .request(&mut client, &alice, rtbh("192.0.2.10"), Some(key))
        .await
        .unwrap();
    assert_eq!(first.state, MitigationState::Requested);
    assert_eq!(first.version, 1);
    assert_eq!(
        first.incident_id.as_deref(),
        Some(&*INCIDENT.to_lowercase())
    );
    assert_eq!(
        count(&client, "SELECT count(*) FROM mitigation_history").await,
        1
    );
    assert_eq!(
        count(
            &client,
            "SELECT count(*) FROM incident_outbox \
             WHERE aggregate_type = 'mitigation' AND event_type = 'mitigation.requested'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &client,
            "SELECT count(*) FROM incident_audit WHERE resource_type = 'mitigation' \
             AND action = 'mitigation.request' AND result = 'allowed'"
        )
        .await,
        1
    );

    // --- A retry replays; the same key for another request is refused ---
    let replay = store
        .request(&mut client, &alice, rtbh("192.0.2.10"), Some(key))
        .await
        .unwrap();
    assert_eq!(replay, first);
    assert_eq!(count(&client, "SELECT count(*) FROM mitigations").await, 1);
    assert!(matches!(
        store
            .request(&mut client, &alice, rtbh("192.0.2.11"), Some(key))
            .await,
        Err(MitigationStoreError::IdempotencyMismatch)
    ));

    // --- Duplicate-action protection, sequential and concurrent ---
    assert_eq!(
        mitigation_error(
            store
                .request(&mut client, &alice, rtbh("192.0.2.10"), None)
                .await
        ),
        MitigationError::Duplicate
    );
    let flowspec = MitigationRequest {
        action: Action::FlowspecDiscard(FlowMatch {
            protocol: Some(17),
            source_port: Some(53),
            ..FlowMatch::default()
        }),
        ..rtbh("192.0.2.10")
    };
    let other_action = store
        .request(&mut client, &alice, flowspec, None)
        .await
        .unwrap();
    store
        .reject(&mut client, &lead, &other_action.id, 1, "not needed")
        .await
        .unwrap();

    let (mut one, mut two) = (connect(&url).await, connect(&url).await);
    let (a, b) = tokio::join!(
        store.request(&mut one, &alice, rtbh("192.0.2.20"), None),
        store.request(&mut two, &alice, rtbh("192.0.2.20"), None),
    );
    let outcomes = [a.is_ok(), b.is_ok()];
    assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1, "{a:?} {b:?}");
    let loser = if a.is_ok() { b } else { a };
    assert_eq!(mitigation_error(loser), MitigationError::Duplicate);

    // --- Another tenant sees nothing ---
    assert_eq!(
        mitigation_error(store.get(&client, &outsider, &first.id).await),
        MitigationError::NotFound
    );
    assert_eq!(
        mitigation_error(store.approve(&mut client, &outsider, &first.id, 1).await),
        MitigationError::NotFound
    );
    assert!(store.list(&client, &outsider, 50).await.unwrap().is_empty());

    // --- Refusals change nothing and are audited ---
    assert_eq!(
        mitigation_error(store.approve(&mut client, &alice, &first.id, 1).await),
        MitigationError::Forbidden(Permission::MitigationApprove)
    );
    assert_eq!(
        mitigation_error(
            store
                .begin_announcing(
                    &mut client,
                    &lead,
                    &first.id,
                    false,
                    &serde_json::json!({"lab": true})
                )
                .await
        ),
        MitigationError::Forbidden(Permission::MitigationExecute)
    );
    assert_eq!(
        count(
            &client,
            "SELECT count(*) FROM incident_audit WHERE resource_type = 'mitigation' \
             AND result = 'denied'"
        )
        .await,
        2
    );
    assert_eq!(
        mitigation_error(store.approve(&mut client, &lead, &first.id, 7).await),
        MitigationError::VersionConflict(1)
    );
    assert_eq!(
        store.get(&client, &alice, &first.id).await.unwrap().version,
        1,
        "nothing moved"
    );

    // --- Approval, then the mitigator's steps to withdrawn ---
    let approved = store
        .approve(&mut client, &lead, &first.id, 1)
        .await
        .unwrap();
    assert_eq!(approved.state, MitigationState::Approved);
    assert_eq!(approved.approved_by, Some(lead.actor().clone()));
    store
        .begin_announcing(
            &mut client,
            &mitigator,
            &first.id,
            true,
            &serde_json::json!({"lab": true}),
        )
        .await
        .unwrap();
    store
        .mark_active(&mut client, &mitigator, &first.id)
        .await
        .unwrap();
    let window: i64 = client
        .query_one(
            "SELECT extract(epoch FROM expires_at - active_since)::bigint FROM mitigations \
             WHERE mitigation_id = $1::text::uuid",
            &[&first.id.as_str()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(window, 600, "the duration runs from activation");
    store
        .begin_withdrawal(
            &mut client,
            &mitigator,
            &first.id,
            WithdrawalCause::DurationReached,
        )
        .await
        .unwrap();
    let ended = store
        .mark_withdrawn(&mut client, &mitigator, &first.id)
        .await
        .unwrap();
    assert_eq!(ended.state, MitigationState::Withdrawn);
    assert_eq!(ended.version, 6);
    assert_eq!(ended.dry_run, Some(true));
    assert_eq!(ended.withdrawal, Some(WithdrawalCause::DurationReached));
    let events: Vec<String> = client
        .query(
            "SELECT event_type FROM incident_outbox WHERE aggregate_id = $1 ORDER BY outbox_id",
            &[&first.id.as_str()],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        events,
        [
            "mitigation.requested",
            "mitigation.approved",
            "mitigation.announcing",
            "mitigation.active",
            "mitigation.withdrawing",
            "mitigation.withdrawn"
        ]
    );
    let history: Vec<(i64, Option<String>, String)> = client
        .query(
            "SELECT version, from_state, to_state FROM mitigation_history \
             WHERE mitigation_id = $1::text::uuid ORDER BY version",
            &[&first.id.as_str()],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(history.len(), 6);
    assert_eq!(history[0], (1, None, "requested".to_string()));
    assert_eq!(
        history[5],
        (6, Some("withdrawing".into()), "withdrawn".to_string())
    );
    let ended_at_set = count(
        &client,
        "SELECT count(*) FROM mitigations WHERE state = 'withdrawn' AND ended_at IS NOT NULL",
    )
    .await;
    assert_eq!(ended_at_set, 1);

    // --- Once ended, the same mitigation may be requested again ---
    let again = store
        .request(&mut client, &alice, rtbh("192.0.2.10"), None)
        .await
        .unwrap();
    assert_eq!(again.state, MitigationState::Requested);

    // --- Nobody approves their own ---
    let own = store
        .request(&mut client, &lead, rtbh("192.0.2.30"), None)
        .await
        .unwrap();
    assert_eq!(
        mitigation_error(store.approve(&mut client, &lead, &own.id, 1).await),
        MitigationError::SelfApproval
    );

    // --- The schema refuses what the domain refuses ---
    let broad = client
        .execute(
            "INSERT INTO mitigations (mitigation_id, tenant_id, prefix, action, reason, \
             duration_seconds, state, version, duplicate_key, requested_by_type, requested_by) \
             VALUES ('01900000-0000-7000-8000-0000000000ff', 'acme', '198.51.100.0/24', 'rtbh', \
             'x', 600, 'requested', 1, 'k', 'operator', 'mallory')",
            &[],
        )
        .await;
    assert!(broad.is_err(), "an RTBH wider than a host route is refused");
    let host_bits = client.execute("SELECT '192.0.2.1/24'::cidr", &[]).await;
    assert!(host_bits.is_err(), "CIDR refuses bits below the length");

    // --- The tenant's list, newest first ---
    let listed = store.list(&client, &alice, 50).await.unwrap();
    assert_eq!(listed.len(), 5);
    assert_eq!(listed[0].id, own.id);
    assert!(listed.iter().all(|m| m.tenant.as_str() == "acme"));
}
