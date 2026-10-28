//! Phase 7D (ADR 0049): the mitigator against a real PostgreSQL and a real
//! `gobgpd`. Announcing, the duration, operator withdrawal, the kill
//! switch, restart reconciliation, dry-run, BGP off, approval expiry, a
//! guard refusal at the last moment, and proposals.
//!
//! Needs `TIDEGARD_INCIDENT_POSTGRES_TEST_URL` (an ephemeral database
//! this test wipes) and `TIDEGARD_GOBGP_TEST_ENDPOINT` (a throwaway
//! `gobgpd` on loopback). Without them the test says why and passes; CI
//! sets both and fails on the skip message. Only documentation prefixes
//! and private ASNs are used.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use tidegard_detector::{
    ActionTaken, AddressFamily, DataCompleteness, DetectionEvent, DetectionState, EventKind,
    EventTarget, ExecutionMode, MatchedReason, MetricKind, MetricRates, SamplingStatus, ScopeId,
    ScopeType, Severity, TestClock, TrafficDirection, TransitionReason,
};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::mitigation::MitigationStore;
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_mitigation::guard::AllowlistEntry;
use tidegard_mitigation::{
    Action, ActionKind, Guard, GuardConfig, MitigationId, MitigationRecord, MitigationRequest,
    MitigationState, WithdrawalCause,
};
use tidegard_mitigator::config::ProposalPolicy;
use tidegard_mitigator::gobgp::{GoBgp, GoBgpEndpoint};
use tidegard_mitigator::metrics::MitigatorMetrics;
use tidegard_mitigator::route::{announcement, withdrawal, RouteConfig};
use tidegard_mitigator::service::{Mitigator, MitigatorError};
use tokio_postgres::NoTls;

const DATABASE_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const GOBGP_VAR: &str = "TIDEGARD_GOBGP_TEST_ENDPOINT";

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
        reason: "service test".into(),
        duration: Duration::from_secs(600),
        incident_id: None,
    }
}

fn routes() -> RouteConfig {
    serde_json::from_str(
        r#"{"local_asn": 65001, "rtbh_next_hop_ipv4": "192.0.2.254",
            "rtbh_next_hop_ipv6": "2001:db8::254"}"#,
    )
    .unwrap()
}

fn guard(live: bool, allowlisted: bool) -> Guard {
    Guard::new(GuardConfig {
        bgp_enabled: live,
        dry_run: !live,
        approval_window_seconds: 60,
        allowlist: if allowlisted {
            vec![AllowlistEntry {
                prefix: "192.0.2.0/24".parse().unwrap(),
                tenant: "acme".into(),
                actions: vec![ActionKind::Rtbh],
            }]
        } else {
            Vec::new()
        },
        ..GuardConfig::default()
    })
    .unwrap()
}

fn store(guard: Guard) -> MitigationStore {
    MitigationStore::new(Arc::new(UuidV7IncidentGenerator::new()), Arc::new(guard))
}

async fn mitigator(guard: Guard, gobgp: Option<GoBgp>, proposals: ProposalPolicy) -> Mitigator {
    Mitigator::new(
        "mitigator-test".into(),
        store(guard),
        routes(),
        proposals,
        tidegard_mitigator::platform_authority(),
        gobgp,
        MitigatorMetrics::new().unwrap().0,
    )
}

async fn record(pool: &Pool, id: &MitigationId) -> MitigationRecord {
    let client = pool.get().await.unwrap();
    store(guard(true, true))
        .get(&**client, &person("alice", "viewer"), id)
        .await
        .unwrap()
}

/// Requests and approves an RTBH on `host`.
async fn approved(pool: &Pool, host: &str) -> MitigationId {
    let mut client = pool.get().await.unwrap();
    let s = store(guard(true, true));
    let m = s
        .request(
            &mut client,
            &person("alice", "senior_operator"),
            rtbh(host),
            None,
        )
        .await
        .unwrap();
    s.approve(&mut client, &person("lead", "noc_lead"), &m.id, 1)
        .await
        .unwrap();
    m.id
}

async fn owned_keys(gobgp: &mut GoBgp) -> Vec<String> {
    gobgp
        .owned_routes(&routes())
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.key)
        .collect()
}

fn incoming_attack(host: Ipv4Addr) -> DetectionEvent {
    DetectionEvent {
        schema_version: tidegard_detector::EVENT_SCHEMA_VERSION,
        event_id: "det-svc-1".into(),
        detection_id: "det-svc".into(),
        sequence: 1,
        kind: EventKind::Started,
        dedup_key: "det-svc:started:1".into(),
        policy_id: "p-svc".into(),
        policy_name: "p-svc".into(),
        policy_version: 1,
        severity: Severity::Major,
        execution_mode: ExecutionMode::AlertOnly,
        action: ActionTaken::Alerted,
        labels: BTreeMap::new(),
        target: EventTarget {
            tenant: "acme".into(),
            scope_type: ScopeType::Host,
            scope_id: ScopeId::Host {
                addr: IpAddr::V4(host),
            },
            display: host.to_string(),
            direction: TrafficDirection::Incoming,
            address_family: AddressFamily::Ipv4,
        },
        previous_state: DetectionState::PendingTrigger,
        state: DetectionState::Active,
        reason: TransitionReason::TriggerSustained,
        detected_at_ms: 1_700_000_000_000,
        observed_at_ms: 1_700_000_000_000,
        duration_ms: 0,
        window_ms: 1000,
        matched: vec![MatchedReason {
            metric: MetricKind::Bps,
            observed: 2_000,
            threshold: 1_000,
            excess: 1_000,
            ratio_percent: 200,
        }],
        peak: Vec::new(),
        skipped: Vec::new(),
        rates: MetricRates::default(),
        completeness: DataCompleteness::default(),
        sampling: SamplingStatus::default(),
        flows_observed: 42,
        exporters_observed: 2,
        snapshots_in_detection: 1,
        executed: false,
        summary: format!("major incoming on {host}"),
    }
}

#[tokio::test]
async fn the_mitigator_announces_withdraws_reconciles_and_obeys_the_kill_switch() {
    let (Some(url), Some(endpoint)) = (
        std::env::var(DATABASE_VAR).ok(),
        std::env::var(GOBGP_VAR).ok(),
    ) else {
        eprintln!(
            "skipping mitigator_service: {DATABASE_VAR} or {GOBGP_VAR} is not set. This test \
             requires an ephemeral PostgreSQL and a throwaway gobgpd on loopback."
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
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .unwrap();
    let (pool, _) = tidegard_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 4,
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();
    let connect = || async {
        GoBgp::connect(&GoBgpEndpoint::loopback(&endpoint))
            .await
            .unwrap()
    };
    let mut gobgp = connect().await;
    for route in gobgp.owned_routes(&routes()).await.unwrap() {
        gobgp
            .withdraw(withdrawal(&route.prefix, &route.action))
            .await
            .unwrap();
    }
    let mut live = mitigator(
        guard(true, true),
        Some(connect().await),
        ProposalPolicy::default(),
    )
    .await;

    // --- Approved: announced to GoBGP, active, the route recorded ---
    let first = approved(&pool, "192.0.2.10").await;
    let report = live.run_once(&pool).await.unwrap();
    assert_eq!(report.announced, 1, "{report:?}");
    let r = record(&pool, &first).await;
    assert_eq!(r.state, MitigationState::Active);
    assert_eq!(r.dry_run, Some(false));
    assert_eq!(owned_keys(&mut gobgp).await, ["rtbh|192.0.2.10/32|"]);
    let route: String = client
        .query_one(
            "SELECT route::text FROM mitigations WHERE mitigation_id = $1::text::uuid",
            &[&first.as_str()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        route.contains("192.0.2.254") && route.contains("65535:666"),
        "{route}"
    );

    // --- At its duration it comes down, without anyone acting ---
    client
        .execute(
            "UPDATE mitigations SET expires_at = transaction_timestamp() - interval '1 second' \
             WHERE mitigation_id = $1::text::uuid",
            &[&first.as_str()],
        )
        .await
        .unwrap();
    let report = live.run_once(&pool).await.unwrap();
    assert_eq!(report.withdrawn, 1, "{report:?}");
    let r = record(&pool, &first).await;
    assert_eq!(r.state, MitigationState::Withdrawn);
    assert_eq!(r.withdrawal, Some(WithdrawalCause::DurationReached));
    assert!(owned_keys(&mut gobgp).await.is_empty());

    // --- Reconciliation: a route nothing claims is withdrawn ---
    let leftover = "198.51.100.7/32".parse().unwrap();
    gobgp
        .announce(announcement(&leftover, &Action::Rtbh, &routes()))
        .await
        .unwrap();
    let report = live.reconcile(&pool).await.unwrap();
    assert_eq!(report.stale_withdrawn, 1, "{report:?}");
    assert!(owned_keys(&mut gobgp).await.is_empty());

    // --- Reconciliation: a lost route is restored (a gobgpd restart) ---
    let second = approved(&pool, "192.0.2.20").await;
    live.run_once(&pool).await.unwrap();
    let r = record(&pool, &second).await;
    gobgp
        .withdraw(withdrawal(&r.prefix, &r.action))
        .await
        .unwrap();
    assert!(owned_keys(&mut gobgp).await.is_empty());
    let report = live.reconcile(&pool).await.unwrap();
    assert_eq!(report.restored, 1, "{report:?}");
    assert_eq!(owned_keys(&mut gobgp).await, ["rtbh|192.0.2.20/32|"]);

    // --- An operator withdraws it ---
    {
        let mut c = pool.get().await.unwrap();
        store(guard(true, true))
            .withdraw(
                &mut c,
                &person("dave", "senior_operator"),
                &second,
                r.version,
                "attack over",
            )
            .await
            .unwrap();
    }
    live.run_once(&pool).await.unwrap();
    assert_eq!(
        record(&pool, &second).await.state,
        MitigationState::Withdrawn
    );
    assert!(owned_keys(&mut gobgp).await.is_empty());

    // --- The kill switch takes down what is up and stops what is next ---
    let third = approved(&pool, "192.0.2.30").await;
    live.run_once(&pool).await.unwrap();
    let fourth = approved(&pool, "192.0.2.40").await;
    {
        let mut c = pool.get().await.unwrap();
        store(guard(true, true))
            .set_kill_switch(&mut c, &person("lead", "noc_lead"), true, "drill")
            .await
            .unwrap();
    }
    let report = live.run_once(&pool).await.unwrap();
    assert!(report.kill_switch);
    assert_eq!(report.withdrawn, 2, "{report:?}");
    for id in [&third, &fourth] {
        let r = record(&pool, id).await;
        assert_eq!(r.state, MitigationState::Withdrawn);
        assert_eq!(r.withdrawal, Some(WithdrawalCause::KillSwitch));
    }
    assert!(owned_keys(&mut gobgp).await.is_empty());
    {
        let mut c = pool.get().await.unwrap();
        store(guard(true, true))
            .set_kill_switch(&mut c, &person("root", "super_admin"), false, "drill over")
            .await
            .unwrap();
    }

    // --- Dry-run: recorded, active, and nothing sent ---
    let mut dry = mitigator(
        Guard::new(GuardConfig {
            dry_run: true,
            ..guard(true, true).config().clone()
        })
        .unwrap(),
        Some(connect().await),
        ProposalPolicy::default(),
    )
    .await;
    assert!(dry.dry_run());
    let fifth = approved(&pool, "192.0.2.50").await;
    let report = dry.run_once(&pool).await.unwrap();
    assert_eq!(report.dry_run, 1, "{report:?}");
    let r = record(&pool, &fifth).await;
    assert_eq!(r.state, MitigationState::Active);
    assert_eq!(r.dry_run, Some(true));
    assert!(
        owned_keys(&mut gobgp).await.is_empty(),
        "dry-run sent nothing"
    );
    // A live mitigator's reconciliation leaves a dry-run mitigation alone.
    assert_eq!(live.reconcile(&pool).await.unwrap().restored, 0);
    {
        let mut c = pool.get().await.unwrap();
        store(guard(true, true))
            .withdraw(
                &mut c,
                &person("dave", "senior_operator"),
                &fifth,
                r.version,
                "done",
            )
            .await
            .unwrap();
    }
    dry.run_once(&pool).await.unwrap();
    assert_eq!(
        record(&pool, &fifth).await.state,
        MitigationState::Withdrawn
    );

    // --- Peers: the lab gobgpd has none; the snapshot is recorded ---
    assert_eq!(live.check_peers(&pool).await.unwrap(), (0, 0));
    let peers: i64 = client
        .query_one("SELECT count(*) FROM bgp_peers", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(peers, 0);

    // --- BGP off: no connection, no reconciliation, dry-run only ---
    let mut off = mitigator(guard(false, true), None, ProposalPolicy::default()).await;
    assert!(!off.has_bgp() && off.dry_run());
    assert!(matches!(
        off.reconcile(&pool).await,
        Err(MitigatorError::NoBgp)
    ));

    // --- Nobody approved it in time ---
    let waiting = {
        let mut c = pool.get().await.unwrap();
        store(guard(true, true))
            .request(
                &mut c,
                &person("alice", "senior_operator"),
                rtbh("192.0.2.60"),
                None,
            )
            .await
            .unwrap()
            .id
    };
    client
        .execute(
            "UPDATE mitigations SET created_at = created_at - interval '2 minutes' \
             WHERE mitigation_id = $1::text::uuid",
            &[&waiting.as_str()],
        )
        .await
        .unwrap();
    let report = off.run_once(&pool).await.unwrap();
    assert_eq!(report.expired, 1, "{report:?}");
    assert_eq!(
        record(&pool, &waiting).await.state,
        MitigationState::Expired
    );

    // --- The allowlist changed after approval: refused, failed, audited ---
    let late = approved(&pool, "192.0.2.70").await;
    let mut narrowed = mitigator(
        guard(true, false),
        Some(connect().await),
        ProposalPolicy::default(),
    )
    .await;
    let report = narrowed.run_once(&pool).await.unwrap();
    assert_eq!(report.refused, 1, "{report:?}");
    let r = record(&pool, &late).await;
    assert_eq!(r.state, MitigationState::Failed);
    assert!(r.last_error.unwrap().contains("refused by the guard"));
    assert!(owned_keys(&mut gobgp).await.is_empty());

    // --- Proposals: an incoming attack on an allowlisted host ---
    IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(TestClock::new()),
    )
    .ingest_detection_event(
        &mut client,
        &AuthorizationContext::correlator(TenantId::new("acme")),
        &incoming_attack(Ipv4Addr::new(192, 0, 2, 90)),
    )
    .await
    .unwrap()
    .unwrap();
    client
        .batch_execute("UPDATE incidents SET opened_at = transaction_timestamp()")
        .await
        .unwrap();
    let incident_before: (String, i64) = {
        let row = client
            .query_one("SELECT state, version FROM incidents", &[])
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    let mut proposing = mitigator(
        guard(false, true),
        None,
        ProposalPolicy {
            enabled: true,
            severities: vec!["major".into()],
            ..ProposalPolicy::default()
        },
    )
    .await;
    let report = proposing.run_once(&pool).await.unwrap();
    assert_eq!(report.proposed, 1, "{report:?}");
    let proposed: (String, String) = {
        let row = client
            .query_one(
                "SELECT state, prefix::text FROM mitigations WHERE incident_id IS NOT NULL",
                &[],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(
        proposed,
        ("proposed".to_string(), "192.0.2.90/32".to_string())
    );
    // Proposing again finds nothing new; a proposal announced nothing.
    assert_eq!(proposing.run_once(&pool).await.unwrap().proposed, 0);
    assert!(owned_keys(&mut gobgp).await.is_empty());
    // A mitigation never changes its incident: same state, same version.
    let incident_after: (String, i64) = {
        let row = client
            .query_one("SELECT state, version FROM incidents", &[])
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(incident_after, incident_before);
}
