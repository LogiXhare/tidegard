//! Phase 5A dependency-free domain end-to-end test.
//!
//! Builds a synthetic `DetectionEvent` **directly via struct literal** —
//! no IPFIX bytes, no collector, no detector state machine — per the
//! Stage A plan: "no real IPFIX/collector/detector wiring needed." This
//! keeps the incident crate's test fixtures inside the same narrow
//! import boundary as its production code: only the detector's public
//! event vocabulary is touched, never `StateTable`, `evaluate`, or
//! policy-matching internals.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use wetechinetmon_detector::{
    ActionTaken, AddressFamily, Clock, DataCompleteness, DetectionEvent, DetectionState, EventKind,
    EventTarget, ExecutionMode, MatchedReason, MetricKind, MetricRates, SamplingStatus, ScopeId,
    ScopeType, Severity, TestClock, TrafficDirection, TransitionReason,
};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, Permission, PermissionResolver,
};
use wetechinetmon_incident::closure::ClosureReason;
use wetechinetmon_incident::command::Command;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::error::IncidentError;
use wetechinetmon_incident::id::TestIncidentGenerator;
use wetechinetmon_incident::idempotency::IdempotencyKey;
use wetechinetmon_incident::incident::NoteVisibility;
use wetechinetmon_incident::number::InMemoryNumberAllocator;
use wetechinetmon_incident::state::IncidentState;
use wetechinetmon_incident::timeline::{
    AutomaticCause, OperatorCommandKind, TimelinePayload, TransitionCause,
};
use wetechinetmon_incident::unit_of_work::{IncidentUnitOfWork, IngestOutcomeKind};

/// Delegates to a shared, externally-advanceable [`TestClock`] so a test
/// can control elapsed time (reopen windows, auto-close delays) after the
/// `IncidentUnitOfWork` has already taken ownership of its clock as a
/// `Box<dyn Clock>`.
struct SharedClock(Arc<TestClock>);

impl Clock for SharedClock {
    fn monotonic(&self) -> Instant {
        self.0.monotonic()
    }

    fn wall(&self) -> SystemTime {
        self.0.wall()
    }
}

fn uow_with_shared_clock() -> (IncidentUnitOfWork, Arc<TestClock>) {
    let clock = Arc::new(TestClock::new());
    let uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(SharedClock(clock.clone())),
    );
    (uow, clock)
}

#[allow(clippy::too_many_arguments)]
fn event(
    detection_id: &str,
    sequence: u64,
    kind: EventKind,
    tenant: &str,
    addr: IpAddr,
    metric: MetricKind,
    observed: u64,
    threshold: u64,
) -> DetectionEvent {
    let matched = if kind == EventKind::Ended {
        Vec::new()
    } else {
        vec![MatchedReason {
            metric,
            observed,
            threshold,
            excess: observed.saturating_sub(threshold),
            ratio_percent: observed * 100 / threshold.max(1),
        }]
    };
    DetectionEvent {
        schema_version: wetechinetmon_detector::EVENT_SCHEMA_VERSION,
        event_id: format!("{detection_id}-{sequence}"),
        detection_id: detection_id.to_string(),
        sequence,
        kind,
        dedup_key: format!("{detection_id}:{}:{sequence}", kind.as_str()),
        policy_id: "p-host-bps".to_string(),
        policy_name: "host bps".to_string(),
        policy_version: 1,
        severity: Severity::Major,
        execution_mode: ExecutionMode::AlertOnly,
        action: ActionTaken::Alerted,
        labels: BTreeMap::new(),
        target: EventTarget {
            tenant: tenant.to_string(),
            scope_type: ScopeType::Host,
            scope_id: ScopeId::Host { addr },
            display: addr.to_string(),
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
        matched,
        peak: Vec::new(),
        skipped: Vec::new(),
        rates: MetricRates::default(),
        completeness: DataCompleteness::default(),
        sampling: SamplingStatus::default(),
        flows_observed: 42,
        exporters_observed: 2,
        snapshots_in_detection: 1,
        executed: false,
        summary: format!("major started: incoming host {addr} under policy p-host-bps"),
    }
}

fn resolver_context(
    resolver: &FixedBundleResolver,
    tenant: &str,
    role: &str,
    actor_id: &str,
) -> AuthorizationContext {
    AuthorizationContext::new(
        TenantId::new(tenant),
        Actor::Operator {
            id: actor_id.to_string(),
        },
        resolver.permissions_for(role),
    )
}

#[test]
fn detection_to_incident_full_lifecycle_end_to_end() {
    let clock = TestClock::new();
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    // The unit of work owns its own clock instance; drive time through
    // the same handle it was built with is not possible from here, so
    // this test uses the unit-of-work's internal clock indirectly by
    // reasoning only about what its own returned data proves — the
    // reopen-boundary precision is already covered directly in
    // crate::reopen's unit tests against a `TestClock` the test controls
    // completely. This test proves the wiring, not the boundary math.
    let _ = &clock;

    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    // noc_lead, not senior_operator: this scenario also exercises
    // suppress/unsuppress, which is deliberately outside senior_operator
    // per the security model (see authorization::tests for the negative
    // case pinning senior_operator's exact boundary).
    let operator = resolver_context(&resolver, "acme", "noc_lead", "u1");

    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    // 1. Detection starts -> incident created.
    let started = event(
        "det-1",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let result = uow.ingest_detection_event(&correlator, &started).unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Created);
    let incident_id = result.incident_id.unwrap();

    let incident = uow.get(&incident_id).unwrap();
    assert_eq!(incident.tenant_id, TenantId::new("acme"));
    assert_eq!(incident.state, IncidentState::Open);
    assert_eq!(incident.severity, Severity::Major);
    assert_eq!(incident.reopen_count, 0);
    assert!(!incident.evidence.is_truncated());
    assert_eq!(incident.evidence.retained_count(), 1);

    // 2. Duplicate delivery of the same start event is rejected at the
    // duplicate gate, not treated as a second incident.
    let replay = uow.ingest_detection_event(&correlator, &started).unwrap();
    assert_eq!(replay.outcome_kind, IngestOutcomeKind::Duplicate);
    assert_eq!(uow.incident_count(), 1);

    // 3. A second matched reason on an update links as evidence and
    // widens the category.
    let updated = event(
        "det-1",
        1,
        EventKind::Updated,
        "acme",
        addr,
        MetricKind::TcpSynPps,
        9_000,
        1_000,
    );
    let result = uow.ingest_detection_event(&correlator, &updated).unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Updated);
    // Bps (opening) + TcpSynPps (update) is still one protocol family
    // (TCP) by the category derivation rules — TCP SYN is checked before
    // the generic bandwidth category, matching category::tests's own
    // `tcp_syn_wins_over_generic_packet_rate`. Multi-vector requires two
    // *families* (TCP/UDP/ICMP), not two metrics.
    let incident = uow.get(&incident_id).unwrap();
    assert_eq!(
        incident.category,
        wetechinetmon_incident::category::IncidentCategory::TcpSynFlood
    );
    assert_eq!(incident.version, 2);

    // 4. Operator acknowledges, investigates.
    let version = uow
        .handle_command(
            &operator,
            incident_id,
            Command::AcknowledgeIncident {
                expected_version: incident.version,
            },
            None,
        )
        .unwrap();
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Acknowledged
    );
    let version = uow
        .handle_command(
            &operator,
            incident_id,
            Command::BeginInvestigation {
                expected_version: version,
            },
            None,
        )
        .unwrap();
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Investigating
    );

    // 5. Suppress, then unsuppress — lifecycle state must not move.
    let version = uow
        .handle_command(
            &operator,
            incident_id,
            Command::SuppressIncident {
                expected_version: version,
                reason: "known scanner".to_string(),
                duration: Duration::from_secs(3600),
            },
            None,
        )
        .unwrap();
    let incident = uow.get(&incident_id).unwrap();
    assert_eq!(
        incident.state,
        IncidentState::Investigating,
        "suppression must not change lifecycle state"
    );
    assert!(incident.suppression.is_some());
    let _version = uow
        .handle_command(
            &operator,
            incident_id,
            Command::UnsuppressIncident {
                expected_version: version,
            },
            None,
        )
        .unwrap();
    let incident = uow.get(&incident_id).unwrap();
    assert_eq!(incident.state, IncidentState::Investigating);
    assert!(incident.suppression.is_none());

    // 6. A note is added, non-mutating-state, then a note over the
    // customer-visible refusal is rejected.
    let _version = uow
        .handle_command(
            &operator,
            incident_id,
            Command::AddNote {
                body: "post-mortem draft".to_string(),
                visibility: NoteVisibility::Internal,
            },
            None,
        )
        .unwrap();
    assert_eq!(uow.get(&incident_id).unwrap().notes.len(), 1);
    let denied = uow.handle_command(
        &operator,
        incident_id,
        Command::AddNote {
            body: "x".to_string(),
            visibility: NoteVisibility::CustomerVisible,
        },
        None,
    );
    assert!(denied.is_err());

    // 7. A wrong expected_version is a structured conflict, not a silent
    // overwrite, and does not mutate the incident.
    let before = uow.get(&incident_id).unwrap().clone();
    let conflict = uow.handle_command(
        &operator,
        incident_id,
        Command::AcknowledgeIncident {
            expected_version: 999,
        },
        None,
    );
    assert!(matches!(
        conflict,
        Err(wetechinetmon_incident::error::IncidentError::VersionConflict { .. })
    ));
    assert_eq!(
        uow.get(&incident_id).unwrap(),
        &before,
        "a version conflict must not mutate anything"
    );

    // 8. Detection ends -> Recovering, automatically, as one ingest call:
    // correlation links the event and the state machine reacts to its
    // `Ended` kind in the same call ("let the state machine decide
    // whether the event causes a transition" per the correlation
    // design's step 5).
    let ended = event(
        "det-1",
        2,
        EventKind::Ended,
        "acme",
        addr,
        MetricKind::Bps,
        0,
        1_000_000,
    );
    let result = uow.ingest_detection_event(&correlator, &ended).unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Updated);
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Recovering
    );
    let confirmed = uow
        .confirm_recovery_if_due(&correlator, incident_id, Duration::from_secs(300))
        .unwrap();
    assert!(
        !confirmed,
        "recovery confirmation period has not elapsed yet"
    );

    // 9. Force severity to Critical partway through this lifecycle so
    // `ever_critical` latches; the actual auto-close-refused-then-manual-
    // close-works assertions live in
    // `critical_incident_does_not_auto_close_but_manual_close_works`.
    let incident = uow.get(&incident_id).unwrap();
    let version = uow
        .handle_command(
            &operator,
            incident_id,
            Command::ChangeSeverity {
                expected_version: incident.version,
                new_severity: Severity::Critical,
                reason: None,
            },
            None,
        )
        .unwrap();
    let _ = version;
}

#[test]
fn critical_incident_does_not_auto_close_but_manual_close_works() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));

    let started = event(
        "det-crit",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        9_000_000,
        1_000_000,
    );
    let mut started = started;
    started.severity = Severity::Critical;
    let result = uow.ingest_detection_event(&correlator, &started).unwrap();
    let incident_id = result.incident_id.unwrap();
    assert_eq!(uow.get(&incident_id).unwrap().severity, Severity::Critical);

    uow.enter_recovering(
        &correlator,
        incident_id,
        wetechinetmon_incident::transition::DetectionEndReason::TrafficCleared,
    )
    .unwrap();
    // Recovery confirmation is satisfied because the injected TestClock
    // inside the unit of work never advances, so "0 elapsed >= 0
    // duration" trivially holds — exercised explicitly here so the
    // confirm path itself is proven, independent of timing.
    let confirmed = uow
        .confirm_recovery_if_due(&correlator, incident_id, Duration::ZERO)
        .unwrap();
    assert!(confirmed);
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Resolved
    );

    let auto_closed = uow
        .attempt_automatic_closure(&correlator, incident_id)
        .unwrap();
    assert!(
        !auto_closed,
        "a critical incident must never auto-close under the default policy"
    );
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Resolved
    );

    // An operator without incident.close cannot close it either.
    let viewer = resolver_context(&resolver, "acme", "viewer", "u2");
    let denied = uow.handle_command(
        &viewer,
        incident_id,
        Command::CloseIncident {
            expected_version: 3,
            reason: ClosureReason::Resolved,
            detail: None,
        },
        None,
    );
    assert!(denied.is_err());
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Resolved,
        "a denied close must not mutate the incident"
    );

    let version = uow.get(&incident_id).unwrap().version;
    uow.handle_command(
        &operator,
        incident_id,
        Command::CloseIncident {
            expected_version: version,
            reason: ClosureReason::Resolved,
            detail: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(uow.get(&incident_id).unwrap().state, IncidentState::Closed);

    // Negative assertions: nothing here ever notified or mitigated.
    for outbox_message in uow.outbox() {
        let name = outbox_message.event.event_type();
        assert!(
            !name.contains("notif"),
            "no notification event type may appear: {name}"
        );
        assert!(
            !name.contains("mitig"),
            "no mitigation event type may appear: {name}"
        );
    }
}

/// BQ-8 closure-bypass regression, end to end through `handle_command`
/// rather than the unit-level `attempt_automatic_closure` test in
/// `transition.rs`: an incident that reached `Critical`, was resolved,
/// and was then downgraded through the ordinary `ChangeSeverity` command
/// (which only requires `IncidentSeverityChange`, not the specially-gated
/// `incident.closure_policy.override`) must still refuse automatic
/// closure. Before `ever_critical` existed, this exact operator sequence
/// silently unlocked automatic closure for a formerly critical incident.
#[test]
fn severity_downgrade_does_not_unlock_automatic_closure_for_a_formerly_critical_incident() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

    let mut started = event(
        "det-crit-downgrade",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        9_000_000,
        1_000_000,
    );
    started.severity = Severity::Critical;
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();
    assert!(uow.get(&incident_id).unwrap().ever_critical);

    uow.enter_recovering(
        &correlator,
        incident_id,
        wetechinetmon_incident::transition::DetectionEndReason::TrafficCleared,
    )
    .unwrap();
    assert!(uow
        .confirm_recovery_if_due(&correlator, incident_id, Duration::ZERO)
        .unwrap());
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Resolved
    );

    // Ordinary severity downgrade — not the closure-policy override.
    let version = uow.get(&incident_id).unwrap().version;
    uow.handle_command(
        &operator,
        incident_id,
        Command::ChangeSeverity {
            expected_version: version,
            new_severity: Severity::Major,
            reason: Some("recovered, downgrading".to_string()),
        },
        None,
    )
    .unwrap();
    assert_eq!(uow.get(&incident_id).unwrap().severity, Severity::Major);
    assert!(
        uow.get(&incident_id).unwrap().ever_critical,
        "ever_critical must not be cleared by an ordinary severity change"
    );

    let auto_closed = uow
        .attempt_automatic_closure(&correlator, incident_id)
        .unwrap();
    assert!(
        !auto_closed,
        "a formerly critical incident must not auto-close after a mere severity downgrade"
    );
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Resolved
    );

    // Manual closure still works.
    let version = uow.get(&incident_id).unwrap().version;
    uow.handle_command(
        &operator,
        incident_id,
        Command::CloseIncident {
            expected_version: version,
            reason: ClosureReason::Resolved,
            detail: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(uow.get(&incident_id).unwrap().state, IncidentState::Closed);
}

#[test]
fn a_denied_ingest_permission_writes_no_incident() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let unauthorized = AuthorizationContext::new(
        TenantId::new("acme"),
        Actor::Operator {
            id: "u1".to_string(),
        },
        vec![],
    );
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let started = event(
        "det-x",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let result = uow.ingest_detection_event(&unauthorized, &started);
    assert!(result.is_err());
    assert_eq!(uow.incident_count(), 0);
    assert!(uow.audit().iter().any(|a| a.is_denied()));
}

#[test]
fn cross_tenant_command_returns_not_found_not_forbidden() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let started = event(
        "det-y",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();

    let other_tenant_operator = resolver_context(&resolver, "globex", "senior_operator", "u9");
    let result = uow.handle_command(
        &other_tenant_operator,
        incident_id,
        Command::AcknowledgeIncident {
            expected_version: 1,
        },
        None,
    );
    assert_eq!(
        result,
        Err(wetechinetmon_incident::error::IncidentError::NotFound)
    );
    let _ = Permission::IncidentAcknowledge;
}

#[test]
fn duplicate_idempotency_key_replays_and_conflicting_body_conflicts() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let started = event(
        "det-z",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();

    let key = wetechinetmon_incident::idempotency::IdempotencyKey::new("a".repeat(20)).unwrap();
    let v1 = uow
        .handle_command(
            &operator,
            incident_id,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            Some(key.clone()),
        )
        .unwrap();
    let v2 = uow
        .handle_command(
            &operator,
            incident_id,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            Some(key.clone()),
        )
        .unwrap();
    assert_eq!(
        v1, v2,
        "same key, same command must replay the original result"
    );
    assert_eq!(
        uow.get(&incident_id).unwrap().version,
        2,
        "a replay must not apply the mutation twice"
    );

    let conflict = uow.handle_command(
        &operator,
        incident_id,
        Command::BeginInvestigation {
            expected_version: 2,
        },
        Some(key),
    );
    assert_eq!(
        conflict,
        Err(wetechinetmon_incident::error::IncidentError::IdempotencyConflict)
    );
}

// `failure_injection_documents_the_in_memory_commit_boundary` moved to
// `crates/incident/src/unit_of_work.rs`'s own `#[cfg(test)] mod tests`:
// the failure-injection hook it exercises is `pub(crate)` and
// `cfg(test)`-gated (see M8 in the review), so it is not visible to this
// separate integration-test compilation unit.

// ---------------------------------------------------------------------
// B1: a Resolved (not only Closed) incident is a reopen candidate.
// ---------------------------------------------------------------------

#[test]
fn resolved_incident_reopens_within_window_through_ingestion() {
    let (mut uow, clock) = uow_with_shared_clock();
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));

    let started = event(
        "det-b1a",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();

    uow.handle_command(
        &operator,
        incident_id,
        Command::ResolveIncident {
            expected_version: 1,
            resolution_note: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Resolved
    );

    // Within the 15-minute default reopen window.
    clock.advance(Duration::from_secs(5 * 60));
    let recurrence = event(
        "det-b1a-recur",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        6_000_000,
        1_000_000,
    );
    let result = uow
        .ingest_detection_event(&correlator, &recurrence)
        .unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Reopened);
    assert_eq!(
        result.incident_id,
        Some(incident_id),
        "recurrence must reopen the same incident, not create a second one"
    );
    let incident = uow.get(&incident_id).unwrap();
    assert_eq!(incident.state, IncidentState::Open);
    assert_eq!(incident.reopen_count, 1);
    assert_eq!(uow.incident_count(), 1);
    // FU-37: a reopened, active incident must not carry a stale
    // `resolved_at` from the prior cycle — that history lives in the
    // timeline's `StateChanged` entries instead.
    assert_eq!(
        incident.resolved_at, None,
        "resolved_at must be cleared on reopen, not left stale from the prior cycle"
    );
}

#[test]
fn resolved_incident_recurrence_outside_window_creates_a_new_incident() {
    let (mut uow, clock) = uow_with_shared_clock();
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21));

    let started = event(
        "det-b1b",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let first_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();

    uow.handle_command(
        &operator,
        first_id,
        Command::ResolveIncident {
            expected_version: 1,
            resolution_note: None,
        },
        None,
    )
    .unwrap();

    // Outside the 15-minute default reopen window.
    clock.advance(Duration::from_secs(16 * 60));
    let recurrence = event(
        "det-b1b-recur",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        6_000_000,
        1_000_000,
    );
    let result = uow
        .ingest_detection_event(&correlator, &recurrence)
        .unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Created);
    assert_ne!(result.incident_id, Some(first_id));
    assert_eq!(uow.incident_count(), 2);
    assert_eq!(
        uow.get(&first_id).unwrap().state,
        IncidentState::Resolved,
        "the original incident is untouched by a recurrence outside its window"
    );
}

#[test]
fn closed_incident_reopens_within_window_through_ingestion() {
    let (mut uow, clock) = uow_with_shared_clock();
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22));

    let started = event(
        "det-b1c",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();

    uow.handle_command(
        &operator,
        incident_id,
        Command::ResolveIncident {
            expected_version: 1,
            resolution_note: None,
        },
        None,
    )
    .unwrap();
    clock.advance(Duration::from_secs(60));
    uow.handle_command(
        &operator,
        incident_id,
        Command::CloseIncident {
            expected_version: 2,
            reason: ClosureReason::Resolved,
            detail: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(uow.get(&incident_id).unwrap().state, IncidentState::Closed);

    // 10 minutes after `closed_at`, still within the 15-minute window.
    clock.advance(Duration::from_secs(10 * 60));
    let recurrence = event(
        "det-b1c-recur",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        6_000_000,
        1_000_000,
    );
    let result = uow
        .ingest_detection_event(&correlator, &recurrence)
        .unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Reopened);
    assert_eq!(result.incident_id, Some(incident_id));
    assert_eq!(uow.incident_count(), 1);
    assert_eq!(uow.get(&incident_id).unwrap().reopen_count, 1);
    // FU-37: same guarantee for the closed-then-reopened path.
    let incident = uow.get(&incident_id).unwrap();
    assert_eq!(
        incident.resolved_at, None,
        "resolved_at must be cleared on reopen"
    );
    assert_eq!(
        incident.closed_at, None,
        "closed_at must be cleared on reopen, not left stale from the prior cycle"
    );
}

// ---------------------------------------------------------------------
// B2: `ResolveIncident` must invoke the transition guard.
// ---------------------------------------------------------------------

#[test]
fn resolve_from_closed_is_rejected_and_leaves_state_unchanged() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 23));

    let started = event(
        "det-b2a",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();
    uow.handle_command(
        &operator,
        incident_id,
        Command::ResolveIncident {
            expected_version: 1,
            resolution_note: None,
        },
        None,
    )
    .unwrap();
    uow.handle_command(
        &operator,
        incident_id,
        Command::CloseIncident {
            expected_version: 2,
            reason: ClosureReason::Resolved,
            detail: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(uow.get(&incident_id).unwrap().state, IncidentState::Closed);
    let before = uow.get(&incident_id).unwrap().clone();

    let result = uow.handle_command(
        &operator,
        incident_id,
        Command::ResolveIncident {
            expected_version: 3,
            resolution_note: None,
        },
        None,
    );
    assert_eq!(
        result,
        Err(IncidentError::InvalidTransition {
            from: IncidentState::Closed,
            to: IncidentState::Resolved,
        })
    );
    assert_eq!(
        uow.get(&incident_id).unwrap(),
        &before,
        "a rejected Closed -> Resolved must not mutate the incident"
    );
}

#[test]
fn resolving_an_already_resolved_incident_is_state_unchanged() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 24));

    let started = event(
        "det-b2b",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();
    uow.handle_command(
        &operator,
        incident_id,
        Command::ResolveIncident {
            expected_version: 1,
            resolution_note: None,
        },
        None,
    )
    .unwrap();
    let before = uow.get(&incident_id).unwrap().clone();

    let result = uow.handle_command(
        &operator,
        incident_id,
        Command::ResolveIncident {
            expected_version: 2,
            resolution_note: None,
        },
        None,
    );
    assert_eq!(
        result,
        Err(IncidentError::StateUnchanged(IncidentState::Resolved))
    );
    assert_eq!(
        uow.get(&incident_id).unwrap(),
        &before,
        "a rejected Resolved -> Resolved must not mutate the incident"
    );
}

// ---------------------------------------------------------------------
// H1: transition metadata is command-specific, not hardcoded to
// Acknowledge for every guarded operator transition.
// ---------------------------------------------------------------------

#[test]
fn begin_investigation_and_mark_monitoring_emit_their_own_metadata() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 25));

    let started = event(
        "det-h1",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();

    uow.handle_command(
        &operator,
        incident_id,
        Command::AcknowledgeIncident {
            expected_version: 1,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        uow.audit().last().unwrap().permission,
        Permission::IncidentAcknowledge
    );

    uow.handle_command(
        &operator,
        incident_id,
        Command::BeginInvestigation {
            expected_version: 2,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        uow.audit().last().unwrap().permission,
        Permission::IncidentInvestigate,
        "BeginInvestigation must not be audited under IncidentAcknowledge"
    );
    match &uow.timeline().last().unwrap().payload {
        wetechinetmon_incident::timeline::TimelinePayload::StateChanged { cause, .. } => {
            assert_eq!(
                *cause,
                wetechinetmon_incident::timeline::TransitionCause::Operator(
                    OperatorCommandKind::BeginInvestigation
                ),
                "BeginInvestigation must not be recorded as Acknowledge on the timeline"
            );
        }
        other => panic!("expected StateChanged, got {other:?}"),
    }

    uow.handle_command(
        &operator,
        incident_id,
        Command::MarkMonitoring {
            expected_version: 3,
        },
        None,
    )
    .unwrap();
    match &uow.timeline().last().unwrap().payload {
        wetechinetmon_incident::timeline::TimelinePayload::StateChanged { cause, .. } => {
            assert_eq!(
                *cause,
                wetechinetmon_incident::timeline::TransitionCause::Operator(
                    OperatorCommandKind::MarkMonitoring
                ),
                "MarkMonitoring must not be recorded as Acknowledge or BeginInvestigation"
            );
        }
        other => panic!("expected StateChanged, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// H2: automatic-maintenance methods require IncidentIngest, and are not
// reachable by a caller who holds no permission at all.
// ---------------------------------------------------------------------

#[test]
fn unauthorized_context_cannot_drive_automatic_maintenance_methods() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 26));
    let started = event(
        "det-h2",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();

    let unauthorized = AuthorizationContext::new(
        TenantId::new("acme"),
        Actor::Operator {
            id: "u1".to_string(),
        },
        vec![],
    );
    let version_before = uow.get(&incident_id).unwrap().version;

    assert_eq!(
        uow.enter_recovering(
            &unauthorized,
            incident_id,
            wetechinetmon_incident::transition::DetectionEndReason::TrafficCleared,
        ),
        Err(IncidentError::Unauthorized)
    );
    assert_eq!(
        uow.confirm_recovery_if_due(&unauthorized, incident_id, Duration::ZERO),
        Err(IncidentError::Unauthorized)
    );
    assert_eq!(
        uow.abort_recovery(&unauthorized, incident_id),
        Err(IncidentError::Unauthorized)
    );
    assert_eq!(
        uow.attempt_automatic_closure(&unauthorized, incident_id),
        Err(IncidentError::Unauthorized)
    );

    let incident = uow.get(&incident_id).unwrap();
    assert_eq!(
        incident.state,
        IncidentState::Open,
        "no maintenance call may mutate state"
    );
    assert_eq!(
        incident.version, version_before,
        "no maintenance call may bump version"
    );
    assert_eq!(
        uow.audit().iter().filter(|a| a.is_denied()).count(),
        4,
        "each of the four denied calls must write exactly one denied audit record"
    );

    // The correlator's own IncidentIngest permission is sufficient — this
    // proves the four methods are reachable by their intended caller, not
    // merely locked out entirely.
    uow.enter_recovering(
        &correlator,
        incident_id,
        wetechinetmon_incident::transition::DetectionEndReason::TrafficCleared,
    )
    .unwrap();
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Recovering
    );
}

// ---------------------------------------------------------------------
// H3: the idempotency fingerprint is bound to the target incident.
// ---------------------------------------------------------------------

#[test]
fn idempotency_key_reused_across_two_incidents_conflicts() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "senior_operator", "u1");

    let addr_a: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 27));
    let addr_b: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 28));
    let incident_a = uow
        .ingest_detection_event(
            &correlator,
            &event(
                "det-h3a",
                0,
                EventKind::Started,
                "acme",
                addr_a,
                MetricKind::Bps,
                5_000_000,
                1_000_000,
            ),
        )
        .unwrap()
        .incident_id
        .unwrap();
    let incident_b = uow
        .ingest_detection_event(
            &correlator,
            &event(
                "det-h3b",
                0,
                EventKind::Started,
                "acme",
                addr_b,
                MetricKind::Bps,
                5_000_000,
                1_000_000,
            ),
        )
        .unwrap()
        .incident_id
        .unwrap();

    let key = IdempotencyKey::new("a".repeat(20)).unwrap();
    let v = uow
        .handle_command(
            &operator,
            incident_a,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            Some(key.clone()),
        )
        .unwrap();
    assert_eq!(v, 2);

    // Same key, same command shape, but a *different* incident — must
    // conflict, not silently replay incident A's stored success against B.
    let result = uow.handle_command(
        &operator,
        incident_b,
        Command::AcknowledgeIncident {
            expected_version: 1,
        },
        Some(key),
    );
    assert_eq!(result, Err(IncidentError::IdempotencyConflict));
    assert_eq!(
        uow.get(&incident_b).unwrap().version,
        1,
        "the conflicting call must not have mutated incident B"
    );
}

// ---------------------------------------------------------------------
// H4: replaying a failed command reproduces its original error category,
// and a transient/injected failure is never persisted as a permanent
// idempotency outcome.
// ---------------------------------------------------------------------

#[test]
fn version_conflict_replays_as_the_same_version_conflict() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 29));
    let incident_id = uow
        .ingest_detection_event(
            &correlator,
            &event(
                "det-h4a",
                0,
                EventKind::Started,
                "acme",
                addr,
                MetricKind::Bps,
                5_000_000,
                1_000_000,
            ),
        )
        .unwrap()
        .incident_id
        .unwrap();

    let key = IdempotencyKey::new("b".repeat(20)).unwrap();
    let first = uow.handle_command(
        &operator,
        incident_id,
        Command::AcknowledgeIncident {
            expected_version: 999,
        },
        Some(key.clone()),
    );
    assert!(matches!(first, Err(IncidentError::VersionConflict { .. })));

    let replay = uow.handle_command(
        &operator,
        incident_id,
        Command::AcknowledgeIncident {
            expected_version: 999,
        },
        Some(key),
    );
    assert_eq!(
        first, replay,
        "a replayed VersionConflict must reproduce the exact original error, not Unauthorized"
    );
}

#[test]
fn capacity_exceeded_replays_as_the_same_capacity_error() {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let operator = resolver_context(&resolver, "acme", "operator", "u1");
    let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30));
    let incident_id = uow
        .ingest_detection_event(
            &correlator,
            &event(
                "det-h4b",
                0,
                EventKind::Started,
                "acme",
                addr,
                MetricKind::Bps,
                5_000_000,
                1_000_000,
            ),
        )
        .unwrap()
        .incident_id
        .unwrap();

    for i in 0..500 {
        uow.handle_command(
            &operator,
            incident_id,
            Command::AddNote {
                body: format!("note {i}"),
                visibility: NoteVisibility::Internal,
            },
            None,
        )
        .unwrap();
    }

    let key = IdempotencyKey::new("c".repeat(20)).unwrap();
    let first = uow.handle_command(
        &operator,
        incident_id,
        Command::AddNote {
            body: "one too many".to_string(),
            visibility: NoteVisibility::Internal,
        },
        Some(key.clone()),
    );
    assert!(matches!(first, Err(IncidentError::CapacityExceeded(_))));

    let replay = uow.handle_command(
        &operator,
        incident_id,
        Command::AddNote {
            body: "one too many".to_string(),
            visibility: NoteVisibility::Internal,
        },
        Some(key),
    );
    assert_eq!(first, replay);
    assert_eq!(uow.get(&incident_id).unwrap().notes.len(), 500);
}

// `injected_failure_does_not_poison_an_idempotency_key` moved to
// `crates/incident/src/unit_of_work.rs`'s own `#[cfg(test)] mod tests`
// for the same reason as above.

/// FU-40: automatic closure waits for `automatic_closure_delay` after
/// `resolved_at`, measured on the unit of work's decision time.
#[test]
fn automatic_closure_waits_for_the_closure_delay() {
    let (mut uow, clock) = uow_with_shared_clock();
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 41));
    let started = event(
        "det-delay",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        9_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();
    uow.enter_recovering(
        &correlator,
        incident_id,
        wetechinetmon_incident::transition::DetectionEndReason::TrafficCleared,
    )
    .unwrap();
    assert!(uow
        .confirm_recovery_if_due(&correlator, incident_id, Duration::ZERO)
        .unwrap());

    let delay =
        wetechinetmon_incident::closure::ClosurePolicy::approved_default().automatic_closure_delay;
    assert!(!uow
        .attempt_automatic_closure(&correlator, incident_id)
        .unwrap());
    clock.advance(delay - Duration::from_secs(1));
    assert!(
        !uow.attempt_automatic_closure(&correlator, incident_id)
            .unwrap(),
        "one second before the delay elapses, the incident stays resolved"
    );
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Resolved
    );
    clock.advance(Duration::from_secs(1));
    assert!(uow
        .attempt_automatic_closure(&correlator, incident_id)
        .unwrap());
    assert_eq!(uow.get(&incident_id).unwrap().state, IncidentState::Closed);
}

/// The staleness sweep's transition: silence for `silent_after` moves an
/// open incident to `Recovering` as `DetectorSilent`; a recent detection
/// keeps it open.
#[test]
fn a_silent_detector_moves_an_incident_to_recovering_only_after_the_threshold() {
    let (mut uow, clock) = uow_with_shared_clock();
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    let started = event(
        "det-silent",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        9_000_000,
        1_000_000,
    );
    let incident_id = uow
        .ingest_detection_event(&correlator, &started)
        .unwrap()
        .incident_id
        .unwrap();
    let silent_after = Duration::from_secs(300);

    clock.advance(silent_after - Duration::from_secs(1));
    assert!(!uow
        .enter_recovering_if_silent(&correlator, incident_id, silent_after)
        .unwrap());
    assert_eq!(uow.get(&incident_id).unwrap().state, IncidentState::Open);

    clock.advance(Duration::from_secs(1));
    assert!(uow
        .enter_recovering_if_silent(&correlator, incident_id, silent_after)
        .unwrap());
    assert_eq!(
        uow.get(&incident_id).unwrap().state,
        IncidentState::Recovering
    );

    let operator_without_ingest = AuthorizationContext::new(
        TenantId::new("acme"),
        Actor::Operator {
            id: "viewer".to_string(),
        },
        FixedBundleResolver.permissions_for("viewer"),
    );
    assert!(uow
        .enter_recovering_if_silent(&operator_without_ingest, incident_id, silent_after)
        .is_err());
}

/// T-18: news about what was already resolved never reopens it. A late
/// event of the resolved detection episode, and a detection ending, link
/// as evidence; only a new episode reopens.
#[test]
fn late_news_about_a_resolved_incident_links_and_never_reopens() {
    let resolver = FixedBundleResolver;
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let senior = resolver_context(&resolver, "acme", "senior_operator", "u1");
    let (mut uow, _clock) = uow_with_shared_clock();
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40));
    let opening = event(
        "det-old",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let id = uow
        .ingest_detection_event(&correlator, &opening)
        .unwrap()
        .incident_id
        .unwrap();
    let version = uow.get(&id).unwrap().version;
    uow.handle_command(
        &senior,
        id,
        Command::ResolveIncident {
            expected_version: version,
            resolution_note: None,
        },
        None,
    )
    .unwrap();

    // A delayed event of the episode the incident already holds.
    let delayed = event(
        "det-old",
        1,
        EventKind::Updated,
        "acme",
        addr,
        MetricKind::Bps,
        4_000_000,
        1_000_000,
    );
    let linked = uow.ingest_detection_event(&correlator, &delayed).unwrap();
    assert_eq!(linked.outcome_kind, IngestOutcomeKind::LinkedLate);
    assert_eq!(linked.incident_id, Some(id));
    assert_eq!(
        uow.get(&id).unwrap().state,
        IncidentState::Resolved,
        "not reopened"
    );

    // A detection ending, even of an episode never seen, is not a recurrence.
    let ended = event(
        "det-other",
        7,
        EventKind::Ended,
        "acme",
        addr,
        MetricKind::Bps,
        0,
        1_000_000,
    );
    let linked = uow.ingest_detection_event(&correlator, &ended).unwrap();
    assert_eq!(linked.outcome_kind, IngestOutcomeKind::LinkedLate);
    assert_eq!(
        uow.get(&id).unwrap().state,
        IncidentState::Resolved,
        "not reopened"
    );
    assert_eq!(uow.get(&id).unwrap().reopen_count, 0);

    // A new episode is a recurrence, and reopens.
    let recurrence = event(
        "det-new",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        5_000_000,
        1_000_000,
    );
    let reopened = uow
        .ingest_detection_event(&correlator, &recurrence)
        .unwrap();
    assert_eq!(reopened.outcome_kind, IngestOutcomeKind::Reopened);
    assert_eq!(uow.get(&id).unwrap().state, IncidentState::Open);
    assert_eq!(uow.incident_count(), 1);
}

/// Gate 2: the five ways a detection can end are recorded distinctly, so
/// an operator can tell "the attack stopped" from "we stopped hearing
/// about it" (ADR 0014). The cause is on the timeline entry, which the API
/// returns as stored, under these exact names.
#[test]
fn the_five_end_reasons_are_recorded_distinctly() {
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 43));
    let started = || {
        event(
            "det-end",
            0,
            EventKind::Started,
            "acme",
            addr,
            MetricKind::Bps,
            9_000_000,
            1_000_000,
        )
    };
    let recovering_cause = |uow: &IncidentUnitOfWork| {
        uow.timeline()
            .iter()
            .rev()
            .find_map(|entry| match &entry.payload {
                TimelinePayload::StateChanged {
                    to: IncidentState::Recovering,
                    cause: TransitionCause::Automatic(cause),
                    ..
                } => Some(*cause),
                _ => None,
            })
            .expect("the incident entered Recovering")
    };

    let mut seen = Vec::new();
    for (detector_reason, expected, name) in [
        (
            TransitionReason::ClearSustained,
            AutomaticCause::TrafficCleared,
            "traffic_cleared",
        ),
        (
            TransitionReason::Stale,
            AutomaticCause::DetectorStale,
            "detector_stale",
        ),
        (
            TransitionReason::PolicyWithdrawn,
            AutomaticCause::PolicyWithdrawn,
            "policy_withdrawn",
        ),
        (
            TransitionReason::ManualReset,
            AutomaticCause::DetectorReset,
            "detector_reset",
        ),
    ] {
        let (mut uow, _) = uow_with_shared_clock();
        let id = uow
            .ingest_detection_event(&correlator, &started())
            .unwrap()
            .incident_id
            .unwrap();
        let mut ended = event(
            "det-end",
            1,
            EventKind::Ended,
            "acme",
            addr,
            MetricKind::Bps,
            0,
            1_000_000,
        );
        ended.reason = detector_reason;
        uow.ingest_detection_event(&correlator, &ended).unwrap();
        assert_eq!(uow.get(&id).unwrap().state, IncidentState::Recovering);
        let cause = recovering_cause(&uow);
        assert_eq!(cause, expected);
        assert_eq!(serde_json::to_value(cause).unwrap(), name);
        seen.push(cause);
    }

    // The fifth: the detector went quiet without saying the detection ended.
    let (mut uow, clock) = uow_with_shared_clock();
    let id = uow
        .ingest_detection_event(&correlator, &started())
        .unwrap()
        .incident_id
        .unwrap();
    clock.advance(Duration::from_secs(301));
    assert!(uow
        .enter_recovering_if_silent(&correlator, id, Duration::from_secs(300))
        .unwrap());
    let cause = recovering_cause(&uow);
    assert_eq!(cause, AutomaticCause::DetectorSilent);
    assert_eq!(serde_json::to_value(cause).unwrap(), "detector_silent");
    seen.push(cause);

    seen.sort_by_key(|cause| format!("{cause:?}"));
    seen.dedup();
    assert_eq!(seen.len(), 5, "five distinct causes");
}

/// Gate 2: a detector restart mid-attack yields one incident, not two. A
/// restarted detector forgets its state and opens a new detection, with a
/// new detection id and its sequence back at zero (ADR 0009). The target
/// is still under attack, so the incident it already has takes the event.
#[test]
fn a_detector_restart_mid_attack_yields_one_incident() {
    let (mut uow, _) = uow_with_shared_clock();
    let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
    let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44));
    let before = |sequence, kind| {
        event(
            "det-before-restart",
            sequence,
            kind,
            "acme",
            addr,
            MetricKind::Bps,
            9_000_000,
            1_000_000,
        )
    };
    let id = uow
        .ingest_detection_event(&correlator, &before(0, EventKind::Started))
        .unwrap()
        .incident_id
        .unwrap();
    uow.ingest_detection_event(&correlator, &before(1, EventKind::Updated))
        .unwrap();

    // The detector restarts and detects the same attack afresh.
    let after_restart = event(
        "det-after-restart",
        0,
        EventKind::Started,
        "acme",
        addr,
        MetricKind::Bps,
        9_500_000,
        1_000_000,
    );
    let result = uow
        .ingest_detection_event(&correlator, &after_restart)
        .unwrap();
    assert_eq!(
        (result.outcome_kind, result.incident_id),
        (IngestOutcomeKind::Updated, Some(id))
    );
    assert_eq!(uow.incident_count(), 1);
    assert_eq!(uow.get(&id).unwrap().state, IncidentState::Open);
}
