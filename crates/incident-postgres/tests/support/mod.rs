//! Incidents built through the real unit of work, shared by the row
//! mapping tests and the PostgreSQL round-trip test.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tidegard_detector::{
    ActionTaken, AddressFamily, DataCompleteness, DetectionEvent, DetectionState, EventKind,
    EventTarget, ExecutionMode, MatchedReason, MetricKind, MetricRates, SamplingStatus, ScopeId,
    ScopeType, Severity, TestClock, TrafficDirection, TransitionReason,
};
use tidegard_incident::assignment::Assignee;
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::command::Command;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::{IncidentId, TestIncidentGenerator};
use tidegard_incident::incident::NoteVisibility;
use tidegard_incident::number::InMemoryNumberAllocator;
use tidegard_incident::severity::Priority;
use tidegard_incident::unit_of_work::IncidentUnitOfWork;

pub struct Scope {
    pub tenant: &'static str,
    pub scope_type: ScopeType,
    pub scope_id: ScopeId,
}

pub fn host_scope() -> Scope {
    Scope {
        tenant: "acme",
        scope_type: ScopeType::Host,
        scope_id: ScopeId::Host {
            addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90)),
        },
    }
}

/// A policy prefix with host bits set, which a `cidr` column rejects as is.
pub fn network_scope_with_host_bits() -> Scope {
    Scope {
        tenant: "globex",
        scope_type: ScopeType::Prefix,
        scope_id: ScopeId::Network {
            addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
            prefix_len: 24,
        },
    }
}

pub fn hostgroup_scope() -> Scope {
    Scope {
        tenant: "initech",
        scope_type: ScopeType::HostgroupTotal,
        scope_id: ScopeId::Hostgroup {
            name: "edge-routers".to_string(),
        },
    }
}

/// Every scope, each with its own tenant and id seed so all of them can
/// share one database.
pub fn all_scopes() -> Vec<(Scope, u64)> {
    vec![
        (host_scope(), 1),
        (network_scope_with_host_bits(), 1_000),
        (hostgroup_scope(), 2_000),
    ]
}

/// Same shape as `crates/incident/tests/domain_end_to_end.rs`'s builder.
pub fn event(
    scope: &Scope,
    sequence: u64,
    kind: EventKind,
    policy_id: &str,
    metric: MetricKind,
) -> DetectionEvent {
    let detection_id = "det-row";
    DetectionEvent {
        schema_version: tidegard_detector::EVENT_SCHEMA_VERSION,
        event_id: format!("{detection_id}-{sequence}"),
        detection_id: detection_id.to_string(),
        sequence,
        kind,
        dedup_key: format!("{detection_id}:{}:{sequence}", kind.as_str()),
        policy_id: policy_id.to_string(),
        policy_name: policy_id.to_string(),
        policy_version: 3,
        severity: Severity::Major,
        execution_mode: ExecutionMode::AlertOnly,
        action: ActionTaken::Alerted,
        labels: BTreeMap::new(),
        target: EventTarget {
            tenant: scope.tenant.to_string(),
            scope_type: scope.scope_type,
            scope_id: scope.scope_id.clone(),
            display: scope.scope_id.to_string(),
            direction: TrafficDirection::Incoming,
            address_family: AddressFamily::Ipv4,
        },
        previous_state: DetectionState::PendingTrigger,
        state: DetectionState::Active,
        reason: TransitionReason::TriggerSustained,
        detected_at_ms: 1_700_000_000_000 + sequence * 1_000,
        observed_at_ms: 1_700_000_000_000 + sequence * 1_000,
        duration_ms: 0,
        window_ms: 1000,
        matched: vec![MatchedReason {
            metric,
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
        summary: format!("major {} under policy {policy_id}", scope.scope_id),
    }
}

pub fn operator(tenant: &str) -> AuthorizationContext {
    AuthorizationContext::new(
        TenantId::new(tenant),
        Actor::Operator {
            id: "op-7".to_string(),
        },
        // Tags need `IncidentUpdate`, which no human default bundle holds.
        FixedBundleResolver
            .permissions_for("noc_lead")
            .into_iter()
            .chain([tidegard_incident::authorization::Permission::IncidentUpdate])
            .collect(),
    )
}

/// Runs one operator command against the incident's current version.
pub fn run(
    uow: &mut IncidentUnitOfWork,
    auth: &AuthorizationContext,
    id: IncidentId,
    command: impl FnOnce(u64) -> Command,
) {
    let version = uow.get(&id).expect("incident exists").version;
    uow.handle_command(auth, id, command(version), None)
        .expect("command must succeed");
}

/// One incident with two policy references, an acknowledgement, an
/// assignee, a suppression, a note and two tags, so most nullable
/// columns and every child table carry a value.
pub fn worked_incident(scope: &Scope, seed: u64) -> (IncidentUnitOfWork, IncidentId) {
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(seed)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    );
    let correlator = AuthorizationContext::correlator(TenantId::new(scope.tenant));
    let id = uow
        .ingest_detection_event(
            &correlator,
            &event(scope, 1, EventKind::Started, "p-opening", MetricKind::Bps),
        )
        .expect("opening event ingests")
        .incident_id
        .expect("opening event creates an incident");
    uow.ingest_detection_event(
        &correlator,
        &event(
            scope,
            2,
            EventKind::Updated,
            "p-second",
            MetricKind::TcpSynPps,
        ),
    )
    .expect("update event ingests");

    let operator = operator(scope.tenant);
    run(&mut uow, &operator, id, |v| Command::AcknowledgeIncident {
        expected_version: v,
    });
    run(&mut uow, &operator, id, |v| Command::AssignIncident {
        expected_version: v,
        assignee: Assignee::User {
            id: "op-7".to_string(),
        },
    });
    run(&mut uow, &operator, id, |v| Command::SuppressIncident {
        expected_version: v,
        reason: "known scanner".to_string(),
        duration: Duration::from_secs(3600),
    });
    run(&mut uow, &operator, id, |v| Command::ChangePriority {
        expected_version: v,
        new_priority: Priority::P1,
    });
    run(&mut uow, &operator, id, |_| Command::AddNote {
        body: "first look".to_string(),
        visibility: NoteVisibility::Internal,
    });
    run(&mut uow, &operator, id, |_| Command::AddTag {
        key: "customer".to_string(),
        value: "acme-core".to_string(),
    });
    run(&mut uow, &operator, id, |_| Command::AddTag {
        key: "site".to_string(),
        value: "dhaka-1".to_string(),
    });
    (uow, id)
}

/// `event` as part of another detection episode: a recurrence carries a
/// new detection id (ADR 0009), and only a new episode may reopen a
/// resolved incident (T-18).
pub fn in_episode(mut event: DetectionEvent, detection_id: &str) -> DetectionEvent {
    event.event_id = format!("{detection_id}-{}", event.sequence);
    event.dedup_key = format!("{detection_id}:{}:{}", event.kind.as_str(), event.sequence);
    event.detection_id = detection_id.to_string();
    event
}
