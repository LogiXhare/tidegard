//! The Phase 5F security review: the domain-level tests the
//! [threat model](../../../docs/security/incident-threat-model.md) names,
//! one section per threat. PostgreSQL- and API-level threats are tested
//! where those layers are; `docs/security/incident-threat-tests.md` maps
//! every threat to its tests.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use proptest::prelude::*;
use wetechinetmon_detector::{
    ActionTaken, AddressFamily, DataCompleteness, DetectionEvent, DetectionState, EventKind,
    EventTarget, ExecutionMode, MatchedReason, MetricKind, MetricRates, SamplingStatus, ScopeId,
    ScopeType, Severity, TestClock, TrafficDirection, TransitionReason,
};
use wetechinetmon_incident::assignment::Assignee;
use wetechinetmon_incident::audit::{AttemptedResource, AuditOutcome, FieldChange};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, Permission, PermissionResolver,
};
use wetechinetmon_incident::closure::ClosureReason;
use wetechinetmon_incident::command::Command;
use wetechinetmon_incident::correlation::{CorrelationKey, TenantId};
use wetechinetmon_incident::error::IncidentError;
use wetechinetmon_incident::id::{IncidentId, TestIncidentGenerator};
use wetechinetmon_incident::incident::NoteVisibility;
use wetechinetmon_incident::number::InMemoryNumberAllocator;
use wetechinetmon_incident::severity::Priority;
use wetechinetmon_incident::state::IncidentState;
use wetechinetmon_incident::timeline::TimelinePayload;
use wetechinetmon_incident::unit_of_work::{IncidentUnitOfWork, IngestOutcomeKind};

fn uow() -> IncidentUnitOfWork {
    IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    )
}

fn event(detection_id: &str, sequence: u64, kind: EventKind, addr: IpAddr) -> DetectionEvent {
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
            tenant: "acme".to_string(),
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
        matched: vec![MatchedReason {
            metric: MetricKind::Bps,
            observed: 5_000_000,
            threshold: 1_000_000,
            excess: 4_000_000,
            ratio_percent: 500,
        }],
        peak: Vec::new(),
        skipped: Vec::new(),
        rates: MetricRates::default(),
        completeness: DataCompleteness::default(),
        sampling: SamplingStatus::default(),
        flows_observed: 1,
        exporters_observed: 1,
        snapshots_in_detection: 1,
        executed: false,
        summary: "test".to_string(),
    }
}

const ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 60));

fn correlator() -> AuthorizationContext {
    AuthorizationContext::correlator(TenantId::new("acme"))
}

fn role(name: &str) -> AuthorizationContext {
    AuthorizationContext::new(
        TenantId::new("acme"),
        Actor::Operator {
            id: format!("u-{name}"),
        },
        FixedBundleResolver.permissions_for(name),
    )
}

/// A fresh unit of work holding one open incident.
fn opened() -> (IncidentUnitOfWork, IncidentId, u64) {
    let mut uow = uow();
    let id = uow
        .ingest_detection_event(&correlator(), &event("det-1", 0, EventKind::Started, ADDR))
        .unwrap()
        .incident_id
        .unwrap();
    let version = uow.get(&id).unwrap().version;
    (uow, id, version)
}

/// Every operator command, built for the incident's current version.
fn every_command(version: u64) -> Vec<Command> {
    vec![
        Command::AcknowledgeIncident {
            expected_version: version,
        },
        Command::BeginInvestigation {
            expected_version: version,
        },
        Command::MarkMonitoring {
            expected_version: version,
        },
        Command::ResolveIncident {
            expected_version: version,
            resolution_note: None,
        },
        Command::CloseIncident {
            expected_version: version,
            reason: ClosureReason::Resolved,
            detail: None,
        },
        Command::ReopenIncident {
            expected_version: version,
            reason: "recurred".into(),
        },
        Command::SuppressIncident {
            expected_version: version,
            reason: "maintenance".into(),
            duration: Duration::from_secs(3_600),
        },
        Command::UnsuppressIncident {
            expected_version: version,
        },
        Command::AssignIncident {
            expected_version: version,
            assignee: Assignee::User { id: "u_1".into() },
        },
        Command::UnassignIncident {
            expected_version: version,
        },
        Command::ChangeSeverity {
            expected_version: version,
            new_severity: Severity::Minor,
            reason: Some("subsided".into()),
        },
        Command::ChangePriority {
            expected_version: version,
            new_priority: Priority::P4,
        },
        Command::AddNote {
            body: "note".into(),
            visibility: NoteVisibility::Internal,
        },
        Command::EditNote {
            note_index: 0,
            body: "edited".into(),
        },
        Command::RedactNote {
            note_index: 0,
            reason: "pasted a credential".into(),
        },
        Command::AddTag {
            key: "env".into(),
            value: "prod".into(),
        },
        Command::RemoveTag { key: "env".into() },
    ]
}

// --- T-01 Forged detection event, and T-06 Unauthorized state transition ---

/// Every command × every role, plus the ingestion credential: a command
/// is refused exactly when the role lacks its permission, a refusal
/// changes nothing and is audited, and the ingestion credential can
/// drive no operator command at all.
#[test]
fn every_command_is_allowed_exactly_by_its_permission_for_every_role() {
    let contexts = [
        ("viewer", role("viewer")),
        ("operator", role("operator")),
        ("senior_operator", role("senior_operator")),
        ("noc_lead", role("noc_lead")),
        ("ingestion", correlator()),
    ];
    let mut checked = 0;
    for (name, context) in &contexts {
        for index in 0..every_command(1).len() {
            let (mut uow, id, version) = opened();
            let command = every_command(version).remove(index);
            let permission = command.required_permission();
            let result = uow.handle_command(context, id, command.clone(), None);
            if context.has(permission) {
                assert_ne!(
                    result,
                    Err(IncidentError::Unauthorized),
                    "{name} holds {permission:?} but {command:?} was refused"
                );
            } else {
                assert_eq!(
                    result,
                    Err(IncidentError::Unauthorized),
                    "{name} lacks {permission:?} but {command:?} was allowed"
                );
                assert_eq!(
                    uow.get(&id).unwrap().version,
                    version,
                    "a refusal changes nothing"
                );
                let last = uow.audit().last().unwrap();
                assert_eq!(last.outcome, AuditOutcome::Denied, "a refusal is audited");
                assert_eq!(last.permission, permission);
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 5 * 17);
    // T-01 in one line: the ingestion credential holds no operator permission.
    for command in every_command(1) {
        assert!(
            !correlator().has(command.required_permission()),
            "{command:?}"
        );
    }
}

// --- Notes: edits supersede, redaction is recorded (FU-63) ---

fn add_note(uow: &mut IncidentUnitOfWork, id: IncidentId, who: &str, body: &str) {
    uow.handle_command(
        &role(who),
        id,
        Command::AddNote {
            body: body.into(),
            visibility: NoteVisibility::Internal,
        },
        None,
    )
    .unwrap();
}

fn edit(
    uow: &mut IncidentUnitOfWork,
    id: IncidentId,
    who: &str,
    note_index: u32,
) -> Result<u64, IncidentError> {
    uow.handle_command(
        &role(who),
        id,
        Command::EditNote {
            note_index,
            body: format!("edit of {note_index}"),
        },
        None,
    )
}

fn redact(
    uow: &mut IncidentUnitOfWork,
    id: IncidentId,
    who: &str,
    note_index: u32,
    reason: &str,
) -> Result<u64, IncidentError> {
    uow.handle_command(
        &role(who),
        id,
        Command::RedactNote {
            note_index,
            reason: reason.into(),
        },
        None,
    )
}

/// An edit appends; the original stays, so what was first written
/// survives. A note is replaced once, and the replacement can be edited.
#[test]
fn an_edit_appends_a_new_note_and_keeps_the_original() {
    let (mut uow, id, _) = opened();
    add_note(&mut uow, id, "operator", "upstream says spoofed");
    let before = uow.get(&id).unwrap().version;

    assert_eq!(edit(&mut uow, id, "operator", 0), Ok(before + 1));
    let incident = uow.get(&id).unwrap();
    assert_eq!(incident.notes.len(), 2);
    assert_eq!(incident.notes[0].body, "upstream says spoofed");
    assert_eq!(incident.notes[1].body, "edit of 0");
    assert_eq!(incident.notes[1].supersedes, Some(0));
    assert_eq!(incident.notes[1].visibility, NoteVisibility::Internal);
    assert_eq!(incident.note_superseded_by(0), Some(1));
    assert_eq!(
        uow.timeline().last().unwrap().payload,
        TimelinePayload::NoteSuperseded {
            note_index: 0,
            by_note_index: 1
        }
    );
    let audited = uow.audit().last().unwrap();
    assert_eq!(
        (audited.outcome, audited.permission),
        (AuditOutcome::Allowed, Permission::IncidentNoteCreate)
    );

    assert!(matches!(
        edit(&mut uow, id, "operator", 0),
        Err(IncidentError::ValidationError(_))
    ));
    assert!(matches!(
        edit(&mut uow, id, "operator", 9),
        Err(IncidentError::ValidationError(_))
    ));
    assert_eq!(edit(&mut uow, id, "operator", 1), Ok(before + 2));
    assert_eq!(uow.get(&id).unwrap().notes[2].supersedes, Some(1));
}

/// Holding `incident.note.create` is not enough to replace someone
/// else's words: the attempt is refused, changes nothing, and is audited.
#[test]
fn only_the_author_may_edit_a_note() {
    let (mut uow, id, _) = opened();
    add_note(&mut uow, id, "operator", "mine");
    let before = uow.get(&id).unwrap().version;
    for other in ["senior_operator", "noc_lead"] {
        assert_eq!(
            edit(&mut uow, id, other, 0),
            Err(IncidentError::Unauthorized)
        );
        let audited = uow.audit().last().unwrap();
        assert_eq!(audited.outcome, AuditOutcome::Denied);
        assert_eq!(audited.permission, Permission::IncidentNoteCreate);
        assert_eq!(audited.resource, AttemptedResource::Incident(id));
    }
    assert_eq!(uow.get(&id).unwrap().version, before);
    assert_eq!(uow.get(&id).unwrap().notes.len(), 1);
}

/// Redaction removes the words and keeps the record: who, why, and that
/// the note existed. The reason is on the audit trail, not the timeline,
/// and the removed words are nowhere.
#[test]
fn redaction_needs_its_permission_and_a_reason_and_keeps_the_record() {
    let (mut uow, id, _) = opened();
    add_note(&mut uow, id, "operator", "router password is hunter2");
    edit(&mut uow, id, "operator", 0).unwrap();
    let before = uow.get(&id).unwrap().version;

    // The author cannot redact; only noc_lead and above hold the permission.
    for lacking in ["operator", "senior_operator"] {
        assert_eq!(
            redact(&mut uow, id, lacking, 0, "credential"),
            Err(IncidentError::Unauthorized)
        );
    }
    assert!(matches!(
        redact(&mut uow, id, "noc_lead", 0, "  "),
        Err(IncidentError::ValidationError(_))
    ));
    assert!(matches!(
        redact(&mut uow, id, "noc_lead", 0, &"r".repeat(501)),
        Err(IncidentError::ValidationError(_))
    ));
    assert!(matches!(
        redact(&mut uow, id, "noc_lead", 7, "credential"),
        Err(IncidentError::ValidationError(_))
    ));
    assert_eq!(uow.get(&id).unwrap().version, before);

    // A superseded note can be redacted: the words are in the original.
    assert_eq!(
        redact(&mut uow, id, "noc_lead", 0, "pasted a credential"),
        Ok(before + 1)
    );
    let note = &uow.get(&id).unwrap().notes[0];
    assert_eq!(note.body, "");
    let redaction = note.redaction.as_ref().unwrap();
    assert_eq!(
        redaction.by,
        Actor::Operator {
            id: "u-noc_lead".into()
        }
    );
    assert_eq!(redaction.reason, "pasted a credential");
    assert_eq!(
        uow.timeline().last().unwrap().payload,
        TimelinePayload::NoteRedacted { note_index: 0 }
    );
    let audited = uow.audit().last().unwrap();
    assert_eq!(audited.outcome, AuditOutcome::Allowed);
    assert_eq!(audited.permission, Permission::IncidentNoteRedact);
    assert_eq!(audited.reason.as_deref(), Some("pasted a credential"));
    let everything = format!(
        "{:?}{:?}{:?}",
        uow.get(&id).unwrap(),
        uow.timeline(),
        uow.audit()
    );
    assert!(!everything.contains("hunter2"));

    // Once only, and a redacted note cannot be edited back.
    assert!(matches!(
        redact(&mut uow, id, "noc_lead", 0, "again"),
        Err(IncidentError::ValidationError(_))
    ));
    add_note(&mut uow, id, "operator", "second");
    redact(&mut uow, id, "noc_lead", 2, "wrong incident").unwrap();
    assert!(matches!(
        edit(&mut uow, id, "operator", 2),
        Err(IncidentError::ValidationError(_))
    ));
}

// --- T-03 Correlation-key collision ---

fn host_key(tenant: &str, addr: Ipv4Addr) -> CorrelationKey {
    CorrelationKey::new(
        TenantId::new(tenant),
        ScopeType::Host,
        ScopeId::Host {
            addr: IpAddr::V4(addr),
        },
        TrafficDirection::Incoming,
        AddressFamily::Ipv4,
    )
}

proptest! {
    /// The key is typed, never a rendered string: the same target always
    /// gives one key, and different addresses, tenants, scopes or
    /// directions never collide.
    #[test]
    fn equal_targets_share_a_key_and_different_ones_never_do(a in any::<u32>(), b in any::<u32>()) {
        let (a, b) = (Ipv4Addr::from(a), Ipv4Addr::from(b));
        prop_assert_eq!(host_key("acme", a), host_key("acme", a));
        prop_assert_eq!(host_key("acme", a) == host_key("acme", b), a == b);
        prop_assert_ne!(host_key("acme", a), host_key("globex", a));
        let as_network = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Prefix,
            ScopeId::Network { addr: IpAddr::V4(a), prefix_len: 32 },
            TrafficDirection::Incoming,
            AddressFamily::Ipv4,
        );
        prop_assert_ne!(host_key("acme", a), as_network, "a /32 is not the host");
        let mut outgoing = host_key("acme", a);
        outgoing.direction = TrafficDirection::Outgoing;
        prop_assert_ne!(host_key("acme", a), outgoing);
    }
}

// --- T-19 Unauthorized suppression ---

/// A suppressed incident still ingests, links and counts: suppression
/// hides nothing from the record.
/// Gate 2: `executed` stays false on every linked event. Nothing in this
/// release can act on traffic, so an event claiming it did is quarantined
/// and changes nothing.
#[test]
fn an_event_claiming_an_executed_action_is_quarantined_and_never_linked() {
    let mut fresh = uow();
    let mut forged = event("det-9", 0, EventKind::Started, ADDR);
    forged.executed = true;
    let result = fresh
        .ingest_detection_event(&correlator(), &forged)
        .unwrap();
    assert_eq!(
        (result.outcome_kind, result.incident_id),
        (IngestOutcomeKind::Quarantined, None)
    );

    let (mut uow, id, version) = opened();
    let mut update = event("det-1", 1, EventKind::Updated, ADDR);
    update.executed = true;
    let result = uow.ingest_detection_event(&correlator(), &update).unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Quarantined);
    assert_eq!(uow.get(&id).unwrap().version, version, "nothing was linked");
    // The genuine event with the same identity still links afterwards.
    let genuine = event("det-1", 1, EventKind::Updated, ADDR);
    let result = uow.ingest_detection_event(&correlator(), &genuine).unwrap();
    assert_eq!(result.outcome_kind, IngestOutcomeKind::Updated);
}

#[test]
fn a_suppressed_incident_still_accumulates_events() {
    let (mut uow, id, version) = opened();
    uow.handle_command(
        &role("noc_lead"),
        id,
        Command::SuppressIncident {
            expected_version: version,
            reason: "maintenance".into(),
            duration: Duration::from_secs(3_600),
        },
        None,
    )
    .unwrap();
    let before = uow.get(&id).unwrap().evidence.observed_total();
    let linked = uow
        .ingest_detection_event(&correlator(), &event("det-1", 1, EventKind::Updated, ADDR))
        .unwrap();
    assert_eq!(linked.outcome_kind, IngestOutcomeKind::Updated);
    assert_eq!(linked.incident_id, Some(id));
    let incident = uow.get(&id).unwrap();
    assert_eq!(incident.evidence.observed_total(), before + 1);
    assert!(incident.suppression.is_some(), "still suppressed");
    // Suppression is not in the operator's or senior operator's bundle.
    for name in ["viewer", "operator", "senior_operator"] {
        let (mut uow, id, version) = opened();
        let refused = uow.handle_command(
            &role(name),
            id,
            Command::SuppressIncident {
                expected_version: version,
                reason: "hide it".into(),
                duration: Duration::from_secs(60),
            },
            None,
        );
        assert_eq!(refused, Err(IncidentError::Unauthorized), "{name}");
    }
}

// --- T-20 Unauthorized severity reduction ---

/// Lowering needs a reason; every change records who, from and to, both
/// on the timeline entry and on the audit entry (FU-59), so the audit
/// trail alone is the control the threat model asks for.
#[test]
fn lowering_severity_needs_a_reason_and_records_both_values() {
    let (mut uow, id, version) = opened();
    let senior = role("senior_operator");
    let refused = uow.handle_command(
        &senior,
        id,
        Command::ChangeSeverity {
            expected_version: version,
            new_severity: Severity::Info,
            reason: None,
        },
        None,
    );
    assert!(
        matches!(refused, Err(IncidentError::ValidationError(_))),
        "{refused:?}"
    );
    assert_eq!(uow.get(&id).unwrap().severity, Severity::Major, "unchanged");

    uow.handle_command(
        &senior,
        id,
        Command::ChangeSeverity {
            expected_version: version,
            new_severity: Severity::Info,
            reason: Some("upstream filtered it".into()),
        },
        None,
    )
    .unwrap();
    let change = uow
        .timeline()
        .iter()
        .rev()
        .find_map(|entry| match &entry.payload {
            TimelinePayload::SeverityChanged { from, to, reason } => {
                Some((entry.actor.clone(), *from, *to, reason.clone()))
            }
            _ => None,
        })
        .expect("a severity-change timeline entry");
    assert_eq!(
        change,
        (
            Actor::Operator {
                id: "u-senior_operator".into()
            },
            Severity::Major,
            Severity::Info,
            Some("upstream filtered it".to_string())
        )
    );
    let audited = uow.audit().last().unwrap();
    assert_eq!(audited.outcome, AuditOutcome::Allowed);
    assert_eq!(audited.resource, AttemptedResource::Incident(id));
    assert_eq!(
        audited.change,
        Some(FieldChange {
            field: "severity".into(),
            before: "major".into(),
            after: "info".into(),
        })
    );
    assert_eq!(audited.reason.as_deref(), Some("upstream filtered it"));
}

// --- T-13 Optimistic-lock bypass (domain half) ---

/// Every state-changing command is versioned, and a stale version
/// changes nothing.
#[test]
fn every_transition_needs_the_current_version() {
    for command in every_command(1) {
        if !command.requires_expected_version() {
            assert!(matches!(
                command,
                Command::AddNote { .. }
                    | Command::EditNote { .. }
                    | Command::RedactNote { .. }
                    | Command::AddTag { .. }
                    | Command::RemoveTag { .. }
            ));
            continue;
        }
        let (mut uow, id, version) = opened();
        let stale = every_command(version + 7)
            .into_iter()
            .find(|c| c.kind() == command.kind())
            .unwrap();
        let refused = uow.handle_command(&role("noc_lead"), id, stale, None);
        assert!(
            matches!(refused, Err(IncidentError::VersionConflict { .. })),
            "{command:?}: {refused:?}"
        );
        assert_eq!(uow.get(&id).unwrap().version, version);
        assert_eq!(uow.get(&id).unwrap().state, IncidentState::Open);
    }
}
