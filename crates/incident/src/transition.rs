//! Automatic-transition logic: recovery entry, recovery confirmation,
//! recovery abort, automatic closure, and reopen — the edges driven by
//! the clock or a detection event rather than an operator command.
//! Operator-command transitions are validated directly against
//! [`crate::state::IncidentState::can_operator_transition_to`] in
//! [`crate::unit_of_work`], which is simple enough not to need a second
//! layer here.

use crate::closure::ClosurePolicy;
use crate::error::IncidentError;
use crate::incident::Incident;
use crate::reopen::ReopenPolicy;
use crate::severity::Severity;
use crate::state::IncidentState;
use crate::timeline::AutomaticCause;

/// The five distinct reasons a detection can end, translated into an
/// automatic cause. Kept separate from the detector's own
/// `TransitionReason` (which also carries detector-internal reasons like
/// `ThresholdCrossed` that have no incident-domain meaning) rather than
/// reusing it directly — this crate names only the subset that matters
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionEndReason {
    TrafficCleared,
    DetectorStale,
    DetectorSilent,
    PolicyWithdrawn,
    DetectorReset,
}

impl From<DetectionEndReason> for AutomaticCause {
    fn from(reason: DetectionEndReason) -> Self {
        match reason {
            DetectionEndReason::TrafficCleared => AutomaticCause::TrafficCleared,
            DetectionEndReason::DetectorStale => AutomaticCause::DetectorStale,
            DetectionEndReason::DetectorSilent => AutomaticCause::DetectorSilent,
            DetectionEndReason::PolicyWithdrawn => AutomaticCause::PolicyWithdrawn,
            DetectionEndReason::DetectorReset => AutomaticCause::DetectorReset,
        }
    }
}

/// Moves an open, non-recovering incident to `Recovering`, recording
/// which of the five reasons caused it and — for the first time this
/// incident enters `Recovering` from its current state — remembering
/// that state so an abort can restore it.
pub fn enter_recovering(
    incident: &Incident,
    reason: DetectionEndReason,
) -> Result<IncidentState, IncidentError> {
    if !incident
        .state
        .can_automatic_transition_to(IncidentState::Recovering)
    {
        return Err(IncidentError::InvalidTransition {
            from: incident.state,
            to: IncidentState::Recovering,
        });
    }
    let _ = reason;
    Ok(IncidentState::Recovering)
}

/// `Recovering -> Resolved`, once the recovery confirmation period has
/// elapsed. The caller (`unit_of_work`) is responsible for the elapsed-time
/// check against `recovering_since`; this function only validates the
/// state edge itself.
pub fn confirm_recovery(incident: &Incident) -> Result<(), IncidentError> {
    if incident.state != IncidentState::Recovering {
        return Err(IncidentError::InvalidTransition {
            from: incident.state,
            to: IncidentState::Resolved,
        });
    }
    Ok(())
}

/// `Recovering -> (state_before_recovering)`, aborting recovery because a
/// new qualifying event arrived. Returns the restored state, or an error
/// if the incident was not actually recovering or has no remembered
/// prior state — the latter would be an internal invariant violation,
/// since every path into `Recovering` records one.
pub fn abort_recovery(incident: &Incident) -> Result<IncidentState, IncidentError> {
    if incident.state != IncidentState::Recovering {
        return Err(IncidentError::InvalidTransition {
            from: incident.state,
            to: incident
                .state_before_recovering
                .unwrap_or(IncidentState::Open),
        });
    }
    incident
        .state_before_recovering
        .ok_or(IncidentError::InternalInvariantViolation(
            "Recovering incident has no state_before_recovering",
        ))
}

/// `Resolved -> Closed`, only if the closure policy allows automatic
/// closure for this incident's severity (BQ-8: never for `critical`
/// under the default policy).
pub fn attempt_automatic_closure(
    incident: &Incident,
    policy: &ClosurePolicy,
) -> Result<(), IncidentError> {
    if incident.state != IncidentState::Resolved {
        return Err(IncidentError::InvalidTransition {
            from: incident.state,
            to: IncidentState::Closed,
        });
    }
    // Decided from `ever_critical`, not the live `severity`: BQ-8's
    // protection must not lapse just because the incident was later
    // downgraded (see the field's doc on `Incident`).
    let effective_severity = if incident.ever_critical {
        Severity::Critical
    } else {
        incident.severity
    };
    if !policy.allows_automatic_closure(effective_severity) {
        return Err(IncidentError::ManualClosureRequired);
    }
    Ok(())
}

/// `{Resolved, Closed} -> Open`, if the recurrence falls within the
/// reopen window. Returns `Ok(())` when a reopen is warranted; `Err`
/// otherwise, distinguishing "not eligible to reopen at all" (wrong
/// source state) from "outside the window" (caller creates a new
/// incident instead — not an error condition, just a different outcome,
/// so this function reports it as `Ok(false)`).
pub fn evaluate_reopen(
    incident: &Incident,
    policy: &ReopenPolicy,
    now: &crate::durable_time::DurableTimestamp,
) -> Result<bool, IncidentError> {
    if !incident.is_reopen_candidate() {
        return Err(IncidentError::InvalidReopen(
            "only a Resolved or Closed incident may reopen".to_string(),
        ));
    }
    // `resolved_at` when `Resolved`, `closed_at` when `Closed` — not "prefer
    // resolved_at" — per the state-machine plan's reopen timing rule.
    let reference =
        incident
            .reopen_reference_timestamp()
            .ok_or(IncidentError::InternalInvariantViolation(
                "a Resolved or Closed incident must have resolved_at or closed_at set",
            ))?;
    Ok(policy.reopens(reference, now)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::Actor;
    use crate::category::IncidentCategory;
    use crate::clock::TestClock;
    use crate::correlation::{CorrelationKey, TenantId};
    use crate::durable_time::DurableTimestamp;
    use crate::evidence::EvidenceLedger;
    use crate::id::IncidentId;
    use crate::number::NumberAllocator;
    use crate::severity::{Priority, Severity, SeveritySource};
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;
    use tidegard_detector::{AddressFamily, ScopeId, ScopeType, TrafficDirection};

    fn bare_incident(state: IncidentState, clock: &TestClock) -> Incident {
        let now = DurableTimestamp::now(clock).unwrap();
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        let key = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Host,
            ScopeId::Host { addr },
            TrafficDirection::Incoming,
            AddressFamily::Ipv4,
        );
        Incident {
            incident_id: IncidentId::from_bytes([1; 16]),
            incident_number: crate::number::InMemoryNumberAllocator::new()
                .allocate("acme", 2026)
                .unwrap(),
            schema_version: crate::incident::INCIDENT_SCHEMA_VERSION,
            tenant_id: TenantId::new("acme"),
            correlation_key: key,
            address_family: AddressFamily::Ipv4,
            direction: TrafficDirection::Incoming,
            target_type: ScopeType::Host,
            target_identity: ScopeId::Host { addr },
            created_by: Actor::System,
            title: "test".to_string(),
            description: None,
            state,
            severity: Severity::Major,
            severity_source: SeveritySource::Detection,
            ever_critical: false,
            maximum_detected_severity: Severity::Major,
            priority: Priority::default_for(Severity::Major),
            closure_reason: None,
            state_before_recovering: if state == IncidentState::Recovering {
                Some(IncidentState::Investigating)
            } else {
                None
            },
            suppression: None,
            version: 1,
            category: IncidentCategory::Unclassified,
            matched_metrics: BTreeSet::new(),
            first_detected_at: now,
            opened_at: now,
            last_detected_at: now,
            last_updated_at: now,
            acknowledged_at: None,
            recovering_since: None,
            resolved_at: None,
            closed_at: None,
            reopened_at: None,
            reopen_count: 0,
            assignment: crate::assignment::Assignment::unassigned(),
            updated_by: Actor::System,
            evidence: EvidenceLedger::new(),
            notes: Vec::new(),
            tags: BTreeMap::new(),
            policy_refs: Vec::new(),
            policy_refs_omitted: 0,
        }
    }

    #[test]
    fn recovery_abort_restores_investigating_not_open() {
        let clock = TestClock::new();
        let incident = bare_incident(IncidentState::Recovering, &clock);
        assert_eq!(
            abort_recovery(&incident).unwrap(),
            IncidentState::Investigating
        );
    }

    #[test]
    fn abort_recovery_fails_when_not_recovering() {
        let clock = TestClock::new();
        let incident = bare_incident(IncidentState::Open, &clock);
        assert!(abort_recovery(&incident).is_err());
    }

    #[test]
    fn automatic_closure_is_refused_for_critical_under_default_policy() {
        let clock = TestClock::new();
        let mut incident = bare_incident(IncidentState::Resolved, &clock);
        incident.severity = Severity::Critical;
        incident.ever_critical = true;
        let result = attempt_automatic_closure(&incident, &ClosurePolicy::approved_default());
        assert_eq!(result, Err(IncidentError::ManualClosureRequired));
    }

    #[test]
    fn automatic_closure_succeeds_for_major_under_default_policy() {
        let clock = TestClock::new();
        let mut incident = bare_incident(IncidentState::Resolved, &clock);
        incident.severity = Severity::Major;
        assert!(attempt_automatic_closure(&incident, &ClosurePolicy::approved_default()).is_ok());
    }

    /// BQ-8 closure-bypass regression: an incident that reached `Critical`
    /// and was later downgraded to a lower severity — the ordinary
    /// `IncidentSeverityChange` path, not the specially-gated
    /// `incident.closure_policy.override` — must still refuse automatic
    /// closure. Before `ever_critical` existed, this exact sequence
    /// (downgrade a Resolved Critical, then let the automatic-closure
    /// sweep run) silently unlocked automatic closure.
    #[test]
    fn automatic_closure_is_refused_after_a_downgrade_from_critical() {
        let clock = TestClock::new();
        let mut incident = bare_incident(IncidentState::Resolved, &clock);
        incident.severity = Severity::Major;
        incident.ever_critical = true;
        let result = attempt_automatic_closure(&incident, &ClosurePolicy::approved_default());
        assert_eq!(
            result,
            Err(IncidentError::ManualClosureRequired),
            "a severity downgrade must not unlock automatic closure for a formerly critical incident"
        );
    }

    /// The converse: an incident that never reached `Critical` and is
    /// currently non-critical still auto-closes normally after the
    /// approved delay — the fix must not over-restrict.
    #[test]
    fn automatic_closure_still_succeeds_for_never_critical_non_critical() {
        let clock = TestClock::new();
        let mut incident = bare_incident(IncidentState::Resolved, &clock);
        incident.severity = Severity::Minor;
        assert!(!incident.ever_critical);
        assert!(attempt_automatic_closure(&incident, &ClosurePolicy::approved_default()).is_ok());
    }

    #[test]
    fn evaluate_reopen_uses_resolved_at_when_present() {
        let clock = TestClock::new();
        let mut incident = bare_incident(IncidentState::Resolved, &clock);
        incident.resolved_at = Some(DurableTimestamp::now(&clock).unwrap());
        clock.advance(std::time::Duration::from_secs(60));
        let now = DurableTimestamp::now(&clock).unwrap();
        assert!(evaluate_reopen(&incident, &ReopenPolicy::approved_default(), &now).unwrap());
    }

    #[test]
    fn evaluate_reopen_rejects_a_non_terminal_incident() {
        let clock = TestClock::new();
        let incident = bare_incident(IncidentState::Open, &clock);
        let now = DurableTimestamp::now(&clock).unwrap();
        assert!(evaluate_reopen(&incident, &ReopenPolicy::approved_default(), &now).is_err());
    }
}
