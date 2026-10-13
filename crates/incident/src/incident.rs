//! The `Incident` aggregate.
//!
//! Every field is `pub`, so this is discipline, not a type-system
//! guarantee: nothing here stops code that already holds `&mut Incident`
//! from setting a field directly and skipping a guard, a version bump, a
//! timeline entry, and an audit entry. What *does* hold is narrower than
//! that — no code outside this crate can ever obtain `&mut Incident` in
//! the first place, because [`crate::unit_of_work::IncidentUnitOfWork`]
//! keeps its incident map private and its only public accessor,
//! [`crate::unit_of_work::IncidentUnitOfWork::get`], returns `&Incident`.
//! Every external mutation path is therefore forced through a typed
//! command and [`crate::transition`]'s guards. Within the crate,
//! [`crate::unit_of_work`] is the only module that takes `&mut Incident`
//! with intent to change it, and each of its mutation sites is expected
//! to pair the field write with a version bump, a timeline entry, and an
//! audit entry — but that pairing is convention, verified by tests, not
//! something the compiler enforces (see FU-30's sibling entries in
//! `docs/development/follow-ups.md` for the specific sites reviewed).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tidegard_detector::{AddressFamily, MetricKind, ScopeId, ScopeType, TrafficDirection};

use crate::assignment::Assignment;
use crate::authorization::Actor;
use crate::category::IncidentCategory;
use crate::closure::ClosureReason;
use crate::correlation::{CorrelationKey, TenantId};
use crate::durable_time::DurableTimestamp;
use crate::evidence::EvidenceLedger;
use crate::id::IncidentId;
use crate::limits::{
    DESCRIPTION_MAX_LEN, NOTES_PER_INCIDENT_MAX, NOTE_BODY_MAX_LEN, NOTE_REDACTION_REASON_MAX_LEN,
    POLICY_REFS_MAX, TAGS_PER_INCIDENT_MAX, TITLE_MAX_LEN,
};
use crate::number::IncidentNumber;
use crate::severity::{Priority, Severity, SeveritySource};
use crate::state::IncidentState;
use crate::suppression::Suppression;

pub const INCIDENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteVisibility {
    Internal,
    /// Stored, never honoured in Phase 5A — there is no customer-facing
    /// surface and no tenant authorization model to decide who may
    /// publish to one. A command requesting this is refused.
    CustomerVisible,
}

/// Notes are immutable with supersession (incident-persistence.md): an
/// edit appends a new note that names the one it replaces, so the record
/// of what the operator first wrote survives. A redaction is the one
/// in-place change, and it is itself recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub index: u32,
    /// Empty once the note is redacted.
    pub body: String,
    pub visibility: NoteVisibility,
    pub created_by: Actor,
    /// The earlier note this one replaces, when it is an edit.
    #[serde(default)]
    pub supersedes: Option<u32>,
    #[serde(default)]
    pub redaction: Option<NoteRedaction>,
}

impl Note {
    pub fn new(index: u32, body: String, visibility: NoteVisibility, created_by: Actor) -> Self {
        Note {
            index,
            body,
            visibility,
            created_by,
            supersedes: None,
            redaction: None,
        }
    }
}

/// Who removed a note's body, and why. The reason is required, because
/// removing an operator's words must itself be explainable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteRedaction {
    pub by: Actor,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub policy_id: String,
    pub policy_version: u32,
    pub first_seen_sequence: u64,
    pub last_seen_sequence: u64,
}

/// The aggregate. `pub(crate)` mutation is the norm; only
/// [`crate::transition`] and [`crate::unit_of_work`] hold `&mut Incident`
/// with intent to change it, and every path they use also appends a
/// timeline entry, an audit entry, and bumps `version`.
#[derive(Debug, Clone, PartialEq)]
pub struct Incident {
    // Identity — immutable after creation.
    pub incident_id: IncidentId,
    pub incident_number: IncidentNumber,
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub correlation_key: CorrelationKey,
    pub address_family: AddressFamily,
    pub direction: TrafficDirection,
    pub target_type: ScopeType,
    pub target_identity: ScopeId,
    pub created_by: Actor,

    // Title/description — derived-then-mutable.
    pub title: String,
    pub description: Option<String>,

    // State and priority.
    pub state: IncidentState,
    pub severity: Severity,
    pub severity_source: SeveritySource,
    /// Whether this incident has ever reached `Critical`, tracked
    /// independently of the current, operator-mutable `severity` field.
    /// BQ-8's manual-closure protection is decided from this, not from
    /// `severity` directly: the approved decision states "there is no
    /// path by which the protection lapses silently", so a routine
    /// severity downgrade — which only requires `IncidentSeverityChange`,
    /// not the specially-gated `incident.closure_policy.override` — must
    /// not be able to quietly unlock automatic closure for an incident
    /// that was, at some point, `Critical`. Set on creation and on every
    /// severity change that reaches `Critical`; never cleared in 5A, since
    /// no permissioned override exists yet to clear it safely (5B).
    pub ever_critical: bool,
    /// The highest severity any detection event has reported for this
    /// incident — monotonic, and never written by the operator
    /// `ChangeSeverity` command (that changes `severity`, not what was
    /// detected). Persisted as `incidents.maximum_detected_severity`
    /// (incident-persistence.md, FU-47). Today only incident creation sets
    /// it, from the opening event: raising it when a later event links in
    /// is FU-41's detection-driven escalation, which must move this,
    /// `ever_critical`, and the closure decision together (Milestone 5C).
    pub maximum_detected_severity: Severity,
    pub priority: Priority,
    pub closure_reason: Option<ClosureReason>,
    pub(crate) state_before_recovering: Option<IncidentState>,
    pub suppression: Option<Suppression>,
    pub version: u64,

    // Category — derived, recomputed on every linked event.
    pub category: IncidentCategory,
    pub(crate) matched_metrics: BTreeSet<MetricKind>,

    // Timestamps.
    pub first_detected_at: DurableTimestamp,
    pub opened_at: DurableTimestamp,
    pub last_detected_at: DurableTimestamp,
    pub last_updated_at: DurableTimestamp,
    pub acknowledged_at: Option<DurableTimestamp>,
    pub recovering_since: Option<DurableTimestamp>,
    pub resolved_at: Option<DurableTimestamp>,
    pub closed_at: Option<DurableTimestamp>,
    pub reopened_at: Option<DurableTimestamp>,
    pub reopen_count: u32,

    // Ownership.
    pub assignment: Assignment,
    pub updated_by: Actor,

    // Evidence, notes, tags, policy references — all bounded.
    pub evidence: EvidenceLedger,
    pub notes: Vec<Note>,
    pub tags: BTreeMap<String, String>,
    pub policy_refs: Vec<PolicyRef>,
    /// Linked events whose policy was not recorded in `policy_refs` because
    /// it already held `POLICY_REFS_MAX` distinct policies (FU-34). Counts
    /// events, not distinct policies, the way the evidence ledger counts
    /// what it stops retaining, so an omission is never silent.
    pub policy_refs_omitted: u64,
}

impl Incident {
    /// Whether this incident is "open" for correlation purposes — any
    /// state other than `Closed`.
    pub fn is_open_for_correlation(&self) -> bool {
        !self.state.is_terminal()
    }

    /// Whether this incident is eligible to be the target of a recurrence
    /// reopen — `Resolved` or `Closed`. Distinct from "terminal"
    /// (`Closed` only): a `Resolved` incident is not terminal but is
    /// removed from the active correlation index the moment it resolves,
    /// so the reopen-candidate search must use this predicate, not
    /// `!state.is_terminal()` and not `state.is_terminal()` — see the
    /// state machine plan's "a `Resolved` incident may be reopened, not
    /// only a `Closed` one".
    pub fn is_reopen_candidate(&self) -> bool {
        matches!(self.state, IncidentState::Resolved | IncidentState::Closed)
    }

    /// The timestamp a reopen decision measures elapsed time from:
    /// `resolved_at` when `Resolved`, `closed_at` when `Closed`. `None`
    /// for any other state, which callers treat as "not eligible".
    pub fn reopen_reference_timestamp(&self) -> Option<&DurableTimestamp> {
        match self.state {
            IncidentState::Resolved => self.resolved_at.as_ref(),
            IncidentState::Closed => self.closed_at.as_ref(),
            _ => None,
        }
    }

    pub fn is_suppressed(&self, now: &DurableTimestamp) -> bool {
        self.suppression.as_ref().is_some_and(|s| s.is_active(now))
    }

    pub fn notes_at_capacity(&self) -> bool {
        self.notes.len() >= NOTES_PER_INCIDENT_MAX
    }

    /// The note that replaced note `index`, if it has been edited.
    pub fn note_superseded_by(&self, index: u32) -> Option<u32> {
        self.notes
            .iter()
            .find(|note| note.supersedes == Some(index))
            .map(|note| note.index)
    }

    pub fn tags_at_capacity(&self) -> bool {
        self.tags.len() >= TAGS_PER_INCIDENT_MAX
    }

    pub fn policy_refs_at_capacity(&self) -> bool {
        self.policy_refs.len() >= POLICY_REFS_MAX
    }
}

/// Validates a title against its bound. Returns the owned, validated
/// string so a caller cannot construct an `Incident` with an oversized
/// one by accident.
pub fn validate_title(title: &str) -> Result<(), crate::error::IncidentError> {
    if title.chars().count() > TITLE_MAX_LEN {
        return Err(crate::error::IncidentError::ValidationError(format!(
            "title exceeds {TITLE_MAX_LEN} characters"
        )));
    }
    Ok(())
}

pub fn validate_description(description: &str) -> Result<(), crate::error::IncidentError> {
    if description.chars().count() > DESCRIPTION_MAX_LEN {
        return Err(crate::error::IncidentError::ValidationError(format!(
            "description exceeds {DESCRIPTION_MAX_LEN} characters"
        )));
    }
    Ok(())
}

pub fn validate_note_body(body: &str) -> Result<(), crate::error::IncidentError> {
    if body.chars().count() > NOTE_BODY_MAX_LEN {
        return Err(crate::error::IncidentError::ValidationError(format!(
            "note body exceeds {NOTE_BODY_MAX_LEN} characters"
        )));
    }
    Ok(())
}

pub fn validate_redaction_reason(reason: &str) -> Result<(), crate::error::IncidentError> {
    if reason.trim().is_empty() {
        return Err(crate::error::IncidentError::ValidationError(
            "a redaction needs a reason".to_string(),
        ));
    }
    if reason.chars().count() > NOTE_REDACTION_REASON_MAX_LEN {
        return Err(crate::error::IncidentError::ValidationError(format!(
            "redaction reason exceeds {NOTE_REDACTION_REASON_MAX_LEN} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_title_at_exactly_the_bound_is_valid() {
        let title: String = "a".repeat(TITLE_MAX_LEN);
        assert!(validate_title(&title).is_ok());
    }

    #[test]
    fn a_title_one_over_the_bound_is_rejected() {
        let title: String = "a".repeat(TITLE_MAX_LEN + 1);
        assert!(validate_title(&title).is_err());
    }

    #[test]
    fn a_note_body_over_the_bound_is_rejected() {
        let body: String = "a".repeat(NOTE_BODY_MAX_LEN + 1);
        assert!(validate_note_body(&body).is_err());
    }
}
