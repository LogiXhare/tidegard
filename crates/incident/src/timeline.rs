//! The append-only timeline.
//!
//! Owner decision: no raw `serde_json::Value` as the primary payload.
//! [`TimelinePayload`] is a typed enum — a domain mutation can only ever
//! produce a structurally valid entry, because there is no variant that
//! accepts an arbitrary bag of JSON. [`TimelineEntry::payload_json`]
//! serializes to JSON **at the boundary**, for a future API or export
//! path; nothing inside this crate stores or compares JSON directly.

use serde::{Deserialize, Serialize};

use crate::assignment::Assignee;
use crate::authorization::Actor;
use crate::category::IncidentCategory;
use crate::evidence::EvidenceReference;
use crate::id::IncidentId;
use crate::severity::{Priority, Severity};
use crate::state::IncidentState;

pub const TIMELINE_ENTRY_LIMIT: usize = 50_000;

/// Why an automatic transition happened. Mirrors the five distinct end
/// reasons the correlation and state-machine plans require an operator
/// be able to tell apart, plus the other clock- and event-driven causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticCause {
    TrafficCleared,
    DetectorStale,
    DetectorSilent,
    PolicyWithdrawn,
    DetectorReset,
    RecoveryConfirmed,
    RecoveryAborted,
    AutomaticClosure,
    ReopenedByRecurrence,
}

/// Which operator command caused a mutation, for attribution on entries
/// that a human, not the correlator, produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCommandKind {
    Acknowledge,
    BeginInvestigation,
    MarkMonitoring,
    Resolve,
    Close,
    Reopen,
    Suppress,
    Unsuppress,
    Assign,
    Unassign,
    Claim,
    Release,
    AddNote,
    EditNote,
    RedactNote,
    ChangeSeverity,
    ChangePriority,
    AddTag,
    RemoveTag,
    UpdateDetails,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionCause {
    Automatic(AutomaticCause),
    Operator(OperatorCommandKind),
}

/// The structurally typed content of one timeline entry. Every variant
/// carries exactly the data that kind of event has, so a reader never
/// has to guess a shape out of an untyped payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelinePayload {
    Opened,
    EventLinked {
        evidence: EvidenceReference,
    },
    LateEventLinked {
        evidence: EvidenceReference,
    },
    DuplicateIgnored {
        dedup_key: String,
    },
    StateChanged {
        from: IncidentState,
        to: IncidentState,
        cause: TransitionCause,
    },
    CategoryChanged {
        from: IncidentCategory,
        to: IncidentCategory,
    },
    SeverityChanged {
        from: Severity,
        to: Severity,
        reason: Option<String>,
    },
    PriorityChanged {
        from: Priority,
        to: Priority,
    },
    AssignmentChanged {
        from: Option<Assignee>,
        to: Option<Assignee>,
    },
    NoteAdded {
        note_index: u32,
    },
    /// An edit: note `by_note_index` replaces note `note_index`.
    NoteSuperseded {
        note_index: u32,
        by_note_index: u32,
    },
    /// The reason is on the audit entry, not here: the timeline is read
    /// more widely than the audit trail.
    NoteRedacted {
        note_index: u32,
    },
    Suppressed {
        reason: String,
    },
    Unsuppressed,
    Reopened {
        reopen_count: u32,
        previous_incident_id: Option<IncidentId>,
        /// The operator-supplied reason (FU-36), when this reopen was an
        /// operator command. `None` for an automatic recurrence reopen,
        /// which carries no human-authored reason to preserve.
        reason: Option<String>,
    },
    LimitReached {
        limit_name: String,
    },
    /// FU-37: `add_tag` and `remove_tag` previously mutated the incident
    /// with no timeline record at all — every other mutation appends one.
    TagAdded {
        key: String,
        value: String,
    },
    TagRemoved {
        key: String,
    },
}

impl TimelinePayload {
    /// The stable, versioned entry-type tag used for filtering and for
    /// the `entry_type` column the persistence plan documents.
    pub fn entry_type(&self) -> &'static str {
        match self {
            TimelinePayload::Opened => "opened",
            TimelinePayload::EventLinked { .. } => "event_linked",
            TimelinePayload::LateEventLinked { .. } => "late_event_linked",
            TimelinePayload::DuplicateIgnored { .. } => "duplicate_ignored",
            TimelinePayload::StateChanged { .. } => "state_changed",
            TimelinePayload::CategoryChanged { .. } => "category_changed",
            TimelinePayload::SeverityChanged { .. } => "severity_changed",
            TimelinePayload::PriorityChanged { .. } => "priority_changed",
            TimelinePayload::AssignmentChanged { .. } => "assignment_changed",
            TimelinePayload::NoteAdded { .. } => "note_added",
            TimelinePayload::NoteSuperseded { .. } => "note_superseded",
            TimelinePayload::NoteRedacted { .. } => "note_redacted",
            TimelinePayload::Suppressed { .. } => "suppressed",
            TimelinePayload::Unsuppressed => "unsuppressed",
            TimelinePayload::Reopened { .. } => "reopened",
            TimelinePayload::LimitReached { .. } => "limit_reached",
            TimelinePayload::TagAdded { .. } => "tag_added",
            TimelinePayload::TagRemoved { .. } => "tag_removed",
        }
    }
}

pub const TIMELINE_SCHEMA_VERSION: u32 = 1;

/// One append-only timeline entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub schema_version: u32,
    pub sequence: u64,
    pub incident_id: IncidentId,
    pub actor: Actor,
    pub payload: TimelinePayload,
}

impl TimelineEntry {
    pub fn new(
        sequence: u64,
        incident_id: IncidentId,
        actor: Actor,
        payload: TimelinePayload,
    ) -> Self {
        TimelineEntry {
            schema_version: TIMELINE_SCHEMA_VERSION,
            sequence,
            incident_id,
            actor,
            payload,
        }
    }

    /// The boundary serialization. Nothing inside this crate calls this
    /// — it exists for a future API or export path.
    pub fn payload_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.payload).expect("TimelinePayload always serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_type_matches_the_payload_variant() {
        let payload = TimelinePayload::StateChanged {
            from: IncidentState::Open,
            to: IncidentState::Acknowledged,
            cause: TransitionCause::Operator(OperatorCommandKind::Acknowledge),
        };
        assert_eq!(payload.entry_type(), "state_changed");
    }

    #[test]
    fn payload_json_round_trips_a_typed_variant() {
        let payload = TimelinePayload::Reopened {
            reopen_count: 2,
            previous_incident_id: None,
            reason: Some("recurring attack pattern".to_string()),
        };
        let entry = TimelineEntry::new(
            0,
            IncidentId::from_bytes([1; 16]),
            Actor::System,
            payload.clone(),
        );
        let json = entry.payload_json();
        let back: TimelinePayload = serde_json::from_value(json).unwrap();
        assert_eq!(back, payload);
    }
}
