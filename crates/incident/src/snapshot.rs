//! The serializable rendering of an [`Incident`], and the only shape a
//! persistence adapter may speak.
//!
//! [`Incident`] derives `Debug, Clone, PartialEq` and nothing else. It has
//! no public constructor, and two of the fields its own logic depends on
//! — `state_before_recovering` (which drives `abort_recovery`) and
//! `matched_metrics` (which drives category derivation) — are
//! `pub(crate)` with no accessor. A row read back from PostgreSQL cannot
//! become a valid `Incident` today by any means available outside this
//! crate. That is the gap this module closes, and ADR 0030 fixes how:
//! through a separate DTO and a validating constructor, never through a
//! bare `#[derive(Deserialize)]` on the aggregate.
//!
//! The distinction matters because it is the difference between two
//! things that look alike. `Incident`'s module doc states its invariant:
//! every mutation goes through a method with intent to change it, and
//! every path that does so also appends a timeline entry, appends an
//! audit entry, and bumps `version`. A `Deserialize` impl on `Incident`
//! would accept whatever combination of field values a payload happened
//! to contain — an incident `Closed` with no `closed_at`, a `Critical`
//! one with `ever_critical` false, a `Recovering` one with no state to
//! recover to — reopening at the deserialization level exactly the class
//! of bypass the adversarial reviews' Blocker and High findings closed at
//! the method level.
//!
//! So the snapshot is a *dumb* type by design: it validates nothing,
//! because validation belongs to `Incident::reconstitute`, which is the
//! single door back into the aggregate. Read it as "what the row said",
//! not "what is true".
//!
//! # Field parity
//!
//! [`Incident::to_snapshot`] destructures `Incident` exhaustively, with
//! no `..` rest pattern. Adding a field to the aggregate therefore fails
//! to compile until it is carried here too — the parity check ADR 0030's
//! follow-up asks for, enforced by the compiler rather than by a test
//! that a future field could simply not be added to.
//!
//! # Where the shapes differ, and why
//!
//! - `suppression` is [`SuppressionDisplay`], the boundary DTO
//!   [`crate::suppression`] already defines for exactly this purpose, so
//!   there is one serializable rendering of a suppression rather than
//!   two that could drift.
//! - `matched_metrics` is a `Vec`, not the aggregate's `BTreeSet`.
//!   Deserializing a set silently absorbs duplicates; deserializing a
//!   sequence lets `reconstitute` *notice* them and reject the row, which
//!   is the whole point of having a validating door.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tidegard_detector::{
    AddressFamily, MetricKind, ScopeId, ScopeType, Severity, TrafficDirection,
};

use crate::assignment::Assignment;
use crate::authorization::Actor;
use crate::category::IncidentCategory;
use crate::closure::ClosureReason;
use crate::correlation::{CorrelationKey, TenantId};
use crate::durable_time::DurableTimestamp;
use crate::evidence::EvidenceLedger;
use crate::id::IncidentId;
use crate::incident::{Incident, Note, PolicyRef};
use crate::number::IncidentNumber;
use crate::severity::{Priority, SeveritySource};
use crate::state::IncidentState;
use crate::suppression::SuppressionDisplay;

/// A row's worth of incident, as read or as about to be written.
///
/// Every field mirrors [`Incident`]'s field of the same name. Nothing
/// here is validated; see the module doc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentSnapshot {
    // Identity.
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

    // Title/description.
    pub title: String,
    pub description: Option<String>,

    // State and priority.
    pub state: IncidentState,
    pub severity: Severity,
    pub severity_source: SeveritySource,
    pub ever_critical: bool,
    pub maximum_detected_severity: Severity,
    pub priority: Priority,
    pub closure_reason: Option<ClosureReason>,
    /// Mirrors the aggregate's `pub(crate)` field. A snapshot may carry
    /// it; only [`Incident::reconstitute`] decides whether the value it
    /// carries is consistent with `state`.
    pub state_before_recovering: Option<IncidentState>,
    pub suppression: Option<SuppressionDisplay>,
    pub version: u64,

    // Category.
    pub category: IncidentCategory,
    /// Mirrors the aggregate's `pub(crate)` field, as an ordered sequence
    /// rather than a set — see the module doc on why duplicates must stay
    /// visible to `reconstitute`.
    pub matched_metrics: Vec<MetricKind>,

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

    // Evidence, notes, tags, policy references.
    pub evidence: EvidenceLedger,
    pub notes: Vec<Note>,
    pub tags: BTreeMap<String, String>,
    pub policy_refs: Vec<PolicyRef>,
    pub policy_refs_omitted: u64,
}

impl Incident {
    /// This incident as a snapshot, for a persistence adapter to write.
    ///
    /// Read-only: there is deliberately no counterpart returning
    /// `&mut Incident` or a mutable handle to any field, because that
    /// would be Option C of ADR 0030 — the same bypass as a bare
    /// `Deserialize`, wearing a different hat.
    ///
    /// The exhaustive destructuring below is load-bearing. Do not
    /// introduce a `..` rest pattern to quiet it: the missing-field error
    /// it produces when the aggregate grows is the field-parity check.
    pub fn to_snapshot(&self) -> IncidentSnapshot {
        let Incident {
            incident_id,
            incident_number,
            schema_version,
            tenant_id,
            correlation_key,
            address_family,
            direction,
            target_type,
            target_identity,
            created_by,
            title,
            description,
            state,
            severity,
            severity_source,
            ever_critical,
            maximum_detected_severity,
            priority,
            closure_reason,
            state_before_recovering,
            suppression,
            version,
            category,
            matched_metrics,
            first_detected_at,
            opened_at,
            last_detected_at,
            last_updated_at,
            acknowledged_at,
            recovering_since,
            resolved_at,
            closed_at,
            reopened_at,
            reopen_count,
            assignment,
            updated_by,
            evidence,
            notes,
            tags,
            policy_refs,
            policy_refs_omitted,
        } = self;

        IncidentSnapshot {
            incident_id: *incident_id,
            incident_number: incident_number.clone(),
            schema_version: *schema_version,
            tenant_id: tenant_id.clone(),
            correlation_key: correlation_key.clone(),
            address_family: *address_family,
            direction: *direction,
            target_type: *target_type,
            target_identity: target_identity.clone(),
            created_by: created_by.clone(),
            title: title.clone(),
            description: description.clone(),
            state: *state,
            severity: *severity,
            severity_source: *severity_source,
            ever_critical: *ever_critical,
            maximum_detected_severity: *maximum_detected_severity,
            priority: *priority,
            closure_reason: *closure_reason,
            state_before_recovering: *state_before_recovering,
            suppression: suppression.as_ref().map(|s| s.to_display()),
            version: *version,
            category: *category,
            matched_metrics: matched_metrics.iter().copied().collect(),
            first_detected_at: *first_detected_at,
            opened_at: *opened_at,
            last_detected_at: *last_detected_at,
            last_updated_at: *last_updated_at,
            acknowledged_at: *acknowledged_at,
            recovering_since: *recovering_since,
            resolved_at: *resolved_at,
            closed_at: *closed_at,
            reopened_at: *reopened_at,
            reopen_count: *reopen_count,
            assignment: assignment.clone(),
            updated_by: updated_by.clone(),
            evidence: evidence.clone(),
            notes: notes.clone(),
            tags: tags.clone(),
            policy_refs: policy_refs.clone(),
            policy_refs_omitted: *policy_refs_omitted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::valid_incident;
    use tidegard_detector::MetricKind;

    /// Every state, not just one: the state-dependent fields
    /// (`closure_reason`, `state_before_recovering`, `resolved_at`,
    /// `closed_at`, `recovering_since`) are exactly the ones a partial
    /// mirror would drop, and only a `Closed` or `Recovering` fixture
    /// carries them at all.
    #[test]
    fn a_snapshot_round_trips_through_json_in_every_state() {
        for state in [
            IncidentState::Open,
            IncidentState::Acknowledged,
            IncidentState::Investigating,
            IncidentState::Monitoring,
            IncidentState::Recovering,
            IncidentState::Resolved,
            IncidentState::Closed,
        ] {
            let snapshot = valid_incident(state).to_snapshot();
            let json = serde_json::to_string(&snapshot).expect("a snapshot must serialize");
            let restored: IncidentSnapshot =
                serde_json::from_str(&json).expect("a snapshot must deserialize");
            assert_eq!(restored, snapshot, "round trip differed in state {state:?}");
        }
    }

    /// The two `pub(crate)` fields are the reason this module exists: no
    /// code outside the crate can read them off the aggregate, so if the
    /// snapshot dropped them a persistence adapter would silently lose
    /// the state `abort_recovery` and category derivation depend on.
    #[test]
    fn a_snapshot_carries_the_two_fields_no_accessor_exposes() {
        let mut incident = valid_incident(IncidentState::Recovering);
        incident.matched_metrics.insert(MetricKind::Pps);
        incident.matched_metrics.insert(MetricKind::Bps);

        let snapshot = incident.to_snapshot();
        assert_eq!(
            snapshot.state_before_recovering,
            Some(IncidentState::Investigating)
        );
        assert_eq!(snapshot.matched_metrics.len(), 2);
    }

    /// `BTreeSet` iterates in sorted order, so the sequence a snapshot
    /// carries is deterministic — two equal aggregates cannot produce
    /// two byte-different rows.
    #[test]
    fn matched_metrics_is_carried_in_a_deterministic_order() {
        let mut first = valid_incident(IncidentState::Open);
        first.matched_metrics.insert(MetricKind::Pps);
        first.matched_metrics.insert(MetricKind::Bps);

        let mut second = valid_incident(IncidentState::Open);
        second.matched_metrics.insert(MetricKind::Bps);
        second.matched_metrics.insert(MetricKind::Pps);

        assert_eq!(
            first.to_snapshot().matched_metrics,
            second.to_snapshot().matched_metrics,
            "insertion order must not reach the wire"
        );
    }

    #[test]
    fn a_suppression_is_carried_through_the_existing_boundary_dto() {
        use crate::suppression::Suppression;
        let mut incident = valid_incident(IncidentState::Open);
        let deadline = DurableTimestamp::from_micros(1_756_000_003_600_000);
        incident.suppression = Some(Suppression::new("known scanner", Actor::System, deadline));

        let snapshot = incident.to_snapshot();
        let carried = snapshot.suppression.expect("the suppression must survive");
        assert_eq!(carried.until, deadline);
        assert_eq!(carried.reason, "known scanner");
    }
}
