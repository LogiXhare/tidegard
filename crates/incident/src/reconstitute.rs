//! The single door from an [`IncidentSnapshot`] back to a live
//! [`Incident`].
//!
//! [`crate::snapshot`] explains why a bare `#[derive(Deserialize)]` on
//! the aggregate is the wrong shape; this module is the right one. Every
//! check below exists because some guard elsewhere in the crate *already
//! assumes* the condition holds, and would misbehave rather than complain
//! if a database row arrived without it. The pairing is deliberate: this
//! is not a general-purpose schema validator, it is the set of
//! assumptions the domain makes about its own aggregate, written down
//! and enforced at the one place an aggregate can enter the process from
//! outside.
//!
//! Where each check comes from:
//!
//! - **`state_before_recovering` ⟺ `Recovering`.**
//!   [`crate::transition::abort_recovery`] returns
//!   `InternalInvariantViolation` when a `Recovering` incident has no
//!   state to restore. The only edges out of `Recovering` are the four
//!   abort edges and `Recovering -> Resolved`, and every one of them
//!   clears the field, so the biconditional holds in live code and a row
//!   that breaks it is corrupt.
//! - **`recovering_since` ⟺ `Recovering`.** Same edges, same clearing.
//! - **`resolved_at` ⟺ `Resolved` or `Closed`.** `Resolved -> Closed`
//!   keeps it; the reopen edges (`Resolved -> Open`, `Closed -> Open`)
//!   clear it; nothing else reaches those states.
//! - **`closed_at` ⟺ `Closed`, `closure_reason` ⟺ `Closed`.** Set
//!   together on close, cleared together on reopen.
//!   [`crate::transition::evaluate_reopen`] reads `closed_at` for a
//!   `Closed` incident and treats its absence as an internal invariant
//!   violation.
//! - **`Critical` implies `ever_critical`.** BQ-8's manual-closure
//!   protection is decided from `ever_critical`, never from the live
//!   `severity`, precisely so a downgrade cannot unlock automatic
//!   closure. A row claiming a `Critical` incident that was never
//!   critical would hand an attacker that unlock through the database
//!   instead of through the API.
//! - **`category` is derived.** It is recomputed from `matched_metrics`
//!   on creation and on every linked event, and no command sets it, so a
//!   row where the two disagree has been edited outside the domain.
//! - **The correlation key agrees with the denormalized fields.** The
//!   aggregate stores tenant, target type, target identity, direction,
//!   and address family both inside `correlation_key` and again beside
//!   it. Nothing in 5A can make the two disagree, and nothing checks
//!   that they do not; a row where they disagree would correlate as one
//!   incident and display as another.
//! - **Bounds and note indices.** Every capacity limit the mutation
//!   methods enforce before appending is re-enforced here, because a row
//!   is another way to append. Note indices are assigned as
//!   `notes.len()` and notes are never removed, so they are contiguous
//!   from zero.
//! - **Lifecycle ordering.** These became *expressible* only with ADR
//!   0031's durable timestamps: two `Instant`s from different processes
//!   could not be compared at all. A violation is evidence of the clock
//!   skew ADR 0031 requires be surfaced rather than absorbed, and an
//!   incident whose timestamps run backward cannot be trusted for the
//!   reopen decision that reads them.
//!
//! One deliberate omission: `priority` is **not** checked against
//! `Priority::default_for(severity)`. The `ChangePriority` command lets
//! an operator set priority independently of severity, so enforcing the
//! derived value here would reject rows the domain itself produces.
//! Over-constraining reconstitution is as much a defect as
//! under-constraining it — it just fails in the other direction, where
//! it looks like data loss rather than a security hole.

use std::collections::BTreeSet;

use tidegard_detector::Severity;

use crate::category::derive_category;
use crate::durable_time::DurableTimestamp;
use crate::error::IncidentError;
use crate::evidence::EVIDENCE_RETAINED_LIMIT;
use crate::incident::{Incident, INCIDENT_SCHEMA_VERSION};
use crate::limits::{
    DESCRIPTION_MAX_LEN, NOTES_PER_INCIDENT_MAX, NOTE_BODY_MAX_LEN, NOTE_REDACTION_REASON_MAX_LEN,
    POLICY_REFS_MAX, TAGS_PER_INCIDENT_MAX, TAG_KEY_MAX_LEN, TAG_VALUE_MAX_LEN, TITLE_MAX_LEN,
};
use crate::number::INCIDENT_NUMBER_MAX_LEN;
use crate::severity::SeveritySource;
use crate::snapshot::IncidentSnapshot;
use crate::state::IncidentState;
use crate::suppression::{Suppression, SUPPRESSION_REASON_MAX_LEN};

/// Builds the one error kind this module raises.
fn corrupt(field: &'static str, detail: &'static str) -> IncidentError {
    IncidentError::CorruptSnapshot { field, detail }
}

/// Rejects unless `condition` holds.
fn require(
    condition: bool,
    field: &'static str,
    detail: &'static str,
) -> Result<(), IncidentError> {
    if condition {
        Ok(())
    } else {
        Err(corrupt(field, detail))
    }
}

/// Rejects unless `later` is at or after `earlier`, when `later` is set.
fn require_not_before(
    later: Option<DurableTimestamp>,
    earlier: DurableTimestamp,
    field: &'static str,
) -> Result<(), IncidentError> {
    match later {
        Some(later) if later < earlier => Err(corrupt(field, "precedes the incident's start")),
        _ => Ok(()),
    }
}

impl Incident {
    /// Rebuilds an aggregate from a persisted snapshot, or reports which
    /// invariant the snapshot violates.
    ///
    /// This is the **only** path from an [`IncidentSnapshot`] to an
    /// [`Incident`]. There is no `From` impl, no `Deserialize`, and no
    /// field-by-field public constructor, because each of those would be
    /// a way to obtain an aggregate the domain's own methods could never
    /// have produced (ADR 0030, Options B and C).
    ///
    /// Errors are [`IncidentError::CorruptSnapshot`] carrying the field
    /// and a fixed description. Neither is caller-supplied, so an error
    /// cannot echo row contents back to a client — the security model
    /// treats the database as trusted but not infallible, which is a
    /// reason to reject its output, not to quote it.
    pub fn reconstitute(snapshot: IncidentSnapshot) -> Result<Incident, IncidentError> {
        let s = snapshot;

        // --- Structural bounds, cheapest first. ---
        require(
            s.schema_version >= 1 && s.schema_version <= INCIDENT_SCHEMA_VERSION,
            "schema_version",
            "is outside the range this build understands",
        )?;
        require(s.version >= 1, "version", "must start at one")?;
        require(
            !s.incident_number.as_str().is_empty()
                && s.incident_number.as_str().len() <= INCIDENT_NUMBER_MAX_LEN,
            "incident_number",
            "is empty or exceeds its length bound",
        )?;
        require(
            !s.title.is_empty() && s.title.chars().count() <= TITLE_MAX_LEN,
            "title",
            "is empty or exceeds its length bound",
        )?;
        require(
            s.description
                .as_ref()
                .is_none_or(|d| d.chars().count() <= DESCRIPTION_MAX_LEN),
            "description",
            "exceeds its length bound",
        )?;

        // --- Collections: the same caps the mutation methods enforce
        // before appending, because a row is another way to append. ---
        require(
            s.notes.len() <= NOTES_PER_INCIDENT_MAX,
            "notes",
            "exceeds the per-incident cap",
        )?;
        require(
            s.notes
                .iter()
                .all(|n| n.body.chars().count() <= NOTE_BODY_MAX_LEN),
            "notes",
            "contains a body over its length bound",
        )?;
        require(
            s.notes
                .iter()
                .enumerate()
                .all(|(position, note)| note.index as usize == position),
            "notes",
            "indices are not contiguous from zero",
        )?;
        require(
            s.notes
                .iter()
                .all(|note| note.supersedes.is_none_or(|earlier| earlier < note.index)),
            "notes",
            "a note supersedes itself or a later note",
        )?;
        {
            let mut replaced = std::collections::BTreeSet::new();
            require(
                s.notes
                    .iter()
                    .filter_map(|note| note.supersedes)
                    .all(|earlier| replaced.insert(earlier)),
                "notes",
                "a note is superseded more than once",
            )?;
        }
        require(
            s.notes.iter().all(|note| match &note.redaction {
                None => true,
                Some(redaction) => {
                    note.body.is_empty()
                        && !redaction.reason.trim().is_empty()
                        && redaction.reason.chars().count() <= NOTE_REDACTION_REASON_MAX_LEN
                }
            }),
            "notes",
            "a redacted note keeps a body or lacks a bounded reason",
        )?;
        require(
            s.tags.len() <= TAGS_PER_INCIDENT_MAX,
            "tags",
            "exceeds the per-incident cap",
        )?;
        require(
            s.tags.iter().all(|(key, value)| {
                key.chars().count() <= TAG_KEY_MAX_LEN && value.chars().count() <= TAG_VALUE_MAX_LEN
            }),
            "tags",
            "contains a key or value over its length bound",
        )?;
        require(
            s.policy_refs.len() <= POLICY_REFS_MAX,
            "policy_refs",
            "exceeds the per-incident cap",
        )?;
        require(
            s.policy_refs_omitted == 0 || s.policy_refs.len() == POLICY_REFS_MAX,
            "policy_refs_omitted",
            "counts omissions, but the policy references are below their cap",
        )?;
        require(
            s.evidence.retained_count() <= EVIDENCE_RETAINED_LIMIT,
            "evidence",
            "retains more references than the ledger permits",
        )?;
        require(
            s.evidence.observed_total() >= s.evidence.retained_count() as u64,
            "evidence",
            "retains more references than it claims to have observed",
        )?;
        if let Some(suppression) = &s.suppression {
            require(
                suppression.reason.chars().count() <= SUPPRESSION_REASON_MAX_LEN,
                "suppression",
                "reason exceeds its length bound",
            )?;
        }

        // --- Derived values must agree with what they derive from. ---
        let matched_metrics: BTreeSet<_> = s.matched_metrics.iter().copied().collect();
        require(
            matched_metrics.len() == s.matched_metrics.len(),
            "matched_metrics",
            "contains a duplicate metric",
        )?;
        require(
            s.category == derive_category(&matched_metrics),
            "category",
            "disagrees with the metrics it is derived from",
        )?;
        require(
            s.correlation_key.tenant == s.tenant_id
                && s.correlation_key.target_type == s.target_type
                && s.correlation_key.target_identity == s.target_identity
                && s.correlation_key.direction == s.direction
                && s.correlation_key.address_family == s.address_family,
            "correlation_key",
            "disagrees with the denormalized identity fields beside it",
        )?;

        // --- State-dependent fields. Each biconditional is verified
        // against the transition tables in `crate::state`. ---
        let is_recovering = s.state == IncidentState::Recovering;
        require(
            s.state_before_recovering.is_some() == is_recovering,
            "state_before_recovering",
            "is set only for a Recovering incident, and required for one",
        )?;
        require(
            s.recovering_since.is_some() == is_recovering,
            "recovering_since",
            "is set only for a Recovering incident, and required for one",
        )?;
        require(
            s.state_before_recovering
                .is_none_or(|before| before != IncidentState::Recovering),
            "state_before_recovering",
            "cannot itself be Recovering",
        )?;

        let is_resolved_or_closed =
            matches!(s.state, IncidentState::Resolved | IncidentState::Closed);
        require(
            s.resolved_at.is_some() == is_resolved_or_closed,
            "resolved_at",
            "is set exactly for a Resolved or Closed incident",
        )?;

        let is_closed = s.state == IncidentState::Closed;
        require(
            s.closed_at.is_some() == is_closed,
            "closed_at",
            "is set exactly for a Closed incident",
        )?;
        require(
            s.closure_reason.is_some() == is_closed,
            "closure_reason",
            "is set exactly for a Closed incident",
        )?;

        require(
            s.severity != Severity::Critical || s.ever_critical,
            "ever_critical",
            "must be set for an incident whose severity is Critical",
        )?;
        require(
            s.maximum_detected_severity != Severity::Critical || s.ever_critical,
            "ever_critical",
            "must be set for an incident that has ever detected Critical",
        )?;
        // A detection-sourced severity came from an event, so it cannot
        // exceed the highest severity any event reported. An operator
        // override may (it is not a detection), hence the source check.
        require(
            s.severity_source != SeveritySource::Detection
                || (s.severity as u8) <= (s.maximum_detected_severity as u8),
            "maximum_detected_severity",
            "is below a detection-sourced severity",
        )?;
        require(
            (s.reopen_count > 0) == s.reopened_at.is_some(),
            "reopened_at",
            "is set exactly when the incident has been reopened at least once",
        )?;

        // --- Lifecycle ordering. Expressible only because ADR 0031 made
        // these timestamps comparable across processes. ---
        require(
            s.opened_at >= s.first_detected_at,
            "opened_at",
            "precedes the first detection",
        )?;
        require(
            s.last_detected_at >= s.first_detected_at,
            "last_detected_at",
            "precedes the first detection",
        )?;
        require(
            s.last_updated_at >= s.opened_at,
            "last_updated_at",
            "precedes the incident's start",
        )?;
        require_not_before(s.acknowledged_at, s.opened_at, "acknowledged_at")?;
        require_not_before(s.recovering_since, s.opened_at, "recovering_since")?;
        require_not_before(s.resolved_at, s.opened_at, "resolved_at")?;
        require_not_before(s.closed_at, s.opened_at, "closed_at")?;
        require_not_before(s.reopened_at, s.opened_at, "reopened_at")?;
        if let (Some(resolved_at), Some(closed_at)) = (s.resolved_at, s.closed_at) {
            require(
                closed_at >= resolved_at,
                "closed_at",
                "precedes the resolution it closes",
            )?;
        }

        Ok(Incident {
            incident_id: s.incident_id,
            incident_number: s.incident_number,
            schema_version: s.schema_version,
            tenant_id: s.tenant_id,
            correlation_key: s.correlation_key,
            address_family: s.address_family,
            direction: s.direction,
            target_type: s.target_type,
            target_identity: s.target_identity,
            created_by: s.created_by,
            title: s.title,
            description: s.description,
            state: s.state,
            severity: s.severity,
            severity_source: s.severity_source,
            ever_critical: s.ever_critical,
            maximum_detected_severity: s.maximum_detected_severity,
            priority: s.priority,
            closure_reason: s.closure_reason,
            state_before_recovering: s.state_before_recovering,
            suppression: s
                .suppression
                .map(|d| Suppression::new(d.reason, d.by, d.until)),
            version: s.version,
            category: s.category,
            matched_metrics,
            first_detected_at: s.first_detected_at,
            opened_at: s.opened_at,
            last_detected_at: s.last_detected_at,
            last_updated_at: s.last_updated_at,
            acknowledged_at: s.acknowledged_at,
            recovering_since: s.recovering_since,
            resolved_at: s.resolved_at,
            closed_at: s.closed_at,
            reopened_at: s.reopened_at,
            reopen_count: s.reopen_count,
            assignment: s.assignment,
            updated_by: s.updated_by,
            evidence: s.evidence,
            notes: s.notes,
            tags: s.tags,
            policy_refs: s.policy_refs,
            policy_refs_omitted: s.policy_refs_omitted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::IncidentCategory;
    use crate::closure::ClosureReason;
    use crate::correlation::TenantId;
    use crate::incident::{Note, NoteVisibility};
    use crate::test_fixtures::{valid_incident, FIXTURE_TIME};
    use tidegard_detector::MetricKind;

    const EVERY_STATE: [IncidentState; 7] = [
        IncidentState::Open,
        IncidentState::Acknowledged,
        IncidentState::Investigating,
        IncidentState::Monitoring,
        IncidentState::Recovering,
        IncidentState::Resolved,
        IncidentState::Closed,
    ];

    fn snapshot_of(state: IncidentState) -> IncidentSnapshot {
        valid_incident(state).to_snapshot()
    }

    /// Asserts the snapshot is rejected, and rejected for the *stated*
    /// reason. Asserting only `is_err()` would let a later change move
    /// the rejection to an unrelated check and still pass.
    #[track_caller]
    fn expect_rejected(snapshot: IncidentSnapshot, expected_field: &str) {
        match Incident::reconstitute(snapshot) {
            Err(IncidentError::CorruptSnapshot { field, .. }) => assert_eq!(
                field, expected_field,
                "rejected, but for the wrong field: expected {expected_field}, got {field}"
            ),
            other => panic!("expected {expected_field} to be rejected, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_aggregate_survives_a_full_round_trip_in_every_state() {
        for state in EVERY_STATE {
            let original = valid_incident(state);
            let restored = Incident::reconstitute(original.to_snapshot())
                .unwrap_or_else(|e| panic!("a valid {state:?} incident was rejected: {e:?}"));
            assert_eq!(restored, original, "round trip differed in state {state:?}");
        }
    }

    #[test]
    fn a_reconstituted_aggregate_snapshots_identically() {
        for state in EVERY_STATE {
            let snapshot = snapshot_of(state);
            let again = Incident::reconstitute(snapshot.clone())
                .unwrap()
                .to_snapshot();
            assert_eq!(again, snapshot, "reconstitution is not idempotent");
        }
    }

    #[test]
    fn a_schema_version_this_build_does_not_understand_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.schema_version = 0;
        expect_rejected(s, "schema_version");

        let mut s = snapshot_of(IncidentState::Open);
        s.schema_version = INCIDENT_SCHEMA_VERSION + 1;
        expect_rejected(s, "schema_version");
    }

    #[test]
    fn a_zero_version_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.version = 0;
        expect_rejected(s, "version");
    }

    #[test]
    fn an_empty_or_oversized_title_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.title = String::new();
        expect_rejected(s, "title");

        let mut s = snapshot_of(IncidentState::Open);
        s.title = "a".repeat(TITLE_MAX_LEN + 1);
        expect_rejected(s, "title");
    }

    #[test]
    fn a_title_at_exactly_the_bound_is_accepted() {
        let mut s = snapshot_of(IncidentState::Open);
        s.title = "a".repeat(TITLE_MAX_LEN);
        assert!(Incident::reconstitute(s).is_ok(), "the bound is inclusive");
    }

    #[test]
    fn an_oversized_description_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.description = Some("a".repeat(DESCRIPTION_MAX_LEN + 1));
        expect_rejected(s, "description");
    }

    #[test]
    fn more_notes_than_the_cap_are_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.notes = (0..=NOTES_PER_INCIDENT_MAX)
            .map(|index| {
                Note::new(
                    index as u32,
                    "n".to_string(),
                    NoteVisibility::Internal,
                    s.created_by.clone(),
                )
            })
            .collect();
        expect_rejected(s, "notes");
    }

    #[test]
    fn an_oversized_note_body_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.notes = vec![Note::new(
            0,
            "n".repeat(NOTE_BODY_MAX_LEN + 1),
            NoteVisibility::Internal,
            s.created_by.clone(),
        )];
        expect_rejected(s, "notes");
    }

    /// Indices are assigned as `notes.len()` and notes are never removed,
    /// so a gap means the row was written by something other than the
    /// domain.
    #[test]
    fn non_contiguous_note_indices_are_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.notes = vec![Note::new(
            7,
            "n".to_string(),
            NoteVisibility::Internal,
            s.created_by.clone(),
        )];
        expect_rejected(s, "notes");
    }

    fn two_notes(s: &IncidentSnapshot) -> Vec<Note> {
        (0..2)
            .map(|index| {
                Note::new(
                    index,
                    "n".to_string(),
                    NoteVisibility::Internal,
                    s.created_by.clone(),
                )
            })
            .collect()
    }

    /// An edit names an earlier note, and replaces it once.
    #[test]
    fn a_supersession_chain_that_points_forward_or_forks_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.notes = two_notes(&s);
        s.notes[0].supersedes = Some(1);
        expect_rejected(s, "notes");

        let mut s = snapshot_of(IncidentState::Open);
        s.notes = two_notes(&s);
        s.notes[1].supersedes = Some(1);
        expect_rejected(s, "notes");

        let mut s = snapshot_of(IncidentState::Open);
        s.notes = two_notes(&s);
        s.notes.push(Note::new(
            2,
            "n".to_string(),
            NoteVisibility::Internal,
            s.created_by.clone(),
        ));
        s.notes[1].supersedes = Some(0);
        s.notes[2].supersedes = Some(0);
        expect_rejected(s, "notes");

        let mut s = snapshot_of(IncidentState::Open);
        s.notes = two_notes(&s);
        s.notes[1].supersedes = Some(0);
        Incident::reconstitute(s).expect("a single edit is a valid chain");
    }

    #[test]
    fn a_redacted_note_with_a_body_or_without_a_reason_is_rejected() {
        let redaction = |reason: &str| crate::incident::NoteRedaction {
            by: crate::authorization::Actor::System,
            reason: reason.to_string(),
        };
        let mut s = snapshot_of(IncidentState::Open);
        s.notes = two_notes(&s);
        s.notes[0].redaction = Some(redaction("pasted a password"));
        expect_rejected(s, "notes");

        let mut s = snapshot_of(IncidentState::Open);
        s.notes = two_notes(&s);
        s.notes[0].body.clear();
        s.notes[0].redaction = Some(redaction(" "));
        expect_rejected(s, "notes");

        let mut s = snapshot_of(IncidentState::Open);
        s.notes = two_notes(&s);
        s.notes[0].body.clear();
        s.notes[0].redaction = Some(redaction("pasted a password"));
        Incident::reconstitute(s).expect("a redacted note with a reason is valid");
    }

    #[test]
    fn tags_over_the_cap_or_over_a_length_bound_are_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        for i in 0..=TAGS_PER_INCIDENT_MAX {
            s.tags.insert(format!("k{i}"), "v".to_string());
        }
        expect_rejected(s, "tags");

        let mut s = snapshot_of(IncidentState::Open);
        s.tags
            .insert("k".repeat(TAG_KEY_MAX_LEN + 1), "v".to_string());
        expect_rejected(s, "tags");

        let mut s = snapshot_of(IncidentState::Open);
        s.tags
            .insert("k".to_string(), "v".repeat(TAG_VALUE_MAX_LEN + 1));
        expect_rejected(s, "tags");
    }

    /// `EvidenceLedger`'s fields are private with no setter, so this
    /// inconsistency is unreachable through the domain — it is reachable
    /// only from a row, which is exactly the threat reconstitution
    /// exists to answer. Building it through `serde` is therefore not a
    /// test shortcut; it is the actual attack shape.
    #[test]
    fn an_evidence_ledger_claiming_fewer_observations_than_it_retains_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.evidence = serde_json::from_str(
            r#"{"retained":[{"detection_event_id":"e-1","dedup_key":"d-1","detection_id":"det-1","link_type":"opening","matched_metrics":[]}],"observed_total":0}"#,
        )
        .expect("the ledger DTO must accept this shape");
        expect_rejected(s, "evidence");
    }

    #[test]
    fn a_duplicate_matched_metric_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.matched_metrics = vec![MetricKind::Bps, MetricKind::Bps];
        expect_rejected(s, "matched_metrics");
    }

    #[test]
    fn a_category_that_disagrees_with_its_metrics_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.category = IncidentCategory::TcpSynFlood;
        expect_rejected(s, "category");
    }

    #[test]
    fn a_correlation_key_disagreeing_with_the_fields_beside_it_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.tenant_id = TenantId::new("someone-else");
        expect_rejected(s, "correlation_key");

        let mut s = snapshot_of(IncidentState::Open);
        s.correlation_key.direction = tidegard_detector::TrafficDirection::Outgoing;
        expect_rejected(s, "correlation_key");
    }

    #[test]
    fn state_before_recovering_must_match_the_state_exactly() {
        let mut s = snapshot_of(IncidentState::Open);
        s.state_before_recovering = Some(IncidentState::Investigating);
        expect_rejected(s, "state_before_recovering");

        let mut s = snapshot_of(IncidentState::Recovering);
        s.state_before_recovering = None;
        expect_rejected(s, "state_before_recovering");

        let mut s = snapshot_of(IncidentState::Recovering);
        s.state_before_recovering = Some(IncidentState::Recovering);
        expect_rejected(s, "state_before_recovering");
    }

    #[test]
    fn recovering_since_must_match_the_state_exactly() {
        let mut s = snapshot_of(IncidentState::Recovering);
        s.recovering_since = None;
        expect_rejected(s, "recovering_since");

        let mut s = snapshot_of(IncidentState::Open);
        s.recovering_since = Some(FIXTURE_TIME);
        expect_rejected(s, "recovering_since");
    }

    #[test]
    fn resolved_at_is_required_for_resolved_and_closed_and_forbidden_otherwise() {
        for state in [IncidentState::Resolved, IncidentState::Closed] {
            let mut s = snapshot_of(state);
            s.resolved_at = None;
            expect_rejected(s, "resolved_at");
        }
        let mut s = snapshot_of(IncidentState::Open);
        s.resolved_at = Some(FIXTURE_TIME);
        expect_rejected(s, "resolved_at");
    }

    #[test]
    fn closed_at_and_closure_reason_are_required_for_closed_and_forbidden_otherwise() {
        let mut s = snapshot_of(IncidentState::Closed);
        s.closed_at = None;
        expect_rejected(s, "closed_at");

        let mut s = snapshot_of(IncidentState::Closed);
        s.closure_reason = None;
        expect_rejected(s, "closure_reason");

        let mut s = snapshot_of(IncidentState::Resolved);
        s.closure_reason = Some(ClosureReason::Resolved);
        expect_rejected(s, "closure_reason");
    }

    /// BQ-8: the manual-closure protection is decided from
    /// `ever_critical`, so a row that unsets it for a Critical incident
    /// is asking for automatic closure of something that must not be
    /// automatically closed.
    #[test]
    fn a_critical_incident_that_was_never_critical_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.severity = Severity::Critical;
        s.ever_critical = false;
        expect_rejected(s, "ever_critical");
    }

    #[test]
    fn a_downgraded_incident_may_still_be_ever_critical() {
        let mut s = snapshot_of(IncidentState::Open);
        s.severity = Severity::Minor;
        s.ever_critical = true;
        assert!(
            Incident::reconstitute(s).is_ok(),
            "ever_critical is never cleared, so this is the normal downgrade shape"
        );
    }

    #[test]
    fn a_critical_detection_without_ever_critical_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.maximum_detected_severity = Severity::Critical;
        s.ever_critical = false;
        expect_rejected(s, "ever_critical");
    }

    #[test]
    fn a_detection_severity_above_the_maximum_detected_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.severity = Severity::Major;
        s.severity_source = SeveritySource::Detection;
        s.maximum_detected_severity = Severity::Minor;
        expect_rejected(s, "maximum_detected_severity");
    }

    /// An operator may raise severity past anything detected; that is an
    /// override, not a detection, so the maximum stays where it was.
    #[test]
    fn an_operator_severity_above_the_maximum_detected_is_accepted() {
        let mut s = snapshot_of(IncidentState::Open);
        s.severity = Severity::Major;
        s.severity_source = SeveritySource::Operator;
        s.maximum_detected_severity = Severity::Minor;
        assert!(Incident::reconstitute(s).is_ok());
    }

    #[test]
    fn a_reopen_count_without_a_reopen_timestamp_is_rejected() {
        let mut s = snapshot_of(IncidentState::Open);
        s.reopen_count = 1;
        expect_rejected(s, "reopened_at");

        let mut s = snapshot_of(IncidentState::Open);
        s.reopened_at = Some(FIXTURE_TIME);
        expect_rejected(s, "reopened_at");
    }

    #[test]
    fn timestamps_that_run_backward_are_rejected() {
        let earlier = DurableTimestamp::from_micros(FIXTURE_TIME.as_micros() - 1);

        let mut s = snapshot_of(IncidentState::Open);
        s.opened_at = earlier;
        expect_rejected(s, "opened_at");

        let mut s = snapshot_of(IncidentState::Open);
        s.last_detected_at = earlier;
        expect_rejected(s, "last_detected_at");

        let mut s = snapshot_of(IncidentState::Open);
        s.last_updated_at = earlier;
        expect_rejected(s, "last_updated_at");

        let mut s = snapshot_of(IncidentState::Open);
        s.acknowledged_at = Some(earlier);
        expect_rejected(s, "acknowledged_at");

        let mut s = snapshot_of(IncidentState::Closed);
        s.closed_at = Some(earlier);
        expect_rejected(s, "closed_at");
    }

    #[test]
    fn a_closure_that_predates_its_own_resolution_is_rejected() {
        let mut s = snapshot_of(IncidentState::Closed);
        s.resolved_at = Some(DurableTimestamp::from_micros(FIXTURE_TIME.as_micros() + 10));
        s.closed_at = Some(FIXTURE_TIME);
        expect_rejected(s, "closed_at");
    }

    #[test]
    fn an_oversized_suppression_reason_is_rejected() {
        use crate::suppression::Suppression;
        let mut incident = valid_incident(IncidentState::Open);
        incident.suppression = Some(Suppression::new(
            "r".repeat(SUPPRESSION_REASON_MAX_LEN + 1),
            incident.created_by.clone(),
            FIXTURE_TIME,
        ));
        expect_rejected(incident.to_snapshot(), "suppression");
    }

    /// The complement of every test above: reconstitution must not
    /// invent constraints the domain does not have. `ChangePriority`
    /// sets priority independently of severity, so a row where they
    /// disagree is normal, not corrupt.
    #[test]
    fn a_priority_that_does_not_match_the_severity_default_is_accepted() {
        let mut s = snapshot_of(IncidentState::Open);
        s.priority = crate::severity::Priority::P4;
        assert!(
            Incident::reconstitute(s).is_ok(),
            "an operator-set priority must survive a round trip"
        );
    }
}
