//! The bounded, in-memory `IncidentUnitOfWork`.
//!
//! One store, not many concrete repositories — the approved Phase 5A
//! shape.
//!
//! **This is not a transaction, and 5A does not claim rollback.** Every
//! public mutation method validates everything it can — permission,
//! tenant, expected version, transition legality, capacity — *before*
//! touching `self`'s maps, so a predictable, non-injected error never
//! mutates anything (proven by the `_leaves_state_unchanged` family of
//! tests). But once a mutation begins, the incident write happens first
//! and the timeline/audit/outbox writes happen after; a failure between
//! them — reachable in 5A only through the test-only
//! [`IncidentUnitOfWork::inject_failure_after_incident_write`] hook —
//! leaves the incident mutated with no corresponding history. That gap is
//! real, is exercised by
//! `failure_injection_documents_the_in_memory_commit_boundary` in
//! `tests/domain_end_to_end.rs`, and is exactly what Milestone 5B's real
//! PostgreSQL transaction closes. Treat "exclusive in-process mutation
//! with pre-validated commands" as 5A's guarantee, not "atomic."
//!
//! Denied commands (owner decision 9) are handled by
//! [`IncidentUnitOfWork::check_permission`], called first in every
//! command-handling method, before the incident is even read mutably: a
//! denial returns before any of the incident, timeline, or outbox state
//! is touched, and writes exactly one [`crate::audit::AuditEntry::denied`].
//!
//! Correlation conflicts (owner decision 10) are never retried inside
//! this crate — [`crate::correlation::CorrelationConflict`] is returned
//! to the caller immediately. In 5A's single-threaded model a genuine
//! conflict can only arise from a caller re-entering with stale
//! information, which is exactly the case a bounded, non-retrying return
//! is correct for.

use std::collections::BTreeSet;
use std::time::Duration;

use wetechinetmon_detector::{DetectionEvent, EventKind, MetricKind};

use crate::assignment::Assignee;
use crate::audit::{AttemptedResource, AuditEntry};
use crate::authorization::{Actor, AuthorizationContext, Permission};
use crate::category::derive_category;
use crate::clock::Clock;
use crate::closure::ClosurePolicy;
use crate::command::Command;
use crate::correlation::{CorrelationConflict, CorrelationKey, TenantId};
use crate::durable_time::DurableTimestamp;
use crate::error::IncidentError;
use crate::evidence::{EvidenceLinkType, EvidenceReference};
use crate::id::{IncidentGenerator, IncidentId};
use crate::idempotency::{IdempotencyCheck, IdempotencyKey, RequestFingerprint, StoredOutcome};
use crate::incident::{
    validate_note_body, Incident, Note, NoteVisibility, INCIDENT_SCHEMA_VERSION,
};
use crate::limits::{AFFECTED_TARGETS_MAX, POLICY_REFS_MAX, TAG_KEY_MAX_LEN, TAG_VALUE_MAX_LEN};
use crate::manual::ManualIncident;
use crate::number::NumberAllocator;
use crate::outbox::{OutboxEvent, OutboxMessage};
use crate::reopen::ReopenPolicy;
use crate::severity::{Priority, SeveritySource};
use crate::state::IncidentState;
use crate::store::{InMemoryIncidentStore, IncidentStore};
use crate::suppression::Suppression;
use crate::timeline::{
    AutomaticCause, OperatorCommandKind, TimelineEntry, TimelinePayload, TransitionCause,
};
use crate::transition;

/// Every stored piece of one incident's history, kept behind
/// [`IncidentStore`] (Phase 5B-0, ADR 0029) rather than as this struct's
/// own fields — `InMemoryIncidentStore` is the reference implementation,
/// used here unconditionally, but any type implementing the trait would
/// do. A prior version of this doc warned that splitting into a
/// repository trait risked "guessing the seam wrong before 5B's real
/// PostgreSQL implementation exists to compare against"; ADR 0029 records
/// why that risk is accepted now rather than deferred again, and
/// [`crate::store`]'s module doc records the specific risk (partial
/// writes under a future async adapter) that acceptance carries forward
/// as **FU-44**.
pub struct IncidentUnitOfWork {
    store: Box<dyn IncidentStore>,
    timeline_sequence: u64,
    audit_sequence: u64,
    outbox_sequence: u64,
    incident_generator: Box<dyn IncidentGenerator>,
    number_allocator: Box<dyn NumberAllocator>,
    /// The display year tagged onto every [`crate::number::IncidentNumber`]
    /// this unit-of-work allocates. Deliberately not derived from a wall
    /// clock — that would be a time dependency this crate does not need —
    /// and deliberately not hardcoded at the call site either, so a test
    /// or a future caller can supply an explicit, deterministic period.
    /// Provisional in the same sense as the rest of `IncidentNumber`'s
    /// display format (FU-24): this is a display value, not a domain rule,
    /// and 5A implements no year-reset semantics.
    number_allocation_year: u32,
    clock: Box<dyn Clock>,
    closure_policy: ClosurePolicy,
    reopen_policy: ReopenPolicy,
    /// Test-support seam: when set, every subsequent mutation's
    /// `maybe_fail` checkpoint returns an error instead of committing
    /// its timeline/audit/outbox writes. `cfg(test)`-gated so it exists
    /// only in the crate's own test builds and is not part of the public
    /// production API — a production caller with `&mut
    /// IncidentUnitOfWork` must not be able to switch every subsequent
    /// mutation to failure. Exercised by
    /// `unit_of_work::tests::failure_injection_documents_the_in_memory_commit_boundary`,
    /// which lives in this module (rather than the separate `tests/`
    /// integration crate) precisely so it can see this field.
    #[cfg(test)]
    fail_after_incident_write: bool,
}

/// Result of successfully ingesting a detection event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestResult {
    pub outcome_kind: IngestOutcomeKind,
    pub incident_id: Option<IncidentId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcomeKind {
    Created,
    Updated,
    Reopened,
    LinkedLate,
    Duplicate,
    Quarantined,
    ObserveOnly,
}

/// The permission an audit record should name for a mutation, given which
/// actor caused it. An automatic transition is driven by the correlator
/// (or, eventually, a 5C scheduler) holding only `IncidentIngest` — never
/// the human-facing permission (`IncidentResolve`, `IncidentClose`, …)
/// that name describes an *operator* exercising. Auditing an automatic
/// transition under the operator permission would record a grant that was
/// never checked and never held.
fn audited_permission_for(cause: &TransitionCause, operator_permission: Permission) -> Permission {
    match cause {
        TransitionCause::Automatic(_) => Permission::IncidentIngest,
        TransitionCause::Operator(_) => operator_permission,
    }
}

/// The placeholder display year used until a caller configures a real one
/// via [`IncidentUnitOfWork::with_number_allocation_year`]. Not a domain
/// rule — see the field doc on `number_allocation_year` and FU-24.
const PROVISIONAL_DEFAULT_ALLOCATION_YEAR: u32 = 2026;

impl IncidentUnitOfWork {
    pub fn new(
        incident_generator: Box<dyn IncidentGenerator>,
        number_allocator: Box<dyn NumberAllocator>,
        clock: Box<dyn Clock>,
    ) -> Self {
        IncidentUnitOfWork {
            store: Box::new(InMemoryIncidentStore::new()),
            timeline_sequence: 0,
            audit_sequence: 0,
            outbox_sequence: 0,
            incident_generator,
            number_allocator,
            number_allocation_year: PROVISIONAL_DEFAULT_ALLOCATION_YEAR,
            clock,
            closure_policy: ClosurePolicy::approved_default(),
            reopen_policy: ReopenPolicy::approved_default(),
            #[cfg(test)]
            fail_after_incident_write: false,
        }
    }

    /// Overrides the display year tagged onto every subsequently allocated
    /// [`crate::number::IncidentNumber`]. See the `number_allocation_year`
    /// field doc — this is a display value, not a time dependency.
    pub fn with_number_allocation_year(mut self, year: u32) -> Self {
        self.number_allocation_year = year;
        self
    }

    pub fn with_policies(
        mut self,
        closure_policy: ClosurePolicy,
        reopen_policy: ReopenPolicy,
    ) -> Self {
        self.closure_policy = closure_policy;
        self.reopen_policy = reopen_policy;
        self
    }

    /// Replaces the backing store, for a persistence adapter that runs one
    /// call against rows it has already loaded ([ADR 0034]'s
    /// load–run–flush). Call it on a freshly built unit of work: the
    /// timeline/audit/outbox sequence counters are not rewound, so they
    /// only mean "order within this call" in that mode.
    ///
    /// [ADR 0034]: ../../../docs/architecture/decisions/0034-phase5b-persistence-bridge-load-run-flush.md
    pub fn with_store(mut self, store: Box<dyn IncidentStore>) -> Self {
        self.store = store;
        self
    }

    /// Consumes this unit of work and hands back its store, so the adapter
    /// that supplied it through [`Self::with_store`] can read what the call
    /// changed. Recover the concrete type by upcasting to
    /// `Box<dyn std::any::Any>` and downcasting.
    pub fn into_store(self) -> Box<dyn IncidentStore> {
        self.store
    }

    pub fn get(&self, id: &IncidentId) -> Option<&Incident> {
        self.store.get(id)
    }

    pub fn timeline(&self) -> &[TimelineEntry] {
        self.store.timeline()
    }

    pub fn audit(&self) -> &[AuditEntry] {
        self.store.audit()
    }

    pub fn outbox(&self) -> &[OutboxMessage] {
        self.store.outbox()
    }

    pub fn incident_count(&self) -> usize {
        self.store.len()
    }

    /// The authoritative UTC instant for the operation being decided.
    ///
    /// The in-memory adapter reads the injected clock's wall half. The
    /// future PostgreSQL adapter will source this from
    /// `transaction_timestamp()` instead, so that one database rather than
    /// several application hosts with independently drifting clocks is the
    /// single authority on when a transition was decided (ADR 0031).
    fn decision_time(&self) -> Result<DurableTimestamp, IncidentError> {
        DurableTimestamp::now(self.clock.as_ref())
    }

    /// Documented overflow behavior: `saturating_add`, not a wrapping
    /// `+= 1`. Unlike `version`, these three sequence counters are
    /// display/ordering values, not an optimistic-concurrency comparison
    /// — saturating at `u64::MAX` (unreachable in practice; it would
    /// require that many timeline entries) can duplicate the final
    /// sequence number rather than wrap to a small one that could collide
    /// with an early entry.
    fn next_timeline_sequence(&mut self) -> u64 {
        let s = self.timeline_sequence;
        self.timeline_sequence = self.timeline_sequence.saturating_add(1);
        s
    }

    fn next_audit_sequence(&mut self) -> u64 {
        let s = self.audit_sequence;
        self.audit_sequence = self.audit_sequence.saturating_add(1);
        s
    }

    fn next_outbox_sequence(&mut self) -> u64 {
        let s = self.outbox_sequence;
        self.outbox_sequence = self.outbox_sequence.saturating_add(1);
        s
    }

    /// Test-support seam (see the field doc comment on
    /// `fail_after_incident_write`). `cfg(test)`-gated: not part of the
    /// public production API.
    #[cfg(test)]
    pub(crate) fn inject_failure_after_incident_write(&mut self, enabled: bool) {
        self.fail_after_incident_write = enabled;
    }

    #[cfg(test)]
    fn maybe_fail(&self) -> Result<(), IncidentError> {
        if self.fail_after_incident_write {
            Err(IncidentError::InternalInvariantViolation(
                "injected test failure",
            ))
        } else {
            Ok(())
        }
    }

    #[cfg(not(test))]
    fn maybe_fail(&self) -> Result<(), IncidentError> {
        Ok(())
    }

    /// Checks a permission and, if denied, writes exactly one denied
    /// audit record and returns `Err(Unauthorized)` — before anything
    /// else is touched. Never mutates an incident, never bumps a
    /// version, never emits an outbox event.
    fn check_permission(
        &mut self,
        auth: &AuthorizationContext,
        permission: Permission,
        resource: AttemptedResource,
    ) -> Result<(), IncidentError> {
        if auth.has(permission) {
            return Ok(());
        }
        let sequence = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::denied(
            sequence,
            auth.tenant().clone(),
            auth.actor().clone(),
            permission,
            resource,
            "missing required permission",
        ));
        // The denial stands regardless of anything about the audit write
        // itself — in this in-memory store the push above cannot fail,
        // and the ordering here (decide denied, then audit, then return
        // denied) is deliberate: the returned result does not depend on
        // the audit push having "succeeded" in any sense beyond being a
        // Vec::push.
        Err(IncidentError::Unauthorized)
    }

    fn check_tenant(
        &self,
        auth: &AuthorizationContext,
        incident: &Incident,
    ) -> Result<(), IncidentError> {
        if &incident.tenant_id != auth.tenant() {
            return Err(IncidentError::NotFound);
        }
        Ok(())
    }

    // ---------------------------------------------------------------
    // Ingestion / correlation
    // ---------------------------------------------------------------

    /// Runs the six-outcome deterministic correlation decision procedure
    /// against one detection event and applies its effect atomically.
    pub fn ingest_detection_event(
        &mut self,
        auth: &AuthorizationContext,
        event: &DetectionEvent,
    ) -> Result<IngestResult, IncidentError> {
        let resource = AttemptedResource::Unresolved(event.detection_id.clone());
        self.check_permission(auth, Permission::IncidentIngest, resource)?;

        let tenant = TenantId::new(event.target.tenant.clone());
        if &tenant != auth.tenant() {
            return Err(IncidentError::TenantMismatch);
        }

        // 1. Schema and safety gate. Nothing in this release can act on
        // traffic (ADR 0007, ADR 0011), so an event reporting an executed
        // action is forged or corrupt: quarantined, never linked, so no
        // incident ever holds one (Gate 2).
        if event.schema_version > wetechinetmon_detector::EVENT_SCHEMA_VERSION || event.executed {
            return Ok(IngestResult {
                outcome_kind: IngestOutcomeKind::Quarantined,
                incident_id: None,
            });
        }

        // 2. Duplicate gate — runs before anything mutable.
        let dedup = (tenant.clone(), event.dedup_key.clone());
        if let Some(existing) = self.store.dedup_get(&dedup) {
            return Ok(IngestResult {
                outcome_kind: IngestOutcomeKind::Duplicate,
                incident_id: Some(existing),
            });
        }

        // 3. Mode gate — Observe events never open or change an incident.
        if !event.is_publishable() && event.action == wetechinetmon_detector::ActionTaken::Observed
        {
            return Ok(IngestResult {
                outcome_kind: IngestOutcomeKind::ObserveOnly,
                incident_id: None,
            });
        }

        let key = CorrelationKey::new(
            tenant.clone(),
            event.target.scope_type,
            event.target.scope_id.clone(),
            event.target.direction,
            event.target.address_family,
        );

        // 4. Lookup.
        if let Some(incident_id) = self.store.open_index_get(&key) {
            self.store.dedup_record(dedup, incident_id);
            let result = self.link_event_to_open_incident(auth, incident_id, event)?;
            // Let the state machine decide whether this event causes a
            // transition (correlation design, step 5): an `Ended` event
            // on an open, non-recovering incident automatically enters
            // `Recovering`. A late `Ended` (superseded by a newer event
            // already recorded) or one on an incident already past
            // `Open`/`Acknowledged`/`Investigating`/`Monitoring` is
            // linked as evidence only — `enter_recovering`'s own guard
            // is what makes that distinction, so a failure here is
            // expected and silently ignored rather than propagated.
            if event.kind == EventKind::Ended && result.outcome_kind == IngestOutcomeKind::Updated {
                let reason = match event.reason {
                    wetechinetmon_detector::TransitionReason::Stale => {
                        transition::DetectionEndReason::DetectorStale
                    }
                    wetechinetmon_detector::TransitionReason::PolicyWithdrawn => {
                        transition::DetectionEndReason::PolicyWithdrawn
                    }
                    wetechinetmon_detector::TransitionReason::ManualReset => {
                        transition::DetectionEndReason::DetectorReset
                    }
                    _ => transition::DetectionEndReason::TrafficCleared,
                };
                let _ = self.enter_recovering(auth, incident_id, reason);
            }
            return Ok(result);
        }

        // 5. Not found — look for a recently resolved or closed incident
        // to reopen. `is_reopen_candidate()` is deliberately not
        // `state.is_terminal()` (Closed-only) and not
        // `is_open_for_correlation()` (excludes Closed): a Resolved
        // incident is removed from `open_index` the moment it resolves,
        // so it must still be found here or a recurrence would silently
        // create a second incident instead of reopening it (BQ-9's
        // "a Resolved incident may be reopened, not only a Closed one").
        // Deterministic selection when more than one historical incident
        // matches this key: the most recently resolved-or-closed one,
        // using each candidate's own reopen reference timestamp
        // (`resolved_at` for Resolved, `closed_at` for Closed) rather than
        // `closed_at` alone, which would treat every Resolved candidate as
        // equally (un)ranked.
        let reopen_candidate = self.store.reopen_candidate(&key, &tenant);

        if let Some(candidate) = reopen_candidate {
            // T-18: news about what was already resolved never reopens it.
            // A detection ending, or any event of a detection episode the
            // incident already holds as evidence, is late: it links as
            // evidence and leaves the state alone. A recurrence is a new
            // episode, with a new detection id (ADR 0009). Comparing
            // detection ids rather than timestamps keeps the detector's
            // clock out of the decision (ADR 0031). Past the evidence cap
            // an old id may no longer be retained; the event then reopens,
            // which errs toward visibility.
            let already_held = candidate
                .evidence
                .retained()
                .iter()
                .any(|reference| reference.detection_id == event.detection_id);
            if event.kind == EventKind::Ended || already_held {
                let incident_id = candidate.incident_id;
                self.store.dedup_record(dedup, incident_id);
                return self.link_event(auth, incident_id, event, true);
            }
            let now = self.decision_time()?;
            // ADR 0031: a decision time before the candidate's reference is
            // clock skew. Returned, never read as "outside the window": that
            // would fall through to creating a duplicate incident.
            if transition::evaluate_reopen(candidate, &self.reopen_policy, &now)? {
                let incident_id = candidate.incident_id;
                self.store.dedup_record(dedup, incident_id);
                return self.reopen_incident_internal(
                    auth,
                    incident_id,
                    event,
                    AutomaticCause::ReopenedByRecurrence,
                );
            }
        }

        // 6. Ended events with nothing to attach to create nothing.
        if event.kind == EventKind::Ended {
            return Ok(IngestResult {
                outcome_kind: IngestOutcomeKind::Quarantined,
                incident_id: None,
            });
        }

        // Create.
        let incident_id = self.create_incident_internal(auth, &tenant, &key, event)?;
        self.store.dedup_record(dedup, incident_id);
        Ok(IngestResult {
            outcome_kind: IngestOutcomeKind::Created,
            incident_id: Some(incident_id),
        })
    }

    /// Opens an incident an operator asked for (ADR 0039). Needs
    /// `incident.create`.
    ///
    /// The incident takes the correlation key a detection for the same
    /// target would, so where one is already active the request is refused
    /// with [`IncidentError::DuplicateActiveIncident`] naming it, and while
    /// this one is active, detections attach to it. With an idempotency
    /// key, a retry replays the first outcome.
    pub fn create_manual_incident(
        &mut self,
        auth: &AuthorizationContext,
        request: ManualIncident,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Result<IncidentId, IncidentError> {
        self.check_permission(
            auth,
            Permission::IncidentCreate,
            AttemptedResource::Unresolved("new incident".to_string()),
        )?;
        let fingerprint = RequestFingerprint::of(&("create_manual_incident", &request));
        if let Some(key) = &idempotency_key {
            match self
                .store
                .idempotency()
                .check(auth.tenant(), key, &fingerprint)
            {
                IdempotencyCheck::Replay(StoredOutcome::Mutated { incident_id, .. }) => {
                    return Ok(incident_id)
                }
                IdempotencyCheck::Replay(StoredOutcome::Failed(err)) => return Err(err),
                IdempotencyCheck::Conflict => return Err(IncidentError::IdempotencyConflict),
                IdempotencyCheck::New => {}
            }
        }

        let result = self.open_manual_incident(auth, &request);

        if let Some(key) = idempotency_key {
            let outcome = match &result {
                // Never persisted: a retry may succeed once it clears.
                Err(IncidentError::InternalInvariantViolation(_)) => None,
                Ok(incident_id) => Some(StoredOutcome::Mutated {
                    incident_id: *incident_id,
                    version: 1,
                }),
                Err(err) => Some(StoredOutcome::Failed(err.clone())),
            };
            if let Some(outcome) = outcome {
                self.store.idempotency_mut().record(
                    auth.tenant().clone(),
                    key,
                    fingerprint,
                    outcome,
                );
            }
        }
        result
    }

    fn open_manual_incident(
        &mut self,
        auth: &AuthorizationContext,
        request: &ManualIncident,
    ) -> Result<IncidentId, IncidentError> {
        request.validate()?;
        let tenant = auth.tenant().clone();
        let key = request.correlation_key(&tenant);
        if let Some(existing) = self.store.open_index_get(&key) {
            return Err(IncidentError::DuplicateActiveIncident(existing));
        }
        let now = self.decision_time()?;
        let incident_id = self.incident_generator.generate()?;
        let incident_number = self
            .number_allocator
            .allocate(tenant.as_str(), self.number_allocation_year)?;
        let matched_metrics = BTreeSet::new();
        let category = derive_category(&matched_metrics);
        let actor = auth.actor().clone();

        let incident = Incident {
            incident_id,
            incident_number,
            schema_version: INCIDENT_SCHEMA_VERSION,
            tenant_id: tenant.clone(),
            correlation_key: key.clone(),
            address_family: request.address_family,
            direction: request.direction,
            target_type: request.target_type,
            target_identity: request.target_identity.clone(),
            created_by: actor.clone(),
            title: request.title.clone(),
            description: request.description.clone(),
            state: IncidentState::Open,
            severity: request.severity,
            severity_source: SeveritySource::Operator,
            ever_critical: request.severity == wetechinetmon_detector::Severity::Critical,
            maximum_detected_severity: request.severity,
            priority: request
                .priority
                .unwrap_or_else(|| Priority::default_for(request.severity)),
            closure_reason: None,
            state_before_recovering: None,
            suppression: None,
            version: 1,
            category,
            matched_metrics,
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
            updated_by: actor.clone(),
            evidence: crate::evidence::EvidenceLedger::new(),
            notes: Vec::new(),
            tags: std::collections::BTreeMap::new(),
            policy_refs: Vec::new(),
            policy_refs_omitted: 0,
        };

        self.store.insert(incident);
        self.store.open_index_claim(key, incident_id);
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            actor.clone(),
            TimelinePayload::Opened,
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            tenant.clone(),
            actor,
            Permission::IncidentCreate,
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            tenant,
            incident_id,
            OutboxEvent::IncidentOpened,
        ));
        Ok(incident_id)
    }

    /// Records that `auth` is exporting the incident: an allowed audit
    /// entry under `incident.export`, and nothing else. Exports carry an
    /// incident's whole history out of the system, so each one is
    /// attributable; the caller records it before reading.
    pub fn record_export(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
    ) -> Result<(), IncidentError> {
        self.check_permission(
            auth,
            Permission::IncidentExport,
            AttemptedResource::Unresolved(incident_id.to_string()),
        )?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        self.check_tenant(auth, incident)?;
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentExport,
            incident_id,
        ));
        Ok(())
    }

    fn create_incident_internal(
        &mut self,
        auth: &AuthorizationContext,
        tenant: &TenantId,
        key: &CorrelationKey,
        event: &DetectionEvent,
    ) -> Result<IncidentId, IncidentError> {
        if self.store.open_index_get(key).is_some() {
            return Err(CorrelationConflict::OpenIncidentAlreadyExists(
                self.store.open_index_get(key).expect("checked above"),
            )
            .into());
        }
        let now = self.decision_time()?;
        let incident_id = self.incident_generator.generate()?;
        // Wall-clock year derivation is a display concern; `Timestamp`
        // carries no calendar API without a new dependency, so the value
        // comes from `self.number_allocation_year` (configurable via
        // `with_number_allocation_year`, defaulting to a documented
        // placeholder) rather than a literal — see that field's doc and
        // FU-24 for why the number itself stays provisional regardless.
        let incident_number = self
            .number_allocator
            .allocate(tenant.as_str(), self.number_allocation_year)?;

        let mut matched_metrics: BTreeSet<MetricKind> = BTreeSet::new();
        for reason in &event.matched {
            matched_metrics.insert(reason.metric);
        }
        let category = derive_category(&matched_metrics);

        let evidence_ref = EvidenceReference {
            detection_event_id: event.event_id.clone(),
            dedup_key: event.dedup_key.clone(),
            detection_id: event.detection_id.clone(),
            link_type: EvidenceLinkType::Opening,
            matched_metrics: matched_metrics.iter().copied().collect(),
        };
        let mut evidence = crate::evidence::EvidenceLedger::new();
        evidence.record(evidence_ref.clone());

        let incident = Incident {
            incident_id,
            incident_number,
            schema_version: INCIDENT_SCHEMA_VERSION,
            tenant_id: tenant.clone(),
            correlation_key: key.clone(),
            address_family: event.target.address_family,
            direction: event.target.direction,
            target_type: event.target.scope_type,
            target_identity: event.target.scope_id.clone(),
            created_by: Actor::System,
            title: event
                .summary
                .chars()
                .take(crate::limits::TITLE_MAX_LEN)
                .collect(),
            description: None,
            state: IncidentState::Open,
            severity: event.severity,
            severity_source: SeveritySource::Detection,
            ever_critical: event.severity == wetechinetmon_detector::Severity::Critical,
            maximum_detected_severity: event.severity,
            priority: Priority::default_for(event.severity),
            closure_reason: None,
            state_before_recovering: None,
            suppression: None,
            version: 1,
            category,
            matched_metrics,
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
            evidence,
            notes: Vec::new(),
            tags: std::collections::BTreeMap::new(),
            policy_refs: vec![crate::incident::PolicyRef {
                policy_id: event.policy_id.clone(),
                policy_version: event.policy_version,
                first_seen_sequence: event.sequence,
                last_seen_sequence: event.sequence,
            }],
            policy_refs_omitted: 0,
        };

        self.store.insert(incident);
        self.store.open_index_claim(key.clone(), incident_id);
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            Actor::System,
            TimelinePayload::Opened,
        ));
        let ts2 = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts2,
            incident_id,
            Actor::System,
            TimelinePayload::EventLinked {
                evidence: evidence_ref,
            },
        ));

        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            tenant.clone(),
            auth.actor().clone(),
            Permission::IncidentIngest,
            incident_id,
        ));

        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            tenant.clone(),
            incident_id,
            OutboxEvent::IncidentOpened,
        ));

        Ok(incident_id)
    }

    fn link_event_to_open_incident(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        event: &DetectionEvent,
    ) -> Result<IngestResult, IncidentError> {
        self.link_event(auth, incident_id, event, false)
    }

    /// Links `event` as evidence. `late` forces a late link, which never
    /// moves `last_detected_at`; otherwise an event is late when the
    /// decision time is behind `last_detected_at`.
    fn link_event(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        event: &DetectionEvent,
        late: bool,
    ) -> Result<IngestResult, IncidentError> {
        let now = self.decision_time()?;

        let (evidence_ref, is_late, category_changed, old_category, new_category) = {
            let incident = self
                .store
                .get_mut(&incident_id)
                .ok_or(IncidentError::NotFound)?;
            let is_late = late || now < incident.last_detected_at;
            let new_version = incident.version.checked_add(1).ok_or(
                IncidentError::InternalInvariantViolation("incident version overflowed u64"),
            )?;

            for reason in &event.matched {
                incident.matched_metrics.insert(reason.metric);
            }
            // FU-34: record every distinct policy that ever matched, not
            // only the one that opened the incident — otherwise a second
            // policy matching a later event leaves no trace anywhere on
            // the aggregate. Bounded the same way evidence is (stops
            // growing new distinct entries past the cap, per the
            // documented asymmetry in `crate::limits`), rather than
            // refusing the whole event link over policy bookkeeping.
            match incident
                .policy_refs
                .iter()
                .position(|p| p.policy_id == event.policy_id)
            {
                Some(idx) => {
                    // Events can arrive out of order. The seen range only
                    // widens, so `first_seen <= last_seen` always holds, and
                    // an older event never overwrites a newer event's
                    // policy version.
                    let existing = &mut incident.policy_refs[idx];
                    if event.sequence >= existing.last_seen_sequence {
                        existing.last_seen_sequence = event.sequence;
                        existing.policy_version = event.policy_version;
                    }
                    existing.first_seen_sequence = existing.first_seen_sequence.min(event.sequence);
                }
                None if incident.policy_refs.len() < POLICY_REFS_MAX => {
                    incident.policy_refs.push(crate::incident::PolicyRef {
                        policy_id: event.policy_id.clone(),
                        policy_version: event.policy_version,
                        first_seen_sequence: event.sequence,
                        last_seen_sequence: event.sequence,
                    });
                }
                None => {
                    // At the cap: counted, never silently dropped (FU-34).
                    incident.policy_refs_omitted = incident.policy_refs_omitted.saturating_add(1);
                }
            }
            let new_category = derive_category(&incident.matched_metrics);
            let old_category = incident.category;
            let category_changed = new_category != old_category;

            let evidence_ref = EvidenceReference {
                detection_event_id: event.event_id.clone(),
                dedup_key: event.dedup_key.clone(),
                detection_id: event.detection_id.clone(),
                link_type: if is_late {
                    EvidenceLinkType::Late
                } else {
                    EvidenceLinkType::Update
                },
                matched_metrics: event.matched.iter().map(|m| m.metric).collect(),
            };
            incident.evidence.record(evidence_ref.clone());
            if !is_late {
                incident.last_detected_at = now;
            }
            incident.last_updated_at = now;
            incident.category = new_category;
            incident.version = new_version;
            (
                evidence_ref,
                is_late,
                category_changed,
                old_category,
                new_category,
            )
        };
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        let payload = if is_late {
            TimelinePayload::LateEventLinked {
                evidence: evidence_ref,
            }
        } else {
            TimelinePayload::EventLinked {
                evidence: evidence_ref,
            }
        };
        self.store
            .append_timeline(TimelineEntry::new(ts, incident_id, Actor::System, payload));
        if category_changed {
            let ts2 = self.next_timeline_sequence();
            self.store.append_timeline(TimelineEntry::new(
                ts2,
                incident_id,
                Actor::System,
                TimelinePayload::CategoryChanged {
                    from: old_category,
                    to: new_category,
                },
            ));
        }
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentIngest,
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentUpdated,
        ));

        Ok(IngestResult {
            outcome_kind: if is_late {
                IngestOutcomeKind::LinkedLate
            } else {
                IngestOutcomeKind::Updated
            },
            incident_id: Some(incident_id),
        })
    }

    fn reopen_incident_internal(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        event: &DetectionEvent,
        cause: AutomaticCause,
    ) -> Result<IngestResult, IncidentError> {
        let now = self.decision_time()?;
        let key = {
            let incident = self
                .store
                .get(&incident_id)
                .ok_or(IncidentError::NotFound)?;
            if self
                .store
                .open_index_get(&incident.correlation_key)
                .is_some()
            {
                return Err(CorrelationConflict::OpenIncidentAlreadyExists(
                    self.store
                        .open_index_get(&incident.correlation_key)
                        .expect("checked above"),
                )
                .into());
            }
            incident.correlation_key.clone()
        };

        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let from_state = incident.state;
        // FU-38: this path is reached today only from a caller that has
        // already checked `is_reopen_candidate()` (Resolved or Closed) and
        // the reopen window. The guard is repeated here, independently, so
        // that stays true no matter how many callers this function ever
        // gets — the same reasoning close_internal's guard above uses.
        //
        // Deliberately `is_reopen_candidate()`, not
        // `can_automatic_transition_to(Open)`: that table also legalizes
        // `Recovering -> Open` for recovery-abort restoration, a
        // completely different operation with its own path
        // (`Self::abort_recovery`, via `transition::abort_recovery`) that
        // does not touch `reopen_count`, `reopened_at`, or evidence the
        // way this function does. Using the wider table here would let a
        // future caller reopen-bookkeep a Recovering incident, which is
        // not a state this function's mutations are correct for.
        if !matches!(from_state, IncidentState::Resolved | IncidentState::Closed) {
            return Err(IncidentError::InvalidTransition {
                from: from_state,
                to: IncidentState::Open,
            });
        }
        // Both counters computed before any field is mutated.
        let new_reopen_count = incident.reopen_count.checked_add(1).ok_or(
            IncidentError::InternalInvariantViolation("reopen_count overflowed u32"),
        )?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;

        let incident = self.store.get_mut(&incident_id).expect("checked above");
        incident.state = IncidentState::Open;
        incident.reopen_count = new_reopen_count;
        incident.reopened_at = Some(now);
        incident.last_detected_at = now;
        incident.last_updated_at = now;
        incident.closure_reason = None;
        // FU-37: `resolved_at`/`closed_at` are current-state fields, not
        // historical ones — the prior cycle's values are already
        // preserved immutably in the timeline's `StateChanged` entries.
        // Leaving them set here would let a now-active, reopened incident
        // display a stale "resolved"/"closed" timestamp.
        incident.resolved_at = None;
        incident.closed_at = None;
        for reason in &event.matched {
            incident.matched_metrics.insert(reason.metric);
        }
        incident.category = derive_category(&incident.matched_metrics);
        let evidence_ref = EvidenceReference {
            detection_event_id: event.event_id.clone(),
            dedup_key: event.dedup_key.clone(),
            detection_id: event.detection_id.clone(),
            link_type: EvidenceLinkType::Opening,
            matched_metrics: event.matched.iter().map(|m| m.metric).collect(),
        };
        incident.evidence.record(evidence_ref);
        incident.version = new_version;
        let reopen_count = incident.reopen_count;
        self.maybe_fail()?;

        self.store.open_index_claim(key, incident_id);

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            Actor::System,
            TimelinePayload::StateChanged {
                from: from_state,
                to: IncidentState::Open,
                cause: TransitionCause::Automatic(cause),
            },
        ));
        let ts2 = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts2,
            incident_id,
            Actor::System,
            TimelinePayload::Reopened {
                reopen_count,
                previous_incident_id: None,
                reason: None,
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentIngest,
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentReopened { reopen_count },
        ));

        Ok(IngestResult {
            outcome_kind: IngestOutcomeKind::Reopened,
            incident_id: Some(incident_id),
        })
    }

    // ---------------------------------------------------------------
    // Automatic maintenance (recovery entry / confirm / abort, auto-close)
    // ---------------------------------------------------------------

    /// Driven by the correlator (or, from 5C on, a scheduler) holding
    /// `IncidentIngest` — this is not an operator command, and must not
    /// be reachable by a caller who lacks even that permission.
    pub fn enter_recovering(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        reason: transition::DetectionEndReason,
    ) -> Result<(), IncidentError> {
        // Not yet resolved or tenant-checked — `Unresolved` (L4), same
        // rationale as `handle_command`'s permission check.
        self.check_permission(
            auth,
            Permission::IncidentIngest,
            AttemptedResource::Unresolved(incident_id.to_string()),
        )?;
        let now = self.decision_time()?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        self.check_tenant(auth, incident)?;
        let _ = transition::enter_recovering(incident, reason)?;
        let from = incident.state;
        let key = incident.correlation_key.clone();
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;

        let incident = self.store.get_mut(&incident_id).expect("checked above");
        incident.state_before_recovering = Some(from);
        incident.state = IncidentState::Recovering;
        incident.recovering_since = Some(now);
        incident.last_updated_at = now;
        incident.version = new_version;
        self.maybe_fail()?;
        // Recovering is still "open" for correlation purposes, so the
        // open_index entry is left untouched (it already points here).
        let _ = &key;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            Actor::System,
            TimelinePayload::StateChanged {
                from,
                to: IncidentState::Recovering,
                cause: TransitionCause::Automatic(reason.into()),
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentIngest,
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentRecovering,
        ));
        Ok(())
    }

    /// The staleness sweep's transition (5C): an active incident whose
    /// detector has said nothing for `silent_after` moves to `Recovering`
    /// with reason `DetectorSilent`. `Ok(false)` if a detection arrived
    /// recently enough, checked here against the incident as this call
    /// reads it, so an event that landed after the sweep chose the incident
    /// keeps it open.
    pub fn enter_recovering_if_silent(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        silent_after: Duration,
    ) -> Result<bool, IncidentError> {
        // Not yet resolved or tenant-checked — `Unresolved` (L4), same
        // rationale as `handle_command`'s permission check.
        self.check_permission(
            auth,
            Permission::IncidentIngest,
            AttemptedResource::Unresolved(incident_id.to_string()),
        )?;
        let now = self.decision_time()?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        self.check_tenant(auth, incident)?;
        if now.checked_elapsed_since(&incident.last_detected_at)? < silent_after {
            return Ok(false);
        }
        self.enter_recovering(
            auth,
            incident_id,
            transition::DetectionEndReason::DetectorSilent,
        )?;
        Ok(true)
    }

    /// Driven by the correlator or scheduler — see [`Self::enter_recovering`].
    pub fn confirm_recovery_if_due(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        recovery_confirmation: Duration,
    ) -> Result<bool, IncidentError> {
        // Not yet resolved or tenant-checked — `Unresolved` (L4), same
        // rationale as `handle_command`'s permission check.
        self.check_permission(
            auth,
            Permission::IncidentIngest,
            AttemptedResource::Unresolved(incident_id.to_string()),
        )?;
        let now = self.decision_time()?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        self.check_tenant(auth, incident)?;
        transition::confirm_recovery(incident)?;
        let recovering_since =
            incident
                .recovering_since
                .ok_or(IncidentError::InternalInvariantViolation(
                    "Recovering incident has no recovering_since",
                ))?;
        if now.checked_elapsed_since(&recovering_since)? < recovery_confirmation {
            return Ok(false);
        }
        self.resolve_internal(
            auth,
            incident_id,
            TransitionCause::Automatic(AutomaticCause::RecoveryConfirmed),
            None,
        )?;
        Ok(true)
    }

    /// Driven by the correlator or scheduler — see [`Self::enter_recovering`].
    pub fn abort_recovery(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
    ) -> Result<(), IncidentError> {
        // Not yet resolved or tenant-checked — `Unresolved` (L4), same
        // rationale as `handle_command`'s permission check.
        self.check_permission(
            auth,
            Permission::IncidentIngest,
            AttemptedResource::Unresolved(incident_id.to_string()),
        )?;
        let now = self.decision_time()?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        self.check_tenant(auth, incident)?;
        let restored = transition::abort_recovery(incident)?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;

        let incident = self.store.get_mut(&incident_id).expect("checked above");
        incident.state = restored;
        incident.recovering_since = None;
        incident.state_before_recovering = None;
        incident.last_updated_at = now;
        incident.version = new_version;
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            Actor::System,
            TimelinePayload::StateChanged {
                from: IncidentState::Recovering,
                to: restored,
                cause: TransitionCause::Automatic(AutomaticCause::RecoveryAborted),
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentIngest,
            incident_id,
        ));
        Ok(())
    }

    /// Driven by the correlator or scheduler — see [`Self::enter_recovering`].
    pub fn attempt_automatic_closure(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
    ) -> Result<bool, IncidentError> {
        // Not yet resolved or tenant-checked — `Unresolved` (L4), same
        // rationale as `handle_command`'s permission check.
        self.check_permission(
            auth,
            Permission::IncidentIngest,
            AttemptedResource::Unresolved(incident_id.to_string()),
        )?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        self.check_tenant(auth, incident)?;
        match transition::attempt_automatic_closure(incident, &self.closure_policy) {
            Ok(()) => {
                // FU-40: the delay is enforced here, where the incident is
                // read under the call's own consistency, not only by the
                // scheduler's query that chose it. An incident reopened and
                // resolved again since that query must wait a full delay.
                let resolved_at =
                    incident
                        .resolved_at
                        .ok_or(IncidentError::InternalInvariantViolation(
                            "Resolved incident has no resolved_at",
                        ))?;
                let now = self.decision_time()?;
                if now.checked_elapsed_since(&resolved_at)?
                    < self.closure_policy.automatic_closure_delay
                {
                    return Ok(false);
                }
                self.close_internal(
                    auth,
                    incident_id,
                    crate::closure::ClosureReason::Resolved,
                    TransitionCause::Automatic(AutomaticCause::AutomaticClosure),
                )?;
                Ok(true)
            }
            Err(IncidentError::ManualClosureRequired) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Guarded `-> Resolved`. Every call site — the operator command and
    /// the automatic recovery-confirmation path — must have its edge
    /// validated here before any mutation happens; this was previously
    /// missing, which let `Closed -> Resolved` and `Resolved -> Resolved`
    /// both succeed unguarded (see the review's B2 finding).
    fn resolve_internal(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        cause: TransitionCause,
        resolution_note: Option<String>,
    ) -> Result<(), IncidentError> {
        let now = self.decision_time()?;
        let existing = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let current_state = existing.state;
        if current_state == IncidentState::Resolved {
            return Err(IncidentError::StateUnchanged(current_state));
        }
        let legal = match cause {
            TransitionCause::Automatic(_) => {
                current_state.can_automatic_transition_to(IncidentState::Resolved)
            }
            TransitionCause::Operator(_) => {
                current_state.can_operator_transition_to(IncidentState::Resolved)
            }
        };
        if !legal {
            return Err(IncidentError::InvalidTransition {
                from: current_state,
                to: IncidentState::Resolved,
            });
        }
        let new_version =
            existing
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;

        let (from, correlation_key) = {
            let incident = self
                .store
                .get_mut(&incident_id)
                .ok_or(IncidentError::NotFound)?;
            let from = incident.state;
            incident.state = IncidentState::Resolved;
            incident.resolved_at = Some(now);
            incident.recovering_since = None;
            incident.state_before_recovering = None;
            incident.last_updated_at = now;
            incident.version = new_version;
            (from, incident.correlation_key.clone())
        };
        self.store.open_index_release(&correlation_key);
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::StateChanged {
                from,
                to: IncidentState::Resolved,
                cause,
            },
        ));
        if let Some(note) = resolution_note {
            let incident = self.store.get_mut(&incident_id).expect("checked above");
            let idx = incident.notes.len() as u32;
            incident.notes.push(Note {
                index: idx,
                body: note,
                visibility: NoteVisibility::Internal,
                created_by: auth.actor().clone(),
            });
        }
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            audited_permission_for(&cause, Permission::IncidentResolve),
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentResolved,
        ));
        Ok(())
    }

    fn close_internal(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        reason: crate::closure::ClosureReason,
        cause: TransitionCause,
    ) -> Result<(), IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let from = incident.state;
        // FU-38: this guard used to live only at close_internal's two call
        // sites (Command::CloseIncident checking `state != Resolved`, and
        // attempt_automatic_closure delegating to
        // transition::attempt_automatic_closure). A second caller added
        // without the same check would have been able to close an incident
        // from any state. The check now lives here, dispatched by cause the
        // same way resolve_internal already dispatches its own — so it
        // applies no matter how many callers this function ever gets.
        let legal = match cause {
            TransitionCause::Automatic(_) => {
                from.can_automatic_transition_to(IncidentState::Closed)
            }
            TransitionCause::Operator(_) => from.can_operator_transition_to(IncidentState::Closed),
        };
        if !legal {
            return Err(IncidentError::InvalidTransition {
                from,
                to: IncidentState::Closed,
            });
        }
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        let incident = self.store.get_mut(&incident_id).expect("checked above");
        incident.state = IncidentState::Closed;
        incident.closed_at = Some(now);
        incident.closure_reason = Some(reason);
        incident.last_updated_at = now;
        incident.version = new_version;
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::StateChanged {
                from,
                to: IncidentState::Closed,
                cause,
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            audited_permission_for(&cause, Permission::IncidentClose),
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentClosed,
        ));
        Ok(())
    }

    // ---------------------------------------------------------------
    // Operator commands
    // ---------------------------------------------------------------

    pub fn handle_command(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        command: Command,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Result<u64, IncidentError> {
        let permission = command.required_permission();
        // Not yet resolved against the store or checked against the
        // caller's tenant — this is only what the caller supplied, so a
        // denial here uses `Unresolved` (L4), matching `AttemptedResource`'s
        // own documented rule for a denial before (or instead of) a lookup.
        let resource = AttemptedResource::Unresolved(incident_id.to_string());
        self.check_permission(auth, permission, resource)?;

        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        self.check_tenant(auth, incident)?;

        if let Some(key) = &idempotency_key {
            // The fingerprinted value includes `incident_id`: the same
            // key reused against two different incidents must conflict,
            // not silently replay the first incident's stored result
            // against the second.
            let fingerprint = RequestFingerprint::of(&(incident_id, &command));
            match self
                .store
                .idempotency()
                .check(auth.tenant(), key, &fingerprint)
            {
                IdempotencyCheck::Replay(StoredOutcome::Mutated { version, .. }) => {
                    return Ok(version)
                }
                IdempotencyCheck::Replay(StoredOutcome::Failed(err)) => return Err(err),
                IdempotencyCheck::Conflict => return Err(IncidentError::IdempotencyConflict),
                IdempotencyCheck::New => {}
            }
        }

        if command.requires_expected_version() {
            let expected = command.expected_version().expect("checked above");
            if expected != incident.version {
                return Err(IncidentError::VersionConflict {
                    expected,
                    current: incident.version,
                    current_state: incident.state,
                });
            }
        }

        let result = self.apply_command(auth, incident_id, &command);

        if let Some(key) = idempotency_key {
            match &result {
                Err(IncidentError::InternalInvariantViolation(_)) => {
                    // Transient/injected failure: never persisted as a
                    // permanent idempotency record, so a retry under the
                    // same key can still succeed once the underlying
                    // condition clears.
                }
                _ => {
                    let fingerprint = RequestFingerprint::of(&(incident_id, &command));
                    let outcome = match &result {
                        Ok(version) => StoredOutcome::Mutated {
                            incident_id,
                            version: *version,
                        },
                        Err(err) => StoredOutcome::Failed(err.clone()),
                    };
                    self.store.idempotency_mut().record(
                        auth.tenant().clone(),
                        key,
                        fingerprint,
                        outcome,
                    );
                }
            }
        }

        result
    }

    fn apply_command(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        command: &Command,
    ) -> Result<u64, IncidentError> {
        match command {
            Command::AcknowledgeIncident { .. } => self.guarded_operator_transition(
                auth,
                incident_id,
                IncidentState::Acknowledged,
                command.kind(),
                command.required_permission(),
                |i, now| {
                    i.acknowledged_at = Some(now);
                },
            ),
            Command::BeginInvestigation { .. } => self.guarded_operator_transition(
                auth,
                incident_id,
                IncidentState::Investigating,
                command.kind(),
                command.required_permission(),
                |_, _| {},
            ),
            Command::MarkMonitoring { .. } => self.guarded_operator_transition(
                auth,
                incident_id,
                IncidentState::Monitoring,
                command.kind(),
                command.required_permission(),
                |_, _| {},
            ),
            Command::ResolveIncident {
                resolution_note, ..
            } => {
                self.resolve_internal(
                    auth,
                    incident_id,
                    TransitionCause::Operator(command.kind()),
                    resolution_note.clone(),
                )?;
                Ok(self
                    .store
                    .get(&incident_id)
                    .expect("incident exists")
                    .version)
            }
            Command::CloseIncident { reason, .. } => {
                // The transition-legality check used to live here; it now
                // lives inside close_internal itself (FU-38), so this arm
                // no longer needs its own lookup to perform it.
                self.close_internal(
                    auth,
                    incident_id,
                    *reason,
                    TransitionCause::Operator(command.kind()),
                )?;
                Ok(self
                    .store
                    .get(&incident_id)
                    .expect("incident exists")
                    .version)
            }
            Command::ReopenIncident { reason, .. } => {
                self.operator_reopen(auth, incident_id, reason.clone())
            }
            Command::SuppressIncident {
                reason, duration, ..
            } => self.suppress(auth, incident_id, reason.clone(), *duration),
            Command::UnsuppressIncident { .. } => self.unsuppress(auth, incident_id),
            Command::AssignIncident { assignee, .. } => {
                self.assign(auth, incident_id, Some(assignee.clone()))
            }
            Command::UnassignIncident { .. } => self.assign(auth, incident_id, None),
            Command::ChangeSeverity {
                new_severity,
                reason,
                ..
            } => self.change_severity(auth, incident_id, *new_severity, reason.clone()),
            Command::ChangePriority { new_priority, .. } => {
                self.change_priority(auth, incident_id, *new_priority)
            }
            Command::AddNote { body, visibility } => {
                self.add_note(auth, incident_id, body.clone(), visibility.clone())
            }
            Command::AddTag { key, value } => {
                self.add_tag(auth, incident_id, key.clone(), value.clone())
            }
            Command::RemoveTag { key } => self.remove_tag(auth, incident_id, key.clone()),
        }
    }

    /// Shared by every operator transition that is a pure state move with
    /// no other domain effect (`Acknowledge`, `BeginInvestigation`,
    /// `MarkMonitoring`). `command_kind` and `permission` name the actual
    /// command driving this call — previously hardcoded to
    /// `Acknowledge`/`IncidentAcknowledge` for all three, which made the
    /// timeline and audit records for `BeginInvestigation` and
    /// `MarkMonitoring` indistinguishable from an acknowledgement.
    fn guarded_operator_transition(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        to: IncidentState,
        command_kind: OperatorCommandKind,
        permission: Permission,
        extra: impl FnOnce(&mut Incident, DurableTimestamp),
    ) -> Result<u64, IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let from = incident.state;
        if from == to {
            return Err(IncidentError::StateUnchanged(from));
        }
        if !from.can_operator_transition_to(to) {
            return Err(IncidentError::InvalidTransition { from, to });
        }
        // Computed before any field is mutated: an overflow must refuse
        // the whole transition, not apply the state change and then fail.
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        let incident = self.store.get_mut(&incident_id).expect("checked above");
        incident.state = to;
        incident.last_updated_at = now;
        incident.version = new_version;
        extra(incident, now);
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::StateChanged {
                from,
                to,
                cause: TransitionCause::Operator(command_kind),
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            permission,
            incident_id,
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn operator_reopen(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        reason: String,
    ) -> Result<u64, IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let from = incident.state;
        if !from.can_operator_transition_to(IncidentState::Open) {
            return Err(IncidentError::InvalidTransition {
                from,
                to: IncidentState::Open,
            });
        }
        let key = incident.correlation_key.clone();
        if self.store.open_index_get(&key).is_some() {
            return Err(CorrelationConflict::OpenIncidentAlreadyExists(
                self.store.open_index_get(&key).expect("checked above"),
            )
            .into());
        }
        // Both counters computed before any field is mutated — an
        // overflow on either must refuse the whole reopen.
        let new_reopen_count = incident.reopen_count.checked_add(1).ok_or(
            IncidentError::InternalInvariantViolation("reopen_count overflowed u32"),
        )?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        let incident = self.store.get_mut(&incident_id).expect("checked above");
        incident.state = IncidentState::Open;
        incident.reopen_count = new_reopen_count;
        incident.reopened_at = Some(now);
        incident.closure_reason = None;
        // FU-37: see the analogous comment in the automatic-recurrence
        // reopen path — these are current-state fields, not historical
        // ones.
        incident.resolved_at = None;
        incident.closed_at = None;
        incident.last_updated_at = now;
        incident.version = new_version;
        let reopen_count = incident.reopen_count;
        self.maybe_fail()?;
        self.store.open_index_claim(key, incident_id);

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::StateChanged {
                from,
                to: IncidentState::Open,
                cause: TransitionCause::Operator(crate::timeline::OperatorCommandKind::Reopen),
            },
        ));
        let ts2 = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts2,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::Reopened {
                reopen_count,
                previous_incident_id: None,
                reason: Some(reason),
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentReopen,
            incident_id,
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn suppress(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        reason: String,
        duration: Duration,
    ) -> Result<u64, IncidentError> {
        crate::suppression::validate_reason(&reason)?;
        let now = self.decision_time()?;
        let deadline =
            self.decision_time()?
                .checked_plus(duration)
                .ok_or(IncidentError::ValidationError(
                    "suppression duration is too large to represent as a deadline".to_string(),
                ))?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        incident.suppression = Some(Suppression::new(
            reason.clone(),
            auth.actor().clone(),
            deadline,
        ));
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::Suppressed { reason },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentSuppress,
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentSuppressionChanged { suppressed: true },
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn unsuppress(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
    ) -> Result<u64, IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        incident.suppression = None;
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::Unsuppressed,
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentSuppress,
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentSuppressionChanged { suppressed: false },
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn assign(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        assignee: Option<Assignee>,
    ) -> Result<u64, IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        let from = incident.assignment.assignee.clone();
        incident.assignment.assignee = assignee.clone();
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::AssignmentChanged { from, to: assignee },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentAssign,
            incident_id,
        ));
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentAssignmentChanged,
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn change_severity(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        new_severity: wetechinetmon_detector::Severity,
        reason: Option<String>,
    ) -> Result<u64, IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let from = incident.severity;
        if (new_severity as u8) < (from as u8) && reason.is_none() {
            return Err(IncidentError::ValidationError(
                "a reason is required when lowering severity".to_string(),
            ));
        }
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        incident.severity = new_severity;
        // Latches on reaching Critical; never cleared by an ordinary
        // severity change — see the field's doc on `Incident`.
        if new_severity == wetechinetmon_detector::Severity::Critical {
            incident.ever_critical = true;
        }
        incident.severity_source = SeveritySource::Operator;
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;
        let reason_for_audit = reason.clone();

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::SeverityChanged {
                from,
                to: new_severity,
                reason,
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(
            AuditEntry::allowed(
                asq,
                auth.tenant().clone(),
                auth.actor().clone(),
                Permission::IncidentSeverityChange,
                incident_id,
            )
            .with_change(
                "severity",
                from.as_str(),
                new_severity.as_str(),
                reason_for_audit,
            ),
        );
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentSeverityChanged {
                from,
                to: new_severity,
            },
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn change_priority(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        new_priority: Priority,
    ) -> Result<u64, IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        let from = incident.priority;
        incident.priority = new_priority;
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::PriorityChanged {
                from,
                to: new_priority,
            },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(
            AuditEntry::allowed(
                asq,
                auth.tenant().clone(),
                auth.actor().clone(),
                Permission::IncidentPriorityChange,
                incident_id,
            )
            .with_change("priority", from.as_str(), new_priority.as_str(), None),
        );
        let osq = self.next_outbox_sequence();
        self.store.append_outbox(OutboxMessage::new(
            osq,
            auth.tenant().clone(),
            incident_id,
            OutboxEvent::IncidentPriorityChanged {
                from,
                to: new_priority,
            },
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn add_note(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        body: String,
        visibility: NoteVisibility,
    ) -> Result<u64, IncidentError> {
        if visibility == NoteVisibility::CustomerVisible {
            return Err(IncidentError::ValidationError(
                "customer-visible notes are refused in Phase 5".to_string(),
            ));
        }
        validate_note_body(&body)?;
        let now = self.decision_time()?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        if incident.notes_at_capacity() {
            return Err(IncidentError::CapacityExceeded("notes per incident"));
        }
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        let index = incident.notes.len() as u32;
        incident.notes.push(Note {
            index,
            body,
            visibility,
            created_by: auth.actor().clone(),
        });
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;

        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::NoteAdded { note_index: index },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentNoteCreate,
            incident_id,
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn add_tag(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        key: String,
        value: String,
    ) -> Result<u64, IncidentError> {
        if key.len() > TAG_KEY_MAX_LEN || value.len() > TAG_VALUE_MAX_LEN {
            return Err(IncidentError::ValidationError(
                "tag key or value exceeds its bound".to_string(),
            ));
        }
        let now = self.decision_time()?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        if !incident.tags.contains_key(&key) && incident.tags_at_capacity() {
            return Err(IncidentError::CapacityExceeded("tags per incident"));
        }
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        incident.tags.insert(key.clone(), value.clone());
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;
        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::TagAdded { key, value },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentUpdate,
            incident_id,
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }

    fn remove_tag(
        &mut self,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        key: String,
    ) -> Result<u64, IncidentError> {
        let now = self.decision_time()?;
        let incident = self
            .store
            .get_mut(&incident_id)
            .ok_or(IncidentError::NotFound)?;
        let new_version =
            incident
                .version
                .checked_add(1)
                .ok_or(IncidentError::InternalInvariantViolation(
                    "incident version overflowed u64",
                ))?;
        incident.tags.remove(&key);
        incident.version = new_version;
        incident.last_updated_at = now;
        self.maybe_fail()?;
        let ts = self.next_timeline_sequence();
        self.store.append_timeline(TimelineEntry::new(
            ts,
            incident_id,
            auth.actor().clone(),
            TimelinePayload::TagRemoved { key },
        ));
        let asq = self.next_audit_sequence();
        self.store.append_audit(AuditEntry::allowed(
            asq,
            auth.tenant().clone(),
            auth.actor().clone(),
            Permission::IncidentUpdate,
            incident_id,
        ));
        Ok(self
            .store
            .get(&incident_id)
            .expect("incident exists")
            .version)
    }
}

/// Never referenced outside this module — retained purely so
/// `AFFECTED_TARGETS_MAX` participates in at least one compiled path
/// until a future milestone tracks affected-target counts on the
/// aggregate itself.
#[allow(dead_code)]
const _: usize = AFFECTED_TARGETS_MAX;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{FixedBundleResolver, PermissionResolver};
    use crate::clock::TestClock;
    use crate::id::TestIncidentGenerator;
    use crate::idempotency::IdempotencyKey;
    use crate::number::InMemoryNumberAllocator;
    use std::collections::BTreeMap as StdBTreeMap;
    use std::net::{IpAddr, Ipv4Addr};
    use wetechinetmon_detector::{
        ActionTaken, AddressFamily, DataCompleteness, DetectionState, EventTarget, ExecutionMode,
        MatchedReason, MetricRates, SamplingStatus, ScopeId, ScopeType, Severity, TrafficDirection,
        TransitionReason,
    };

    fn fresh_uow() -> IncidentUnitOfWork {
        IncidentUnitOfWork::new(
            Box::new(TestIncidentGenerator::starting_at(1)),
            Box::new(InMemoryNumberAllocator::new()),
            Box::new(TestClock::new()),
        )
    }

    /// ADR 0034: an adapter supplies a store holding the rows it loaded,
    /// and must get that same store back to read what the call changed.
    #[test]
    fn with_store_reads_the_supplied_store_and_into_store_returns_it() {
        let mut store = InMemoryIncidentStore::new();
        let incident = crate::test_fixtures::valid_incident(IncidentState::Open);
        let id = incident.incident_id;
        store.insert(incident);

        let uow = fresh_uow().with_store(Box::new(store));
        assert!(
            uow.get(&id).is_some(),
            "the unit of work must read the supplied store"
        );

        let recovered: Box<dyn std::any::Any> = uow.into_store();
        let recovered = recovered
            .downcast::<InMemoryIncidentStore>()
            .expect("into_store must return the store with_store was given");
        assert_eq!(recovered.len(), 1);
    }

    fn event(detection_id: &str, sequence: u64, addr: IpAddr, observed: u64) -> DetectionEvent {
        DetectionEvent {
            schema_version: wetechinetmon_detector::EVENT_SCHEMA_VERSION,
            event_id: format!("{detection_id}-{sequence}"),
            detection_id: detection_id.to_string(),
            sequence,
            kind: if sequence == 0 {
                EventKind::Started
            } else {
                EventKind::Updated
            },
            dedup_key: format!("{detection_id}:updated:{sequence}"),
            policy_id: "p-host-bps".to_string(),
            policy_name: "host bps".to_string(),
            policy_version: 1,
            severity: Severity::Major,
            execution_mode: ExecutionMode::AlertOnly,
            action: ActionTaken::Alerted,
            labels: StdBTreeMap::new(),
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
            detected_at_ms: 1_700_000_000_000 + sequence,
            observed_at_ms: 1_700_000_000_000 + sequence,
            duration_ms: sequence,
            window_ms: 1000,
            matched: vec![MatchedReason {
                metric: MetricKind::Bps,
                observed,
                threshold: 1_000_000,
                excess: observed.saturating_sub(1_000_000),
                ratio_percent: observed * 100 / 1_000_000,
            }],
            peak: Vec::new(),
            skipped: Vec::new(),
            rates: MetricRates::default(),
            completeness: DataCompleteness::default(),
            sampling: SamplingStatus::default(),
            flows_observed: 1,
            exporters_observed: 1,
            snapshots_in_detection: sequence + 1,
            executed: false,
            summary: "test".to_string(),
        }
    }

    fn senior_operator(tenant: &str) -> AuthorizationContext {
        let resolver = FixedBundleResolver;
        AuthorizationContext::new(
            TenantId::new(tenant),
            Actor::Operator {
                id: "u1".to_string(),
            },
            resolver.permissions_for("senior_operator"),
        )
    }

    /// Documents 5A's actual in-memory commit boundary — not "atomic".
    /// There is no real transaction in this crate: `create_incident_internal`
    /// writes the incident into the store and *then* checks
    /// `fail_after_incident_write`. An injected failure at that checkpoint
    /// therefore leaves the incident present but its timeline/audit/outbox
    /// entries absent — genuine partial state. This is the honest boundary
    /// Milestone 5B's real PostgreSQL transaction must close (see the
    /// module doc above and the review's B/H6 findings). The name states
    /// what is actually proven: partial persistence survives, not that it
    /// does not. Lives here, rather than in the `tests/` integration
    /// crate, because `inject_failure_after_incident_write` is
    /// `pub(crate)` and `cfg(test)`-gated (M8): a separate compilation
    /// unit cannot see it.
    #[test]
    fn failure_injection_documents_the_in_memory_commit_boundary() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
        let started = event("det-fail", 0, addr, 5_000_000);
        let incident_id_before = uow
            .ingest_detection_event(&correlator, &started)
            .unwrap()
            .incident_id;
        assert!(incident_id_before.is_some());
        let count_before = uow.incident_count();
        let timeline_before = uow.timeline().len();
        let audit_before = uow.audit().len();
        let outbox_before = uow.outbox().len();

        uow.inject_failure_after_incident_write(true);
        let addr2: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
        let started2 = event("det-fail-2", 0, addr2, 5_000_000);
        let result = uow.ingest_detection_event(&correlator, &started2);
        assert!(
            result.is_err(),
            "the injected failure must propagate as an error"
        );
        assert_eq!(
            uow.incident_count(),
            count_before + 1,
            "the in-memory incident map is written before the injected checkpoint"
        );
        assert_eq!(
            uow.timeline().len(),
            timeline_before,
            "no timeline entry for the failed incident should have been committed"
        );
        assert_eq!(
            uow.audit().len(),
            audit_before,
            "no audit entry for the failed incident should have been committed"
        );
        assert_eq!(
            uow.outbox().len(),
            outbox_before,
            "no outbox entry for the failed incident should have been committed"
        );
        uow.inject_failure_after_incident_write(false);
    }

    /// H4: an injected/transient failure must never become a permanent
    /// idempotency record. See the analogous discussion in the module doc
    /// and in `failure_injection_documents_the_in_memory_commit_boundary`
    /// above about what "partial" means in this in-memory model.
    #[test]
    fn injected_failure_does_not_poison_an_idempotency_key() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let operator = senior_operator("acme");
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-h4c", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();

        let key = IdempotencyKey::new("d".repeat(20)).unwrap();
        uow.inject_failure_after_incident_write(true);
        let failed = uow.handle_command(
            &operator,
            incident_id,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            Some(key.clone()),
        );
        assert_eq!(
            failed,
            Err(IncidentError::InternalInvariantViolation(
                "injected test failure"
            ))
        );
        uow.inject_failure_after_incident_write(false);

        // The partial mutation already landed (state is genuinely
        // Acknowledged/version 2 now — the same documented boundary as
        // above), so retrying with the stale expected_version must see
        // *live* state, not a cached InternalInvariantViolation.
        let retried_with_stale_version = uow.handle_command(
            &operator,
            incident_id,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            Some(key.clone()),
        );
        assert_eq!(
            retried_with_stale_version,
            Err(IncidentError::VersionConflict {
                expected: 1,
                current: 2,
                current_state: IncidentState::Acknowledged,
            }),
            "the key must not replay the stale injected failure"
        );

        let retried_with_current_version = uow.handle_command(
            &operator,
            incident_id,
            Command::BeginInvestigation {
                expected_version: 2,
            },
            Some(key),
        );
        assert_eq!(retried_with_current_version, Ok(3));
    }

    /// M1 (active-index consistency): reopening an incident must restore
    /// its `open_index` entry, not merely change its state — otherwise a
    /// third event on the same key would create a second incident instead
    /// of linking to the reopened one.
    #[test]
    fn reopen_restores_the_active_index_so_a_later_event_links_rather_than_creates() {
        let (mut uow, clock) = {
            let clock = std::sync::Arc::new(TestClock::new());
            struct Shared(std::sync::Arc<TestClock>);
            impl Clock for Shared {
                fn monotonic(&self) -> std::time::Instant {
                    self.0.monotonic()
                }
                fn wall(&self) -> std::time::SystemTime {
                    self.0.wall()
                }
            }
            let uow = IncidentUnitOfWork::new(
                Box::new(TestIncidentGenerator::starting_at(1)),
                Box::new(InMemoryNumberAllocator::new()),
                Box::new(Shared(clock.clone())),
            );
            (uow, clock)
        };
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let operator = senior_operator("acme");
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40));

        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-m1", 0, addr, 5_000_000))
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
        let reopen_result = uow
            .ingest_detection_event(&correlator, &event("det-m1-recur", 0, addr, 6_000_000))
            .unwrap();
        assert_eq!(reopen_result.outcome_kind, IngestOutcomeKind::Reopened);

        // A third event on the same key must now link to the reopened
        // incident (found via the restored `open_index` entry), not spawn
        // a second incident.
        let third = uow
            .ingest_detection_event(&correlator, &event("det-m1-recur", 1, addr, 6_500_000))
            .unwrap();
        assert_eq!(third.outcome_kind, IngestOutcomeKind::Updated);
        assert_eq!(third.incident_id, Some(incident_id));
        assert_eq!(uow.incident_count(), 1);
    }

    /// ADR 0031: a recurrence whose decision time precedes the candidate's
    /// `resolved_at` is refused with `ClockSkew`. It neither reopens on an
    /// untrustworthy comparison nor opens a duplicate incident.
    #[test]
    fn a_recurrence_before_the_reference_time_is_refused_not_duplicated() {
        let clock = std::sync::Arc::new(TestClock::new());
        struct Shared(std::sync::Arc<TestClock>);
        impl Clock for Shared {
            fn monotonic(&self) -> std::time::Instant {
                self.0.monotonic()
            }
            fn wall(&self) -> std::time::SystemTime {
                self.0.wall()
            }
        }
        let mut uow = IncidentUnitOfWork::new(
            Box::new(TestIncidentGenerator::starting_at(1)),
            Box::new(InMemoryNumberAllocator::new()),
            Box::new(Shared(clock.clone())),
        );
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 41));

        clock.advance(Duration::from_secs(3_600));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-skew", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        uow.handle_command(
            &senior_operator("acme"),
            incident_id,
            Command::ResolveIncident {
                expected_version: 1,
                resolution_note: None,
            },
            None,
        )
        .unwrap();

        // A second process whose clock has not reached that resolution,
        // reading the same store.
        let mut behind = IncidentUnitOfWork::new(
            Box::new(TestIncidentGenerator::starting_at(100)),
            Box::new(InMemoryNumberAllocator::new()),
            Box::new(TestClock::new()),
        )
        .with_store(uow.into_store());
        let refused = behind
            .ingest_detection_event(&correlator, &event("det-skew-recur", 0, addr, 6_000_000));
        assert!(
            matches!(refused, Err(IncidentError::ClockSkew { .. })),
            "got {refused:?}"
        );
        assert_eq!(behind.incident_count(), 1, "no duplicate incident");
        assert_eq!(
            behind.get(&incident_id).unwrap().state,
            IncidentState::Resolved
        );
    }

    /// Version-overflow safety (required correction): a command that
    /// would push `version` past `u64::MAX` is refused, not silently
    /// wrapped to zero, and the incident is left unmutated.
    #[test]
    fn version_overflow_is_refused_and_leaves_the_incident_unmutated() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let operator = senior_operator("acme");
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 41));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-ovf", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        uow.store.get_mut(&incident_id).unwrap().version = u64::MAX;

        let result = uow.handle_command(
            &operator,
            incident_id,
            Command::AcknowledgeIncident {
                expected_version: u64::MAX,
            },
            None,
        );
        assert_eq!(
            result,
            Err(IncidentError::InternalInvariantViolation(
                "incident version overflowed u64"
            ))
        );
        let incident = uow.get(&incident_id).unwrap();
        assert_eq!(incident.version, u64::MAX, "must not wrap to zero");
        assert_eq!(
            incident.state,
            IncidentState::Open,
            "a refused overflow must not have applied the state change either"
        );
    }

    /// `reopen_count` gets the same treatment as `version`.
    #[test]
    fn reopen_count_overflow_is_refused() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let operator = senior_operator("acme");
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-ovf2", 0, addr, 5_000_000))
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
        {
            let incident = uow.store.get_mut(&incident_id).unwrap();
            incident.reopen_count = u32::MAX;
        }

        let result = uow.handle_command(
            &operator,
            incident_id,
            Command::ReopenIncident {
                expected_version: 2,
                reason: "test".to_string(),
            },
            None,
        );
        assert_eq!(
            result,
            Err(IncidentError::InternalInvariantViolation(
                "reopen_count overflowed u32"
            ))
        );
        assert_eq!(uow.get(&incident_id).unwrap().reopen_count, u32::MAX);
    }

    /// FU-38's acceptance gate: `close_internal` must refuse every
    /// illegal source state **on its own**, called directly, bypassing
    /// every caller-side check — the whole point being that a future
    /// second caller that forgets its own check must still be safe.
    #[test]
    fn close_internal_refuses_every_illegal_source_state() {
        let auth = AuthorizationContext::correlator(TenantId::new("acme"));
        for state in [
            IncidentState::Open,
            IncidentState::Acknowledged,
            IncidentState::Investigating,
            IncidentState::Monitoring,
            IncidentState::Recovering,
            IncidentState::Closed,
        ] {
            for cause in [
                TransitionCause::Automatic(AutomaticCause::AutomaticClosure),
                TransitionCause::Operator(crate::timeline::OperatorCommandKind::Close),
            ] {
                let mut uow = fresh_uow();
                let incident = crate::test_fixtures::valid_incident(state);
                let incident_id = incident.incident_id;
                uow.store.insert(incident);

                let result = uow.close_internal(
                    &auth,
                    incident_id,
                    crate::closure::ClosureReason::Resolved,
                    cause,
                );
                assert_eq!(
                    result,
                    Err(IncidentError::InvalidTransition {
                        from: state,
                        to: IncidentState::Closed,
                    }),
                    "state {state:?} with cause {cause:?} must be refused"
                );
                assert_eq!(
                    uow.store.get(&incident_id).expect("incident exists").state,
                    state,
                    "a refused close must not mutate state"
                );
                assert!(
                    uow.store.timeline().is_empty()
                        && uow.store.audit().is_empty()
                        && uow.store.outbox().is_empty(),
                    "a refused close must not append anything"
                );
            }
        }
    }

    /// The complement: `Resolved` is legal for both causes, and the
    /// mutation actually applies — otherwise the guard above could be
    /// satisfied by a guard that rejects everything.
    #[test]
    fn close_internal_accepts_the_one_legal_source_state_for_both_causes() {
        let auth = AuthorizationContext::correlator(TenantId::new("acme"));
        for cause in [
            TransitionCause::Automatic(AutomaticCause::AutomaticClosure),
            TransitionCause::Operator(crate::timeline::OperatorCommandKind::Close),
        ] {
            let mut uow = fresh_uow();
            let incident = crate::test_fixtures::valid_incident(IncidentState::Resolved);
            let incident_id = incident.incident_id;
            uow.store.insert(incident);

            uow.close_internal(
                &auth,
                incident_id,
                crate::closure::ClosureReason::Resolved,
                cause,
            )
            .unwrap();
            assert_eq!(
                uow.store.get(&incident_id).expect("incident exists").state,
                IncidentState::Closed
            );
        }
    }

    /// FU-38's acceptance gate for the reopen side: `reopen_incident_internal`
    /// must refuse every state outside `{Resolved, Closed}` on its own.
    /// `Recovering` is included and matters specifically: it is a legal
    /// automatic destination-source for `Open` in the shared state table
    /// (recovery-abort restoration), but this function's mutations
    /// (`reopen_count`, `reopened_at`, evidence) are wrong for that case —
    /// see the guard's own comment.
    #[test]
    fn reopen_incident_internal_refuses_every_illegal_source_state() {
        let auth = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90));
        for state in [
            IncidentState::Open,
            IncidentState::Acknowledged,
            IncidentState::Investigating,
            IncidentState::Monitoring,
            IncidentState::Recovering,
        ] {
            let mut uow = fresh_uow();
            let incident = crate::test_fixtures::valid_incident(state);
            let incident_id = incident.incident_id;
            uow.store.insert(incident);

            let result = uow.reopen_incident_internal(
                &auth,
                incident_id,
                &event("det-fu38", 0, addr, 5_000_000),
                AutomaticCause::ReopenedByRecurrence,
            );
            assert!(
                matches!(
                    result,
                    Err(IncidentError::InvalidTransition { from, to: IncidentState::Open }) if from == state
                ),
                "state {state:?} must be refused, got {result:?}"
            );
            assert_eq!(
                uow.store.get(&incident_id).expect("incident exists").state,
                state,
                "a refused reopen must not mutate state"
            );
            assert!(
                uow.store.timeline().is_empty()
                    && uow.store.audit().is_empty()
                    && uow.store.outbox().is_empty(),
                "a refused reopen must not append anything"
            );
        }
    }

    /// The complement for reopen: both legal sources actually apply the
    /// mutation.
    #[test]
    fn reopen_incident_internal_accepts_both_legal_source_states() {
        let auth = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 91));
        for state in [IncidentState::Resolved, IncidentState::Closed] {
            let mut uow = fresh_uow();
            let incident = crate::test_fixtures::valid_incident(state);
            let incident_id = incident.incident_id;
            uow.store.insert(incident);

            uow.reopen_incident_internal(
                &auth,
                incident_id,
                &event("det-fu38b", 0, addr, 5_000_000),
                AutomaticCause::ReopenedByRecurrence,
            )
            .unwrap();
            assert_eq!(
                uow.store.get(&incident_id).expect("incident exists").state,
                IncidentState::Open
            );
        }
    }

    /// R1: a genuine, non-tautological regression test for
    /// `last_detected_at` monotonicity. `TestClock` deliberately has no
    /// rewind (mirroring the production `SystemClock` guarantee), so a
    /// "late" delivery — the incident's stored `last_detected_at` reading
    /// ahead of the next call's observed clock reading — cannot occur
    /// through ordinary sequential calls with a forward-only clock; see
    /// the FU-30 module doc in `tests/properties.rs`. Reaching that branch
    /// for a test therefore requires manufacturing the stored state
    /// directly, the same established idiom `version_overflow_is_refused`
    /// and `reopen_count_overflow_is_refused` above already use via
    /// `uow.store.get_mut(...)`. This asserts the actual stored field,
    /// not a saturating comparison that can never fail.
    #[test]
    fn last_detected_at_does_not_regress_on_a_late_event() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 70));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-late", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();

        // Manufacture a stored `last_detected_at` strictly ahead of the
        // clock the unit-of-work will next read from — the only way a
        // forward-only clock can produce `observed < stored`.
        let future = uow
            .get(&incident_id)
            .unwrap()
            .last_detected_at
            .checked_plus(Duration::from_secs(3600))
            .unwrap();
        uow.store.get_mut(&incident_id).unwrap().last_detected_at = future;

        let result = uow
            .ingest_detection_event(&correlator, &event("det-late", 1, addr, 5_500_000))
            .unwrap();
        assert_eq!(result.outcome_kind, IngestOutcomeKind::LinkedLate);

        let stored = uow.get(&incident_id).unwrap().last_detected_at;
        assert_eq!(
            stored, future,
            "a late event must never move last_detected_at backward from its stored value"
        );
        assert!(matches!(
            uow.timeline().last().unwrap().payload,
            TimelinePayload::LateEventLinked { .. }
        ));
    }

    /// The positive counterpart: a strictly newer event (the clock has
    /// genuinely advanced) must advance `last_detected_at`, driven through
    /// a real `SharedClock` advance rather than field manipulation.
    #[test]
    fn last_detected_at_advances_on_a_strictly_newer_event() {
        let clock = std::sync::Arc::new(TestClock::new());
        struct Shared(std::sync::Arc<TestClock>);
        impl Clock for Shared {
            fn monotonic(&self) -> std::time::Instant {
                self.0.monotonic()
            }
            fn wall(&self) -> std::time::SystemTime {
                self.0.wall()
            }
        }
        let mut uow = IncidentUnitOfWork::new(
            Box::new(TestIncidentGenerator::starting_at(1)),
            Box::new(InMemoryNumberAllocator::new()),
            Box::new(Shared(clock.clone())),
        );
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 71));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-newer", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        let before = uow.get(&incident_id).unwrap().last_detected_at;

        clock.advance(Duration::from_secs(5));
        uow.ingest_detection_event(&correlator, &event("det-newer", 1, addr, 5_500_000))
            .unwrap();
        let after = uow.get(&incident_id).unwrap().last_detected_at;

        assert!(
            after.checked_elapsed_since(&before).unwrap() == Duration::from_secs(5),
            "a strictly newer observation must advance last_detected_at by exactly the clock advance"
        );
        assert!(matches!(
            uow.timeline().last().unwrap().payload,
            TimelinePayload::EventLinked { .. }
        ));
    }

    /// The boundary case: an event observed at exactly the same clock
    /// reading as the stored `last_detected_at` (no clock advance between
    /// calls) is not "late" — `is_late` uses a strict `<` — so it must be
    /// treated as a normal update, not regress, and not be misclassified.
    #[test]
    fn last_detected_at_is_stable_on_an_equal_timestamp_event() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 72));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-equal", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        let before = uow.get(&incident_id).unwrap().last_detected_at;

        // No clock advance: the next observed reading equals `before`.
        uow.ingest_detection_event(&correlator, &event("det-equal", 1, addr, 5_500_000))
            .unwrap();
        let after = uow.get(&incident_id).unwrap().last_detected_at;

        assert_eq!(
            after, before,
            "an equal-timestamp event must not regress last_detected_at"
        );
        assert!(
            matches!(
                uow.timeline().last().unwrap().payload,
                TimelinePayload::EventLinked { .. }
            ),
            "an equal-timestamp event is an on-time update, not late"
        );
    }

    /// FU-37: `AddTag` and `RemoveTag` must each append a timeline entry,
    /// matching every other mutation.
    #[test]
    fn add_and_remove_tag_each_append_a_timeline_entry() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let resolver = crate::authorization::FixedBundleResolver;
        let platform_admin = AuthorizationContext::new(
            TenantId::new("acme"),
            Actor::Operator {
                id: "u1".to_string(),
            },
            resolver.permissions_for("platform_admin"),
        );
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 78));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-tag", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        let timeline_before = uow.timeline().len();

        uow.handle_command(
            &platform_admin,
            incident_id,
            Command::AddTag {
                key: "team".to_string(),
                value: "network".to_string(),
            },
            None,
        )
        .unwrap();
        assert_eq!(uow.timeline().len(), timeline_before + 1);
        assert!(matches!(
            uow.timeline().last().unwrap().payload,
            TimelinePayload::TagAdded { .. }
        ));

        uow.handle_command(
            &platform_admin,
            incident_id,
            Command::RemoveTag {
                key: "team".to_string(),
            },
            None,
        )
        .unwrap();
        assert_eq!(uow.timeline().len(), timeline_before + 2);
        assert!(matches!(
            uow.timeline().last().unwrap().payload,
            TimelinePayload::TagRemoved { .. }
        ));
    }

    /// FU-34: a second event matching under a different policy than the
    /// one that opened the incident must be recorded in `policy_refs`,
    /// not silently omitted.
    #[test]
    fn a_later_event_under_a_different_policy_is_recorded_in_policy_refs() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        let started = event("det-policy", 0, addr, 5_000_000);
        assert_eq!(started.policy_id, "p-host-bps");
        let incident_id = uow
            .ingest_detection_event(&correlator, &started)
            .unwrap()
            .incident_id
            .unwrap();
        assert_eq!(uow.get(&incident_id).unwrap().policy_refs.len(), 1);

        let mut second = event("det-policy", 1, addr, 5_500_000);
        second.policy_id = "p-other-policy".to_string();
        second.policy_version = 2;
        uow.ingest_detection_event(&correlator, &second).unwrap();

        let policy_refs = &uow.get(&incident_id).unwrap().policy_refs;
        assert_eq!(
            policy_refs.len(),
            2,
            "a second distinct policy must be recorded, not silently omitted"
        );
        let other = policy_refs
            .iter()
            .find(|p| p.policy_id == "p-other-policy")
            .expect("the second policy must appear in policy_refs");
        assert_eq!(other.policy_version, 2);
        assert_eq!(other.first_seen_sequence, 1);
        assert_eq!(other.last_seen_sequence, 1);
    }

    /// An event arriving after a newer one, under the same policy, widens
    /// the reference's seen range instead of moving `last_seen_sequence`
    /// backward. A backward move breaks `first_seen <= last_seen`, which
    /// PostgreSQL's `incident_policy_references` CHECK refuses. It must not
    /// overwrite the newer event's policy version either.
    #[test]
    fn an_out_of_order_event_never_moves_a_policy_reference_backward() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 78));
        let mut newer = event("det-order", 5, addr, 5_000_000);
        newer.policy_version = 4;
        let incident_id = uow
            .ingest_detection_event(&correlator, &newer)
            .unwrap()
            .incident_id
            .unwrap();

        let mut older = event("det-order", 2, addr, 5_500_000);
        older.policy_version = 3;
        uow.ingest_detection_event(&correlator, &older).unwrap();

        let reference = &uow.get(&incident_id).unwrap().policy_refs[0];
        assert_eq!(reference.first_seen_sequence, 2);
        assert_eq!(reference.last_seen_sequence, 5);
        assert_eq!(reference.policy_version, 4);
    }

    /// FU-34: once `policy_refs` holds `POLICY_REFS_MAX` distinct policies,
    /// an event under an unseen policy is counted in `policy_refs_omitted`
    /// rather than silently dropped, and a recorded policy still updates.
    #[test]
    fn a_policy_past_the_cap_is_counted_as_omitted() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-policy", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        let cap = POLICY_REFS_MAX as u64;
        for sequence in 1..cap {
            let mut next = event("det-policy", sequence, addr, 5_000_000);
            next.policy_id = format!("p-extra-{sequence}");
            uow.ingest_detection_event(&correlator, &next).unwrap();
        }
        let incident = uow.get(&incident_id).unwrap();
        assert_eq!(incident.policy_refs.len(), POLICY_REFS_MAX);
        assert_eq!(incident.policy_refs_omitted, 0);

        let mut overflow = event("det-policy", cap, addr, 5_000_000);
        overflow.policy_id = "p-past-the-cap".to_string();
        uow.ingest_detection_event(&correlator, &overflow).unwrap();
        let mut recorded = event("det-policy", cap + 1, addr, 5_000_000);
        recorded.policy_id = "p-extra-1".to_string();
        uow.ingest_detection_event(&correlator, &recorded).unwrap();

        let incident = uow.get(&incident_id).unwrap();
        assert_eq!(incident.policy_refs.len(), POLICY_REFS_MAX);
        assert_eq!(
            incident.policy_refs_omitted, 1,
            "the policy past the cap is counted, not silently dropped"
        );
        assert!(incident
            .policy_refs
            .iter()
            .all(|p| p.policy_id != "p-past-the-cap"));
        let updated = incident
            .policy_refs
            .iter()
            .find(|p| p.policy_id == "p-extra-1")
            .unwrap();
        assert_eq!(updated.last_seen_sequence, cap + 1);
    }

    /// FU-37: a manual operator reopen must also clear the stale
    /// `resolved_at` from the prior cycle, not only the ingestion-driven
    /// automatic recurrence path (covered separately in
    /// `tests/domain_end_to_end.rs`).
    #[test]
    fn manual_reopen_clears_the_stale_resolved_at() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let operator = senior_operator("acme");
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 76));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-manual-reopen", 0, addr, 5_000_000))
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
        assert!(uow.get(&incident_id).unwrap().resolved_at.is_some());

        uow.handle_command(
            &operator,
            incident_id,
            Command::ReopenIncident {
                expected_version: 2,
                reason: "test".to_string(),
            },
            None,
        )
        .unwrap();
        assert_eq!(uow.get(&incident_id).unwrap().resolved_at, None);
    }

    /// FU-36: an operator-supplied reopen reason must be preserved on the
    /// timeline, not discarded.
    #[test]
    fn operator_reopen_reason_is_preserved_on_the_timeline() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let operator = senior_operator("acme");
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 75));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-reopen-reason", 0, addr, 5_000_000))
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
            Command::ReopenIncident {
                expected_version: 2,
                reason: "customer confirmed traffic resumed".to_string(),
            },
            None,
        )
        .unwrap();

        let reopened_entry = uow
            .timeline()
            .iter()
            .rev()
            .find(|e| matches!(e.payload, TimelinePayload::Reopened { .. }))
            .expect("a Reopened timeline entry must exist");
        match &reopened_entry.payload {
            TimelinePayload::Reopened { reason, .. } => {
                assert_eq!(
                    reason.as_deref(),
                    Some("customer confirmed traffic resumed")
                );
            }
            _ => unreachable!(),
        }
    }

    /// FU-32: an oversized suppression reason must refuse the whole
    /// command before any mutation, matching the treatment `add_note` and
    /// the title/description validators already receive.
    #[test]
    fn oversized_suppression_reason_is_refused_and_leaves_the_incident_unmutated() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let resolver = crate::authorization::FixedBundleResolver;
        let noc_lead = AuthorizationContext::new(
            TenantId::new("acme"),
            Actor::Operator {
                id: "u1".to_string(),
            },
            resolver.permissions_for("noc_lead"),
        );
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 74));
        let incident_id = uow
            .ingest_detection_event(&correlator, &event("det-suppress-len", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        let version_before = uow.get(&incident_id).unwrap().version;

        let result = uow.handle_command(
            &noc_lead,
            incident_id,
            Command::SuppressIncident {
                expected_version: version_before,
                reason: "a".repeat(crate::suppression::SUPPRESSION_REASON_MAX_LEN + 1),
                duration: Duration::from_secs(3600),
            },
            None,
        );
        assert!(
            matches!(result, Err(IncidentError::ValidationError(_))),
            "expected ValidationError, got {result:?}"
        );
        assert_eq!(uow.get(&incident_id).unwrap().version, version_before);
        assert!(uow.get(&incident_id).unwrap().suppression.is_none());
    }

    /// L2: `with_number_allocation_year` is honored, and is deterministic
    /// (not derived from any wall-clock reading) — a config-provided
    /// value, not a hardcoded literal.
    #[test]
    fn number_allocation_year_is_configurable_and_not_wall_clock_derived() {
        let mut uow_2030 = fresh_uow().with_number_allocation_year(2030);
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 73));
        let incident_id = uow_2030
            .ingest_detection_event(&correlator, &event("det-year", 0, addr, 5_000_000))
            .unwrap()
            .incident_id
            .unwrap();
        let number = uow_2030.get(&incident_id).unwrap().incident_number.as_str();
        assert!(
            number.contains("2030"),
            "configured allocation year must appear in the display number: {number}"
        );
        assert!(
            !number.contains("2026"),
            "the placeholder default must not leak through once overridden: {number}"
        );
    }

    /// L4: a permission denial on `handle_command`, before the target
    /// incident has been looked up or tenant-checked, must record
    /// `AttemptedResource::Unresolved` (what the caller supplied), never
    /// `Incident` (which the crate's own doc reserves for a resource the
    /// audit path has actually resolved). Targets a nonexistent incident
    /// id on purpose — precisely because this check runs before any
    /// lookup, existence must not matter to the outcome.
    #[test]
    fn a_denied_command_records_unresolved_not_incident() {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let bogus_id = crate::id::IncidentId::from_bytes([9; 16]);

        let result = uow.handle_command(
            &correlator,
            bogus_id,
            Command::AcknowledgeIncident {
                expected_version: 1,
            },
            None,
        );
        assert_eq!(result, Err(IncidentError::Unauthorized));

        let entry = uow.audit().last().unwrap();
        assert!(entry.is_denied());
        match &entry.resource {
            AttemptedResource::Unresolved(id) => assert_eq!(id, &bogus_id.to_string()),
            AttemptedResource::Incident(_) => {
                panic!("a pre-lookup denial must use Unresolved, not Incident")
            }
        }
    }

    fn manual_host(addr: IpAddr) -> ManualIncident {
        ManualIncident {
            title: "Upstream reports spoofed sources".to_string(),
            description: Some("Seen by the transit provider, not by us".to_string()),
            severity: Severity::Major,
            priority: None,
            target_type: ScopeType::Host,
            target_identity: ScopeId::Host { addr },
            direction: TrafficDirection::Incoming,
            address_family: AddressFamily::Ipv4,
        }
    }

    /// ADR 0039: a manual incident is a full incident, and a later
    /// detection for the same target attaches to it.
    #[test]
    fn a_manual_incident_opens_and_later_detections_attach_to_it() {
        let mut uow = fresh_uow();
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let auth = senior_operator("acme");
        let id = uow
            .create_manual_incident(&auth, manual_host(addr), None)
            .unwrap();
        let incident = uow.get(&id).unwrap();
        assert_eq!(incident.state, IncidentState::Open);
        assert_eq!(incident.version, 1);
        assert_eq!(incident.priority, Priority::P2);
        assert_eq!(incident.severity_source, SeveritySource::Operator);
        assert_eq!(
            incident.created_by,
            Actor::Operator {
                id: "u1".to_string()
            }
        );
        assert!(uow
            .audit()
            .iter()
            .any(|entry| entry.permission == Permission::IncidentCreate));
        assert!(uow
            .outbox()
            .iter()
            .any(|message| message.event == OutboxEvent::IncidentOpened));

        let linked = uow
            .ingest_detection_event(
                &AuthorizationContext::correlator(TenantId::new("acme")),
                &event("d-manual", 0, addr, 2_000_000),
            )
            .unwrap();
        assert_eq!(
            linked.incident_id,
            Some(id),
            "attached, not a second incident"
        );
    }

    #[test]
    fn a_manual_incident_is_refused_where_one_is_already_active() {
        let mut uow = fresh_uow();
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6));
        let auth = senior_operator("acme");
        let first = uow
            .create_manual_incident(&auth, manual_host(addr), None)
            .unwrap();
        assert_eq!(
            uow.create_manual_incident(&auth, manual_host(addr), None),
            Err(IncidentError::DuplicateActiveIncident(first))
        );
    }

    #[test]
    fn an_operator_without_incident_create_is_refused_and_audited() {
        let mut uow = fresh_uow();
        let operator = AuthorizationContext::new(
            TenantId::new("acme"),
            Actor::Operator {
                id: "u2".to_string(),
            },
            FixedBundleResolver.permissions_for("operator"),
        );
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(
            uow.create_manual_incident(&operator, manual_host(addr), None),
            Err(IncidentError::Unauthorized)
        );
        assert!(uow
            .audit()
            .iter()
            .any(|entry| entry.permission == Permission::IncidentCreate
                && entry.outcome == crate::audit::AuditOutcome::Denied));
    }

    #[test]
    fn a_keyed_manual_create_replays_and_refuses_a_different_body() {
        let mut uow = fresh_uow();
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let auth = senior_operator("acme");
        let key = IdempotencyKey::new("manual-create-key-0001").unwrap();
        let first = uow
            .create_manual_incident(&auth, manual_host(addr), Some(key.clone()))
            .unwrap();
        assert_eq!(
            uow.create_manual_incident(&auth, manual_host(addr), Some(key.clone())),
            Ok(first),
            "the same key and body replay the first outcome"
        );
        let mut other = manual_host(addr);
        other.title = "Something else".to_string();
        assert_eq!(
            uow.create_manual_incident(&auth, other, Some(key)),
            Err(IncidentError::IdempotencyConflict)
        );
    }
}
