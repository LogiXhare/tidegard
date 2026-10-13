//! The in-memory half of ADR 0034's load–run–flush.
//!
//! One `IncidentUnitOfWork` call runs against a [`StagingStore`] that holds
//! only the rows the adapter loaded for that call. The store records every
//! change the call makes, and every lookup of a key that was never loaded.
//! [`StagingStore::into_changes`] then returns exactly what the flush must
//! write. If the call looked up anything the load step did not fetch, it
//! refuses instead, so the adapter rolls back rather than committing a
//! decision made against a false "absent".
//!
//! No SQL lives here, so all of this is testable without a database.
//!
//! Two things are deliberately not flushed from here:
//!
//! - **Open-index claims and releases.** In PostgreSQL the open index is the
//!   active-incident partial unique indexes, derived from each incident's
//!   own state. Writing the incident is what claims or releases it.
//! - **Idempotency misses.** `IdempotencyStore` is a concrete type, so a
//!   lookup of an unloaded key cannot be intercepted. The load step must
//!   always query the command's own key, which makes "not found" a real
//!   answer rather than a miss.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use tidegard_incident::audit::AuditEntry;
use tidegard_incident::correlation::{CorrelationKey, TenantId};
use tidegard_incident::id::IncidentId;
use tidegard_incident::idempotency::{
    IdempotencyKey, IdempotencyStore, RequestFingerprint, StoredOutcome,
};
use tidegard_incident::incident::Incident;
use tidegard_incident::outbox::OutboxMessage;
use tidegard_incident::store::IncidentStore;
use tidegard_incident::timeline::TimelineEntry;

/// A lookup the domain made against a key the load step never fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnloadedLookup {
    Incident(IncidentId),
    OpenIndex(CorrelationKey),
    ReopenCandidate(CorrelationKey, TenantId),
    Dedup(TenantId, String),
}

/// An idempotency record the call added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIdempotencyRecord {
    pub tenant: TenantId,
    pub key: IdempotencyKey,
    pub fingerprint: RequestFingerprint,
    pub outcome: StoredOutcome,
}

/// A loaded incident the call reached mutably, with the version it was
/// loaded at, for the flush's `WHERE version = loaded_version` guard.
#[derive(Debug)]
pub struct UpdatedIncident {
    pub incident: Incident,
    pub loaded_version: u64,
}

/// Everything one call changed, for the flush to write.
#[derive(Debug)]
pub struct ChangeSet {
    /// Incidents the call created, ordered by id.
    pub inserted: Vec<Incident>,
    /// Loaded incidents the call reached mutably, ordered by id. Included
    /// even when nothing changed: the version guard makes rewriting an
    /// unchanged row harmless, while guessing "unchanged" would not be.
    pub updated: Vec<UpdatedIncident>,
    /// New `(tenant, dedup_key)` to incident links, in call order.
    pub dedup_records: Vec<((TenantId, String), IncidentId)>,
    pub timeline: Vec<TimelineEntry>,
    pub audit: Vec<AuditEntry>,
    pub outbox: Vec<OutboxMessage>,
    /// Ordered by tenant, then key.
    pub idempotency: Vec<NewIdempotencyRecord>,
}

#[derive(Debug)]
struct Staged {
    incident: Incident,
    /// `None` for an incident this call inserted.
    loaded_version: Option<u64>,
    touched: bool,
}

/// See the module doc.
#[derive(Debug, Default)]
pub struct StagingStore {
    incidents: HashMap<IncidentId, Staged>,
    absent_incidents: HashSet<IncidentId>,
    open_index: HashMap<CorrelationKey, Option<IncidentId>>,
    reopen_candidates: HashMap<(CorrelationKey, TenantId), Option<IncidentId>>,
    dedup: HashMap<(TenantId, String), Option<IncidentId>>,
    new_dedup: Vec<((TenantId, String), IncidentId)>,
    timeline: Vec<TimelineEntry>,
    audit: Vec<AuditEntry>,
    outbox: Vec<OutboxMessage>,
    idempotency: IdempotencyStore,
    preexisting_idempotency: HashSet<(TenantId, IdempotencyKey)>,
    unloaded: RefCell<Vec<UnloadedLookup>>,
}

impl StagingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// An incident row the load step found.
    pub fn load_incident(&mut self, incident: Incident) {
        let loaded_version = Some(incident.version);
        self.incidents.insert(
            incident.incident_id,
            Staged {
                incident,
                loaded_version,
                touched: false,
            },
        );
    }

    /// An incident id the load step looked for and did not find, so a
    /// lookup of it is a real "not found", not a miss.
    pub fn load_absent_incident(&mut self, id: IncidentId) {
        self.absent_incidents.insert(id);
    }

    /// The active incident for `key`, or `None` when the load found none.
    pub fn load_open_index(&mut self, key: CorrelationKey, active: Option<IncidentId>) {
        self.open_index.insert(key, active);
    }

    /// The reopen candidate for `key`, or `None`. A `Some` id must also be
    /// loaded with [`Self::load_incident`]. The load query must pick the
    /// same row `InMemoryIncidentStore::reopen_candidate` would.
    pub fn load_reopen_candidate(
        &mut self,
        key: CorrelationKey,
        tenant: TenantId,
        candidate: Option<IncidentId>,
    ) {
        self.reopen_candidates.insert((key, tenant), candidate);
    }

    /// The incident a `(tenant, dedup_key)` pair is already linked to, or
    /// `None` when the load found no link.
    pub fn load_dedup(&mut self, tenant: TenantId, dedup_key: String, linked: Option<IncidentId>) {
        self.dedup.insert((tenant, dedup_key), linked);
    }

    /// An idempotency record the load step found. Loaded records are never
    /// reported back as new.
    pub fn load_idempotency(
        &mut self,
        tenant: TenantId,
        key: IdempotencyKey,
        fingerprint: RequestFingerprint,
        outcome: StoredOutcome,
    ) {
        self.idempotency
            .record(tenant.clone(), key.clone(), fingerprint, outcome);
        self.preexisting_idempotency.insert((tenant, key));
    }

    /// Recovers a staging store from `IncidentUnitOfWork::into_store`.
    /// `None` if that unit of work was not built over one.
    pub fn recover(store: Box<dyn IncidentStore>) -> Option<StagingStore> {
        let any: Box<dyn std::any::Any> = store;
        any.downcast::<StagingStore>().ok().map(|boxed| *boxed)
    }

    /// What the call changed, or every unloaded lookup it made.
    pub fn into_changes(self) -> Result<ChangeSet, Vec<UnloadedLookup>> {
        let unloaded = self.unloaded.into_inner();
        if !unloaded.is_empty() {
            return Err(unloaded);
        }

        let mut idempotency: Vec<NewIdempotencyRecord> = self
            .idempotency
            .iter()
            .filter(|(tenant, key, _, _)| {
                !self
                    .preexisting_idempotency
                    .contains(&((*tenant).clone(), (*key).clone()))
            })
            .map(|(tenant, key, fingerprint, outcome)| NewIdempotencyRecord {
                tenant: tenant.clone(),
                key: key.clone(),
                fingerprint: fingerprint.clone(),
                outcome: outcome.clone(),
            })
            .collect();
        idempotency.sort_by(|a, b| (&a.tenant, a.key.as_str()).cmp(&(&b.tenant, b.key.as_str())));

        let mut staged: Vec<Staged> = self.incidents.into_values().collect();
        staged.sort_by_key(|s| s.incident.incident_id);
        let mut inserted = Vec::new();
        let mut updated = Vec::new();
        for s in staged {
            match s.loaded_version {
                None => inserted.push(s.incident),
                Some(loaded_version) if s.touched => updated.push(UpdatedIncident {
                    incident: s.incident,
                    loaded_version,
                }),
                Some(_) => {}
            }
        }

        Ok(ChangeSet {
            inserted,
            updated,
            dedup_records: self.new_dedup,
            timeline: self.timeline,
            audit: self.audit,
            outbox: self.outbox,
            idempotency,
        })
    }

    fn miss(&self, lookup: UnloadedLookup) {
        self.unloaded.borrow_mut().push(lookup);
    }
}

impl IncidentStore for StagingStore {
    fn get(&self, id: &IncidentId) -> Option<&Incident> {
        let found = self.incidents.get(id).map(|s| &s.incident);
        if found.is_none() && !self.absent_incidents.contains(id) {
            self.miss(UnloadedLookup::Incident(*id));
        }
        found
    }

    fn get_mut(&mut self, id: &IncidentId) -> Option<&mut Incident> {
        if !self.incidents.contains_key(id) && !self.absent_incidents.contains(id) {
            self.unloaded.get_mut().push(UnloadedLookup::Incident(*id));
        }
        self.incidents.get_mut(id).map(|s| {
            s.touched = true;
            &mut s.incident
        })
    }

    fn insert(&mut self, incident: Incident) {
        let id = incident.incident_id;
        match self.incidents.get_mut(&id) {
            Some(existing) => {
                existing.incident = incident;
                existing.touched = true;
            }
            None => {
                self.absent_incidents.remove(&id);
                self.incidents.insert(
                    id,
                    Staged {
                        incident,
                        loaded_version: None,
                        touched: true,
                    },
                );
            }
        }
    }

    fn len(&self) -> usize {
        self.incidents.len()
    }

    fn reopen_candidate(&self, key: &CorrelationKey, tenant: &TenantId) -> Option<&Incident> {
        match self.reopen_candidates.get(&(key.clone(), tenant.clone())) {
            Some(Some(id)) => self.get(id),
            Some(None) => None,
            None => {
                self.miss(UnloadedLookup::ReopenCandidate(key.clone(), tenant.clone()));
                None
            }
        }
    }

    fn open_index_get(&self, key: &CorrelationKey) -> Option<IncidentId> {
        match self.open_index.get(key) {
            Some(active) => *active,
            None => {
                self.miss(UnloadedLookup::OpenIndex(key.clone()));
                None
            }
        }
    }

    fn open_index_claim(&mut self, key: CorrelationKey, id: IncidentId) {
        self.open_index.insert(key, Some(id));
    }

    fn open_index_release(&mut self, key: &CorrelationKey) {
        self.open_index.insert(key.clone(), None);
    }

    fn dedup_get(&self, key: &(TenantId, String)) -> Option<IncidentId> {
        match self.dedup.get(key) {
            Some(linked) => *linked,
            None => {
                self.miss(UnloadedLookup::Dedup(key.0.clone(), key.1.clone()));
                None
            }
        }
    }

    fn dedup_record(&mut self, key: (TenantId, String), id: IncidentId) {
        self.dedup.insert(key.clone(), Some(id));
        self.new_dedup.push((key, id));
    }

    fn append_timeline(&mut self, entry: TimelineEntry) {
        self.timeline.push(entry);
    }

    fn timeline(&self) -> &[TimelineEntry] {
        &self.timeline
    }

    fn append_audit(&mut self, entry: AuditEntry) {
        self.audit.push(entry);
    }

    fn audit(&self) -> &[AuditEntry] {
        &self.audit
    }

    fn append_outbox(&mut self, message: OutboxMessage) {
        self.outbox.push(message);
    }

    fn outbox(&self) -> &[OutboxMessage] {
        &self.outbox
    }

    fn idempotency(&self) -> &IdempotencyStore {
        &self.idempotency
    }

    fn idempotency_mut(&mut self) -> &mut IdempotencyStore {
        &mut self.idempotency
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use tidegard_detector::{
        ActionTaken, AddressFamily, DataCompleteness, DetectionEvent, DetectionState, EventKind,
        EventTarget, ExecutionMode, MatchedReason, MetricKind, MetricRates, SamplingStatus,
        ScopeId, ScopeType, Severity, TestClock, TrafficDirection, TransitionReason,
    };
    use tidegard_incident::authorization::AuthorizationContext;
    use tidegard_incident::id::TestIncidentGenerator;
    use tidegard_incident::number::InMemoryNumberAllocator;
    use tidegard_incident::store::InMemoryIncidentStore;
    use tidegard_incident::transition::DetectionEndReason;
    use tidegard_incident::unit_of_work::{IncidentUnitOfWork, IngestOutcomeKind};

    use super::*;

    fn uow_over(store: StagingStore) -> IncidentUnitOfWork {
        IncidentUnitOfWork::new(
            Box::new(TestIncidentGenerator::starting_at(1)),
            Box::new(InMemoryNumberAllocator::new()),
            Box::new(TestClock::new()),
        )
        .with_store(Box::new(store))
    }

    fn correlator() -> AuthorizationContext {
        AuthorizationContext::correlator(TenantId::new("acme"))
    }

    /// Same shape as `crates/incident/tests/domain_end_to_end.rs`'s builder.
    fn started_event() -> DetectionEvent {
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90));
        let (detection_id, sequence, kind) = ("det-staging", 1, EventKind::Started);
        DetectionEvent {
            schema_version: tidegard_detector::EVENT_SCHEMA_VERSION,
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
            summary: format!("major started: incoming host {addr} under policy p-host-bps"),
        }
    }

    /// What the load step fetches for an ingest that finds nothing.
    fn loaded_for_first_detection(event: &DetectionEvent) -> StagingStore {
        let tenant = TenantId::new(event.target.tenant.clone());
        let key = CorrelationKey::new(
            tenant.clone(),
            event.target.scope_type,
            event.target.scope_id.clone(),
            event.target.direction,
            event.target.address_family,
        );
        let mut store = StagingStore::new();
        store.load_dedup(tenant.clone(), event.dedup_key.clone(), None);
        store.load_open_index(key.clone(), None);
        store.load_reopen_candidate(key, tenant, None);
        store
    }

    fn changes_of(uow: IncidentUnitOfWork) -> Result<ChangeSet, Vec<UnloadedLookup>> {
        StagingStore::recover(uow.into_store())
            .expect("the unit of work was built over a staging store")
            .into_changes()
    }

    #[test]
    fn a_first_detection_stages_one_new_incident_and_its_history() {
        let event = started_event();
        let mut uow = uow_over(loaded_for_first_detection(&event));
        let result = uow.ingest_detection_event(&correlator(), &event).unwrap();
        assert_eq!(result.outcome_kind, IngestOutcomeKind::Created);

        let changes = changes_of(uow).expect("every lookup was loaded");
        assert_eq!(changes.inserted.len(), 1);
        assert_eq!(Some(changes.inserted[0].incident_id), result.incident_id);
        assert!(changes.updated.is_empty());
        assert_eq!(changes.dedup_records.len(), 1);
        assert!(!changes.timeline.is_empty());
        assert!(!changes.audit.is_empty());
        assert!(!changes.outbox.is_empty());
    }

    /// ADR 0034's fail-closed rule: the domain still decides (here it
    /// creates), but the decision cannot be flushed.
    #[test]
    fn a_lookup_the_load_step_skipped_blocks_the_flush() {
        let event = started_event();
        let mut uow = uow_over(StagingStore::new());
        let _ = uow.ingest_detection_event(&correlator(), &event);

        let unloaded = changes_of(uow).expect_err("nothing was loaded");
        assert!(unloaded.contains(&UnloadedLookup::Dedup(
            TenantId::new("acme"),
            event.dedup_key.clone()
        )));
    }

    #[test]
    fn a_loaded_incident_reached_mutably_is_an_update_carrying_its_loaded_version() {
        let event = started_event();
        let mut first = uow_over(loaded_for_first_detection(&event));
        first.ingest_detection_event(&correlator(), &event).unwrap();
        let row = changes_of(first).unwrap().inserted.pop().unwrap();
        let id = row.incident_id;
        let loaded_version = row.version;

        let mut store = StagingStore::new();
        store.load_incident(row);
        let mut second = uow_over(store);
        second
            .enter_recovering(&correlator(), id, DetectionEndReason::TrafficCleared)
            .unwrap();

        let changes = changes_of(second).expect("the incident was loaded");
        assert!(changes.inserted.is_empty());
        assert_eq!(changes.updated.len(), 1);
        assert_eq!(changes.updated[0].loaded_version, loaded_version);
        assert!(changes.updated[0].incident.version > loaded_version);
        assert!(!changes.timeline.is_empty());
    }

    #[test]
    fn a_loaded_idempotency_record_is_not_reported_as_new() {
        let tenant = TenantId::new("acme");
        let outcome = StoredOutcome::Mutated {
            incident_id: IncidentId::from_bytes([9; 16]),
            version: 1,
        };
        let mut store = StagingStore::new();
        store.load_idempotency(
            tenant.clone(),
            IdempotencyKey::new("preexisting-key-0001").unwrap(),
            RequestFingerprint::of(&"old"),
            outcome.clone(),
        );
        let added = IdempotencyKey::new("added-this-call-0002").unwrap();
        store.idempotency_mut().record(
            tenant,
            added.clone(),
            RequestFingerprint::of(&"new"),
            outcome,
        );

        let changes = store.into_changes().unwrap();
        assert_eq!(changes.idempotency.len(), 1);
        assert_eq!(changes.idempotency[0].key, added);
    }

    #[test]
    fn an_id_the_load_step_found_absent_is_not_a_miss() {
        let id = IncidentId::from_bytes([7; 16]);
        let mut store = StagingStore::new();
        store.load_absent_incident(id);
        assert!(store.get(&id).is_none());
        assert!(store.into_changes().is_ok());
    }

    #[test]
    fn recover_returns_none_for_any_other_store() {
        assert!(StagingStore::recover(Box::new(InMemoryIncidentStore::new())).is_none());
    }
}
