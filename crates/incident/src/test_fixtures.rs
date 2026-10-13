//! Shared aggregate fixtures for this crate's own tests.
//!
//! Compiled only under `cfg(test)`. It exists because three separate test
//! bodies — snapshot round-tripping, reconstitution invariants, and the
//! table-driven illegal-transition matrix FU-38 requires — each need a
//! valid [`Incident`] in an arbitrary state, and a `Incident { .. }`
//! literal repeated three times is three places to forget a field when
//! the aggregate grows.
//!
//! [`valid_incident`] returns an incident that satisfies every invariant
//! [`Incident::reconstitute`] enforces, so a test that wants to prove a
//! *violation* is rejected can start from a valid value and break exactly
//! one thing. A fixture that started out subtly invalid would make such a
//! test pass for the wrong reason.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use tidegard_detector::{AddressFamily, ScopeId, ScopeType, Severity, TrafficDirection};

use crate::assignment::Assignment;
use crate::authorization::Actor;
use crate::category::IncidentCategory;
use crate::correlation::{CorrelationKey, TenantId};
use crate::durable_time::DurableTimestamp;
use crate::evidence::EvidenceLedger;
use crate::id::IncidentId;
use crate::incident::{Incident, INCIDENT_SCHEMA_VERSION};
use crate::number::{InMemoryNumberAllocator, NumberAllocator};
use crate::severity::{Priority, SeveritySource};
use crate::state::IncidentState;

/// A fixed decision time, so a fixture is reproducible run to run.
pub(crate) const FIXTURE_TIME: DurableTimestamp = DurableTimestamp::from_micros(1_756_000_000_000);

/// A fully valid incident in `state`, with every state-dependent field
/// set consistently.
///
/// The state-dependent fields are the point: `Recovering` requires a
/// state to recover to, `Resolved` requires `resolved_at`, and `Closed`
/// requires both `closed_at` and a `closure_reason`. Setting them here
/// rather than leaving them `None` is what makes this fixture a valid
/// aggregate rather than merely a populated one.
pub(crate) fn valid_incident(state: IncidentState) -> Incident {
    let addr: IpAddr = "203.0.113.7".parse().expect("a fixed literal address");
    let now = FIXTURE_TIME;
    let key = CorrelationKey::new(
        TenantId::new("acme"),
        ScopeType::Host,
        ScopeId::Host { addr },
        TrafficDirection::Incoming,
        AddressFamily::Ipv4,
    );

    Incident {
        incident_id: IncidentId::from_bytes([1; 16]),
        incident_number: InMemoryNumberAllocator::new()
            .allocate("acme", 2026)
            .expect("the in-memory allocator cannot fail on its first call"),
        schema_version: INCIDENT_SCHEMA_VERSION,
        tenant_id: TenantId::new("acme"),
        correlation_key: key,
        address_family: AddressFamily::Ipv4,
        direction: TrafficDirection::Incoming,
        target_type: ScopeType::Host,
        target_identity: ScopeId::Host { addr },
        created_by: Actor::System,
        title: "fixture incident".to_string(),
        description: None,
        state,
        severity: Severity::Major,
        severity_source: SeveritySource::Detection,
        ever_critical: false,
        maximum_detected_severity: Severity::Major,
        priority: Priority::default_for(Severity::Major),
        closure_reason: if state == IncidentState::Closed {
            Some(crate::closure::ClosureReason::Resolved)
        } else {
            None
        },
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
        recovering_since: if state == IncidentState::Recovering {
            Some(now)
        } else {
            None
        },
        resolved_at: if matches!(state, IncidentState::Resolved | IncidentState::Closed) {
            Some(now)
        } else {
            None
        },
        closed_at: if state == IncidentState::Closed {
            Some(now)
        } else {
            None
        },
        reopened_at: None,
        reopen_count: 0,
        assignment: Assignment::unassigned(),
        updated_by: Actor::System,
        evidence: EvidenceLedger::new(),
        notes: Vec::new(),
        tags: BTreeMap::new(),
        policy_refs: Vec::new(),
        policy_refs_omitted: 0,
    }
}
