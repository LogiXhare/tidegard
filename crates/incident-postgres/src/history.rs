//! Pure mapping for the rows one call appends: detection-event links,
//! timeline, audit and outbox entries, and idempotency records.
//!
//! Like [`crate::row`], nothing here touches a database.
//!
//! - Durable order is each table's identity column (ADR 0027). The
//!   domain's call-local `sequence` counters are not stored.
//! - `occurred_at`, `recorded_at` and `created_at` come from the
//!   database's `transaction_timestamp()` defaults.
//! - An idempotency record's outcome is stored as `response_status`
//!   (`mutated` or `failed`) plus JSON in `response_body_ref`. A failed
//!   outcome keeps its error variant and every owned field. A
//!   `&'static str` detail cannot be rebuilt from text, so it replays as
//!   [`REPLAYED_DETAIL`]. `IdempotencyStore` promises a replay the same
//!   error category, which this keeps.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use wetechinetmon_detector::DetectionEvent;
use wetechinetmon_incident::audit::{AttemptedResource, AuditEntry, AuditOutcome};
use wetechinetmon_incident::correlation::{CorrelationConflict, TenantId};
use wetechinetmon_incident::error::IncidentError;
use wetechinetmon_incident::evidence::EvidenceLinkType;
use wetechinetmon_incident::id::IncidentId;
use wetechinetmon_incident::idempotency::StoredOutcome;
use wetechinetmon_incident::incident::Incident;
use wetechinetmon_incident::outbox::OutboxMessage;
use wetechinetmon_incident::state::IncidentState;
use wetechinetmon_incident::timeline::TimelineEntry;

use crate::error::PersistError;
use crate::row::{actor_columns, severity_text, ActorColumns};
use crate::staging::NewIdempotencyRecord;

/// What a `&'static str` error detail replays as.
pub const REPLAYED_DETAIL: &str = "replayed from a stored idempotency record";

/// The `operation` column for records written by `handle_command`, the only
/// entry point that takes an idempotency key.
pub const IDEMPOTENCY_OPERATION: &str = "handle_command";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionLinkRow {
    pub incident_id: String,
    pub detection_event_id: String,
    pub tenant_id: String,
    pub dedup_key: String,
    pub detection_id: String,
    pub policy_id: String,
    pub policy_version: i32,
    pub kind: String,
    pub severity: String,
    pub observed_at: SystemTime,
    pub detected_at: SystemTime,
    pub matched: String,
    pub rates: String,
    pub link_type: String,
}

/// The link row for `event`, which the call linked to `incident_id`.
///
/// The link type is the one the incident's evidence ledger recorded for
/// this dedup key, or `evidence` when the ledger no longer retains it.
pub fn detection_link_row(
    tenant: &TenantId,
    incident_id: IncidentId,
    event: &DetectionEvent,
    incident: Option<&Incident>,
) -> Result<DetectionLinkRow, PersistError> {
    let link_type = incident
        .and_then(|incident| {
            incident
                .evidence
                .retained()
                .iter()
                .rev()
                .find(|reference| reference.dedup_key == event.dedup_key)
        })
        .map(|reference| link_type_text(reference.link_type))
        .unwrap_or("evidence");
    Ok(DetectionLinkRow {
        incident_id: incident_id.to_canonical_string(),
        detection_event_id: event.event_id.clone(),
        tenant_id: tenant.as_str().to_string(),
        dedup_key: event.dedup_key.clone(),
        detection_id: event.detection_id.clone(),
        policy_id: event.policy_id.clone(),
        policy_version: i32::try_from(event.policy_version)
            .map_err(|_| PersistError::unrepresentable("policy_version", "exceeds INTEGER"))?,
        kind: event.kind.as_str().to_string(),
        severity: severity_text(&event.severity).to_string(),
        observed_at: from_millis(event.observed_at_ms, "observed_at")?,
        detected_at: from_millis(event.detected_at_ms, "detected_at")?,
        matched: json(&event.matched, "matched")?,
        rates: json(&event.rates, "rates")?,
        link_type: link_type.to_string(),
    })
}

fn link_type_text(link_type: EvidenceLinkType) -> &'static str {
    match link_type {
        EvidenceLinkType::Opening => "opening",
        EvidenceLinkType::Update => "update",
        EvidenceLinkType::Closing => "closing",
        EvidenceLinkType::Late => "late",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineRow {
    pub incident_id: String,
    pub tenant_id: String,
    pub schema_version: i32,
    pub entry_type: &'static str,
    pub actor: ActorColumns,
    pub payload: String,
}

pub fn timeline_row(tenant: &TenantId, entry: &TimelineEntry) -> Result<TimelineRow, PersistError> {
    Ok(TimelineRow {
        incident_id: entry.incident_id.to_canonical_string(),
        tenant_id: tenant.as_str().to_string(),
        schema_version: to_i32(entry.schema_version, "timeline.schema_version")?,
        entry_type: entry.payload.entry_type(),
        actor: actor_columns(&entry.actor, "timeline.actor")?,
        payload: json(&entry.payload, "timeline.payload")?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub tenant_id: String,
    pub schema_version: i32,
    pub actor: ActorColumns,
    /// The permission's snake_case name, e.g. `incident_acknowledge`.
    pub action: String,
    pub resource_type: &'static str,
    pub resource_id: String,
    pub result: &'static str,
    pub reason: Option<String>,
    /// JSON objects naming the changed field, such as
    /// `{"severity":"major"}` and `{"severity":"info"}` (T-20).
    pub before: Option<String>,
    pub after: Option<String>,
}

pub fn audit_row(entry: &AuditEntry) -> Result<AuditRow, PersistError> {
    let action = match serde_json::to_value(entry.permission) {
        Ok(serde_json::Value::String(name)) => name,
        other => {
            return Err(PersistError::unrepresentable(
                "audit.action",
                format!("{other:?}"),
            ))
        }
    };
    let (resource_type, resource_id) = match &entry.resource {
        AttemptedResource::Incident(id) => ("incident", id.to_canonical_string()),
        AttemptedResource::Unresolved(text) => ("unresolved", text.clone()),
    };
    let result = match entry.outcome {
        AuditOutcome::Allowed => "allowed",
        AuditOutcome::Denied => "denied",
    };
    Ok(AuditRow {
        tenant_id: entry.tenant.as_str().to_string(),
        schema_version: to_i32(entry.schema_version, "audit.schema_version")?,
        actor: actor_columns(&entry.actor, "audit.actor")?,
        action,
        resource_type,
        resource_id,
        result,
        reason: entry.reason.clone(),
        before: entry
            .change
            .as_ref()
            .map(|change| serde_json::json!({ change.field.as_str(): change.before }).to_string()),
        after: entry
            .change
            .as_ref()
            .map(|change| serde_json::json!({ change.field.as_str(): change.after }).to_string()),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub tenant_id: String,
    pub aggregate_id: String,
    pub aggregate_version: i64,
    pub event_type: &'static str,
    /// The whole message as JSON.
    pub payload: String,
}

/// `aggregate_version` is the incident's version after the call, which the
/// message itself does not carry.
pub fn outbox_row(
    message: &OutboxMessage,
    aggregate_version: u64,
) -> Result<OutboxRow, PersistError> {
    Ok(OutboxRow {
        tenant_id: message.tenant.as_str().to_string(),
        aggregate_id: message.incident_id.to_canonical_string(),
        aggregate_version: i64::try_from(aggregate_version).map_err(|_| {
            PersistError::unrepresentable("outbox.aggregate_version", "exceeds BIGINT")
        })?,
        event_type: message.event.event_type(),
        payload: json(message, "outbox.payload")?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRow {
    pub tenant_id: String,
    pub idempotency_key: String,
    /// The incident a mutated outcome names; `None` for a failed outcome.
    pub resource_id: Option<String>,
    pub request_fingerprint: Vec<u8>,
    pub response_status: &'static str,
    pub response_body: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MutatedBody {
    version: u64,
}

pub fn idempotency_row(record: &NewIdempotencyRecord) -> Result<IdempotencyRow, PersistError> {
    let (resource_id, response_status, response_body) = match &record.outcome {
        StoredOutcome::Mutated {
            incident_id,
            version,
        } => (
            Some(incident_id.to_canonical_string()),
            "mutated",
            json(&MutatedBody { version: *version }, "idempotency.response")?,
        ),
        StoredOutcome::Failed(error) => (
            None,
            "failed",
            json(&PersistedError::from_error(error)?, "idempotency.response")?,
        ),
    };
    Ok(IdempotencyRow {
        tenant_id: record.tenant.as_str().to_string(),
        idempotency_key: record.key.as_str().to_string(),
        resource_id,
        request_fingerprint: record.fingerprint.as_bytes().to_vec(),
        response_status,
        response_body,
    })
}

/// Rebuilds a stored outcome from its idempotency columns.
pub fn stored_outcome(
    response_status: &str,
    resource_id: Option<&str>,
    response_body: &str,
) -> Result<StoredOutcome, PersistError> {
    match response_status {
        "mutated" => {
            let id = resource_id.ok_or_else(|| {
                PersistError::corrupt("resource_id", "a mutated outcome names no incident")
            })?;
            let incident_id = IncidentId::parse(id)
                .map_err(|e| PersistError::corrupt("resource_id", e.to_string()))?;
            let body: MutatedBody = from_json(response_body, "response_body_ref")?;
            Ok(StoredOutcome::Mutated {
                incident_id,
                version: body.version,
            })
        }
        "failed" => Ok(StoredOutcome::Failed(
            from_json::<PersistedError>(response_body, "response_body_ref")?.into_error(),
        )),
        other => Err(PersistError::corrupt(
            "response_status",
            format!("unknown value {other:?}"),
        )),
    }
}

/// `IncidentError` with every field owned, so it can be stored as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
enum PersistedError {
    NotFound,
    InvalidTransition {
        from: IncidentState,
        to: IncidentState,
    },
    VersionConflict {
        expected: u64,
        current: u64,
        current_state: IncidentState,
    },
    IdempotencyConflict,
    TenantMismatch,
    Unauthorized,
    ValidationError {
        detail: String,
    },
    CapacityExceeded,
    DuplicateActiveIncident {
        incident_id: IncidentId,
    },
    InvalidReopen {
        detail: String,
    },
    ManualClosureRequired,
    SuppressedOperation,
    EvidenceUnavailable,
    StateUnchanged {
        state: IncidentState,
    },
    CorruptSnapshot,
    ClockSkew {
        reference_micros: i64,
        decision_micros: i64,
    },
    OpenIncidentAlreadyExists {
        incident_id: IncidentId,
    },
    ReopenTargetChanged,
}

impl PersistedError {
    fn from_error(error: &IncidentError) -> Result<Self, PersistError> {
        use IncidentError as E;
        Ok(match error {
            E::NotFound => Self::NotFound,
            E::InvalidTransition { from, to } => Self::InvalidTransition {
                from: *from,
                to: *to,
            },
            E::VersionConflict {
                expected,
                current,
                current_state,
            } => Self::VersionConflict {
                expected: *expected,
                current: *current,
                current_state: *current_state,
            },
            E::IdempotencyConflict => Self::IdempotencyConflict,
            E::TenantMismatch => Self::TenantMismatch,
            E::Unauthorized => Self::Unauthorized,
            E::ValidationError(detail) => Self::ValidationError {
                detail: detail.clone(),
            },
            E::CapacityExceeded(_) => Self::CapacityExceeded,
            E::DuplicateActiveIncident(id) => Self::DuplicateActiveIncident { incident_id: *id },
            E::InvalidReopen(detail) => Self::InvalidReopen {
                detail: detail.clone(),
            },
            E::ManualClosureRequired => Self::ManualClosureRequired,
            E::SuppressedOperation => Self::SuppressedOperation,
            E::EvidenceUnavailable => Self::EvidenceUnavailable,
            E::InternalInvariantViolation(_) => {
                return Err(PersistError::unrepresentable(
                    "idempotency.response",
                    "the domain never records an internal invariant violation",
                ))
            }
            E::StateUnchanged(state) => Self::StateUnchanged { state: *state },
            E::CorruptSnapshot { .. } => Self::CorruptSnapshot,
            E::ClockSkew {
                reference_micros,
                decision_micros,
            } => Self::ClockSkew {
                reference_micros: *reference_micros,
                decision_micros: *decision_micros,
            },
            E::Correlation(CorrelationConflict::OpenIncidentAlreadyExists(id)) => {
                Self::OpenIncidentAlreadyExists { incident_id: *id }
            }
            E::Correlation(CorrelationConflict::ReopenTargetChanged) => Self::ReopenTargetChanged,
        })
    }

    fn into_error(self) -> IncidentError {
        use IncidentError as E;
        match self {
            Self::NotFound => E::NotFound,
            Self::InvalidTransition { from, to } => E::InvalidTransition { from, to },
            Self::VersionConflict {
                expected,
                current,
                current_state,
            } => E::VersionConflict {
                expected,
                current,
                current_state,
            },
            Self::IdempotencyConflict => E::IdempotencyConflict,
            Self::TenantMismatch => E::TenantMismatch,
            Self::Unauthorized => E::Unauthorized,
            Self::ValidationError { detail } => E::ValidationError(detail),
            Self::CapacityExceeded => E::CapacityExceeded(REPLAYED_DETAIL),
            Self::DuplicateActiveIncident { incident_id } => {
                E::DuplicateActiveIncident(incident_id)
            }
            Self::InvalidReopen { detail } => E::InvalidReopen(detail),
            Self::ManualClosureRequired => E::ManualClosureRequired,
            Self::SuppressedOperation => E::SuppressedOperation,
            Self::EvidenceUnavailable => E::EvidenceUnavailable,
            Self::StateUnchanged { state } => E::StateUnchanged(state),
            Self::CorruptSnapshot => E::CorruptSnapshot {
                field: REPLAYED_DETAIL,
                detail: REPLAYED_DETAIL,
            },
            Self::ClockSkew {
                reference_micros,
                decision_micros,
            } => E::ClockSkew {
                reference_micros,
                decision_micros,
            },
            Self::OpenIncidentAlreadyExists { incident_id } => {
                E::Correlation(CorrelationConflict::OpenIncidentAlreadyExists(incident_id))
            }
            Self::ReopenTargetChanged => E::Correlation(CorrelationConflict::ReopenTargetChanged),
        }
    }
}

fn to_i32(value: u32, field: &'static str) -> Result<i32, PersistError> {
    i32::try_from(value).map_err(|_| PersistError::unrepresentable(field, "exceeds INTEGER"))
}

fn from_millis(millis: u64, field: &'static str) -> Result<SystemTime, PersistError> {
    UNIX_EPOCH
        .checked_add(Duration::from_millis(millis))
        .ok_or_else(|| PersistError::unrepresentable(field, "outside this platform's SystemTime"))
}

fn json<T: Serialize + ?Sized>(value: &T, field: &'static str) -> Result<String, PersistError> {
    serde_json::to_string(value).map_err(|e| PersistError::unrepresentable(field, e.to_string()))
}

fn from_json<T: serde::de::DeserializeOwned>(
    text: &str,
    column: &'static str,
) -> Result<T, PersistError> {
    serde_json::from_str(text).map_err(|e| PersistError::corrupt(column, e.to_string()))
}

#[cfg(test)]
mod tests {
    use wetechinetmon_incident::authorization::{Actor, Permission};
    use wetechinetmon_incident::id::{IncidentGenerator, TestIncidentGenerator};
    use wetechinetmon_incident::idempotency::{IdempotencyKey, RequestFingerprint};

    use super::*;

    fn some_id() -> IncidentId {
        TestIncidentGenerator::starting_at(7).generate().unwrap()
    }

    fn replay(outcome: StoredOutcome) -> StoredOutcome {
        let record = NewIdempotencyRecord {
            tenant: TenantId::new("acme"),
            key: IdempotencyKey::new("history-test-key-01").unwrap(),
            fingerprint: RequestFingerprint::of(&"request"),
            outcome,
        };
        let row = idempotency_row(&record).unwrap();
        stored_outcome(
            row.response_status,
            row.resource_id.as_deref(),
            &row.response_body,
        )
        .unwrap()
    }

    #[test]
    fn a_mutated_outcome_replays_exactly() {
        let outcome = StoredOutcome::Mutated {
            incident_id: some_id(),
            version: 42,
        };
        assert_eq!(replay(outcome.clone()), outcome);
    }

    #[test]
    fn every_failed_outcome_with_owned_fields_replays_exactly() {
        let id = some_id();
        for error in [
            IncidentError::NotFound,
            IncidentError::InvalidTransition {
                from: IncidentState::Open,
                to: IncidentState::Closed,
            },
            IncidentError::VersionConflict {
                expected: 3,
                current: 4,
                current_state: IncidentState::Acknowledged,
            },
            IncidentError::IdempotencyConflict,
            IncidentError::TenantMismatch,
            IncidentError::Unauthorized,
            IncidentError::ValidationError("title too long".to_string()),
            IncidentError::DuplicateActiveIncident(id),
            IncidentError::InvalidReopen("outside the window".to_string()),
            IncidentError::ManualClosureRequired,
            IncidentError::SuppressedOperation,
            IncidentError::EvidenceUnavailable,
            IncidentError::StateUnchanged(IncidentState::Monitoring),
            IncidentError::ClockSkew {
                reference_micros: 10,
                decision_micros: 5,
            },
            IncidentError::Correlation(CorrelationConflict::OpenIncidentAlreadyExists(id)),
            IncidentError::Correlation(CorrelationConflict::ReopenTargetChanged),
        ] {
            let outcome = StoredOutcome::Failed(error);
            assert_eq!(replay(outcome.clone()), outcome);
        }
    }

    #[test]
    fn static_error_details_replay_with_the_same_category() {
        assert_eq!(
            replay(StoredOutcome::Failed(IncidentError::CapacityExceeded(
                "notes"
            ))),
            StoredOutcome::Failed(IncidentError::CapacityExceeded(REPLAYED_DETAIL))
        );
        assert!(matches!(
            replay(StoredOutcome::Failed(IncidentError::CorruptSnapshot {
                field: "version",
                detail: "must start at one",
            })),
            StoredOutcome::Failed(IncidentError::CorruptSnapshot { .. })
        ));
    }

    #[test]
    fn an_internal_invariant_violation_is_never_stored() {
        let record = NewIdempotencyRecord {
            tenant: TenantId::new("acme"),
            key: IdempotencyKey::new("history-test-key-02").unwrap(),
            fingerprint: RequestFingerprint::of(&"request"),
            outcome: StoredOutcome::Failed(IncidentError::InternalInvariantViolation("x")),
        };
        assert!(matches!(
            idempotency_row(&record),
            Err(PersistError::Unrepresentable { .. })
        ));
    }

    #[test]
    fn unknown_or_incomplete_stored_outcomes_are_corrupt() {
        assert!(stored_outcome("pending", None, "{}").is_err());
        assert!(stored_outcome("mutated", None, r#"{"version":1}"#).is_err());
        assert!(stored_outcome("failed", None, r#"{"error":"no_such_error"}"#).is_err());
    }

    #[test]
    fn audit_rows_name_the_permission_resource_and_result() {
        let id = some_id();
        let row = audit_row(&AuditEntry::allowed(
            1,
            TenantId::new("acme"),
            Actor::System,
            Permission::IncidentAcknowledge,
            id,
        ))
        .unwrap();
        assert_eq!(row.action, "incident_acknowledge");
        assert_eq!(
            (row.resource_type, row.resource_id.as_str(), row.result),
            ("incident", id.to_canonical_string().as_str(), "allowed")
        );
        assert_eq!(
            (row.actor.actor_type.as_str(), row.actor.actor_id),
            ("system", None)
        );
        assert_eq!((row.before, row.after), (None, None));
    }

    #[test]
    fn a_field_change_is_written_as_before_and_after_objects() {
        let row = audit_row(
            &AuditEntry::allowed(
                1,
                TenantId::new("acme"),
                Actor::System,
                Permission::IncidentSeverityChange,
                some_id(),
            )
            .with_change("severity", "major", "info", Some("filtered".into())),
        )
        .unwrap();
        assert_eq!(row.before.as_deref(), Some(r#"{"severity":"major"}"#));
        assert_eq!(row.after.as_deref(), Some(r#"{"severity":"info"}"#));
        assert_eq!(row.reason.as_deref(), Some("filtered"));
    }
}
