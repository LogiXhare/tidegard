//! Pure mapping between an incident and the column values of its
//! `incidents` row and child rows.
//!
//! No SQL and no connection live here, so every rule below is testable
//! without a database. [`crate::sql`] binds these values to statements.
//!
//! Rules worth knowing before changing this file:
//!
//! - **Enum text comes from the tables in this file, never from serde.**
//!   Serde names are camelCase or UPPERCASE depending on the type; the
//!   schema's CHECK constraints use the values below. One table per enum
//!   serves both directions, and a stored value outside it is corrupt.
//! - **`correlation_key` is the authority for scope.** It is stored as the
//!   key's JSON, which keeps the 4-valued `ScopeType` that the 3-valued
//!   `target_type` column cannot. `target_type`, `target_addr`,
//!   `target_network` and `target_hostgroup` are derived from it on write
//!   for the partial unique indexes. On load only `target_type` is
//!   cross-checked; the typed address columns are never read back.
//! - **A network target is written through `network(inet)`** by the SQL
//!   layer, because a policy prefix may carry host bits (`203.0.113.5/24`)
//!   that a `cidr` column rejects. The key keeps the exact value.
//! - **Timestamps are microseconds since the epoch**, the resolution both
//!   `DurableTimestamp` and `timestamptz` store, so a round trip is exact.

use std::collections::BTreeMap;

use wetechinetmon_detector::{AddressFamily, MetricKind, ScopeId, Severity, TrafficDirection};
use wetechinetmon_incident::assignment::{Assignee, Assignment};
use wetechinetmon_incident::authorization::Actor;
use wetechinetmon_incident::category::IncidentCategory;
use wetechinetmon_incident::closure::ClosureReason;
use wetechinetmon_incident::correlation::{CorrelationKey, TenantId};
use wetechinetmon_incident::durable_time::DurableTimestamp;
use wetechinetmon_incident::evidence::EvidenceLedger;
use wetechinetmon_incident::id::IncidentId;
use wetechinetmon_incident::incident::{Incident, Note, NoteRedaction, NoteVisibility, PolicyRef};
use wetechinetmon_incident::number::IncidentNumber;
use wetechinetmon_incident::severity::{Priority, SeveritySource};
use wetechinetmon_incident::snapshot::IncidentSnapshot;
use wetechinetmon_incident::state::IncidentState;
use wetechinetmon_incident::suppression::SuppressionDisplay;

use crate::error::PersistError;

/// One incident as plain column values: the `incidents` row plus its
/// notes, tags and policy references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentRow {
    pub incident_id: String,
    pub incident_number: String,
    pub schema_version: i32,
    pub tenant_id: String,
    pub correlation_key: String,
    pub address_family: i16,
    pub direction: String,
    pub target_type: String,
    pub target_addr: Option<String>,
    /// `address/prefix_len` as the key holds it; see the module doc.
    pub target_network: Option<String>,
    pub target_hostgroup: Option<String>,
    pub created_by: ActorColumns,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub severity: String,
    pub severity_source: String,
    pub ever_critical: bool,
    pub maximum_detected_severity: String,
    pub priority: String,
    pub closure_reason: Option<String>,
    pub state_before_recovering: Option<String>,
    pub suppression: Option<SuppressionColumns>,
    pub version: i64,
    pub category: String,
    pub matched_metrics: String,
    pub first_detected_at: i64,
    pub opened_at: i64,
    pub last_detected_at: i64,
    pub last_updated_at: i64,
    pub acknowledged_at: Option<i64>,
    pub recovering_since: Option<i64>,
    pub resolved_at: Option<i64>,
    pub closed_at: Option<i64>,
    pub reopened_at: Option<i64>,
    pub reopen_count: i32,
    pub assigned_kind: Option<String>,
    pub assigned_id: Option<String>,
    pub updated_by: ActorColumns,
    pub evidence_summary: String,
    pub notes: Vec<NoteRow>,
    /// Ordered by key.
    pub tags: Vec<(String, String)>,
    pub policy_refs: Vec<PolicyRefRow>,
    /// V13.
    pub policy_refs_omitted: i64,
}

/// An actor split into `_type` and nullable `_id` (V2 design note 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorColumns {
    pub actor_type: String,
    pub actor_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionColumns {
    pub until: i64,
    pub reason: String,
    pub by: ActorColumns,
}

impl SuppressionColumns {
    /// Rebuilds a suppression from its four nullable columns. Either all
    /// of them are set or none are.
    pub fn from_nullable(
        until: Option<i64>,
        reason: Option<String>,
        by_type: Option<String>,
        by_id: Option<String>,
    ) -> Result<Option<Self>, PersistError> {
        match (until, reason, by_type) {
            (None, None, None) if by_id.is_none() => Ok(None),
            (Some(until), Some(reason), Some(actor_type)) => Ok(Some(SuppressionColumns {
                until,
                reason,
                by: ActorColumns {
                    actor_type,
                    actor_id: by_id,
                },
            })),
            _ => Err(PersistError::corrupt(
                "suppressed_until",
                "suppression columns are only partly set",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRow {
    pub note_index: i32,
    pub body: String,
    pub visibility: String,
    pub created_by: ActorColumns,
    /// The `note_index` of the note this one replaces. Stored as
    /// `supersedes_note_id`, the replaced row's identity.
    pub supersedes: Option<i32>,
    pub redaction: Option<NoteRedactionColumns>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRedactionColumns {
    pub by: ActorColumns,
    pub reason: String,
}

impl NoteRedactionColumns {
    /// Rebuilds a redaction from its nullable columns. `redacted` is
    /// `redacted_at IS NOT NULL`; the actor type and the reason are set
    /// exactly when it is.
    pub fn from_nullable(
        redacted: bool,
        by_type: Option<String>,
        by_id: Option<String>,
        reason: Option<String>,
    ) -> Result<Option<Self>, PersistError> {
        match (redacted, by_type, reason) {
            (false, None, None) if by_id.is_none() => Ok(None),
            (true, Some(actor_type), Some(reason)) => Ok(Some(NoteRedactionColumns {
                by: ActorColumns {
                    actor_type,
                    actor_id: by_id,
                },
                reason,
            })),
            _ => Err(PersistError::corrupt(
                "redacted_at",
                "redaction columns are only partly set",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefRow {
    /// Position in `Incident::policy_refs` (V12).
    pub ref_index: i32,
    pub policy_id: String,
    pub policy_version: i32,
    pub first_seen_sequence: i64,
    pub last_seen_sequence: i64,
}

/// One table per enum, used in both directions.
macro_rules! text_mapping {
    ($to:ident, $from:ident, $ty:ty, $column:literal, { $($variant:path => $text:literal),+ $(,)? }) => {
        pub(crate) fn $to(value: &$ty) -> &'static str {
            match value {
                $($variant => $text,)+
            }
        }

        pub(crate) fn $from(text: &str) -> Result<$ty, PersistError> {
            match text {
                $($text => Ok($variant),)+
                other => Err(PersistError::corrupt($column, format!("unknown value {other:?}"))),
            }
        }
    };
}

text_mapping!(state_text, state_from, IncidentState, "state", {
    IncidentState::Open => "open",
    IncidentState::Acknowledged => "acknowledged",
    IncidentState::Investigating => "investigating",
    IncidentState::Monitoring => "monitoring",
    IncidentState::Recovering => "recovering",
    IncidentState::Resolved => "resolved",
    IncidentState::Closed => "closed",
});

text_mapping!(severity_text, severity_from, Severity, "severity", {
    Severity::Info => "info",
    Severity::Minor => "minor",
    Severity::Major => "major",
    Severity::Critical => "critical",
});

text_mapping!(severity_source_text, severity_source_from, SeveritySource, "severity_source", {
    SeveritySource::Detection => "detection",
    SeveritySource::Operator => "operator",
});

text_mapping!(priority_text, priority_from, Priority, "priority", {
    Priority::P1 => "P1",
    Priority::P2 => "P2",
    Priority::P3 => "P3",
    Priority::P4 => "P4",
});

text_mapping!(closure_reason_text, closure_reason_from, ClosureReason, "closure_reason", {
    ClosureReason::Resolved => "resolved",
    ClosureReason::FalsePositive => "false_positive",
    ClosureReason::Duplicate => "duplicate",
    ClosureReason::ExpectedTraffic => "expected_traffic",
    ClosureReason::NoActionRequired => "no_action_required",
    ClosureReason::Other => "other",
});

text_mapping!(category_text, category_from, IncidentCategory, "category", {
    IncidentCategory::TcpSynFlood => "tcp_syn_flood",
    IncidentCategory::FragmentationFlood => "fragmentation_flood",
    IncidentCategory::IcmpFlood => "icmp_flood",
    IncidentCategory::UdpFlood => "udp_flood",
    IncidentCategory::TcpFlood => "tcp_flood",
    IncidentCategory::PacketRate => "packet_rate",
    IncidentCategory::Bandwidth => "bandwidth",
    IncidentCategory::DropPressure => "drop_pressure",
    IncidentCategory::MultiVector => "multi_vector",
    IncidentCategory::Unclassified => "unclassified",
});

text_mapping!(direction_text, direction_from, TrafficDirection, "direction", {
    TrafficDirection::Incoming => "incoming",
    TrafficDirection::Outgoing => "outgoing",
    TrafficDirection::Internal => "internal",
    TrafficDirection::Other => "other",
    TrafficDirection::Unknown => "unknown",
});

text_mapping!(visibility_text, visibility_from, NoteVisibility, "visibility", {
    NoteVisibility::Internal => "internal",
    NoteVisibility::CustomerVisible => "customer_visible",
});

fn address_family_value(family: AddressFamily) -> i16 {
    match family {
        AddressFamily::Ipv4 => 4,
        AddressFamily::Ipv6 => 6,
    }
}

fn address_family_from(value: i16) -> Result<AddressFamily, PersistError> {
    match value {
        4 => Ok(AddressFamily::Ipv4),
        6 => Ok(AddressFamily::Ipv6),
        other => Err(PersistError::corrupt(
            "address_family",
            format!("unknown value {other}"),
        )),
    }
}

/// The `target_type` column value for a scope identity.
pub(crate) fn target_type_text(identity: &ScopeId) -> &'static str {
    match identity {
        ScopeId::Host { .. } => "host",
        ScopeId::Network { .. } => "network",
        ScopeId::Hostgroup { .. } => "hostgroup",
    }
}

pub(crate) fn actor_columns(
    actor: &Actor,
    field: &'static str,
) -> Result<ActorColumns, PersistError> {
    let (actor_type, actor_id) = match actor {
        Actor::Operator { id } => ("operator", Some(id.clone())),
        Actor::ServiceAccount { id } => ("service_account", Some(id.clone())),
        Actor::System => ("system", None),
        Actor::Platform { .. } => {
            return Err(PersistError::unrepresentable(
                field,
                "the schema has no actor type for a platform actor (FU-48)",
            ))
        }
    };
    Ok(ActorColumns {
        actor_type: actor_type.to_string(),
        actor_id,
    })
}

fn actor_from(columns: ActorColumns, column: &'static str) -> Result<Actor, PersistError> {
    match (columns.actor_type.as_str(), columns.actor_id) {
        ("operator", Some(id)) => Ok(Actor::Operator { id }),
        ("service_account", Some(id)) => Ok(Actor::ServiceAccount { id }),
        ("system", None) => Ok(Actor::System),
        (other, id) => Err(PersistError::corrupt(
            column,
            format!("actor type {other:?} with id present: {}", id.is_some()),
        )),
    }
}

fn to_i32(value: u32, field: &'static str) -> Result<i32, PersistError> {
    i32::try_from(value).map_err(|_| PersistError::unrepresentable(field, "exceeds INTEGER"))
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, PersistError> {
    i64::try_from(value).map_err(|_| PersistError::unrepresentable(field, "exceeds BIGINT"))
}

fn to_u32(value: i32, column: &'static str) -> Result<u32, PersistError> {
    u32::try_from(value).map_err(|_| PersistError::corrupt(column, "is negative"))
}

fn to_u64(value: i64, column: &'static str) -> Result<u64, PersistError> {
    u64::try_from(value).map_err(|_| PersistError::corrupt(column, "is negative"))
}

fn json<T: serde::Serialize>(value: &T, field: &'static str) -> Result<String, PersistError> {
    serde_json::to_string(value).map_err(|e| PersistError::unrepresentable(field, e.to_string()))
}

fn from_json<T: serde::de::DeserializeOwned>(
    text: &str,
    column: &'static str,
) -> Result<T, PersistError> {
    serde_json::from_str(text).map_err(|e| PersistError::corrupt(column, e.to_string()))
}

fn micros(timestamp: &DurableTimestamp) -> i64 {
    timestamp.as_micros()
}

fn timestamp(micros: i64) -> DurableTimestamp {
    DurableTimestamp::from_micros(micros)
}

impl IncidentRow {
    pub fn from_incident(incident: &Incident) -> Result<Self, PersistError> {
        Self::from_snapshot(&incident.to_snapshot())
    }

    /// Maps the columns back and runs the domain's own consistency checks.
    pub fn into_incident(self) -> Result<Incident, PersistError> {
        Incident::reconstitute(self.into_snapshot()?).map_err(PersistError::Rejected)
    }

    pub fn from_snapshot(s: &IncidentSnapshot) -> Result<Self, PersistError> {
        let (target_addr, target_network, target_hostgroup) = match &s.target_identity {
            ScopeId::Host { addr } => (Some(addr.to_string()), None, None),
            ScopeId::Network { addr, prefix_len } => {
                (None, Some(format!("{addr}/{prefix_len}")), None)
            }
            ScopeId::Hostgroup { name } => (None, None, Some(name.clone())),
        };
        let suppression = match &s.suppression {
            None => None,
            Some(display) => Some(SuppressionColumns {
                until: micros(&display.until),
                reason: display.reason.clone(),
                by: actor_columns(&display.by, "suppression.by")?,
            }),
        };
        let (assigned_kind, assigned_id) = match &s.assignment.assignee {
            None => (None, None),
            Some(Assignee::User { id }) => (Some("user".to_string()), Some(id.clone())),
            Some(Assignee::Team { id }) => (Some("team".to_string()), Some(id.clone())),
        };
        let notes = s
            .notes
            .iter()
            .map(|note| {
                Ok(NoteRow {
                    note_index: to_i32(note.index, "notes.index")?,
                    body: note.body.clone(),
                    visibility: visibility_text(&note.visibility).to_string(),
                    created_by: actor_columns(&note.created_by, "notes.created_by")?,
                    supersedes: note
                        .supersedes
                        .map(|earlier| to_i32(earlier, "notes.supersedes"))
                        .transpose()?,
                    redaction: note
                        .redaction
                        .as_ref()
                        .map(|redaction| {
                            Ok::<_, PersistError>(NoteRedactionColumns {
                                by: actor_columns(&redaction.by, "notes.redaction.by")?,
                                reason: redaction.reason.clone(),
                            })
                        })
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, PersistError>>()?;
        let policy_refs = s
            .policy_refs
            .iter()
            .enumerate()
            .map(|(position, reference)| {
                Ok(PolicyRefRow {
                    ref_index: i32::try_from(position).map_err(|_| {
                        PersistError::unrepresentable("policy_refs", "exceeds INTEGER")
                    })?,
                    policy_id: reference.policy_id.clone(),
                    policy_version: to_i32(reference.policy_version, "policy_refs.policy_version")?,
                    first_seen_sequence: to_i64(
                        reference.first_seen_sequence,
                        "policy_refs.first_seen_sequence",
                    )?,
                    last_seen_sequence: to_i64(
                        reference.last_seen_sequence,
                        "policy_refs.last_seen_sequence",
                    )?,
                })
            })
            .collect::<Result<Vec<_>, PersistError>>()?;

        Ok(IncidentRow {
            incident_id: s.incident_id.to_canonical_string(),
            incident_number: s.incident_number.as_str().to_string(),
            schema_version: to_i32(s.schema_version, "schema_version")?,
            tenant_id: s.tenant_id.as_str().to_string(),
            correlation_key: json(&s.correlation_key, "correlation_key")?,
            address_family: address_family_value(s.address_family),
            direction: direction_text(&s.direction).to_string(),
            target_type: target_type_text(&s.target_identity).to_string(),
            target_addr,
            target_network,
            target_hostgroup,
            created_by: actor_columns(&s.created_by, "created_by")?,
            title: s.title.clone(),
            description: s.description.clone(),
            state: state_text(&s.state).to_string(),
            severity: severity_text(&s.severity).to_string(),
            severity_source: severity_source_text(&s.severity_source).to_string(),
            ever_critical: s.ever_critical,
            maximum_detected_severity: severity_text(&s.maximum_detected_severity).to_string(),
            priority: priority_text(&s.priority).to_string(),
            closure_reason: s
                .closure_reason
                .as_ref()
                .map(|r| closure_reason_text(r).to_string()),
            state_before_recovering: s
                .state_before_recovering
                .as_ref()
                .map(|state| state_text(state).to_string()),
            suppression,
            version: to_i64(s.version, "version")?,
            category: category_text(&s.category).to_string(),
            matched_metrics: json(&s.matched_metrics, "matched_metrics")?,
            first_detected_at: micros(&s.first_detected_at),
            opened_at: micros(&s.opened_at),
            last_detected_at: micros(&s.last_detected_at),
            last_updated_at: micros(&s.last_updated_at),
            acknowledged_at: s.acknowledged_at.as_ref().map(micros),
            recovering_since: s.recovering_since.as_ref().map(micros),
            resolved_at: s.resolved_at.as_ref().map(micros),
            closed_at: s.closed_at.as_ref().map(micros),
            reopened_at: s.reopened_at.as_ref().map(micros),
            reopen_count: to_i32(s.reopen_count, "reopen_count")?,
            assigned_kind,
            assigned_id,
            updated_by: actor_columns(&s.updated_by, "updated_by")?,
            evidence_summary: json(&s.evidence, "evidence_summary")?,
            notes,
            tags: s
                .tags
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            policy_refs,
            policy_refs_omitted: to_i64(s.policy_refs_omitted, "policy_refs_omitted")?,
        })
    }

    /// Maps the columns back without the domain's consistency checks;
    /// [`IncidentRow::into_incident`] runs them.
    pub fn into_snapshot(self) -> Result<IncidentSnapshot, PersistError> {
        let correlation_key: CorrelationKey = from_json(&self.correlation_key, "correlation_key")?;
        let derived_target_type = target_type_text(&correlation_key.target_identity);
        if self.target_type != derived_target_type {
            return Err(PersistError::corrupt(
                "target_type",
                format!(
                    "{:?} disagrees with the correlation key's {derived_target_type:?}",
                    self.target_type
                ),
            ));
        }

        let incident_number: IncidentNumber =
            serde_json::from_value(serde_json::Value::String(self.incident_number))
                .map_err(|e| PersistError::corrupt("incident_number", e.to_string()))?;
        let suppression = match self.suppression {
            None => None,
            Some(columns) => Some(SuppressionDisplay {
                until: timestamp(columns.until),
                reason: columns.reason,
                by: actor_from(columns.by, "suppressed_by_type")?,
            }),
        };
        let assignee = match (self.assigned_kind.as_deref(), self.assigned_id) {
            (None, None) => None,
            (Some("user"), Some(id)) => Some(Assignee::User { id }),
            (Some("team"), Some(id)) => Some(Assignee::Team { id }),
            (kind, _) => {
                return Err(PersistError::corrupt(
                    "assigned_kind",
                    format!("unknown or half-set assignment {kind:?}"),
                ))
            }
        };

        let mut note_rows = self.notes;
        note_rows.sort_by_key(|note| note.note_index);
        let notes = note_rows
            .into_iter()
            .map(|note| {
                Ok(Note {
                    index: to_u32(note.note_index, "note_index")?,
                    body: note.body,
                    visibility: visibility_from(&note.visibility)?,
                    created_by: actor_from(note.created_by, "incident_notes.created_by_type")?,
                    supersedes: note
                        .supersedes
                        .map(|earlier| to_u32(earlier, "supersedes_note_id"))
                        .transpose()?,
                    redaction: note
                        .redaction
                        .map(|columns| {
                            Ok::<_, PersistError>(NoteRedaction {
                                by: actor_from(columns.by, "incident_notes.redacted_by_type")?,
                                reason: columns.reason,
                            })
                        })
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, PersistError>>()?;

        let mut ref_rows = self.policy_refs;
        ref_rows.sort_by_key(|reference| reference.ref_index);
        if ref_rows
            .iter()
            .enumerate()
            .any(|(position, reference)| i32::try_from(position) != Ok(reference.ref_index))
        {
            return Err(PersistError::corrupt(
                "ref_index",
                "policy reference positions are not 0..n without gaps",
            ));
        }
        let policy_refs = ref_rows
            .into_iter()
            .map(|reference| {
                Ok(PolicyRef {
                    policy_id: reference.policy_id,
                    policy_version: to_u32(reference.policy_version, "policy_version")?,
                    first_seen_sequence: to_u64(
                        reference.first_seen_sequence,
                        "first_seen_sequence",
                    )?,
                    last_seen_sequence: to_u64(reference.last_seen_sequence, "last_seen_sequence")?,
                })
            })
            .collect::<Result<Vec<_>, PersistError>>()?;

        Ok(IncidentSnapshot {
            incident_id: IncidentId::parse(&self.incident_id)
                .map_err(|e| PersistError::corrupt("incident_id", e.to_string()))?,
            incident_number,
            schema_version: to_u32(self.schema_version, "schema_version")?,
            tenant_id: TenantId::new(self.tenant_id),
            address_family: address_family_from(self.address_family)?,
            direction: direction_from(&self.direction)?,
            target_type: correlation_key.target_type,
            target_identity: correlation_key.target_identity.clone(),
            correlation_key,
            created_by: actor_from(self.created_by, "created_by_type")?,
            title: self.title,
            description: self.description,
            state: state_from(&self.state)?,
            severity: severity_from(&self.severity)?,
            severity_source: severity_source_from(&self.severity_source)?,
            ever_critical: self.ever_critical,
            maximum_detected_severity: severity_from(&self.maximum_detected_severity)?,
            priority: priority_from(&self.priority)?,
            closure_reason: self
                .closure_reason
                .as_deref()
                .map(closure_reason_from)
                .transpose()?,
            state_before_recovering: self
                .state_before_recovering
                .as_deref()
                .map(state_from)
                .transpose()?,
            suppression,
            version: to_u64(self.version, "version")?,
            category: category_from(&self.category)?,
            matched_metrics: from_json::<Vec<MetricKind>>(
                &self.matched_metrics,
                "matched_metrics",
            )?,
            first_detected_at: timestamp(self.first_detected_at),
            opened_at: timestamp(self.opened_at),
            last_detected_at: timestamp(self.last_detected_at),
            last_updated_at: timestamp(self.last_updated_at),
            acknowledged_at: self.acknowledged_at.map(timestamp),
            recovering_since: self.recovering_since.map(timestamp),
            resolved_at: self.resolved_at.map(timestamp),
            closed_at: self.closed_at.map(timestamp),
            reopened_at: self.reopened_at.map(timestamp),
            reopen_count: to_u32(self.reopen_count, "reopen_count")?,
            assignment: Assignment { assignee },
            updated_by: actor_from(self.updated_by, "updated_by_type")?,
            evidence: from_json::<EvidenceLedger>(&self.evidence_summary, "evidence_summary")?,
            notes,
            tags: self.tags.into_iter().collect::<BTreeMap<_, _>>(),
            policy_refs,
            policy_refs_omitted: to_u64(self.policy_refs_omitted, "policy_refs_omitted")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each table's texts must be exactly the set the schema's CHECK
    /// constraint allows, and every variant must survive the round trip.
    fn assert_table<T: PartialEq + std::fmt::Debug>(
        variants: &[T],
        to: fn(&T) -> &'static str,
        from: fn(&str) -> Result<T, PersistError>,
        schema_values: &[&str],
    ) {
        let texts: Vec<&str> = variants.iter().map(to).collect();
        assert_eq!(texts, schema_values);
        for variant in variants {
            assert_eq!(&from(to(variant)).unwrap(), variant);
        }
        assert!(matches!(
            from("not-a-value"),
            Err(PersistError::Corrupt { .. })
        ));
    }

    #[test]
    fn every_enum_table_matches_the_schema_check_values() {
        use IncidentState::*;
        assert_table(
            &[
                Open,
                Acknowledged,
                Investigating,
                Monitoring,
                Recovering,
                Resolved,
                Closed,
            ],
            state_text,
            state_from,
            &[
                "open",
                "acknowledged",
                "investigating",
                "monitoring",
                "recovering",
                "resolved",
                "closed",
            ],
        );
        assert_table(
            &[
                Severity::Info,
                Severity::Minor,
                Severity::Major,
                Severity::Critical,
            ],
            severity_text,
            severity_from,
            &["info", "minor", "major", "critical"],
        );
        assert_table(
            &[SeveritySource::Detection, SeveritySource::Operator],
            severity_source_text,
            severity_source_from,
            &["detection", "operator"],
        );
        assert_table(
            &[Priority::P1, Priority::P2, Priority::P3, Priority::P4],
            priority_text,
            priority_from,
            &["P1", "P2", "P3", "P4"],
        );
        assert_table(
            &[
                ClosureReason::Resolved,
                ClosureReason::FalsePositive,
                ClosureReason::Duplicate,
                ClosureReason::ExpectedTraffic,
                ClosureReason::NoActionRequired,
                ClosureReason::Other,
            ],
            closure_reason_text,
            closure_reason_from,
            &[
                "resolved",
                "false_positive",
                "duplicate",
                "expected_traffic",
                "no_action_required",
                "other",
            ],
        );
        assert_table(
            &[
                IncidentCategory::TcpSynFlood,
                IncidentCategory::FragmentationFlood,
                IncidentCategory::IcmpFlood,
                IncidentCategory::UdpFlood,
                IncidentCategory::TcpFlood,
                IncidentCategory::PacketRate,
                IncidentCategory::Bandwidth,
                IncidentCategory::DropPressure,
                IncidentCategory::MultiVector,
                IncidentCategory::Unclassified,
            ],
            category_text,
            category_from,
            &[
                "tcp_syn_flood",
                "fragmentation_flood",
                "icmp_flood",
                "udp_flood",
                "tcp_flood",
                "packet_rate",
                "bandwidth",
                "drop_pressure",
                "multi_vector",
                "unclassified",
            ],
        );
        assert_table(
            &[
                TrafficDirection::Incoming,
                TrafficDirection::Outgoing,
                TrafficDirection::Internal,
                TrafficDirection::Other,
                TrafficDirection::Unknown,
            ],
            direction_text,
            direction_from,
            &["incoming", "outgoing", "internal", "other", "unknown"],
        );
        assert_table(
            &[NoteVisibility::Internal, NoteVisibility::CustomerVisible],
            visibility_text,
            visibility_from,
            &["internal", "customer_visible"],
        );
    }

    #[test]
    fn tables_agree_with_the_domain_as_str_where_one_exists() {
        for state in [
            IncidentState::Open,
            IncidentState::Recovering,
            IncidentState::Closed,
        ] {
            assert_eq!(state_text(&state), state.as_str());
        }
        for severity in [Severity::Info, Severity::Critical] {
            assert_eq!(severity_text(&severity), severity.as_str());
        }
        assert_eq!(priority_text(&Priority::P3), Priority::P3.as_str());
        assert_eq!(
            category_text(&IncidentCategory::MultiVector),
            IncidentCategory::MultiVector.as_str()
        );
        assert_eq!(
            direction_text(&TrafficDirection::Internal),
            TrafficDirection::Internal.as_str()
        );
    }

    #[test]
    fn address_family_round_trips_and_rejects_other_values() {
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            assert_eq!(
                address_family_from(address_family_value(family)).unwrap(),
                family
            );
        }
        assert!(address_family_from(5).is_err());
    }

    #[test]
    fn actors_round_trip_and_a_platform_actor_is_refused() {
        for actor in [
            Actor::Operator { id: "op-1".into() },
            Actor::ServiceAccount { id: "svc-1".into() },
            Actor::System,
        ] {
            let columns = actor_columns(&actor, "created_by").unwrap();
            assert_eq!(actor_from(columns, "created_by_type").unwrap(), actor);
        }
        assert!(matches!(
            actor_columns(&Actor::Platform { id: "p".into() }, "updated_by"),
            Err(PersistError::Unrepresentable {
                field: "updated_by",
                ..
            })
        ));
        let system_with_id = ActorColumns {
            actor_type: "system".into(),
            actor_id: Some("x".into()),
        };
        assert!(actor_from(system_with_id, "created_by_type").is_err());
    }

    #[test]
    fn suppression_columns_must_be_all_set_or_all_null() {
        assert_eq!(
            SuppressionColumns::from_nullable(None, None, None, None).unwrap(),
            None
        );
        assert!(SuppressionColumns::from_nullable(
            Some(1),
            Some("scanner".into()),
            Some("operator".into()),
            Some("op-1".into())
        )
        .unwrap()
        .is_some());
        assert!(SuppressionColumns::from_nullable(Some(1), None, None, None).is_err());
        assert!(SuppressionColumns::from_nullable(None, None, None, Some("op-1".into())).is_err());
    }
}
