//! The audit trail — separate from the timeline, and the only place a
//! **denied** command is recorded.
//!
//! Owner decision: a denied command never mutates the incident, never
//! increments its version, never emits a normal mutation outbox event,
//! and produces exactly one denied audit record. [`AuditEntry::denied`]
//! and [`AuditEntry::allowed`] are two separate constructors rather than
//! one taking a boolean, so the call site states which happened instead
//! of computing it — and [`crate::unit_of_work`]'s denial path is
//! structured so the denial itself does not depend on whether the audit
//! write "succeeds": in this in-memory crate an append cannot fail, so
//! the denied result is returned to the caller regardless, which is the
//! correct direction for the stronger real-database rule ("if it can't
//! be audited, don't proceed") to specialise into once persistence
//! exists.
//!
//! Payloads are typed, matching [`crate::timeline::TimelinePayload`]'s
//! rule: no raw `serde_json::Value` as the primary record.

use serde::{Deserialize, Serialize};

use crate::authorization::{Actor, Permission};
use crate::correlation::TenantId;
use crate::id::IncidentId;

pub const AUDIT_SCHEMA_VERSION: u32 = 1;

/// The resource an audited action targeted. A denied lookup records only
/// what the caller supplied — never whether it actually resolved to a
/// real incident in another tenant — so the audit log cannot become the
/// existence oracle the 404-not-403 rule exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptedResource {
    Incident(IncidentId),
    /// A caller-supplied identifier that was never resolved — used for a
    /// denial that occurred before (or instead of) a lookup.
    Unresolved(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Allowed,
    Denied,
}

/// A field an audited command changed, with its value before and after,
/// so the audit trail alone shows what was done (T-20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub schema_version: u32,
    pub sequence: u64,
    pub tenant: TenantId,
    pub actor: Actor,
    pub permission: Permission,
    pub resource: AttemptedResource,
    pub outcome: AuditOutcome,
    pub reason: Option<String>,
    /// Set for commands that change one field, such as severity.
    #[serde(default)]
    pub change: Option<FieldChange>,
}

impl AuditEntry {
    pub fn allowed(
        sequence: u64,
        tenant: TenantId,
        actor: Actor,
        permission: Permission,
        resource: IncidentId,
    ) -> Self {
        AuditEntry {
            schema_version: AUDIT_SCHEMA_VERSION,
            sequence,
            tenant,
            actor,
            permission,
            resource: AttemptedResource::Incident(resource),
            outcome: AuditOutcome::Allowed,
            reason: None,
            change: None,
        }
    }

    pub fn denied(
        sequence: u64,
        tenant: TenantId,
        actor: Actor,
        permission: Permission,
        resource: AttemptedResource,
        reason: impl Into<String>,
    ) -> Self {
        AuditEntry {
            schema_version: AUDIT_SCHEMA_VERSION,
            sequence,
            tenant,
            actor,
            permission,
            resource,
            outcome: AuditOutcome::Denied,
            reason: Some(reason.into()),
            change: None,
        }
    }

    /// Records the field this allowed command changed, and why, if the
    /// command gave a reason.
    pub fn with_change(
        mut self,
        field: &str,
        before: &str,
        after: &str,
        reason: Option<String>,
    ) -> Self {
        self.change = Some(FieldChange {
            field: field.to_string(),
            before: before.to_string(),
            after: after.to_string(),
        });
        self.reason = reason;
        self
    }

    pub fn is_denied(&self) -> bool {
        matches!(self.outcome, AuditOutcome::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denied_entry_carries_a_reason_and_no_resolved_incident() {
        let entry = AuditEntry::denied(
            0,
            TenantId::new("acme"),
            Actor::Operator {
                id: "u1".to_string(),
            },
            Permission::IncidentClose,
            AttemptedResource::Unresolved("some-id-from-another-tenant".to_string()),
            "unauthorized",
        );
        assert!(entry.is_denied());
        assert!(entry.reason.is_some());
        assert!(matches!(entry.resource, AttemptedResource::Unresolved(_)));
    }

    #[test]
    fn an_allowed_entry_carries_a_resolved_incident_and_no_reason() {
        let entry = AuditEntry::allowed(
            0,
            TenantId::new("acme"),
            Actor::Operator {
                id: "u1".to_string(),
            },
            Permission::IncidentAcknowledge,
            IncidentId::from_bytes([1; 16]),
        );
        assert!(!entry.is_denied());
        assert!(entry.reason.is_none());
    }
}
