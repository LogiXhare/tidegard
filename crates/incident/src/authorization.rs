//! Authorization: permissions, actors, and the tenant-aware context every
//! command carries.
//!
//! Tenant isolation's most reliable layer is the repository one: the
//! tenant context is a **constructor argument**, never an optional
//! parameter a caller can forget to pass. [`AuthorizationContext`] is
//! that argument — every command-handling entry point in
//! [`crate::unit_of_work`] takes one, so a tenant-less mutation is not
//! merely discouraged, it does not type-check.

use serde::{Deserialize, Serialize};

use crate::correlation::TenantId;

/// Everything the code checks. Roles are bundles that differ per
/// deployment; this crate only ever compares against permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    IncidentRead,
    IncidentList,
    /// Open an incident by hand (ADR 0039).
    IncidentCreate,
    IncidentUpdate,
    IncidentAcknowledge,
    IncidentAssign,
    IncidentInvestigate,
    IncidentNoteCreate,
    /// Remove a note's body, keeping the record that it existed. Held by
    /// `noc_lead` and above: it removes another operator's words.
    IncidentNoteRedact,
    IncidentNoteCustomerVisible,
    IncidentSeverityChange,
    IncidentPriorityChange,
    IncidentResolve,
    IncidentClose,
    IncidentReopen,
    IncidentSuppress,
    IncidentExport,
    IncidentAuditRead,
    IncidentConfigRead,
    IncidentClosurePolicyOverride,
    /// Ingestion-only: may create and update incidents through
    /// correlation. Deliberately cannot acknowledge, assign, resolve,
    /// close, or note — a compromised ingestion credential should be able
    /// to create noise, not hide an attack.
    IncidentIngest,
    PlatformIncidentReadAll,
    PlatformIncidentAdmin,
    /// Read deployment-wide traffic (ADR 0042). Traffic carries no tenant
    /// until Phase 8, so the API also requires the caller to be in the
    /// one configured traffic tenant.
    TrafficRead,
}

impl Permission {
    /// The dotted name the security model and the API use, such as
    /// `incident.note.create`. Stable: an API client may switch on it.
    pub fn name(self) -> &'static str {
        use Permission::*;
        match self {
            IncidentRead => "incident.read",
            IncidentList => "incident.list",
            IncidentCreate => "incident.create",
            IncidentUpdate => "incident.update",
            IncidentAcknowledge => "incident.acknowledge",
            IncidentAssign => "incident.assign",
            IncidentInvestigate => "incident.investigate",
            IncidentNoteCreate => "incident.note.create",
            IncidentNoteRedact => "incident.note.redact",
            IncidentNoteCustomerVisible => "incident.note.customer_visible",
            IncidentSeverityChange => "incident.severity.change",
            IncidentPriorityChange => "incident.priority.change",
            IncidentResolve => "incident.resolve",
            IncidentClose => "incident.close",
            IncidentReopen => "incident.reopen",
            IncidentSuppress => "incident.suppress",
            IncidentExport => "incident.export",
            IncidentAuditRead => "incident.audit.read",
            IncidentConfigRead => "incident.config.read",
            IncidentClosurePolicyOverride => "incident.closure_policy.override",
            IncidentIngest => "incident.ingest",
            PlatformIncidentReadAll => "platform.incident.read_all",
            PlatformIncidentAdmin => "platform.incident.admin",
            TrafficRead => "traffic.read",
        }
    }
}

/// Who is performing an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Actor {
    Operator {
        id: String,
    },
    ServiceAccount {
        id: String,
    },
    /// The correlator, driving automatic transitions. Not an operator —
    /// automatic transitions carry no permission check, but every one
    /// still writes a timeline entry and an audit record with this actor.
    System,
    /// A platform-level actor operating across tenants, distinct from a
    /// tenant-scoped operator and never granted implicitly.
    Platform {
        id: String,
    },
}

impl Actor {
    pub fn system_correlator() -> Self {
        Actor::System
    }

    pub fn is_system(&self) -> bool {
        matches!(self, Actor::System)
    }
}

/// The caller's tenant and granted permissions, constructed once per
/// request and threaded through every command. There is no
/// `AuthorizationContext::none()` — a command handler that needs one
/// cannot be called without it.
#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    tenant: TenantId,
    actor: Actor,
    granted: Vec<Permission>,
}

impl AuthorizationContext {
    pub fn new(tenant: TenantId, actor: Actor, granted: Vec<Permission>) -> Self {
        AuthorizationContext {
            tenant,
            actor,
            granted,
        }
    }

    /// The correlator's context for a given tenant: `system:correlator`,
    /// holding only `IncidentIngest`.
    pub fn correlator(tenant: TenantId) -> Self {
        AuthorizationContext {
            tenant,
            actor: Actor::System,
            granted: vec![Permission::IncidentIngest],
        }
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    pub fn has(&self, permission: Permission) -> bool {
        self.granted.contains(&permission)
    }
}

/// The ADR-0017 Community extension point for turning a role into a
/// permission set. This crate's `FixedBundleResolver` is the complete
/// Community implementation; Enterprise may substitute custom roles and
/// per-field authorization without this trait's shape changing.
pub trait PermissionResolver: Send + Sync {
    fn permissions_for(&self, role: &str) -> Vec<Permission>;
}

/// The five suggested Community role bundles from the security model.
/// `incident.closure_policy.override` appears in **none** of them,
/// including `noc_lead` — it must be granted deliberately, on its own,
/// or not at all.
pub struct FixedBundleResolver;

impl PermissionResolver for FixedBundleResolver {
    fn permissions_for(&self, role: &str) -> Vec<Permission> {
        use Permission::*;
        let viewer = vec![IncidentRead, IncidentList, TrafficRead];
        let operator = {
            let mut v = viewer.clone();
            v.extend([
                IncidentAcknowledge,
                IncidentAssign,
                IncidentInvestigate,
                IncidentNoteCreate,
            ]);
            v
        };
        let senior_operator = {
            let mut v = operator.clone();
            v.extend([
                IncidentSeverityChange,
                IncidentPriorityChange,
                IncidentResolve,
                IncidentClose,
                IncidentReopen,
                IncidentCreate,
            ]);
            v
        };
        let noc_lead = {
            let mut v = senior_operator.clone();
            v.extend([
                IncidentSuppress,
                IncidentExport,
                IncidentAuditRead,
                IncidentConfigRead,
                IncidentUpdate,
                IncidentNoteRedact,
            ]);
            v
        };
        match role {
            "viewer" => viewer,
            "operator" => operator,
            "senior_operator" => senior_operator,
            "noc_lead" => noc_lead,
            "platform_admin" => {
                let mut v = noc_lead.clone();
                v.extend([
                    IncidentClosurePolicyOverride,
                    PlatformIncidentReadAll,
                    PlatformIncidentAdmin,
                    IncidentNoteCustomerVisible,
                ]);
                v
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name is the one the security model's permission table uses.
    #[test]
    fn names_match_the_security_model() {
        let document = include_str!("../../../docs/architecture/incident-security-model.md");
        let resolver = FixedBundleResolver;
        for permission in resolver.permissions_for("platform_admin") {
            let row = format!("| `{}` |", permission.name());
            assert!(document.contains(&row), "the security model lacks {row}");
        }
    }

    #[test]
    fn closure_policy_override_is_in_no_default_bundle() {
        let resolver = FixedBundleResolver;
        for role in ["viewer", "operator", "senior_operator", "noc_lead"] {
            let granted = resolver.permissions_for(role);
            assert!(
                !granted.contains(&Permission::IncidentClosurePolicyOverride),
                "{role} must not carry the closure-policy override permission"
            );
        }
    }

    #[test]
    fn platform_admin_carries_the_override_explicitly() {
        let resolver = FixedBundleResolver;
        assert!(resolver
            .permissions_for("platform_admin")
            .contains(&Permission::IncidentClosurePolicyOverride));
    }

    #[test]
    fn ingestion_service_account_permission_is_not_in_any_human_bundle() {
        let resolver = FixedBundleResolver;
        for role in [
            "viewer",
            "operator",
            "senior_operator",
            "noc_lead",
            "platform_admin",
        ] {
            assert!(!resolver
                .permissions_for(role)
                .contains(&Permission::IncidentIngest));
        }
    }

    #[test]
    fn an_unknown_role_grants_nothing() {
        let resolver = FixedBundleResolver;
        assert!(resolver.permissions_for("nonexistent").is_empty());
    }

    #[test]
    fn correlator_context_holds_only_ingest() {
        let ctx = AuthorizationContext::correlator(TenantId::new("acme"));
        assert!(ctx.has(Permission::IncidentIngest));
        assert!(!ctx.has(Permission::IncidentClose));
        assert!(ctx.actor().is_system());
    }
}
