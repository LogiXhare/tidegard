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
    /// Record a notification's outcome on an incident's timeline
    /// (ADR 0045). Held only by the notifier, never a human role.
    IncidentNotificationRecord,
    /// Read deployment-wide traffic (ADR 0042). Traffic carries no tenant
    /// until Phase 8, so the API also requires the caller to be in the
    /// one configured traffic tenant.
    TrafficRead,
    /// Read mitigations (ADR 0046).
    MitigationRead,
    /// Ask for a mitigation. Nothing is announced until it is approved.
    MitigationRequest,
    /// Approve or reject a mitigation: `noc_lead` and above.
    MitigationApprove,
    /// Take an approved mitigation down.
    MitigationWithdraw,
    /// Propose a mitigation for an incident. The mitigator only, never a
    /// human role: a proposal still needs an approver.
    MitigationPropose,
    /// Move a mitigation through announcing, active, withdrawing and the
    /// ends. The mitigator only, never a human role.
    MitigationExecute,
    /// Turn the deployment-wide kill switch on: `noc_lead` and above.
    /// Stopping every mitigation is always safe to ask for.
    MitigationKillSwitchEngage,
    /// Turn it off again: platform administrators only.
    MitigationKillSwitchRelease,
    /// Register, suspend and reactivate tenants, and their prefixes
    /// (ADR 0060). Platform roles only.
    PlatformTenantAdmin,
    /// Issue and revoke the API tokens of the tenant acted in.
    TenantTokenAdmin,
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
            IncidentNotificationRecord => "incident.notification.record",
            MitigationRead => "mitigation.read",
            MitigationRequest => "mitigation.request",
            MitigationApprove => "mitigation.approve",
            MitigationWithdraw => "mitigation.withdraw",
            MitigationPropose => "mitigation.propose",
            MitigationExecute => "mitigation.execute",
            MitigationKillSwitchEngage => "mitigation.kill_switch.engage",
            MitigationKillSwitchRelease => "mitigation.kill_switch.release",
            PlatformTenantAdmin => "platform.tenant.admin",
            TenantTokenAdmin => "tenant.token.admin",
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
    /// The notifier's context for a tenant (ADR 0045): a service account
    /// that may record notification outcomes and read incidents, nothing
    /// else.
    pub fn notifier(tenant: TenantId, consumer_id: &str) -> Self {
        AuthorizationContext {
            tenant,
            actor: Actor::ServiceAccount {
                id: consumer_id.to_string(),
            },
            granted: vec![
                Permission::IncidentRead,
                Permission::IncidentNotificationRecord,
            ],
        }
    }

    /// The mitigator's context for a tenant (ADR 0046): it may read,
    /// propose and carry out mitigations, and never approve one.
    pub fn mitigator(tenant: TenantId, consumer_id: &str) -> Self {
        AuthorizationContext {
            tenant,
            actor: Actor::ServiceAccount {
                id: consumer_id.to_string(),
            },
            granted: vec![
                Permission::IncidentRead,
                Permission::MitigationRead,
                Permission::MitigationPropose,
                Permission::MitigationExecute,
            ],
        }
    }

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

/// The roles a tenant-scoped principal may hold: the four of v1.0.0,
/// unchanged, and the tenant roles of FR-12.2 (ADR 0060).
pub const TENANT_ROLES: [&str; 7] = [
    "viewer",
    "operator",
    "senior_operator",
    "noc_lead",
    "customer_admin",
    "security_analyst",
    "automation",
];

/// The provider roles of FR-12.2, which act across tenants (BQ-21). A
/// tenant-scoped principal never holds one.
pub const PLATFORM_ROLES: [&str; 5] = [
    "noc_operator",
    "noc_admin",
    "auditor",
    "platform_admin",
    "super_admin",
];

/// The Community role bundles from the security model, one per role in
/// [`TENANT_ROLES`] and [`PLATFORM_ROLES`]. `incident.closure_policy.override`
/// appears in none of them but `super_admin`, which holds every human
/// permission: it must be granted deliberately or not at all.
pub struct FixedBundleResolver;

impl PermissionResolver for FixedBundleResolver {
    fn permissions_for(&self, role: &str) -> Vec<Permission> {
        use Permission::*;
        let with = |base: &Vec<Permission>, more: &[Permission]| {
            let mut v = base.clone();
            v.extend_from_slice(more);
            v
        };
        let viewer = vec![IncidentRead, IncidentList, TrafficRead, MitigationRead];
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
                MitigationRequest,
                MitigationWithdraw,
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
                MitigationApprove,
                MitigationKillSwitchEngage,
            ]);
            v
        };
        // Provider roles read every tenant's records, and say so.
        let reader = with(
            &viewer,
            &[
                IncidentAuditRead,
                IncidentConfigRead,
                PlatformIncidentReadAll,
            ],
        );
        let platform_admin = with(
            &reader,
            &[
                PlatformIncidentAdmin,
                PlatformTenantAdmin,
                TenantTokenAdmin,
                MitigationKillSwitchRelease,
            ],
        );
        let noc_admin = with(&noc_lead, &[PlatformIncidentReadAll]);
        match role {
            "viewer" => viewer,
            "operator" => operator,
            "senior_operator" => senior_operator,
            "noc_lead" => noc_lead,
            "customer_admin" => with(&noc_lead, &[TenantTokenAdmin]),
            "security_analyst" => with(
                &viewer,
                &[IncidentNoteCreate, IncidentExport, IncidentAuditRead],
            ),
            "automation" => with(
                &viewer,
                &[IncidentCreate, IncidentAcknowledge, IncidentNoteCreate],
            ),
            "noc_operator" => with(&senior_operator, &[PlatformIncidentReadAll]),
            "noc_admin" => noc_admin,
            "auditor" => reader,
            "platform_admin" => platform_admin,
            "super_admin" => {
                let mut v = with(
                    &noc_admin,
                    &[IncidentClosurePolicyOverride, IncidentNoteCustomerVisible],
                );
                for permission in platform_admin {
                    if !v.contains(&permission) {
                        v.push(permission);
                    }
                }
                v
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_roles() -> impl Iterator<Item = &'static str> {
        TENANT_ROLES.into_iter().chain(PLATFORM_ROLES)
    }

    fn names(role: &str) -> Vec<&'static str> {
        let mut names: Vec<_> = FixedBundleResolver
            .permissions_for(role)
            .into_iter()
            .map(Permission::name)
            .collect();
        names.sort_unstable();
        names
    }

    /// Every name is the one the security model's permission table uses.
    #[test]
    fn names_match_the_security_model() {
        let document = include_str!("../../../docs/architecture/incident-security-model.md");
        for role in all_roles() {
            for name in names(role) {
                let row = format!("| `{name}` |");
                assert!(document.contains(&row), "the security model lacks {row}");
            }
        }
    }

    /// No v1.0.0 token gains or loses a permission (Phase 8 plan).
    #[test]
    fn the_v1_roles_are_unchanged() {
        let viewer = [
            "incident.list",
            "incident.read",
            "mitigation.read",
            "traffic.read",
        ];
        assert_eq!(names("viewer"), viewer);
        let mut operator = viewer.to_vec();
        operator.extend([
            "incident.acknowledge",
            "incident.assign",
            "incident.investigate",
            "incident.note.create",
        ]);
        operator.sort_unstable();
        assert_eq!(names("operator"), operator);
        let mut senior = operator.clone();
        senior.extend([
            "incident.severity.change",
            "incident.priority.change",
            "incident.resolve",
            "incident.close",
            "incident.reopen",
            "incident.create",
            "mitigation.request",
            "mitigation.withdraw",
        ]);
        senior.sort_unstable();
        assert_eq!(names("senior_operator"), senior);
        let mut lead = senior.clone();
        lead.extend([
            "incident.suppress",
            "incident.export",
            "incident.audit.read",
            "incident.config.read",
            "incident.update",
            "incident.note.redact",
            "mitigation.approve",
            "mitigation.kill_switch.engage",
        ]);
        lead.sort_unstable();
        assert_eq!(names("noc_lead"), lead);
    }

    /// FR-12.2: every role has at least one allow and one deny case.
    #[test]
    fn every_role_has_an_allow_and_a_deny() {
        use Permission::*;
        let cases: [(&str, Permission, Permission); 12] = [
            ("viewer", IncidentRead, IncidentAcknowledge),
            ("operator", IncidentAcknowledge, IncidentClose),
            ("senior_operator", IncidentClose, MitigationApprove),
            ("noc_lead", MitigationApprove, TenantTokenAdmin),
            ("customer_admin", TenantTokenAdmin, PlatformTenantAdmin),
            ("security_analyst", IncidentExport, IncidentAcknowledge),
            ("automation", IncidentCreate, IncidentClose),
            ("noc_operator", PlatformIncidentReadAll, MitigationApprove),
            ("noc_admin", MitigationApprove, PlatformTenantAdmin),
            ("auditor", IncidentAuditRead, IncidentNoteCreate),
            ("platform_admin", PlatformTenantAdmin, IncidentClose),
            ("super_admin", IncidentClosurePolicyOverride, IncidentIngest),
        ];
        assert_eq!(
            cases.iter().map(|case| case.0).collect::<Vec<_>>(),
            all_roles().collect::<Vec<_>>(),
            "one case per role, in order"
        );
        for (role, allowed, denied) in cases {
            let granted = FixedBundleResolver.permissions_for(role);
            assert!(
                granted.contains(&allowed),
                "{role} lacks {}",
                allowed.name()
            );
            assert!(!granted.contains(&denied), "{role} holds {}", denied.name());
        }
    }

    /// A tenant role never reaches across tenants or administers the
    /// platform (BQ-21).
    #[test]
    fn tenant_roles_carry_no_platform_permission() {
        use Permission::*;
        for role in TENANT_ROLES {
            let granted = FixedBundleResolver.permissions_for(role);
            for platform in [
                PlatformIncidentReadAll,
                PlatformIncidentAdmin,
                PlatformTenantAdmin,
                MitigationKillSwitchRelease,
                IncidentClosurePolicyOverride,
            ] {
                assert!(
                    !granted.contains(&platform),
                    "{role} holds {}",
                    platform.name()
                );
            }
        }
        for role in PLATFORM_ROLES {
            assert!(
                FixedBundleResolver
                    .permissions_for(role)
                    .contains(&PlatformIncidentReadAll),
                "{role} reads across tenants, and says so"
            );
        }
    }

    #[test]
    fn super_admin_holds_every_other_bundle() {
        let all = FixedBundleResolver.permissions_for("super_admin");
        for role in all_roles() {
            for permission in FixedBundleResolver.permissions_for(role) {
                assert!(all.contains(&permission), "{role}: {}", permission.name());
            }
        }
    }

    #[test]
    fn closure_policy_override_is_in_no_default_bundle() {
        for role in all_roles().filter(|role| *role != "super_admin") {
            assert!(
                !FixedBundleResolver
                    .permissions_for(role)
                    .contains(&Permission::IncidentClosurePolicyOverride),
                "{role} must not carry the closure-policy override permission"
            );
        }
    }

    #[test]
    fn ingestion_service_account_permission_is_not_in_any_human_bundle() {
        for role in all_roles() {
            assert!(!FixedBundleResolver
                .permissions_for(role)
                .contains(&Permission::IncidentIngest));
        }
    }

    #[test]
    fn only_the_mitigator_proposes_or_executes() {
        for role in all_roles() {
            let granted = FixedBundleResolver.permissions_for(role);
            assert!(!granted.contains(&Permission::MitigationPropose), "{role}");
            assert!(!granted.contains(&Permission::MitigationExecute), "{role}");
        }
        let mitigator = AuthorizationContext::mitigator(TenantId::new("acme"), "m1");
        assert!(mitigator.has(Permission::MitigationExecute));
        assert!(!mitigator.has(Permission::MitigationApprove));
        assert!(!mitigator.has(Permission::MitigationRequest));
    }

    #[test]
    fn approval_starts_at_noc_lead() {
        let resolver = FixedBundleResolver;
        for role in ["viewer", "operator", "senior_operator"] {
            assert!(!resolver
                .permissions_for(role)
                .contains(&Permission::MitigationApprove));
        }
        assert!(resolver
            .permissions_for("noc_lead")
            .contains(&Permission::MitigationApprove));
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
