//! The explicitly authorized path for cross-tenant maintenance
//! (ADR 0032, decision item 7).
//!
//! Every incident read and write in this crate is tenant-scoped. The
//! service takes its tenant from the caller's `AuthorizationContext`, and
//! the SQL functions take either a tenant or a correlation key that carries
//! one.
//!
//! Two operations span every tenant by nature: consuming the outbox, and
//! running retention. Both require a [`PlatformAuthority`]. Only a context
//! holding [`Permission::PlatformIncidentAdmin`] can produce one, and no
//! tenant role bundle grants that permission. A cross-tenant path therefore
//! cannot be reached by accident with an ordinary operator's context.
//!
//! These operations are not audited yet, because the audit table has no
//! actor type for a platform actor (FU-48).

use tidegard_incident::authorization::{Actor, AuthorizationContext, Permission};
use tidegard_incident::error::IncidentError;

/// Proof that the caller was authorized for cross-tenant maintenance.
#[derive(Debug, Clone)]
pub struct PlatformAuthority {
    actor: Actor,
}

impl PlatformAuthority {
    /// `Unauthorized` unless `auth` holds `PlatformIncidentAdmin`.
    pub fn from_context(auth: &AuthorizationContext) -> Result<Self, IncidentError> {
        if auth.has(Permission::PlatformIncidentAdmin) {
            Ok(PlatformAuthority {
                actor: auth.actor().clone(),
            })
        } else {
            Err(IncidentError::Unauthorized)
        }
    }

    /// Who was authorized.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }
}

#[cfg(test)]
mod tests {
    use tidegard_incident::authorization::{FixedBundleResolver, PermissionResolver};
    use tidegard_incident::correlation::TenantId;

    use super::*;

    fn context(role: &str) -> AuthorizationContext {
        AuthorizationContext::new(
            TenantId::new("acme"),
            Actor::Operator {
                id: "op-1".to_string(),
            },
            FixedBundleResolver.permissions_for(role),
        )
    }

    #[test]
    fn only_a_platform_admin_context_grants_platform_authority() {
        let authority = PlatformAuthority::from_context(&context("platform_admin")).unwrap();
        assert_eq!(
            authority.actor(),
            &Actor::Operator {
                id: "op-1".to_string()
            }
        );
        for role in [
            "viewer",
            "operator",
            "senior_operator",
            "noc_lead",
            "no_such_role",
        ] {
            assert_eq!(
                PlatformAuthority::from_context(&context(role)).unwrap_err(),
                IncidentError::Unauthorized,
                "{role} must not grant platform authority"
            );
        }
        assert!(
            PlatformAuthority::from_context(&AuthorizationContext::correlator(TenantId::new(
                "acme"
            )))
            .is_err()
        );
    }
}
