//! Issuing, revoking and listing API tokens (ADR 0038, gate 4).
//!
//! The bootstrap path: `tidegard-api token ...` talks to the database
//! directly, so the first token needs no running API and no prior token.
//! The secret is returned once, by [`create`], and never stored or listed;
//! only its SHA-256 is kept.

use tokio_postgres::GenericClient;

use crate::auth::{generate_token, token_hash, Role, Scope};

/// The longest a token may live; the table enforces the same bound.
pub const MAX_LIFETIME_DAYS: u32 = 366;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorType {
    Operator,
    ServiceAccount,
}

impl ActorType {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorType::Operator => "operator",
            ActorType::ServiceAccount => "service_account",
        }
    }

    pub fn parse(text: &str) -> Option<ActorType> {
        match text {
            "operator" => Some(ActorType::Operator),
            "service_account" => Some(ActorType::ServiceAccount),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToken {
    pub tenant: String,
    pub actor_type: ActorType,
    pub actor_id: String,
    pub role: Role,
    pub lifetime_days: u32,
    pub description: String,
}

/// A created token. `secret` is shown once and exists nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    pub token_id: String,
    pub secret: String,
    pub expires_at: String,
}

/// A token as listed: never its secret or hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSummary {
    pub token_id: String,
    pub actor_type: String,
    pub actor_id: String,
    pub role: String,
    pub description: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

/// A platform token is a provider's key to every tenant (R36), so it lives
/// at most this long; the table enforces the same bound.
pub const MAX_PLATFORM_LIFETIME_DAYS: u32 = 90;

/// A platform token (ADR 0060): one of the provider roles, no tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPlatformToken {
    pub actor_type: ActorType,
    pub actor_id: String,
    pub role: Role,
    pub lifetime_days: u32,
    pub description: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("the lifetime must be 1 to {MAX_LIFETIME_DAYS} days, not {0}")]
    Lifetime(u32),
    #[error("a platform token's lifetime must be 1 to {MAX_PLATFORM_LIFETIME_DAYS} days, not {0}")]
    PlatformLifetime(u32),
    #[error("the operating system's random source failed")]
    Random,
    /// A token names a registered tenant (ADR 0060).
    #[error("no tenant {0:?} is registered")]
    UnknownTenant(String),
    /// A provider role on a tenant token, or a tenant role on a platform
    /// token.
    #[error("{} is a {} role", .0.as_str(), .0.scope().as_str())]
    WrongScope(Role),
    #[error("the automation role is for service accounts only")]
    AutomationIsAService,
    #[error(transparent)]
    Database(#[from] tokio_postgres::Error),
}

const INSERT: &str = "\
INSERT INTO api_tokens (
    token_id, tenant_id, actor_type, actor_id, role, token_hash, description, expires_at, scope
)
VALUES (
    $1::text::uuid, $2, $3, $4, $5, $6, $7,
    transaction_timestamp() + $8::integer * interval '1 day', $9
)
RETURNING expires_at::text AS expires_at";

const REVOKE: &str = "\
UPDATE api_tokens SET revoked_at = transaction_timestamp()
WHERE token_id = $1::text::uuid AND revoked_at IS NULL";

const LIST: &str = "\
SELECT token_id::text AS token_id, actor_type, actor_id, role, description,
       created_at::text AS created_at, expires_at::text AS expires_at,
       revoked_at::text AS revoked_at
FROM api_tokens WHERE tenant_id = $1 ORDER BY created_at";

const LIST_PLATFORM: &str = "\
SELECT token_id::text AS token_id, actor_type, actor_id, role, description,
       created_at::text AS created_at, expires_at::text AS expires_at,
       revoked_at::text AS revoked_at
FROM api_tokens WHERE scope = 'platform' ORDER BY created_at";

/// A tenant token. Refuses a provider role, and a tenant nobody
/// registered.
pub async fn create(
    client: &impl GenericClient,
    new: &NewToken,
) -> Result<IssuedToken, AdminError> {
    if !(1..=MAX_LIFETIME_DAYS).contains(&new.lifetime_days) {
        return Err(AdminError::Lifetime(new.lifetime_days));
    }
    if new.role.scope() != Scope::Tenant {
        return Err(AdminError::WrongScope(new.role));
    }
    insert(
        client,
        Some(&new.tenant),
        new.actor_type,
        &new.actor_id,
        new.role,
        new.lifetime_days,
        &new.description,
    )
    .await
}

/// A platform token: one of the provider roles, at most
/// [`MAX_PLATFORM_LIFETIME_DAYS`] days.
pub async fn create_platform(
    client: &impl GenericClient,
    new: &NewPlatformToken,
) -> Result<IssuedToken, AdminError> {
    if !(1..=MAX_PLATFORM_LIFETIME_DAYS).contains(&new.lifetime_days) {
        return Err(AdminError::PlatformLifetime(new.lifetime_days));
    }
    if new.role.scope() != Scope::Platform {
        return Err(AdminError::WrongScope(new.role));
    }
    insert(
        client,
        None,
        new.actor_type,
        &new.actor_id,
        new.role,
        new.lifetime_days,
        &new.description,
    )
    .await
}

async fn insert(
    client: &impl GenericClient,
    tenant: Option<&str>,
    actor_type: ActorType,
    actor_id: &str,
    role: Role,
    lifetime_days: u32,
    description: &str,
) -> Result<IssuedToken, AdminError> {
    if role == Role::Automation && actor_type != ActorType::ServiceAccount {
        return Err(AdminError::AutomationIsAService);
    }
    let secret = generate_token().map_err(|_| AdminError::Random)?;
    let token_id = crate::request_id::generate();
    let lifetime = i32::try_from(lifetime_days).expect("bounded above");
    let row = client
        .query_one(
            INSERT,
            &[
                &token_id,
                &tenant,
                &actor_type.as_str(),
                &actor_id,
                &role.as_str(),
                &token_hash(&secret),
                &description,
                &lifetime,
                &role.scope().as_str(),
            ],
        )
        .await
        .map_err(|error| match tenant {
            Some(tenant)
                if error.code()
                    == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) =>
            {
                AdminError::UnknownTenant(tenant.to_string())
            }
            _ => AdminError::Database(error),
        })?;
    Ok(IssuedToken {
        token_id,
        secret,
        expires_at: row.get("expires_at"),
    })
}

/// Revokes a live token of `tenant`. `false` for another tenant's token, a
/// platform token, a revoked one, or none (ADR 0060).
pub async fn revoke_in_tenant(
    client: &impl GenericClient,
    tenant: &str,
    token_id: &str,
) -> Result<bool, AdminError> {
    Ok(client
        .execute(REVOKE_IN_TENANT, &[&token_id, &tenant])
        .await?
        == 1)
}

const REVOKE_IN_TENANT: &str = "\
UPDATE api_tokens SET revoked_at = transaction_timestamp()
WHERE token_id = $1::text::uuid AND tenant_id = $2 AND revoked_at IS NULL";

/// `false` if no live token has this id.
pub async fn revoke(client: &impl GenericClient, token_id: &str) -> Result<bool, AdminError> {
    Ok(client.execute(REVOKE, &[&token_id]).await? == 1)
}

pub async fn list(
    client: &impl GenericClient,
    tenant: &str,
) -> Result<Vec<TokenSummary>, AdminError> {
    summaries(client.query(LIST, &[&tenant]).await?)
}

/// Every platform token, live or not.
pub async fn list_platform(client: &impl GenericClient) -> Result<Vec<TokenSummary>, AdminError> {
    summaries(client.query(LIST_PLATFORM, &[]).await?)
}

fn summaries(rows: Vec<tokio_postgres::Row>) -> Result<Vec<TokenSummary>, AdminError> {
    Ok(rows
        .iter()
        .map(|row| TokenSummary {
            token_id: row.get("token_id"),
            actor_type: row.get("actor_type"),
            actor_id: row.get("actor_id"),
            role: row.get("role"),
            description: row.get("description"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            revoked_at: row.get("revoked_at"),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_types_round_trip_and_nothing_else_parses() {
        for actor in [ActorType::Operator, ActorType::ServiceAccount] {
            assert_eq!(ActorType::parse(actor.as_str()), Some(actor));
        }
        assert_eq!(ActorType::parse("platform"), None);
        assert_eq!(ActorType::parse("system"), None);
    }
}
