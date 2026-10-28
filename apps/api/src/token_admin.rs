//! Issuing, revoking and listing API tokens (ADR 0038, gate 4).
//!
//! The bootstrap path: `tidegard-api token ...` talks to the database
//! directly, so the first token needs no running API and no prior token.
//! The secret is returned once, by [`create`], and never stored or listed;
//! only its SHA-256 is kept.

use tokio_postgres::GenericClient;

use crate::auth::{generate_token, token_hash, Role};

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

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("the lifetime must be 1 to {MAX_LIFETIME_DAYS} days, not {0}")]
    Lifetime(u32),
    #[error("the operating system's random source failed")]
    Random,
    /// A token names a registered tenant (ADR 0060).
    #[error("no tenant {0:?} is registered")]
    UnknownTenant(String),
    #[error(transparent)]
    Database(#[from] tokio_postgres::Error),
}

const INSERT: &str = "\
INSERT INTO api_tokens (
    token_id, tenant_id, actor_type, actor_id, role, token_hash, description, expires_at
)
VALUES (
    $1::text::uuid, $2, $3, $4, $5, $6, $7,
    transaction_timestamp() + $8::integer * interval '1 day'
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

pub async fn create(
    client: &impl GenericClient,
    new: &NewToken,
) -> Result<IssuedToken, AdminError> {
    if !(1..=MAX_LIFETIME_DAYS).contains(&new.lifetime_days) {
        return Err(AdminError::Lifetime(new.lifetime_days));
    }
    let secret = generate_token().map_err(|_| AdminError::Random)?;
    let token_id = crate::request_id::generate();
    let lifetime = i32::try_from(new.lifetime_days).expect("bounded above");
    let row = client
        .query_one(
            INSERT,
            &[
                &token_id,
                &new.tenant,
                &new.actor_type.as_str(),
                &new.actor_id,
                &new.role.as_str(),
                &token_hash(&secret),
                &new.description,
                &lifetime,
            ],
        )
        .await
        .map_err(|error| {
            if error.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION) {
                AdminError::UnknownTenant(new.tenant.clone())
            } else {
                AdminError::Database(error)
            }
        })?;
    Ok(IssuedToken {
        token_id,
        secret,
        expires_at: row.get("expires_at"),
    })
}

/// `false` if no live token has this id.
pub async fn revoke(client: &impl GenericClient, token_id: &str) -> Result<bool, AdminError> {
    Ok(client.execute(REVOKE, &[&token_id]).await? == 1)
}

pub async fn list(
    client: &impl GenericClient,
    tenant: &str,
) -> Result<Vec<TokenSummary>, AdminError> {
    Ok(client
        .query(LIST, &[&tenant])
        .await?
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
