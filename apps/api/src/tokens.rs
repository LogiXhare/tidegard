//! A tenant's API tokens over the API (Phase 8A-3, ADR 0060).
//!
//! - **`tenant.token.admin`** is needed to list, issue or revoke, in the
//!   tenant acted in: `customer_admin` in its own tenant, `platform_admin`
//!   and `super_admin` in the tenant they name.
//! - **No escalation.** A tenant principal may issue only a role whose
//!   every permission it holds itself. A platform principal may issue any
//!   tenant role, which is how a provider onboards a customer's first
//!   `customer_admin`.
//! - **Tenant tokens only.** A platform token is issued on the host
//!   (`tidegard-api token create --platform`), never over the API.
//! - **Audited in the same transaction**, on the tenant's audit trail. The
//!   secret is returned once and is in no audit record.

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tidegard_incident::authorization::Permission;
use tidegard_incident_postgres::pool::acquire;
use utoipa::ToSchema;

use crate::auth::{Principal, Role, Scope};
use crate::incidents::limit;
use crate::platform::{audit, database};
use crate::problem::{ErrorCode, Problem};
use crate::token_admin::{self, ActorType, AdminError, NewToken, TokenSummary};
use crate::AppState;

/// A token as listed: never its secret.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenView {
    pub token_id: String,
    /// operator or service_account.
    pub actor_type: String,
    pub actor_id: String,
    pub role: String,
    pub description: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

impl From<TokenSummary> for TokenView {
    fn from(token: TokenSummary) -> Self {
        TokenView {
            token_id: token.token_id,
            actor_type: token.actor_type,
            actor_id: token.actor_id,
            role: token.role,
            description: token.description,
            created_at: token.created_at,
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenList {
    pub tokens: Vec<TokenView>,
}

/// A new token in the tenant acted in.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewTokenBody {
    pub actor_id: String,
    /// A tenant role.
    pub role: String,
    /// operator (the default) or service_account.
    #[serde(default)]
    pub actor_type: Option<String>,
    /// 1 to 366; 90 when absent.
    #[serde(default)]
    pub lifetime_days: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
}

/// An issued token. `token` is shown once, here, and exists nowhere else.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssuedTokenView {
    pub token_id: String,
    pub token: String,
    pub expires_at: String,
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(ErrorCode::TokenInvalid).with_detail(detail)
}

impl From<&AdminError> for Problem {
    fn from(error: &AdminError) -> Self {
        match error {
            AdminError::Lifetime(_)
            | AdminError::PlatformLifetime(_)
            | AdminError::WrongScope(_)
            | AdminError::AutomationIsAService => invalid(error.to_string()),
            AdminError::UnknownTenant(_) => Problem::new(ErrorCode::TenantNotFound),
            AdminError::Random => Problem::new(ErrorCode::Internal),
            AdminError::Database(database_error) => database(database_error),
        }
    }
}

fn require_admin(principal: &Principal, state: &AppState) -> Result<(), Problem> {
    let auth = principal.authorization(state.resolver.as_ref());
    if auth.has(Permission::TenantTokenAdmin) {
        Ok(())
    } else {
        Err(Problem::new(ErrorCode::Forbidden))
    }
}

/// Whether `principal` may hand out `role`: a platform principal any tenant
/// role, a tenant principal only one it could not gain anything from.
fn may_issue(principal: &Principal, state: &AppState, role: Role) -> bool {
    if principal.role.scope() == Scope::Platform {
        return true;
    }
    let held = state.resolver.permissions_for(principal.role.as_str());
    state
        .resolver
        .permissions_for(role.as_str())
        .iter()
        .all(|permission| held.contains(permission))
}

fn respond<T: Serialize>(status: StatusCode, result: Result<T, Problem>) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// The tenant's tokens, live and not. Never a secret.
#[utoipa::path(
    get,
    path = "/api/v1/tokens",
    tag = "tokens",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant's tokens", body = TokenList),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks tenant.token.admin", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn list_tokens(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        require_admin(&principal, &state)?;
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tokens = token_admin::list(&**client, principal.tenant.as_str())
            .await
            .map_err(|e| Problem::from(&e))?;
        Ok(TokenList {
            tokens: tokens.into_iter().map(TokenView::from).collect(),
        })
    }
    .await;
    respond(StatusCode::OK, result)
}

/// Issues a token in the tenant acted in. The secret is in this answer
/// only.
#[utoipa::path(
    post,
    path = "/api/v1/tokens",
    tag = "tokens",
    request_body = NewTokenBody,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Issued; the secret is shown once", body = IssuedTokenView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks tenant.token.admin, or the role has a permission the caller lacks", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "An unknown role, a platform role, a lifetime out of range, or automation for a person", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn create_token(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        require_admin(&principal, &state)?;
        let body: NewTokenBody = crate::body::json(&headers, body)?;
        let role = Role::parse(&body.role).ok_or_else(|| invalid("unknown role"))?;
        if role.scope() != Scope::Tenant {
            return Err(invalid("a platform token is issued on the host only"));
        }
        if !may_issue(&principal, &state, role) {
            return Err(Problem::new(ErrorCode::Forbidden)
                .with_detail("the role holds a permission the caller does not"));
        }
        let actor_type = match body.actor_type.as_deref() {
            None => ActorType::Operator,
            Some(text) => ActorType::parse(text)
                .ok_or_else(|| invalid("actor_type is operator or service_account"))?,
        };
        if !(1..=128).contains(&body.actor_id.chars().count()) {
            return Err(invalid("actor_id is 1 to 128 characters"));
        }
        let description = body.description.unwrap_or_default();
        if description.chars().count() > 200 {
            return Err(invalid("description is at most 200 characters"));
        }
        let new = NewToken {
            tenant: principal.tenant.as_str().to_string(),
            actor_type,
            actor_id: body.actor_id,
            role,
            lifetime_days: body.lifetime_days.unwrap_or(90),
            description,
        };
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tx = tokio_postgres::Client::transaction(&mut client)
            .await
            .map_err(|e| database(&e))?;
        let issued = token_admin::create(&tx, &new)
            .await
            .map_err(|e| Problem::from(&e))?;
        audit(
            &tx,
            &principal,
            &new.tenant,
            "token.create",
            ("api_token", &issued.token_id),
            None,
            Some(json!({
                "actor_type": new.actor_type.as_str(),
                "actor_id": new.actor_id,
                "role": new.role.as_str(),
                "expires_at": issued.expires_at,
            })),
        )
        .await?;
        tx.commit().await.map_err(|e| database(&e))?;
        Ok(IssuedTokenView {
            token_id: issued.token_id,
            token: issued.secret,
            expires_at: issued.expires_at,
        })
    }
    .await;
    respond(StatusCode::CREATED, result)
}

/// Revokes a live token of the tenant acted in. Its sessions end with it.
#[utoipa::path(
    post,
    path = "/api/v1/tokens/{token_id}/revoke",
    tag = "tokens",
    params(("token_id" = String, Path, description = "The token's id")),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks tenant.token.admin", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No live token with this id in the tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn revoke_token(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(token_id): Path<String>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        require_admin(&principal, &state)?;
        // Another tenant's token, a platform token, a revoked one and an id
        // that is not a UUID are all the same 404.
        if uuid::Uuid::parse_str(&token_id).is_err() {
            return Err(Problem::new(ErrorCode::TokenNotFound));
        }
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tx = tokio_postgres::Client::transaction(&mut client)
            .await
            .map_err(|e| database(&e))?;
        if !token_admin::revoke_in_tenant(&tx, principal.tenant.as_str(), &token_id)
            .await
            .map_err(|e| Problem::from(&e))?
        {
            return Err(Problem::new(ErrorCode::TokenNotFound));
        }
        audit(
            &tx,
            &principal,
            principal.tenant.as_str(),
            "token.revoke",
            ("api_token", &token_id),
            None,
            None,
        )
        .await?;
        tx.commit().await.map_err(|e| database(&e))?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(problem) => problem.into_response(),
    }
}
