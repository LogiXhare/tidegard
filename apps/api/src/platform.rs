//! The tenant registry over the API (Phase 8A-3, ADR 0060).
//!
//! - **Platform principals only.** Reading needs `platform.incident.read_all`,
//!   which every provider role holds and no tenant role does; changing needs
//!   `platform.tenant.admin` (`platform_admin`, `super_admin`). A tenant
//!   principal gets `403 api.forbidden`. These endpoints need no
//!   `Tidegard-Tenant` header: they name the tenant in the path.
//! - **Every change is audited in the same transaction** as the change, on
//!   the tenant concerned, so the tenant can read what its provider did
//!   (BQ-21). A change that cannot be audited does not happen.
//! - **The database holds the rules** (V22): an overlapping or too-wide
//!   prefix, a duplicate tenant, `platform` as an id. The errors name the
//!   overlap, which only a platform principal ever sees.

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tidegard_incident::authorization::{Actor, Permission};
use tidegard_incident_postgres::pool::acquire;
use tidegard_incident_postgres::tenants::{self, RegistryError, Tenant, TenantStatus};
use tidegard_mitigation::Prefix;
use tokio_postgres::GenericClient;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::incidents::limit;
use crate::problem::{ErrorCode, Problem};
use crate::AppState;

/// One tenant. `prefixes` is present when one tenant is read.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantView {
    pub tenant_id: String,
    pub display_name: String,
    /// `active` or `suspended`.
    pub status: &'static str,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefixes: Option<Vec<String>>,
}

impl TenantView {
    fn from(tenant: Tenant, prefixes: Option<Vec<Prefix>>) -> Self {
        TenantView {
            tenant_id: tenant.tenant_id,
            display_name: tenant.display_name,
            status: tenant.status.as_str(),
            created_at: tenant.created_at,
            updated_at: tenant.updated_at,
            prefixes: prefixes.map(|all| all.iter().map(Prefix::to_string).collect()),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TenantList {
    pub tenants: Vec<TenantView>,
}

/// A new tenant. Without a display name, it is named by its id.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewTenantBody {
    pub tenant_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrefixBody {
    /// Such as `192.0.2.0/24` or `2001:db8::/32`, with no host bits.
    pub prefix: String,
}

/// A prefix and the tenant it is registered to.
#[derive(Debug, Serialize, ToSchema)]
pub struct PrefixView {
    pub prefix: String,
    pub tenant_id: String,
}

fn require(principal: &Principal, state: &AppState, permission: Permission) -> Result<(), Problem> {
    let auth = principal.authorization(state.resolver.as_ref());
    if auth.has(permission) {
        Ok(())
    } else {
        Err(Problem::new(ErrorCode::Forbidden))
    }
}

/// The API fails closed when the database is unreachable; anything else
/// unexpected is internal.
pub(crate) fn database(error: &tokio_postgres::Error) -> Problem {
    if error.is_closed() || error.as_db_error().is_none() {
        Problem::new(ErrorCode::Unavailable).retry_after(5)
    } else {
        Problem::new(ErrorCode::Internal)
    }
}

impl From<&RegistryError> for Problem {
    fn from(error: &RegistryError) -> Self {
        match error {
            RegistryError::InvalidId
            | RegistryError::InvalidName
            | RegistryError::Prefix(_)
            | RegistryError::TooWide(_) => {
                Problem::new(ErrorCode::TenantInvalid).with_detail(error.to_string())
            }
            RegistryError::Exists(_) => Problem::new(ErrorCode::TenantExists),
            RegistryError::NoSuchTenant(_) => Problem::new(ErrorCode::TenantNotFound),
            RegistryError::Overlaps {
                existing, owner, ..
            } => Problem::new(ErrorCode::PrefixOverlap)
                .with_detail(error.to_string())
                .with("existing", existing.to_string())
                .with("owner", owner.clone()),
            RegistryError::Contended(_) => {
                Problem::new(ErrorCode::PrefixOverlap).with_detail(error.to_string())
            }
            RegistryError::Corrupt(_) => Problem::new(ErrorCode::Internal),
            RegistryError::Database(database_error) => database(database_error),
        }
    }
}

const AUDIT: &str = "\
INSERT INTO incident_audit (
    tenant_id, schema_version, actor_type, actor_id, action, resource_type, resource_id,
    result, request_id, before, after
) VALUES ($1, 1, $2, $3, $4, $5, $6, 'allowed', $7, $8::text::jsonb, $9::text::jsonb)";

/// One allowed change, on `tenant`'s audit trail, inside the caller's
/// transaction.
pub(crate) async fn audit(
    client: &impl GenericClient,
    principal: &Principal,
    tenant: &str,
    action: &str,
    resource: (&str, &str),
    before: Option<Value>,
    after: Option<Value>,
) -> Result<(), Problem> {
    let (actor_type, actor_id) = match &principal.actor {
        Actor::Operator { id } => ("operator", id.as_str()),
        Actor::ServiceAccount { id } => ("service_account", id.as_str()),
        // A token never carries these (ADR 0038).
        Actor::System | Actor::Platform { .. } => return Err(Problem::new(ErrorCode::Internal)),
    };
    let before = before.map(|value| value.to_string());
    let after = after.map(|value| value.to_string());
    client
        .execute(
            AUDIT,
            &[
                &tenant,
                &actor_type,
                &actor_id,
                &action,
                &resource.0,
                &resource.1,
                &crate::request_id::current(),
                &before,
                &after,
            ],
        )
        .await
        .map(|_| ())
        .map_err(|error| database(&error))
}

fn respond<T: Serialize>(status: StatusCode, result: Result<T, Problem>) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Every tenant, by id.
#[utoipa::path(
    get,
    path = "/api/v1/platform/tenants",
    tag = "platform",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Every tenant", body = TenantList),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Not a platform role", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn list_tenants(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        require(&principal, &state, Permission::PlatformIncidentReadAll)?;
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let all = tenants::list(&**client)
            .await
            .map_err(|e| Problem::from(&e))?;
        Ok(TenantList {
            tenants: all
                .into_iter()
                .map(|tenant| TenantView::from(tenant, None))
                .collect(),
        })
    }
    .await;
    respond(StatusCode::OK, result)
}

/// Registers a tenant, active.
#[utoipa::path(
    post,
    path = "/api/v1/platform/tenants",
    tag = "platform",
    request_body = NewTenantBody,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Registered", body = TenantView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks platform.tenant.admin", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "Already registered", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "An invalid id or name", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn create_tenant(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        require(&principal, &state, Permission::PlatformTenantAdmin)?;
        let body: NewTenantBody = crate::body::json(&headers, body)?;
        let name = body.display_name.unwrap_or_else(|| body.tenant_id.clone());
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tx = tokio_postgres::Client::transaction(&mut client)
            .await
            .map_err(|e| database(&e))?;
        let created = tenants::create(&tx, &body.tenant_id, &name)
            .await
            .map_err(|e| Problem::from(&e))?;
        audit(
            &tx,
            &principal,
            &created.tenant_id,
            "tenant.create",
            ("tenant", &created.tenant_id),
            None,
            Some(json!({"display_name": created.display_name, "status": "active"})),
        )
        .await?;
        tx.commit().await.map_err(|e| database(&e))?;
        Ok(TenantView::from(created, Some(Vec::new())))
    }
    .await;
    respond(StatusCode::CREATED, result)
}

/// One tenant, with its prefixes.
#[utoipa::path(
    get,
    path = "/api/v1/platform/tenants/{tenant_id}",
    tag = "platform",
    params(("tenant_id" = String, Path, description = "The tenant")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant", body = TenantView),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Not a platform role", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn get_tenant(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(tenant_id): Path<String>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        require(&principal, &state, Permission::PlatformIncidentReadAll)?;
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tenant = tenants::get(&**client, &tenant_id)
            .await
            .map_err(|e| Problem::from(&e))?
            .ok_or_else(|| Problem::new(ErrorCode::TenantNotFound))?;
        let prefixes = tenants::prefixes(&**client, &tenant_id)
            .await
            .map_err(|e| Problem::from(&e))?;
        Ok(TenantView::from(tenant, Some(prefixes)))
    }
    .await;
    respond(StatusCode::OK, result)
}

async fn set_status(
    state: AppState,
    principal: Principal,
    tenant_id: String,
    status: TenantStatus,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        require(&principal, &state, Permission::PlatformTenantAdmin)?;
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tx = tokio_postgres::Client::transaction(&mut client)
            .await
            .map_err(|e| database(&e))?;
        let before = tenants::get(&tx, &tenant_id)
            .await
            .map_err(|e| Problem::from(&e))?
            .ok_or_else(|| Problem::new(ErrorCode::TenantNotFound))?;
        let after = tenants::set_status(&tx, &tenant_id, status)
            .await
            .map_err(|e| Problem::from(&e))?;
        if before.status != after.status {
            let action = match status {
                TenantStatus::Suspended => "tenant.suspend",
                TenantStatus::Active => "tenant.activate",
            };
            audit(
                &tx,
                &principal,
                &tenant_id,
                action,
                ("tenant", &tenant_id),
                Some(json!({"status": before.status.as_str()})),
                Some(json!({"status": after.status.as_str()})),
            )
            .await?;
        }
        tx.commit().await.map_err(|e| database(&e))?;
        Ok(TenantView::from(after, None))
    }
    .await;
    respond(StatusCode::OK, result)
}

/// Suspends a tenant: its tokens and sessions are refused at once; its
/// data is kept. Suspending a suspended tenant changes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/platform/tenants/{tenant_id}/suspend",
    tag = "platform",
    params(("tenant_id" = String, Path, description = "The tenant")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant as it now is", body = TenantView),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks platform.tenant.admin", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn suspend_tenant(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(tenant_id): Path<String>,
) -> Response {
    set_status(state, principal, tenant_id, TenantStatus::Suspended).await
}

/// Reactivates a suspended tenant.
#[utoipa::path(
    post,
    path = "/api/v1/platform/tenants/{tenant_id}/activate",
    tag = "platform",
    params(("tenant_id" = String, Path, description = "The tenant")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant as it now is", body = TenantView),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks platform.tenant.admin", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn activate_tenant(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(tenant_id): Path<String>,
) -> Response {
    set_status(state, principal, tenant_id, TenantStatus::Active).await
}

/// Registers a prefix to a tenant. Refused if it overlaps any registered
/// prefix, the tenant's own included.
#[utoipa::path(
    post,
    path = "/api/v1/platform/tenants/{tenant_id}/prefixes",
    tag = "platform",
    params(("tenant_id" = String, Path, description = "The tenant")),
    request_body = PrefixBody,
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Registered", body = PrefixView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks platform.tenant.admin", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "Overlaps a registered prefix", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "Malformed, host bits, or too wide", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn add_prefix(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        require(&principal, &state, Permission::PlatformTenantAdmin)?;
        let body: PrefixBody = crate::body::json(&headers, body)?;
        let prefix: Prefix = body
            .prefix
            .parse()
            .map_err(|e| Problem::from(&RegistryError::Prefix(e)))?;
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tx = tokio_postgres::Client::transaction(&mut client)
            .await
            .map_err(|e| database(&e))?;
        tenants::add_prefix(&tx, &tenant_id, prefix)
            .await
            .map_err(|e| Problem::from(&e))?;
        audit(
            &tx,
            &principal,
            &tenant_id,
            "tenant.prefix.add",
            ("tenant_prefix", &prefix.to_string()),
            None,
            Some(json!({"prefix": prefix.to_string()})),
        )
        .await?;
        tx.commit().await.map_err(|e| database(&e))?;
        Ok(PrefixView {
            prefix: prefix.to_string(),
            tenant_id,
        })
    }
    .await;
    respond(StatusCode::CREATED, result)
}

/// Removes a prefix from a tenant. The prefix is two path segments, its
/// address and its length: `.../prefixes/192.0.2.0/24`.
#[utoipa::path(
    delete,
    path = "/api/v1/platform/tenants/{tenant_id}/prefixes/{address}/{length}",
    tag = "platform",
    params(
        ("tenant_id" = String, Path, description = "The tenant"),
        ("address" = String, Path, description = "The prefix's address, such as 192.0.2.0"),
        ("length" = u8, Path, description = "The prefix's length, such as 24"),
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks platform.tenant.admin", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "The tenant has no such prefix", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "Not a prefix", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn remove_prefix(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((tenant_id, address, length)): Path<(String, String, String)>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        require(&principal, &state, Permission::PlatformTenantAdmin)?;
        let prefix: Prefix = format!("{address}/{length}")
            .parse()
            .map_err(|e| Problem::from(&RegistryError::Prefix(e)))?;
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let tx = tokio_postgres::Client::transaction(&mut client)
            .await
            .map_err(|e| database(&e))?;
        if !tenants::remove_prefix(&tx, &tenant_id, prefix)
            .await
            .map_err(|e| Problem::from(&e))?
        {
            return Err(Problem::new(ErrorCode::PrefixNotFound));
        }
        audit(
            &tx,
            &principal,
            &tenant_id,
            "tenant.prefix.remove",
            ("tenant_prefix", &prefix.to_string()),
            Some(json!({"prefix": prefix.to_string()})),
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
