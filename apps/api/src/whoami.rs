//! `GET /api/v1/whoami`: who the bearer token says the caller is (5E-3).
//!
//! The CLI's `claim` assigns an incident to the caller and needs the
//! caller's id. Any valid token may ask; the answer is only what the token
//! already carries, never another principal's.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Serialize;
use tidegard_incident::authorization::Actor;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::incidents::limit;
use crate::AppState;

/// The caller, as its token identifies it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WhoAmI {
    pub tenant_id: String,
    /// operator or service_account.
    pub actor_type: &'static str,
    pub actor_id: String,
    /// viewer, operator, senior_operator or noc_lead.
    pub role: &'static str,
    /// What the role grants, such as `incident.read`.
    pub permissions: Vec<&'static str>,
}

/// The caller's identity and permissions.
#[utoipa::path(
    get,
    path = "/api/v1/whoami",
    tag = "identity",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The caller", body = WhoAmI),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn whoami(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Err(problem) = limit(&state.limits.reads, &principal) {
        return problem.into_response();
    }
    let (actor_type, actor_id) = match &principal.actor {
        Actor::Operator { id } => ("operator", id.clone()),
        Actor::ServiceAccount { id } => ("service_account", id.clone()),
        // A token never carries these (ADR 0038); answer without inventing one.
        Actor::System => ("system", String::new()),
        Actor::Platform { id } => ("platform", id.clone()),
    };
    let mut permissions: Vec<&'static str> = state
        .resolver
        .permissions_for(principal.role.as_str())
        .into_iter()
        .map(|permission| permission.name())
        .collect();
    permissions.sort_unstable();
    Json(WhoAmI {
        tenant_id: principal.tenant.as_str().to_string(),
        actor_type,
        actor_id,
        role: principal.role.as_str(),
        permissions,
    })
    .into_response()
}
