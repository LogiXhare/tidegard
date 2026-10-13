//! The incident endpoints (Milestone 5D), under `/api/v1`.
//!
//! Every handler follows the same shape:
//!
//! 1. The principal comes from the auth middleware, never the request.
//! 2. The actor is rate-limited for the surface (ADR 0038, gate 6).
//! 3. The domain or the read service decides. The handler never checks a
//!    permission itself (gate 5).
//! 4. The result is rendered, or mapped to problem details. Another
//!    tenant's incident is `404 incident.not_found`, the same as one that
//!    does not exist.
//!
//! The representation follows [docs/api/incident-api-plan.md](../../../docs/api/incident-api-plan.md),
//! built from the persistence row mapping so the API and the database use
//! one vocabulary.

use std::collections::BTreeMap;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Serialize;
use tidegard_incident::id::IncidentId;
use tidegard_incident::incident::Incident;
use tidegard_incident_postgres::pool::acquire;
use tidegard_incident_postgres::queries;
use tidegard_incident_postgres::row::{ActorColumns, IncidentRow};
use tidegard_incident_postgres::status;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::problem::{ErrorCode, Problem};
use crate::rate_limit::{Quota, RateLimiter};
use crate::time::rfc3339;
use crate::AppState;

/// Per-actor limits from the security model (ADR 0038, gate 6).
pub const READ_QUOTA: Quota = Quota::per_minute(120);
pub const MUTATION_QUOTA: Quota = Quota::per_minute(60);
pub const AUDIT_QUOTA: Quota = Quota::per_minute(30);
/// Exports read an incident's whole history, so they get the tightest.
pub const EXPORT_QUOTA: Quota = Quota::per_minute(10);
/// Actors tracked per surface at once.
const MAX_ACTORS: usize = 100_000;

/// One limiter per surface, keyed by tenant and actor.
pub struct Limits {
    pub reads: RateLimiter<(String, String)>,
    pub mutations: RateLimiter<(String, String)>,
    pub audit: RateLimiter<(String, String)>,
    pub exports: RateLimiter<(String, String)>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            reads: RateLimiter::new(READ_QUOTA, MAX_ACTORS),
            mutations: RateLimiter::new(MUTATION_QUOTA, MAX_ACTORS),
            audit: RateLimiter::new(AUDIT_QUOTA, MAX_ACTORS),
            exports: RateLimiter::new(EXPORT_QUOTA, MAX_ACTORS),
        }
    }
}

/// Counts one request against `limiter`, or the `429` to return.
pub fn limit(
    limiter: &RateLimiter<(String, String)>,
    principal: &Principal,
) -> Result<(), Problem> {
    let key = (
        principal.tenant.as_str().to_string(),
        actor_text(&principal.actor),
    );
    limiter.check(&key, Instant::now()).map_err(|refusal| {
        Problem::new(ErrorCode::RateLimited).retry_after(refusal.retry_after_secs())
    })
}

/// How an actor is shown to people, as in every API response.
pub fn actor_label(actor: &tidegard_incident::authorization::Actor) -> String {
    actor_text(actor)
}

pub(crate) fn actor_text(actor: &tidegard_incident::authorization::Actor) -> String {
    use tidegard_incident::authorization::Actor;
    match actor {
        Actor::Operator { id } => id.clone(),
        Actor::ServiceAccount { id } => format!("service_account:{id}"),
        Actor::System => "system:correlator".to_string(),
        Actor::Platform { id } => format!("platform:{id}"),
    }
}

fn columns_text(columns: &ActorColumns) -> String {
    match (columns.actor_type.as_str(), &columns.actor_id) {
        ("operator", Some(id)) => id.clone(),
        ("system", _) => "system:correlator".to_string(),
        (kind, Some(id)) => format!("{kind}:{id}"),
        (kind, None) => kind.to_string(),
    }
}

/// An active suppression.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SuppressionView {
    pub until: String,
    pub reason: String,
    pub by: String,
}

/// A detection policy that contributed to the incident.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyRefView {
    pub policy_id: String,
    pub policy_version: i32,
}

/// One incident, as `GET /api/v1/incidents/{id}` returns it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IncidentView {
    pub incident_id: String,
    /// Per tenant and year, for example `WNM-2026-000123`.
    pub incident_number: String,
    pub schema_version: i32,
    pub tenant_id: String,
    pub title: String,
    pub description: Option<String>,
    /// open, acknowledged, investigating, monitoring, recovering, resolved, closed.
    pub state: String,
    /// info, minor, major, critical.
    pub severity: String,
    pub severity_source: String,
    pub maximum_detected_severity: String,
    /// P1 to P4.
    pub priority: String,
    pub category: String,
    /// incoming, outgoing, internal.
    pub direction: String,
    /// 4 or 6.
    pub address_family: i16,
    /// host, network, hostgroup.
    pub target_type: String,
    pub target_id: String,
    pub correlation_key: String,
    pub first_detected_at: String,
    pub opened_at: String,
    pub last_detected_at: String,
    pub last_updated_at: String,
    pub acknowledged_at: Option<String>,
    pub recovering_since: Option<String>,
    pub resolved_at: Option<String>,
    pub closed_at: Option<String>,
    pub reopened_at: Option<String>,
    pub reopen_count: i32,
    pub assigned_user_id: Option<String>,
    pub assigned_team_id: Option<String>,
    pub suppression: Option<SuppressionView>,
    pub closure_reason: Option<String>,
    pub policy_refs: Vec<PolicyRefView>,
    /// Linked events whose policy was not recorded because the list is full.
    pub policy_refs_omitted: i64,
    pub tags: BTreeMap<String, String>,
    /// The incident's most live mitigation, or else the one that ended
    /// last: `none`, `pending_approval`, `approved`, `active`, `dry_run`,
    /// `withdrawing`, `withdrawn`, `rejected`, `expired` or `failed`
    /// (FU-64).
    pub mitigation_status: String,
    /// Each channel's latest outcome: `none`, `delivered` (every
    /// channel), `partial`, or `failed` (none delivered) (FU-64).
    pub notification_status: String,
    /// For `expected_version` on transitions.
    pub version: i64,
    pub created_by: String,
    pub updated_by: String,
}

impl IncidentView {
    pub fn from_incident(incident: &Incident) -> Result<Self, Problem> {
        let row = IncidentRow::from_incident(incident).map_err(|error| Problem::from(&error))?;
        let (assigned_user_id, assigned_team_id) =
            match (row.assigned_kind.as_deref(), row.assigned_id.clone()) {
                (Some("user"), id) => (id, None),
                (Some("team"), id) => (None, id),
                _ => (None, None),
            };
        let target_id = row
            .target_addr
            .clone()
            .or_else(|| row.target_network.clone())
            .or_else(|| row.target_hostgroup.clone())
            .unwrap_or_default();
        Ok(IncidentView {
            incident_id: row.incident_id,
            incident_number: row.incident_number,
            schema_version: row.schema_version,
            tenant_id: row.tenant_id,
            title: row.title,
            description: row.description,
            state: row.state,
            severity: row.severity,
            severity_source: row.severity_source,
            maximum_detected_severity: row.maximum_detected_severity,
            priority: row.priority,
            category: row.category,
            direction: row.direction,
            address_family: row.address_family,
            target_type: row.target_type,
            target_id,
            correlation_key: row.correlation_key,
            first_detected_at: rfc3339(row.first_detected_at),
            opened_at: rfc3339(row.opened_at),
            last_detected_at: rfc3339(row.last_detected_at),
            last_updated_at: rfc3339(row.last_updated_at),
            acknowledged_at: row.acknowledged_at.map(rfc3339),
            recovering_since: row.recovering_since.map(rfc3339),
            resolved_at: row.resolved_at.map(rfc3339),
            closed_at: row.closed_at.map(rfc3339),
            reopened_at: row.reopened_at.map(rfc3339),
            reopen_count: row.reopen_count,
            assigned_user_id,
            assigned_team_id,
            suppression: row.suppression.map(|s| SuppressionView {
                until: rfc3339(s.until),
                reason: s.reason,
                by: columns_text(&s.by),
            }),
            closure_reason: row.closure_reason,
            policy_refs: row
                .policy_refs
                .into_iter()
                .map(|r| PolicyRefView {
                    policy_id: r.policy_id,
                    policy_version: r.policy_version,
                })
                .collect(),
            policy_refs_omitted: row.policy_refs_omitted,
            tags: row.tags.into_iter().collect(),
            mitigation_status: "none".to_string(),
            notification_status: "none".to_string(),
            version: row.version,
            created_by: columns_text(&row.created_by),
            updated_by: columns_text(&row.updated_by),
        })
    }
}

impl IncidentView {
    /// Fills in the mitigation and notification status from the records
    /// (FU-64), within the incident's own tenant.
    pub async fn with_statuses(
        mut self,
        client: &impl tokio_postgres::GenericClient,
    ) -> Result<Self, Problem> {
        let tenant = tidegard_incident::correlation::TenantId::new(self.tenant_id.clone());
        self.mitigation_status =
            status::incident_mitigation_status(client, &tenant, &self.incident_id)
                .await
                .map_err(|error| Problem::from(&error))?
                .to_string();
        self.notification_status =
            status::incident_notification_status(client, &tenant, &self.incident_id)
                .await
                .map_err(|error| Problem::from(&error))?
                .to_string();
        Ok(self)
    }
}

/// Parses an incident id path segment: a malformed id is `400` and never
/// reaches the database.
pub fn parse_id(text: &str) -> Result<IncidentId, Problem> {
    IncidentId::parse(text).map_err(|_| {
        Problem::new(ErrorCode::InvalidRequest).with_detail("the incident id is not a UUID")
    })
}

/// One incident.
#[utoipa::path(
    get,
    path = "/api/v1/incidents/{incident_id}",
    tag = "incidents",
    params(("incident_id" = String, Path, description = "The incident's UUID")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The incident", body = IncidentView),
        (status = 400, description = "The id is not a UUID", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn get_incident(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(incident_id): Path<String>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let id = parse_id(&incident_id)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool)
            .await
            .map_err(|error| Problem::from(&error))?;
        let incident = queries::get_incident(&mut client, &auth, &id)
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        IncidentView::from_incident(&incident)?
            .with_statuses(&**client)
            .await
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}
