//! Mitigations, the kill switch and BGP status (Phase 7E, ADR 0050).
//!
//! The API records and decides; it never speaks to GoBGP. The mitigator
//! (ADR 0049) announces what is approved. So:
//!
//! - **Requesting** checks the request and the safety guard, and stores a
//!   `requested` mitigation. `Idempotency-Key` is required.
//! - **Approving, rejecting and withdrawing** carry `expected_version`, as
//!   incident transitions do.
//! - **Another tenant's mitigation does not exist:** `404
//!   mitigation.not_found`, the same as for an id nobody has.
//! - **The kill switch and BGP peers are deployment-wide** (FU-65).
//!
//! The guard here is the one the API was started with
//! (`TIDEGARD_API_MITIGATION_GUARD_FILE`). Without one, nothing is
//! allowlisted and every request is refused: the safe default.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use tidegard_incident_postgres::mitigation::{
    HistoryEntry, KillSwitch, ListFilter, MitigationDetail, PeerStatus,
};
use tidegard_incident_postgres::pool::acquire;
use tidegard_mitigation::{Action, ActionKind, FlowMatch, MitigationId, MitigationRequest};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::incidents::{actor_text, limit};
use crate::problem::{ErrorCode, Problem};
use crate::time::rfc3339;
use crate::AppState;

/// The most mitigations one list returns.
pub const MAX_LIST: u32 = 500;
const DEFAULT_LIST: u32 = 100;

/// What a FlowSpec rule matches beyond the destination.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FlowView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
}

/// One mitigation.
#[derive(Debug, Serialize, ToSchema)]
pub struct MitigationView {
    pub mitigation_id: String,
    pub tenant_id: String,
    pub incident_id: Option<String>,
    pub prefix: String,
    /// `rtbh`, `parent_prefix`, `flowspec_discard` or `flowspec_rate_limit`.
    pub action: String,
    pub flow: Option<FlowView>,
    pub bytes_per_second: Option<u64>,
    pub reason: String,
    pub duration_seconds: u64,
    /// `proposed`, `requested`, `approved`, `announcing`, `active`,
    /// `withdrawing`, `withdrawn`, `rejected`, `expired` or `failed`.
    pub state: String,
    /// For `expected_version`.
    pub version: u64,
    pub requested_by: String,
    pub approved_by: Option<String>,
    /// Whether the mitigator was in dry-run when announcing began.
    pub dry_run: Option<bool>,
    /// `operator`, `duration_reached` or `kill_switch`.
    pub withdrawal_cause: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub approved_at: Option<String>,
    pub active_since: Option<String>,
    pub expires_at: Option<String>,
    pub ended_at: Option<String>,
    /// The route recorded when announcing began.
    #[schema(value_type = Option<Object>)]
    pub route: Option<serde_json::Value>,
}

impl MitigationView {
    fn from_detail(detail: MitigationDetail) -> Self {
        let r = detail.record;
        let flow = r.action.flow().map(|f| FlowView {
            protocol: f.protocol,
            source: f.source.map(|p| p.to_string()),
            source_port: f.source_port,
            destination_port: f.destination_port,
        });
        MitigationView {
            mitigation_id: r.id.to_string(),
            tenant_id: r.tenant.as_str().to_string(),
            incident_id: r.incident_id,
            prefix: r.prefix.to_string(),
            action: r.action.kind().as_str().to_string(),
            flow,
            bytes_per_second: r.action.bytes_per_second(),
            reason: r.reason,
            duration_seconds: r.duration.as_secs(),
            state: r.state.as_str().to_string(),
            version: r.version,
            requested_by: actor_text(&r.requested_by),
            approved_by: r.approved_by.as_ref().map(actor_text),
            dry_run: r.dry_run,
            withdrawal_cause: r.withdrawal.map(|c| c.as_str().to_string()),
            last_error: r.last_error,
            created_at: rfc3339(detail.created_at_us),
            updated_at: rfc3339(detail.updated_at_us),
            approved_at: detail.approved_at_us.map(rfc3339),
            active_since: detail.active_since_us.map(rfc3339),
            expires_at: detail.expires_at_us.map(rfc3339),
            ended_at: detail.ended_at_us.map(rfc3339),
            route: detail
                .route
                .and_then(|text| serde_json::from_str(&text).ok()),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MitigationList {
    pub items: Vec<MitigationView>,
}

/// One state change.
#[derive(Debug, Serialize, ToSchema)]
pub struct MitigationHistoryEntry {
    pub version: u64,
    pub occurred_at: String,
    pub from_state: Option<String>,
    pub to_state: String,
    pub actor: String,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MitigationHistory {
    pub items: Vec<MitigationHistoryEntry>,
}

impl From<HistoryEntry> for MitigationHistoryEntry {
    fn from(entry: HistoryEntry) -> Self {
        MitigationHistoryEntry {
            version: entry.version,
            occurred_at: rfc3339(entry.occurred_at_us),
            from_state: entry.from_state,
            to_state: entry.to_state,
            actor: actor_text(&entry.actor),
            detail: entry.detail,
        }
    }
}

/// A request for a mitigation. Route attributes are not here: they are
/// the deployment's (ADR 0046).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MitigationRequestBody {
    /// A canonical prefix, such as `192.0.2.10/32`.
    pub prefix: String,
    pub action: String,
    #[serde(default)]
    pub flow: Option<FlowView>,
    #[serde(default)]
    pub bytes_per_second: Option<u64>,
    pub reason: String,
    pub duration_seconds: u64,
    #[serde(default)]
    pub incident_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveBody {
    pub expected_version: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReasonBody {
    pub expected_version: u64,
    pub reason: String,
}

/// The deployment-wide kill switch.
#[derive(Debug, Serialize, ToSchema)]
pub struct KillSwitchView {
    pub engaged: bool,
    pub version: u64,
    pub changed_at: Option<String>,
    pub changed_by: Option<String>,
    pub reason: Option<String>,
}

impl From<KillSwitch> for KillSwitchView {
    fn from(k: KillSwitch) -> Self {
        KillSwitchView {
            engaged: k.engaged,
            version: k.version,
            changed_at: k.changed_at,
            changed_by: k.changed_by.as_ref().map(actor_text),
            reason: k.reason,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchBody {
    pub engaged: bool,
    pub reason: String,
}

/// A route the tenant's mitigations have in GoBGP.
#[derive(Debug, Serialize, ToSchema)]
pub struct BgpRoute {
    pub mitigation_id: String,
    pub state: String,
    pub prefix: String,
    pub action: String,
    #[schema(value_type = Option<Object>)]
    pub route: Option<serde_json::Value>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BgpRouteList {
    pub items: Vec<BgpRoute>,
}

/// One of GoBGP's peers, as the mitigator last saw it.
#[derive(Debug, Serialize, ToSchema)]
pub struct BgpPeer {
    pub neighbor_address: String,
    pub peer_asn: u32,
    pub session_state: String,
    /// When the mitigator last saw it. An old time means the mitigator has
    /// stopped, not that the session is still up.
    pub updated_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BgpPeerList {
    pub items: Vec<BgpPeer>,
}

/// The context of `tidegard-api kill-switch ...` on the API host:
/// break-glass, with database access. It may turn the kill switch either
/// way, and nothing else. API tokens never carry the release permission
/// (ADR 0050).
pub fn host_admin_context(
    actor_id: &str,
) -> tidegard_incident::authorization::AuthorizationContext {
    use tidegard_incident::authorization::{Actor, AuthorizationContext, Permission};
    AuthorizationContext::new(
        tidegard_incident::correlation::TenantId::new("platform"),
        Actor::Operator {
            id: actor_id.to_string(),
        },
        vec![
            Permission::MitigationKillSwitchEngage,
            Permission::MitigationKillSwitchRelease,
        ],
    )
}

fn parse_mitigation_id(text: &str) -> Result<MitigationId, Problem> {
    MitigationId::parse(text).map_err(|_| {
        Problem::new(ErrorCode::InvalidRequest).with_detail("the mitigation id is not a UUID")
    })
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(ErrorCode::MitigationInvalid).with_detail(detail)
}

fn request_from(body: MitigationRequestBody) -> Result<MitigationRequest, Problem> {
    let prefix = body
        .prefix
        .parse()
        .map_err(|e| invalid(format!("prefix: {e}")))?;
    let kind = ActionKind::parse(&body.action).ok_or_else(|| {
        invalid("action must be rtbh, parent_prefix, flowspec_discard or flowspec_rate_limit")
    })?;
    let flow = body
        .flow
        .map(|f| {
            Ok::<_, Problem>(FlowMatch {
                protocol: f.protocol,
                source: f
                    .source
                    .map(|s| s.parse().map_err(|e| invalid(format!("flow.source: {e}"))))
                    .transpose()?,
                source_port: f.source_port,
                destination_port: f.destination_port,
            })
        })
        .transpose()?;
    let action = Action::from_parts(kind, flow, body.bytes_per_second)
        .map_err(|e| invalid(e.to_string()))?;
    Ok(MitigationRequest {
        prefix,
        action,
        reason: body.reason,
        duration: Duration::from_secs(body.duration_seconds),
        incident_id: body.incident_id,
    })
}

fn respond<T: Serialize>(status: StatusCode, result: Result<T, Problem>) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

fn list_limit(pairs: &[(String, String)]) -> Result<(u32, ListFilter), Problem> {
    let mut limit = DEFAULT_LIST;
    let mut filter = ListFilter::All;
    for (name, value) in pairs {
        match name.as_str() {
            "limit" => {
                limit = value
                    .parse::<u32>()
                    .ok()
                    .filter(|n| (1..=MAX_LIST).contains(n))
                    .ok_or_else(|| {
                        Problem::new(ErrorCode::InvalidRequest)
                            .with_detail(format!("limit must be from 1 to {MAX_LIST}"))
                    })?
            }
            "live" => {
                filter = match value.as_str() {
                    "true" => ListFilter::Live,
                    "false" => ListFilter::All,
                    _ => {
                        return Err(Problem::new(ErrorCode::InvalidRequest)
                            .with_detail("live must be true or false"))
                    }
                }
            }
            other => {
                return Err(Problem::new(ErrorCode::InvalidRequest)
                    .with_detail(format!("unknown query parameter {other:?}")))
            }
        }
    }
    Ok((limit, filter))
}

/// The tenant's mitigations, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/mitigations",
    tag = "mitigations",
    params(
        ("limit" = Option<u32>, Query, description = "1 to 500; 100 by default"),
        ("live" = Option<bool>, Query, description = "Only mitigations that have not ended"),
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant's mitigations", body = MitigationList),
        (status = 400, description = "A bad query", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks mitigation.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn list_mitigations(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let (count, filter) = list_limit(&pairs)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let items = state
            .mitigations
            .list_details(&**client, &auth, filter, count)
            .await
            .map_err(|e| Problem::from(&e))?;
        Ok(MitigationList {
            items: items.into_iter().map(MitigationView::from_detail).collect(),
        })
    }
    .await;
    respond(StatusCode::OK, result)
}

/// Asks for a mitigation. Nothing is announced until it is approved.
#[utoipa::path(
    post,
    path = "/api/v1/mitigations",
    tag = "mitigations",
    request_body = MitigationRequestBody,
    params(("Idempotency-Key" = String, Header, description = "16 to 255 characters")),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Requested", body = MitigationView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks mitigation.request, or the prefix or action is not allowlisted", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "A duplicate, the kill switch, or a reused key", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "Not a valid mitigation, or outside the guard's bounds", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn request_mitigation(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        let key = crate::transitions::idempotency_key(&headers)?;
        let request = request_from(crate::body::json(&headers, body)?)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let created = state
            .mitigations
            .request(&mut client, &auth, request, Some(key.as_str()))
            .await
            .map_err(|e| Problem::from(&e))?;
        state
            .mitigations
            .detail(&**client, &auth, &created.id)
            .await
            .map(MitigationView::from_detail)
            .map_err(|e| Problem::from(&e))
    }
    .await;
    respond(StatusCode::CREATED, result)
}

/// One mitigation.
#[utoipa::path(
    get,
    path = "/api/v1/mitigations/{mitigation_id}",
    tag = "mitigations",
    params(("mitigation_id" = String, Path, description = "The mitigation's UUID")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The mitigation", body = MitigationView),
        (status = 400, description = "The id is not a UUID", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks mitigation.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such mitigation in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn get_mitigation(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(mitigation_id): Path<String>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let id = parse_mitigation_id(&mitigation_id)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        state
            .mitigations
            .detail(&**client, &auth, &id)
            .await
            .map(MitigationView::from_detail)
            .map_err(|e| Problem::from(&e))
    }
    .await;
    respond(StatusCode::OK, result)
}

/// A mitigation's state changes, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/mitigations/{mitigation_id}/history",
    tag = "mitigations",
    params(("mitigation_id" = String, Path, description = "The mitigation's UUID")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Every state change", body = MitigationHistory),
        (status = 400, description = "The id is not a UUID", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks mitigation.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such mitigation in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn mitigation_history(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(mitigation_id): Path<String>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let id = parse_mitigation_id(&mitigation_id)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let items = state
            .mitigations
            .history(&**client, &auth, &id)
            .await
            .map_err(|e| Problem::from(&e))?;
        Ok(MitigationHistory {
            items: items.into_iter().map(Into::into).collect(),
        })
    }
    .await;
    respond(StatusCode::OK, result)
}

#[derive(Clone, Copy)]
enum Change {
    Approve,
    Reject,
    Withdraw,
}

async fn change(
    state: AppState,
    principal: Principal,
    mitigation_id: String,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    kind: Change,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        let id = parse_mitigation_id(&mitigation_id)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let store = &state.mitigations;
        let outcome = match kind {
            Change::Approve => {
                let body: ApproveBody = crate::body::json(&headers, body)?;
                store
                    .approve(&mut client, &auth, &id, body.expected_version)
                    .await
            }
            Change::Reject => {
                let body: ReasonBody = crate::body::json(&headers, body)?;
                store
                    .reject(&mut client, &auth, &id, body.expected_version, &body.reason)
                    .await
            }
            Change::Withdraw => {
                let body: ReasonBody = crate::body::json(&headers, body)?;
                store
                    .withdraw(&mut client, &auth, &id, body.expected_version, &body.reason)
                    .await
            }
        };
        outcome.map_err(|e| Problem::from(&e))?;
        store
            .detail(&**client, &auth, &id)
            .await
            .map(MitigationView::from_detail)
            .map_err(|e| Problem::from(&e))
    }
    .await;
    respond(StatusCode::OK, result)
}

/// Approves a mitigation: the mitigator will announce it. `noc_lead` and
/// up, and not your own unless the deployment allows it.
#[utoipa::path(
    post,
    path = "/api/v1/mitigations/{mitigation_id}/approve",
    tag = "mitigations",
    params(("mitigation_id" = String, Path, description = "The mitigation's UUID")),
    request_body = ApproveBody,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Approved", body = MitigationView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks mitigation.approve, your own request, or no longer allowlisted", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such mitigation in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "Not awaiting approval, a stale version, or the kill switch", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn approve_mitigation(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(mitigation_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    change(
        state,
        principal,
        mitigation_id,
        headers,
        body,
        Change::Approve,
    )
    .await
}

/// Rejects a mitigation awaiting approval.
#[utoipa::path(
    post,
    path = "/api/v1/mitigations/{mitigation_id}/reject",
    tag = "mitigations",
    params(("mitigation_id" = String, Path, description = "The mitigation's UUID")),
    request_body = ReasonBody,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Rejected", body = MitigationView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks mitigation.approve", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such mitigation in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "Not awaiting approval, or a stale version", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "No reason", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn reject_mitigation(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(mitigation_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    change(
        state,
        principal,
        mitigation_id,
        headers,
        body,
        Change::Reject,
    )
    .await
}

/// Takes an approved mitigation down. The mitigator withdraws its route.
#[utoipa::path(
    post,
    path = "/api/v1/mitigations/{mitigation_id}/withdraw",
    tag = "mitigations",
    params(("mitigation_id" = String, Path, description = "The mitigation's UUID")),
    request_body = ReasonBody,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Withdrawing, or withdrawn if nothing was announced", body = MitigationView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks mitigation.withdraw", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such mitigation in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "Not up, or a stale version", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "No reason", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn withdraw_mitigation(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(mitigation_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    change(
        state,
        principal,
        mitigation_id,
        headers,
        body,
        Change::Withdraw,
    )
    .await
}

/// The deployment-wide kill switch.
#[utoipa::path(
    get,
    path = "/api/v1/mitigation-controls/kill-switch",
    tag = "mitigations",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The kill switch", body = KillSwitchView),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks mitigation.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn get_kill_switch(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let auth = principal.authorization(state.resolver.as_ref());
        if !auth.has(tidegard_incident::authorization::Permission::MitigationRead) {
            return Err(Problem::new(ErrorCode::MitigationForbidden));
        }
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        state
            .mitigations
            .kill_switch(&**client)
            .await
            .map(KillSwitchView::from)
            .map_err(|e| Problem::from(&e))
    }
    .await;
    respond(StatusCode::OK, result)
}

/// Turns the kill switch on (`noc_lead` and up) or off (platform
/// administrators only), with a reason.
#[utoipa::path(
    put,
    path = "/api/v1/mitigation-controls/kill-switch",
    tag = "mitigations",
    request_body = KillSwitchBody,
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The kill switch as it now is", body = KillSwitchView),
        (status = 400, description = "Malformed", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks mitigation.kill_switch.engage or .release", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "No reason", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn set_kill_switch(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        let body: KillSwitchBody = crate::body::json(&headers, body)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        state
            .mitigations
            .set_kill_switch(&mut client, &auth, body.engaged, &body.reason)
            .await
            .map(KillSwitchView::from)
            .map_err(|e| Problem::from(&e))
    }
    .await;
    respond(StatusCode::OK, result)
}

/// The routes the tenant's mitigations announced live and may hold in
/// GoBGP now. Dry-run mitigations hold none.
#[utoipa::path(
    get,
    path = "/api/v1/bgp/routes",
    tag = "mitigations",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tenant's routes", body = BgpRouteList),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks mitigation.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn bgp_routes(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let items = state
            .mitigations
            .list_details(&**client, &auth, ListFilter::Routed, MAX_LIST)
            .await
            .map_err(|e| Problem::from(&e))?;
        Ok(BgpRouteList {
            items: items
                .into_iter()
                .map(|d| BgpRoute {
                    mitigation_id: d.record.id.to_string(),
                    state: d.record.state.as_str().to_string(),
                    prefix: d.record.prefix.to_string(),
                    action: d.record.action.kind().as_str().to_string(),
                    route: d.route.and_then(|t| serde_json::from_str(&t).ok()),
                    expires_at: d.expires_at_us.map(rfc3339),
                })
                .collect(),
        })
    }
    .await;
    respond(StatusCode::OK, result)
}

/// GoBGP's peers as the mitigator last saw them. Deployment-wide: for
/// those who may pull the kill switch (FU-65).
#[utoipa::path(
    get,
    path = "/api/v1/bgp/peers",
    tag = "mitigations",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The peers", body = BgpPeerList),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "Lacks mitigation.kill_switch.engage", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn bgp_peers(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
        let items = state
            .mitigations
            .peers(&**client, &auth)
            .await
            .map_err(|e| Problem::from(&e))?;
        Ok(BgpPeerList {
            items: items
                .into_iter()
                .map(|p: PeerStatus| BgpPeer {
                    neighbor_address: p.neighbor_address,
                    peer_asn: p.peer_asn,
                    session_state: p.session_state,
                    updated_at: rfc3339(p.updated_at_us),
                })
                .collect(),
        })
    }
    .await;
    respond(StatusCode::OK, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &str) -> MitigationRequestBody {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn requests_are_checked_before_the_database() {
        let ok = request_from(body(
            r#"{"prefix": "192.0.2.10/32", "action": "rtbh", "reason": "flood", "duration_seconds": 600}"#,
        ))
        .unwrap();
        assert_eq!(ok.action, Action::Rtbh);
        for (json, needle) in [
            (
                r#"{"prefix": "192.0.2.10/24", "action": "rtbh", "reason": "r", "duration_seconds": 600}"#,
                "prefix",
            ),
            (
                r#"{"prefix": "192.0.2.10/32", "action": "flowspec_redirect", "reason": "r", "duration_seconds": 600}"#,
                "action",
            ),
            (
                r#"{"prefix": "192.0.2.10/32", "action": "flowspec_discard", "flow": {"source": "x"}, "reason": "r", "duration_seconds": 600}"#,
                "flow.source",
            ),
            (
                r#"{"prefix": "192.0.2.10/32", "action": "flowspec_rate_limit", "reason": "r", "duration_seconds": 600}"#,
                "rate",
            ),
        ] {
            let problem = request_from(body(json)).unwrap_err();
            assert_eq!(problem.code(), ErrorCode::MitigationInvalid, "{json}");
            assert!(
                problem.body()["detail"].as_str().unwrap().contains(needle),
                "{json}"
            );
        }
        // Unknown fields are refused, never ignored: a request cannot smuggle
        // a next hop.
        assert!(serde_json::from_str::<MitigationRequestBody>(
            r#"{"prefix": "192.0.2.10/32", "action": "rtbh", "reason": "r", "duration_seconds": 600, "next_hop": "198.51.100.1"}"#
        )
        .is_err());
    }

    #[test]
    fn list_queries_are_strict() {
        assert!(list_limit(&[("limit".into(), "501".into())]).is_err());
        assert!(list_limit(&[("live".into(), "yes".into())]).is_err());
        assert!(list_limit(&[("state".into(), "active".into())]).is_err());
        assert_eq!(list_limit(&[]).unwrap().0, DEFAULT_LIST);
    }
}
