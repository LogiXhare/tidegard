//! Tidegard incident REST API (Milestone 5D).
//!
//! The boundary decisions are [ADR 0037](../../docs/architecture/decisions/0037-phase5d-http-framework-and-openapi.md)
//! (axum, OpenAPI from code) and [ADR 0038](../../docs/architecture/decisions/0038-phase5d-api-boundary.md)
//! (TLS, identity, authorization, rate limits, errors). This crate is
//! the API's foundation: errors, request ids, the rate limiter, the
//! listener, health and readiness, and the OpenAPI document. The incident
//! endpoints build on it.
//!
//! Every response that is not a success is RFC 9457 problem details,
//! including unknown paths and wrong methods.

pub mod auth;
pub mod body;
pub mod clickhouse;
pub mod config;
pub mod create;
pub mod export;
pub mod history;
pub mod incidents;
pub mod list;
pub mod mitigations;
pub mod openapi;
pub mod problem;
pub mod rate_limit;
pub mod request_id;
pub mod server;
pub mod session;
pub mod time;
pub mod token_admin;
pub mod traffic;
pub mod transitions;
pub mod web;
pub mod whoami;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use deadpool_postgres::Pool;
use serde::Serialize;
use std::sync::Arc;
use tidegard_incident::authorization::{FixedBundleResolver, PermissionResolver};
use tidegard_incident::clock::SystemClock;
use tidegard_incident_postgres::id::UuidV7IncidentGenerator;
use tidegard_incident_postgres::mitigation::MitigationStore;
use tidegard_incident_postgres::pool::acquire;
use tidegard_incident_postgres::service::IncidentPersistence;
use utoipa::ToSchema;

use crate::auth::{AuthLayerState, TokenAuthenticator};
use crate::problem::{ErrorCode, Problem};

/// The largest request body accepted, before any handler sees it.
pub const BODY_LIMIT_BYTES: usize = 64 * 1024;

/// What every handler shares.
#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    /// Bearer authentication and its failure limiter (ADR 0038, gate 4).
    pub auth: AuthLayerState,
    /// Role to permissions (ADR 0017's `PermissionResolver`, gate 5).
    pub resolver: Arc<dyn PermissionResolver>,
    /// Per-actor limits for each surface (gate 6).
    pub limits: Arc<incidents::Limits>,
    /// The command path: the same unit of work the incident manager runs.
    pub incidents: Arc<IncidentPersistence>,
    /// Deployment-wide traffic, when configured (ADR 0042).
    pub traffic: Option<Arc<traffic::TrafficSource>>,
    /// Session cookies carry `Secure` (ADR 0043). Only a plain-HTTP API,
    /// which is loopback-only, turns it off.
    pub secure_cookies: bool,
    /// The built NOC UI, when configured (ADR 0044).
    pub web: Option<Arc<web::WebRoot>>,
    /// Mitigation records under the safety guard (ADR 0050). Without a
    /// configured guard nothing is allowlisted, so every request is refused.
    pub mitigations: Arc<MitigationStore>,
}

impl AppState {
    /// The Community wiring: the token table and the fixed role bundles.
    pub fn new(pool: Pool) -> Self {
        AppState {
            auth: AuthLayerState::new(Arc::new(TokenAuthenticator::new(pool.clone())))
                .with_audit(pool.clone()),
            resolver: Arc::new(FixedBundleResolver),
            limits: Arc::new(incidents::Limits::default()),
            incidents: Arc::new(IncidentPersistence::new(
                Arc::new(UuidV7IncidentGenerator::new()),
                Arc::new(SystemClock),
            )),
            traffic: None,
            secure_cookies: true,
            web: None,
            mitigations: Arc::new(MitigationStore::new(
                Arc::new(UuidV7IncidentGenerator::new()),
                Arc::new(
                    tidegard_mitigation::Guard::new(tidegard_mitigation::GuardConfig::default())
                        .expect("the default guard is valid"),
                ),
            )),
            pool,
        }
    }

    /// Checks mitigation requests against `guard` (ADR 0047, ADR 0050).
    pub fn with_guard(mut self, guard: tidegard_mitigation::Guard) -> Self {
        self.mitigations = Arc::new(MitigationStore::new(
            Arc::new(UuidV7IncidentGenerator::new()),
            Arc::new(guard),
        ));
        self
    }

    /// Serves the built NOC UI from `root` (ADR 0044).
    pub fn with_web(mut self, root: web::WebRoot) -> Self {
        self.web = Some(Arc::new(root));
        self
    }

    /// Lets the traffic tenant read traffic from `source` (ADR 0042).
    pub fn with_traffic(mut self, source: traffic::TrafficSource) -> Self {
        self.traffic = Some(Arc::new(source));
        self
    }
}

/// The whole API: routes, problem-details fallbacks, request ids and the
/// body limit.
pub fn router(state: AppState) -> Router {
    // Every /api/v1 route requires a principal. `route_layer` applies only
    // to matched routes, so an unknown path is a plain 404 either way.
    let api = Router::new()
        .route("/whoami", get(whoami::whoami))
        .route(
            "/incidents",
            get(list::list_incidents).post(create::create_incident),
        )
        .route("/incidents/{incident_id}", get(incidents::get_incident))
        .route("/incidents/{incident_id}/timeline", get(history::timeline))
        .route(
            "/incidents/{incident_id}/notes",
            get(history::notes).post(transitions::add_note),
        )
        .route(
            "/incidents/{incident_id}/notes/{note_index}/edit",
            post(transitions::edit_note),
        )
        .route(
            "/incidents/{incident_id}/notes/{note_index}/redact",
            post(transitions::redact_note),
        )
        .route(
            "/incidents/{incident_id}/detections",
            get(history::detections),
        )
        .route("/incidents/{incident_id}/audit", get(history::audit))
        .route("/traffic/summary", get(traffic::summary))
        .route("/traffic/top", get(traffic::top))
        .route("/exporters", get(traffic::exporters))
        .route(
            "/incidents/{incident_id}/acknowledge",
            post(transitions::acknowledge),
        )
        .route(
            "/incidents/{incident_id}/investigate",
            post(transitions::investigate),
        )
        .route(
            "/incidents/{incident_id}/monitor",
            post(transitions::monitor),
        )
        .route(
            "/incidents/{incident_id}/resolve",
            post(transitions::resolve),
        )
        .route("/incidents/{incident_id}/close", post(transitions::close))
        .route("/incidents/{incident_id}/reopen", post(transitions::reopen))
        .route(
            "/incidents/{incident_id}/suppress",
            post(transitions::suppress),
        )
        .route(
            "/incidents/{incident_id}/unsuppress",
            post(transitions::unsuppress),
        )
        .route("/incidents/{incident_id}/assign", post(transitions::assign))
        .route(
            "/incidents/{incident_id}/unassign",
            post(transitions::unassign),
        )
        .route(
            "/incidents/{incident_id}/severity",
            post(transitions::severity),
        )
        .route(
            "/incidents/{incident_id}/priority",
            post(transitions::priority),
        )
        .route("/incidents/{incident_id}/export", post(export::export))
        .route(
            "/incidents/{incident_id}/tags/{key}",
            put(transitions::set_tag).delete(transitions::remove_tag),
        )
        .route(
            "/mitigations",
            get(mitigations::list_mitigations).post(mitigations::request_mitigation),
        )
        .route(
            "/mitigations/{mitigation_id}",
            get(mitigations::get_mitigation),
        )
        .route(
            "/mitigations/{mitigation_id}/history",
            get(mitigations::mitigation_history),
        )
        .route(
            "/mitigations/{mitigation_id}/approve",
            post(mitigations::approve_mitigation),
        )
        .route(
            "/mitigations/{mitigation_id}/reject",
            post(mitigations::reject_mitigation),
        )
        .route(
            "/mitigations/{mitigation_id}/withdraw",
            post(mitigations::withdraw_mitigation),
        )
        .route(
            "/mitigation-controls/kill-switch",
            get(mitigations::get_kill_switch).put(mitigations::set_kill_switch),
        )
        .route("/bgp/routes", get(mitigations::bgp_routes))
        .route("/bgp/peers", get(mitigations::bgp_peers))
        .route_layer(axum::middleware::from_fn_with_state(
            state.auth.clone(),
            auth::require_principal,
        ))
        // Signing in needs no principal; reading or ending the session does.
        .route(
            "/session",
            post(session::sign_in).merge(
                get(session::current).delete(session::sign_out).route_layer(
                    axum::middleware::from_fn_with_state(
                        state.auth.clone(),
                        auth::require_principal,
                    ),
                ),
            ),
        );
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .nest("/api/v1", api)
        // The UI's pages and assets, or the usual 404 problem (ADR 0044).
        .fallback(web::fallback)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(axum::extract::DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(axum::middleware::from_fn(request_id::middleware))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(state.secure_cookies),
            web::security_headers,
        ))
        .with_state(state)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    /// `ok` or `ready`.
    pub status: &'static str,
}

/// Liveness: the process is up. Touches nothing else.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "operations",
    responses((status = 200, description = "The process is running", body = Health))
)]
pub async fn healthz() -> Json<Health> {
    Json(Health { status: "ok" })
}

/// Readiness: the database answers. The API fails closed without it.
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "operations",
    responses(
        (status = 200, description = "The database answers", body = Health),
        (status = 503, description = "The database is unreachable", body = openapi::ProblemDocument,
            content_type = "application/problem+json"),
    )
)]
pub async fn readyz(State(state): State<AppState>) -> Response {
    let ready = async {
        let client = acquire(&state.pool).await?;
        client.query_one("SELECT 1", &[]).await?;
        Ok::<_, tidegard_incident_postgres::error::PersistError>(())
    }
    .await;
    match ready {
        Ok(()) => (StatusCode::OK, Json(Health { status: "ready" })).into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "readiness check failed");
            Problem::new(ErrorCode::Unavailable)
                .retry_after(5)
                .into_response()
        }
    }
}

async fn method_not_allowed() -> Problem {
    Problem::new(ErrorCode::MethodNotAllowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    /// A pool that is never connected: building one opens nothing.
    fn state() -> AppState {
        let (pool, _) = tidegard_incident_postgres::connect::connect(
            "host=127.0.0.1 port=1 user=nobody connect_timeout=1",
            None,
            tidegard_incident_postgres::pool::PoolPolicy {
                max_size: 1,
                wait_timeout: std::time::Duration::from_millis(200),
                create_timeout: std::time::Duration::from_millis(500),
                recycle_timeout: std::time::Duration::from_millis(200),
            },
        )
        .unwrap();
        AppState::new(pool)
    }

    async fn call(
        method: &str,
        path: &str,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        let response = router(state())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, headers, body)
    }

    #[tokio::test]
    async fn liveness_answers_without_the_database() {
        let (status, headers, body) = call("GET", "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert!(headers.contains_key(request_id::HEADER));
    }

    #[tokio::test]
    async fn readiness_fails_closed_when_the_database_is_unreachable() {
        let (status, headers, body) = call("GET", "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "api.unavailable");
        assert!(headers.contains_key(header::RETRY_AFTER));
        // The body names the request, matching the header.
        assert_eq!(
            body["request_id"],
            headers[request_id::HEADER].to_str().unwrap()
        );
    }

    #[tokio::test]
    async fn unknown_paths_and_methods_are_problem_details() {
        let (status, headers, body) = call("GET", "/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CONTENT_TYPE], problem::PROBLEM_CONTENT_TYPE);
        assert_eq!(body["error"], "api.not_found");

        let (status, _, body) = call("DELETE", "/healthz").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(body["error"], "api.method_not_allowed");
    }
}
