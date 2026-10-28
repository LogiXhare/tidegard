//! Authentication and the bridge to authorization (ADR 0038, gates 4–5).
//!
//! - **Tokens** are `wnm_` and 64 lowercase hex characters (256 bits from
//!   the OS CSPRNG). Only `SHA-256(token)` is stored, in `api_tokens`
//!   (migration V15), and lookup is by that hash, so no secret is compared
//!   in application code.
//! - **[`Authenticator`] is the seam.** The Community implementation reads
//!   the token table; Phase 8 adds OIDC. Nothing past it knows how a
//!   caller proved who they are.
//! - **Every failure looks the same:** `401 api.unauthenticated` with
//!   `WWW-Authenticate: Bearer`, whatever the cause. Failed attempts are
//!   rate-limited per source address, and a limited address is refused
//!   before its token is even looked at.
//! - **The database being down is not a failed login:** it is
//!   `503 api.unavailable`. The API fails closed, and nobody is locked out
//!   for an outage.
//! - **A principal never carries cross-tenant authority.** The roles are
//!   the four tenant bundles; `platform_admin` is refused here and by the
//!   table's CHECK constraint.
//! - **A browser session is the other way in** (ADR 0043): without a
//!   bearer token, a `wnm_session` cookie is looked up, and a request that
//!   changes anything must also carry the session's CSRF value.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use tidegard_incident::authorization::{Actor, AuthorizationContext, PermissionResolver};
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::pool::acquire;

use crate::problem::{ErrorCode, Problem};
use crate::rate_limit::{Quota, RateLimiter};

pub const TOKEN_PREFIX: &str = "wnm_";
const SECRET_BYTES: usize = 32;
const TOKEN_LEN: usize = TOKEN_PREFIX.len() + SECRET_BYTES * 2;

/// Failed authentications allowed per source address (security model).
pub const FAILED_AUTH_QUOTA: Quota = Quota::per_minute(30);
/// Source addresses tracked for failed authentication at once.
const FAILED_AUTH_MAX_KEYS: usize = 100_000;

/// A tenant role a token may carry. Never `platform_admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Operator,
    SeniorOperator,
    NocLead,
}

impl Role {
    pub const ALL: [Role; 4] = [
        Role::Viewer,
        Role::Operator,
        Role::SeniorOperator,
        Role::NocLead,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::SeniorOperator => "senior_operator",
            Role::NocLead => "noc_lead",
        }
    }

    pub fn parse(text: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|role| role.as_str() == text)
    }
}

/// Who is calling: one tenant, one actor, one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub tenant: TenantId,
    pub actor: Actor,
    pub role: Role,
}

impl Principal {
    /// The context every domain call for this request runs under.
    pub fn authorization(&self, resolver: &dyn PermissionResolver) -> AuthorizationContext {
        AuthorizationContext::new(
            self.tenant.clone(),
            self.actor.clone(),
            resolver.permissions_for(self.role.as_str()),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Missing, malformed, unknown, expired or revoked: never which.
    Rejected,
    /// The identity store cannot be reached.
    Unavailable,
}

pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = Result<Principal, AuthError>> + Send + 'a>>;
/// A session's principal and the id of the token it was made from.
pub type SessionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(Principal, String), AuthError>> + Send + 'a>>;

/// The identity seam (ADR 0017's `IdentityProvider`, request side).
pub trait Authenticator: Send + Sync {
    fn authenticate<'a>(&'a self, bearer: &'a str) -> AuthFuture<'a>;

    /// A browser session (ADR 0043). Without a session store, none is
    /// accepted.
    fn authenticate_session<'a>(&'a self, _session_id: &'a str) -> SessionFuture<'a> {
        Box::pin(async { Err(AuthError::Rejected) })
    }
}

/// A new token's secret: `wnm_` and 64 hex characters.
pub fn generate_token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes)?;
    let mut token = String::with_capacity(TOKEN_LEN);
    token.push_str(TOKEN_PREFIX);
    for byte in bytes {
        token.push_str(&format!("{byte:02x}"));
    }
    Ok(token)
}

/// What is stored and looked up.
pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Shape only; says nothing about whether the token exists.
pub fn is_well_formed(token: &str) -> bool {
    token.len() == TOKEN_LEN
        && token.starts_with(TOKEN_PREFIX)
        && token[TOKEN_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A token of a suspended tenant is refused like an unknown one
/// (ADR 0060).
const LOOKUP: &str = "\
SELECT t.tenant_id, t.actor_type, t.actor_id, t.role FROM api_tokens t
JOIN tenants ON tenants.tenant_id = t.tenant_id
WHERE t.token_hash = $1
  AND t.revoked_at IS NULL
  AND t.expires_at > transaction_timestamp()
  AND tenants.status = 'active'";

/// A session: live, not idle past the timeout, its token still valid and
/// its tenant active. `stale` says `last_seen_at` is due a write.
const SESSION_LOOKUP: &str = "\
SELECT t.token_id::text AS token_id, t.tenant_id, t.actor_type, t.actor_id, t.role,
    s.last_seen_at < transaction_timestamp() - $3::bigint * interval '1 second' AS stale
FROM api_sessions s
JOIN api_tokens t ON t.token_id = s.token_id
JOIN tenants ON tenants.tenant_id = t.tenant_id
WHERE s.session_hash = $1
  AND s.expires_at > transaction_timestamp()
  AND s.last_seen_at > transaction_timestamp() - $2::bigint * interval '1 second'
  AND t.revoked_at IS NULL
  AND t.expires_at > transaction_timestamp()
  AND tenants.status = 'active'";

const SESSION_TOUCH: &str =
    "UPDATE api_sessions SET last_seen_at = transaction_timestamp() WHERE session_hash = $1";

fn principal_from(row: &tokio_postgres::Row) -> Result<Principal, AuthError> {
    let tenant: String = row.get("tenant_id");
    let actor_type: String = row.get("actor_type");
    let actor_id: String = row.get("actor_id");
    let role: String = row.get("role");
    let actor = match actor_type.as_str() {
        "operator" => Actor::Operator { id: actor_id },
        "service_account" => Actor::ServiceAccount { id: actor_id },
        _ => return Err(AuthError::Rejected),
    };
    Ok(Principal {
        tenant: TenantId::new(tenant),
        actor,
        role: Role::parse(&role).ok_or(AuthError::Rejected)?,
    })
}

/// The Community authenticator: the `api_tokens` table.
pub struct TokenAuthenticator {
    pool: Pool,
}

impl TokenAuthenticator {
    pub fn new(pool: Pool) -> Self {
        TokenAuthenticator { pool }
    }
}

impl Authenticator for TokenAuthenticator {
    fn authenticate<'a>(&'a self, bearer: &'a str) -> AuthFuture<'a> {
        Box::pin(async move {
            if !is_well_formed(bearer) {
                return Err(AuthError::Rejected);
            }
            let client = acquire(&self.pool)
                .await
                .map_err(|_| AuthError::Unavailable)?;
            let row = client
                .query_opt(LOOKUP, &[&token_hash(bearer)])
                .await
                .map_err(|_| AuthError::Unavailable)?
                .ok_or(AuthError::Rejected)?;
            principal_from(&row)
        })
    }

    fn authenticate_session<'a>(&'a self, session_id: &'a str) -> SessionFuture<'a> {
        Box::pin(async move {
            if !crate::session::is_well_formed_session(session_id) {
                return Err(AuthError::Rejected);
            }
            let client = acquire(&self.pool)
                .await
                .map_err(|_| AuthError::Unavailable)?;
            let hash = crate::session::session_hash(session_id);
            let idle = crate::session::IDLE_TIMEOUT.as_secs() as i64;
            let touch = crate::session::TOUCH_INTERVAL.as_secs() as i64;
            let row = client
                .query_opt(SESSION_LOOKUP, &[&hash, &idle, &touch])
                .await
                .map_err(|_| AuthError::Unavailable)?
                .ok_or(AuthError::Rejected)?;
            if row.get::<_, bool>("stale") {
                client
                    .execute(SESSION_TOUCH, &[&hash])
                    .await
                    .map_err(|_| AuthError::Unavailable)?;
            }
            Ok((principal_from(&row)?, row.get("token_id")))
        })
    }
}

/// What the authentication middleware needs.
#[derive(Clone)]
pub struct AuthLayerState {
    pub authenticator: Arc<dyn Authenticator>,
    pub failures: Arc<RateLimiter<IpAddr>>,
    /// Where refused CSRF checks are audited (ADR 0043), when there is a
    /// database.
    pub audit: Option<Pool>,
}

impl AuthLayerState {
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        AuthLayerState {
            authenticator,
            failures: Arc::new(RateLimiter::new(FAILED_AUTH_QUOTA, FAILED_AUTH_MAX_KEYS)),
            audit: None,
        }
    }

    pub fn with_audit(mut self, pool: Pool) -> Self {
        self.audit = Some(pool);
        self
    }
}

fn bearer(request: &Request) -> Option<&str> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Requires a valid bearer token, and puts the [`Principal`] in the
/// request's extensions for the handlers.
pub async fn require_principal(
    State(auth): State<AuthLayerState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Without connection info (a test driving the router directly), every
    // caller shares one bucket, which only ever makes limiting stricter.
    let source = request
        .extensions()
        .get::<ConnectInfo<crate::server::PeerAddr>>()
        .map(|info| info.0 .0.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let now = Instant::now();
    if let Err(refusal) = auth.failures.peek(&source, now) {
        return Problem::new(ErrorCode::RateLimited)
            .retry_after(refusal.retry_after_secs())
            .into_response();
    }
    // A bearer token wins; the cookie is only for a browser that has none.
    let outcome = match bearer(&request) {
        Some(token) => auth
            .authenticator
            .authenticate(token)
            .await
            .map(|principal| (principal, None)),
        None => match crate::session::session_cookie(request.headers()) {
            Some(id) => {
                let id = id.to_string();
                auth.authenticator
                    .authenticate_session(&id)
                    .await
                    .map(|(principal, token_id)| {
                        (
                            principal,
                            Some(crate::session::SessionContext { id, token_id }),
                        )
                    })
            }
            None => Err(AuthError::Rejected),
        },
    };
    match outcome {
        Ok((principal, session)) => {
            if let Some(session) = session {
                if crate::session::needs_csrf(request.method()) {
                    let presented = request
                        .headers()
                        .get(crate::session::CSRF_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    if !crate::session::csrf_matches(&session.id, presented) {
                        if let Some(pool) = &auth.audit {
                            crate::session::record(
                                pool,
                                crate::session::SessionEvent {
                                    action: "session.csrf_rejected",
                                    principal: &principal,
                                    token_id: &session.token_id,
                                    allowed: false,
                                    reason: Some("missing or wrong CSRF header"),
                                    source: Some(source),
                                },
                            )
                            .await;
                        }
                        tracing::info!(%source, "a CSRF check failed");
                        return Problem::new(ErrorCode::CsrfRejected).into_response();
                    }
                }
                request.extensions_mut().insert(session);
            }
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(AuthError::Unavailable) => Problem::new(ErrorCode::Unavailable)
            .retry_after(5)
            .into_response(),
        Err(AuthError::Rejected) => {
            let _ = auth.failures.check(&source, now);
            tracing::info!(%source, "authentication failed");
            Problem::new(ErrorCode::Unauthenticated).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use tower::ServiceExt;

    const GOOD: &str = "wnm_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn generated_tokens_are_well_formed_and_distinct() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert!(is_well_formed(&a), "{a}");
        assert_ne!(a, b);
        assert_eq!(token_hash(&a).len(), 32);
    }

    #[test]
    fn malformed_tokens_are_refused_before_any_lookup() {
        for token in [
            "",
            "wnm_",
            "wnm_short",
            &GOOD.to_uppercase(),
            &GOOD.replace("wnm_", "abc_"),
            &format!("{GOOD}0"),
            "wnm_zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ] {
            assert!(!is_well_formed(token), "{token}");
        }
        assert!(is_well_formed(GOOD));
    }

    #[test]
    fn platform_admin_is_never_a_token_role() {
        assert_eq!(Role::parse("platform_admin"), None);
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
    }

    /// Accepts exactly one token; reports the store down for another.
    struct FakeAuthenticator;

    impl Authenticator for FakeAuthenticator {
        fn authenticate<'a>(&'a self, bearer: &'a str) -> AuthFuture<'a> {
            Box::pin(async move {
                match bearer {
                    GOOD => Ok(Principal {
                        tenant: TenantId::new("acme"),
                        actor: Actor::Operator {
                            id: "alice".to_string(),
                        },
                        role: Role::Operator,
                    }),
                    "down" => Err(AuthError::Unavailable),
                    _ => Err(AuthError::Rejected),
                }
            })
        }
    }

    fn app(state: AuthLayerState) -> Router {
        Router::new()
            .route(
                "/whoami",
                get(|Extension(principal): Extension<Principal>| async move {
                    principal.tenant.as_str().to_string()
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                require_principal,
            ))
    }

    async fn call(
        app: &Router,
        authorization: Option<&str>,
    ) -> (StatusCode, String, Option<String>) {
        let mut request = HttpRequest::builder().uri("/whoami");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let www = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|v| v.to_str().unwrap().to_string());
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap(), www)
    }

    #[tokio::test]
    async fn a_valid_token_reaches_the_handler_as_its_principal() {
        let app = app(AuthLayerState::new(Arc::new(FakeAuthenticator)));
        let (status, body, _) = call(&app, Some(&format!("Bearer {GOOD}"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "acme");
        let (status, _, _) = call(&app, Some(&format!("bearer {GOOD}"))).await;
        assert_eq!(status, StatusCode::OK, "the scheme is case-insensitive");
    }

    #[tokio::test]
    async fn every_failure_is_the_same_401() {
        let app = app(AuthLayerState::new(Arc::new(FakeAuthenticator)));
        let mut bodies = Vec::new();
        for header in [
            None,
            Some("Basic abc"),
            Some("Bearer wnm_wrong"),
            Some("Bearer"),
        ] {
            let (status, body, www) = call(&app, header).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{header:?}");
            assert_eq!(www.as_deref(), Some("Bearer"));
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["error"], "api.unauthenticated");
            bodies.push((json["title"].clone(), json.get("detail").cloned()));
        }
        assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[tokio::test]
    async fn an_outage_is_503_and_counts_as_no_failure() {
        let state = AuthLayerState::new(Arc::new(FakeAuthenticator));
        let app = app(state.clone());
        let (status, body, _) = call(&app, Some("Bearer down")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("api.unavailable"));
        assert_eq!(state.failures.tracked(), 0);
    }

    #[tokio::test]
    async fn too_many_failures_lock_the_source_out_even_with_a_good_token() {
        let state = AuthLayerState::new(Arc::new(FakeAuthenticator));
        let app = app(state);
        for _ in 0..FAILED_AUTH_QUOTA.limit {
            let (status, _, _) = call(&app, Some("Bearer wnm_wrong")).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, body, _) = call(&app, Some(&format!("Bearer {GOOD}"))).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(body.contains("api.rate_limited"));
    }
}
