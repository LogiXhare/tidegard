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
//! - **A principal acts in one tenant per request** (ADR 0060). A tenant
//!   token's is its own. A platform token, which only the provider roles
//!   of FR-12.2 may hold, names the tenant in the `Tidegard-Tenant` header;
//!   without one it reaches only the endpoints that need no tenant. The
//!   table refuses a provider role on a tenant token, and the reverse.
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

/// Where a principal's authority runs (ADR 0060).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// One tenant, named by its token.
    Tenant,
    /// Every tenant, one per request, named by the [`TENANT_HEADER`].
    Platform,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Tenant => "tenant",
            Scope::Platform => "platform",
        }
    }
}

/// A role a token may carry: the seven tenant roles, or the five provider
/// roles of FR-12.2. The role decides the scope; the table refuses a
/// mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Operator,
    SeniorOperator,
    NocLead,
    CustomerAdmin,
    SecurityAnalyst,
    Automation,
    NocOperator,
    NocAdmin,
    Auditor,
    PlatformAdmin,
    SuperAdmin,
}

impl Role {
    pub const ALL: [Role; 12] = [
        Role::Viewer,
        Role::Operator,
        Role::SeniorOperator,
        Role::NocLead,
        Role::CustomerAdmin,
        Role::SecurityAnalyst,
        Role::Automation,
        Role::NocOperator,
        Role::NocAdmin,
        Role::Auditor,
        Role::PlatformAdmin,
        Role::SuperAdmin,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::SeniorOperator => "senior_operator",
            Role::NocLead => "noc_lead",
            Role::CustomerAdmin => "customer_admin",
            Role::SecurityAnalyst => "security_analyst",
            Role::Automation => "automation",
            Role::NocOperator => "noc_operator",
            Role::NocAdmin => "noc_admin",
            Role::Auditor => "auditor",
            Role::PlatformAdmin => "platform_admin",
            Role::SuperAdmin => "super_admin",
        }
    }

    pub fn parse(text: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|role| role.as_str() == text)
    }

    pub fn scope(self) -> Scope {
        match self {
            Role::NocOperator
            | Role::NocAdmin
            | Role::Auditor
            | Role::PlatformAdmin
            | Role::SuperAdmin => Scope::Platform,
            _ => Scope::Tenant,
        }
    }
}

/// The header a platform principal names the tenant it acts in with. A
/// tenant principal may send it only with its own tenant.
pub const TENANT_HEADER: &str = "tidegard-tenant";

/// What a platform principal's `tenant` is before a request names one.
/// Never a registered tenant (V22 refuses it), so it reads nothing.
pub const PLATFORM_TENANT: &str = "platform";

/// Who is calling: one actor and one role, acting in one tenant: its
/// token's, or for a platform role the one the request names.
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

    /// Whether a platform principal may act in `tenant`: it is registered,
    /// whatever its status, so a provider can look into a suspended one.
    /// Without a registry, no tenant is.
    fn tenant_registered<'a>(&'a self, _tenant: &'a str) -> TenantFuture<'a> {
        Box::pin(async { Ok(false) })
    }
}

pub type TenantFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, AuthError>> + Send + 'a>>;

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
/// (ADR 0060). A platform token names no tenant, so only its own fields
/// decide.
const LOOKUP: &str = "\
SELECT t.tenant_id, t.actor_type, t.actor_id, t.role FROM api_tokens t
LEFT JOIN tenants ON tenants.tenant_id = t.tenant_id
WHERE t.token_hash = $1
  AND t.revoked_at IS NULL
  AND t.expires_at > transaction_timestamp()
  AND (t.scope = 'platform' OR tenants.status = 'active')";

/// A session: live, not idle past the timeout, its token still valid and
/// its tenant active. `stale` says `last_seen_at` is due a write.
const SESSION_LOOKUP: &str = "\
SELECT t.token_id::text AS token_id, t.tenant_id, t.actor_type, t.actor_id, t.role,
    s.last_seen_at < transaction_timestamp() - $3::bigint * interval '1 second' AS stale
FROM api_sessions s
JOIN api_tokens t ON t.token_id = s.token_id
LEFT JOIN tenants ON tenants.tenant_id = t.tenant_id
WHERE s.session_hash = $1
  AND s.expires_at > transaction_timestamp()
  AND s.last_seen_at > transaction_timestamp() - $2::bigint * interval '1 second'
  AND t.revoked_at IS NULL
  AND t.expires_at > transaction_timestamp()
  AND (t.scope = 'platform' OR tenants.status = 'active')";

const TENANT_REGISTERED: &str = "SELECT EXISTS (SELECT 1 FROM tenants WHERE tenant_id = $1)";

const SESSION_TOUCH: &str =
    "UPDATE api_sessions SET last_seen_at = transaction_timestamp() WHERE session_hash = $1";

/// A principal from a token row. A platform token's tenant is
/// [`PLATFORM_TENANT`] until the request names one.
pub(crate) fn principal_from(row: &tokio_postgres::Row) -> Result<Principal, AuthError> {
    let tenant: Option<String> = row.get("tenant_id");
    let actor_type: String = row.get("actor_type");
    let actor_id: String = row.get("actor_id");
    let role: String = row.get("role");
    let actor = match actor_type.as_str() {
        "operator" => Actor::Operator { id: actor_id },
        "service_account" => Actor::ServiceAccount { id: actor_id },
        _ => return Err(AuthError::Rejected),
    };
    let role = Role::parse(&role).ok_or(AuthError::Rejected)?;
    let tenant = match (role.scope(), tenant) {
        (Scope::Tenant, Some(tenant)) => tenant,
        (Scope::Platform, None) => PLATFORM_TENANT.to_string(),
        // The table refuses both; a row that has one anyway signs in to
        // nothing.
        _ => return Err(AuthError::Rejected),
    };
    Ok(Principal {
        tenant: TenantId::new(tenant),
        actor,
        role,
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

    fn tenant_registered<'a>(&'a self, tenant: &'a str) -> TenantFuture<'a> {
        Box::pin(async move {
            let client = acquire(&self.pool)
                .await
                .map_err(|_| AuthError::Unavailable)?;
            let row = client
                .query_one(TENANT_REGISTERED, &[&tenant])
                .await
                .map_err(|_| AuthError::Unavailable)?;
            Ok(row.get(0))
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
            let named = request
                .headers()
                .get(TENANT_HEADER)
                .map(|value| value.to_str().map(|text| text.trim().to_string()));
            let named = match named {
                None => None,
                Some(Ok(tenant)) if !tenant.is_empty() => Some(tenant),
                Some(_) => {
                    return Problem::new(ErrorCode::InvalidRequest)
                        .with_detail("the Tidegard-Tenant header is empty or not text")
                        .into_response()
                }
            };
            let path = request.uri().path().to_string();
            let principal = match act_in(&auth, principal, named, &path).await {
                Ok(principal) => principal,
                Err(refusal) => return refusal.into_response(),
            };
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

/// The endpoints a platform principal reaches without naming a tenant:
/// who it is, its session, and the platform's own. The router nests the
/// API under `/api/v1`, so the middleware sees the path without it.
fn needs_no_tenant(path: &str) -> bool {
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    matches!(path, "/whoami" | "/session") || path.starts_with("/platform/")
}

/// The tenant this request acts in (ADR 0060). A tenant principal's is its
/// own, and naming another is `403`. A platform principal names a
/// registered tenant, or calls only what needs none.
async fn act_in(
    auth: &AuthLayerState,
    mut principal: Principal,
    named: Option<String>,
    path: &str,
) -> Result<Principal, Problem> {
    match (principal.role.scope(), named) {
        (Scope::Tenant, Some(tenant)) if tenant != principal.tenant.as_str() => {
            Err(Problem::new(ErrorCode::Forbidden))
        }
        (Scope::Tenant, _) => Ok(principal),
        (Scope::Platform, Some(tenant)) => {
            match auth.authenticator.tenant_registered(&tenant).await {
                Ok(true) => {
                    principal.tenant = TenantId::new(tenant);
                    Ok(principal)
                }
                Ok(false) => Err(Problem::new(ErrorCode::TenantUnknown)),
                Err(_) => Err(Problem::new(ErrorCode::Unavailable).retry_after(5)),
            }
        }
        (Scope::Platform, None) if needs_no_tenant(path) => Ok(principal),
        (Scope::Platform, None) => Err(Problem::new(ErrorCode::TenantRequired)),
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

    /// The roles are the domain's bundles, each in the scope the domain
    /// gives it.
    #[test]
    fn every_role_parses_and_has_the_domains_scope() {
        use tidegard_incident::authorization::{PLATFORM_ROLES, TENANT_ROLES};
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        let tenant: Vec<_> = Role::ALL
            .into_iter()
            .filter(|role| role.scope() == Scope::Tenant)
            .map(Role::as_str)
            .collect();
        let platform: Vec<_> = Role::ALL
            .into_iter()
            .filter(|role| role.scope() == Scope::Platform)
            .map(Role::as_str)
            .collect();
        assert_eq!(tenant, TENANT_ROLES);
        assert_eq!(platform, PLATFORM_ROLES);
        assert_eq!(Role::parse("root"), None);
    }

    const PLATFORM: &str = "wnm_ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    /// Accepts one tenant token and one platform token; reports the store
    /// down for another. Knows the tenants `acme` and `globex`.
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
                    PLATFORM => Ok(Principal {
                        tenant: TenantId::new(PLATFORM_TENANT),
                        actor: Actor::Operator {
                            id: "nora".to_string(),
                        },
                        role: Role::NocOperator,
                    }),
                    "down" => Err(AuthError::Unavailable),
                    _ => Err(AuthError::Rejected),
                }
            })
        }

        fn tenant_registered<'a>(&'a self, tenant: &'a str) -> TenantFuture<'a> {
            Box::pin(async move { Ok(matches!(tenant, "acme" | "globex")) })
        }
    }

    /// `path` with `token` and an optional `Tidegard-Tenant`: the status, and
    /// the tenant the handler saw or the problem's code.
    async fn act(token: &str, path: &str, tenant: Option<&str>) -> (StatusCode, String) {
        let app = Router::new()
            .route(
                "/api/v1/{*rest}",
                get(|Extension(principal): Extension<Principal>| async move {
                    principal.tenant.as_str().to_string()
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                AuthLayerState::new(Arc::new(FakeAuthenticator)),
                require_principal,
            ));
        let mut request = HttpRequest::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(tenant) = tenant {
            request = request.header(TENANT_HEADER, tenant);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(problem) => (status, problem["error"].as_str().unwrap().to_string()),
            Err(_) => (status, body),
        }
    }

    #[tokio::test]
    async fn a_tenant_principal_acts_only_in_its_own_tenant() {
        let incidents = "/api/v1/incidents";
        assert_eq!(
            act(GOOD, incidents, None).await,
            (StatusCode::OK, "acme".into())
        );
        assert_eq!(
            act(GOOD, incidents, Some("acme")).await,
            (StatusCode::OK, "acme".into())
        );
        assert_eq!(
            act(GOOD, incidents, Some("globex")).await,
            (StatusCode::FORBIDDEN, "api.forbidden".into())
        );
        assert_eq!(
            act(GOOD, incidents, Some("nobody")).await,
            (StatusCode::FORBIDDEN, "api.forbidden".into()),
            "a tenant principal learns nothing of other tenants"
        );
    }

    #[tokio::test]
    async fn a_platform_principal_names_a_registered_tenant() {
        let incidents = "/api/v1/incidents";
        assert_eq!(
            act(PLATFORM, incidents, Some("globex")).await,
            (StatusCode::OK, "globex".into())
        );
        assert_eq!(
            act(PLATFORM, incidents, Some(" acme ")).await,
            (StatusCode::OK, "acme".into())
        );
        assert_eq!(
            act(PLATFORM, incidents, None).await,
            (StatusCode::BAD_REQUEST, "api.tenant_required".into())
        );
        for unknown in ["nobody", PLATFORM_TENANT] {
            assert_eq!(
                act(PLATFORM, incidents, Some(unknown)).await,
                (StatusCode::BAD_REQUEST, "api.tenant_unknown".into()),
                "{unknown}"
            );
        }
        assert_eq!(
            act(PLATFORM, incidents, Some("")).await,
            (StatusCode::BAD_REQUEST, "api.invalid_request".into())
        );
        for path in [
            "/api/v1/whoami",
            "/api/v1/session",
            "/api/v1/platform/tenants",
        ] {
            assert_eq!(
                act(PLATFORM, path, None).await,
                (StatusCode::OK, PLATFORM_TENANT.into()),
                "{path} needs no tenant"
            );
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
