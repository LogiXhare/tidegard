//! Browser sessions for the NOC UI (ADR 0043).
//!
//! - **Sign-in exchanges a token for a session.** The id is new and random
//!   every time, whatever cookie the request carried (no fixation). Only
//!   its SHA-256 is stored, in `api_sessions` (V18).
//! - **A session lives no longer than its token**, 30 minutes idle and
//!   12 hours in all. Every lookup reads the token, so revoking it ends
//!   its sessions.
//! - **The cookie is `HttpOnly` and `SameSite=Strict`**, and `Secure`
//!   whenever the API serves TLS.
//! - **CSRF:** a cookie-authenticated request that changes anything must
//!   carry `X-WNM-CSRF`, a value derived from the session id that only
//!   the page can learn. Nothing about it is stored.
//! - **No session id, CSRF value or token is ever logged.**

use std::net::IpAddr;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tidegard_incident::authorization::Actor;
use tidegard_incident_postgres::pool::acquire;
use utoipa::ToSchema;

use crate::auth::{is_well_formed, token_hash, Principal, Role};
use crate::problem::{ErrorCode, Problem};
use crate::time::rfc3339;
use crate::AppState;

pub const COOKIE_NAME: &str = "wnm_session";
pub const CSRF_HEADER: &str = "x-wnm-csrf";
const SESSION_PREFIX: &str = "wns_";
const SECRET_BYTES: usize = 32;
const SESSION_LEN: usize = SESSION_PREFIX.len() + SECRET_BYTES * 2;
/// A session unused this long is refused.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// A session ends this long after sign-in, used or not.
pub const ABSOLUTE_LIFETIME: Duration = Duration::from_secs(12 * 3_600);
/// `last_seen_at` is written at most this often per session.
pub const TOUCH_INTERVAL: Duration = Duration::from_secs(60);

/// A new session id: `wns_` and 64 hex characters from the OS CSPRNG.
pub fn generate_session_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes)?;
    let mut id = String::with_capacity(SESSION_LEN);
    id.push_str(SESSION_PREFIX);
    for byte in bytes {
        id.push_str(&format!("{byte:02x}"));
    }
    Ok(id)
}

/// Shape only; says nothing about whether the session exists.
pub fn is_well_formed_session(id: &str) -> bool {
    id.len() == SESSION_LEN
        && id.starts_with(SESSION_PREFIX)
        && id[SESSION_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What is stored and looked up.
pub fn session_hash(id: &str) -> Vec<u8> {
    Sha256::digest(id.as_bytes()).to_vec()
}

/// The CSRF value for a session: derivable only from the id, which the
/// page's JavaScript never sees.
pub fn csrf_token(id: &str) -> String {
    csrf_value(b"tidegard csrf\0", id)
}

/// The value v0.9.0 gave the same session, before the rename (ADR 0058).
/// Still accepted through 1.x, so a page left open across the upgrade
/// keeps working.
fn legacy_csrf_token(id: &str) -> String {
    csrf_value(b"wetechinetmon csrf\0", id)
}

fn csrf_value(separator: &[u8], id: &str) -> String {
    let digest = Sha256::new()
        .chain_update(separator)
        .chain_update(id.as_bytes())
        .finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether `presented` is the session's CSRF value, current or from
/// before the rename.
pub fn csrf_matches(id: &str, presented: &str) -> bool {
    constant_time_eq(&csrf_token(id), presented)
        | constant_time_eq(&legacy_csrf_token(id), presented)
}

/// Compares without stopping at the first difference.
fn constant_time_eq(expected: &str, presented: &str) -> bool {
    expected.len() == presented.len()
        && expected
            .bytes()
            .zip(presented.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// The session id from the `Cookie` header, if there is exactly one.
pub fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        for pair in value.to_str().ok()?.split(';') {
            if let Some(id) = pair
                .trim()
                .strip_prefix(COOKIE_NAME)
                .and_then(|rest| rest.strip_prefix('='))
            {
                if found.is_some() {
                    return None;
                }
                found = Some(id.trim());
            }
        }
    }
    found
}

/// A request that may change state needs the CSRF header.
pub fn needs_csrf(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn cookie(id: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{COOKIE_NAME}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        ABSOLUTE_LIFETIME.as_secs()
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn expired_cookie(secure: bool) -> String {
    let mut cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// What the middleware learned from a session cookie, for the handlers.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub id: String,
    pub token_id: String,
}

/// An identity event for the audit trail.
pub struct SessionEvent<'a> {
    pub action: &'static str,
    pub principal: &'a Principal,
    pub token_id: &'a str,
    pub allowed: bool,
    pub reason: Option<&'static str>,
    pub source: Option<IpAddr>,
}

const AUDIT: &str = "\
INSERT INTO incident_audit (
    tenant_id, schema_version, actor_type, actor_id, action, resource_type, resource_id,
    result, reason, source_ip
) VALUES ($1, 1, $2, $3, $4, 'session', $5, $6, $7, $8::text::inet)";

/// Writes `event` to `incident_audit`. A failure is logged, never
/// surfaced: the request it describes has already been decided.
pub async fn record(pool: &deadpool_postgres::Pool, event: SessionEvent<'_>) {
    let (actor_type, actor_id) = match &event.principal.actor {
        Actor::Operator { id } => ("operator", id.as_str()),
        Actor::ServiceAccount { id } => ("service_account", id.as_str()),
        // A token never carries these (ADR 0038).
        Actor::System | Actor::Platform { .. } => return,
    };
    let result = if event.allowed { "allowed" } else { "denied" };
    let source = event.source.map(|ip| ip.to_string());
    let written = async {
        let client = acquire(pool).await.map_err(|error| error.to_string())?;
        client
            .execute(
                AUDIT,
                &[
                    &event.principal.tenant.as_str(),
                    &actor_type,
                    &actor_id,
                    &event.action,
                    &event.token_id,
                    &result,
                    &event.reason,
                    &source,
                ],
            )
            .await
            .map_err(|error| error.to_string())
    }
    .await;
    if let Err(error) = written {
        tracing::warn!(action = event.action, error = %error, "a session audit entry could not be written");
    }
}

const TOKEN_FOR_SIGN_IN: &str = "\
SELECT token_id::text AS token_id, tenant_id, actor_type, actor_id, role,
    least(expires_at, transaction_timestamp() + $2::bigint * interval '1 second') AS session_expires
FROM api_tokens
WHERE token_hash = $1
  AND revoked_at IS NULL
  AND expires_at > transaction_timestamp()";

const CREATE: &str = "\
INSERT INTO api_sessions (session_hash, token_id, expires_at)
VALUES ($1, $2::text::uuid, $3)";

const DELETE: &str = "DELETE FROM api_sessions WHERE session_hash = $1";

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignIn {
    /// An API token, `wnm_` and 64 hex characters. Used once, never stored
    /// by the browser.
    pub token: String,
}

/// The session, as the page needs it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SessionView {
    /// Send this in `X-WNM-CSRF` on every request that changes anything.
    pub csrf_token: String,
    /// When the session ends at the latest, RFC 3339 UTC.
    pub expires_at: String,
    /// The session ends after this many seconds without a request.
    pub idle_timeout_seconds: u64,
    pub tenant_id: String,
    pub actor_id: String,
    pub role: &'static str,
}

fn actor_id(actor: &Actor) -> String {
    match actor {
        Actor::Operator { id } | Actor::ServiceAccount { id } | Actor::Platform { id } => {
            id.clone()
        }
        Actor::System => String::new(),
    }
}

fn source_of(request: &Request) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ConnectInfo<crate::server::PeerAddr>>()
        .map(|info| info.0 .0.ip())
}

/// Signs in with an API token and answers with a session cookie. The
/// token goes in the body, never a header a proxy might log.
#[utoipa::path(
    post,
    path = "/api/v1/session",
    tag = "identity",
    request_body(content = SignIn, content_type = "application/json"),
    responses(
        (status = 201, description = "Signed in; the session cookie is set", body = SessionView),
        (status = 400, description = "A bad body or an unknown field", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "The token is unknown, expired or revoked", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 415, description = "The body is not application/json", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Too many failed sign-ins from this address", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn sign_in(State(state): State<AppState>, request: Request) -> Response {
    let source = source_of(&request);
    let key = source.unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let now = std::time::Instant::now();
    if let Err(refusal) = state.auth.failures.peek(&key, now) {
        return Problem::new(ErrorCode::RateLimited)
            .retry_after(refusal.retry_after_secs())
            .into_response();
    }
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, crate::BODY_LIMIT_BYTES)
        .await
        .map_err(|_| Problem::new(ErrorCode::PayloadTooLarge));
    let result = async {
        let body: Bytes = body?;
        let sign_in: SignIn = crate::body::json(
            &parts.headers,
            Ok::<Bytes, axum::extract::rejection::BytesRejection>(body),
        )?;
        let rejected = || {
            let _ = state.auth.failures.check(&key, now);
            tracing::info!(source = ?source, "a sign-in was refused");
            Problem::new(ErrorCode::Unauthenticated)
        };
        if !is_well_formed(&sign_in.token) {
            return Err(rejected());
        }
        let client = acquire(&state.pool)
            .await
            .map_err(|_| Problem::new(ErrorCode::Unavailable).retry_after(5))?;
        let lifetime = ABSOLUTE_LIFETIME.as_secs() as i64;
        let row = client
            .query_opt(TOKEN_FOR_SIGN_IN, &[&token_hash(&sign_in.token), &lifetime])
            .await
            .map_err(|_| Problem::new(ErrorCode::Unavailable).retry_after(5))?
            .ok_or_else(rejected)?;
        let actor_id: String = row.get("actor_id");
        let actor = match row.get::<_, String>("actor_type").as_str() {
            "operator" => Actor::Operator { id: actor_id },
            "service_account" => Actor::ServiceAccount { id: actor_id },
            _ => return Err(rejected()),
        };
        let role = Role::parse(row.get::<_, &str>("role")).ok_or_else(rejected)?;
        let principal = Principal {
            tenant: tidegard_incident::correlation::TenantId::new(
                row.get::<_, String>("tenant_id"),
            ),
            actor,
            role,
        };
        let token_id: String = row.get("token_id");
        let expires: std::time::SystemTime = row.get("session_expires");
        let id = generate_session_id().map_err(|_| Problem::new(ErrorCode::Internal))?;
        client
            .execute(CREATE, &[&session_hash(&id), &token_id, &expires])
            .await
            .map_err(|_| Problem::new(ErrorCode::Unavailable).retry_after(5))?;
        drop(client);
        record(
            &state.pool,
            SessionEvent {
                action: "session.create",
                principal: &principal,
                token_id: &token_id,
                allowed: true,
                reason: None,
                source,
            },
        )
        .await;
        let view = view(&id, &principal, expires);
        Ok::<_, Problem>((id, view))
    }
    .await;
    match result {
        Ok((id, view)) => {
            let mut response = (StatusCode::CREATED, Json(view)).into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie(&id, state.secure_cookies))
                    .expect("a session cookie is ASCII"),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(problem) => problem.into_response(),
    }
}

fn view(id: &str, principal: &Principal, expires: std::time::SystemTime) -> SessionView {
    let micros = expires
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as i64);
    SessionView {
        csrf_token: csrf_token(id),
        expires_at: rfc3339(micros),
        idle_timeout_seconds: IDLE_TIMEOUT.as_secs(),
        tenant_id: principal.tenant.as_str().to_string(),
        actor_id: actor_id(&principal.actor),
        role: principal.role.as_str(),
    }
}

const EXPIRY: &str = "SELECT expires_at FROM api_sessions WHERE session_hash = $1";

/// The current session, so a reloaded page can learn its CSRF value.
/// Only a session cookie has one; a bearer token gets `404`.
#[utoipa::path(
    get,
    path = "/api/v1/session",
    tag = "identity",
    responses(
        (status = 200, description = "The current session", body = SessionView),
        (status = 401, description = "No usable session", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "The request was not made with a session", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn current(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return Problem::new(ErrorCode::NotFound).into_response();
    };
    let result = async {
        let client = acquire(&state.pool)
            .await
            .map_err(|_| Problem::new(ErrorCode::Unavailable).retry_after(5))?;
        let expires: std::time::SystemTime = client
            .query_opt(EXPIRY, &[&session_hash(&session.id)])
            .await
            .map_err(|_| Problem::new(ErrorCode::Unavailable).retry_after(5))?
            .ok_or_else(|| Problem::new(ErrorCode::Unauthenticated))?
            .get("expires_at");
        Ok::<_, Problem>(view(&session.id, &principal, expires))
    }
    .await;
    match result {
        Ok(view) => {
            let mut response = Json(view).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(problem) => problem.into_response(),
    }
}

/// Signs out: the session ends now, and the cookie is cleared. Needs the
/// CSRF header, like every cookie request that changes anything.
#[utoipa::path(
    delete,
    path = "/api/v1/session",
    tag = "identity",
    params(("X-WNM-CSRF" = String, Header, description = "The session's CSRF value")),
    responses(
        (status = 204, description = "Signed out"),
        (status = 401, description = "No usable session", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The CSRF header is missing or wrong", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "The request was not made with a session", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn sign_out(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    session: Option<Extension<SessionContext>>,
    request: Request,
) -> Response {
    let Some(Extension(session)) = session else {
        return Problem::new(ErrorCode::NotFound).into_response();
    };
    let source = source_of(&request);
    let deleted = async {
        let client = acquire(&state.pool).await.ok()?;
        client
            .execute(DELETE, &[&session_hash(&session.id)])
            .await
            .ok()
    }
    .await;
    if deleted.is_none() {
        return Problem::new(ErrorCode::Unavailable)
            .retry_after(5)
            .into_response();
    }
    record(
        &state.pool,
        SessionEvent {
            action: "session.delete",
            principal: &principal,
            token_id: &session.token_id,
            allowed: true,
            reason: None,
            source,
        },
    )
    .await;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&expired_cookie(state.secure_cookies)).expect("a cookie is ASCII"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_are_well_formed_distinct_and_hashed() {
        let a = generate_session_id().unwrap();
        let b = generate_session_id().unwrap();
        assert!(is_well_formed_session(&a), "{a}");
        assert_ne!(a, b);
        assert_eq!(session_hash(&a).len(), 32);
        assert!(!is_well_formed_session(&a.replace("wns_", "wnm_")));
        assert!(!is_well_formed_session(&a.to_uppercase()));
        assert!(!is_well_formed_session(&a[..a.len() - 1]));
    }

    #[test]
    fn the_csrf_value_belongs_to_one_session() {
        let a = generate_session_id().unwrap();
        let b = generate_session_id().unwrap();
        assert!(csrf_matches(&a, &csrf_token(&a)));
        assert!(!csrf_matches(&a, &csrf_token(&b)));
        assert!(!csrf_matches(&a, ""));
        assert!(!csrf_matches(&a, &a));
        assert_eq!(csrf_token(&a).len(), 64);
        // A page left open across the upgrade from v0.9.0 still works,
        // for its own session only.
        assert!(csrf_matches(&a, &legacy_csrf_token(&a)));
        assert!(!csrf_matches(&a, &legacy_csrf_token(&b)));
        assert_ne!(legacy_csrf_token(&a), csrf_token(&a));
    }

    #[test]
    fn the_cookie_is_http_only_strict_and_secure_with_tls() {
        let with_tls = cookie("wns_x", true);
        for attribute in [
            "HttpOnly",
            "SameSite=Strict",
            "Path=/",
            "Secure",
            "Max-Age=43200",
        ] {
            assert!(with_tls.contains(attribute), "{with_tls}");
        }
        assert!(!cookie("wns_x", false).contains("Secure"));
        assert!(expired_cookie(true).contains("Max-Age=0"));
    }

    #[test]
    fn exactly_one_session_cookie_is_read() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; wnm_session=wns_abc"),
        );
        assert_eq!(session_cookie(&headers), Some("wns_abc"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("wnm_session=wns_a; wnm_session=wns_b"),
        );
        assert_eq!(session_cookie(&headers), None, "ambiguous is refused");
        headers.insert(header::COOKIE, HeaderValue::from_static("wnm_sessionx=1"));
        assert_eq!(session_cookie(&headers), None);
    }

    #[test]
    fn only_safe_methods_skip_the_csrf_header() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!needs_csrf(&method));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(needs_csrf(&method));
        }
    }
}
