//! RFC 9457 problem details with stable error codes (ADR 0038, gate 7).
//!
//! - **`error` is the contract.** Every code the API can emit is an
//!   [`ErrorCode`], and [`ErrorCode::ALL`] is the registry that
//!   `docs/api/error-codes.md` must match (a test checks it). A published
//!   code is never reused for another meaning.
//! - **Nothing internal leaks.** A `500` carries only `api.internal` and the
//!   request id. Another tenant's incident is `incident.not_found`, never
//!   `incident.tenant_mismatch`, so a caller cannot learn that it exists.
//! - **`request_id`** comes from the request-id middleware through a task
//!   local, so every problem body, however deep it was built, names the
//!   request it answers.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};
use tidegard_incident::error::IncidentError;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::mitigation::MitigationStoreError;
use tidegard_mitigation::{GuardRefusal, MitigationError};

use crate::request_id;

pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";
const TYPE_BASE: &str = "https://logixhare.com/tidegard/problems/";

macro_rules! error_codes {
    ($($variant:ident => ($code:literal, $status:literal, $title:literal),)+) => {
        /// Every error code the API emits.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum ErrorCode { $($variant,)+ }

        impl ErrorCode {
            /// The registry: every code, in documentation order.
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant,)+];

            /// The stable, machine-readable code.
            pub const fn code(self) -> &'static str {
                match self { $(ErrorCode::$variant => $code,)+ }
            }

            pub fn status(self) -> StatusCode {
                let status = match self { $(ErrorCode::$variant => $status,)+ };
                StatusCode::from_u16(status).expect("registry statuses are valid")
            }

            /// A short human title. Clients must not switch on it.
            pub const fn title(self) -> &'static str {
                match self { $(ErrorCode::$variant => $title,)+ }
            }
        }
    };
}

error_codes! {
    Unauthenticated => ("api.unauthenticated", 401, "Authentication required"),
    Forbidden => ("api.forbidden", 403, "Permission denied"),
    CsrfRejected => ("api.csrf_rejected", 403, "CSRF check failed"),
    NotFound => ("api.not_found", 404, "Not found"),
    MethodNotAllowed => ("api.method_not_allowed", 405, "Method not allowed"),
    InvalidRequest => ("api.invalid_request", 400, "Invalid request"),
    UnknownField => ("api.unknown_field", 400, "Unknown field"),
    UnsupportedMediaType => ("api.unsupported_media_type", 415, "Unsupported media type"),
    PayloadTooLarge => ("api.payload_too_large", 413, "Payload too large"),
    RateLimited => ("api.rate_limited", 429, "Rate limit exceeded"),
    Unavailable => ("api.unavailable", 503, "Service unavailable"),
    Internal => ("api.internal", 500, "Internal error"),
    TenantRequired => ("api.tenant_required", 400, "Tenant required"),
    TenantUnknown => ("api.tenant_unknown", 400, "Unknown tenant"),
    IncidentNotFound => ("incident.not_found", 404, "Incident not found"),
    IllegalTransition => ("incident.illegal_transition", 409, "Illegal state transition"),
    VersionConflict => ("incident.version_conflict", 409, "Version conflict"),
    IdempotencyKeyReuse => ("incident.idempotency_key_reuse", 409, "Idempotency key reused"),
    IncidentForbidden => ("incident.forbidden", 403, "Permission denied"),
    ValidationFailed => ("incident.validation_failed", 422, "Validation failed"),
    LimitReached => ("incident.limit_reached", 409, "Limit reached"),
    DuplicateActive => ("incident.duplicate_active", 409, "An active incident already exists"),
    InvalidReopen => ("incident.invalid_reopen", 409, "Incident cannot be reopened"),
    ManualClosureRequired => ("incident.manual_closure_required", 409, "Manual closure required"),
    SuppressedOperation => ("incident.suppressed_operation", 409, "Incident is suppressed"),
    EvidenceUnavailable => ("incident.evidence_unavailable", 422, "Evidence unavailable"),
    StateUnchanged => ("incident.state_unchanged", 409, "State unchanged"),
    ClockSkew => ("incident.clock_skew", 503, "Clock skew; retry"),
    CorrelationConflict => ("incident.correlation_conflict", 409, "Correlation conflict"),
    CustomerVisibleUnsupported => ("incident.customer_visible_unsupported", 501, "Customer-visible notes are not available"),
    MitigationNotFound => ("mitigation.not_found", 404, "Mitigation not found"),
    MitigationForbidden => ("mitigation.forbidden", 403, "Permission denied"),
    MitigationIllegalTransition => ("mitigation.illegal_transition", 409, "Illegal mitigation transition"),
    MitigationSelfApproval => ("mitigation.self_approval", 403, "Cannot approve your own mitigation"),
    MitigationInvalid => ("mitigation.invalid", 422, "Invalid mitigation"),
    MitigationDuplicate => ("mitigation.duplicate", 409, "A live mitigation already does this"),
    MitigationVersionConflict => ("mitigation.version_conflict", 409, "Version conflict"),
    MitigationIdempotencyKeyReuse => ("mitigation.idempotency_key_reuse", 409, "Idempotency key reused"),
    MitigationKillSwitch => ("mitigation.kill_switch", 409, "The kill switch is on"),
    MitigationNotAllowlisted => ("mitigation.not_allowlisted", 403, "Not on the allowlist"),
    MitigationActionNotAllowed => ("mitigation.action_not_allowed", 403, "Action not allowed on this prefix"),
    MitigationTooWide => ("mitigation.too_wide", 422, "Prefix too wide"),
    MitigationTooLong => ("mitigation.too_long", 422, "Duration too long"),
    TenantNotFound => ("tenant.not_found", 404, "Tenant not found"),
    TenantExists => ("tenant.exists", 409, "Tenant already exists"),
    TenantInvalid => ("tenant.invalid", 422, "Invalid tenant"),
    PrefixOverlap => ("tenant.prefix_overlap", 409, "Prefix overlaps a registered prefix"),
    PrefixNotFound => ("tenant.prefix_not_found", 404, "Prefix not found"),
    TokenNotFound => ("token.not_found", 404, "Token not found"),
    TokenInvalid => ("token.invalid", 422, "Invalid token request"),
}

impl ErrorCode {
    /// `https://logixhare.com/tidegard/problems/` and the code with `.` and `_` as `-`.
    pub fn type_uri(self) -> String {
        format!("{TYPE_BASE}{}", self.code().replace(['.', '_'], "-"))
    }
}

/// One problem-details response.
#[derive(Debug, Clone)]
pub struct Problem {
    code: ErrorCode,
    detail: Option<String>,
    extensions: Map<String, Value>,
    retry_after_secs: Option<u64>,
}

impl Problem {
    pub fn new(code: ErrorCode) -> Self {
        Problem {
            code,
            detail: None,
            extensions: Map::new(),
            retry_after_secs: None,
        }
    }

    /// Human detail. Never include another tenant's data or internal state.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// An extension member, such as `current_version`.
    pub fn with(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.extensions.insert(name.to_string(), value.into());
        self
    }

    /// Adds `Retry-After`, in whole seconds, rounded up.
    pub fn retry_after(mut self, secs: u64) -> Self {
        self.retry_after_secs = Some(secs.max(1));
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The JSON body, with the current request's id.
    pub fn body(&self) -> Value {
        let mut body = Map::new();
        body.insert("type".into(), self.code.type_uri().into());
        body.insert("title".into(), self.code.title().into());
        body.insert("status".into(), self.code.status().as_u16().into());
        if let Some(detail) = &self.detail {
            body.insert("detail".into(), detail.clone().into());
        }
        body.insert("error".into(), self.code.code().into());
        if let Some(id) = request_id::current() {
            body.insert("request_id".into(), id.into());
        }
        for (name, value) in &self.extensions {
            body.entry(name.clone()).or_insert_with(|| value.clone());
        }
        Value::Object(body)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self.body()).expect("a JSON object always serializes");
        let mut response = (self.code.status(), body).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
        );
        if let Some(secs) = self.retry_after_secs {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        if self.code == ErrorCode::Unauthenticated {
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

impl From<&IncidentError> for Problem {
    fn from(error: &IncidentError) -> Self {
        use IncidentError as E;
        let code = match error {
            // Another tenant's incident is indistinguishable from none.
            E::NotFound | E::TenantMismatch => ErrorCode::IncidentNotFound,
            E::InvalidTransition { .. } => ErrorCode::IllegalTransition,
            E::VersionConflict { .. } => ErrorCode::VersionConflict,
            E::IdempotencyConflict => ErrorCode::IdempotencyKeyReuse,
            E::Unauthorized => ErrorCode::IncidentForbidden,
            E::ValidationError(_) => ErrorCode::ValidationFailed,
            E::CapacityExceeded(_) => ErrorCode::LimitReached,
            E::DuplicateActiveIncident(_) => ErrorCode::DuplicateActive,
            E::InvalidReopen(_) => ErrorCode::InvalidReopen,
            E::ManualClosureRequired => ErrorCode::ManualClosureRequired,
            E::SuppressedOperation => ErrorCode::SuppressedOperation,
            E::EvidenceUnavailable => ErrorCode::EvidenceUnavailable,
            E::StateUnchanged(_) => ErrorCode::StateUnchanged,
            E::ClockSkew { .. } => ErrorCode::ClockSkew,
            E::Correlation(_) => ErrorCode::CorrelationConflict,
            // Internal faults: the code says only that something broke.
            E::InternalInvariantViolation(_) | E::CorruptSnapshot { .. } => ErrorCode::Internal,
        };
        let problem = Problem::new(code);
        match (code, error) {
            (ErrorCode::ValidationFailed, E::ValidationError(detail)) => {
                problem.with_detail(detail.clone())
            }
            (
                ErrorCode::VersionConflict,
                E::VersionConflict {
                    expected,
                    current,
                    current_state,
                },
            ) => problem
                .with("expected_version", *expected)
                .with("current_version", *current)
                .with("current_state", current_state.as_str()),
            // Same tenant by construction: the key includes the tenant.
            (ErrorCode::DuplicateActive, E::DuplicateActiveIncident(existing)) => {
                problem.with("incident_id", existing.to_canonical_string())
            }
            (ErrorCode::ClockSkew, _) => problem.retry_after(1),
            _ => problem,
        }
    }
}

impl From<&MitigationStoreError> for Problem {
    fn from(error: &MitigationStoreError) -> Self {
        match error {
            MitigationStoreError::Mitigation(error) => Problem::from(error),
            MitigationStoreError::IdempotencyMismatch => {
                Problem::new(ErrorCode::MitigationIdempotencyKeyReuse)
            }
            MitigationStoreError::Persist(PersistError::IdempotencyKeyTaken) => {
                Problem::new(ErrorCode::MitigationIdempotencyKeyReuse)
            }
            MitigationStoreError::Persist(error) => Problem::from(error),
        }
    }
}

impl From<&MitigationError> for Problem {
    fn from(error: &MitigationError) -> Self {
        let code = match error {
            MitigationError::Forbidden(_) => ErrorCode::MitigationForbidden,
            MitigationError::NotFound => ErrorCode::MitigationNotFound,
            MitigationError::IllegalTransition { .. } => ErrorCode::MitigationIllegalTransition,
            MitigationError::SelfApproval => ErrorCode::MitigationSelfApproval,
            MitigationError::Invalid(_) => ErrorCode::MitigationInvalid,
            MitigationError::Duplicate => ErrorCode::MitigationDuplicate,
            MitigationError::VersionConflict(_) => ErrorCode::MitigationVersionConflict,
            MitigationError::Refused(refusal) => match refusal {
                GuardRefusal::KillSwitch => ErrorCode::MitigationKillSwitch,
                GuardRefusal::NotAllowlisted(_) => ErrorCode::MitigationNotAllowlisted,
                GuardRefusal::ActionNotAllowed(..) => ErrorCode::MitigationActionNotAllowed,
                GuardRefusal::TooWide(..) => ErrorCode::MitigationTooWide,
                GuardRefusal::TooLong(_) => ErrorCode::MitigationTooLong,
            },
        };
        let problem = Problem::new(code);
        match error {
            // The detail names the rule or the field, never another tenant.
            MitigationError::Invalid(_)
            | MitigationError::Refused(_)
            | MitigationError::IllegalTransition { .. } => problem.with_detail(error.to_string()),
            MitigationError::VersionConflict(current) => problem.with("current_version", *current),
            _ => problem,
        }
    }
}

impl From<&PersistError> for Problem {
    fn from(error: &PersistError) -> Self {
        match error {
            PersistError::Rejected(domain) => Problem::from(domain),
            PersistError::VersionConflict { .. } => Problem::new(ErrorCode::VersionConflict),
            PersistError::IdempotencyKeyTaken => Problem::new(ErrorCode::IdempotencyKeyReuse),
            // The API fails closed when the database is unreachable.
            PersistError::Unavailable(_) => Problem::new(ErrorCode::Unavailable).retry_after(5),
            _ => Problem::new(ErrorCode::Internal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn codes_are_unique_and_namespaced() {
        let mut seen = HashSet::new();
        for code in ErrorCode::ALL {
            assert!(seen.insert(code.code()), "duplicate {}", code.code());
            assert!(
                code.code().starts_with("api.")
                    || code.code().starts_with("incident.")
                    || code.code().starts_with("mitigation.")
                    || code.code().starts_with("tenant.")
                    || code.code().starts_with("token."),
                "{}",
                code.code()
            );
        }
    }

    #[test]
    fn the_registry_document_lists_every_code_with_its_status() {
        let document = include_str!("../../../docs/api/error-codes.md");
        for code in ErrorCode::ALL {
            let row = format!("| `{}` | {} |", code.code(), code.status().as_u16());
            assert!(document.contains(&row), "error-codes.md lacks {row}");
        }
    }

    #[test]
    fn another_tenants_incident_is_plain_not_found() {
        let problem = Problem::from(&IncidentError::TenantMismatch);
        assert_eq!(problem.code(), ErrorCode::IncidentNotFound);
        let body = problem.body();
        assert_eq!(body["status"], 404);
        assert!(!body.to_string().contains("tenant"));
    }

    #[test]
    fn internal_faults_say_nothing_more() {
        let problem = Problem::from(&IncidentError::InternalInvariantViolation(
            "secret internals",
        ));
        assert_eq!(problem.code(), ErrorCode::Internal);
        assert!(!problem.body().to_string().contains("secret"));
        let unavailable = Problem::from(&PersistError::Unavailable("host=db".to_string()));
        assert_eq!(unavailable.code(), ErrorCode::Unavailable);
        assert!(!unavailable.body().to_string().contains("host=db"));
    }

    #[test]
    fn the_body_has_the_rfc_9457_members_and_the_code() {
        let response = Problem::new(ErrorCode::RateLimited)
            .retry_after(3)
            .into_response();
        assert_eq!(response.status(), 429);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            PROBLEM_CONTENT_TYPE
        );
        assert_eq!(response.headers()[header::RETRY_AFTER], "3");
        let body = Problem::new(ErrorCode::VersionConflict)
            .with("current_version", 8)
            .body();
        assert_eq!(
            body["type"],
            "https://logixhare.com/tidegard/problems/incident-version-conflict"
        );
        assert_eq!(body["error"], "incident.version_conflict");
        assert_eq!(body["status"], 409);
        assert_eq!(body["current_version"], 8);
    }

    #[test]
    fn an_extension_cannot_overwrite_a_standard_member() {
        let body = Problem::new(ErrorCode::NotFound)
            .with("status", 200)
            .with("error", "spoofed")
            .body();
        assert_eq!(body["status"], 404);
        assert_eq!(body["error"], "api.not_found");
    }
}
