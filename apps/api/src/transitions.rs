//! State transitions and safety-relevant field changes (5D-6), adding a
//! note (5D-7), and setting or removing a tag (5D-8).
//!
//! Each is a `POST` action on one incident, never a `PATCH` of `state`
//! (the API plan): a transition has its own permission, its own fields
//! and its own audit entry. Every one:
//!
//! - **Requires `Idempotency-Key`** (16 to 255 characters). A retry with
//!   the same key and body replays the first outcome; the same key with a
//!   different body, or against another incident, is
//!   `409 incident.idempotency_key_reuse`. Keys are scoped to the tenant.
//! - **Requires `expected_version`** in the body. A stale one is
//!   `409 incident.version_conflict`, with `current_version` and
//!   `current_state` so the client can re-read and decide.
//! - **Is decided by the domain.** The handler parses and shapes; the
//!   unit of work checks the permission, the tenant, the state machine and
//!   the field rules (for example, a reason when lowering severity).
//! - **Answers with the incident as it now is,** the same representation
//!   as `GET /api/v1/incidents/{id}`. On a replay that is the current
//!   incident, which may have moved on since the first call.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use utoipa::ToSchema;
use wetechinetmon_incident::assignment::Assignee;
use wetechinetmon_incident::closure::ClosureReason;
use wetechinetmon_incident::command::Command;
use wetechinetmon_incident::id::IncidentId;
use wetechinetmon_incident::idempotency::IdempotencyKey;
use wetechinetmon_incident::incident::NoteVisibility;
use wetechinetmon_incident::severity::{Priority, Severity};
use wetechinetmon_incident_postgres::pool::acquire;
use wetechinetmon_incident_postgres::queries;

use crate::auth::Principal;
use crate::incidents::{limit, parse_id, IncidentView};
use crate::problem::{ErrorCode, Problem};
use crate::time::parse_rfc3339;
use crate::AppState;

pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// The longest suppression the API accepts. The domain refuses only a
/// deadline it cannot represent, so without this bound a suppression a
/// century long would be accepted: indefinite in all but name, which is
/// how a real attack gets missed. Longer quiet periods are re-suppressed
/// deliberately, leaving an audit entry each time.
pub const MAX_SUPPRESSION: Duration = Duration::from_secs(30 * 24 * 3_600);

/// The `Idempotency-Key` header, or the `400` to return.
pub(crate) fn idempotency_key(headers: &HeaderMap) -> Result<IdempotencyKey, Problem> {
    let value = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .ok_or_else(|| {
            Problem::new(ErrorCode::InvalidRequest)
                .with_detail("the Idempotency-Key header is required")
        })?
        .to_str()
        .map_err(|_| {
            Problem::new(ErrorCode::InvalidRequest)
                .with_detail("the Idempotency-Key header must be visible ASCII")
        })?;
    IdempotencyKey::new(value).map_err(|_| {
        Problem::new(ErrorCode::InvalidRequest)
            .with_detail("the Idempotency-Key header must be 16 to 255 characters")
    })
}

/// The shared path of every command: limit, parse, decide, re-read.
async fn apply<T: DeserializeOwned>(
    state: AppState,
    principal: Principal,
    incident_id: String,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    key_required: bool,
    command: impl FnOnce(T) -> Result<Command, Problem>,
) -> Result<IncidentView, Problem> {
    limit(&state.limits.mutations, &principal)?;
    let id = parse_id(&incident_id)?;
    let key = optional_key(&headers, key_required)?;
    let command = command(crate::body::json(&headers, body)?)?;
    execute(&state, &principal, id, key, command).await
}

/// The key when required, or when given although optional.
fn optional_key(headers: &HeaderMap, required: bool) -> Result<Option<IdempotencyKey>, Problem> {
    if required || headers.contains_key(IDEMPOTENCY_KEY_HEADER) {
        idempotency_key(headers).map(Some)
    } else {
        Ok(None)
    }
}

/// Runs one domain command and re-reads the incident.
async fn execute(
    state: &AppState,
    principal: &Principal,
    id: IncidentId,
    key: Option<IdempotencyKey>,
    command: Command,
) -> Result<IncidentView, Problem> {
    {
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool)
            .await
            .map_err(|error| Problem::from(&error))?;
        state
            .incidents
            .handle_command(&mut client, &auth, id, command, key)
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        let incident = queries::get_incident(&mut client, &auth, &id)
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        IncidentView::from_incident(&incident)
    }
}

/// A transition: the key is required, and success is `200`.
async fn run<T: DeserializeOwned>(
    state: AppState,
    principal: Principal,
    incident_id: String,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    command: impl FnOnce(T) -> Result<Command, Problem>,
) -> Response {
    match apply(state, principal, incident_id, headers, body, true, command).await {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// A transition that carries nothing but the version it expects.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionOnly {
    /// The incident's `version` as the caller last read it.
    pub expected_version: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub expected_version: u64,
    pub resolution_note: Option<String>,
}

/// Why an incident is closed.
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClosureReasonValue {
    Resolved,
    FalsePositive,
    Duplicate,
    ExpectedTraffic,
    NoActionRequired,
    /// Requires `detail`.
    Other,
}

impl From<ClosureReasonValue> for ClosureReason {
    fn from(value: ClosureReasonValue) -> Self {
        match value {
            ClosureReasonValue::Resolved => ClosureReason::Resolved,
            ClosureReasonValue::FalsePositive => ClosureReason::FalsePositive,
            ClosureReasonValue::Duplicate => ClosureReason::Duplicate,
            ClosureReasonValue::ExpectedTraffic => ClosureReason::ExpectedTraffic,
            ClosureReasonValue::NoActionRequired => ClosureReason::NoActionRequired,
            ClosureReasonValue::Other => ClosureReason::Other,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseRequest {
    pub expected_version: u64,
    pub closure_reason: ClosureReasonValue,
    pub detail: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReopenRequest {
    pub expected_version: u64,
    pub reason: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SuppressRequest {
    pub expected_version: u64,
    pub reason: String,
    /// RFC 3339 UTC, in the future. Required: an indefinite suppression is
    /// how a real attack gets missed.
    pub expires_at: String,
}

/// Exactly one of `user_id` and `team_id`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AssignRequest {
    pub expected_version: u64,
    pub user_id: Option<String>,
    pub team_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeverityValue {
    Info,
    Minor,
    Major,
    Critical,
}

impl From<SeverityValue> for Severity {
    fn from(value: SeverityValue) -> Self {
        match value {
            SeverityValue::Info => Severity::Info,
            SeverityValue::Minor => Severity::Minor,
            SeverityValue::Major => Severity::Major,
            SeverityValue::Critical => Severity::Critical,
        }
    }
}

/// `reason` is required when lowering severity, optional when raising it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SeverityRequest {
    pub expected_version: u64,
    pub severity: SeverityValue,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
pub enum PriorityValue {
    P1,
    P2,
    P3,
    P4,
}

impl From<PriorityValue> for Priority {
    fn from(value: PriorityValue) -> Self {
        match value {
            PriorityValue::P1 => Priority::P1,
            PriorityValue::P2 => Priority::P2,
            PriorityValue::P3 => Priority::P3,
            PriorityValue::P4 => Priority::P4,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PriorityRequest {
    pub expected_version: u64,
    pub priority: PriorityValue,
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX)
        })
}

/// `expires_at` as a duration from now: in the future, and at most
/// [`MAX_SUPPRESSION`] away.
fn suppression_duration(expires_at: &str, now_micros: i64) -> Result<Duration, Problem> {
    let until = parse_rfc3339(expires_at).ok_or_else(|| {
        Problem::new(ErrorCode::InvalidRequest).with_detail("expires_at is not RFC 3339 UTC")
    })?;
    match u64::try_from(until.saturating_sub(now_micros)) {
        Ok(micros) if micros > 0 => {
            let duration = Duration::from_micros(micros);
            if duration > MAX_SUPPRESSION {
                return Err(Problem::new(ErrorCode::ValidationFailed)
                    .with_detail("expires_at must be at most 30 days away"));
            }
            Ok(duration)
        }
        _ => Err(Problem::new(ErrorCode::ValidationFailed)
            .with_detail("expires_at must be in the future")),
    }
}

fn assignee(request: AssignRequest) -> Result<Command, Problem> {
    let assignee = match (request.user_id, request.team_id) {
        (Some(id), None) => Assignee::User { id },
        (None, Some(id)) => Assignee::Team { id },
        _ => {
            return Err(Problem::new(ErrorCode::InvalidRequest)
                .with_detail("give exactly one of user_id and team_id"))
        }
    };
    Ok(Command::AssignIncident {
        expected_version: request.expected_version,
        assignee,
    })
}

/// One transition endpoint: the handler, its OpenAPI operation, and the
/// mapping from its body to a domain command.
macro_rules! transition {
    ($name:ident, $path:tt, $summary:tt, $request:ident, $command:expr) => {
        #[doc = $summary]
        #[utoipa::path(
            post,
            path = $path,
            tag = "incidents",
            params(
                ("incident_id" = String, Path, description = "The incident's UUID"),
                ("Idempotency-Key" = String, Header, description = "16 to 255 characters; a retry with the same key and body replays the first outcome"),
            ),
            request_body(content = $request, content_type = "application/json"),
            security(("bearer" = [])),
            responses(
                (status = 200, description = "The incident after the change, or the current incident on a replay", body = IncidentView),
                (status = 400, description = "Bad id, header or body, or an unknown field", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 403, description = "The role lacks the permission", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 409, description = "Version conflict, illegal transition, unchanged state or key reuse", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 413, description = "The body is over 64 KiB", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 415, description = "The body is not application/json", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 422, description = "Well-formed but semantically invalid", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
                (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
            )
        )]
        pub async fn $name(
            State(state): State<AppState>,
            Extension(principal): Extension<Principal>,
            Path(incident_id): Path<String>,
            headers: HeaderMap,
            body: Result<Bytes, BytesRejection>,
        ) -> Response {
            run::<$request>(state, principal, incident_id, headers, body, $command).await
        }
    };
}

transition!(
    acknowledge,
    "/api/v1/incidents/{incident_id}/acknowledge",
    "Acknowledges an open incident. Needs `incident.acknowledge`.",
    VersionOnly,
    |r: VersionOnly| Ok(Command::AcknowledgeIncident {
        expected_version: r.expected_version
    })
);

transition!(
    investigate,
    "/api/v1/incidents/{incident_id}/investigate",
    "Begins investigation. Needs `incident.investigate`.",
    VersionOnly,
    |r: VersionOnly| Ok(Command::BeginInvestigation {
        expected_version: r.expected_version
    })
);

transition!(
    monitor,
    "/api/v1/incidents/{incident_id}/monitor",
    "Moves the incident to monitoring. Needs `incident.investigate`.",
    VersionOnly,
    |r: VersionOnly| Ok(Command::MarkMonitoring {
        expected_version: r.expected_version
    })
);

transition!(
    resolve,
    "/api/v1/incidents/{incident_id}/resolve",
    "Resolves the incident. Needs `incident.resolve`.",
    ResolveRequest,
    |r: ResolveRequest| Ok(Command::ResolveIncident {
        expected_version: r.expected_version,
        resolution_note: r.resolution_note,
    })
);

transition!(
    close,
    "/api/v1/incidents/{incident_id}/close",
    "Closes a resolved incident. Needs `incident.close`.",
    CloseRequest,
    |r: CloseRequest| Ok(Command::CloseIncident {
        expected_version: r.expected_version,
        reason: r.closure_reason.into(),
        detail: r.detail,
    })
);

transition!(
    reopen,
    "/api/v1/incidents/{incident_id}/reopen",
    "Reopens a resolved or closed incident. Needs `incident.reopen`.",
    ReopenRequest,
    |r: ReopenRequest| Ok(Command::ReopenIncident {
        expected_version: r.expected_version,
        reason: r.reason,
    })
);

transition!(
    suppress,
    "/api/v1/incidents/{incident_id}/suppress",
    "Suppresses the incident until `expires_at`, at most 30 days away. Needs `incident.suppress`.",
    SuppressRequest,
    |r: SuppressRequest| Ok(Command::SuppressIncident {
        expected_version: r.expected_version,
        duration: suppression_duration(&r.expires_at, now_micros())?,
        reason: r.reason,
    })
);

transition!(
    unsuppress,
    "/api/v1/incidents/{incident_id}/unsuppress",
    "Ends a suppression early. Needs `incident.suppress`.",
    VersionOnly,
    |r: VersionOnly| Ok(Command::UnsuppressIncident {
        expected_version: r.expected_version
    })
);

transition!(
    assign,
    "/api/v1/incidents/{incident_id}/assign",
    "Assigns the incident to one user or one team. Needs `incident.assign`.",
    AssignRequest,
    assignee
);

transition!(
    unassign,
    "/api/v1/incidents/{incident_id}/unassign",
    "Removes the assignment. Needs `incident.assign`.",
    VersionOnly,
    |r: VersionOnly| Ok(Command::UnassignIncident {
        expected_version: r.expected_version
    })
);

transition!(
    severity,
    "/api/v1/incidents/{incident_id}/severity",
    "Changes severity; lowering it needs a `reason`. Needs `incident.severity.change`.",
    SeverityRequest,
    |r: SeverityRequest| Ok(Command::ChangeSeverity {
        expected_version: r.expected_version,
        new_severity: r.severity.into(),
        reason: r.reason,
    })
);

transition!(
    priority,
    "/api/v1/incidents/{incident_id}/priority",
    "Changes priority. Needs `incident.priority.change`.",
    PriorityRequest,
    |r: PriorityRequest| Ok(Command::ChangePriority {
        expected_version: r.expected_version,
        new_priority: r.priority.into(),
    })
);

/// Who may read a note. Only `internal` exists in Phase 5.
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoteVisibilityValue {
    #[default]
    Internal,
    /// Refused with `501 incident.customer_visible_unsupported`.
    CustomerVisible,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteRequest {
    /// Untrusted operator text, stored and returned verbatim.
    pub body: String,
    /// Defaults to `internal`.
    #[serde(default)]
    pub visibility: NoteVisibilityValue,
}

fn note(request: NoteRequest) -> Result<Command, Problem> {
    match request.visibility {
        NoteVisibilityValue::Internal => Ok(Command::AddNote {
            body: request.body,
            visibility: NoteVisibility::Internal,
        }),
        NoteVisibilityValue::CustomerVisible => {
            Err(Problem::new(ErrorCode::CustomerVisibleUnsupported))
        }
    }
}

/// Adds an internal note. Needs `incident.note.create`.
///
/// Notes are append-only and cannot conflict, so neither
/// `expected_version` nor `Idempotency-Key` is required; a key, when
/// given, makes a retry replay instead of adding the note twice.
#[utoipa::path(
    post,
    path = "/api/v1/incidents/{incident_id}/notes",
    tag = "incidents",
    params(
        ("incident_id" = String, Path, description = "The incident's UUID"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional; 16 to 255 characters"),
    ),
    request_body(content = NoteRequest, content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The incident with the note added, or the current incident on a replay", body = IncidentView),
        (status = 400, description = "Bad id, header or body, or an unknown field", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.note.create", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "The note limit is reached, or the key was reused", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 413, description = "The body is over 64 KiB", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 415, description = "The body is not application/json", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "The note is too long", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 501, description = "Customer-visible notes are not available", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn add_note(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(incident_id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    match apply(state, principal, incident_id, headers, body, false, note).await {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteEditRequest {
    /// The replacement text. Untrusted, stored and returned verbatim.
    pub body: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteRedactRequest {
    /// Required, up to 500 characters. Recorded on the audit trail.
    pub reason: String,
}

/// The common part of both note-change endpoints: limit, parse, decide.
async fn note_change<T: DeserializeOwned>(
    state: AppState,
    principal: Principal,
    (incident_id, note_index): (String, String),
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    command: impl FnOnce(u32, T) -> Command,
) -> Result<IncidentView, Problem> {
    limit(&state.limits.mutations, &principal)?;
    let id = parse_id(&incident_id)?;
    let note_index = note_index.parse::<u32>().map_err(|_| {
        Problem::new(ErrorCode::InvalidRequest)
            .with_detail("the note index must be a non-negative integer")
    })?;
    let key = optional_key(&headers, false)?;
    let command = command(note_index, crate::body::json(&headers, body)?);
    execute(&state, &principal, id, key, command).await
}

/// Replaces your own note with new text. Needs `incident.note.create`,
/// and the note must be yours.
///
/// The original stays, marked superseded: `GET .../notes` shows the
/// replacement, and `include_superseded=true` shows both. A note is
/// replaced once; to change the text again, edit the replacement.
#[utoipa::path(
    post,
    path = "/api/v1/incidents/{incident_id}/notes/{note_index}/edit",
    tag = "incidents",
    params(
        ("incident_id" = String, Path, description = "The incident's UUID"),
        ("note_index" = u32, Path, description = "The note to replace"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional; 16 to 255 characters"),
    ),
    request_body(content = NoteEditRequest, content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The incident with the replacement note added", body = IncidentView),
        (status = 400, description = "Bad id, index, header or body, or an unknown field", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.note.create, or the note is someone else's", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "The note limit is reached, or the key was reused", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 413, description = "The body is over 64 KiB", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 415, description = "The body is not application/json", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "No such note, it was already replaced or redacted, or the text is too long", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn edit_note(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(path): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = note_change(
        state,
        principal,
        path,
        headers,
        body,
        |note_index, request: NoteEditRequest| Command::EditNote {
            note_index,
            body: request.body,
        },
    )
    .await;
    match result {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Removes a note's body, keeping the note and the record of who removed
/// it and why. Needs `incident.note.redact` (`noc_lead` and above).
///
/// For words that must go, such as a pasted credential. A replaced note
/// can be redacted too. A note is redacted once.
#[utoipa::path(
    post,
    path = "/api/v1/incidents/{incident_id}/notes/{note_index}/redact",
    tag = "incidents",
    params(
        ("incident_id" = String, Path, description = "The incident's UUID"),
        ("note_index" = u32, Path, description = "The note to redact"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional; 16 to 255 characters"),
    ),
    request_body(content = NoteRedactRequest, content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The incident with the note redacted", body = IncidentView),
        (status = 400, description = "Bad id, index, header or body, or an unknown field", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.note.redact", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "The key was reused", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 415, description = "The body is not application/json", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "No such note, it is already redacted, or the reason is blank or too long", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn redact_note(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(path): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let result = note_change(
        state,
        principal,
        path,
        headers,
        body,
        |note_index, request: NoteRedactRequest| Command::RedactNote {
            note_index,
            reason: request.reason,
        },
    )
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TagRequest {
    /// Up to 256 characters.
    pub value: String,
}

/// The common part of both tag endpoints: limit, parse, decide.
async fn tag_command(
    state: AppState,
    principal: Principal,
    incident_id: String,
    headers: HeaderMap,
    command: impl FnOnce() -> Result<Command, Problem>,
) -> Response {
    let result = async {
        limit(&state.limits.mutations, &principal)?;
        let id = parse_id(&incident_id)?;
        let key = optional_key(&headers, false)?;
        let command = command()?;
        // A tag key arrives in the path, outside the body's NUL check.
        if let Command::AddTag { key: tag, .. } | Command::RemoveTag { key: tag } = &command {
            if tag.contains('\0') {
                return Err(Problem::new(ErrorCode::InvalidRequest)
                    .with_detail("text may not contain a NUL character"));
            }
        }
        execute(&state, &principal, id, key, command).await
    }
    .await;
    match result {
        Ok(view) => Json(view).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// Sets one tag, replacing its value if the key exists. Needs
/// `incident.update`.
///
/// `PUT` is idempotent by definition, so no `expected_version` is
/// required, and `Idempotency-Key` is optional.
#[utoipa::path(
    put,
    path = "/api/v1/incidents/{incident_id}/tags/{key}",
    tag = "incidents",
    params(
        ("incident_id" = String, Path, description = "The incident's UUID"),
        ("key" = String, Path, description = "The tag key, up to 64 characters"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional; 16 to 255 characters"),
    ),
    request_body(content = TagRequest, content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The incident with the tag set", body = IncidentView),
        (status = 400, description = "Bad id, header or body, or an unknown field", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.update", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "The tag limit is reached, or the key was reused", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 415, description = "The body is not application/json", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 422, description = "The key or value is too long", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn set_tag(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((incident_id, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    // Parsed only after the limit and the id, like every other command.
    let content_type = headers.clone();
    tag_command(state, principal, incident_id, headers, move || {
        let request: TagRequest = crate::body::json(&content_type, body)?;
        Ok(Command::AddTag {
            key,
            value: request.value,
        })
    })
    .await
}

/// Removes one tag. Removing a tag that is not set succeeds. Needs
/// `incident.update`.
#[utoipa::path(
    delete,
    path = "/api/v1/incidents/{incident_id}/tags/{key}",
    tag = "incidents",
    params(
        ("incident_id" = String, Path, description = "The incident's UUID"),
        ("key" = String, Path, description = "The tag key"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional; 16 to 255 characters"),
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The incident without the tag", body = IncidentView),
        (status = 400, description = "Bad id or header", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.update", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 409, description = "The key was reused", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn remove_tag(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((incident_id, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    tag_command(state, principal, incident_id, headers, move || {
        Ok(Command::RemoveTag { key })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn the_idempotency_key_is_required_and_bounded() {
        let mut headers = HeaderMap::new();
        assert!(idempotency_key(&headers).is_err());
        headers.insert(IDEMPOTENCY_KEY_HEADER, HeaderValue::from_static("short"));
        assert!(idempotency_key(&headers).is_err());
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("0192f3c4-retry-key-01"),
        );
        assert!(idempotency_key(&headers).is_ok());
    }

    #[test]
    fn a_suppression_must_end_in_the_future() {
        let now = 1_700_000_000_000_000;
        assert_eq!(
            suppression_duration("2023-11-14T23:13:20Z", now).unwrap(),
            Duration::from_secs(3_600)
        );
        for past in ["2023-11-14T22:13:20Z", "2023-11-14T21:00:00Z"] {
            assert_eq!(
                suppression_duration(past, now).unwrap_err().code(),
                ErrorCode::ValidationFailed
            );
        }
        // 30 days is accepted, a moment more is not.
        assert!(suppression_duration("2023-12-14T22:13:20Z", now).is_ok());
        assert_eq!(
            suppression_duration("2023-12-14T22:13:21Z", now)
                .unwrap_err()
                .code(),
            ErrorCode::ValidationFailed
        );
        assert_eq!(
            suppression_duration("tomorrow", now).unwrap_err().code(),
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn assignment_takes_exactly_one_assignee() {
        let request = |user: Option<&str>, team: Option<&str>| AssignRequest {
            expected_version: 1,
            user_id: user.map(String::from),
            team_id: team.map(String::from),
        };
        assert!(assignee(request(Some("u1"), None)).is_ok());
        assert!(assignee(request(None, Some("t1"))).is_ok());
        assert!(assignee(request(None, None)).is_err());
        assert!(assignee(request(Some("u1"), Some("t1"))).is_err());
    }
}
