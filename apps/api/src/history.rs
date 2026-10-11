//! An incident's history: timeline, notes, detections and audit (5D-5).
//!
//! Each is a sub-resource of one incident, read under the same rules as
//! the incident itself:
//!
//! - **The incident must be in the caller's tenant.** Otherwise it is
//!   `404 incident.not_found`, whatever the sub-resource.
//! - **The permission is checked by the read service.** Timeline, notes
//!   and detections need `incident.read`; audit needs `incident.audit.read`
//!   and has its own, tighter limit.
//! - **Unbounded histories are keyset-paginated,** oldest first. Notes are
//!   bounded by the domain and returned whole.
//! - **Stored JSON is returned as stored.** A timeline entry's values, an
//!   audit record's before and after, a detection's matched reasons and
//!   rates: the API does not reinterpret them.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Serialize;
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use wetechinetmon_incident_postgres::pool::acquire;
use wetechinetmon_incident_postgres::queries::{
    self, AuditRow, DetectionLinkRow, TimelineEntryRow,
};
use wetechinetmon_incident_postgres::row::{IncidentRow, NoteRow};

use crate::auth::Principal;
use crate::incidents::{limit, parse_id};
use crate::problem::{ErrorCode, Problem};
use crate::time::rfc3339;
use crate::AppState;

pub const DEFAULT_HISTORY_PAGE: u32 = 100;
pub const MAX_HISTORY_PAGE: u32 = 500;

/// Paging parameters for a history.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub struct HistoryParams {
    /// 1 to 500; default 100. Larger values are capped at 500.
    limit: Option<u32>,
    /// `next_cursor` from the previous page.
    cursor: Option<String>,
}

struct Paging {
    cursor: Option<String>,
    limit: u32,
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(ErrorCode::InvalidRequest).with_detail(detail)
}

fn paging(pairs: &[(String, String)]) -> Result<Paging, Problem> {
    let mut paging = Paging {
        cursor: None,
        limit: DEFAULT_HISTORY_PAGE,
    };
    let (mut saw_limit, mut saw_cursor) = (false, false);
    for (name, value) in pairs {
        match name.as_str() {
            "limit" if !std::mem::replace(&mut saw_limit, true) => {
                let size: u32 = value
                    .parse()
                    .ok()
                    .filter(|size| *size > 0)
                    .ok_or_else(|| invalid("limit is a positive integer"))?;
                paging.limit = size.min(MAX_HISTORY_PAGE);
            }
            "cursor" if !std::mem::replace(&mut saw_cursor, true) => {
                paging.cursor = Some(value.clone());
            }
            "limit" | "cursor" => return Err(invalid(format!("'{name}' may appear once"))),
            other => {
                return Err(Problem::new(ErrorCode::UnknownField)
                    .with_detail(format!("unknown query parameter '{other}'")))
            }
        }
    }
    Ok(paging)
}

/// A numeric cursor: the last id seen.
fn id_cursor(cursor: &Option<String>) -> Result<Option<i64>, Problem> {
    cursor
        .as_deref()
        .map(|text| {
            text.parse::<i64>()
                .ok()
                .filter(|id| *id >= 0)
                .ok_or_else(|| invalid("the cursor is not valid for this request"))
        })
        .transpose()
}

/// A detection cursor: `<detected micros>.<event id>`.
fn detection_cursor(cursor: &Option<String>) -> Result<Option<(i64, String)>, Problem> {
    cursor
        .as_deref()
        .map(|text| {
            text.split_once('.')
                .and_then(|(micros, id)| Some((micros.parse::<i64>().ok()?, id.to_string())))
                .filter(|(_, id)| !id.is_empty())
                .ok_or_else(|| invalid("the cursor is not valid for this request"))
        })
        .transpose()
}

fn json(text: Option<String>) -> Option<Value> {
    text.map(|text| serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

pub(crate) fn actor(actor_type: &str, actor_id: Option<String>) -> String {
    match (actor_type, actor_id) {
        ("system", _) => "system:correlator".to_string(),
        ("operator", Some(id)) => id,
        (kind, Some(id)) => format!("{kind}:{id}"),
        (kind, None) => kind.to_string(),
    }
}

/// One timeline entry.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimelineEntryView {
    /// Increasing within the incident; also the paging cursor.
    pub timeline_id: String,
    pub occurred_at: String,
    pub entry_type: String,
    pub actor: String,
    pub correlation_id: Option<String>,
    pub command_id: Option<String>,
    pub source_event_id: Option<String>,
    pub previous_value: Option<Value>,
    pub new_value: Option<Value>,
    pub payload: Value,
    pub schema_version: i32,
}

impl From<TimelineEntryRow> for TimelineEntryView {
    fn from(row: TimelineEntryRow) -> Self {
        TimelineEntryView {
            timeline_id: row.timeline_id.to_string(),
            occurred_at: rfc3339(row.occurred_at),
            entry_type: row.entry_type,
            actor: actor(&row.actor_type, row.actor_id),
            correlation_id: row.correlation_id,
            command_id: row.command_id,
            source_event_id: row.source_event_id,
            previous_value: json(row.previous_value),
            new_value: json(row.new_value),
            payload: json(Some(row.payload)).unwrap_or(Value::Null),
            schema_version: row.schema_version,
        }
    }
}

/// One audit record.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditEntryView {
    pub audit_id: String,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    /// allowed, denied, error.
    pub result: String,
    pub reason: Option<String>,
    pub request_id: Option<String>,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

impl From<AuditRow> for AuditEntryView {
    fn from(row: AuditRow) -> Self {
        AuditEntryView {
            audit_id: row.audit_id.to_string(),
            occurred_at: rfc3339(row.occurred_at),
            actor: actor(&row.actor_type, row.actor_id),
            action: row.action,
            result: row.result,
            reason: row.reason,
            request_id: row.request_id,
            before: json(row.before),
            after: json(row.after),
        }
    }
}

/// One detection event linked to the incident.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DetectionView {
    pub detection_event_id: String,
    pub detection_id: String,
    pub policy_id: String,
    pub policy_version: i32,
    /// started, updated, ended.
    pub kind: String,
    pub severity: String,
    /// opening, update, closing, late, evidence.
    pub link_type: String,
    pub detected_at: String,
    pub observed_at: String,
    pub matched: Value,
    pub rates: Value,
}

impl From<DetectionLinkRow> for DetectionView {
    fn from(row: DetectionLinkRow) -> Self {
        DetectionView {
            detection_event_id: row.detection_event_id,
            detection_id: row.detection_id,
            policy_id: row.policy_id,
            policy_version: row.policy_version,
            kind: row.kind,
            severity: row.severity,
            link_type: row.link_type,
            detected_at: rfc3339(row.detected_at),
            observed_at: rfc3339(row.observed_at),
            matched: json(Some(row.matched)).unwrap_or(Value::Null),
            rates: json(Some(row.rates)).unwrap_or(Value::Null),
        }
    }
}

/// One note.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct NoteView {
    /// Position within the incident's notes.
    pub note_index: i32,
    pub author: String,
    /// Untrusted operator text, returned verbatim: escape it on output.
    /// Empty once the note is redacted.
    pub body: String,
    /// internal or customer_visible.
    pub visibility: String,
    /// The note this one replaces, when it is an edit.
    pub supersedes_note_index: Option<i32>,
    /// The edit that replaced this note, if any.
    pub superseded_by_note_index: Option<i32>,
    /// The body was removed. Who did it, and why, is on the audit trail.
    pub redacted: bool,
}

/// The notes as the API shows them. A superseded note is left out
/// unless `include_superseded`, so the default view is the current text.
pub fn note_views(notes: Vec<NoteRow>, include_superseded: bool) -> Vec<NoteView> {
    let replaced_by: std::collections::BTreeMap<i32, i32> = notes
        .iter()
        .filter_map(|note| note.supersedes.map(|earlier| (earlier, note.note_index)))
        .collect();
    notes
        .into_iter()
        .map(|note| NoteView {
            superseded_by_note_index: replaced_by.get(&note.note_index).copied(),
            note_index: note.note_index,
            author: actor(&note.created_by.actor_type, note.created_by.actor_id),
            body: note.body,
            visibility: note.visibility,
            supersedes_note_index: note.supersedes,
            redacted: note.redaction.is_some(),
        })
        .filter(|view| include_superseded || view.superseded_by_note_index.is_none())
        .collect()
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TimelinePage {
    pub items: Vec<TimelineEntryView>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditPage {
    pub items: Vec<AuditEntryView>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DetectionPage {
    pub items: Vec<DetectionView>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct NoteList {
    pub items: Vec<NoteView>,
}

async fn respond<T: Serialize>(result: Result<T, Problem>) -> Response {
    match result {
        Ok(body) => Json(body).into_response(),
        Err(problem) => problem.into_response(),
    }
}

/// An incident's timeline, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/incidents/{incident_id}/timeline",
    tag = "incidents",
    params(("incident_id" = String, Path, description = "The incident's UUID"), HistoryParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of timeline entries", body = TimelinePage),
        (status = 400, description = "Bad id, parameter or cursor", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn timeline(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(incident_id): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    respond(
        async {
            limit(&state.limits.reads, &principal)?;
            let id = parse_id(&incident_id)?;
            let paging = paging(&pairs)?;
            let after = id_cursor(&paging.cursor)?;
            let auth = principal.authorization(state.resolver.as_ref());
            let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
            let page = queries::timeline(&mut client, &auth, &id, after, paging.limit)
                .await
                .map_err(|e| Problem::from(&e))?
                .map_err(|e| Problem::from(&e))?;
            let next_cursor = page
                .has_more
                .then(|| page.items.last().map(|e| e.timeline_id.to_string()))
                .flatten();
            Ok(TimelinePage {
                items: page.items.into_iter().map(Into::into).collect(),
                next_cursor,
                has_more: page.has_more,
            })
        }
        .await,
    )
    .await
}

/// An incident's audit records, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/incidents/{incident_id}/audit",
    tag = "incidents",
    params(("incident_id" = String, Path, description = "The incident's UUID"), HistoryParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of audit records", body = AuditPage),
        (status = 400, description = "Bad id, parameter or cursor", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.audit.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited (30/min)", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn audit(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(incident_id): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    respond(
        async {
            limit(&state.limits.audit, &principal)?;
            let id = parse_id(&incident_id)?;
            let paging = paging(&pairs)?;
            let after = id_cursor(&paging.cursor)?;
            let auth = principal.authorization(state.resolver.as_ref());
            let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
            let page = queries::audit(&mut client, &auth, &id, after, paging.limit)
                .await
                .map_err(|e| Problem::from(&e))?
                .map_err(|e| Problem::from(&e))?;
            let next_cursor = page
                .has_more
                .then(|| page.items.last().map(|e| e.audit_id.to_string()))
                .flatten();
            Ok(AuditPage {
                items: page.items.into_iter().map(Into::into).collect(),
                next_cursor,
                has_more: page.has_more,
            })
        }
        .await,
    )
    .await
}

/// The detection events linked to an incident, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/incidents/{incident_id}/detections",
    tag = "incidents",
    params(("incident_id" = String, Path, description = "The incident's UUID"), HistoryParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of linked detection events", body = DetectionPage),
        (status = 400, description = "Bad id, parameter or cursor", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn detections(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(incident_id): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    respond(
        async {
            limit(&state.limits.reads, &principal)?;
            let id = parse_id(&incident_id)?;
            let paging = paging(&pairs)?;
            let after = detection_cursor(&paging.cursor)?;
            let auth = principal.authorization(state.resolver.as_ref());
            let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
            let page = queries::detections(&mut client, &auth, &id, after, paging.limit)
                .await
                .map_err(|e| Problem::from(&e))?
                .map_err(|e| Problem::from(&e))?;
            let next_cursor = page
                .has_more
                .then(|| {
                    page.items
                        .last()
                        .map(|e| format!("{}.{}", e.detected_at, e.detection_event_id))
                })
                .flatten();
            Ok(DetectionPage {
                items: page.items.into_iter().map(Into::into).collect(),
                next_cursor,
                has_more: page.has_more,
            })
        }
        .await,
    )
    .await
}

/// An incident's notes. Bounded by the domain, so never paginated.
/// Notes an edit replaced are left out unless `include_superseded=true`.
#[utoipa::path(
    get,
    path = "/api/v1/incidents/{incident_id}/notes",
    tag = "incidents",
    params(
        ("incident_id" = String, Path, description = "The incident's UUID"),
        ("include_superseded" = Option<bool>, Query, description = "Also return the notes an edit replaced. Defaults to false"),
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The current notes, or every note with include_superseded", body = NoteList),
        (status = 400, description = "Bad id or an unknown parameter", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn notes(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(incident_id): Path<String>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    respond(
        async {
            limit(&state.limits.reads, &principal)?;
            let id = parse_id(&incident_id)?;
            let mut include_superseded = false;
            for (name, value) in &pairs {
                match (name.as_str(), value.as_str()) {
                    ("include_superseded", "true") => include_superseded = true,
                    ("include_superseded", "false") => include_superseded = false,
                    ("include_superseded", _) => {
                        return Err(Problem::new(ErrorCode::InvalidRequest)
                            .with_detail("include_superseded must be true or false"))
                    }
                    _ => {
                        return Err(Problem::new(ErrorCode::UnknownField)
                            .with_detail(format!("unknown query parameter '{name}'")))
                    }
                }
            }
            let auth = principal.authorization(state.resolver.as_ref());
            let mut client = acquire(&state.pool).await.map_err(|e| Problem::from(&e))?;
            let incident = queries::get_incident(&mut client, &auth, &id)
                .await
                .map_err(|e| Problem::from(&e))?
                .map_err(|e| Problem::from(&e))?;
            let row = IncidentRow::from_incident(&incident).map_err(|e| Problem::from(&e))?;
            Ok(NoteList {
                items: note_views(row.notes, include_superseded),
            })
        }
        .await,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn paging_defaults_caps_and_refuses() {
        let default = paging(&[]).unwrap();
        assert_eq!(default.limit, DEFAULT_HISTORY_PAGE);
        assert_eq!(
            paging(&pairs(&[("limit", "9999")])).unwrap().limit,
            MAX_HISTORY_PAGE
        );
        assert!(paging(&pairs(&[("limit", "0")])).is_err());
        assert!(paging(&pairs(&[("limit", "5"), ("limit", "6")])).is_err());
        assert_eq!(
            paging(&pairs(&[("sort", "x")])).err().unwrap().code(),
            ErrorCode::UnknownField
        );
    }

    #[test]
    fn cursors_parse_or_are_refused() {
        assert_eq!(id_cursor(&Some("42".into())).unwrap(), Some(42));
        assert!(id_cursor(&Some("-1".into())).is_err());
        assert!(id_cursor(&Some("x".into())).is_err());
        assert_eq!(
            detection_cursor(&Some("1700.det-1-2".into())).unwrap(),
            Some((1700, "det-1-2".to_string()))
        );
        assert!(detection_cursor(&Some("1700.".into())).is_err());
        assert!(detection_cursor(&Some("nope".into())).is_err());
    }

    #[test]
    fn stored_json_is_passed_through_and_actors_are_rendered() {
        assert_eq!(
            json(Some("{\"state\":\"open\"}".into())).unwrap()["state"],
            "open"
        );
        assert_eq!(json(None), None);
        assert_eq!(actor("system", None), "system:correlator");
        assert_eq!(actor("operator", Some("alice".into())), "alice");
        assert_eq!(
            actor("service_account", Some("ci".into())),
            "service_account:ci"
        );
    }
}
