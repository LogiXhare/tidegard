//! `POST /api/v1/incidents/{id}/export`: one incident and its whole
//! history as a single JSON document (5D-10).
//!
//! - **Needs `incident.export`.** The audit section is included only for a
//!   caller who also holds `incident.audit.read`, and is `null` otherwise.
//! - **Audited before it is read.** An export carries an incident's whole
//!   history out of the system, so the audit entry is committed first: an
//!   export that fails afterwards is still on record, and none leaves
//!   unrecorded. That side effect is why this is a `POST`.
//! - **One snapshot.** The sections are read in one repeatable-read
//!   transaction, so they agree with each other.
//! - **Bounded.** Each history carries at most [`EXPORT_MAX_ROWS`]
//!   entries; `truncated` says which were cut short. Exports have their
//!   own, tighter rate limit.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Serialize;
use tidegard_incident_postgres::pool::acquire;
use tidegard_incident_postgres::queries;
use tidegard_incident_postgres::row::IncidentRow;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::history::{note_views, AuditEntryView, DetectionView, NoteView, TimelineEntryView};
use crate::incidents::{actor_text, limit, parse_id, IncidentView};
use crate::problem::Problem;
use crate::time::rfc3339;
use crate::AppState;

/// The most entries each history section carries.
pub const EXPORT_MAX_ROWS: u32 = 5_000;
/// The value of `format`, so a reader can recognise the document.
pub const EXPORT_FORMAT: &str = "tidegard.incident-export";
/// Raised on any change a reader must notice.
pub const EXPORT_FORMAT_VERSION: u32 = 1;

/// Which sections were cut short at [`EXPORT_MAX_ROWS`].
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Truncation {
    pub timeline: bool,
    pub detections: bool,
    pub audit: bool,
}

/// One incident and its history.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IncidentExport {
    /// Always `tidegard.incident-export`.
    pub format: &'static str,
    pub format_version: u32,
    pub exported_at: String,
    pub exported_by: String,
    pub incident: IncidentView,
    pub timeline: Vec<TimelineEntryView>,
    pub notes: Vec<NoteView>,
    pub detections: Vec<DetectionView>,
    /// `null` unless the caller holds `incident.audit.read`.
    pub audit: Option<Vec<AuditEntryView>>,
    pub truncated: Truncation,
}

/// `WNM-2026-000123` stays as it is; anything else becomes `-`, so the
/// header can never carry a quote or a path.
fn file_name(incident_number: &str) -> String {
    let safe: String = incident_number
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("attachment; filename=\"{safe}.json\"")
}

/// Exports one incident. Needs `incident.export`.
#[utoipa::path(
    post,
    path = "/api/v1/incidents/{incident_id}/export",
    tag = "incidents",
    params(("incident_id" = String, Path, description = "The incident's UUID")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The export, as an attachment", body = IncidentExport),
        (status = 400, description = "The id is not a UUID", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.export", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "No such incident in the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn export(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(incident_id): Path<String>,
) -> Response {
    let result = async {
        limit(&state.limits.exports, &principal)?;
        let id = parse_id(&incident_id)?;
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool)
            .await
            .map_err(|error| Problem::from(&error))?;
        // Recorded first, so no export leaves unaudited.
        state
            .incidents
            .record_export(&mut client, &auth, id)
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        let bundle = queries::export(&mut client, &auth, &id, EXPORT_MAX_ROWS)
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        let row = IncidentRow::from_incident(&bundle.incident).map_err(|e| Problem::from(&e))?;
        // The whole chain: an export is the record, edits included.
        let notes = note_views(row.notes, true);
        let exported_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX)
            });
        Ok::<_, Problem>(IncidentExport {
            format: EXPORT_FORMAT,
            format_version: EXPORT_FORMAT_VERSION,
            exported_at: rfc3339(exported_at),
            exported_by: actor_text(&principal.actor),
            incident: IncidentView::from_incident(&bundle.incident)?
                .with_statuses(&**client)
                .await?,
            truncated: Truncation {
                timeline: bundle.timeline.has_more,
                detections: bundle.detections.has_more,
                audit: bundle.audit.as_ref().is_some_and(|page| page.has_more),
            },
            timeline: bundle.timeline.items.into_iter().map(Into::into).collect(),
            notes,
            detections: bundle
                .detections
                .items
                .into_iter()
                .map(Into::into)
                .collect(),
            audit: bundle
                .audit
                .map(|page| page.items.into_iter().map(Into::into).collect()),
        })
    }
    .await;
    match result {
        Ok(document) => {
            let disposition = file_name(&document.incident.incident_number);
            let mut response = Json(document).into_response();
            if let Ok(value) = HeaderValue::from_str(&disposition) {
                response
                    .headers_mut()
                    .insert(header::CONTENT_DISPOSITION, value);
            }
            response
        }
        Err(problem) => problem.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_name_cannot_escape_its_quotes() {
        assert_eq!(
            file_name("WNM-2026-000123"),
            "attachment; filename=\"WNM-2026-000123.json\""
        );
        assert_eq!(
            file_name("a\"b/../c\r\n"),
            "attachment; filename=\"a-b----c--.json\""
        );
    }
}
