//! `GET /api/v1/incidents`: filtered, keyset-paginated, tenant-scoped.
//!
//! The rules come from the API design ([incident-api-plan.md](../../../docs/architecture/incident-api-plan.md)):
//!
//! - **Allowlisted parameters.** An unknown parameter, an unknown filter
//!   value or an undocumented sort is `400`, never ignored.
//! - **Cursor, never offset.** A cursor is opaque and records the tenant,
//!   the sort and the position. One from another tenant, or for another
//!   sort, is refused. Cursors are not signed: every query is
//!   tenant-scoped in SQL, so an edited cursor can only move within the
//!   caller's own incidents.
//! - **Bounded.** The page size defaults to 50 and is capped at 200
//!   server-side whatever is asked. A time range is at most 90 days.
//!   `include_total=true` counts, and is charged twice against the
//!   caller's read limit, because counting is the expensive part.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use tidegard_incident_postgres::pool::acquire;
use tidegard_incident_postgres::queries::{self, IncidentSummary, ListFilter, ListSort, SortOrder};
use utoipa::{IntoParams, ToSchema};

use crate::auth::Principal;
use crate::incidents::limit;
use crate::problem::{ErrorCode, Problem};
use crate::time::{parse_rfc3339, rfc3339};
use crate::AppState;

pub const DEFAULT_PAGE_SIZE: u32 = 50;
pub const MAX_PAGE_SIZE: u32 = 200;
/// The widest `opened_from`..`opened_to` range, in microseconds.
pub const MAX_RANGE_MICROS: i64 = 90 * 24 * 3_600 * 1_000_000;

const STATES: &[&str] = &[
    "open",
    "acknowledged",
    "investigating",
    "monitoring",
    "recovering",
    "resolved",
    "closed",
];
const SEVERITIES: &[&str] = &["info", "minor", "major", "critical"];
const PRIORITIES: &[&str] = &["P1", "P2", "P3", "P4"];
const DIRECTIONS: &[&str] = &["incoming", "outgoing", "internal", "other", "unknown"];
const TARGET_TYPES: &[&str] = &["host", "network", "hostgroup"];

/// The documented query parameters, for the OpenAPI document. Parsing is
/// done by hand from the raw pairs, because `state`, `severity` and
/// `priority` repeat.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub struct ListParams {
    /// Repeatable. open, acknowledged, investigating, monitoring, recovering, resolved, closed.
    state: Option<Vec<String>>,
    /// Repeatable. info, minor, major, critical.
    severity: Option<Vec<String>>,
    /// Repeatable. P1, P2, P3, P4.
    priority: Option<Vec<String>>,
    /// incoming, outgoing, internal, other, unknown.
    direction: Option<String>,
    /// host, network, hostgroup.
    target_type: Option<String>,
    /// Exact, such as `WNM-2026-000123`.
    incident_number: Option<String>,
    /// RFC 3339 UTC, inclusive. Needs `opened_to`; at most 90 days apart.
    opened_from: Option<String>,
    /// RFC 3339 UTC, exclusive.
    opened_to: Option<String>,
    /// opened_at (default) or last_detected_at.
    sort: Option<String>,
    /// desc (default) or asc.
    order: Option<String>,
    /// 1 to 200; default 50. Larger values are capped at 200.
    limit: Option<u32>,
    /// `next_cursor` from the previous page.
    cursor: Option<String>,
    /// `true` to count every match; charged twice against the read limit.
    include_total: Option<bool>,
}

/// One incident in a list.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IncidentSummaryView {
    pub incident_id: String,
    pub incident_number: String,
    pub title: String,
    pub state: String,
    pub severity: String,
    pub priority: String,
    pub category: String,
    pub direction: String,
    pub address_family: i16,
    pub target_type: String,
    pub target_id: String,
    pub opened_at: String,
    pub last_detected_at: String,
    pub last_updated_at: String,
    pub assigned_user_id: Option<String>,
    pub assigned_team_id: Option<String>,
    pub version: i64,
}

impl From<IncidentSummary> for IncidentSummaryView {
    fn from(s: IncidentSummary) -> Self {
        let (assigned_user_id, assigned_team_id) = match (s.assigned_kind.as_deref(), s.assigned_id)
        {
            (Some("user"), id) => (id, None),
            (Some("team"), id) => (None, id),
            _ => (None, None),
        };
        IncidentSummaryView {
            incident_id: s.incident_id,
            incident_number: s.incident_number,
            title: s.title,
            state: s.state,
            severity: s.severity,
            priority: s.priority,
            category: s.category,
            direction: s.direction,
            address_family: s.address_family,
            target_type: s.target_type,
            target_id: s.target_id,
            opened_at: rfc3339(s.opened_at),
            last_detected_at: rfc3339(s.last_detected_at),
            last_updated_at: rfc3339(s.last_updated_at),
            assigned_user_id,
            assigned_team_id,
            version: s.version,
        }
    }
}

/// A page of incidents.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IncidentPage {
    pub items: Vec<IncidentSummaryView>,
    /// Pass as `cursor` for the next page; `null` on the last.
    pub next_cursor: Option<String>,
    pub has_more: bool,
    /// Every match, only with `include_total=true`.
    pub total: Option<i64>,
}

/// What a cursor records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Cursor {
    /// Format version.
    v: u8,
    /// Tenant.
    t: String,
    /// Sort column.
    s: String,
    /// Order.
    o: String,
    /// Sort key, microseconds.
    k: i64,
    /// Incident id.
    i: String,
}

fn encode_cursor(cursor: &Cursor) -> String {
    let json = serde_json::to_vec(cursor).expect("a cursor serializes");
    json.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_cursor(text: &str) -> Option<Cursor> {
    if !text.len().is_multiple_of(2) || text.len() > 2_048 {
        return None;
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    serde_json::from_slice(&bytes).ok()
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(ErrorCode::InvalidRequest).with_detail(detail)
}

fn one_of(name: &str, value: &str, allowed: &[&str]) -> Result<String, Problem> {
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(invalid(format!("'{value}' is not a valid {name}")))
    }
}

/// The request, validated against the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest {
    pub filter: ListFilter,
    pub include_total: bool,
}

/// Parses the raw query pairs. `tenant` binds the cursor.
pub fn parse(pairs: &[(String, String)], tenant: &str) -> Result<ListRequest, Problem> {
    let mut filter = ListFilter {
        states: Vec::new(),
        severities: Vec::new(),
        priorities: Vec::new(),
        direction: None,
        target_type: None,
        incident_number: None,
        opened_between: None,
        sort: ListSort::OpenedAt,
        order: SortOrder::Desc,
        after: None,
        limit: DEFAULT_PAGE_SIZE,
    };
    let (mut from, mut to, mut cursor, mut include_total) = (None, None, None, false);
    let single = |seen: &mut bool, name: &str| -> Result<(), Problem> {
        if std::mem::replace(seen, true) {
            Err(invalid(format!("'{name}' may appear once")))
        } else {
            Ok(())
        }
    };
    let mut seen = std::collections::HashMap::<&'static str, bool>::new();
    for (name, value) in pairs {
        match name.as_str() {
            "state" => filter.states.push(one_of("state", value, STATES)?),
            "severity" => filter
                .severities
                .push(one_of("severity", value, SEVERITIES)?),
            "priority" => filter
                .priorities
                .push(one_of("priority", value, PRIORITIES)?),
            "direction" => {
                single(seen.entry("direction").or_default(), name)?;
                filter.direction = Some(one_of("direction", value, DIRECTIONS)?);
            }
            "target_type" => {
                single(seen.entry("target_type").or_default(), name)?;
                filter.target_type = Some(one_of("target_type", value, TARGET_TYPES)?);
            }
            "incident_number" => {
                single(seen.entry("incident_number").or_default(), name)?;
                let well_formed = !value.is_empty()
                    && value.len() <= 32
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-');
                if !well_formed {
                    return Err(invalid("incident_number is not an incident number"));
                }
                filter.incident_number = Some(value.clone());
            }
            "opened_from" => {
                single(seen.entry("opened_from").or_default(), name)?;
                from = Some(
                    parse_rfc3339(value)
                        .ok_or_else(|| invalid("opened_from is not RFC 3339 UTC"))?,
                );
            }
            "opened_to" => {
                single(seen.entry("opened_to").or_default(), name)?;
                to = Some(
                    parse_rfc3339(value).ok_or_else(|| invalid("opened_to is not RFC 3339 UTC"))?,
                );
            }
            "sort" => {
                single(seen.entry("sort").or_default(), name)?;
                filter.sort = ListSort::parse(value)
                    .ok_or_else(|| invalid(format!("'{value}' is not a sortable field")))?;
            }
            "order" => {
                single(seen.entry("order").or_default(), name)?;
                filter.order =
                    SortOrder::parse(value).ok_or_else(|| invalid("order is asc or desc"))?;
            }
            "limit" => {
                single(seen.entry("limit").or_default(), name)?;
                let size: u32 = value
                    .parse()
                    .ok()
                    .filter(|size| *size > 0)
                    .ok_or_else(|| invalid("limit is a positive integer"))?;
                filter.limit = size.min(MAX_PAGE_SIZE);
            }
            "cursor" => {
                single(seen.entry("cursor").or_default(), name)?;
                cursor = Some(value.clone());
            }
            "include_total" => {
                single(seen.entry("include_total").or_default(), name)?;
                include_total = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return Err(invalid("include_total is true or false")),
                };
            }
            other => {
                return Err(Problem::new(ErrorCode::UnknownField)
                    .with_detail(format!("unknown query parameter '{other}'")))
            }
        }
    }
    filter.opened_between = match (from, to) {
        (None, None) => None,
        (Some(from), Some(to)) if from < to && to - from <= MAX_RANGE_MICROS => Some((from, to)),
        (Some(_), Some(_)) => {
            return Err(invalid(
                "opened_from must be before opened_to, at most 90 days apart",
            ))
        }
        _ => return Err(invalid("opened_from and opened_to go together")),
    };
    if let Some(text) = cursor {
        let cursor = decode_cursor(&text)
            .filter(|c| {
                c.v == 1
                    && c.t == tenant
                    && c.s == filter.sort.as_str()
                    && c.o == filter.order.as_str()
            })
            .ok_or_else(|| invalid("the cursor is not valid for this request"))?;
        filter.after = Some((cursor.k, cursor.i));
    }
    Ok(ListRequest {
        filter,
        include_total,
    })
}

/// The caller's tenant's incidents, newest first by default.
#[utoipa::path(
    get,
    path = "/api/v1/incidents",
    tag = "incidents",
    params(ListParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of incidents", body = IncidentPage),
        (status = 400, description = "An unknown parameter or value, a bad range or cursor", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks incident.list", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "The database is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn list_incidents(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let result = async {
        limit(&state.limits.reads, &principal)?;
        let request = parse(&pairs, principal.tenant.as_str())?;
        if request.include_total {
            limit(&state.limits.reads, &principal)?;
        }
        let auth = principal.authorization(state.resolver.as_ref());
        let mut client = acquire(&state.pool)
            .await
            .map_err(|error| Problem::from(&error))?;
        let page = queries::list_incidents(&mut client, &auth, &request.filter)
            .await
            .map_err(|error| Problem::from(&error))?
            .map_err(|error| Problem::from(&error))?;
        let total = if request.include_total {
            Some(
                queries::count_incidents(&mut client, &auth, &request.filter)
                    .await
                    .map_err(|error| Problem::from(&error))?
                    .map_err(|error| Problem::from(&error))?,
            )
        } else {
            None
        };
        let next_cursor = match (page.has_more, page.items.last()) {
            (true, Some(last)) => Some(encode_cursor(&Cursor {
                v: 1,
                t: principal.tenant.as_str().to_string(),
                s: request.filter.sort.as_str().to_string(),
                o: request.filter.order.as_str().to_string(),
                k: last.sort_key(request.filter.sort),
                i: last.incident_id.clone(),
            })),
            _ => None,
        };
        Ok::<_, Problem>(IncidentPage {
            items: page
                .items
                .into_iter()
                .map(IncidentSummaryView::from)
                .collect(),
            next_cursor,
            has_more: page.has_more,
            total,
        })
    }
    .await;
    match result {
        Ok(page) => Json(page).into_response(),
        Err(problem) => problem.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn error(result: Result<ListRequest, Problem>) -> &'static str {
        result.expect_err("refused").code().code()
    }

    #[test]
    fn defaults_are_newest_first_fifty_per_page() {
        let request = parse(&[], "acme").unwrap();
        assert_eq!(request.filter.sort, ListSort::OpenedAt);
        assert_eq!(request.filter.order, SortOrder::Desc);
        assert_eq!(request.filter.limit, DEFAULT_PAGE_SIZE);
        assert!(!request.include_total);
    }

    #[test]
    fn repeated_filters_accumulate_and_the_page_size_is_capped() {
        let request = parse(
            &pairs(&[
                ("state", "open"),
                ("state", "acknowledged"),
                ("severity", "critical"),
                ("limit", "10000"),
            ]),
            "acme",
        )
        .unwrap();
        assert_eq!(request.filter.states, ["open", "acknowledged"]);
        assert_eq!(request.filter.severities, ["critical"]);
        assert_eq!(request.filter.limit, MAX_PAGE_SIZE);
    }

    #[test]
    fn unknown_parameters_values_and_sorts_are_refused() {
        assert_eq!(
            error(parse(&pairs(&[("tenant", "globex")]), "acme")),
            "api.unknown_field"
        );
        assert_eq!(
            error(parse(&pairs(&[("state", "deleted")]), "acme")),
            "api.invalid_request"
        );
        assert_eq!(
            error(parse(&pairs(&[("sort", "title")]), "acme")),
            "api.invalid_request"
        );
        assert_eq!(
            error(parse(&pairs(&[("limit", "0")]), "acme")),
            "api.invalid_request"
        );
        assert_eq!(
            error(parse(
                &pairs(&[("sort", "opened_at"), ("sort", "opened_at")]),
                "acme"
            )),
            "api.invalid_request"
        );
    }

    #[test]
    fn time_ranges_are_paired_ordered_and_bounded() {
        let ok = parse(
            &pairs(&[
                ("opened_from", "2026-08-01T00:00:00Z"),
                ("opened_to", "2026-09-01T00:00:00Z"),
            ]),
            "acme",
        )
        .unwrap();
        assert!(ok.filter.opened_between.is_some());
        for range in [
            vec![("opened_from", "2026-08-01T00:00:00Z")],
            vec![
                ("opened_from", "2026-09-01T00:00:00Z"),
                ("opened_to", "2026-08-01T00:00:00Z"),
            ],
            vec![
                ("opened_from", "2026-01-01T00:00:00Z"),
                ("opened_to", "2026-09-01T00:00:00Z"),
            ],
            vec![
                ("opened_from", "yesterday"),
                ("opened_to", "2026-09-01T00:00:00Z"),
            ],
        ] {
            assert_eq!(
                error(parse(&pairs(&range), "acme")),
                "api.invalid_request",
                "{range:?}"
            );
        }
    }

    #[test]
    fn a_cursor_only_works_for_its_tenant_and_sort() {
        let cursor = encode_cursor(&Cursor {
            v: 1,
            t: "acme".into(),
            s: "opened_at".into(),
            o: "desc".into(),
            k: 42,
            i: "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d".into(),
        });
        let resumed = parse(&pairs(&[("cursor", &cursor)]), "acme").unwrap();
        assert_eq!(
            resumed.filter.after,
            Some((42, "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d".to_string()))
        );
        assert_eq!(
            error(parse(&pairs(&[("cursor", &cursor)]), "globex")),
            "api.invalid_request"
        );
        assert_eq!(
            error(parse(
                &pairs(&[("cursor", &cursor), ("order", "asc")]),
                "acme"
            )),
            "api.invalid_request"
        );
        assert_eq!(
            error(parse(&pairs(&[("cursor", "zz")]), "acme")),
            "api.invalid_request"
        );
    }
}
