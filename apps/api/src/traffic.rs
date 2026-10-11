//! Deployment-wide traffic for the NOC UI (ADR 0042).
//!
//! The traffic tables carry no tenant until Phase 8 (R21). So only the one
//! configured traffic tenant may read them: every other tenant gets `404`,
//! decided before anything is read, and the caller's role must also hold
//! `traffic.read`. Queries are fixed text with server-side parameters; a
//! dimension picks a query from an allowlist, never a fragment of SQL.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use wetechinetmon_incident::authorization::Permission;
use wetechinetmon_incident::correlation::TenantId;

use crate::auth::Principal;
use crate::clickhouse::{ClickHouse, ClickHouseError};
use crate::incidents::limit;
use crate::problem::{ErrorCode, Problem};
use crate::time::{parse_rfc3339, rfc3339};
use crate::AppState;

/// ClickHouse keeps traffic for 30 days, so a longer range reads nothing more.
pub const MAX_RANGE_SECONDS: i64 = 30 * 24 * 3_600;
/// A summary has at most this many points, whatever the range.
pub const MAX_POINTS: i64 = 500;
/// The finest step: no detection window is shorter.
pub const MIN_STEP_SECONDS: i64 = 10;
const DEFAULT_RANGE_SECONDS: i64 = 3_600;
pub const MAX_TOP: usize = 50;
const DEFAULT_TOP: usize = 10;
/// An exporter's rate is measured over this many seconds.
const EXPORTER_RATE_WINDOW: u64 = 300;

/// Where traffic comes from, and the one tenant allowed to read it.
pub struct TrafficSource {
    pub tenant: TenantId,
    pub clickhouse: ClickHouse,
}

/// The caller may read traffic: the right tenant, then the permission.
fn source<'a>(state: &'a AppState, principal: &Principal) -> Result<&'a ClickHouse, Problem> {
    limit(&state.limits.reads, principal)?;
    let source = state
        .traffic
        .as_deref()
        .filter(|source| source.tenant == principal.tenant)
        .ok_or_else(|| Problem::new(ErrorCode::NotFound))?;
    if !principal
        .authorization(state.resolver.as_ref())
        .has(Permission::TrafficRead)
    {
        return Err(Problem::new(ErrorCode::Forbidden).with_detail("the role lacks traffic.read"));
    }
    Ok(&source.clickhouse)
}

fn unavailable(error: ClickHouseError) -> Problem {
    tracing::warn!(error = %error, "a traffic query failed");
    match error {
        ClickHouseError::Unreachable(_) => Problem::new(ErrorCode::Unavailable).retry_after(5),
        _ => Problem::new(ErrorCode::Internal),
    }
}

fn invalid(detail: impl Into<String>) -> Problem {
    Problem::new(ErrorCode::InvalidRequest).with_detail(detail)
}

/// The query string as a map, refusing unknown and repeated names.
fn parameters<'a>(
    pairs: &'a [(String, String)],
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, Problem> {
    let mut seen = BTreeMap::new();
    for (name, value) in pairs {
        if !allowed.contains(&name.as_str()) {
            return Err(Problem::new(ErrorCode::UnknownField)
                .with_detail(format!("unknown query parameter '{name}'")));
        }
        if seen.insert(name.as_str(), value.as_str()).is_some() {
            return Err(invalid(format!("'{name}' is given more than once")));
        }
    }
    Ok(seen)
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// `from` and `to` in Unix seconds: the last hour by default, `from`
/// before `to`, at most 30 days apart.
fn range(parameters: &BTreeMap<&str, &str>, now: i64) -> Result<(i64, i64), Problem> {
    let seconds = |name: &str| -> Result<Option<i64>, Problem> {
        parameters
            .get(name)
            .map(|text| {
                parse_rfc3339(text)
                    .map(|micros| micros.div_euclid(1_000_000))
                    .ok_or_else(|| invalid(format!("{name} is not RFC 3339 UTC")))
            })
            .transpose()
    };
    let to = seconds("to")?.unwrap_or(now);
    let from = seconds("from")?.unwrap_or(to - DEFAULT_RANGE_SECONDS);
    if from >= to || to - from > MAX_RANGE_SECONDS {
        return Err(invalid("from must be before to, at most 30 days apart"));
    }
    if from < 0 || to > i64::from(u32::MAX) {
        return Err(invalid("from and to must fall between 1970 and 2106"));
    }
    Ok((from, to))
}

/// The step that keeps a summary within [`MAX_POINTS`]: a multiple of
/// ten seconds, never below [`MIN_STEP_SECONDS`].
pub fn step_for(from: i64, to: i64) -> i64 {
    let raw = ((to - from) + MAX_POINTS - 1) / MAX_POINTS;
    let rounded = (raw + MIN_STEP_SECONDS - 1) / MIN_STEP_SECONDS * MIN_STEP_SECONDS;
    rounded.max(MIN_STEP_SECONDS)
}

fn time_text(seconds: u32) -> String {
    rfc3339(i64::from(seconds) * 1_000_000)
}

// --- Summary ---

const SUMMARY_IPV4: &str = "\
SELECT toUInt32(toUnixTimestamp(toStartOfInterval(timestamp, toIntervalSecond({step:UInt32})))) AS t,
    sum(bytes) AS bytes, sum(packets) AS packets
FROM wetechinetmon_total_ipv4_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY t ORDER BY t";

const SUMMARY_IPV6: &str = "\
SELECT toUInt32(toUnixTimestamp(toStartOfInterval(timestamp, toIntervalSecond({step:UInt32})))) AS t,
    sum(bytes) AS bytes, sum(packets) AS packets
FROM wetechinetmon_total_ipv6_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY t ORDER BY t";

#[derive(Debug, Deserialize)]
struct BucketRow {
    t: u32,
    bytes: u64,
    packets: u64,
}

/// One step of the summary. A step with no traffic is absent, not zero:
/// an absent point means no data arrived.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct TrafficPoint {
    /// The start of the step, RFC 3339 UTC.
    pub time: String,
    pub ipv4_bps: f64,
    pub ipv6_bps: f64,
    pub ipv4_pps: f64,
    pub ipv6_pps: f64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TrafficSummary {
    pub from: String,
    pub to: String,
    pub step_seconds: i64,
    pub points: Vec<TrafficPoint>,
}

/// Bits and packets per second over time, IPv4 and IPv6. Needs
/// `traffic.read`, from the traffic tenant only.
#[utoipa::path(
    get,
    path = "/api/v1/traffic/summary",
    tag = "traffic",
    params(
        ("from" = Option<String>, Query, description = "RFC 3339 UTC; defaults to an hour before `to`"),
        ("to" = Option<String>, Query, description = "RFC 3339 UTC, exclusive; defaults to now. At most 30 days after `from`"),
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "At most 500 points", body = TrafficSummary),
        (status = 400, description = "A bad range or an unknown parameter", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks traffic.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "Traffic is not available to the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "ClickHouse is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn summary(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let result = async {
        let clickhouse = source(&state, &principal)?;
        let (from, to) = range(&parameters(&pairs, &["from", "to"])?, now_seconds())?;
        let step = step_for(from, to);
        let params = [
            ("step", step.to_string()),
            ("from", from.to_string()),
            ("to", to.to_string()),
        ];
        let ipv4: Vec<BucketRow> = clickhouse
            .rows(SUMMARY_IPV4, &params)
            .await
            .map_err(unavailable)?;
        let ipv6: Vec<BucketRow> = clickhouse
            .rows(SUMMARY_IPV6, &params)
            .await
            .map_err(unavailable)?;
        let per_second = |count: u64| count as f64 / step as f64;
        let mut points: BTreeMap<u32, TrafficPoint> = BTreeMap::new();
        for row in ipv4 {
            let point = points.entry(row.t).or_default();
            point.ipv4_bps = per_second(row.bytes) * 8.0;
            point.ipv4_pps = per_second(row.packets);
        }
        for row in ipv6 {
            let point = points.entry(row.t).or_default();
            point.ipv6_bps = per_second(row.bytes) * 8.0;
            point.ipv6_pps = per_second(row.packets);
        }
        Ok::<_, Problem>(TrafficSummary {
            from: rfc3339(from * 1_000_000),
            to: rfc3339(to * 1_000_000),
            step_seconds: step,
            points: points
                .into_iter()
                .map(|(t, point)| TrafficPoint {
                    time: time_text(t),
                    ..point
                })
                .collect(),
        })
    }
    .await;
    respond(result)
}

// --- Top talkers ---

/// Each dimension's query. The key expression is fixed here; the caller
/// only names the dimension.
const TOP: &[(&str, &str)] = &[
    ("host", "\
SELECT address AS key, sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows
FROM wetechinetmon_host_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY key ORDER BY bytes DESC LIMIT 50"),
    ("network", "\
SELECT concat(address, '/', toString(prefix_len)) AS key, sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows
FROM wetechinetmon_network_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY key ORDER BY bytes DESC LIMIT 50"),
    ("slash24", "\
SELECT address AS key, sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows
FROM wetechinetmon_slash24_network_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY key ORDER BY bytes DESC LIMIT 50"),
    ("hostgroup", "\
SELECT hostgroup AS key, sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows
FROM wetechinetmon_hostgroup_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY key ORDER BY bytes DESC LIMIT 50"),
    ("asn", "\
SELECT toString(asn) AS key, sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows
FROM wetechinetmon_asn_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY key ORDER BY bytes DESC LIMIT 50"),
    ("interface", "\
SELECT concat(exporter, '/', toString(interface_index), '/', toString(direction)) AS key,
    sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows
FROM wetechinetmon_interface_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY key ORDER BY bytes DESC LIMIT 50"),
    ("exporter", "\
SELECT exporter AS key, sum(bytes) AS bytes, sum(packets) AS packets, sum(flows) AS flows
FROM wetechinetmon_exporter_traffic
WHERE timestamp >= toDateTime({from:UInt32}) AND timestamp < toDateTime({to:UInt32})
GROUP BY key ORDER BY bytes DESC LIMIT 50"),
];

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct TopEntry {
    /// The host, network (`address/length`), /24, hostgroup, ASN,
    /// interface (`exporter/index/direction`) or exporter.
    pub key: String,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TopList {
    pub dimension: String,
    pub from: String,
    pub to: String,
    /// Largest first, by bytes.
    pub items: Vec<TopEntry>,
}

/// The top talkers of one dimension, by bytes. Needs `traffic.read`, from
/// the traffic tenant only.
#[utoipa::path(
    get,
    path = "/api/v1/traffic/top",
    tag = "traffic",
    params(
        ("dimension" = String, Query, description = "host, network, slash24, hostgroup, asn, interface or exporter"),
        ("limit" = Option<u32>, Query, description = "1 to 50; defaults to 10"),
        ("from" = Option<String>, Query, description = "RFC 3339 UTC; defaults to an hour before `to`"),
        ("to" = Option<String>, Query, description = "RFC 3339 UTC, exclusive; defaults to now. At most 30 days after `from`"),
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The top entries, largest first", body = TopList),
        (status = 400, description = "An unknown dimension, a bad limit or range, or an unknown parameter", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks traffic.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "Traffic is not available to the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "ClickHouse is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn top(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let result = async {
        let clickhouse = source(&state, &principal)?;
        let parameters = parameters(&pairs, &["dimension", "limit", "from", "to"])?;
        let dimension = parameters
            .get("dimension")
            .ok_or_else(|| invalid("dimension is required"))?;
        let sql = TOP
            .iter()
            .find(|(name, _)| name == dimension)
            .map(|(_, sql)| *sql)
            .ok_or_else(|| {
                let names: BTreeSet<&str> = TOP.iter().map(|(name, _)| *name).collect();
                invalid(format!("dimension must be one of {names:?}"))
            })?;
        let wanted = match parameters.get("limit") {
            None => DEFAULT_TOP,
            Some(text) => text
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=MAX_TOP).contains(n))
                .ok_or_else(|| invalid(format!("limit must be 1 to {MAX_TOP}")))?,
        };
        let (from, to) = range(&parameters, now_seconds())?;
        let mut items: Vec<TopEntry> = clickhouse
            .rows(sql, &[("from", from.to_string()), ("to", to.to_string())])
            .await
            .map_err(unavailable)?;
        items.truncate(wanted);
        Ok::<_, Problem>(TopList {
            dimension: dimension.to_string(),
            from: rfc3339(from * 1_000_000),
            to: rfc3339(to * 1_000_000),
            items,
        })
    }
    .await;
    respond(result)
}

// --- Exporters ---

const EXPORTERS: &str = "\
SELECT exporter,
    toUInt32(toUnixTimestamp(max(timestamp))) AS last_seen,
    sumIf(bytes, timestamp >= now() - {window:UInt32}) AS bytes,
    sumIf(packets, timestamp >= now() - {window:UInt32}) AS packets
FROM wetechinetmon_exporter_traffic
WHERE timestamp >= now() - 86400
GROUP BY exporter ORDER BY exporter LIMIT 1000";

#[derive(Debug, Deserialize)]
struct ExporterRow {
    exporter: String,
    last_seen: u32,
    bytes: u64,
    packets: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExporterView {
    /// The exporter's address.
    pub exporter: String,
    /// When its traffic was last recorded, RFC 3339 UTC.
    pub last_seen: String,
    /// Seconds since then. A large number means a silent exporter.
    pub silent_seconds: i64,
    /// Over the last five minutes.
    pub bps: f64,
    pub pps: f64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExporterList {
    pub items: Vec<ExporterView>,
}

/// Every exporter seen in the last day: when it last reported, and its
/// rate over the last five minutes. Needs `traffic.read`, from the
/// traffic tenant only.
#[utoipa::path(
    get,
    path = "/api/v1/exporters",
    tag = "traffic",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "At most 1,000 exporters, by address", body = ExporterList),
        (status = 400, description = "An unknown parameter", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 401, description = "No usable token", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 403, description = "The role lacks traffic.read", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 404, description = "Traffic is not available to the caller's tenant", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
        (status = 503, description = "ClickHouse is unreachable", body = crate::openapi::ProblemDocument, content_type = "application/problem+json"),
    )
)]
pub async fn exporters(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let result = async {
        let clickhouse = source(&state, &principal)?;
        parameters(&pairs, &[])?;
        let rows: Vec<ExporterRow> = clickhouse
            .rows(EXPORTERS, &[("window", EXPORTER_RATE_WINDOW.to_string())])
            .await
            .map_err(unavailable)?;
        let now = now_seconds();
        let window = EXPORTER_RATE_WINDOW as f64;
        Ok::<_, Problem>(ExporterList {
            items: rows
                .into_iter()
                .map(|row| ExporterView {
                    exporter: row.exporter,
                    last_seen: time_text(row.last_seen),
                    silent_seconds: (now - i64::from(row.last_seen)).max(0),
                    bps: row.bytes as f64 * 8.0 / window,
                    pps: row.packets as f64 / window,
                })
                .collect(),
        })
    }
    .await;
    respond(result)
}

fn respond<T: Serialize>(result: Result<T, Problem>) -> Response {
    match result {
        Ok(body) => Json(body).into_response(),
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

    #[test]
    fn a_summary_never_exceeds_its_point_budget() {
        assert_eq!(step_for(0, 3_600), 10);
        for range in [60, 3_600, 86_400, 7 * 86_400, MAX_RANGE_SECONDS] {
            let step = step_for(0, range);
            assert!(
                step >= MIN_STEP_SECONDS && step % 10 == 0,
                "{range}: {step}"
            );
            assert!((range + step - 1) / step <= MAX_POINTS, "{range}: {step}");
        }
    }

    #[test]
    fn ranges_default_to_the_last_hour_and_are_bounded() {
        let now = 1_800_000_000;
        let none = parameters(&[], &["from", "to"]).unwrap();
        assert_eq!(range(&none, now).unwrap(), (now - 3_600, now));
        let given = pairs(&[
            ("from", "2026-10-01T00:00:00Z"),
            ("to", "2026-10-02T00:00:00Z"),
        ]);
        let (from, to) = range(&parameters(&given, &["from", "to"]).unwrap(), now).unwrap();
        assert_eq!(to - from, 86_400);
        for bad in [
            pairs(&[
                ("from", "2026-10-02T00:00:00Z"),
                ("to", "2026-10-01T00:00:00Z"),
            ]),
            pairs(&[
                ("from", "2026-01-01T00:00:00Z"),
                ("to", "2026-10-01T00:00:00Z"),
            ]),
            pairs(&[("from", "yesterday")]),
        ] {
            let parsed = parameters(&bad, &["from", "to"]).unwrap();
            assert!(range(&parsed, now).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unknown_and_repeated_parameters_are_refused() {
        assert!(parameters(&pairs(&[("sort", "x")]), &["from"]).is_err());
        assert!(parameters(&pairs(&[("from", "a"), ("from", "b")]), &["from"]).is_err());
    }

    #[test]
    fn every_query_is_parameterised_and_reads_only_traffic_tables() {
        let mut queries: Vec<&str> = TOP.iter().map(|(_, sql)| *sql).collect();
        queries.extend([SUMMARY_IPV4, SUMMARY_IPV6, EXPORTERS]);
        let tables: BTreeSet<&str> = wetechinetmon_storage::schema::CREATE_TABLE_STATEMENTS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        for sql in queries {
            assert!(sql.trim_start().starts_with("SELECT"), "{sql}");
            assert!(!sql.contains(';'), "{sql}");
            let from = sql.split("FROM ").nth(1).unwrap();
            let table = from.split_whitespace().next().unwrap();
            assert!(tables.contains(table), "{table}");
        }
    }
}
