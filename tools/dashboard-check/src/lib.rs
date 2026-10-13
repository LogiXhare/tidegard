//! Static checks for the Grafana dashboards in `grafana/dashboards/`
//! ([ADR 0041](../../../docs/architecture/decisions/0041-phase6a-grafana-dashboards-as-code.md)).
//!
//! A dashboard is code that nothing compiles: a renamed metric leaves a
//! panel quietly empty. [`check_dashboard`] refuses a dashboard that
//! queries a metric or table that does not exist, or that is tied to one
//! Grafana's datasource UIDs instead of a variable.

use std::collections::BTreeSet;

use serde_json::Value;

/// The datasource variables a panel may use, with the plugin each one
/// must select.
pub const DATASOURCE_VARIABLES: &[(&str, &str)] = &[
    ("ds_prometheus", "prometheus"),
    ("ds_clickhouse", "grafana-clickhouse-datasource"),
];

/// Grafana's limit on a dashboard UID.
const UID_MAX_LEN: usize = 40;

/// What exists for a dashboard to query.
pub struct Known {
    /// Every metric a module registers, by fully qualified name.
    pub metrics: BTreeSet<String>,
    /// Every ClickHouse table the schema creates.
    pub tables: BTreeSet<String>,
}

/// Checks one dashboard. `seen_uids` carries UIDs across files, so a
/// duplicate is caught. Returns every problem found, each naming the
/// file and panel.
pub fn check_dashboard(
    file: &str,
    json: &str,
    known: &Known,
    seen_uids: &mut BTreeSet<String>,
) -> Vec<String> {
    let mut problems = Vec::new();
    let dashboard: Value = match serde_json::from_str(json) {
        Ok(value) => value,
        Err(error) => return vec![format!("{file}: not valid JSON: {error}")],
    };

    match dashboard["uid"].as_str() {
        Some(uid) if valid_uid(uid) => {
            if !seen_uids.insert(uid.to_string()) {
                problems.push(format!("{file}: UID {uid} is used by another dashboard"));
            }
        }
        other => problems.push(format!(
            "{file}: the UID must be `wnm-` and a lowercase slug of at most {UID_MAX_LEN} characters, not {other:?}"
        )),
    }
    if dashboard["title"].as_str().is_none_or(str::is_empty) {
        problems.push(format!("{file}: no title"));
    }
    if !dashboard["id"].is_null() {
        problems.push(format!(
            "{file}: `id` must be null; it belongs to one Grafana instance"
        ));
    }

    let declared = declared_datasources(&dashboard);
    for (name, plugin) in &declared {
        let expected = DATASOURCE_VARIABLES
            .iter()
            .find(|(variable, _)| variable == name);
        match expected {
            Some((_, wanted)) if wanted == plugin => {}
            _ => problems.push(format!(
                "{file}: datasource variable {name} selects {plugin:?}, which is not one of {DATASOURCE_VARIABLES:?}"
            )),
        }
    }

    let mut panels = Vec::new();
    collect_panels(&dashboard["panels"], &mut panels);
    if panels.is_empty() {
        problems.push(format!("{file}: no panels"));
    }
    for panel in panels {
        check_panel(file, panel, &declared, known, &mut problems);
    }
    problems
}

fn valid_uid(uid: &str) -> bool {
    uid.len() <= UID_MAX_LEN
        && uid.strip_prefix("wnm-").is_some_and(|slug| {
            !slug.is_empty()
                && slug
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// `(variable name, plugin)` for every datasource variable.
fn declared_datasources(dashboard: &Value) -> Vec<(String, String)> {
    dashboard["templating"]["list"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|variable| variable["type"] == "datasource")
                .map(|variable| {
                    (
                        variable["name"].as_str().unwrap_or_default().to_string(),
                        variable["query"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every panel, including those nested in collapsed rows.
fn collect_panels<'a>(panels: &'a Value, out: &mut Vec<&'a Value>) {
    for panel in panels.as_array().into_iter().flatten() {
        if panel["type"] == "row" {
            collect_panels(&panel["panels"], out);
        } else {
            out.push(panel);
        }
    }
}

fn check_panel(
    file: &str,
    panel: &Value,
    declared: &[(String, String)],
    known: &Known,
    problems: &mut Vec<String>,
) {
    let title = panel["title"].as_str().unwrap_or_default();
    let at = format!("{file}: panel {title:?}");
    if title.is_empty() {
        problems.push(format!("{at}: no title"));
    }
    if panel["type"] == "text" {
        if panel["options"]["mode"] == "html" {
            problems.push(format!("{at}: HTML text panels are not allowed"));
        }
        return;
    }
    let targets = panel["targets"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if targets.is_empty() {
        problems.push(format!("{at}: no queries"));
    }
    for target in targets {
        let datasource = if target["datasource"].is_object() {
            &target["datasource"]
        } else {
            &panel["datasource"]
        };
        let uid = datasource["uid"].as_str().unwrap_or_default();
        let variable = uid
            .strip_prefix("${")
            .and_then(|rest| rest.strip_suffix('}'));
        let Some((name, plugin)) =
            variable.and_then(|name| declared.iter().find(|(declared, _)| declared == name))
        else {
            problems.push(format!(
                "{at}: datasource {uid:?} is not a declared datasource variable"
            ));
            continue;
        };
        if datasource["type"].as_str() != Some(plugin.as_str()) {
            problems.push(format!(
                "{at}: datasource type {:?} does not match ${{{name}}}",
                datasource["type"]
            ));
        }
        match plugin.as_str() {
            "prometheus" => {
                let expr = target["expr"].as_str().unwrap_or_default();
                if expr.is_empty() {
                    problems.push(format!("{at}: an empty PromQL expression"));
                }
                for metric in product_identifiers(expr) {
                    if !known_metric(&metric, &known.metrics) {
                        problems.push(format!("{at}: no module registers the metric {metric}"));
                    }
                }
            }
            _ => {
                let sql = target["rawSql"].as_str().unwrap_or_default();
                if sql.is_empty() {
                    problems.push(format!("{at}: an empty SQL query"));
                }
                for table in product_identifiers(sql) {
                    if !known.tables.contains(&table) {
                        problems.push(format!("{at}: the schema creates no table {table}"));
                    }
                }
            }
        }
    }
}

/// A histogram is exported as `_bucket`, `_sum` and `_count` series.
fn known_metric(name: &str, metrics: &BTreeSet<String>) -> bool {
    metrics.contains(name)
        || ["_bucket", "_sum", "_count"].iter().any(|suffix| {
            name.strip_suffix(suffix)
                .is_some_and(|base| metrics.contains(base))
        })
}

/// Every product identifier in a query: a metric, `tidegard_...`, or a
/// ClickHouse table, whose names keep the product's first name,
/// `wetechinetmon_...`, so that renaming it lost no history (ADR 0058).
pub fn product_identifiers(query: &str) -> Vec<String> {
    const PREFIXES: [&str; 2] = ["tidegard_", "wetechinetmon_"];
    let mut found = Vec::new();
    let mut rest = query;
    while let Some(start) = PREFIXES.iter().filter_map(|prefix| rest.find(prefix)).min() {
        let preceded_by_word = rest[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(tail.len());
        if !preceded_by_word {
            found.push(tail[..end].to_string());
        }
        rest = &tail[end..];
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn known() -> Known {
        Known {
            metrics: ["tidegard_collector_queue_depth", "tidegard_lat"]
                .map(String::from)
                .into(),
            tables: ["wetechinetmon_host_traffic".to_string()].into(),
        }
    }

    fn dashboard(uid: &str, panels: Value) -> String {
        json!({
            "id": null,
            "uid": uid,
            "title": "Test",
            "templating": {"list": [
                {"type": "datasource", "name": "ds_prometheus", "query": "prometheus"},
                {"type": "datasource", "name": "ds_clickhouse", "query": "grafana-clickhouse-datasource"}
            ]},
            "panels": panels,
        })
        .to_string()
    }

    fn prometheus(expr: &str) -> Value {
        json!({"title": "P", "type": "timeseries",
               "datasource": {"type": "prometheus", "uid": "${ds_prometheus}"},
               "targets": [{"refId": "A", "expr": expr}]})
    }

    fn clickhouse(sql: &str) -> Value {
        json!({"title": "C", "type": "timeseries",
               "datasource": {"type": "grafana-clickhouse-datasource", "uid": "${ds_clickhouse}"},
               "targets": [{"refId": "A", "rawSql": sql}]})
    }

    fn problems(json: &str) -> Vec<String> {
        check_dashboard("t.json", json, &known(), &mut BTreeSet::new())
    }

    #[test]
    fn a_dashboard_over_what_exists_passes() {
        let json = dashboard(
            "wnm-test",
            json!([
                prometheus("sum(tidegard_collector_queue_depth)"),
                prometheus("histogram_quantile(0.9, rate(tidegard_lat_bucket[5m]))"),
                {"type": "row", "title": "R", "panels": [
                    clickhouse("SELECT 1 FROM wetechinetmon_host_traffic WHERE $__timeFilter(timestamp)")
                ]},
            ]),
        );
        assert_eq!(problems(&json), Vec::<String>::new());
    }

    #[test]
    fn an_unknown_metric_or_table_is_refused() {
        let json = dashboard(
            "wnm-test",
            json!([
                prometheus("rate(tidegard_renamed_total[5m])"),
                clickhouse("SELECT 1 FROM wetechinetmon_gone_traffic"),
            ]),
        );
        let found = problems(&json);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("tidegard_renamed_total"));
        assert!(found[1].contains("wetechinetmon_gone_traffic"));
    }

    #[test]
    fn a_hard_coded_datasource_is_refused() {
        let mut panel = prometheus("tidegard_collector_queue_depth");
        panel["datasource"]["uid"] = json!("P1809F7CD0C75ACF3");
        let found = problems(&dashboard("wnm-test", json!([panel])));
        assert!(
            found[0].contains("not a declared datasource variable"),
            "{found:?}"
        );
    }

    #[test]
    fn uids_are_checked_for_form_and_uniqueness() {
        let mut seen = BTreeSet::new();
        let panels = json!([prometheus("tidegard_collector_queue_depth")]);
        let first = check_dashboard(
            "a.json",
            &dashboard("wnm-a", panels.clone()),
            &known(),
            &mut seen,
        );
        assert!(first.is_empty(), "{first:?}");
        let again = check_dashboard(
            "b.json",
            &dashboard("wnm-a", panels.clone()),
            &known(),
            &mut seen,
        );
        assert!(again[0].contains("used by another dashboard"), "{again:?}");
        for bad in [
            "traffic",
            "wnm-",
            "wnm-Traffic",
            &format!("wnm-{}", "a".repeat(40)),
        ] {
            let found = problems(&dashboard(bad, panels.clone()));
            assert!(found[0].contains("UID"), "{bad}: {found:?}");
        }
    }

    #[test]
    fn html_text_panels_and_instance_ids_are_refused() {
        let mut json: Value = serde_json::from_str(&dashboard(
            "wnm-test",
            json!([{"title": "T", "type": "text", "options": {"mode": "html", "content": "<b>x</b>"}}]),
        ))
        .unwrap();
        json["id"] = json!(7);
        let found = problems(&json.to_string());
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn identifiers_are_whole_words() {
        assert_eq!(
            product_identifiers("sum(xtidegard_a) + tidegard_b_total{x=\"y\"}"),
            vec!["tidegard_b_total".to_string()]
        );
    }
}
