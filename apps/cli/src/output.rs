//! Rendering API answers for people. `--output json` bypasses all of this
//! and prints the body verbatim, so a change here never breaks a script.
//!
//! **Every string from the API is untrusted.** Titles, notes and reasons
//! are operator text, so control characters are replaced before they
//! reach a terminal: an escape sequence in a note must not be able to
//! rewrite the operator's screen.

use serde_json::Value;
use wetechinetmon_common::rfc3339::parse_rfc3339;

use crate::args::History;

const TITLE_WIDTH: usize = 48;

/// `text` with every control character replaced, safe for a terminal.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn truncate(text: &str, width: usize) -> String {
    let text = clean(text);
    if text.chars().count() <= width {
        text
    } else {
        let mut cut: String = text.chars().take(width - 1).collect();
        cut.push('…');
        cut
    }
}

/// A field as display text: strings as they are, null as `—`.
fn field(value: &Value, name: &str) -> String {
    match &value[name] {
        Value::Null => "—".to_string(),
        Value::String(text) => clean(text),
        other => clean(&other.to_string()),
    }
}

/// How long ago `at` was, from `now_micros`: `45s`, `6m`, `3h`, `2d`.
pub fn age(at: &str, now_micros: i64) -> String {
    let Some(then) = parse_rfc3339(at) else {
        return "?".to_string();
    };
    let seconds = (now_micros - then).max(0) / 1_000_000;
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3_599 => format!("{}m", seconds / 60),
        3_600..=86_399 => format!("{}h", seconds / 3_600),
        _ => format!("{}d", seconds / 86_400),
    }
}

/// Aligned columns, two spaces apart, no trailing spaces.
pub fn columns(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| -> String {
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                out.push_str(cell);
            } else {
                out.push_str(cell);
                out.push_str(&" ".repeat(widths[i] - cell.chars().count() + 2));
            }
        }
        out.trim_end().to_string()
    };
    let mut out = line(headers.to_vec());
    out.push('\n');
    for row in rows {
        out.push_str(&line(row.iter().map(String::as_str).collect()));
        out.push('\n');
    }
    out
}

fn assigned(incident: &Value) -> String {
    match (&incident["assigned_user_id"], &incident["assigned_team_id"]) {
        (Value::String(user), _) => clean(user),
        (_, Value::String(team)) => format!("team:{}", clean(team)),
        _ => "—".to_string(),
    }
}

/// `incidents list`.
pub fn incident_list(page: &Value, wide: bool, now_micros: i64) -> String {
    let empty = Vec::new();
    let items = page["items"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        return "No incidents.\n".to_string();
    }
    let mut headers = vec![
        "NUMBER", "SEVERITY", "PRI", "STATE", "TARGET", "CATEGORY", "AGE", "ASSIGNED",
    ];
    if wide {
        headers.extend(["DIRECTION", "TITLE", "ID"]);
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            let mut row = vec![
                field(item, "incident_number"),
                field(item, "severity"),
                field(item, "priority"),
                field(item, "state"),
                field(item, "target_id"),
                field(item, "category"),
                age(item["opened_at"].as_str().unwrap_or_default(), now_micros),
                assigned(item),
            ];
            if wide {
                row.push(field(item, "direction"));
                row.push(truncate(
                    item["title"].as_str().unwrap_or_default(),
                    TITLE_WIDTH,
                ));
                row.push(field(item, "incident_id"));
            }
            row
        })
        .collect();
    columns(&headers, &rows)
}

/// `incidents show`: one field per line.
pub fn incident(incident: &Value, now_micros: i64) -> String {
    let mut lines = vec![
        ("Number", field(incident, "incident_number")),
        ("Title", field(incident, "title")),
        ("State", field(incident, "state")),
        ("Severity", field(incident, "severity")),
        ("Priority", field(incident, "priority")),
        ("Category", field(incident, "category")),
        (
            "Target",
            format!(
                "{} ({}, {}, IPv{})",
                field(incident, "target_id"),
                field(incident, "target_type"),
                field(incident, "direction"),
                field(incident, "address_family")
            ),
        ),
        ("Assigned", assigned(incident)),
        (
            "Opened",
            format!(
                "{} ({} ago)",
                field(incident, "opened_at"),
                age(
                    incident["opened_at"].as_str().unwrap_or_default(),
                    now_micros
                )
            ),
        ),
        ("Last detected", field(incident, "last_detected_at")),
        ("Version", field(incident, "version")),
        ("Id", field(incident, "incident_id")),
    ];
    if let Value::String(text) = &incident["description"] {
        lines.insert(2, ("Description", clean(text)));
    }
    if let Value::Object(suppression) = &incident["suppression"] {
        let until = suppression
            .get("until")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let reason = suppression
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("");
        lines.push((
            "Suppressed",
            format!("until {} ({})", clean(until), clean(reason)),
        ));
    }
    if let Some(tags) = incident["tags"].as_object().filter(|tags| !tags.is_empty()) {
        let text: Vec<String> = tags
            .iter()
            .map(|(k, v)| format!("{}={}", clean(k), clean(v.as_str().unwrap_or_default())))
            .collect();
        lines.push(("Tags", text.join(", ")));
    }
    let width = lines.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (name, value) in lines {
        out.push_str(&format!("{name:<width$}  {value}\n"));
    }
    out
}

/// `incidents timeline|detections|audit`.
pub fn history(kind: History, page: &Value, wide: bool) -> String {
    let empty = Vec::new();
    let items = page["items"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        return "Nothing recorded.\n".to_string();
    }
    let (headers, rows): (Vec<&str>, Vec<Vec<String>>) = match kind {
        History::Timeline => {
            let mut headers = vec!["TIME", "ENTRY", "ACTOR"];
            if wide {
                headers.extend(["ID", "NEW VALUE"]);
            }
            let rows = items
                .iter()
                .map(|item| {
                    let mut row = vec![
                        field(item, "occurred_at"),
                        field(item, "entry_type"),
                        field(item, "actor"),
                    ];
                    if wide {
                        row.push(field(item, "timeline_id"));
                        row.push(truncate(&item["new_value"].to_string(), 60));
                    }
                    row
                })
                .collect();
            (headers, rows)
        }
        History::Detections => {
            let mut headers = vec!["DETECTED", "KIND", "SEVERITY", "LINK", "POLICY"];
            if wide {
                headers.extend(["EVENT"]);
            }
            let rows = items
                .iter()
                .map(|item| {
                    let mut row = vec![
                        field(item, "detected_at"),
                        field(item, "kind"),
                        field(item, "severity"),
                        field(item, "link_type"),
                        format!(
                            "{}@{}",
                            field(item, "policy_id"),
                            field(item, "policy_version")
                        ),
                    ];
                    if wide {
                        row.push(field(item, "detection_event_id"));
                    }
                    row
                })
                .collect();
            (headers, rows)
        }
        History::Audit => {
            let mut headers = vec!["TIME", "ACTOR", "ACTION", "RESULT"];
            if wide {
                headers.extend(["REASON", "REQUEST"]);
            }
            let rows = items
                .iter()
                .map(|item| {
                    let mut row = vec![
                        field(item, "occurred_at"),
                        field(item, "actor"),
                        field(item, "action"),
                        field(item, "result"),
                    ];
                    if wide {
                        row.push(field(item, "reason"));
                        row.push(field(item, "request_id"));
                    }
                    row
                })
                .collect();
            (headers, rows)
        }
    };
    columns(&headers, &rows)
}

/// `incidents note list`.
pub fn notes(list: &Value) -> String {
    let empty = Vec::new();
    let items = list["items"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        return "No notes.\n".to_string();
    }
    let mut out = String::new();
    for note in items {
        let mut marks = String::new();
        if !note["supersedes_note_index"].is_null() {
            marks.push_str(&format!(
                ", edits #{}",
                field(note, "supersedes_note_index")
            ));
        }
        if !note["superseded_by_note_index"].is_null() {
            marks.push_str(&format!(
                ", replaced by #{}",
                field(note, "superseded_by_note_index")
            ));
        }
        if note["redacted"] == true {
            marks.push_str(", redacted");
        }
        out.push_str(&format!(
            "#{} by {} ({}{marks})\n",
            field(note, "note_index"),
            field(note, "author"),
            field(note, "visibility")
        ));
        // Line breaks are kept; every other control character is not.
        for line in note["body"].as_str().unwrap_or_default().lines() {
            out.push_str(&format!("    {}\n", clean(line)));
        }
    }
    out
}

/// One field per line, names aligned.
fn fields(lines: Vec<(&str, String)>) -> String {
    let width = lines.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (name, value) in lines {
        out.push_str(&format!("{name:<width$}  {value}\n"));
    }
    out
}

/// A mitigation's action with its FlowSpec match and rate, if any.
fn mitigation_action(m: &Value) -> String {
    let mut text = field(m, "action");
    if let Some(flow) = m["flow"].as_object().filter(|flow| !flow.is_empty()) {
        let parts: Vec<String> = ["protocol", "source", "source_port", "destination_port"]
            .iter()
            .filter_map(|name| {
                flow.get(*name)
                    .filter(|v| !v.is_null())
                    .map(|v| format!("{name}={}", clean(&v.to_string().replace('"', ""))))
            })
            .collect();
        text.push_str(&format!(" [{}]", parts.join(" ")));
    }
    if !m["bytes_per_second"].is_null() {
        text.push_str(&format!(" at {} B/s", field(m, "bytes_per_second")));
    }
    text
}

/// `mitigations list`.
pub fn mitigation_list(page: &Value, wide: bool, now_micros: i64) -> String {
    let empty = Vec::new();
    let items = page["items"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        return "No mitigations.\n".to_string();
    }
    let mut headers = vec![
        "ID",
        "STATE",
        "ACTION",
        "PREFIX",
        "AGE",
        "EXPIRES",
        "REQUESTED BY",
    ];
    if wide {
        headers.extend(["APPROVED BY", "DRY RUN", "INCIDENT", "REASON"]);
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|m| {
            let mut row = vec![
                field(m, "mitigation_id"),
                field(m, "state"),
                field(m, "action"),
                field(m, "prefix"),
                age(m["created_at"].as_str().unwrap_or_default(), now_micros),
                field(m, "expires_at"),
                field(m, "requested_by"),
            ];
            if wide {
                row.push(field(m, "approved_by"));
                row.push(field(m, "dry_run"));
                row.push(field(m, "incident_id"));
                row.push(truncate(
                    m["reason"].as_str().unwrap_or_default(),
                    TITLE_WIDTH,
                ));
            }
            row
        })
        .collect();
    columns(&headers, &rows)
}

/// `mitigations show`: one field per line; times the API leaves null
/// are left out.
pub fn mitigation(m: &Value, now_micros: i64) -> String {
    let mut lines = vec![
        ("Id", field(m, "mitigation_id")),
        ("State", field(m, "state")),
        ("Action", mitigation_action(m)),
        ("Prefix", field(m, "prefix")),
        ("Reason", field(m, "reason")),
        ("Duration", format!("{}s", field(m, "duration_seconds"))),
        ("Requested by", field(m, "requested_by")),
        ("Approved by", field(m, "approved_by")),
        (
            "Created",
            format!(
                "{} ({} ago)",
                field(m, "created_at"),
                age(m["created_at"].as_str().unwrap_or_default(), now_micros)
            ),
        ),
    ];
    for (label, name) in [
        ("Approved", "approved_at"),
        ("Active since", "active_since"),
        ("Expires", "expires_at"),
        ("Ended", "ended_at"),
        ("Incident", "incident_id"),
        ("Dry run", "dry_run"),
        ("Withdrawn by", "withdrawal_cause"),
        ("Last error", "last_error"),
    ] {
        if !m[name].is_null() {
            lines.push((label, field(m, name)));
        }
    }
    if let Some(route) = m["route"].as_object() {
        lines.push(("Route", clean(&Value::Object(route.clone()).to_string())));
    }
    lines.push(("Version", field(m, "version")));
    fields(lines)
}

/// `mitigations history`, oldest first as the API returns it.
pub fn mitigation_history(page: &Value) -> String {
    let empty = Vec::new();
    let items = page["items"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        return "Nothing recorded.\n".to_string();
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|entry| {
            let from = match &entry["from_state"] {
                Value::String(state) => format!("{} → ", clean(state)),
                _ => String::new(),
            };
            vec![
                field(entry, "version"),
                field(entry, "occurred_at"),
                format!("{from}{}", field(entry, "to_state")),
                field(entry, "actor"),
                field(entry, "detail"),
            ]
        })
        .collect();
    columns(&["VERSION", "TIME", "CHANGE", "ACTOR", "DETAIL"], &rows)
}

/// `kill-switch status` and `engage`.
pub fn kill_switch(k: &Value, now_micros: i64) -> String {
    let state = if k["engaged"] == true {
        "ENGAGED: nothing is announced, and live mitigations are withdrawn"
    } else {
        "released"
    };
    let mut lines = vec![("Kill switch", state.to_string())];
    if let Some(at) = k["changed_at"].as_str() {
        lines.push((
            "Changed",
            format!("{} ({} ago)", clean(at), age(at, now_micros)),
        ));
        lines.push(("Changed by", field(k, "changed_by")));
        lines.push(("Reason", field(k, "reason")));
    }
    lines.push(("Version", field(k, "version")));
    fields(lines)
}

/// `bgp routes`.
pub fn bgp_routes(page: &Value, wide: bool) -> String {
    let empty = Vec::new();
    let items = page["items"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        return "No routes announced.\n".to_string();
    }
    let mut headers = vec!["PREFIX", "ACTION", "STATE", "EXPIRES", "MITIGATION"];
    if wide {
        headers.push("ROUTE");
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|r| {
            let mut row = vec![
                field(r, "prefix"),
                field(r, "action"),
                field(r, "state"),
                field(r, "expires_at"),
                field(r, "mitigation_id"),
            ];
            if wide {
                row.push(clean(&r["route"].to_string()));
            }
            row
        })
        .collect();
    columns(&headers, &rows)
}

/// How old a peer snapshot may be before it is called stale: well past
/// the mitigator's default reconciliation interval of a minute.
pub const STALE_PEERS_SECONDS: i64 = 300;

/// `bgp peers`.
pub fn bgp_peers(page: &Value, _wide: bool, now_micros: i64) -> String {
    let empty = Vec::new();
    let items = page["items"].as_array().unwrap_or(&empty);
    if items.is_empty() {
        return "No BGP peers reported. Is the mitigator running with BGP enabled?\n".to_string();
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|p| {
            vec![
                field(p, "neighbor_address"),
                field(p, "peer_asn"),
                field(p, "session_state"),
                age(p["updated_at"].as_str().unwrap_or_default(), now_micros),
            ]
        })
        .collect();
    columns(&["NEIGHBOR", "ASN", "SESSION", "SEEN"], &rows)
}

/// A warning when the newest peer snapshot is old: the mitigator writes
/// it at every reconciliation, so an old one means it has stopped, not
/// that the sessions are still up.
pub fn stale_peers(page: &Value, now_micros: i64) -> Option<String> {
    let newest = page["items"]
        .as_array()?
        .iter()
        .filter_map(|p| parse_rfc3339(p["updated_at"].as_str()?))
        .max()?;
    let seconds = (now_micros - newest) / 1_000_000;
    (seconds > STALE_PEERS_SECONDS).then(|| {
        format!(
            "Warning: the mitigator last reported its peers {} ago. It may have stopped; \
             these sessions may no longer be as shown.",
            age(&wetechinetmon_common::rfc3339::rfc3339(newest), now_micros)
        )
    })
}

/// A problem document for stderr: the stable code, then what is known.
pub fn problem(document: &Value) -> String {
    let code = document["error"].as_str().unwrap_or("unknown");
    let text = document["detail"]
        .as_str()
        .or(document["title"].as_str())
        .unwrap_or("the API refused the request");
    let mut out = format!("Error: {} ({})\n", clean(text), clean(code));
    for (label, name) in [
        ("expected version", "expected_version"),
        ("current version", "current_version"),
        ("current state", "current_state"),
        ("active incident", "incident_id"),
        ("request id", "request_id"),
    ] {
        if !document[name].is_null() {
            out.push_str(&format!("  {label}: {}\n", field(document, name)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_700_000_000_000_000; // 2023-11-14T22:13:20Z

    #[test]
    fn ages_read_naturally() {
        assert_eq!(age("2023-11-14T22:13:00Z", NOW), "20s");
        assert_eq!(age("2023-11-14T22:07:20Z", NOW), "6m");
        assert_eq!(age("2023-11-14T19:13:20Z", NOW), "3h");
        assert_eq!(age("2023-11-12T22:13:20Z", NOW), "2d");
        assert_eq!(age("not a time", NOW), "?");
    }

    #[test]
    fn control_characters_never_reach_the_terminal() {
        let hostile = "ok\u{1b}[2J\u{7}gone";
        assert_eq!(clean(hostile), "ok [2J gone");
        let rendered = notes(&json!({"items": [
            {"note_index": 0, "author": "u\u{1b}]0;x", "visibility": "internal", "body": "a\n\u{1b}[31mb"}
        ]}));
        assert!(!rendered.contains('\u{1b}'), "{rendered:?}");
        assert!(
            rendered.contains("    a\n"),
            "line breaks in a note are kept"
        );
    }

    #[test]
    fn the_list_matches_the_plan_and_wide_adds_columns() {
        let page = json!({"items": [{
            "incident_id": "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d",
            "incident_number": "WNM-2026-000123", "severity": "critical", "priority": "P1",
            "state": "acknowledged", "target_id": "203.0.113.7", "category": "udp_flood",
            "opened_at": "2023-11-14T22:07:20Z", "assigned_user_id": "j.rahman",
            "assigned_team_id": null, "direction": "incoming", "title": "UDP flood"
        }]});
        let table = incident_list(&page, false, NOW);
        assert!(
            table.starts_with("NUMBER           SEVERITY  PRI  STATE"),
            "{table}"
        );
        assert!(table.contains("WNM-2026-000123  critical  P1   acknowledged  203.0.113.7  udp_flood  6m   j.rahman"), "{table}");
        let wide = incident_list(&page, true, NOW);
        assert!(wide.contains("0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d"));
        assert_eq!(
            incident_list(&json!({"items": []}), false, NOW),
            "No incidents.\n"
        );
    }

    #[test]
    fn mitigations_render_and_stay_clean() {
        let m = json!({
            "mitigation_id": "0192f3c4-8a7b-7e1f-9c2d-3e4f5a6b7c8d", "state": "active",
            "action": "flowspec_rate_limit", "prefix": "203.0.113.9/32",
            "flow": {"protocol": 17, "destination_port": 53}, "bytes_per_second": 125000,
            "reason": "dns\u{1b}[2J flood", "duration_seconds": 1800,
            "requested_by": "operator:u_1", "approved_by": "operator:u_2",
            "created_at": "2023-11-14T22:07:20Z", "expires_at": "2023-11-14T22:37:20Z",
            "dry_run": false, "incident_id": null, "version": 4,
            "route": {"next_hop": "192.0.2.1"}
        });
        let shown = mitigation(&m, NOW);
        assert!(
            shown.contains("flowspec_rate_limit [protocol=17 destination_port=53] at 125000 B/s"),
            "{shown}"
        );
        assert!(shown.contains("Dry run       false"), "{shown}");
        assert!(!shown.contains("Incident"), "a null field is left out");
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        let table = mitigation_list(&json!({"items": [m]}), false, NOW);
        assert!(table.starts_with("ID  "), "{table}");
        assert!(
            table.contains("active  flowspec_rate_limit  203.0.113.9/32  6m"),
            "{table}"
        );
        assert_eq!(
            mitigation_list(&json!({"items": []}), false, NOW),
            "No mitigations.\n"
        );
        let history = mitigation_history(&json!({"items": [
            {"version": 1, "occurred_at": "t1", "from_state": null, "to_state": "requested", "actor": "operator:u_1", "detail": null},
            {"version": 2, "occurred_at": "t2", "from_state": "requested", "to_state": "approved", "actor": "operator:u_2", "detail": null}
        ]}));
        assert!(history.contains("requested → approved"), "{history}");
    }

    #[test]
    fn the_kill_switch_and_stale_peers_say_so() {
        let engaged = kill_switch(
            &json!({"engaged": true, "version": 2, "changed_at": "2023-11-14T22:07:20Z",
                    "changed_by": "operator:lead", "reason": "storm"}),
            NOW,
        );
        assert!(engaged.contains("ENGAGED"), "{engaged}");
        assert!(engaged.contains("6m ago"), "{engaged}");
        let released = kill_switch(&json!({"engaged": false, "version": 1}), NOW);
        assert!(released.contains("released") && !released.contains("Changed"));

        let fresh = json!({"items": [{"neighbor_address": "192.0.2.254", "peer_asn": 64512,
                                      "session_state": "established", "updated_at": "2023-11-14T22:12:20Z"}]});
        assert!(bgp_peers(&fresh, false, NOW).contains("192.0.2.254  64512  established  1m"));
        assert_eq!(stale_peers(&fresh, NOW), None);
        let old = json!({"items": [{"neighbor_address": "192.0.2.254", "peer_asn": 64512,
                                    "session_state": "established", "updated_at": "2023-11-14T21:13:20Z"}]});
        assert!(stale_peers(&old, NOW).unwrap().contains("1h ago"));
        assert_eq!(stale_peers(&json!({"items": []}), NOW), None);
    }

    #[test]
    fn a_conflict_shows_what_is_true_now() {
        let text = problem(&json!({
            "error": "incident.version_conflict", "title": "Version conflict",
            "expected_version": 6, "current_version": 8, "current_state": "resolved"
        }));
        assert!(text.starts_with("Error: Version conflict (incident.version_conflict)"));
        assert!(text.contains("current version: 8"));
        assert!(text.contains("current state: resolved"));
    }
}
