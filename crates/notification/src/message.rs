//! What a notification says, in each channel's format (ADR 0045, ADR 0050).
//!
//! Titles, targets and reasons are untrusted text. Control characters are
//! removed, long text is cut, and each channel's markup is escaped: Slack's
//! `&`, `<` and `>` (which would otherwise make links or `@channel`
//! mentions), and Teams' Markdown. Telegram gets plain text with no parse
//! mode, and the generic webhook gets JSON, which escapes itself.
//!
//! Two kinds of news are told: an incident's ([`Notice`]), which says what
//! the incident's mitigation stands at, and a mitigation's, the kill
//! switch's or a BGP session's ([`MitigationNotice`]), from the outbox
//! payload the change wrote.

use serde_json::{json, Value};

const TITLE_MAX_CHARS: usize = 300;
const REASON_MAX_CHARS: usize = 500;
pub const WEBHOOK_SCHEMA: &str = "wetechinetmon.notification.v1";

/// What every channel needs from a notification.
pub trait Render: Sync {
    /// One line.
    fn headline(&self) -> String;
    /// The lines under the headline.
    fn details(&self) -> Vec<String>;
    /// The generic webhook's JSON body.
    fn webhook(&self) -> Value;

    fn plain_text(&self) -> String {
        let mut text = self.headline();
        for line in self.details() {
            text.push('\n');
            text.push_str(&line);
        }
        text
    }
}

/// The facts an incident notification carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub event_type: String,
    pub tenant: String,
    pub incident_id: String,
    pub incident_number: String,
    pub title: String,
    pub severity: String,
    pub state: String,
    pub priority: String,
    pub target: String,
    pub direction: String,
    /// The incident's mitigation, as the records say (FU-64): `none`,
    /// `pending_approval`, `active`, `withdrawn` and so on.
    pub mitigation_status: String,
    /// The incident in the NOC UI, when its address is configured.
    pub link: Option<String>,
}

/// Removes control characters and cuts to `max` characters.
pub fn clean(text: &str, max: usize) -> String {
    let cleaned: String = text.chars().filter(|c| !c.is_control()).collect();
    if cleaned.chars().count() <= max {
        cleaned
    } else {
        let mut cut: String = cleaned.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

fn what_happened(event_type: &str) -> &str {
    match event_type {
        "incident.opened" => "opened",
        "incident.reopened" => "reopened",
        "incident.acknowledged" => "acknowledged",
        "incident.recovering" => "is recovering",
        "incident.resolved" => "resolved",
        "incident.closed" => "closed",
        "incident.severity_changed" => "changed severity",
        "incident.priority_changed" => "changed priority",
        "incident.assignment_changed" => "was reassigned",
        "incident.state_changed" => "changed state",
        "incident.suppression_changed" => "changed suppression",
        _ => "was updated",
    }
}

impl Render for Notice {
    /// `[MAJOR] WNM-2026-000001 opened: UDP flood on 203.0.113.10 (incoming)`.
    fn headline(&self) -> String {
        format!(
            "[{}] {} {}: {} on {} ({})",
            clean(&self.severity, 16).to_uppercase(),
            clean(&self.incident_number, 32),
            what_happened(&self.event_type),
            clean(&self.title, TITLE_MAX_CHARS),
            clean(&self.target, 64),
            clean(&self.direction, 16),
        )
    }

    fn details(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "State: {} · Priority: {} · Tenant: {}",
                clean(&self.state, 32),
                clean(&self.priority, 8),
                clean(&self.tenant, 128)
            ),
            format!("Mitigation: {}", clean(&self.mitigation_status, 32)),
        ];
        if let Some(link) = &self.link {
            lines.push(clean(link, 512));
        }
        lines
    }

    fn webhook(&self) -> Value {
        json!({
            "schema": WEBHOOK_SCHEMA,
            "product": "WetechiNetMon",
            "event_type": self.event_type,
            "tenant": self.tenant,
            "incident": {
                "incident_id": self.incident_id,
                "incident_number": self.incident_number,
                "title": clean(&self.title, TITLE_MAX_CHARS),
                "severity": self.severity,
                "state": self.state,
                "priority": self.priority,
                "target": self.target,
                "direction": self.direction,
                "link": self.link,
            },
            "mitigation_status": self.mitigation_status,
        })
    }
}

/// The outbox aggregates a [`MitigationNotice`] is made from.
pub const MITIGATION_AGGREGATES: [&str; 3] = ["mitigation", "mitigation_controls", "bgp_peer"];

/// A mitigation's, the kill switch's or a BGP session's change, as the
/// outbox payload written with it describes it (ADR 0050).
#[derive(Debug, Clone, PartialEq)]
pub struct MitigationNotice {
    pub event_type: String,
    pub tenant: String,
    pub payload: Value,
    /// The NOC UI's mitigations page, when its address is configured.
    pub link: Option<String>,
}

impl MitigationNotice {
    fn text(&self, name: &str, max: usize) -> String {
        match &self.payload[name] {
            Value::String(text) => clean(text, max),
            Value::Null => String::new(),
            other => clean(&other.to_string(), max),
        }
    }

    /// `rtbh of 203.0.113.9/32`.
    fn what(&self) -> String {
        format!("{} of {}", self.text("action", 32), self.text("prefix", 64))
    }

    /// The severity routes filter on (`min_severity`). A mitigation event
    /// has none of its own, so each kind has a fixed one: losing protection
    /// or control is critical, needing a decision is major.
    pub fn severity(&self) -> &'static str {
        match self.event_type.as_str() {
            "mitigation.failed" | "mitigation.kill_switch_engaged" | "bgp.peer_down" => "critical",
            "mitigation.proposed"
            | "mitigation.requested"
            | "mitigation.active"
            | "mitigation.kill_switch_released" => "major",
            "mitigation.withdrawn" if self.payload["withdrawal_cause"] == "kill_switch" => "major",
            _ => "minor",
        }
    }

    /// The incident the change belongs to, if any.
    pub fn incident_id(&self) -> Option<&str> {
        self.payload["incident_id"].as_str()
    }
}

impl Render for MitigationNotice {
    fn headline(&self) -> String {
        let dry_run = if self.payload["dry_run"] == true {
            " (dry-run: nothing was announced)"
        } else {
            ""
        };
        match self.event_type.as_str() {
            "mitigation.requested" => format!("[MITIGATION] Approval needed: {}", self.what()),
            "mitigation.proposed" => {
                format!("[MITIGATION] Proposed, approval needed: {}", self.what())
            }
            "mitigation.approved" => format!("[MITIGATION] Approved: {}", self.what()),
            "mitigation.active" => format!("[MITIGATION] Active: {}{dry_run}", self.what()),
            "mitigation.failed" => format!("[MITIGATION] FAILED: {}", self.what()),
            "mitigation.withdrawn" => format!(
                "[MITIGATION] Withdrawn ({}): {}",
                match self.text("withdrawal_cause", 32).as_str() {
                    "" => "before announcing".to_string(),
                    cause => cause.replace('_', " "),
                },
                self.what()
            ),
            "mitigation.kill_switch_engaged" => "[KILL SWITCH] Engaged: nothing is announced, \
                 and live mitigations are withdrawn"
                .to_string(),
            "mitigation.kill_switch_released" => {
                "[KILL SWITCH] Released: approved mitigations may be announced again".to_string()
            }
            "bgp.peer_down" => format!(
                "[BGP] Peer {} (AS{}) is down: {}, was {}",
                self.text("neighbor_address", 64),
                self.text("peer_asn", 16),
                self.text("session_state", 16),
                self.text("previous_state", 16),
            ),
            "bgp.peer_up" => format!(
                "[BGP] Peer {} (AS{}) is established again",
                self.text("neighbor_address", 64),
                self.text("peer_asn", 16),
            ),
            other => format!(
                "[MITIGATION] {}: {}",
                clean(other.trim_start_matches("mitigation."), 32),
                self.what()
            ),
        }
    }

    fn details(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let reason = self.text("reason", REASON_MAX_CHARS);
        if !reason.is_empty() {
            lines.push(format!("Reason: {reason}"));
        }
        let detail = self.text("detail", REASON_MAX_CHARS);
        if !detail.is_empty() {
            lines.push(format!("Detail: {detail}"));
        }
        lines.push(format!("Tenant: {}", clean(&self.tenant, 128)));
        if let Some(link) = &self.link {
            lines.push(clean(link, 512));
        }
        lines
    }

    fn webhook(&self) -> Value {
        // The payload is the store's, which carries no route attribute and
        // nothing secret; reasons are cut like titles.
        let mut payload = self.payload.clone();
        for name in ["reason", "detail"] {
            if let Some(Value::String(text)) = payload.get(name) {
                payload[name] = Value::String(clean(text, REASON_MAX_CHARS));
            }
        }
        let key = match self.event_type.as_str() {
            "mitigation.kill_switch_engaged" | "mitigation.kill_switch_released" => "kill_switch",
            event if event.starts_with("bgp.") => "bgp_peer",
            _ => "mitigation",
        };
        json!({
            "schema": WEBHOOK_SCHEMA,
            "product": "WetechiNetMon",
            "event_type": self.event_type,
            "tenant": self.tenant,
            key: payload,
            "link": self.link,
        })
    }
}

/// Slack's three control characters, escaped as Slack documents.
pub fn escape_slack(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Teams Markdown, neutralised by escaping every character it gives meaning.
pub fn escape_markdown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "\\`*_{}[]()#+-.!|>~<".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub fn slack(notice: &dyn Render) -> Value {
    json!({ "text": escape_slack(&notice.plain_text()) })
}

pub fn teams(notice: &dyn Render) -> Value {
    let mut body = vec![json!({
        "type": "TextBlock",
        "text": escape_markdown(&notice.headline()),
        "weight": "Bolder",
        "wrap": true,
    })];
    for line in notice.details() {
        body.push(json!({ "type": "TextBlock", "text": escape_markdown(&line), "wrap": true }));
    }
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
            },
        }],
    })
}

pub fn telegram(notice: &dyn Render, chat_id: &str) -> Value {
    // No parse_mode: Telegram shows the text exactly as sent.
    json!({
        "chat_id": chat_id,
        "text": notice.plain_text(),
        "disable_web_page_preview": true,
    })
}

pub fn webhook(notice: &dyn Render) -> Value {
    notice.webhook()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(title: &str) -> Notice {
        Notice {
            event_type: "incident.opened".into(),
            tenant: "acme".into(),
            incident_id: "0192f3c4-0000-7000-8000-000000000001".into(),
            incident_number: "WNM-2026-000001".into(),
            title: title.into(),
            severity: "major".into(),
            state: "open".into(),
            priority: "P2".into(),
            target: "203.0.113.10".into(),
            direction: "incoming".into(),
            mitigation_status: "active".into(),
            link: Some("https://noc.example.net/incidents/0192f3c4".into()),
        }
    }

    fn mitigation(event_type: &str, payload: Value) -> MitigationNotice {
        MitigationNotice {
            event_type: event_type.into(),
            tenant: "acme".into(),
            payload,
            link: Some("https://noc.example.net/mitigations".into()),
        }
    }

    #[test]
    fn every_incident_message_says_where_its_mitigation_stands() {
        let notice = notice("UDP flood");
        assert_eq!(
            notice.headline(),
            "[MAJOR] WNM-2026-000001 opened: UDP flood on 203.0.113.10 (incoming)"
        );
        for text in [
            slack(&notice).to_string(),
            teams(&notice).to_string(),
            telegram(&notice, "-1").to_string(),
        ] {
            assert!(text.contains("Mitigation: active"), "{text}");
        }
        assert_eq!(webhook(&notice)["mitigation_status"], "active");
        assert_eq!(webhook(&notice)["schema"], WEBHOOK_SCHEMA);
    }

    #[test]
    fn hostile_titles_cannot_mention_link_or_format() {
        let notice =
            notice("<!channel> <https://evil.example|click> *pwn* [x](https://evil)\u{0007}\n");
        let slack = slack(&notice)["text"].as_str().unwrap().to_string();
        assert!(!slack.contains("<!channel>") && !slack.contains("<https://"));
        assert!(slack.contains("&lt;!channel&gt;"));
        let teams = teams(&notice).to_string();
        assert!(teams.contains("\\\\*pwn\\\\*"), "{teams}");
        assert!(teams.contains("\\\\[x\\\\]"), "{teams}");
        let telegram = telegram(&notice, "-1");
        assert!(telegram.get("parse_mode").is_none());
        assert!(!telegram["text"].as_str().unwrap().contains('\u{0007}'));
    }

    #[test]
    fn long_titles_are_cut() {
        let cut = clean(&"a".repeat(1000), 300);
        assert_eq!(cut.chars().count(), 300);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn mitigation_events_say_what_needs_doing() {
        let payload = json!({
            "mitigation_id": "m1", "tenant_id": "acme", "incident_id": "i1",
            "prefix": "203.0.113.9/32", "action": "rtbh", "state": "requested",
            "previous_state": null, "version": 1, "dry_run": null,
            "withdrawal_cause": null, "reason": "<!channel> flood\u{1b}[2J", "detail": null
        });
        let requested = mitigation("mitigation.requested", payload.clone());
        assert_eq!(
            requested.headline(),
            "[MITIGATION] Approval needed: rtbh of 203.0.113.9/32"
        );
        assert_eq!(requested.severity(), "major");
        assert_eq!(requested.incident_id(), Some("i1"));
        let text = slack(&requested)["text"].as_str().unwrap().to_string();
        assert!(text.contains("Reason: &lt;!channel&gt; flood[2J"), "{text}");
        assert!(text.contains("https://noc.example.net/mitigations"));
        let hook = webhook(&requested);
        assert_eq!(hook["mitigation"]["prefix"], "203.0.113.9/32");
        assert!(hook["mitigation"].get("next_hop").is_none());

        let mut active = payload.clone();
        active["dry_run"] = json!(true);
        assert!(mitigation("mitigation.active", active)
            .headline()
            .ends_with("(dry-run: nothing was announced)"));
        assert_eq!(
            mitigation("mitigation.failed", payload.clone()).severity(),
            "critical"
        );
        let mut withdrawn = payload;
        withdrawn["withdrawal_cause"] = json!("kill_switch");
        let withdrawn = mitigation("mitigation.withdrawn", withdrawn);
        assert_eq!(
            withdrawn.headline(),
            "[MITIGATION] Withdrawn (kill switch): rtbh of 203.0.113.9/32"
        );
        assert_eq!(withdrawn.severity(), "major");
    }

    #[test]
    fn the_kill_switch_and_peers_are_told_plainly() {
        let engaged = mitigation(
            "mitigation.kill_switch_engaged",
            json!({"kill_switch": true, "reason": "storm", "version": 2}),
        );
        assert!(engaged.headline().starts_with("[KILL SWITCH] Engaged"));
        assert_eq!(engaged.severity(), "critical");
        assert_eq!(webhook(&engaged)["kill_switch"]["reason"], "storm");

        let down = mitigation(
            "bgp.peer_down",
            json!({"neighbor_address": "192.0.2.254", "peer_asn": 64512,
                   "session_state": "idle", "previous_state": "established"}),
        );
        assert_eq!(
            down.headline(),
            "[BGP] Peer 192.0.2.254 (AS64512) is down: idle, was established"
        );
        assert_eq!(down.severity(), "critical");
        assert_eq!(down.incident_id(), None);
        assert_eq!(webhook(&down)["bgp_peer"]["peer_asn"], 64512);
        let up = mitigation(
            "bgp.peer_up",
            json!({"neighbor_address": "192.0.2.254", "peer_asn": 64512,
                   "session_state": "established", "previous_state": "active"}),
        );
        assert_eq!(up.severity(), "minor");
        assert!(up.headline().contains("established again"));
    }
}
