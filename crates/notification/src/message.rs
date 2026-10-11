//! What a notification says, in each channel's format (ADR 0045).
//!
//! Titles and targets are untrusted text. Control characters are removed,
//! long text is cut, and each channel's markup is escaped: Slack's `&`,
//! `<` and `>` (which would otherwise make links or `@channel` mentions),
//! and Teams' Markdown. Telegram gets plain text with no parse mode, and
//! the generic webhook gets JSON, which escapes itself.
//!
//! Every message says the incident was **not mitigated**: WetechiNetMon
//! detects and records, it does not act on traffic.

use serde_json::{json, Value};

const TITLE_MAX_CHARS: usize = 300;
pub const WEBHOOK_SCHEMA: &str = "wetechinetmon.notification.v1";

/// The facts a notification carries.
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

impl Notice {
    /// One line: `[MAJOR] WNM-2026-000001 opened: UDP flood on 203.0.113.10 (incoming)`.
    pub fn headline(&self) -> String {
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

    /// The lines under the headline.
    pub fn details(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "State: {} · Priority: {} · Tenant: {}",
                clean(&self.state, 32),
                clean(&self.priority, 8),
                clean(&self.tenant, 128)
            ),
            "Mitigation: none. WetechiNetMon detects and records; it does not act on traffic."
                .to_string(),
        ];
        if let Some(link) = &self.link {
            lines.push(clean(link, 512));
        }
        lines
    }

    pub fn plain_text(&self) -> String {
        let mut text = self.headline();
        for line in self.details() {
            text.push('\n');
            text.push_str(&line);
        }
        text
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

pub fn slack(notice: &Notice) -> Value {
    json!({ "text": escape_slack(&notice.plain_text()) })
}

pub fn teams(notice: &Notice) -> Value {
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

pub fn telegram(notice: &Notice, chat_id: &str) -> Value {
    // No parse_mode: Telegram shows the text exactly as sent.
    json!({
        "chat_id": chat_id,
        "text": notice.plain_text(),
        "disable_web_page_preview": true,
    })
}

pub fn webhook(notice: &Notice) -> Value {
    json!({
        "schema": WEBHOOK_SCHEMA,
        "product": "WetechiNetMon",
        "event_type": notice.event_type,
        "tenant": notice.tenant,
        "incident": {
            "incident_id": notice.incident_id,
            "incident_number": notice.incident_number,
            "title": clean(&notice.title, TITLE_MAX_CHARS),
            "severity": notice.severity,
            "state": notice.state,
            "priority": notice.priority,
            "target": notice.target,
            "direction": notice.direction,
            "link": notice.link,
        },
        "mitigation_status": "none",
    })
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
            link: Some("https://noc.example.net/incidents/0192f3c4".into()),
        }
    }

    #[test]
    fn every_message_says_nothing_was_mitigated() {
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
            assert!(text.contains("Mitigation: none"), "{text}");
        }
        assert_eq!(webhook(&notice)["mitigation_status"], "none");
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
}
