//! The notifier's configuration (ADR 0045): the environment for the process,
//! and a JSON file for channels and routes. Secrets are never in either:
//! the file names the files that hold them.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

pub const CONFIG_FILE_ENV_VAR: &str = "TIDEGARD_NOTIFY_CONFIG";
pub const DATABASE_URL_ENV_VAR: &str = "TIDEGARD_NOTIFY_DATABASE_URL";
pub const DATABASE_CA_FILE_ENV_VAR: &str = "TIDEGARD_NOTIFY_DATABASE_CA_FILE";
pub const CONSUMER_ID_ENV_VAR: &str = "TIDEGARD_NOTIFY_CONSUMER_ID";
pub const METRICS_BIND_ENV_VAR: &str = "TIDEGARD_NOTIFY_METRICS_BIND";
const DEFAULT_METRICS_BIND: &str = "127.0.0.1:9093";
const DEFAULT_CONSUMER_ID: &str = "notifier-1";

/// A channel kind. Each speaks its service's own format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    /// Generic JSON, signed with HMAC-SHA-256.
    Webhook,
    Slack,
    Teams,
    Telegram,
    /// SMTP, with STARTTLS or implicit TLS.
    Email,
}

/// How an SMTP connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// Port 587: plain, then upgraded; refused if the server cannot.
    #[default]
    Starttls,
    /// Port 465: TLS from the first byte.
    Implicit,
    /// No TLS: only with `allow_private`, for a relay on the same network.
    None,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Webhook => "webhook",
            ChannelKind::Slack => "slack",
            ChannelKind::Teams => "teams",
            ChannelKind::Telegram => "telegram",
            ChannelKind::Email => "email",
        }
    }
}

/// One channel as written in the file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSpec {
    pub kind: ChannelKind,
    /// The destination, when it holds no secret (a generic webhook).
    pub url: Option<String>,
    /// A file holding the destination, when the URL is the secret (Slack
    /// and Teams incoming webhooks).
    pub url_file: Option<PathBuf>,
    /// The webhook signing secret.
    pub secret_file: Option<PathBuf>,
    /// Telegram: the bot token's file, the chat and the API base.
    pub bot_token_file: Option<PathBuf>,
    pub chat_id: Option<String>,
    pub api_base: Option<String>,
    /// Email: the relay, how it is secured, the sign-in, and the envelope.
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_tls: SmtpTls,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    /// Allows plain HTTP and private addresses: for a receiver inside the
    /// operator's network, or a test.
    #[serde(default)]
    pub allow_private: bool,
}

/// One route: which events of which tenant go to which channels.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub tenant: String,
    /// Outbox event types, such as `incident.opened`.
    pub events: Vec<String>,
    /// The least severe incident this route carries; all when absent.
    pub min_severity: Option<String>,
    pub channels: Vec<String>,
}

/// The file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub channels: BTreeMap<String, ChannelSpec>,
    pub routes: Vec<Route>,
    /// Host names a destination may have: exact, or `*.` and a suffix.
    pub allowed_hosts: Vec<String>,
    /// The CA bundle for every HTTPS destination.
    pub ca_file: PathBuf,
    /// The NOC UI's address, for links to an incident.
    pub ui_base_url: Option<String>,
    #[serde(default = "default_rate")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_dedup")]
    pub dedup_seconds: u64,
}

fn default_rate() -> u32 {
    30
}

fn default_dedup() -> u64 {
    300
}

pub const SEVERITIES: [&str; 4] = ["info", "minor", "major", "critical"];

/// Why the configuration cannot be used. Never holds a secret.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("{var} is not valid: expected {expected}")]
    Invalid {
        var: &'static str,
        expected: &'static str,
    },
    #[error("the notification file cannot be used: {0}")]
    File(String),
}

/// Everything the process needs.
#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub database_ca_file: Option<PathBuf>,
    pub consumer_id: String,
    pub metrics_bind: SocketAddr,
    pub file: File,
    pub dedup: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("consumer_id", &self.consumer_id)
            .field("metrics_bind", &self.metrics_bind)
            .field("channels", &self.file.channels.keys().collect::<Vec<_>>())
            .field("routes", &self.file.routes.len())
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| tidegard_common::env::var(var).ok().flatten())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |var: &str| lookup(var).filter(|value| !value.trim().is_empty());
        let database_url =
            get(DATABASE_URL_ENV_VAR).ok_or(ConfigError::Missing(DATABASE_URL_ENV_VAR))?;
        let path = get(CONFIG_FILE_ENV_VAR).ok_or(ConfigError::Missing(CONFIG_FILE_ENV_VAR))?;
        let metrics_bind = get(METRICS_BIND_ENV_VAR)
            .unwrap_or_else(|| DEFAULT_METRICS_BIND.to_string())
            .trim()
            .parse()
            .map_err(|_| ConfigError::Invalid {
                var: METRICS_BIND_ENV_VAR,
                expected: "a socket address such as 127.0.0.1:9093",
            })?;
        let file = load_file(Path::new(path.trim()))?;
        Ok(Config {
            database_url,
            database_ca_file: get(DATABASE_CA_FILE_ENV_VAR).map(PathBuf::from),
            consumer_id: get(CONSUMER_ID_ENV_VAR)
                .map(|id| id.trim().to_string())
                .unwrap_or_else(|| DEFAULT_CONSUMER_ID.to_string()),
            metrics_bind,
            dedup: Duration::from_secs(file.dedup_seconds),
            file,
        })
    }
}

/// Reads and checks the file: every route names known channels and a
/// known severity, and every channel has what its kind needs.
pub fn load_file(path: &Path) -> Result<File, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::File(format!("{}: {error}", path.display())))?;
    parse_file(&text)
}

pub fn parse_file(text: &str) -> Result<File, ConfigError> {
    let file: File =
        serde_json::from_str(text).map_err(|error| ConfigError::File(error.to_string()))?;
    for (name, spec) in &file.channels {
        let plain = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !plain {
            return Err(ConfigError::File(format!(
                "channel name {name:?} must be letters, digits, '-', '_' or '.'"
            )));
        }
        let ok = match spec.kind {
            ChannelKind::Webhook => {
                (spec.url.is_some() ^ spec.url_file.is_some()) && spec.secret_file.is_some()
            }
            ChannelKind::Slack | ChannelKind::Teams => {
                spec.url_file.is_some() && spec.url.is_none()
            }
            ChannelKind::Telegram => spec.bot_token_file.is_some() && spec.chat_id.is_some(),
            ChannelKind::Email => {
                spec.smtp_host.is_some()
                    && spec.from.is_some()
                    && !spec.to.is_empty()
                    && spec.username.is_some() == spec.password_file.is_some()
                    && (spec.smtp_tls != SmtpTls::None || spec.allow_private)
            }
        };
        if !ok {
            return Err(ConfigError::File(format!(
                "channel {name}: a {} needs {}",
                spec.kind.as_str(),
                match spec.kind {
                    ChannelKind::Webhook => "url or url_file, and secret_file",
                    ChannelKind::Slack | ChannelKind::Teams =>
                        "url_file (the URL is the secret), and no url",
                    ChannelKind::Telegram => "bot_token_file and chat_id",
                    ChannelKind::Email =>
                        "smtp_host, from and to; username and password_file together; and smtp_tls none only with allow_private",
                }
            )));
        }
    }
    for route in &file.routes {
        if let Some(unknown) = route
            .channels
            .iter()
            .find(|name| !file.channels.contains_key(*name))
        {
            return Err(ConfigError::File(format!(
                "a route for {} names no channel {unknown:?}",
                route.tenant
            )));
        }
        if let Some(severity) = &route.min_severity {
            if !SEVERITIES.contains(&severity.as_str()) {
                return Err(ConfigError::File(format!(
                    "min_severity {severity:?} is not one of {SEVERITIES:?}"
                )));
            }
        }
        if route.events.is_empty() || route.channels.is_empty() {
            return Err(ConfigError::File(format!(
                "a route for {} needs events and channels",
                route.tenant
            )));
        }
    }
    if file.rate_limit_per_minute == 0 {
        return Err(ConfigError::File(
            "rate_limit_per_minute must be at least 1".into(),
        ));
    }
    Ok(file)
}

/// The channels a route sends `event` of `severity` for `tenant` to,
/// each named once.
pub fn channels_for<'a>(file: &'a File, tenant: &str, event: &str, severity: &str) -> Vec<&'a str> {
    let rank = |name: &str| SEVERITIES.iter().position(|s| *s == name);
    let mut found: Vec<&str> = Vec::new();
    for route in &file.routes {
        let severe_enough = match (&route.min_severity, rank(severity)) {
            (None, _) => true,
            (Some(min), Some(actual)) => rank(min).is_some_and(|min| actual >= min),
            (Some(_), None) => false,
        };
        if route.tenant == tenant && route.events.iter().any(|e| e == event) && severe_enough {
            for channel in &route.channels {
                if !found.contains(&channel.as_str()) {
                    found.push(channel);
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"{
        "channels": {
            "noc-slack": {"kind": "slack", "url_file": "/run/secrets/slack"},
            "hook": {"kind": "webhook", "url": "https://hooks.example.net/wnm", "secret_file": "/run/secrets/hook"},
            "tg": {"kind": "telegram", "bot_token_file": "/run/secrets/tg", "chat_id": "-100123"}
        },
        "routes": [
            {"tenant": "acme", "events": ["incident.opened"], "min_severity": "major", "channels": ["noc-slack", "tg"]},
            {"tenant": "acme", "events": ["incident.opened", "incident.resolved"], "channels": ["hook", "tg"]}
        ],
        "allowed_hosts": ["hooks.slack.com", "api.telegram.org", "hooks.example.net"],
        "ca_file": "/etc/ssl/certs/ca-certificates.crt"
    }"#;

    #[test]
    fn routes_pick_channels_by_tenant_event_and_severity() {
        let file = parse_file(FILE).unwrap();
        assert_eq!(file.rate_limit_per_minute, 30);
        assert_eq!(file.dedup_seconds, 300);
        assert_eq!(
            channels_for(&file, "acme", "incident.opened", "critical"),
            vec!["noc-slack", "tg", "hook"]
        );
        assert_eq!(
            channels_for(&file, "acme", "incident.opened", "minor"),
            vec!["hook", "tg"]
        );
        assert_eq!(
            channels_for(&file, "acme", "incident.resolved", "critical"),
            vec!["hook", "tg"]
        );
        assert!(channels_for(&file, "globex", "incident.opened", "critical").is_empty());
        assert!(channels_for(&file, "acme", "incident.closed", "critical").is_empty());
    }

    #[test]
    fn a_bad_file_is_refused_with_a_reason() {
        for (broken, why) in [
            (
                FILE.replace("\"noc-slack\", \"tg\"", "\"noc-slack\", \"nowhere\""),
                "unknown channel",
            ),
            (FILE.replace("\"major\"", "\"huge\""), "unknown severity"),
            (
                FILE.replace(
                    r#""url_file": "/run/secrets/slack""#,
                    r#""url": "https://hooks.slack.com/x""#,
                ),
                "a Slack URL is a secret",
            ),
            (
                FILE.replace(r#", "secret_file": "/run/secrets/hook""#, ""),
                "an unsigned webhook",
            ),
            (
                FILE.replace("\"noc-slack\": {", "\"noc slack\": {")
                    .replace("[\"noc-slack\", \"tg\"]", "[\"tg\"]"),
                "a name with a space",
            ),
            (FILE.replace("\"ca_file\"", "\"ca\""), "an unknown field"),
        ] {
            assert!(parse_file(&broken).is_err(), "{why}");
        }
    }

    #[test]
    fn an_email_channel_needs_its_envelope_and_tls() {
        let with = |channel: &str| {
            FILE.replace(
                "\"tg\": {",
                &format!("\"mail\": {channel},\n            \"tg\": {{"),
            )
        };
        let good = r#"{"kind": "email", "smtp_host": "smtp.example.net", "from": "noc@example.net", "to": ["oncall@example.net"], "username": "noc", "password_file": "/run/secrets/smtp"}"#;
        let file = parse_file(&with(good)).unwrap();
        assert_eq!(
            file.channels["mail"].smtp_tls,
            SmtpTls::Starttls,
            "TLS by default"
        );
        for bad in [
            r#"{"kind": "email", "smtp_host": "smtp.example.net", "from": "noc@example.net", "to": []}"#,
            r#"{"kind": "email", "from": "noc@example.net", "to": ["a@example.net"]}"#,
            r#"{"kind": "email", "smtp_host": "smtp.example.net", "from": "noc@example.net", "to": ["a@example.net"], "username": "noc"}"#,
            r#"{"kind": "email", "smtp_host": "smtp.example.net", "from": "noc@example.net", "to": ["a@example.net"], "smtp_tls": "none"}"#,
        ] {
            assert!(parse_file(&with(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_database_url_is_never_debug_printed() {
        let dir = std::env::temp_dir().join(format!("wnm-notify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("notify.json");
        std::fs::write(&file, FILE).unwrap();
        let config = Config::from_lookup(|var| match var {
            DATABASE_URL_ENV_VAR => Some("host=db password=hunter2".into()),
            CONFIG_FILE_ENV_VAR => Some(file.display().to_string()),
            _ => None,
        })
        .unwrap();
        assert!(!format!("{config:?}").contains("hunter2"));
        assert_eq!(config.consumer_id, "notifier-1");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
