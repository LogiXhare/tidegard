//! The mitigator's configuration (ADR 0049): the environment for where
//! things are, and one JSON file for what it may do.
//!
//! ```json
//! {
//!   "guard": { "allowlist": [ ... ] },
//!   "routes": { "local_asn": 65001, "rtbh_next_hop_ipv4": "192.0.2.1",
//!               "rtbh_next_hop_ipv6": "2001:db8::1" },
//!   "gobgp": { "url": "http://127.0.0.1:50051" },
//!   "proposals": { "enabled": false }
//! }
//! ```
//!
//! `guard` is ADR 0047's configuration. Instead of writing it here,
//! `guard_file` may name a file holding it, which the API reads too
//! (`WETECHINETMON_API_MITIGATION_GUARD_FILE`): one allowlist for both.
//! Neither is the fresh install: dry-run, BGP off, nothing allowlisted.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use wetechinetmon_mitigation::{Guard, GuardConfig};

use crate::gobgp::GoBgpEndpoint;
use crate::route::RouteConfig;

pub const DATABASE_URL_ENV_VAR: &str = "WETECHINETMON_MITIGATOR_DATABASE_URL";
pub const DATABASE_CA_FILE_ENV_VAR: &str = "WETECHINETMON_MITIGATOR_DATABASE_CA_FILE";
pub const CONFIG_FILE_ENV_VAR: &str = "WETECHINETMON_MITIGATOR_CONFIG";
pub const METRICS_BIND_ENV_VAR: &str = "WETECHINETMON_MITIGATOR_METRICS_BIND";
pub const CONSUMER_ID_ENV_VAR: &str = "WETECHINETMON_MITIGATOR_ID";
pub const DEFAULT_METRICS_BIND: &str = "127.0.0.1:9094";
pub const DEFAULT_CONSUMER_ID: &str = "wetechinetmon-mitigator";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    #[serde(default)]
    pub guard: GuardConfig,
    /// A file holding the guard, shared with the API. Not with `guard`.
    #[serde(default)]
    pub guard_file: Option<PathBuf>,
    pub routes: RouteConfig,
    pub gobgp: GoBgpEndpoint,
    #[serde(default)]
    pub proposals: ProposalPolicy,
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_reconcile")]
    pub reconcile_interval_seconds: u64,
}

fn default_poll_ms() -> u64 {
    2_000
}

fn default_reconcile() -> u64 {
    60
}

/// When the mitigator proposes an RTBH for an incident (BQ-14). Off by
/// default; a proposal announces nothing until someone approves it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// Incident severities to propose for.
    #[serde(default = "default_severities")]
    pub severities: Vec<String>,
    /// Only incidents opened this recently.
    #[serde(default = "default_within")]
    pub within_seconds: u64,
    /// How long a proposed mitigation would last.
    #[serde(default = "default_duration")]
    pub duration_seconds: u64,
}

fn default_severities() -> Vec<String> {
    vec!["critical".to_string()]
}

fn default_within() -> u64 {
    900
}

fn default_duration() -> u64 {
    1_800
}

impl Default for ProposalPolicy {
    fn default() -> Self {
        ProposalPolicy {
            enabled: false,
            severities: default_severities(),
            within_seconds: default_within(),
            duration_seconds: default_duration(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{var} is invalid: {expected}")]
    Invalid {
        var: &'static str,
        expected: &'static str,
    },
    #[error("the configuration file is invalid: {0}")]
    File(String),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub database_ca_file: Option<PathBuf>,
    pub consumer_id: String,
    pub metrics_bind: SocketAddr,
    pub file: File,
    pub guard: Guard,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
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
                expected: "a socket address such as 127.0.0.1:9094",
            })?;
        let file = load_file(Path::new(path.trim()))?;
        let guard = Guard::new(file.guard.clone()).map_err(|e| ConfigError::File(e.to_string()))?;
        Ok(Config {
            database_url,
            database_ca_file: get(DATABASE_CA_FILE_ENV_VAR).map(PathBuf::from),
            consumer_id: get(CONSUMER_ID_ENV_VAR)
                .map(|id| id.trim().to_string())
                .unwrap_or_else(|| DEFAULT_CONSUMER_ID.to_string()),
            metrics_bind,
            file,
            guard,
        })
    }
}

pub fn load_file(path: &Path) -> Result<File, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::File(format!("{}: {error}", path.display())))?;
    let mut file = parse_file(&text)?;
    if let Some(guard_path) = &file.guard_file {
        if file.guard != GuardConfig::default() {
            return Err(ConfigError::File(
                "give guard or guard_file, not both".into(),
            ));
        }
        let guard = std::fs::read_to_string(guard_path)
            .map_err(|error| ConfigError::File(format!("{}: {error}", guard_path.display())))?;
        file.guard = serde_json::from_str(&guard)
            .map_err(|error| ConfigError::File(format!("{}: {error}", guard_path.display())))?;
        Guard::new(file.guard.clone()).map_err(|e| ConfigError::File(e.to_string()))?;
    }
    Ok(file)
}

pub fn parse_file(text: &str) -> Result<File, ConfigError> {
    let file: File =
        serde_json::from_str(text).map_err(|error| ConfigError::File(error.to_string()))?;
    Guard::new(file.guard.clone()).map_err(|e| ConfigError::File(e.to_string()))?;
    if file.poll_interval_ms < 100 || file.reconcile_interval_seconds == 0 {
        return Err(ConfigError::File(
            "poll_interval_ms must be at least 100 and reconcile_interval_seconds above 0".into(),
        ));
    }
    let p = &file.proposals;
    if p.enabled
        && (p.severities.is_empty()
            || p.severities
                .iter()
                .any(|s| !matches!(s.as_str(), "info" | "minor" | "major" | "critical")))
    {
        return Err(ConfigError::File(
            "proposals.severities must name info, minor, major or critical".into(),
        ));
    }
    Ok(file)
}

impl File {
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }

    pub fn reconcile_interval(&self) -> Duration {
        Duration::from_secs(self.reconcile_interval_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{
        "routes": {"local_asn": 65001, "rtbh_next_hop_ipv4": "192.0.2.1",
                   "rtbh_next_hop_ipv6": "2001:db8::1"},
        "gobgp": {"url": "http://127.0.0.1:50051"}
    }"#;

    #[test]
    fn a_minimal_file_is_a_safe_install() {
        let file = parse_file(MINIMAL).unwrap();
        let guard = Guard::new(file.guard.clone()).unwrap();
        assert!(guard.config().dry_run);
        assert!(!guard.config().bgp_enabled);
        assert!(guard.config().allowlist.is_empty());
        assert!(!file.proposals.enabled);
        assert_eq!(file.poll_interval(), Duration::from_secs(2));
    }

    #[test]
    fn bad_files_are_refused() {
        for text in [
            r#"{"gobgp": {"url": "http://127.0.0.1:50051"}}"#,
            r#"{"routes": {"local_asn": 1, "rtbh_next_hop_ipv4": "192.0.2.1", "rtbh_next_hop_ipv6": "::1"},
                "gobgp": {"url": "http://127.0.0.1:50051"}, "dryrun": false}"#,
            r#"{"routes": {"local_asn": 1, "rtbh_next_hop_ipv4": "192.0.2.1", "rtbh_next_hop_ipv6": "::1"},
                "gobgp": {"url": "http://127.0.0.1:50051"},
                "guard": {"allowlist": [{"prefix": "10.0.0.0/8", "tenant": "a", "actions": ["rtbh"]}]}}"#,
            r#"{"routes": {"local_asn": 1, "rtbh_next_hop_ipv4": "192.0.2.1", "rtbh_next_hop_ipv6": "::1"},
                "gobgp": {"url": "http://127.0.0.1:50051"},
                "proposals": {"enabled": true, "severities": ["urgent"]}}"#,
        ] {
            assert!(parse_file(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_guard_file_is_shared_and_exclusive() {
        let dir = std::env::temp_dir().join(format!("wnm-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let guard = dir.join("guard.json");
        std::fs::write(&guard, r#"{"bgp_enabled": true, "allowlist": [{"prefix": "192.0.2.0/24", "tenant": "acme", "actions": ["rtbh"]}]}"#).unwrap();
        let path = guard.display().to_string().replace('\\', "/");
        let shared = dir.join("shared.json");
        std::fs::write(
            &shared,
            MINIMAL.replace(
                "\"gobgp\"",
                &format!("\"guard_file\": \"{path}\", \"gobgp\""),
            ),
        )
        .unwrap();
        let file = load_file(&shared).unwrap();
        assert!(file.guard.bgp_enabled);
        assert_eq!(file.guard.allowlist.len(), 1);
        let both = dir.join("both.json");
        std::fs::write(
            &both,
            MINIMAL.replace(
                "\"gobgp\"",
                &format!(
                    "\"guard\": {{\"kill_switch\": true}}, \"guard_file\": \"{path}\", \"gobgp\""
                ),
            ),
        )
        .unwrap();
        assert!(load_file(&both).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_environment_names_the_database_and_the_file() {
        let none = |_: &str| None;
        assert_eq!(
            Config::from_lookup(none).unwrap_err(),
            ConfigError::Missing(DATABASE_URL_ENV_VAR)
        );
    }
}
