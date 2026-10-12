//! The safety guard (Phase 7B, ADR 0047).
//!
//! Every path to GoBGP passes through [`Guard::check`]: when a mitigation
//! is requested or proposed, when it is approved, and just before it is
//! announced. The guard refuses anything outside the deployment's
//! allowlist, anything another tenant owns, any action the allowlist entry
//! does not permit, anything wider than the length bounds, anything longer
//! than the maximum duration, and everything while the kill switch is on.
//!
//! The configuration is the deployment's, in a file. Until Phase 8 brings
//! prefix ownership, each allowlist entry names the one tenant that owns
//! it (BQ-4). [`GuardConfig::default`] is the fresh install: dry-run, BGP
//! off, nothing allowlisted, so nothing can be mitigated at all.

use std::time::Duration;

use serde::Deserialize;
use wetechinetmon_incident::correlation::TenantId;

use crate::action::{Action, ActionKind};
use crate::mitigation::{ApprovalPolicy, MAX_DURATION, MIN_DURATION};
use crate::prefix::Prefix;

/// No configuration may allow a non-host mitigation wider than these, or
/// an allowlist entry wider than these: a typo must not blackhole a /8.
pub const IPV4_FLOOR: u8 = 16;
pub const IPV6_FLOOR: u8 = 32;

const DEFAULT_IPV4_MIN: u8 = 24;
const DEFAULT_IPV6_MIN: u8 = 48;
const DEFAULT_MAX_DURATION: u64 = 3600;
const DEFAULT_APPROVAL_WINDOW: u64 = 900;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    /// Build every path and announce none. On in a fresh install.
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// Open a session to GoBGP at all. Off in a fresh install; while it is
    /// off, the mitigator behaves as in dry-run whatever `dry_run` says.
    #[serde(default)]
    pub bgp_enabled: bool,
    /// Refuse every new mitigation and take down what is up.
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default = "default_max_duration")]
    pub max_duration_seconds: u64,
    /// How long a proposal or request waits for an approver before it
    /// expires.
    #[serde(default = "default_approval_window")]
    pub approval_window_seconds: u64,
    #[serde(default)]
    pub allow_self_approval: bool,
    #[serde(default)]
    pub min_length: MinLength,
    #[serde(default)]
    pub allowlist: Vec<AllowlistEntry>,
}

/// The shortest prefix a non-host mitigation (a parent prefix, or a
/// FlowSpec destination) may name, per family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinLength {
    pub ipv4: u8,
    pub ipv6: u8,
}

impl Default for MinLength {
    fn default() -> Self {
        MinLength {
            ipv4: DEFAULT_IPV4_MIN,
            ipv6: DEFAULT_IPV6_MIN,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    pub prefix: Prefix,
    pub tenant: String,
    pub actions: Vec<ActionKind>,
}

fn yes() -> bool {
    true
}

fn default_max_duration() -> u64 {
    DEFAULT_MAX_DURATION
}

fn default_approval_window() -> u64 {
    DEFAULT_APPROVAL_WINDOW
}

impl Default for GuardConfig {
    fn default() -> Self {
        GuardConfig {
            dry_run: true,
            bgp_enabled: false,
            kill_switch: false,
            max_duration_seconds: DEFAULT_MAX_DURATION,
            approval_window_seconds: DEFAULT_APPROVAL_WINDOW,
            allow_self_approval: false,
            min_length: MinLength::default(),
            allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("min_length {0} is wider than the floor of /{IPV4_FLOOR} for IPv4 or /{IPV6_FLOOR} for IPv6, or longer than the family allows")]
    MinLength(String),
    #[error("max_duration_seconds must be between {} and {}", MIN_DURATION.as_secs(), MAX_DURATION.as_secs())]
    MaxDuration,
    #[error("approval_window_seconds must be between 60 and 86400")]
    ApprovalWindow,
    #[error("allowlist entry {0} is wider than the floor of /{IPV4_FLOOR} for IPv4 or /{IPV6_FLOOR} for IPv6")]
    EntryTooWide(Prefix),
    #[error("allowlist entry {0} has no tenant or no actions")]
    EntryEmpty(Prefix),
    #[error("allowlist entries {0} and {1} overlap and name different tenants")]
    Overlap(Prefix, Prefix),
}

/// Why the guard said no. The text names the rule, never another tenant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardRefusal {
    #[error("the kill switch is on: no mitigation may start")]
    KillSwitch,
    #[error("{0} is not on this tenant's allowlist")]
    NotAllowlisted(Prefix),
    #[error("the allowlist does not permit {kind} on {1}", kind = .0.as_str())]
    ActionNotAllowed(ActionKind, Prefix),
    #[error("{0} is wider than the shortest prefix allowed, /{1}")]
    TooWide(Prefix, u8),
    #[error("the duration is longer than the maximum, {0} seconds")]
    TooLong(u64),
}

impl GuardRefusal {
    /// Stable: an API client may switch on it.
    pub fn code(&self) -> &'static str {
        match self {
            GuardRefusal::KillSwitch => "mitigation.kill_switch",
            GuardRefusal::NotAllowlisted(_) => "mitigation.not_allowlisted",
            GuardRefusal::ActionNotAllowed(..) => "mitigation.action_not_allowed",
            GuardRefusal::TooWide(..) => "mitigation.too_wide",
            GuardRefusal::TooLong(_) => "mitigation.too_long",
        }
    }
}

/// A checked configuration. The only way to build one is
/// [`Guard::new`], which validates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guard {
    config: GuardConfig,
}

impl Guard {
    pub fn new(config: GuardConfig) -> Result<Self, ConfigError> {
        let min = config.min_length;
        if !(IPV4_FLOOR..=32).contains(&min.ipv4) {
            return Err(ConfigError::MinLength(format!("ipv4 /{}", min.ipv4)));
        }
        if !(IPV6_FLOOR..=128).contains(&min.ipv6) {
            return Err(ConfigError::MinLength(format!("ipv6 /{}", min.ipv6)));
        }
        let max = Duration::from_secs(config.max_duration_seconds);
        if max < MIN_DURATION || max > MAX_DURATION {
            return Err(ConfigError::MaxDuration);
        }
        if !(60..=86_400).contains(&config.approval_window_seconds) {
            return Err(ConfigError::ApprovalWindow);
        }
        for entry in &config.allowlist {
            if entry.prefix.length() < floor(&entry.prefix) {
                return Err(ConfigError::EntryTooWide(entry.prefix));
            }
            if entry.tenant.trim().is_empty() || entry.actions.is_empty() {
                return Err(ConfigError::EntryEmpty(entry.prefix));
            }
        }
        for (i, a) in config.allowlist.iter().enumerate() {
            for b in &config.allowlist[i + 1..] {
                let overlap = a.prefix.contains(&b.prefix) || b.prefix.contains(&a.prefix);
                if overlap && a.tenant != b.tenant {
                    return Err(ConfigError::Overlap(a.prefix, b.prefix));
                }
            }
        }
        Ok(Guard { config })
    }

    pub fn config(&self) -> &GuardConfig {
        &self.config
    }

    /// Whether the mitigator must not announce: dry-run, or BGP off.
    pub fn effective_dry_run(&self) -> bool {
        self.config.dry_run || !self.config.bgp_enabled
    }

    pub fn approval_policy(&self) -> ApprovalPolicy {
        ApprovalPolicy {
            allow_self_approval: self.config.allow_self_approval,
        }
    }

    pub fn approval_window(&self) -> Duration {
        Duration::from_secs(self.config.approval_window_seconds)
    }

    /// May `tenant` have `action` on `prefix` for `duration`?
    /// `kill_switch` is the runtime switch; the configured one is always
    /// honoured as well.
    pub fn check(
        &self,
        tenant: &TenantId,
        prefix: &Prefix,
        action: &Action,
        duration: Duration,
        kill_switch: bool,
    ) -> Result<(), GuardRefusal> {
        if kill_switch || self.config.kill_switch {
            return Err(GuardRefusal::KillSwitch);
        }
        // The most specific entry decides. Entries of different tenants
        // never overlap, so any covering entry names the same tenant.
        let entry = self
            .config
            .allowlist
            .iter()
            .filter(|entry| entry.prefix.contains(prefix))
            .max_by_key(|entry| entry.prefix.length())
            .filter(|entry| entry.tenant == tenant.as_str())
            .ok_or(GuardRefusal::NotAllowlisted(*prefix))?;
        let kind = action.kind();
        if !entry.actions.contains(&kind) {
            return Err(GuardRefusal::ActionNotAllowed(kind, *prefix));
        }
        if !prefix.is_host() {
            let min = if prefix.is_ipv4() {
                self.config.min_length.ipv4
            } else {
                self.config.min_length.ipv6
            };
            if prefix.length() < min {
                return Err(GuardRefusal::TooWide(*prefix, min));
            }
        }
        if let Some(source) = action.flow().and_then(|flow| flow.source) {
            // A source match only narrows a rule, but a /0 source is a
            // sign the request was not thought through.
            if source.length() == 0 {
                return Err(GuardRefusal::TooWide(source, 1));
            }
        }
        if duration.as_secs() > self.config.max_duration_seconds {
            return Err(GuardRefusal::TooLong(self.config.max_duration_seconds));
        }
        Ok(())
    }
}

fn floor(prefix: &Prefix) -> u8 {
    if prefix.is_ipv4() {
        IPV4_FLOOR
    } else {
        IPV6_FLOOR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::FlowMatch;

    fn p(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    fn entry(prefix: &str, tenant: &str, actions: &[ActionKind]) -> AllowlistEntry {
        AllowlistEntry {
            prefix: p(prefix),
            tenant: tenant.into(),
            actions: actions.to_vec(),
        }
    }

    fn guard() -> Guard {
        Guard::new(GuardConfig {
            allowlist: vec![
                entry(
                    "192.0.2.0/24",
                    "acme",
                    &[
                        ActionKind::Rtbh,
                        ActionKind::FlowspecDiscard,
                        ActionKind::FlowspecRateLimit,
                    ],
                ),
                entry(
                    "198.51.100.0/24",
                    "acme",
                    &[ActionKind::Rtbh, ActionKind::ParentPrefix],
                ),
                entry("203.0.113.0/24", "globex", &[ActionKind::Rtbh]),
                entry("2001:db8:a::/48", "acme", &[ActionKind::Rtbh]),
            ],
            ..GuardConfig::default()
        })
        .unwrap()
    }

    fn acme() -> TenantId {
        TenantId::new("acme")
    }

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn a_fresh_install_is_dry_run_with_bgp_off_and_allows_nothing() {
        let fresh = Guard::new(GuardConfig::default()).unwrap();
        assert!(fresh.config().dry_run);
        assert!(!fresh.config().bgp_enabled);
        assert!(fresh.effective_dry_run());
        assert!(!fresh.approval_policy().allow_self_approval);
        assert_eq!(
            fresh.check(&acme(), &p("192.0.2.1/32"), &Action::Rtbh, HOUR, false),
            Err(GuardRefusal::NotAllowlisted(p("192.0.2.1/32")))
        );
        // An empty file is the same fresh install.
        let empty: GuardConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, GuardConfig::default());
        // BGP on alone is still dry-run; both switches are needed.
        let on: GuardConfig = serde_json::from_str(r#"{"bgp_enabled": true}"#).unwrap();
        assert!(Guard::new(on).unwrap().effective_dry_run());
        let live: GuardConfig =
            serde_json::from_str(r#"{"bgp_enabled": true, "dry_run": false}"#).unwrap();
        assert!(!Guard::new(live).unwrap().effective_dry_run());
    }

    #[test]
    fn the_allowlist_its_tenant_and_its_actions_decide() {
        let g = guard();
        assert_eq!(
            g.check(&acme(), &p("192.0.2.1/32"), &Action::Rtbh, HOUR, false),
            Ok(())
        );
        assert_eq!(
            g.check(&acme(), &p("2001:db8:a::1/128"), &Action::Rtbh, HOUR, false),
            Ok(())
        );
        // Another tenant's space looks exactly like space nobody owns.
        assert_eq!(
            g.check(&acme(), &p("203.0.113.9/32"), &Action::Rtbh, HOUR, false),
            Err(GuardRefusal::NotAllowlisted(p("203.0.113.9/32")))
        );
        assert_eq!(
            g.check(&acme(), &p("192.0.3.1/32"), &Action::Rtbh, HOUR, false),
            Err(GuardRefusal::NotAllowlisted(p("192.0.3.1/32")))
        );
        assert_eq!(
            g.check(
                &acme(),
                &p("192.0.2.0/24"),
                &Action::ParentPrefix,
                HOUR,
                false
            ),
            Err(GuardRefusal::ActionNotAllowed(
                ActionKind::ParentPrefix,
                p("192.0.2.0/24")
            ))
        );
        assert_eq!(
            g.check(
                &acme(),
                &p("198.51.100.0/24"),
                &Action::ParentPrefix,
                HOUR,
                false
            ),
            Ok(())
        );
    }

    #[test]
    fn bounds_duration_and_the_kill_switch_refuse() {
        let g = guard();
        let wide = Action::FlowspecDiscard(FlowMatch::default());
        let narrow = Guard::new(GuardConfig {
            min_length: MinLength { ipv4: 28, ipv6: 64 },
            ..g.config().clone()
        })
        .unwrap();
        assert_eq!(
            g.check(&acme(), &p("192.0.2.0/24"), &wide, HOUR, false),
            Ok(())
        );
        assert_eq!(
            narrow.check(&acme(), &p("192.0.2.0/24"), &wide, HOUR, false),
            Err(GuardRefusal::TooWide(p("192.0.2.0/24"), 28))
        );
        assert_eq!(
            g.check(
                &acme(),
                &p("192.0.2.1/32"),
                &Action::Rtbh,
                HOUR + Duration::from_secs(1),
                false
            ),
            Err(GuardRefusal::TooLong(3600))
        );
        assert_eq!(
            g.check(&acme(), &p("192.0.2.1/32"), &Action::Rtbh, HOUR, true),
            Err(GuardRefusal::KillSwitch)
        );
        let switched = Guard::new(GuardConfig {
            kill_switch: true,
            ..g.config().clone()
        })
        .unwrap();
        assert_eq!(
            switched.check(&acme(), &p("192.0.2.1/32"), &Action::Rtbh, HOUR, false),
            Err(GuardRefusal::KillSwitch)
        );
        let any_source = Action::FlowspecDiscard(FlowMatch {
            source: Some(p("0.0.0.0/0")),
            ..FlowMatch::default()
        });
        assert!(g
            .check(&acme(), &p("192.0.2.1/32"), &any_source, HOUR, false)
            .is_err());
    }

    #[test]
    fn a_dangerous_configuration_is_refused() {
        let with = |allowlist: Vec<AllowlistEntry>| {
            Guard::new(GuardConfig {
                allowlist,
                ..GuardConfig::default()
            })
        };
        assert_eq!(
            with(vec![entry("10.0.0.0/8", "acme", &[ActionKind::Rtbh])]),
            Err(ConfigError::EntryTooWide(p("10.0.0.0/8")))
        );
        assert_eq!(
            with(vec![entry("::/0", "acme", &[ActionKind::Rtbh])]),
            Err(ConfigError::EntryTooWide(p("::/0")))
        );
        assert_eq!(
            with(vec![entry("192.0.2.0/24", "acme", &[])]),
            Err(ConfigError::EntryEmpty(p("192.0.2.0/24")))
        );
        assert_eq!(
            with(vec![
                entry("192.0.2.0/24", "acme", &[ActionKind::Rtbh]),
                entry("192.0.2.128/25", "globex", &[ActionKind::Rtbh]),
            ]),
            Err(ConfigError::Overlap(p("192.0.2.0/24"), p("192.0.2.128/25")))
        );
        for (ipv4, ipv6) in [(15, 48), (24, 31), (33, 48), (24, 129)] {
            assert!(Guard::new(GuardConfig {
                min_length: MinLength { ipv4, ipv6 },
                ..GuardConfig::default()
            })
            .is_err());
        }
        for seconds in [59, MAX_DURATION.as_secs() + 1] {
            assert_eq!(
                Guard::new(GuardConfig {
                    max_duration_seconds: seconds,
                    ..GuardConfig::default()
                }),
                Err(ConfigError::MaxDuration)
            );
        }
        let unknown = serde_json::from_str::<GuardConfig>(r#"{"dryrun": false}"#);
        assert!(
            unknown.is_err(),
            "a misspelt switch is an error, not a default"
        );
        let redirect = serde_json::from_str::<GuardConfig>(
            r#"{"allowlist": [{"prefix": "192.0.2.0/24", "tenant": "acme", "actions": ["flowspec_redirect"]}]}"#,
        );
        assert!(redirect.is_err(), "redirect is not an action (BQ-15)");
    }
}
