//! What a mitigation does (BQ-15).
//!
//! The requester chooses the action and, for FlowSpec, what to match. The
//! route attributes — next hop, communities — are deployment configuration
//! the mitigator applies (7C), never something a request can set.

use serde::{Deserialize, Serialize};

use crate::prefix::Prefix;

/// The fastest FlowSpec rate-limit a request may ask for: 100 Gbit/s, in
/// bytes per second. Above it a "limit" is no longer a mitigation.
pub const MAX_RATE_BYTES_PER_SECOND: u64 = 12_500_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Blackhole one host: a `/32` or `/128` with the blackhole community.
    Rtbh,
    /// Blackhole a covering prefix, when the allowlist entry permits it.
    ParentPrefix,
    /// A FlowSpec rule that drops matching traffic.
    FlowspecDiscard,
    /// A FlowSpec rule that limits matching traffic to a rate.
    FlowspecRateLimit,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Rtbh => "rtbh",
            ActionKind::ParentPrefix => "parent_prefix",
            ActionKind::FlowspecDiscard => "flowspec_discard",
            ActionKind::FlowspecRateLimit => "flowspec_rate_limit",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            ActionKind::Rtbh,
            ActionKind::ParentPrefix,
            ActionKind::FlowspecDiscard,
            ActionKind::FlowspecRateLimit,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == text)
    }

    pub fn is_flowspec(self) -> bool {
        matches!(
            self,
            ActionKind::FlowspecDiscard | ActionKind::FlowspecRateLimit
        )
    }
}

/// What a FlowSpec rule matches beyond its destination, the mitigation's
/// prefix. Every field narrows the rule; none widens it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Prefix>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
}

impl FlowMatch {
    /// A stable text form, for the duplicate key.
    pub fn canonical(&self) -> String {
        let part = |name: &str, value: Option<String>| {
            value.map_or(String::new(), |value| format!("{name}={value};"))
        };
        [
            part("proto", self.protocol.map(|v| v.to_string())),
            part("src", self.source.map(|v| v.to_string())),
            part("sport", self.source_port.map(|v| v.to_string())),
            part("dport", self.destination_port.map(|v| v.to_string())),
        ]
        .concat()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    Rtbh,
    ParentPrefix,
    FlowspecDiscard(FlowMatch),
    FlowspecRateLimit {
        flow: FlowMatch,
        bytes_per_second: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    #[error("RTBH blackholes one host: the prefix must be a /32 or /128")]
    RtbhNotHost,
    #[error("a parent-prefix announcement covers more than one host: use RTBH for a /32 or /128")]
    ParentIsHost,
    #[error("ports are matched only for TCP (6) or UDP (17)")]
    PortsWithoutTransport,
    #[error("the source prefix is not the same address family as the destination")]
    SourceFamily,
    #[error("a rate-limit needs a rate above zero and at most {MAX_RATE_BYTES_PER_SECOND} bytes per second; zero is a discard")]
    Rate,
    #[error("only FlowSpec actions take a match or a rate")]
    NotFlowspec,
}

impl Action {
    /// Builds an action from its parts, as an API or a stored row gives
    /// them.
    pub fn from_parts(
        kind: ActionKind,
        flow: Option<FlowMatch>,
        bytes_per_second: Option<u64>,
    ) -> Result<Self, ActionError> {
        match kind {
            ActionKind::Rtbh | ActionKind::ParentPrefix
                if flow.is_some() || bytes_per_second.is_some() =>
            {
                Err(ActionError::NotFlowspec)
            }
            ActionKind::Rtbh => Ok(Action::Rtbh),
            ActionKind::ParentPrefix => Ok(Action::ParentPrefix),
            ActionKind::FlowspecDiscard if bytes_per_second.is_some() => Err(ActionError::Rate),
            ActionKind::FlowspecDiscard => Ok(Action::FlowspecDiscard(flow.unwrap_or_default())),
            ActionKind::FlowspecRateLimit => Ok(Action::FlowspecRateLimit {
                flow: flow.unwrap_or_default(),
                bytes_per_second: bytes_per_second.ok_or(ActionError::Rate)?,
            }),
        }
    }

    pub fn kind(&self) -> ActionKind {
        match self {
            Action::Rtbh => ActionKind::Rtbh,
            Action::ParentPrefix => ActionKind::ParentPrefix,
            Action::FlowspecDiscard(_) => ActionKind::FlowspecDiscard,
            Action::FlowspecRateLimit { .. } => ActionKind::FlowspecRateLimit,
        }
    }

    pub fn flow(&self) -> Option<&FlowMatch> {
        match self {
            Action::FlowspecDiscard(flow) | Action::FlowspecRateLimit { flow, .. } => Some(flow),
            Action::Rtbh | Action::ParentPrefix => None,
        }
    }

    pub fn bytes_per_second(&self) -> Option<u64> {
        match self {
            Action::FlowspecRateLimit {
                bytes_per_second, ..
            } => Some(*bytes_per_second),
            _ => None,
        }
    }

    /// The structural checks that need no configuration. The allowlist and
    /// the length bounds are the guard's (7B).
    pub fn validate_for(&self, prefix: &Prefix) -> Result<(), ActionError> {
        match self {
            Action::Rtbh if !prefix.is_host() => Err(ActionError::RtbhNotHost),
            Action::ParentPrefix if prefix.is_host() => Err(ActionError::ParentIsHost),
            Action::Rtbh | Action::ParentPrefix => Ok(()),
            Action::FlowspecDiscard(flow) => validate_flow(flow, prefix),
            Action::FlowspecRateLimit {
                flow,
                bytes_per_second,
            } => {
                if *bytes_per_second == 0 || *bytes_per_second > MAX_RATE_BYTES_PER_SECOND {
                    return Err(ActionError::Rate);
                }
                validate_flow(flow, prefix)
            }
        }
    }

    /// Two live mitigations with the same key would announce the same
    /// thing twice.
    pub fn duplicate_key(&self, prefix: &Prefix) -> String {
        let flow = self.flow().map(FlowMatch::canonical).unwrap_or_default();
        format!("{}|{prefix}|{flow}", self.kind().as_str())
    }
}

fn validate_flow(flow: &FlowMatch, prefix: &Prefix) -> Result<(), ActionError> {
    let ports = flow.source_port.is_some() || flow.destination_port.is_some();
    if ports && !matches!(flow.protocol, Some(6) | Some(17)) {
        return Err(ActionError::PortsWithoutTransport);
    }
    if let Some(source) = flow.source {
        if source.is_ipv4() != prefix.is_ipv4() {
            return Err(ActionError::SourceFamily);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    #[test]
    fn rtbh_is_a_host_route_and_a_parent_is_not() {
        assert_eq!(Action::Rtbh.validate_for(&p("192.0.2.1/32")), Ok(()));
        assert_eq!(Action::Rtbh.validate_for(&p("2001:db8::1/128")), Ok(()));
        assert_eq!(
            Action::Rtbh.validate_for(&p("192.0.2.0/24")),
            Err(ActionError::RtbhNotHost)
        );
        assert_eq!(
            Action::ParentPrefix.validate_for(&p("192.0.2.1/32")),
            Err(ActionError::ParentIsHost)
        );
        assert_eq!(
            Action::ParentPrefix.validate_for(&p("192.0.2.0/24")),
            Ok(())
        );
    }

    #[test]
    fn flowspec_matches_and_rates_are_checked() {
        let host = p("192.0.2.1/32");
        let udp_dns = FlowMatch {
            protocol: Some(17),
            source_port: Some(53),
            ..FlowMatch::default()
        };
        assert_eq!(
            Action::FlowspecDiscard(udp_dns.clone()).validate_for(&host),
            Ok(())
        );
        let icmp_port = FlowMatch {
            protocol: Some(1),
            destination_port: Some(80),
            ..FlowMatch::default()
        };
        assert_eq!(
            Action::FlowspecDiscard(icmp_port).validate_for(&host),
            Err(ActionError::PortsWithoutTransport)
        );
        let v6_source = FlowMatch {
            source: Some(p("2001:db8::/32")),
            ..FlowMatch::default()
        };
        assert_eq!(
            Action::FlowspecDiscard(v6_source).validate_for(&host),
            Err(ActionError::SourceFamily)
        );
        for rate in [0, MAX_RATE_BYTES_PER_SECOND + 1] {
            let action = Action::FlowspecRateLimit {
                flow: udp_dns.clone(),
                bytes_per_second: rate,
            };
            assert_eq!(action.validate_for(&host), Err(ActionError::Rate));
        }
    }

    #[test]
    fn parts_build_only_coherent_actions() {
        assert_eq!(
            Action::from_parts(ActionKind::Rtbh, Some(FlowMatch::default()), None),
            Err(ActionError::NotFlowspec)
        );
        assert_eq!(
            Action::from_parts(ActionKind::FlowspecDiscard, None, Some(1)),
            Err(ActionError::Rate)
        );
        assert_eq!(
            Action::from_parts(ActionKind::FlowspecRateLimit, None, None),
            Err(ActionError::Rate)
        );
        assert_eq!(
            Action::from_parts(ActionKind::FlowspecDiscard, None, None),
            Ok(Action::FlowspecDiscard(FlowMatch::default()))
        );
        for kind in [
            ActionKind::Rtbh,
            ActionKind::ParentPrefix,
            ActionKind::FlowspecDiscard,
            ActionKind::FlowspecRateLimit,
        ] {
            assert_eq!(ActionKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(ActionKind::parse("flowspec_redirect"), None);
    }

    #[test]
    fn the_duplicate_key_tells_actions_and_matches_apart() {
        let host = p("192.0.2.1/32");
        let dns = FlowMatch {
            protocol: Some(17),
            source_port: Some(53),
            ..FlowMatch::default()
        };
        let ntp = FlowMatch {
            protocol: Some(17),
            source_port: Some(123),
            ..FlowMatch::default()
        };
        assert_eq!(Action::Rtbh.duplicate_key(&host), "rtbh|192.0.2.1/32|");
        assert_ne!(
            Action::FlowspecDiscard(dns.clone()).duplicate_key(&host),
            Action::FlowspecDiscard(ntp).duplicate_key(&host)
        );
        assert_ne!(
            Action::FlowspecDiscard(dns.clone()).duplicate_key(&host),
            Action::FlowspecRateLimit {
                flow: dns,
                bytes_per_second: 1_000
            }
            .duplicate_key(&host)
        );
    }
}
