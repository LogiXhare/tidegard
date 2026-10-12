//! Turning a mitigation into a GoBGP path, and a path back into a
//! mitigation's key (ADR 0048).
//!
//! The route attributes are the deployment's ([`RouteConfig`]), never the
//! requester's. Every path carries the ownership large community
//! `<local ASN>:5721677:1` ("WNM" as a number), so the mitigator can list
//! exactly its own routes and never touch another's.
//!
//! - **RTBH and parent prefix:** a unicast path to the configured next hop,
//!   with the configured communities (by default `BLACKHOLE`, RFC 7999),
//!   `NO_EXPORT` unless turned off, and the ownership community.
//! - **FlowSpec** (RFC 8955): the destination prefix, then the optional
//!   source prefix, protocol, destination port and source port, in type
//!   order, with a `traffic-rate` of 0 to discard or the configured bytes
//!   per second to limit.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Deserializer};
use wetechinetmon_mitigation::{Action, ActionKind, FlowMatch, Prefix};

use crate::api;
use crate::api::attribute::Attr;
use crate::api::extended_community::Extcom;
use crate::api::flow_spec_rule::Rule;
use crate::api::nlri::Nlri as NlriKind;

/// `BLACKHOLE` (RFC 7999).
pub const BLACKHOLE: u32 = 0xFFFF_029A;
/// `NO_EXPORT` (RFC 1997).
pub const NO_EXPORT: u32 = 0xFFFF_FF01;
/// `NO_ADVERTISE` (RFC 1997).
pub const NO_ADVERTISE: u32 = 0xFFFF_FF02;
/// "WNM" read as a number: the ownership community's first local part.
pub const OWNERSHIP_MARKER: u32 = 0x0057_4E4D;
const OWNERSHIP_VERSION: u32 = 1;

const FLOWSPEC_DESTINATION: u32 = 1;
const FLOWSPEC_SOURCE: u32 = 2;
const FLOWSPEC_PROTOCOL: u32 = 3;
const FLOWSPEC_DESTINATION_PORT: u32 = 5;
const FLOWSPEC_SOURCE_PORT: u32 = 6;
/// The numeric operator `==`. GoBGP adds the length and end-of-list bits.
const OP_EQUAL: u32 = 0x01;
/// The low three bits of a numeric operator: `<`, `>` and `=`.
const OP_COMPARISON: u32 = 0x07;
const ORIGIN_IGP: u32 = 0;

/// The deployment's route attributes, from the mitigator's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// The ASN of WetechiNetMon's own BGP speaker.
    pub local_asn: u32,
    /// Where blackholed IPv4 traffic goes, usually a discard route on the
    /// edge routers.
    pub rtbh_next_hop_ipv4: Ipv4Addr,
    pub rtbh_next_hop_ipv6: Ipv6Addr,
    /// Standard communities on RTBH and parent-prefix routes, as `asn:value`.
    #[serde(
        default = "default_communities",
        deserialize_with = "standard_communities"
    )]
    pub communities: Vec<u32>,
    /// Large communities on every route, as `global:local1:local2`.
    #[serde(default, deserialize_with = "large_communities")]
    pub large_communities: Vec<(u32, u32, u32)>,
    #[serde(default = "yes")]
    pub no_export: bool,
    #[serde(default)]
    pub no_advertise: bool,
}

fn yes() -> bool {
    true
}

fn default_communities() -> Vec<u32> {
    vec![BLACKHOLE]
}

/// Parses `65535:666` into its 32-bit value.
pub fn parse_community(text: &str) -> Result<u32, String> {
    let (high, low) = text
        .split_once(':')
        .ok_or_else(|| format!("community {text:?} is not asn:value"))?;
    let part = |p: &str| {
        p.parse::<u16>()
            .map_err(|_| format!("community {text:?} has a part above 65535"))
    };
    Ok((u32::from(part(high)?) << 16) | u32::from(part(low)?))
}

/// Parses `65001:1:2` into its three parts.
pub fn parse_large_community(text: &str) -> Result<(u32, u32, u32), String> {
    let parts: Vec<&str> = text.split(':').collect();
    let [a, b, c] = parts.as_slice() else {
        return Err(format!(
            "large community {text:?} is not global:local1:local2"
        ));
    };
    let part = |p: &str| {
        p.parse::<u32>()
            .map_err(|_| format!("large community {text:?} has a part that is not a 32-bit number"))
    };
    Ok((part(a)?, part(b)?, part(c)?))
}

fn standard_communities<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u32>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|text| parse_community(text).map_err(serde::de::Error::custom))
        .collect()
}

fn large_communities<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(u32, u32, u32)>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|text| parse_large_community(text).map_err(serde::de::Error::custom))
        .collect()
}

impl RouteConfig {
    /// The large community that marks a route as WetechiNetMon's.
    pub fn ownership(&self) -> api::LargeCommunity {
        api::LargeCommunity {
            global_admin: self.local_asn,
            local_data1: OWNERSHIP_MARKER,
            local_data2: OWNERSHIP_VERSION,
        }
    }

    fn large(&self) -> Vec<api::LargeCommunity> {
        let mut all = vec![self.ownership()];
        all.extend(
            self.large_communities
                .iter()
                .map(|(a, b, c)| api::LargeCommunity {
                    global_admin: *a,
                    local_data1: *b,
                    local_data2: *c,
                }),
        );
        all
    }

    fn scope_communities(&self) -> Vec<u32> {
        let mut scope = Vec::new();
        if self.no_export {
            scope.push(NO_EXPORT);
        }
        if self.no_advertise {
            scope.push(NO_ADVERTISE);
        }
        scope
    }
}

pub fn family(prefix: &Prefix, kind: ActionKind) -> api::Family {
    let afi = if prefix.is_ipv4() {
        api::family::Afi::Ip
    } else {
        api::family::Afi::Ip6
    };
    let safi = if kind.is_flowspec() {
        api::family::Safi::FlowSpecUnicast
    } else {
        api::family::Safi::Unicast
    };
    api::Family {
        afi: afi as i32,
        safi: safi as i32,
    }
}

/// The NLRI a mitigation announces.
pub fn nlri(prefix: &Prefix, action: &Action) -> api::Nlri {
    let kind = match action.flow() {
        None => NlriKind::Prefix(api::IpAddressPrefix {
            prefix_len: u32::from(prefix.length()),
            prefix: prefix.address().to_string(),
        }),
        Some(flow) => NlriKind::FlowSpec(api::FlowSpecNlri {
            rules: flowspec_rules(prefix, flow),
        }),
    };
    api::Nlri { nlri: Some(kind) }
}

fn flowspec_rules(prefix: &Prefix, flow: &FlowMatch) -> Vec<api::FlowSpecRule> {
    let ip = |kind: u32, p: &Prefix| api::FlowSpecRule {
        rule: Some(Rule::IpPrefix(api::FlowSpecIpPrefix {
            r#type: kind,
            prefix_len: u32::from(p.length()),
            prefix: p.address().to_string(),
            offset: 0,
        })),
    };
    let equal = |kind: u32, value: u64| api::FlowSpecRule {
        rule: Some(Rule::Component(api::FlowSpecComponent {
            r#type: kind,
            items: vec![api::FlowSpecComponentItem {
                op: OP_EQUAL,
                value,
            }],
        })),
    };
    let mut rules = vec![ip(FLOWSPEC_DESTINATION, prefix)];
    if let Some(source) = &flow.source {
        rules.push(ip(FLOWSPEC_SOURCE, source));
    }
    if let Some(protocol) = flow.protocol {
        rules.push(equal(FLOWSPEC_PROTOCOL, u64::from(protocol)));
    }
    if let Some(port) = flow.destination_port {
        rules.push(equal(FLOWSPEC_DESTINATION_PORT, u64::from(port)));
    }
    if let Some(port) = flow.source_port {
        rules.push(equal(FLOWSPEC_SOURCE_PORT, u64::from(port)));
    }
    rules
}

fn attribute(attr: Attr) -> api::Attribute {
    api::Attribute { attr: Some(attr) }
}

/// The path that announces `action` on `prefix`.
pub fn announcement(prefix: &Prefix, action: &Action, config: &RouteConfig) -> api::Path {
    let family = family(prefix, action.kind());
    let nlri = nlri(prefix, action);
    let mut pattrs = vec![attribute(Attr::Origin(api::OriginAttribute {
        origin: ORIGIN_IGP,
    }))];
    let mut communities = config.scope_communities();
    match action.flow() {
        None => {
            communities.splice(0..0, config.communities.iter().copied());
            match prefix.address() {
                IpAddr::V4(_) => pattrs.push(attribute(Attr::NextHop(api::NextHopAttribute {
                    next_hop: config.rtbh_next_hop_ipv4.to_string(),
                }))),
                IpAddr::V6(_) => pattrs.push(attribute(Attr::MpReach(api::MpReachNlriAttribute {
                    family: Some(family),
                    next_hops: vec![config.rtbh_next_hop_ipv6.to_string()],
                    nlris: vec![nlri.clone()],
                }))),
            }
        }
        Some(_) => {
            // FlowSpec carries no forwarding next hop; GoBGP still wants one
            // in MP_REACH, and the unspecified address is the convention.
            let unspecified = if prefix.is_ipv4() { "0.0.0.0" } else { "::" };
            pattrs.push(attribute(Attr::MpReach(api::MpReachNlriAttribute {
                family: Some(family),
                next_hops: vec![unspecified.to_string()],
                nlris: vec![nlri.clone()],
            })));
            let rate = action.bytes_per_second().unwrap_or(0);
            pattrs.push(attribute(Attr::ExtendedCommunities(
                api::ExtendedCommunitiesAttribute {
                    communities: vec![api::ExtendedCommunity {
                        extcom: Some(Extcom::TrafficRate(api::TrafficRateExtended {
                            asn: 0,
                            // RFC 8955 carries the rate as a 32-bit float.
                            rate: rate as f32,
                        })),
                    }],
                },
            )));
        }
    }
    if !communities.is_empty() {
        pattrs.push(attribute(Attr::Communities(api::CommunitiesAttribute {
            communities,
        })));
    }
    pattrs.push(attribute(Attr::LargeCommunities(
        api::LargeCommunitiesAttribute {
            communities: config.large(),
        },
    )));
    api::Path {
        nlri: Some(nlri),
        pattrs,
        family: Some(family),
        ..api::Path::default()
    }
}

/// The path that withdraws `action` on `prefix`.
pub fn withdrawal(prefix: &Prefix, action: &Action) -> api::Path {
    api::Path {
        nlri: Some(nlri(prefix, action)),
        family: Some(family(prefix, action.kind())),
        is_withdraw: true,
        ..api::Path::default()
    }
}

/// What a mitigation announces, as JSON for its record: the evidence of
/// exactly what was, or in dry-run would have been, sent.
pub fn summary(
    prefix: &Prefix,
    action: &Action,
    config: &RouteConfig,
    dry_run: bool,
) -> serde_json::Value {
    let path = announcement(prefix, action, config);
    let mut next_hop = None;
    let mut communities = Vec::new();
    let mut large = Vec::new();
    for attribute in &path.pattrs {
        match &attribute.attr {
            Some(Attr::NextHop(n)) => next_hop = Some(n.next_hop.clone()),
            Some(Attr::MpReach(m)) if action.flow().is_none() => {
                next_hop = m.next_hops.first().cloned();
            }
            Some(Attr::Communities(c)) => {
                communities = c
                    .communities
                    .iter()
                    .map(|v| format!("{}:{}", v >> 16, v & 0xFFFF))
                    .collect();
            }
            Some(Attr::LargeCommunities(l)) => {
                large = l
                    .communities
                    .iter()
                    .map(|c| format!("{}:{}:{}", c.global_admin, c.local_data1, c.local_data2))
                    .collect();
            }
            _ => {}
        }
    }
    let family = match (prefix.is_ipv4(), action.kind().is_flowspec()) {
        (true, false) => "ipv4-unicast",
        (false, false) => "ipv6-unicast",
        (true, true) => "ipv4-flowspec",
        (false, true) => "ipv6-flowspec",
    };
    serde_json::json!({
        "family": family,
        "prefix": prefix.to_string(),
        "action": action.kind().as_str(),
        "flow": action.flow(),
        "bytes_per_second": action.bytes_per_second(),
        "next_hop": next_hop,
        "communities": communities,
        "large_communities": large,
        "dry_run": dry_run,
    })
}

/// Whether a path read from GoBGP is WetechiNetMon's.
pub fn is_owned(path: &api::Path, config: &RouteConfig) -> bool {
    let ownership = config.ownership();
    path.pattrs.iter().any(|attribute| {
        matches!(&attribute.attr, Some(Attr::LargeCommunities(large))
            if large.communities.contains(&ownership))
    })
}

/// A route WetechiNetMon announced, read back from GoBGP.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnedRoute {
    pub prefix: Prefix,
    pub action: Action,
    /// The same key a live mitigation has: one route per key.
    pub key: String,
    pub path: api::Path,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a path carrying the ownership community cannot be read back: {0}")]
pub struct UnreadablePath(String);

/// Reads an owned path back into the mitigation it implements.
pub fn read_back(path: &api::Path) -> Result<OwnedRoute, UnreadablePath> {
    let bad = |what: &str| UnreadablePath(what.to_string());
    let nlri = path
        .nlri
        .as_ref()
        .and_then(|n| n.nlri.as_ref())
        .ok_or_else(|| bad("no NLRI"))?;
    let (prefix, action) = match nlri {
        NlriKind::Prefix(p) => {
            let prefix = prefix_of(&p.prefix, p.prefix_len).ok_or_else(|| bad("the prefix"))?;
            let action = if prefix.is_host() {
                Action::Rtbh
            } else {
                Action::ParentPrefix
            };
            (prefix, action)
        }
        NlriKind::FlowSpec(fs) => {
            let mut destination = None;
            let mut flow = FlowMatch::default();
            for rule in &fs.rules {
                match &rule.rule {
                    Some(Rule::IpPrefix(ip)) => {
                        let p = prefix_of(&ip.prefix, ip.prefix_len)
                            .ok_or_else(|| bad("a FlowSpec prefix"))?;
                        match ip.r#type {
                            FLOWSPEC_DESTINATION => destination = Some(p),
                            FLOWSPEC_SOURCE => flow.source = Some(p),
                            _ => return Err(bad("an unexpected FlowSpec prefix type")),
                        }
                    }
                    Some(Rule::Component(c)) => {
                        let [item] = c.items.as_slice() else {
                            return Err(bad("a FlowSpec component with several values"));
                        };
                        if item.op & OP_COMPARISON != OP_EQUAL {
                            return Err(bad("a FlowSpec comparison other than equals"));
                        }
                        let small = |max: u64| {
                            (item.value <= max)
                                .then_some(item.value)
                                .ok_or_else(|| bad("a value out of range"))
                        };
                        match c.r#type {
                            FLOWSPEC_PROTOCOL => flow.protocol = Some(small(255)? as u8),
                            FLOWSPEC_DESTINATION_PORT => {
                                flow.destination_port = Some(small(65535)? as u16)
                            }
                            FLOWSPEC_SOURCE_PORT => flow.source_port = Some(small(65535)? as u16),
                            _ => return Err(bad("an unexpected FlowSpec component")),
                        }
                    }
                    _ => return Err(bad("an unexpected FlowSpec rule")),
                }
            }
            let prefix = destination.ok_or_else(|| bad("no FlowSpec destination"))?;
            let rate = path
                .pattrs
                .iter()
                .find_map(|attribute| match &attribute.attr {
                    Some(Attr::ExtendedCommunities(ext)) => {
                        ext.communities.iter().find_map(|c| match &c.extcom {
                            Some(Extcom::TrafficRate(rate)) => Some(rate.rate),
                            _ => None,
                        })
                    }
                    _ => None,
                })
                .ok_or_else(|| bad("no traffic-rate"))?;
            let action = if rate <= 0.0 {
                Action::FlowspecDiscard(flow)
            } else {
                Action::FlowspecRateLimit {
                    flow,
                    bytes_per_second: rate.round() as u64,
                }
            };
            (prefix, action)
        }
        _ => return Err(bad("an NLRI type WetechiNetMon never announces")),
    };
    Ok(OwnedRoute {
        key: action.duplicate_key(&prefix),
        prefix,
        action,
        path: path.clone(),
    })
}

fn prefix_of(address: &str, length: u32) -> Option<Prefix> {
    let address: IpAddr = address.parse().ok()?;
    Prefix::new(address, u8::try_from(length).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RouteConfig {
        serde_json::from_str(
            r#"{"local_asn": 65001, "rtbh_next_hop_ipv4": "192.0.2.254",
                "rtbh_next_hop_ipv6": "2001:db8::254",
                "communities": ["65535:666", "65001:777"],
                "large_communities": ["65001:1:2"]}"#,
        )
        .unwrap()
    }

    fn p(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    fn communities(path: &api::Path) -> Vec<u32> {
        path.pattrs
            .iter()
            .find_map(|a| match &a.attr {
                Some(Attr::Communities(c)) => Some(c.communities.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    #[test]
    fn the_configuration_has_safe_defaults_and_strict_parsing() {
        let minimal: RouteConfig = serde_json::from_str(
            r#"{"local_asn": 65001, "rtbh_next_hop_ipv4": "192.0.2.254", "rtbh_next_hop_ipv6": "2001:db8::254"}"#,
        )
        .unwrap();
        assert_eq!(minimal.communities, [BLACKHOLE]);
        assert!(minimal.no_export);
        assert!(!minimal.no_advertise);
        assert_eq!(parse_community("65535:666"), Ok(BLACKHOLE));
        assert!(parse_community("65536:1").is_err());
        assert!(parse_community("1").is_err());
        assert_eq!(parse_large_community("65001:1:2"), Ok((65001, 1, 2)));
        assert!(parse_large_community("1:2").is_err());
        assert!(
            serde_json::from_str::<RouteConfig>(r#"{"local_asn": 1, "next_hop": "x"}"#).is_err()
        );
    }

    #[test]
    fn rtbh_carries_the_next_hop_communities_and_ownership() {
        let c = config();
        let v4 = announcement(&p("192.0.2.10/32"), &Action::Rtbh, &c);
        assert_eq!(
            v4.family,
            Some(family(&p("192.0.2.10/32"), ActionKind::Rtbh))
        );
        assert!(v4.pattrs.iter().any(|a| matches!(&a.attr,
            Some(Attr::NextHop(n)) if n.next_hop == "192.0.2.254")));
        assert_eq!(
            communities(&v4),
            [BLACKHOLE, parse_community("65001:777").unwrap(), NO_EXPORT]
        );
        assert!(is_owned(&v4, &c));

        let v6 = announcement(&p("2001:db8::10/128"), &Action::Rtbh, &c);
        assert!(v6.pattrs.iter().any(|a| matches!(&a.attr,
            Some(Attr::MpReach(m)) if m.next_hops == ["2001:db8::254"] && m.nlris.len() == 1)));
        assert!(!v6
            .pattrs
            .iter()
            .any(|a| matches!(&a.attr, Some(Attr::NextHop(_)))));
    }

    #[test]
    fn flowspec_rules_are_in_type_order_with_a_traffic_rate() {
        let c = config();
        let flow = FlowMatch {
            protocol: Some(17),
            source: Some(p("198.51.100.0/24")),
            source_port: Some(53),
            destination_port: Some(443),
        };
        let path = announcement(
            &p("192.0.2.10/32"),
            &Action::FlowspecRateLimit {
                flow: flow.clone(),
                bytes_per_second: 125_000,
            },
            &c,
        );
        let Some(NlriKind::FlowSpec(fs)) = path.nlri.as_ref().and_then(|n| n.nlri.as_ref()) else {
            panic!("not FlowSpec");
        };
        let types: Vec<u32> = fs
            .rules
            .iter()
            .map(|r| match &r.rule {
                Some(Rule::IpPrefix(ip)) => ip.r#type,
                Some(Rule::Component(c)) => c.r#type,
                _ => 0,
            })
            .collect();
        assert_eq!(types, [1, 2, 3, 5, 6]);
        // No blackhole community on a FlowSpec rule.
        assert_eq!(communities(&path), [NO_EXPORT]);
        assert!(is_owned(&path, &c));
    }

    #[test]
    fn every_action_reads_back_to_its_own_key() {
        let c = config();
        let flow = FlowMatch {
            protocol: Some(6),
            destination_port: Some(80),
            ..FlowMatch::default()
        };
        for (prefix, action) in [
            (p("192.0.2.10/32"), Action::Rtbh),
            (p("2001:db8::10/128"), Action::Rtbh),
            (p("192.0.2.0/24"), Action::ParentPrefix),
            (p("192.0.2.10/32"), Action::FlowspecDiscard(flow.clone())),
            (
                p("2001:db8::/64"),
                Action::FlowspecDiscard(FlowMatch::default()),
            ),
            (
                p("192.0.2.10/32"),
                Action::FlowspecRateLimit {
                    flow,
                    bytes_per_second: 125_000,
                },
            ),
        ] {
            let route = read_back(&announcement(&prefix, &action, &c)).unwrap();
            assert_eq!(route.prefix, prefix);
            assert_eq!(route.action, action);
            assert_eq!(route.key, action.duplicate_key(&prefix));
        }
    }

    #[test]
    fn another_speakers_route_is_not_ours() {
        let c = config();
        let mut path = announcement(&p("192.0.2.10/32"), &Action::Rtbh, &c);
        path.pattrs
            .retain(|a| !matches!(a.attr, Some(Attr::LargeCommunities(_))));
        assert!(!is_owned(&path, &c));
        let other_asn = RouteConfig {
            local_asn: 65002,
            ..config()
        };
        assert!(!is_owned(
            &announcement(&p("192.0.2.10/32"), &Action::Rtbh, &other_asn),
            &c
        ));
    }

    #[test]
    fn the_summary_records_what_is_sent() {
        let s = summary(&p("192.0.2.10/32"), &Action::Rtbh, &config(), true);
        assert_eq!(s["family"], "ipv4-unicast");
        assert_eq!(s["next_hop"], "192.0.2.254");
        assert_eq!(
            s["communities"],
            serde_json::json!(["65535:666", "65001:777", "65535:65281"])
        );
        assert_eq!(s["large_communities"][0], "65001:5721677:1");
        assert_eq!(s["dry_run"], true);
        let fs = summary(
            &p("2001:db8::/64"),
            &Action::FlowspecDiscard(FlowMatch::default()),
            &config(),
            false,
        );
        assert_eq!(fs["family"], "ipv6-flowspec");
        assert_eq!(fs["next_hop"], serde_json::Value::Null);
    }

    #[test]
    fn a_withdrawal_names_the_same_nlri() {
        let action = Action::FlowspecDiscard(FlowMatch::default());
        let path = withdrawal(&p("192.0.2.10/32"), &action);
        assert!(path.is_withdraw);
        assert_eq!(
            path.nlri,
            announcement(&p("192.0.2.10/32"), &action, &config()).nlri
        );
    }
}
