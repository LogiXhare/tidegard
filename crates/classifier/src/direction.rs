//! Traffic direction classification (FR-3.1, FR-3.3).

use tidegard_common::NormalizedFlow;

use crate::registry::PrefixRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Source is outside configured local prefixes, destination is local.
    Incoming,
    /// Source is local, destination is outside configured local prefixes.
    Outgoing,
    /// Both source and destination are local.
    Internal,
    /// Neither source nor destination is local.
    Other,
    /// Direction could not be determined — see [`ClassificationResult::reason`].
    Unknown,
}

/// The outcome of classifying one flow, including *why* — FR-3.3's
/// "diagnostic endpoint that explains a given classification decision"
/// is built directly on this type (see
/// `tidegard-collector`'s diagnostics wiring).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationResult {
    pub direction: Direction,
    pub source_local: Option<bool>,
    pub destination_local: Option<bool>,
    pub source_matched_tenant: Option<String>,
    pub destination_matched_tenant: Option<String>,
    pub source_matched_hostgroup: Option<String>,
    pub destination_matched_hostgroup: Option<String>,
    pub reason: String,
}

/// Classifies one flow's direction against `registry`.
///
/// If `registry` has no prefixes configured at all, "local" is
/// undefined, so the result is [`Direction::Unknown`] rather than a
/// guess — this is the "unknown or incomplete classification when
/// required [configuration] is missing" case (Phase 3 objective 4).
pub fn classify(registry: &PrefixRegistry, flow: &NormalizedFlow) -> ClassificationResult {
    if registry.is_empty() {
        return ClassificationResult {
            direction: Direction::Unknown,
            source_local: None,
            destination_local: None,
            source_matched_tenant: None,
            destination_matched_tenant: None,
            source_matched_hostgroup: None,
            destination_matched_hostgroup: None,
            reason: "no local prefixes are configured; direction cannot be determined".to_string(),
        };
    }

    let source_match = registry.lookup(flow.source_addr);
    let destination_match = registry.lookup(flow.destination_addr);
    let source_local = source_match.is_some();
    let destination_local = destination_match.is_some();

    let (direction, reason) = match (source_local, destination_local) {
        (false, true) => (
            Direction::Incoming,
            format!(
                "source {} matched no local prefix; destination {} matched a local prefix (/{}) — classified Incoming",
                flow.source_addr,
                flow.destination_addr,
                destination_match.unwrap().matched_prefix_len
            ),
        ),
        (true, false) => (
            Direction::Outgoing,
            format!(
                "source {} matched a local prefix (/{}); destination {} matched no local prefix — classified Outgoing",
                flow.source_addr,
                source_match.unwrap().matched_prefix_len,
                flow.destination_addr
            ),
        ),
        (true, true) => (
            Direction::Internal,
            format!(
                "source {} (/{}) and destination {} (/{}) both matched local prefixes — classified Internal",
                flow.source_addr,
                source_match.unwrap().matched_prefix_len,
                flow.destination_addr,
                destination_match.unwrap().matched_prefix_len
            ),
        ),
        (false, false) => (
            Direction::Other,
            format!(
                "neither source {} nor destination {} matched a local prefix — classified Other",
                flow.source_addr, flow.destination_addr
            ),
        ),
    };

    ClassificationResult {
        direction,
        source_local: Some(source_local),
        destination_local: Some(destination_local),
        source_matched_tenant: source_match.map(|m| m.entry.tenant.clone()),
        destination_matched_tenant: destination_match.map(|m| m.entry.tenant.clone()),
        source_matched_hostgroup: source_match.and_then(|m| m.entry.hostgroup.clone()),
        destination_matched_hostgroup: destination_match.and_then(|m| m.entry.hostgroup.clone()),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;
    use tidegard_common::{NormalizedFlowBuilder, Protocol, SamplingRate, SamplingSource};

    fn registry_with_local_v4_and_v6() -> PrefixRegistry {
        let mut r = PrefixRegistry::new();
        r.insert(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
            "wetechi",
            Some("core".into()),
        )
        .unwrap();
        r.insert(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
            32,
            "wetechi",
            Some("core-v6".into()),
        )
        .unwrap();
        r
    }

    fn flow(source: IpAddr, destination: IpAddr) -> NormalizedFlow {
        NormalizedFlowBuilder {
            source_addr: source,
            destination_addr: destination,
            source_port: Some(443),
            destination_port: Some(51000),
            protocol: Some(Protocol::Tcp),
            tcp_flags: None,
            raw_bytes: 100,
            raw_packets: 1,
            input_interface: None,
            output_interface: None,
            source_asn: None,
            destination_asn: None,
            exporter: IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            observation_domain_id: 1,
            start_time: Some(SystemTime::now()),
            end_time: None,
            fragmented: false,
            dropped: false,
            forwarding_status_known: false,
        }
        .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
        .unwrap()
    }

    #[test]
    fn classifies_incoming_ipv4() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        );
        let result = classify(&registry, &f);
        assert_eq!(result.direction, Direction::Incoming);
        assert_eq!(result.source_local, Some(false));
        assert_eq!(result.destination_local, Some(true));
        assert!(result.reason.contains("Incoming"));
    }

    #[test]
    fn classifies_outgoing_ipv4() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        );
        assert_eq!(classify(&registry, &f).direction, Direction::Outgoing);
    }

    #[test]
    fn classifies_internal_ipv4() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
        );
        assert_eq!(classify(&registry, &f).direction, Direction::Internal);
    }

    #[test]
    fn classifies_other_ipv4() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
        );
        assert_eq!(classify(&registry, &f).direction, Direction::Other);
    }

    #[test]
    fn classifies_incoming_ipv6() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        );
        assert_eq!(classify(&registry, &f).direction, Direction::Incoming);
    }

    #[test]
    fn classifies_outgoing_ipv6() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
        );
        assert_eq!(classify(&registry, &f).direction, Direction::Outgoing);
    }

    #[test]
    fn classifies_internal_ipv6() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
        );
        assert_eq!(classify(&registry, &f).direction, Direction::Internal);
    }

    #[test]
    fn classifies_other_ipv6() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 1)),
        );
        assert_eq!(classify(&registry, &f).direction, Direction::Other);
    }

    #[test]
    fn unknown_when_no_prefixes_configured() {
        let registry = PrefixRegistry::new();
        let f = flow(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
        );
        let result = classify(&registry, &f);
        assert_eq!(result.direction, Direction::Unknown);
        assert_eq!(result.source_local, None);
        assert!(result.reason.contains("no local prefixes"));
    }

    #[test]
    fn result_reports_matched_tenant() {
        let registry = registry_with_local_v4_and_v6();
        let f = flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        );
        let result = classify(&registry, &f);
        assert_eq!(
            result.destination_matched_tenant.as_deref(),
            Some("wetechi")
        );
        assert_eq!(result.source_matched_tenant, None);
    }
}
