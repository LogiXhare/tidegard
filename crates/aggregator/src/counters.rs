//! Per-key traffic counters (Phase 3 objective 6).

use tidegard_common::{NormalizedFlow, Protocol};

/// Cumulative traffic counters for one aggregation key (a host, a
/// network, a hostgroup, an ASN, ...). Every counter saturates rather
/// than wraps on overflow — a wrapped counter silently corrupting a
/// dashboard is worse than one that caps out and is visibly wrong.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficCounters {
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
    pub tcp_bytes: u64,
    pub tcp_packets: u64,
    pub udp_bytes: u64,
    pub udp_packets: u64,
    pub icmp_bytes: u64,
    pub icmp_packets: u64,
    /// Only incremented when the source protocol actually carried TCP
    /// flags (`NormalizedFlow::tcp_flags.is_some()`) — see Phase 3
    /// objective 6 "TCP SYN when fields are available."
    pub tcp_syn_packets: u64,
    /// Only meaningful when the source protocol declared fragmentation
    /// information; see `NormalizedFlow::fragmented`.
    pub fragmented_packets: u64,
    /// Only incremented when the source protocol carried a
    /// forwarding-status field (`NormalizedFlow::forwarding_status_known`).
    pub dropped_packets: u64,
}

impl TrafficCounters {
    pub fn add(&mut self, flow: &NormalizedFlow) {
        self.bytes = self.bytes.saturating_add(flow.bytes);
        self.packets = self.packets.saturating_add(flow.packets);
        self.flows = self.flows.saturating_add(1);

        match flow.protocol {
            Some(Protocol::Tcp) => {
                self.tcp_bytes = self.tcp_bytes.saturating_add(flow.bytes);
                self.tcp_packets = self.tcp_packets.saturating_add(flow.packets);
                if flow.is_tcp_syn() {
                    self.tcp_syn_packets = self.tcp_syn_packets.saturating_add(flow.packets);
                }
            }
            Some(Protocol::Udp) => {
                self.udp_bytes = self.udp_bytes.saturating_add(flow.bytes);
                self.udp_packets = self.udp_packets.saturating_add(flow.packets);
            }
            Some(Protocol::Icmp) | Some(Protocol::Icmpv6) => {
                self.icmp_bytes = self.icmp_bytes.saturating_add(flow.bytes);
                self.icmp_packets = self.icmp_packets.saturating_add(flow.packets);
            }
            _ => {}
        }

        if flow.fragmented {
            self.fragmented_packets = self.fragmented_packets.saturating_add(flow.packets);
        }
        if flow.forwarding_status_known && flow.dropped {
            self.dropped_packets = self.dropped_packets.saturating_add(flow.packets);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tidegard_common::{NormalizedFlowBuilder, SamplingRate, SamplingSource};

    fn tcp_syn_flow() -> NormalizedFlow {
        NormalizedFlowBuilder {
            source_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: Some(51000),
            destination_port: Some(443),
            protocol: Some(Protocol::Tcp),
            tcp_flags: Some(tidegard_common::flow::TCP_FLAG_SYN),
            raw_bytes: 64,
            raw_packets: 1,
            input_interface: None,
            output_interface: None,
            source_asn: None,
            destination_asn: None,
            exporter: IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            observation_domain_id: 1,
            start_time: None,
            end_time: None,
            fragmented: false,
            dropped: false,
            forwarding_status_known: false,
        }
        .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
        .unwrap()
    }

    #[test]
    fn accumulates_totals_and_protocol_specific_counters() {
        let mut counters = TrafficCounters::default();
        counters.add(&tcp_syn_flow());
        assert_eq!(counters.bytes, 64);
        assert_eq!(counters.packets, 1);
        assert_eq!(counters.flows, 1);
        assert_eq!(counters.tcp_bytes, 64);
        assert_eq!(counters.tcp_syn_packets, 1);
        assert_eq!(counters.udp_bytes, 0);
    }

    #[test]
    fn multiple_adds_accumulate() {
        let mut counters = TrafficCounters::default();
        counters.add(&tcp_syn_flow());
        counters.add(&tcp_syn_flow());
        assert_eq!(counters.flows, 2);
        assert_eq!(counters.bytes, 128);
    }

    #[test]
    fn saturates_instead_of_wrapping_on_overflow() {
        let mut counters = TrafficCounters {
            bytes: u64::MAX - 10,
            ..Default::default()
        };
        let mut flow = tcp_syn_flow();
        flow.bytes = 1000;
        counters.add(&flow);
        assert_eq!(counters.bytes, u64::MAX);
    }

    #[test]
    fn dropped_only_counted_when_forwarding_status_is_known() {
        let mut counters = TrafficCounters::default();
        let mut flow = tcp_syn_flow();
        flow.dropped = true;
        flow.forwarding_status_known = false;
        counters.add(&flow);
        assert_eq!(counters.dropped_packets, 0);

        flow.forwarding_status_known = true;
        counters.add(&flow);
        assert_eq!(counters.dropped_packets, 1);
    }
}
