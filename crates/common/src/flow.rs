//! `NormalizedFlow` — Tidegard's protocol-independent flow record.
//!
//! Every collector (IPFIX today; NetFlow v9/v5 and sFlow v5 in later
//! phases per docs/roadmap.md) converts its wire format into this one
//! type before handing records to the Classifier and Aggregator. Neither
//! of those crates — nor anything downstream — needs to know IPFIX, or
//! any other wire protocol, exists. This is what makes "future NetFlow/
//! sFlow collectors can use the same aggregation pipeline" (Phase 3
//! objective 1) true by construction rather than by convention.

use std::net::IpAddr;
use std::time::SystemTime;

use crate::sampling::{SamplingRate, SamplingSource};

/// IANA-assigned IP protocol numbers this project currently distinguishes
/// by name; anything else is preserved as `Other(n)` rather than lost.
/// (Public IANA protocol-numbers registry — not sourced from any
/// proprietary product.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
    Icmpv6,
    Other(u8),
}

impl Protocol {
    pub fn from_ip_protocol_number(n: u8) -> Self {
        match n {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::Icmpv6,
            other => Protocol::Other(other),
        }
    }

    pub fn as_ip_protocol_number(&self) -> u8 {
        match self {
            Protocol::Icmp => 1,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmpv6 => 58,
            Protocol::Other(n) => *n,
        }
    }
}

/// Common TCP control-bit masks (RFC 9293), used for TCP-SYN detection
/// (Phase 3 objective 6). Only decoded when the source protocol actually
/// carries TCP flags — see `NormalizedFlow::tcp_flags`.
pub const TCP_FLAG_SYN: u8 = 0b0000_0010;

/// A fully normalized, sampling-corrected flow record.
///
/// **Invariant, enforced by construction (see [`NormalizedFlowBuilder`]):**
/// `bytes`/`packets` are always the *corrected* (post-sampling-multiplier)
/// values. There is no public way to construct a `NormalizedFlow` and
/// later re-apply sampling correction to it — the only path that produces
/// one applies the resolved rate exactly once. `raw_bytes`/`raw_packets`
/// are kept alongside purely for audit/debugging, never re-corrected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedFlow {
    pub source_addr: IpAddr,
    pub destination_addr: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub tcp_flags: Option<u8>,
    /// Sampling-corrected byte count.
    pub bytes: u64,
    /// Sampling-corrected packet count.
    pub packets: u64,
    pub raw_bytes: u64,
    pub raw_packets: u64,
    pub sampling_rate: SamplingRate,
    pub sampling_source: SamplingSource,
    pub input_interface: Option<u32>,
    pub output_interface: Option<u32>,
    /// Origin AS of the source address, when the exporter provides it
    /// (e.g. IPFIX `bgpSourceAsNumber`, IE 16) — `None` otherwise. Never
    /// looked up from a separate routing table by this project; only
    /// what the exporter itself declares.
    pub source_asn: Option<u32>,
    /// Origin AS of the destination address, when the exporter provides
    /// it (e.g. IPFIX `bgpDestinationAsNumber`, IE 17).
    pub destination_asn: Option<u32>,
    /// Identifies which exporter sent this flow — protocol-independent,
    /// so just the exporter's network address.
    pub exporter: IpAddr,
    pub observation_domain_id: u32,
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
    pub fragmented: bool,
    /// `true` when the source protocol carried a forwarding-status field
    /// indicating this flow's packets were dropped (e.g. IPFIX IE 89
    /// `forwardingStatus`, drop-reason range). `false` includes both
    /// "known forwarded" and "unknown" — see `forwarding_status_known`.
    pub dropped: bool,
    pub forwarding_status_known: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FlowError {
    #[error("flow has zero bytes and zero packets, which is not a meaningful flow")]
    Empty,
    #[error("sampling correction overflowed u64 while scaling {field}")]
    SamplingOverflow { field: &'static str },
}

/// Builds a [`NormalizedFlow`], applying sampling correction exactly once
/// and rejecting malformed input (Phase 3 "malformed normalized flows
/// rejected" / "missing fields are handled safely" acceptance criteria).
///
/// Missing optional fields (ports, protocol, interfaces, timestamps) are
/// represented as `None` rather than rejected outright — only conditions
/// that make the record meaningless (zero bytes *and* zero packets) or
/// unsafe to represent (sampling overflow) are rejected.
pub struct NormalizedFlowBuilder {
    pub source_addr: IpAddr,
    pub destination_addr: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub tcp_flags: Option<u8>,
    pub raw_bytes: u64,
    pub raw_packets: u64,
    pub input_interface: Option<u32>,
    pub output_interface: Option<u32>,
    pub source_asn: Option<u32>,
    pub destination_asn: Option<u32>,
    pub exporter: IpAddr,
    pub observation_domain_id: u32,
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
    pub fragmented: bool,
    pub dropped: bool,
    pub forwarding_status_known: bool,
}

impl NormalizedFlowBuilder {
    /// Consumes the builder, applying `rate` to the raw counters exactly
    /// once, and returns the resulting `NormalizedFlow` — or a
    /// [`FlowError`] if the record is empty or correction overflows.
    pub fn build(
        self,
        rate: SamplingRate,
        source: SamplingSource,
    ) -> Result<NormalizedFlow, FlowError> {
        if self.raw_bytes == 0 && self.raw_packets == 0 {
            return Err(FlowError::Empty);
        }

        let bytes = rate
            .apply(self.raw_bytes)
            .map_err(|_| FlowError::SamplingOverflow { field: "bytes" })?;
        let packets = rate
            .apply(self.raw_packets)
            .map_err(|_| FlowError::SamplingOverflow { field: "packets" })?;

        Ok(NormalizedFlow {
            source_addr: self.source_addr,
            destination_addr: self.destination_addr,
            source_port: self.source_port,
            destination_port: self.destination_port,
            protocol: self.protocol,
            tcp_flags: self.tcp_flags,
            bytes,
            packets,
            raw_bytes: self.raw_bytes,
            raw_packets: self.raw_packets,
            sampling_rate: rate,
            sampling_source: source,
            input_interface: self.input_interface,
            output_interface: self.output_interface,
            source_asn: self.source_asn,
            destination_asn: self.destination_asn,
            exporter: self.exporter,
            observation_domain_id: self.observation_domain_id,
            start_time: self.start_time,
            end_time: self.end_time,
            fragmented: self.fragmented,
            dropped: self.dropped,
            forwarding_status_known: self.forwarding_status_known,
        })
    }
}

impl NormalizedFlow {
    pub fn is_tcp_syn(&self) -> bool {
        matches!(self.protocol, Some(Protocol::Tcp))
            && self
                .tcp_flags
                .is_some_and(|flags| flags & TCP_FLAG_SYN != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sampling::SamplingRate;
    use std::net::Ipv4Addr;

    fn builder() -> NormalizedFlowBuilder {
        NormalizedFlowBuilder {
            source_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: Some(443),
            destination_port: Some(51000),
            protocol: Some(Protocol::Tcp),
            tcp_flags: Some(TCP_FLAG_SYN),
            raw_bytes: 100,
            raw_packets: 2,
            input_interface: Some(1),
            output_interface: Some(2),
            source_asn: Some(65001),
            destination_asn: Some(65002),
            exporter: IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            observation_domain_id: 7,
            start_time: None,
            end_time: None,
            fragmented: false,
            dropped: false,
            forwarding_status_known: false,
        }
    }

    #[test]
    fn applies_sampling_correction_exactly_once() {
        let rate = SamplingRate::new(100).unwrap();
        let flow = builder()
            .build(rate, SamplingSource::ExporterConfigured)
            .unwrap();
        assert_eq!(flow.raw_bytes, 100);
        assert_eq!(flow.bytes, 10_000); // 100 * 100, not 100 * 100 * 100
        assert_eq!(flow.raw_packets, 2);
        assert_eq!(flow.packets, 200);
    }

    #[test]
    fn unsampled_rate_leaves_counters_unchanged() {
        let flow = builder()
            .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
            .unwrap();
        assert_eq!(flow.bytes, flow.raw_bytes);
        assert_eq!(flow.packets, flow.raw_packets);
    }

    #[test]
    fn rejects_an_empty_flow() {
        let mut b = builder();
        b.raw_bytes = 0;
        b.raw_packets = 0;
        assert_eq!(
            b.build(SamplingRate::unsampled(), SamplingSource::Unsampled),
            Err(FlowError::Empty)
        );
    }

    #[test]
    fn rejects_sampling_overflow_instead_of_wrapping() {
        let mut b = builder();
        b.raw_bytes = u64::MAX;
        let huge_rate = SamplingRate::new(2).unwrap();
        assert_eq!(
            b.build(huge_rate, SamplingSource::GlobalDefault),
            Err(FlowError::SamplingOverflow { field: "bytes" })
        );
    }

    #[test]
    fn missing_optional_fields_are_preserved_as_none_not_rejected() {
        let mut b = builder();
        b.source_port = None;
        b.destination_port = None;
        b.protocol = None;
        b.input_interface = None;
        b.output_interface = None;
        let flow = b
            .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
            .unwrap();
        assert_eq!(flow.source_port, None);
        assert_eq!(flow.protocol, None);
    }

    #[test]
    fn is_tcp_syn_requires_both_tcp_protocol_and_syn_flag() {
        let syn_flow = builder()
            .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
            .unwrap();
        assert!(syn_flow.is_tcp_syn());

        let mut b = builder();
        b.tcp_flags = Some(0b0001_0000); // ACK only, no SYN
        let ack_flow = b
            .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
            .unwrap();
        assert!(!ack_flow.is_tcp_syn());

        let mut b2 = builder();
        b2.protocol = Some(Protocol::Udp);
        let udp_flow = b2
            .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
            .unwrap();
        assert!(!udp_flow.is_tcp_syn());
    }

    #[test]
    fn protocol_round_trips_through_ip_protocol_number() {
        assert_eq!(Protocol::from_ip_protocol_number(6), Protocol::Tcp);
        assert_eq!(Protocol::from_ip_protocol_number(17), Protocol::Udp);
        assert_eq!(Protocol::from_ip_protocol_number(1), Protocol::Icmp);
        assert_eq!(Protocol::from_ip_protocol_number(58), Protocol::Icmpv6);
        assert_eq!(Protocol::from_ip_protocol_number(200), Protocol::Other(200));
        assert_eq!(Protocol::Tcp.as_ip_protocol_number(), 6);
    }
}
