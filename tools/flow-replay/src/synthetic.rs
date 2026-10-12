//! Builds well-formed, synthetic IPFIX messages for safely testing the
//! collector — see docs/security-principles.md: "Use only synthetic
//! telemetry, sanitized telemetry, lab networks, authorized
//! environments" and "Never generate real attack traffic." Nothing in
//! this module reads captured packets or real customer data; every
//! value is either a caller-supplied parameter or a fixed constant.
//!
//! Phase 3 extends this module (objective 11) to cover: IPv4 and IPv6,
//! TCP/UDP/ICMP, sampled flows (via an Options Template declaring
//! `samplingInterval`), and multiple exporters/observation domains — the
//! latter two are a property of *how this is called* (different
//! `observation_domain_id` / different source socket per "exporter"),
//! not something the message-building functions need special-cased for.

use std::net::{Ipv4Addr, Ipv6Addr};

const IPFIX_VERSION: u16 = 0x000a;
const TEMPLATE_SET_ID: u16 = 2;
const OPTIONS_TEMPLATE_SET_ID: u16 = 3;

/// Template ID for IPv4 flow records.
pub const TEMPLATE_ID_IPV4: u16 = 256;
/// Template ID for IPv6 flow records.
pub const TEMPLATE_ID_IPV6: u16 = 257;
/// Template ID for the sampling Options Template.
pub const OPTIONS_TEMPLATE_ID: u16 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
}

impl IpProtocol {
    fn number(self) -> u8 {
        match self {
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Icmp => 1,
        }
    }
}

fn message_header(length: u16, sequence_number: u32, observation_domain_id: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&IPFIX_VERSION.to_be_bytes());
    b.extend_from_slice(&length.to_be_bytes());
    b.extend_from_slice(
        &(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0))
        .to_be_bytes(),
    );
    b.extend_from_slice(&sequence_number.to_be_bytes());
    b.extend_from_slice(&observation_domain_id.to_be_bytes());
    b
}

fn wrap_set(set_id: u16, body: Vec<u8>) -> Vec<u8> {
    let mut set = Vec::new();
    set.extend_from_slice(&set_id.to_be_bytes());
    set.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    set.extend_from_slice(&body);
    set
}

fn wrap_message(set: Vec<u8>, sequence_number: u32, observation_domain_id: u32) -> Vec<u8> {
    let mut message = message_header(
        (16 + set.len()) as u16,
        sequence_number,
        observation_domain_id,
    );
    message.extend_from_slice(&set);
    message
}

/// A Template Set for IPv4 flow records: sourceIPv4Address(8),
/// destinationIPv4Address(12), sourceTransportPort(7),
/// destinationTransportPort(11), protocolIdentifier(4),
/// octetDeltaCount(1), packetDeltaCount(2).
pub fn template_message_ipv4(sequence_number: u32, observation_domain_id: u32) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&TEMPLATE_ID_IPV4.to_be_bytes());
    record.extend_from_slice(&7u16.to_be_bytes());
    for (ie, len) in [
        (8u16, 4u16),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 8),
        (2, 8),
    ] {
        record.extend_from_slice(&ie.to_be_bytes());
        record.extend_from_slice(&len.to_be_bytes());
    }
    wrap_message(
        wrap_set(TEMPLATE_SET_ID, record),
        sequence_number,
        observation_domain_id,
    )
}

/// A Template Set for IPv6 flow records: sourceIPv6Address(27),
/// destinationIPv6Address(28), sourceTransportPort(7),
/// destinationTransportPort(11), protocolIdentifier(4),
/// octetDeltaCount(1), packetDeltaCount(2).
pub fn template_message_ipv6(sequence_number: u32, observation_domain_id: u32) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&TEMPLATE_ID_IPV6.to_be_bytes());
    record.extend_from_slice(&7u16.to_be_bytes());
    for (ie, len) in [
        (27u16, 16u16),
        (28, 16),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 8),
        (2, 8),
    ] {
        record.extend_from_slice(&ie.to_be_bytes());
        record.extend_from_slice(&len.to_be_bytes());
    }
    wrap_message(
        wrap_set(TEMPLATE_SET_ID, record),
        sequence_number,
        observation_domain_id,
    )
}

/// An Options Template Set declaring `samplingInterval` (IE 34), scoped
/// by `ingressInterface` (IE 10) — the structural shape a real exporter
/// uses to advertise its sampling rate (see
/// docs/architecture/aggregation.md sampling-correction section).
pub fn options_template_message(sequence_number: u32, observation_domain_id: u32) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&OPTIONS_TEMPLATE_ID.to_be_bytes());
    record.extend_from_slice(&2u16.to_be_bytes()); // field_count
    record.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count
    record.extend_from_slice(&10u16.to_be_bytes()); // ingressInterface (scope)
    record.extend_from_slice(&4u16.to_be_bytes());
    record.extend_from_slice(&34u16.to_be_bytes()); // samplingInterval
    record.extend_from_slice(&4u16.to_be_bytes());
    wrap_message(
        wrap_set(OPTIONS_TEMPLATE_SET_ID, record),
        sequence_number,
        observation_domain_id,
    )
}

/// A Data Set for [`OPTIONS_TEMPLATE_ID`], declaring `sampling_rate` for
/// `interface`.
pub fn options_data_message(
    sequence_number: u32,
    observation_domain_id: u32,
    interface: u32,
    sampling_rate: u32,
) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&interface.to_be_bytes());
    record.extend_from_slice(&sampling_rate.to_be_bytes());
    wrap_message(
        wrap_set(OPTIONS_TEMPLATE_ID, record),
        sequence_number,
        observation_domain_id,
    )
}

/// A Data Set of one IPv4 flow record matching [`template_message_ipv4`].
#[allow(clippy::too_many_arguments)]
pub fn data_message_ipv4(
    sequence_number: u32,
    observation_domain_id: u32,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    protocol: IpProtocol,
    byte_count: u64,
    packet_count: u64,
) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&source.octets());
    record.extend_from_slice(&destination.octets());
    record.extend_from_slice(&source_port.to_be_bytes());
    record.extend_from_slice(&destination_port.to_be_bytes());
    record.push(protocol.number());
    record.extend_from_slice(&byte_count.to_be_bytes());
    record.extend_from_slice(&packet_count.to_be_bytes());
    wrap_message(
        wrap_set(TEMPLATE_ID_IPV4, record),
        sequence_number,
        observation_domain_id,
    )
}

/// One IPv4 flow record for [`data_message_ipv4_batch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Record {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: IpProtocol,
    pub byte_count: u64,
    pub packet_count: u64,
}

/// The bytes one record takes in [`template_message_ipv4`]'s layout.
pub const IPV4_RECORD_LEN: usize = 29;

/// A Data Set of several IPv4 flow records, as a real exporter batches
/// them. `sequence_number` counts data records sent before this message
/// (RFC 7011), so the caller adds `records.len()` after sending.
pub fn data_message_ipv4_batch(
    sequence_number: u32,
    observation_domain_id: u32,
    records: &[Ipv4Record],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(records.len() * IPV4_RECORD_LEN);
    for record in records {
        body.extend_from_slice(&record.source.octets());
        body.extend_from_slice(&record.destination.octets());
        body.extend_from_slice(&record.source_port.to_be_bytes());
        body.extend_from_slice(&record.destination_port.to_be_bytes());
        body.push(record.protocol.number());
        body.extend_from_slice(&record.byte_count.to_be_bytes());
        body.extend_from_slice(&record.packet_count.to_be_bytes());
    }
    wrap_message(
        wrap_set(TEMPLATE_ID_IPV4, body),
        sequence_number,
        observation_domain_id,
    )
}

/// A Data Set of one IPv6 flow record matching [`template_message_ipv6`].
#[allow(clippy::too_many_arguments)]
pub fn data_message_ipv6(
    sequence_number: u32,
    observation_domain_id: u32,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    protocol: IpProtocol,
    byte_count: u64,
    packet_count: u64,
) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&source.octets());
    record.extend_from_slice(&destination.octets());
    record.extend_from_slice(&source_port.to_be_bytes());
    record.extend_from_slice(&destination_port.to_be_bytes());
    record.push(protocol.number());
    record.extend_from_slice(&byte_count.to_be_bytes());
    record.extend_from_slice(&packet_count.to_be_bytes());
    wrap_message(
        wrap_set(TEMPLATE_ID_IPV6, record),
        sequence_number,
        observation_domain_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_message_has_a_well_formed_header() {
        let msg = template_message_ipv4(1, 7);
        assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), IPFIX_VERSION);
        let declared_len = u16::from_be_bytes([msg[2], msg[3]]);
        assert_eq!(declared_len as usize, msg.len());
    }

    #[test]
    fn data_message_carries_the_requested_sequence_number() {
        let msg = data_message_ipv4(
            42,
            7,
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            51000,
            443,
            IpProtocol::Tcp,
            1000,
            99,
        );
        let seq = u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]);
        assert_eq!(seq, 42);
    }

    /// The real payoff of a synthetic-fixture module: round-trip it
    /// through the actual decoder and confirm the values come back out
    /// unchanged. This exercises `wetechinetmon-protocol-ipfix` the same
    /// way a live exporter's traffic would, without ever touching a real
    /// network capture.
    #[test]
    fn round_trips_ipv4_through_the_real_ipfix_decoder() {
        use wetechinetmon_protocol_ipfix::{decode_message, DecodedSet, TemplateCache};

        let mut cache = TemplateCache::new();

        let tmpl_msg = template_message_ipv4(1, 7);
        let decoded_tmpl = decode_message(&tmpl_msg, &mut cache).unwrap();
        assert!(matches!(decoded_tmpl.sets[0], DecodedSet::Templates(_)));

        let data_msg = data_message_ipv4(
            2,
            7,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            51000,
            443,
            IpProtocol::Tcp,
            1234,
            10,
        );
        let decoded_data = decode_message(&data_msg, &mut cache).unwrap();
        match &decoded_data.sets[0] {
            DecodedSet::Data { records, .. } => {
                assert_eq!(records.len(), 1);
                assert_eq!(
                    records[0].fields[0].as_ipv4(),
                    Some(Ipv4Addr::new(10, 0, 0, 1))
                );
                assert_eq!(records[0].fields[4].as_u64_be(), Some(6)); // protocol = TCP
                assert_eq!(records[0].fields[5].as_u64_be(), Some(1234)); // bytes
            }
            other => panic!("expected a Data set, got {other:?}"),
        }
    }

    #[test]
    fn round_trips_ipv6_through_the_real_ipfix_decoder() {
        use wetechinetmon_protocol_ipfix::{decode_message, DecodedSet, TemplateCache};

        let mut cache = TemplateCache::new();
        decode_message(&template_message_ipv6(1, 7), &mut cache).unwrap();

        let data_msg = data_message_ipv6(
            2,
            7,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            51000,
            443,
            IpProtocol::Udp,
            500,
            5,
        );
        let decoded = decode_message(&data_msg, &mut cache).unwrap();
        match &decoded.sets[0] {
            DecodedSet::Data { records, .. } => {
                assert!(records[0].fields[0].as_ipv6().is_some());
            }
            other => panic!("expected a Data set, got {other:?}"),
        }
    }

    #[test]
    fn options_template_and_data_round_trip_and_populate_sampling_info() {
        use wetechinetmon_protocol_ipfix::{decode_message, TemplateCache};

        let mut cache = TemplateCache::new();
        decode_message(&options_template_message(1, 7), &mut cache).unwrap();
        decode_message(&options_data_message(2, 7, 1, 100), &mut cache).unwrap();
        assert_eq!(cache.sampling().sampling_interval, Some(100));
    }
}
