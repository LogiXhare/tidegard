//! Converts a decoded IPFIX Data Record into a protocol-independent
//! `NormalizedFlow` (Phase 3 objective 1), applying sampling correction
//! per the documented priority order (Phase 3 objective 2).
//!
//! Only a well-known subset of IANA IPFIX Information Elements is
//! mapped, per the public IANA IPFIX Information Elements registry — see
//! docs/clean-room-boundary.md. Unmapped fields are simply not
//! populated on the resulting `NormalizedFlow` (`None`/default), not an
//! error — this is IPFIX's own design: an exporter can include fields
//! this collector doesn't yet interpret. **Known limitation:**
//! fragmentation-status mapping is deliberately left unmapped in Phase 3
//! — the IANA registry does define fragmentation-related elements, but
//! this project has not independently verified the exact element number
//! against the current registry with high enough confidence to encode it
//! without risking a silently wrong mapping; `NormalizedFlow::fragmented`
//! is always `false` from the IPFIX path today. Documented, not hidden.

use std::net::IpAddr;

use tidegard_common::{
    resolve_sampling, FlowError, NormalizedFlow, NormalizedFlowBuilder, Protocol, SamplingInputs,
};
use tidegard_protocol_ipfix::{DataRecord, SamplingInfo};

// IANA IPFIX Information Element IDs used here — see the public IANA
// "IP Flow Information Export (IPFIX) Entities" registry.
const IE_OCTET_DELTA_COUNT: u16 = 1;
const IE_PACKET_DELTA_COUNT: u16 = 2;
const IE_PROTOCOL_IDENTIFIER: u16 = 4;
const IE_TCP_CONTROL_BITS: u16 = 6;
const IE_SOURCE_TRANSPORT_PORT: u16 = 7;
const IE_SOURCE_IPV4_ADDRESS: u16 = 8;
const IE_INGRESS_INTERFACE: u16 = 10;
const IE_DESTINATION_TRANSPORT_PORT: u16 = 11;
const IE_DESTINATION_IPV4_ADDRESS: u16 = 12;
const IE_EGRESS_INTERFACE: u16 = 14;
const IE_BGP_SOURCE_AS_NUMBER: u16 = 16;
const IE_BGP_DESTINATION_AS_NUMBER: u16 = 17;
const IE_SOURCE_IPV6_ADDRESS: u16 = 27;
const IE_DESTINATION_IPV6_ADDRESS: u16 = 28;
const IE_SAMPLING_INTERVAL: u16 = 34;
const IE_FORWARDING_STATUS: u16 = 89;

/// `forwardingStatus` (IE 89) is an 8-bit field whose top 2 bits are the
/// coarse status (0=Unknown, 1=Forwarded, 2=Dropped, 3=Consumed) per the
/// public IANA registry.
const FORWARDING_STATUS_DROPPED: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum NormalizeError {
    #[error("record has no source and/or destination address field (neither IPv4 nor IPv6)")]
    MissingAddresses,
    #[error(transparent)]
    Flow(#[from] FlowError),
}

/// Additional sampling context the collector supplies (exporter-level
/// operator configuration and the global default) — the record-level and
/// options-template tiers are derived from the IPFIX data itself inside
/// this function.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExternalSamplingConfig {
    pub exporter_configured: Option<u32>,
    pub global_default: Option<u32>,
}

/// Result of a normalization attempt, including whether a declared-zero
/// sampling rate had to be skipped — the caller uses this to drive the
/// `sampling_errors_total`-style metric without `crates/common` needing
/// to know about Prometheus.
pub struct NormalizeOutcome {
    pub flow: NormalizedFlow,
    pub zero_rate_skipped: bool,
}

pub fn normalize_ipfix_record(
    record: &DataRecord,
    exporter: IpAddr,
    observation_domain_id: u32,
    options_sampling: SamplingInfo,
    external: ExternalSamplingConfig,
) -> Result<NormalizeOutcome, NormalizeError> {
    let mut source_addr: Option<IpAddr> = None;
    let mut destination_addr: Option<IpAddr> = None;
    let mut source_port = None;
    let mut destination_port = None;
    let mut protocol = None;
    let mut tcp_flags = None;
    let mut raw_bytes = 0u64;
    let mut raw_packets = 0u64;
    let mut input_interface = None;
    let mut output_interface = None;
    let mut source_asn = None;
    let mut destination_asn = None;
    let mut record_level_sampling = None;
    let mut forwarding_status_known = false;
    let mut dropped = false;

    for field in &record.fields {
        match field.information_element_id {
            IE_SOURCE_IPV4_ADDRESS => source_addr = field.as_ipv4().map(IpAddr::V4),
            IE_DESTINATION_IPV4_ADDRESS => destination_addr = field.as_ipv4().map(IpAddr::V4),
            IE_SOURCE_IPV6_ADDRESS => source_addr = field.as_ipv6().map(IpAddr::V6),
            IE_DESTINATION_IPV6_ADDRESS => destination_addr = field.as_ipv6().map(IpAddr::V6),
            IE_SOURCE_TRANSPORT_PORT => {
                source_port = field.as_u64_be().map(|v| v as u16);
            }
            IE_DESTINATION_TRANSPORT_PORT => {
                destination_port = field.as_u64_be().map(|v| v as u16);
            }
            IE_PROTOCOL_IDENTIFIER => {
                protocol = field
                    .as_u64_be()
                    .map(|v| Protocol::from_ip_protocol_number(v as u8));
            }
            IE_TCP_CONTROL_BITS => {
                tcp_flags = field.as_u64_be().map(|v| v as u8);
            }
            IE_OCTET_DELTA_COUNT => {
                raw_bytes = field.as_u64_be().unwrap_or(0);
            }
            IE_PACKET_DELTA_COUNT => {
                raw_packets = field.as_u64_be().unwrap_or(0);
            }
            IE_INGRESS_INTERFACE => {
                input_interface = field.as_u64_be().map(|v| v as u32);
            }
            IE_EGRESS_INTERFACE => {
                output_interface = field.as_u64_be().map(|v| v as u32);
            }
            IE_BGP_SOURCE_AS_NUMBER => {
                source_asn = field.as_u64_be().map(|v| v as u32);
            }
            IE_BGP_DESTINATION_AS_NUMBER => {
                destination_asn = field.as_u64_be().map(|v| v as u32);
            }
            IE_SAMPLING_INTERVAL => {
                record_level_sampling = field.as_u64_be().map(|v| v as u32);
            }
            IE_FORWARDING_STATUS => {
                if let Some(v) = field.as_u64_be() {
                    forwarding_status_known = true;
                    dropped = ((v as u8) >> 6) == FORWARDING_STATUS_DROPPED;
                }
            }
            _ => {}
        }
    }

    let (source_addr, destination_addr) = match (source_addr, destination_addr) {
        (Some(s), Some(d)) => (s, d),
        _ => return Err(NormalizeError::MissingAddresses),
    };

    let sampling_inputs = SamplingInputs {
        record_level: record_level_sampling,
        options_template: options_sampling.sampling_interval,
        exporter_configured: external.exporter_configured,
        global_default: external.global_default,
    };
    let resolved = resolve_sampling(&sampling_inputs);

    let builder = NormalizedFlowBuilder {
        source_addr,
        destination_addr,
        source_port,
        destination_port,
        protocol,
        tcp_flags,
        raw_bytes,
        raw_packets,
        input_interface,
        output_interface,
        source_asn,
        destination_asn,
        exporter,
        observation_domain_id,
        start_time: None,
        end_time: None,
        fragmented: false,
        dropped,
        forwarding_status_known,
    };

    let flow = builder.build(resolved.rate, resolved.source)?;

    Ok(NormalizeOutcome {
        flow,
        zero_rate_skipped: resolved.zero_rate_skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tidegard_protocol_ipfix::DecodedField;

    fn field(ie: u16, bytes: Vec<u8>) -> DecodedField {
        DecodedField {
            information_element_id: ie,
            enterprise_number: None,
            value: bytes,
        }
    }

    fn sample_record() -> DataRecord {
        DataRecord {
            template_id: 256,
            fields: vec![
                field(IE_SOURCE_IPV4_ADDRESS, vec![10, 0, 0, 1]),
                field(IE_DESTINATION_IPV4_ADDRESS, vec![10, 0, 0, 2]),
                field(IE_SOURCE_TRANSPORT_PORT, 51000u16.to_be_bytes().to_vec()),
                field(IE_DESTINATION_TRANSPORT_PORT, 443u16.to_be_bytes().to_vec()),
                field(IE_PROTOCOL_IDENTIFIER, vec![6]), // TCP
                field(IE_OCTET_DELTA_COUNT, 1000u64.to_be_bytes().to_vec()),
                field(IE_PACKET_DELTA_COUNT, 10u64.to_be_bytes().to_vec()),
            ],
        }
    }

    #[test]
    fn maps_well_known_fields_and_applies_unsampled_default() {
        let record = sample_record();
        let outcome = normalize_ipfix_record(
            &record,
            IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            7,
            SamplingInfo::default(),
            ExternalSamplingConfig::default(),
        )
        .unwrap();

        assert_eq!(
            outcome.flow.source_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(outcome.flow.source_port, Some(51000));
        assert_eq!(outcome.flow.destination_port, Some(443));
        assert_eq!(outcome.flow.protocol, Some(Protocol::Tcp));
        assert_eq!(outcome.flow.bytes, 1000); // unsampled: rate 1
        assert_eq!(outcome.flow.packets, 10);
        assert!(!outcome.zero_rate_skipped);
    }

    #[test]
    fn rejects_a_record_missing_addresses() {
        let record = DataRecord {
            template_id: 1,
            fields: vec![field(IE_OCTET_DELTA_COUNT, 100u64.to_be_bytes().to_vec())],
        };
        let result = normalize_ipfix_record(
            &record,
            IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            7,
            SamplingInfo::default(),
            ExternalSamplingConfig::default(),
        );
        assert!(matches!(result, Err(NormalizeError::MissingAddresses)));
    }

    #[test]
    fn options_template_sampling_is_applied_when_present() {
        let record = sample_record();
        let options = SamplingInfo {
            sampling_interval: Some(100),
            sampling_algorithm: None,
        };
        let outcome = normalize_ipfix_record(
            &record,
            IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            7,
            options,
            ExternalSamplingConfig::default(),
        )
        .unwrap();
        assert_eq!(outcome.flow.bytes, 100_000); // 1000 * 100
        assert_eq!(outcome.flow.sampling_rate.get(), 100);
    }

    #[test]
    fn exporter_configured_sampling_used_when_no_ipfix_sampling_present() {
        let record = sample_record();
        let external = ExternalSamplingConfig {
            exporter_configured: Some(50),
            global_default: Some(10),
        };
        let outcome = normalize_ipfix_record(
            &record,
            IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            7,
            SamplingInfo::default(),
            external,
        )
        .unwrap();
        assert_eq!(outcome.flow.sampling_rate.get(), 50);
    }

    #[test]
    fn ipv6_addresses_are_mapped() {
        use std::net::Ipv6Addr;
        let record = DataRecord {
            template_id: 1,
            fields: vec![
                field(
                    IE_SOURCE_IPV6_ADDRESS,
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
                        .octets()
                        .to_vec(),
                ),
                field(
                    IE_DESTINATION_IPV6_ADDRESS,
                    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
                        .octets()
                        .to_vec(),
                ),
                field(IE_OCTET_DELTA_COUNT, 500u64.to_be_bytes().to_vec()),
                field(IE_PACKET_DELTA_COUNT, 5u64.to_be_bytes().to_vec()),
            ],
        };
        let outcome = normalize_ipfix_record(
            &record,
            IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            7,
            SamplingInfo::default(),
            ExternalSamplingConfig::default(),
        )
        .unwrap();
        assert!(outcome.flow.source_addr.is_ipv6());
    }

    #[test]
    fn forwarding_status_dropped_is_mapped() {
        let mut record = sample_record();
        // Top 2 bits = 2 (Dropped) => 0b10_000000 = 0x80
        record.fields.push(field(IE_FORWARDING_STATUS, vec![0x80]));
        let outcome = normalize_ipfix_record(
            &record,
            IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            7,
            SamplingInfo::default(),
            ExternalSamplingConfig::default(),
        )
        .unwrap();
        assert!(outcome.flow.forwarding_status_known);
        assert!(outcome.flow.dropped);
    }
}
