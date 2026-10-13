use crate::error::DecodeError;
use crate::header::{MessageHeader, MESSAGE_HEADER_LEN};
use crate::record::DataRecord;
use crate::template::Template;
use crate::template_cache::TemplateCache;

const TEMPLATE_SET_ID: u16 = 2;
const OPTIONS_TEMPLATE_SET_ID: u16 = 3;
const MIN_DATA_SET_ID: u16 = 256;
const SET_HEADER_LEN: usize = 4;

/// The outcome of decoding one Set within an IPFIX message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedSet {
    Templates(Vec<Template>),
    OptionsTemplates(Vec<Template>),
    Data {
        template_id: u16,
        records: Vec<DataRecord>,
    },
    /// The Data Set's template hasn't been seen yet for this exporter
    /// (RFC 7011 §8.1 — this is an expected, common condition, e.g. right
    /// after an exporter (re)starts, not a parser error). The collector
    /// is expected to count this via the `unknown_templates_total`-style
    /// metric described in docs/security-principles.md, not treat it as
    /// fatal.
    UnknownTemplate {
        template_id: u16,
    },
    /// Set IDs 0, 1, and 4-255 are reserved by RFC 7011 §3.3.2 and never
    /// valid on the wire. Recorded rather than discarded so the caller
    /// can decide whether to count/log it.
    ReservedSetId {
        set_id: u16,
    },
}

/// A fully decoded IPFIX message: its header plus every Set it contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedMessage {
    pub header: MessageHeader,
    pub sets: Vec<DecodedSet>,
}

/// Decodes one complete IPFIX message from `input`.
///
/// `templates` is the caller-owned cache for this exporter's observation
/// domain (RFC 7011 §8.1 — template IDs are only meaningful within one
/// observation domain from one exporter). This function both reads from
/// and writes to it: new/redefined templates from this message are
/// inserted, and any Data Records for an already-known Options Template
/// are inspected for sampling parameters (see
/// `TemplateCache::observe_options_data`).
///
/// A genuinely malformed message (bad header, truncated set, corrupt
/// template record, or a data record that doesn't fit its known
/// template) returns `Err` for the whole message — per
/// docs/security-principles.md, a malformed message is something to
/// detect and count, not to partially trust. An **unknown** template for
/// a Data Set is not an error (see `DecodedSet::UnknownTemplate`): it
/// happens routinely and the rest of the message is still decoded.
pub fn decode_message(
    input: &[u8],
    templates: &mut TemplateCache,
) -> Result<DecodedMessage, DecodeError> {
    let header = MessageHeader::parse(input)?;
    let body = &input[MESSAGE_HEADER_LEN..header.length as usize];

    let mut sets = Vec::new();
    let mut offset = 0usize;

    while offset < body.len() {
        let remaining = &body[offset..];
        if remaining.len() < SET_HEADER_LEN {
            // Fewer than 4 bytes left can't be a Set Header; treat as
            // trailing padding rather than an error.
            break;
        }

        let set_id = u16::from_be_bytes([remaining[0], remaining[1]]);
        let set_len = u16::from_be_bytes([remaining[2], remaining[3]]);

        if (set_len as usize) < SET_HEADER_LEN {
            return Err(DecodeError::SetTooShortForHeader { declared: set_len });
        }
        if set_len as usize > remaining.len() {
            return Err(DecodeError::SetLengthExceedsMessage {
                declared: set_len,
                available: remaining.len(),
            });
        }

        let set_body = &remaining[SET_HEADER_LEN..set_len as usize];

        let decoded = match set_id {
            TEMPLATE_SET_ID => {
                let parsed = parse_template_records(set_body, templates, false)?;
                DecodedSet::Templates(parsed)
            }
            OPTIONS_TEMPLATE_SET_ID => {
                let parsed = parse_template_records(set_body, templates, true)?;
                DecodedSet::OptionsTemplates(parsed)
            }
            id if id < MIN_DATA_SET_ID => DecodedSet::ReservedSetId { set_id: id },
            template_id => match templates.get(template_id).cloned() {
                Some(template) => {
                    let records = decode_data_set(&template, set_body)?;
                    if template.scope_field_count > 0 {
                        for record in &records {
                            templates.observe_options_data(record);
                        }
                    }
                    DecodedSet::Data {
                        template_id,
                        records,
                    }
                }
                None => DecodedSet::UnknownTemplate { template_id },
            },
        };

        sets.push(decoded);
        offset += set_len as usize;
    }

    Ok(DecodedMessage { header, sets })
}

fn parse_template_records(
    set_body: &[u8],
    templates: &mut TemplateCache,
    is_options: bool,
) -> Result<Vec<Template>, DecodeError> {
    let mut parsed = Vec::new();
    let mut offset = 0usize;

    while offset < set_body.len() {
        if set_body.len() - offset < SET_HEADER_LEN {
            break; // trailing padding, shorter than any valid template record header
        }
        let (template, consumed) = if is_options {
            Template::parse_options_template_record(&set_body[offset..])?
        } else {
            Template::parse_template_record(&set_body[offset..])?
        };
        offset += consumed;
        // RFC 7011 §8.1: a record with no fields withdraws its template;
        // template ID 2 (or 3, for Options Templates) withdraws them all.
        // It was cached as a template of zero fields until Phase 9D, and
        // a Data Set for it then decoded empty records without end.
        if template.fields.is_empty() {
            match template.template_id {
                TEMPLATE_SET_ID | OPTIONS_TEMPLATE_SET_ID => templates.clear(),
                template_id => templates.remove(template_id),
            }
            continue;
        }
        if template.min_record_len() == 0 {
            return Err(DecodeError::ZeroLengthTemplate {
                template_id: template.template_id,
            });
        }
        templates.insert(template.clone())?;
        parsed.push(template);
    }

    Ok(parsed)
}

fn decode_data_set(template: &Template, set_body: &[u8]) -> Result<Vec<DataRecord>, DecodeError> {
    let min_len = template.min_record_len().max(1);
    let mut records = Vec::new();
    let mut offset = 0usize;

    while offset < set_body.len() {
        if set_body.len() - offset < min_len {
            break; // trailing padding, too short to be another record
        }
        let (record, consumed) = crate::record::decode_data_record(template, &set_body[offset..])?;
        if consumed == 0 {
            return Err(DecodeError::EmptyDataRecord {
                template_id: template.template_id,
            });
        }
        offset += consumed;
        records.push(record);
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_header_bytes(length: u16, observation_domain_id: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x000au16.to_be_bytes());
        b.extend_from_slice(&length.to_be_bytes());
        b.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&observation_domain_id.to_be_bytes());
        b
    }

    fn template_set_bytes(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&template_id.to_be_bytes());
        record.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        for (ie, len) in fields {
            record.extend_from_slice(&ie.to_be_bytes());
            record.extend_from_slice(&len.to_be_bytes());
        }

        let mut set = Vec::new();
        set.extend_from_slice(&TEMPLATE_SET_ID.to_be_bytes());
        set.extend_from_slice(&((SET_HEADER_LEN + record.len()) as u16).to_be_bytes());
        set.extend_from_slice(&record);
        set
    }

    fn data_set_bytes(template_id: u16, record_bytes: &[u8]) -> Vec<u8> {
        let mut set = Vec::new();
        set.extend_from_slice(&template_id.to_be_bytes());
        set.extend_from_slice(&((SET_HEADER_LEN + record_bytes.len()) as u16).to_be_bytes());
        set.extend_from_slice(record_bytes);
        set
    }

    #[test]
    fn decodes_a_message_with_a_template_set_then_a_data_set_across_two_packets() {
        let mut cache = TemplateCache::new();

        // Packet 1: template definition only.
        let tmpl_set = template_set_bytes(256, &[(8, 4), (12, 4)]);
        let mut msg1 = message_header_bytes((MESSAGE_HEADER_LEN + tmpl_set.len()) as u16, 7);
        msg1.extend_from_slice(&tmpl_set);

        let decoded1 = decode_message(&msg1, &mut cache).unwrap();
        assert_eq!(decoded1.sets.len(), 1);
        assert!(matches!(decoded1.sets[0], DecodedSet::Templates(_)));
        assert!(cache.contains(256));

        // Packet 2: a data set using the now-known template.
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[192, 168, 1, 1]);
        record_bytes.extend_from_slice(&[192, 168, 1, 2]);
        let data_set = data_set_bytes(256, &record_bytes);
        let mut msg2 = message_header_bytes((MESSAGE_HEADER_LEN + data_set.len()) as u16, 7);
        msg2.extend_from_slice(&data_set);

        let decoded2 = decode_message(&msg2, &mut cache).unwrap();
        assert_eq!(decoded2.sets.len(), 1);
        match &decoded2.sets[0] {
            DecodedSet::Data {
                template_id,
                records,
            } => {
                assert_eq!(*template_id, 256);
                assert_eq!(records.len(), 1);
                assert_eq!(
                    records[0].fields[0].as_ipv4(),
                    Some(std::net::Ipv4Addr::new(192, 168, 1, 1))
                );
            }
            other => panic!("expected Data set, got {other:?}"),
        }
    }

    #[test]
    fn reports_unknown_template_instead_of_erroring() {
        let mut cache = TemplateCache::new();
        let data_set = data_set_bytes(999, &[1, 2, 3, 4]);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + data_set.len()) as u16, 7);
        msg.extend_from_slice(&data_set);

        let decoded = decode_message(&msg, &mut cache).unwrap();
        assert_eq!(
            decoded.sets[0],
            DecodedSet::UnknownTemplate { template_id: 999 }
        );
    }

    #[test]
    fn decodes_multiple_records_packed_in_one_data_set() {
        let mut cache = TemplateCache::new();
        cache
            .insert(Template {
                template_id: 300,
                scope_field_count: 0,
                fields: vec![crate::template::FieldSpecifier {
                    information_element_id: 1,
                    field_length: 4,
                    enterprise_number: None,
                }],
            })
            .unwrap();

        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&10u32.to_be_bytes());
        record_bytes.extend_from_slice(&20u32.to_be_bytes());
        record_bytes.extend_from_slice(&30u32.to_be_bytes());
        let data_set = data_set_bytes(300, &record_bytes);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + data_set.len()) as u16, 7);
        msg.extend_from_slice(&data_set);

        let decoded = decode_message(&msg, &mut cache).unwrap();
        match &decoded.sets[0] {
            DecodedSet::Data { records, .. } => assert_eq!(records.len(), 3),
            other => panic!("expected Data set, got {other:?}"),
        }
    }

    #[test]
    fn reserved_set_id_is_reported_not_errored() {
        let mut cache = TemplateCache::new();
        let mut set = Vec::new();
        set.extend_from_slice(&5u16.to_be_bytes()); // reserved (4-255)
        set.extend_from_slice(&8u16.to_be_bytes());
        set.extend_from_slice(&[0, 0, 0, 0]);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + set.len()) as u16, 7);
        msg.extend_from_slice(&set);

        let decoded = decode_message(&msg, &mut cache).unwrap();
        assert_eq!(decoded.sets[0], DecodedSet::ReservedSetId { set_id: 5 });
    }

    #[test]
    fn rejects_set_length_exceeding_message() {
        let mut cache = TemplateCache::new();
        let mut set = Vec::new();
        set.extend_from_slice(&2u16.to_be_bytes());
        set.extend_from_slice(&9000u16.to_be_bytes()); // way bigger than the message
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + set.len()) as u16, 7);
        msg.extend_from_slice(&set);

        assert!(decode_message(&msg, &mut cache).is_err());
    }

    #[test]
    fn options_template_data_populates_sampling_info() {
        let mut cache = TemplateCache::new();

        // Options template: 1 scope field (ingressInterface, IE 10), 1
        // regular field (samplingInterval, IE 34).
        let mut record = Vec::new();
        record.extend_from_slice(&400u16.to_be_bytes()); // template_id
        record.extend_from_slice(&2u16.to_be_bytes()); // field_count
        record.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count
        record.extend_from_slice(&10u16.to_be_bytes());
        record.extend_from_slice(&4u16.to_be_bytes());
        record.extend_from_slice(&34u16.to_be_bytes());
        record.extend_from_slice(&4u16.to_be_bytes());

        let mut opt_set = Vec::new();
        opt_set.extend_from_slice(&OPTIONS_TEMPLATE_SET_ID.to_be_bytes());
        opt_set.extend_from_slice(&((SET_HEADER_LEN + record.len()) as u16).to_be_bytes());
        opt_set.extend_from_slice(&record);

        let mut msg1 = message_header_bytes((MESSAGE_HEADER_LEN + opt_set.len()) as u16, 7);
        msg1.extend_from_slice(&opt_set);
        decode_message(&msg1, &mut cache).unwrap();
        assert!(cache.contains(400));

        // Data set for that options template: interface=1, sampling=100.
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&100u32.to_be_bytes());
        let data_set = data_set_bytes(400, &data);
        let mut msg2 = message_header_bytes((MESSAGE_HEADER_LEN + data_set.len()) as u16, 7);
        msg2.extend_from_slice(&data_set);
        decode_message(&msg2, &mut cache).unwrap();

        assert_eq!(cache.sampling().sampling_interval, Some(100));
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut cache = TemplateCache::new();
        for len in 0..64 {
            let bytes = vec![0x42u8; len];
            let _ = decode_message(&bytes, &mut cache);
        }
    }

    /// The input the fuzzer found (Phase 9D): templates with no fields, then
    /// a Data Set for one of them. It used to decode empty records without
    /// end and allocate until the process ran out of memory.
    #[test]
    fn the_fuzzer_s_out_of_memory_input_ends() {
        let input: &[u8] = &[
            0x00, 0x0a, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x0a, 0x00, 0x2c, 0x00, 0x00, 0x3f, 0xbf,
            0x00, 0x00, 0xbf, 0x30,
        ];
        let mut cache = TemplateCache::new();
        let _ = decode_message(input, &mut cache);
        // A field-less record is a withdrawal: nothing is cached for 0xaa00.
        assert!(!cache.contains(0xaa00));
    }

    #[test]
    fn a_record_without_fields_withdraws_its_template() {
        let mut cache = TemplateCache::new();
        let define = template_set_bytes(300, &[(8, 4)]);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + define.len()) as u16, 1);
        msg.extend_from_slice(&define);
        decode_message(&msg, &mut cache).unwrap();
        assert!(cache.contains(300));

        let withdraw = template_set_bytes(300, &[]);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + withdraw.len()) as u16, 1);
        msg.extend_from_slice(&withdraw);
        let decoded = decode_message(&msg, &mut cache).unwrap();
        assert!(!cache.contains(300));
        assert!(matches!(&decoded.sets[0], DecodedSet::Templates(parsed) if parsed.is_empty()));

        // A Data Set for it is now an unknown template, not an endless loop.
        let data = data_set_bytes(300, &[0u8; 8]);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + data.len()) as u16, 1);
        msg.extend_from_slice(&data);
        let decoded = decode_message(&msg, &mut cache).unwrap();
        assert!(matches!(
            decoded.sets[0],
            DecodedSet::UnknownTemplate { template_id: 300 }
        ));
    }

    #[test]
    fn template_id_two_withdraws_every_template() {
        let mut cache = TemplateCache::new();
        for id in [300, 301] {
            let define = template_set_bytes(id, &[(8, 4)]);
            let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + define.len()) as u16, 1);
            msg.extend_from_slice(&define);
            decode_message(&msg, &mut cache).unwrap();
        }
        let withdraw_all = template_set_bytes(TEMPLATE_SET_ID, &[]);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + withdraw_all.len()) as u16, 1);
        msg.extend_from_slice(&withdraw_all);
        decode_message(&msg, &mut cache).unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn a_template_of_zero_length_records_is_refused() {
        let mut cache = TemplateCache::new();
        // Two fields, each fixed at length zero: records of no bytes.
        let define = template_set_bytes(302, &[(8, 0), (12, 0)]);
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + define.len()) as u16, 1);
        msg.extend_from_slice(&define);
        assert_eq!(
            decode_message(&msg, &mut cache).unwrap_err(),
            DecodeError::ZeroLengthTemplate { template_id: 302 }
        );
        assert!(!cache.contains(302));
    }

    /// One datagram can define thousands of templates. Past the cache's
    /// limit the message is refused, and what was cached stays bounded.
    #[test]
    fn a_message_of_too_many_templates_is_refused() {
        let mut cache = TemplateCache::new();
        let mut sets = Vec::new();
        for id in 0..=crate::MAX_TEMPLATES as u16 {
            sets.extend_from_slice(&template_set_bytes(256 + id, &[(8, 4)]));
        }
        let mut msg = message_header_bytes((MESSAGE_HEADER_LEN + sets.len()) as u16, 1);
        msg.extend_from_slice(&sets);
        let last = 256 + crate::MAX_TEMPLATES as u16;
        assert_eq!(
            decode_message(&msg, &mut cache).unwrap_err(),
            DecodeError::TemplateLimit { template_id: last }
        );
        assert_eq!(cache.len(), crate::MAX_TEMPLATES);
    }

    /// A template record that claims 65,535 fields in a few bytes is
    /// truncated, and reserves only what those bytes could hold.
    #[test]
    fn a_huge_field_count_in_a_short_record_is_truncated() {
        let mut record = Vec::new();
        record.extend_from_slice(&256u16.to_be_bytes());
        record.extend_from_slice(&u16::MAX.to_be_bytes());
        record.extend_from_slice(&[0, 8, 0, 4]);
        assert!(matches!(
            Template::parse_template_record(&record),
            Err(DecodeError::TemplateRecordTruncated { .. })
        ));
    }
}
