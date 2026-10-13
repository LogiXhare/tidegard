use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::DecodeError;
use crate::template::{Template, VARIABLE_LENGTH};

/// One decoded field within a Data Record.
///
/// Phase 2 deliberately decodes into raw bytes rather than a fully typed
/// value per Information Element — Tidegard's IANA IE registry only
/// covers a small, commonly used subset today (see `crate::ie`). Callers
/// that know which IE they're looking at can use `as_u64_be`, `as_ipv4`,
/// or `as_ipv6` to interpret the bytes; full semantic typing for every
/// registered IE is deferred to whichever later phase first needs it
/// (tracked as a known limitation, not silently assumed complete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedField {
    pub information_element_id: u16,
    pub enterprise_number: Option<u32>,
    pub value: Vec<u8>,
}

impl DecodedField {
    /// Interprets `value` as a big-endian unsigned integer, for the
    /// common IPFIX convention of encoding integers in their minimal
    /// byte width (RFC 7011 §6.2). Returns `None` for empty or
    /// oversized (>8 byte) values rather than panicking.
    pub fn as_u64_be(&self) -> Option<u64> {
        if self.value.is_empty() || self.value.len() > 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[8 - self.value.len()..].copy_from_slice(&self.value);
        Some(u64::from_be_bytes(buf))
    }

    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        let bytes: [u8; 4] = self.value.as_slice().try_into().ok()?;
        Some(Ipv4Addr::from(bytes))
    }

    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        let bytes: [u8; 16] = self.value.as_slice().try_into().ok()?;
        Some(Ipv6Addr::from(bytes))
    }
}

/// One decoded Data Record, associated with the template that describes
/// its layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRecord {
    pub template_id: u16,
    pub fields: Vec<DecodedField>,
}

/// Reads one variable-length field's length prefix (RFC 7011 §7) from the
/// start of `input`, returning the declared length and the number of
/// prefix bytes consumed (1, or 3 if the one-byte escape `0xFF` is used).
fn read_variable_length_prefix(input: &[u8]) -> Result<(usize, usize), DecodeError> {
    match input.first() {
        None => Err(DecodeError::VariableLengthTruncated),
        Some(&first) if first != 0xFF => Ok((first as usize, 1)),
        Some(_) => {
            if input.len() < 3 {
                return Err(DecodeError::VariableLengthTruncated);
            }
            let len = u16::from_be_bytes([input[1], input[2]]) as usize;
            Ok((len, 3))
        }
    }
}

/// Decodes a single Data Record described by `template` from the start of
/// `input`. Returns the decoded record and the number of bytes consumed,
/// so callers can decode consecutive records packed into the same Data
/// Set.
pub fn decode_data_record(
    template: &Template,
    input: &[u8],
) -> Result<(DataRecord, usize), DecodeError> {
    let mut offset = 0usize;
    let mut fields = Vec::with_capacity(template.fields.len());

    for spec in &template.fields {
        let field_len = if spec.field_length == VARIABLE_LENGTH {
            let (len, prefix_len) =
                read_variable_length_prefix(&input[offset..]).map_err(|_| {
                    DecodeError::DataRecordTruncated {
                        template_id: template.template_id,
                        needed: 1,
                        available: input.len().saturating_sub(offset),
                    }
                })?;
            offset += prefix_len;
            len
        } else {
            spec.field_length as usize
        };

        if input.len() < offset + field_len {
            return Err(DecodeError::DataRecordTruncated {
                template_id: template.template_id,
                needed: field_len,
                available: input.len().saturating_sub(offset),
            });
        }

        let value = input[offset..offset + field_len].to_vec();
        offset += field_len;

        fields.push(DecodedField {
            information_element_id: spec.information_element_id,
            enterprise_number: spec.enterprise_number,
            value,
        });
    }

    Ok((
        DataRecord {
            template_id: template.template_id,
            fields,
        },
        offset,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::FieldSpecifier;

    fn fixed_template() -> Template {
        Template {
            template_id: 256,
            scope_field_count: 0,
            fields: vec![
                FieldSpecifier {
                    information_element_id: 8, // sourceIPv4Address
                    field_length: 4,
                    enterprise_number: None,
                },
                FieldSpecifier {
                    information_element_id: 12, // destinationIPv4Address
                    field_length: 4,
                    enterprise_number: None,
                },
                FieldSpecifier {
                    information_element_id: 2, // packetDeltaCount
                    field_length: 8,
                    enterprise_number: None,
                },
            ],
        }
    }

    #[test]
    fn decodes_a_fixed_length_record() {
        let template = fixed_template();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[10, 0, 0, 1]); // src ip
        bytes.extend_from_slice(&[10, 0, 0, 2]); // dst ip
        bytes.extend_from_slice(&42u64.to_be_bytes()); // packet count

        let (record, consumed) = decode_data_record(&template, &bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(record.template_id, 256);
        assert_eq!(record.fields[0].as_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(record.fields[1].as_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(record.fields[2].as_u64_be(), Some(42));
    }

    #[test]
    fn decodes_two_consecutive_fixed_records_from_one_set() {
        let template = fixed_template();
        let mut bytes = Vec::new();
        for i in 1..=2u8 {
            bytes.extend_from_slice(&[10, 0, 0, i]);
            bytes.extend_from_slice(&[10, 0, 1, i]);
            bytes.extend_from_slice(&(i as u64).to_be_bytes());
        }

        let (first, consumed1) = decode_data_record(&template, &bytes).unwrap();
        let (second, consumed2) = decode_data_record(&template, &bytes[consumed1..]).unwrap();
        assert_eq!(consumed1 + consumed2, bytes.len());
        assert_eq!(first.fields[0].as_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(second.fields[0].as_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn decodes_a_variable_length_field_short_form() {
        let template = Template {
            template_id: 500,
            scope_field_count: 0,
            fields: vec![FieldSpecifier {
                information_element_id: 11, // e.g. a variable-length string-ish field
                field_length: VARIABLE_LENGTH,
                enterprise_number: None,
            }],
        };
        let mut bytes = vec![3u8]; // length prefix = 3
        bytes.extend_from_slice(b"abc");

        let (record, consumed) = decode_data_record(&template, &bytes).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(record.fields[0].value, b"abc".to_vec());
    }

    #[test]
    fn decodes_a_variable_length_field_long_form() {
        let template = Template {
            template_id: 501,
            scope_field_count: 0,
            fields: vec![FieldSpecifier {
                information_element_id: 11,
                field_length: VARIABLE_LENGTH,
                enterprise_number: None,
            }],
        };
        let payload = vec![b'x'; 300];
        let mut bytes = vec![0xFF, 0x01, 0x2C]; // escape + length 300
        bytes.extend_from_slice(&payload);

        let (record, consumed) = decode_data_record(&template, &bytes).unwrap();
        assert_eq!(consumed, 3 + 300);
        assert_eq!(record.fields[0].value.len(), 300);
    }

    #[test]
    fn rejects_truncated_fixed_field() {
        let template = fixed_template();
        let bytes = vec![10, 0, 0, 1]; // only the first field's worth of bytes
        assert!(decode_data_record(&template, &bytes).is_err());
    }

    #[test]
    fn rejects_truncated_variable_length_prefix() {
        let template = Template {
            template_id: 502,
            scope_field_count: 0,
            fields: vec![FieldSpecifier {
                information_element_id: 11,
                field_length: VARIABLE_LENGTH,
                enterprise_number: None,
            }],
        };
        let bytes: Vec<u8> = vec![];
        assert!(decode_data_record(&template, &bytes).is_err());
    }

    #[test]
    fn never_panics_on_arbitrary_bytes_against_a_variable_length_template() {
        let template = Template {
            template_id: 503,
            scope_field_count: 0,
            fields: vec![
                FieldSpecifier {
                    information_element_id: 11,
                    field_length: VARIABLE_LENGTH,
                    enterprise_number: None,
                },
                FieldSpecifier {
                    information_element_id: 12,
                    field_length: 4,
                    enterprise_number: None,
                },
            ],
        };
        for len in 0..20 {
            let bytes = vec![0x03u8; len];
            let _ = decode_data_record(&template, &bytes);
        }
    }
}
