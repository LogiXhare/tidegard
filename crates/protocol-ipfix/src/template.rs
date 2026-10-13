use crate::error::DecodeError;

/// Marks a field specifier's length as variable — the actual length is
/// carried in-line in each data record instead (RFC 7011 §7).
pub const VARIABLE_LENGTH: u16 = 0xFFFF;

const ENTERPRISE_BIT: u16 = 0x8000;

/// One field specifier within a Template or Options Template record
/// (RFC 7011 §3.4.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpecifier {
    /// The Information Element ID with the enterprise bit already
    /// stripped — use `enterprise_number` to know whether this is an
    /// IANA-registered element or an enterprise-specific one.
    pub information_element_id: u16,
    /// Declared field length in octets, or `VARIABLE_LENGTH` (0xFFFF) if
    /// this field's actual length is carried per-record.
    pub field_length: u16,
    pub enterprise_number: Option<u32>,
}

impl FieldSpecifier {
    fn parse(input: &[u8]) -> Result<(Self, usize), DecodeError> {
        if input.len() < 4 {
            return Err(DecodeError::TemplateRecordTruncated {
                declared: 4,
                available: input.len(),
            });
        }
        let raw_id = u16::from_be_bytes([input[0], input[1]]);
        let field_length = u16::from_be_bytes([input[2], input[3]]);
        let has_enterprise = raw_id & ENTERPRISE_BIT != 0;
        let information_element_id = raw_id & !ENTERPRISE_BIT;

        if has_enterprise {
            if input.len() < 8 {
                return Err(DecodeError::TemplateRecordTruncated {
                    declared: 8,
                    available: input.len(),
                });
            }
            let enterprise_number = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
            let spec = FieldSpecifier {
                information_element_id,
                field_length,
                enterprise_number: Some(enterprise_number),
            };
            Ok((spec, 8))
        } else {
            let spec = FieldSpecifier {
                information_element_id,
                field_length,
                enterprise_number: None,
            };
            Ok((spec, 4))
        }
    }
}

/// A decoded Template Record or Options Template Record (RFC 7011 §3.4).
///
/// Both kinds share the same field-specifier layout on the wire; the
/// only difference is that an Options Template additionally declares how
/// many of its leading fields are "scope" fields. We model both with
/// this one type — `scope_field_count` is `0` for a regular (non-options)
/// template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub template_id: u16,
    /// `0` for a regular Template Record; > 0 for an Options Template
    /// Record, meaning the first `scope_field_count` entries in `fields`
    /// are scope fields (RFC 7011 §3.4.2.2).
    pub scope_field_count: u16,
    pub fields: Vec<FieldSpecifier>,
}

impl Template {
    /// The fixed portion of this template's record size in bytes — the
    /// sum of every field's declared length, treating any
    /// `VARIABLE_LENGTH` field as contributing 0 fixed bytes (its actual
    /// contribution is only known per-record, from the in-line length
    /// prefix).
    pub fn fixed_record_len(&self) -> usize {
        self.fields
            .iter()
            .map(|f| {
                if f.field_length == VARIABLE_LENGTH {
                    0
                } else {
                    f.field_length as usize
                }
            })
            .sum()
    }

    /// Whether any field in this template is variable-length, meaning
    /// `fixed_record_len` alone cannot be used to compute how many
    /// records fit in a data set of a given byte length.
    pub fn has_variable_length_fields(&self) -> bool {
        self.fields
            .iter()
            .any(|f| f.field_length == VARIABLE_LENGTH)
    }

    /// The smallest number of bytes a single record described by this
    /// template could possibly occupy: every fixed field's declared
    /// length, plus 1 byte per variable-length field (the minimum
    /// possible length-prefix, for a zero-length value). Used to tell
    /// "a few bytes of trailing set padding" apart from "the start of a
    /// record that's been truncated" when scanning a Data Set.
    pub fn min_record_len(&self) -> usize {
        self.fields
            .iter()
            .map(|f| {
                if f.field_length == VARIABLE_LENGTH {
                    1
                } else {
                    f.field_length as usize
                }
            })
            .sum()
    }

    /// Parses a single Template Record (`scope_field_count = 0`) from the
    /// start of `input`. Returns the parsed template and the number of
    /// bytes consumed, so callers can keep parsing subsequent records
    /// packed into the same Template Set.
    pub fn parse_template_record(input: &[u8]) -> Result<(Self, usize), DecodeError> {
        Self::parse_record(input, false)
    }

    /// Parses a single Options Template Record from the start of `input`.
    pub fn parse_options_template_record(input: &[u8]) -> Result<(Self, usize), DecodeError> {
        Self::parse_record(input, true)
    }

    fn parse_record(input: &[u8], is_options: bool) -> Result<(Self, usize), DecodeError> {
        let header_len = if is_options { 6 } else { 4 };
        if input.len() < header_len {
            return Err(DecodeError::TemplateRecordTruncated {
                declared: header_len as u16,
                available: input.len(),
            });
        }

        let template_id = u16::from_be_bytes([input[0], input[1]]);
        let field_count = u16::from_be_bytes([input[2], input[3]]);

        let (scope_field_count, mut offset) = if is_options {
            let scope = u16::from_be_bytes([input[4], input[5]]);
            if scope > field_count {
                return Err(DecodeError::InvalidScopeFieldCount {
                    scope,
                    total: field_count,
                });
            }
            (scope, 6)
        } else {
            (0, 4)
        };

        // At most what the bytes left can hold (four per specifier): a
        // record that claims 65,535 fields in a 20-byte set reserves no
        // more than five.
        let mut fields =
            Vec::with_capacity(usize::from(field_count).min((input.len() - offset) / 4));
        for _ in 0..field_count {
            let (spec, consumed) = FieldSpecifier::parse(&input[offset..])?;
            offset += consumed;
            fields.push(spec);
        }

        Ok((
            Template {
                template_id,
                scope_field_count,
                fields,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field_bytes(ie: u16, len: u16) -> [u8; 4] {
        let mut b = [0u8; 4];
        b[0..2].copy_from_slice(&ie.to_be_bytes());
        b[2..4].copy_from_slice(&len.to_be_bytes());
        b
    }

    #[test]
    fn parses_a_simple_template_record_two_fixed_fields() {
        // template_id=256, field_count=2, then two 4-byte field specs.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&256u16.to_be_bytes());
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&field_bytes(8, 4)); // sourceIPv4Address, 4 bytes
        bytes.extend_from_slice(&field_bytes(12, 4)); // destinationIPv4Address, 4 bytes

        let (tmpl, consumed) = Template::parse_template_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(tmpl.template_id, 256);
        assert_eq!(tmpl.scope_field_count, 0);
        assert_eq!(tmpl.fields.len(), 2);
        assert_eq!(tmpl.fields[0].information_element_id, 8);
        assert_eq!(tmpl.fields[0].field_length, 4);
        assert!(tmpl.fields[0].enterprise_number.is_none());
        assert_eq!(tmpl.fixed_record_len(), 8);
        assert!(!tmpl.has_variable_length_fields());
    }

    #[test]
    fn parses_a_field_with_enterprise_bit_set() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&300u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        // enterprise bit set on IE 100, length 4, enterprise number 12345
        bytes.extend_from_slice(&(100u16 | 0x8000).to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&12345u32.to_be_bytes());

        let (tmpl, consumed) = Template::parse_template_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(tmpl.fields[0].information_element_id, 100);
        assert_eq!(tmpl.fields[0].enterprise_number, Some(12345));
    }

    #[test]
    fn parses_a_variable_length_field() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&301u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&field_bytes(11, VARIABLE_LENGTH));

        let (tmpl, _) = Template::parse_template_record(&bytes).unwrap();
        assert!(tmpl.has_variable_length_fields());
        assert_eq!(tmpl.fixed_record_len(), 0);
        assert_eq!(tmpl.min_record_len(), 1);
    }

    #[test]
    fn parses_an_options_template_record_with_scope_fields() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&302u16.to_be_bytes()); // template_id
        bytes.extend_from_slice(&2u16.to_be_bytes()); // field_count
        bytes.extend_from_slice(&1u16.to_be_bytes()); // scope_field_count
        bytes.extend_from_slice(&field_bytes(10, 4)); // scope: ingressInterface
        bytes.extend_from_slice(&field_bytes(34, 4)); // samplingInterval

        let (tmpl, consumed) = Template::parse_options_template_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(tmpl.scope_field_count, 1);
        assert_eq!(tmpl.fields.len(), 2);
    }

    #[test]
    fn rejects_scope_field_count_greater_than_field_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&303u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes()); // field_count = 1
        bytes.extend_from_slice(&5u16.to_be_bytes()); // scope = 5, invalid
        bytes.extend_from_slice(&field_bytes(10, 4));

        assert_eq!(
            Template::parse_options_template_record(&bytes),
            Err(DecodeError::InvalidScopeFieldCount { scope: 5, total: 1 })
        );
    }

    #[test]
    fn rejects_truncated_field_specifier() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&304u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&[0x00, 0x08]); // only 2 bytes of a 4-byte field spec

        assert!(Template::parse_template_record(&bytes).is_err());
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        for len in 0..40 {
            let bytes = vec![0x77u8; len];
            let _ = Template::parse_template_record(&bytes);
            let _ = Template::parse_options_template_record(&bytes);
        }
    }
}
