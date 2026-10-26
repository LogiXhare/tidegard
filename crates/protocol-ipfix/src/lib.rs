//! Clean-room IPFIX (RFC 7011, RFC 7012, RFC 7015) message decoder.
//!
//! Built entirely from the public IETF RFCs and the public IANA IPFIX
//! Information Elements registry — see docs/clean-room-boundary.md. No
//! proprietary source, configuration format, or documentation was
//! consulted or reproduced.
//!
//! # Scope (Phase 2)
//!
//! This crate decodes IPFIX message structure — headers, Template Sets,
//! Options Template Sets, and Data Sets — into typed Rust values. It
//! deliberately does **not** attempt to semantically interpret every
//! IANA-registered Information Element (there are hundreds); decoded
//! field values are exposed as raw bytes with small helpers
//! (`DecodedField::as_u64_be`, `as_ipv4`, `as_ipv6`) for callers that
//! know what they're looking at. Full IE semantic typing is a documented
//! known limitation, deferred to whichever phase first needs it (see
//! docs/roadmap.md).
//!
//! This crate is transport-agnostic: it has no knowledge of UDP sockets,
//! exporters, or multi-exporter template management. That's
//! `tidegard-collector`'s job — this crate exposes one
//! [`TemplateCache`] scoped to a single exporter's observation domain and
//! lets the caller own as many of those as it needs.

mod decoder;
mod error;
mod header;
mod record;
mod template;
mod template_cache;

pub use decoder::{decode_message, DecodedMessage, DecodedSet};
pub use error::DecodeError;
pub use header::{MessageHeader, IPFIX_VERSION, MESSAGE_HEADER_LEN};
pub use record::{decode_data_record, DataRecord, DecodedField};
pub use template::{FieldSpecifier, Template, VARIABLE_LENGTH};
pub use template_cache::{SamplingInfo, TemplateCache, MAX_TEMPLATES, MAX_TEMPLATE_FIELDS};

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The single most important safety property of this crate:
        /// no sequence of bytes, however malformed, ever causes a panic
        /// (index-out-of-range, integer overflow in debug builds, etc.).
        /// A crafted packet is allowed to be *rejected*
        /// (`Err(DecodeError)`); it must never take the collector process
        /// down. See docs/security-principles.md — parser safety against
        /// malformed/hostile input is this component's top threat.
        #[test]
        fn decode_message_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut cache = TemplateCache::new();
            let _ = decode_message(&bytes, &mut cache);
        }

        /// Same property, but seeded with a cache that already has a
        /// plausible-looking template installed, so more of the "data
        /// set" decode path gets exercised by the fuzzed bytes instead
        /// of every input bottoming out at "unknown template".
        #[test]
        fn decode_message_never_panics_with_a_known_template(
            bytes in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            let mut cache = TemplateCache::new();
            cache.insert(Template {
                template_id: 256,
                scope_field_count: 0,
                fields: vec![
                    FieldSpecifier { information_element_id: 8, field_length: 4, enterprise_number: None },
                    FieldSpecifier { information_element_id: 12, field_length: 4, enterprise_number: None },
                    FieldSpecifier { information_element_id: 11, field_length: VARIABLE_LENGTH, enterprise_number: None },
                ],
            }).unwrap();
            let _ = decode_message(&bytes, &mut cache);
        }

        /// Parsing a template record directly (the other main untrusted
        /// entry point besides the top-level message) must also never
        /// panic, independent of message/set framing.
        #[test]
        fn template_record_parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = Template::parse_template_record(&bytes);
            let _ = Template::parse_options_template_record(&bytes);
        }
    }
}
