/// Errors that can occur while decoding an IPFIX message.
///
/// Every variant here corresponds to a case a hostile or simply broken
/// exporter can trigger by sending crafted bytes — this type exists
/// specifically so the collector never has to `panic!`/`unwrap()` on
/// untrusted input. See docs/security-principles.md (parser safety is
/// the top-listed threat for this component).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum DecodeError {
    #[error("input too short: need at least {needed} bytes, have {have}")]
    TooShort { needed: usize, have: usize },

    #[error("unsupported IPFIX version {0:#06x} (expected 0x000a)")]
    UnsupportedVersion(u16),

    #[error("message header declares length {declared}, which is shorter than the 16-byte header itself")]
    MessageTooShortForHeader { declared: u16 },

    #[error("message header declares length {declared}, but only {available} bytes were supplied")]
    MessageLengthExceedsInput { declared: u16, available: usize },

    #[error(
        "set header declares length {declared}, which is shorter than the 4-byte set header itself"
    )]
    SetTooShortForHeader { declared: u16 },

    #[error(
        "set header declares length {declared}, but only {available} bytes remain in the message"
    )]
    SetLengthExceedsMessage { declared: u16, available: usize },

    #[error("template set uses reserved set id {0} for a template/options-template body")]
    InvalidTemplateSetId(u16),

    #[error(
        "template record declares {declared} fields but only {available} bytes remain in the set"
    )]
    TemplateRecordTruncated { declared: u16, available: usize },

    #[error("options template record declares scope field count {scope} greater than total field count {total}")]
    InvalidScopeFieldCount { scope: u16, total: u16 },

    #[error("data set references template id {0}, which is in the reserved range (< 256)")]
    InvalidDataTemplateId(u16),

    #[error("data record for template {template_id} is truncated: needed at least {needed} more bytes, {available} remained")]
    DataRecordTruncated {
        template_id: u16,
        needed: usize,
        available: usize,
    },

    #[error("variable-length field encoding is truncated")]
    VariableLengthTruncated,

    /// A template whose records take no bytes (every field fixed at length
    /// zero). Decoding its Data Set could never advance, so it is refused
    /// where it is defined.
    #[error("template {template_id} defines records of zero length")]
    ZeroLengthTemplate { template_id: u16 },

    /// A Data Record that consumed no bytes. A guard: no template the
    /// decoder accepts can produce one, but a loop that does not advance
    /// must never be possible on untrusted input.
    #[error("a data record for template {template_id} consumed no bytes")]
    EmptyDataRecord { template_id: u16 },

    /// A template the exporter's cache has no room for (Phase 9D,
    /// ADR 0056): see `template_cache::MAX_TEMPLATES` and
    /// `MAX_TEMPLATE_FIELDS`.
    #[error("template {template_id} would take the exporter's template cache past its limit")]
    TemplateLimit { template_id: u16 },
}
