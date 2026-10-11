//! Capacity bounds. Every collection on an incident is bounded; breaching
//! one returns a structured error before any mutation, except linked
//! evidence — see [`crate::evidence`], which stops growing but keeps
//! counting instead, matching the domain model's documented asymmetry.

pub const TITLE_MAX_LEN: usize = 200;
pub const DESCRIPTION_MAX_LEN: usize = 8_000;
pub const NOTE_BODY_MAX_LEN: usize = 16_000;
pub const NOTES_PER_INCIDENT_MAX: usize = 500;
pub const NOTE_REDACTION_REASON_MAX_LEN: usize = 500;
pub const TAGS_PER_INCIDENT_MAX: usize = 32;
pub const TAG_KEY_MAX_LEN: usize = 64;
pub const TAG_VALUE_MAX_LEN: usize = 256;
pub const AFFECTED_TARGETS_MAX: usize = 256;
pub const POLICY_REFS_MAX: usize = 64;

pub use crate::evidence::EVIDENCE_RETAINED_LIMIT;
pub use crate::timeline::TIMELINE_ENTRY_LIMIT;
