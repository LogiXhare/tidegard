//! Incident identity.
//!
//! [`IncidentId`] is an opaque 16-byte value, chosen so that when
//! [ADR 0013](../../../docs/architecture/decisions/0013-incident-identity.md)'s
//! UUIDv7 dependency review lands in Milestone 5B, the `uuid` crate's
//! `Uuid::as_bytes() -> [u8; 16]` output can be handed to
//! [`IncidentId::from_bytes`] unchanged. Nothing about this type's public
//! API depends on the `uuid` crate today, and nothing about it will need
//! to change shape when that crate arrives — only [`IncidentGenerator`]'s
//! production implementation is expected to be replaced.
//!
//! Two identity concerns are kept deliberately apart:
//!
//! - **What the bytes are** — [`IncidentId`] itself: comparable, hashable,
//!   orderable, serializable, parseable. It carries no opinion about how
//!   it was produced.
//! - **How the bytes are produced** — [`IncidentGenerator`], a seam with
//!   one placeholder production implementation
//!   ([`PlaceholderIncidentGenerator`]) and one that is unmistakably
//!   test-only ([`TestIncidentGenerator`]). The placeholder is explicit
//!   about not being UUIDv7 and not being cryptographically unpredictable
//!   — see its own documentation — so nothing downstream can mistake it
//!   for the real thing.
//!
//! Neither `IncidentId` nor the number in [`crate::number`] is an
//! authentication credential or an authorization boundary. Knowing one
//! must never grant access to it — every read is authorized against the
//! caller's tenant and permissions.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::IncidentError;

/// An opaque, 16-byte incident identifier.
///
/// Canonical byte order matches RFC 4122's big-endian field layout — the
/// same order `uuid::Uuid::as_bytes()` returns — so a future switch to a
/// real UUIDv7 generator is a change to [`IncidentGenerator`]'s production
/// implementation only, never to this type or to anything that stores,
/// compares, or displays an `IncidentId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IncidentId([u8; 16]);

/// Why a string failed to parse as an [`IncidentId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IncidentIdParseError {
    #[error("incident id must be exactly 32 hex characters (with or without hyphens), got {0}")]
    WrongLength(usize),
    #[error("incident id contains a non-hex character")]
    InvalidHex,
}

impl IncidentId {
    /// Builds an id from raw canonical-order bytes. This is the only
    /// constructor a generator needs — production and test generators
    /// both bottom out here.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        IncidentId(bytes)
    }

    /// The raw canonical-order bytes.
    pub const fn as_bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Lowercase, hyphenated, UUID-shaped: `8 4 4 4 12` hex digits. Chosen
    /// so that when the underlying bytes genuinely are a UUIDv7 (post
    /// 5B), this string is indistinguishable from calling `.to_string()`
    /// on a real `uuid::Uuid` — the display format is not a second thing
    /// that has to change later.
    pub fn to_canonical_string(&self) -> String {
        let b = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }

    /// Parses the string form back into an id. Accepts hyphens or none;
    /// rejects anything else. Round trips with [`IncidentId::to_canonical_string`].
    pub fn parse(s: &str) -> Result<Self, IncidentIdParseError> {
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return Err(IncidentIdParseError::WrongLength(hex.len()));
        }
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let pair = &hex[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(pair, 16).map_err(|_| IncidentIdParseError::InvalidHex)?;
        }
        Ok(IncidentId(bytes))
    }
}

impl fmt::Display for IncidentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

impl Serialize for IncidentId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_canonical_string())
    }
}

impl<'de> Deserialize<'de> for IncidentId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        IncidentId::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Produces [`IncidentId`] values.
///
/// A seam so the production path and the test path can never be confused
/// for one another at the call site — a caller holds a
/// `&dyn IncidentGenerator` and has no way to tell which implementation
/// is behind it, which is exactly the point: the type system, not
/// discipline, is what keeps a test generator out of a production path.
pub trait IncidentGenerator: Send + Sync {
    /// Produces the next id, or `Err(CapacityExceeded)` if doing so would
    /// require repeating one already issued by this generator instance —
    /// checked before the counter moves, never after, so a caller never
    /// observes a duplicate `IncidentId`. See [`crate::error::IncidentError`].
    fn generate(&self) -> Result<IncidentId, IncidentError>;
}

/// The Phase 5A production generator.
///
/// **This is not UUIDv7 and is not cryptographically unpredictable.** It
/// exists so Milestone 5A can create incidents at all without the `uuid`
/// crate, which BQ-5 approved only conditionally and which
/// [ADR 0018](../../../docs/architecture/decisions/0018-phase5-dependency-selection.md)
/// has not yet cleared. It mixes a per-process salt (derived the same way
/// the detector's `seed_instance_id` is — process id, wall clock at
/// startup, and a heap address ASLR moves between runs) with a
/// process-local monotonic counter, then spreads the result across 16
/// bytes with a fixed-output mixing step. It is unique within one
/// process's lifetime and is not claimed to be unique across processes,
/// unpredictable, or stable across a restart.
///
/// Replacing this with a real `uuid::Uuid::now_v7()`-backed
/// implementation is the entire scope of the 5B follow-up: the trait, the
/// call sites, and `IncidentId` itself do not change.
pub struct PlaceholderIncidentGenerator {
    salt: u64,
    counter: AtomicU64,
}

impl PlaceholderIncidentGenerator {
    pub fn new() -> Self {
        PlaceholderIncidentGenerator {
            salt: process_salt(),
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for PlaceholderIncidentGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentGenerator for PlaceholderIncidentGenerator {
    fn generate(&self) -> Result<IncidentId, IncidentError> {
        // A checked increment rather than `fetch_add`: `fetch_add` wraps
        // silently on overflow, which for an identity generator means
        // repeating a byte-for-byte identical `IncidentId` — a real
        // collision in `self.incidents`, not a display artifact. The
        // checked increment refuses instead, leaving the counter
        // untouched, so the next call refuses again rather than ever
        // handing out a duplicate.
        let seq = checked_increment(&self.counter).ok_or(IncidentError::CapacityExceeded(
            "incident identity counter exhausted",
        ))?;
        Ok(IncidentId::from_bytes(mix(self.salt, seq)))
    }
}

/// Adds one and returns the previous value, or `None`, leaving the
/// counter as it was, when it is already at `u64::MAX`. A compare-and-swap
/// loop: `fetch_update`, which did this, is deprecated on current stable in
/// favour of `try_update`, which older toolchains lack.
fn checked_increment(counter: &AtomicU64) -> Option<u64> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(previous) => return Some(previous),
            Err(actual) => current = actual,
        }
    }
}

/// A generator whose name states plainly what it is for.
///
/// Produces strictly increasing, fully reproducible ids from a starting
/// seed — useful for asserting exact values in a test — and is not
/// wired into any production code path in this crate. A caller that
/// wants a deterministic-but-realistic id for a property test should
/// still prefer [`IncidentId::from_bytes`] directly with values the test
/// controls end to end.
pub struct TestIncidentGenerator {
    counter: AtomicU64,
}

impl TestIncidentGenerator {
    pub fn starting_at(seed: u64) -> Self {
        TestIncidentGenerator {
            counter: AtomicU64::new(seed),
        }
    }
}

impl IncidentGenerator for TestIncidentGenerator {
    fn generate(&self) -> Result<IncidentId, IncidentError> {
        let seq = checked_increment(&self.counter).ok_or(IncidentError::CapacityExceeded(
            "test incident identity counter exhausted",
        ))?;
        let mut bytes = [0u8; 16];
        bytes[8..16].copy_from_slice(&seq.to_be_bytes());
        Ok(IncidentId::from_bytes(bytes))
    }
}

/// Deterministic 64-to-128-bit spread, good enough to avoid trivial
/// collisions between a salt and a small counter without pulling in a
/// hashing dependency. Not claimed to be cryptographically strong.
fn mix(salt: u64, seq: u64) -> [u8; 16] {
    let a = salt ^ seq.rotate_left(17).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let b = seq ^ salt.rotate_left(29).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&a.to_be_bytes());
    bytes[8..16].copy_from_slice(&b.to_be_bytes());
    bytes
}

fn process_salt() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut acc = std::process::id() as u64;
    acc ^= SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let probe = Box::new(0u8);
    acc ^= (Box::as_ref(&probe) as *const u8 as usize) as u64;
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_canonical_string() {
        let id = IncidentId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let s = id.to_canonical_string();
        assert_eq!(s, "01020304-0506-0708-090a-0b0c0d0e0f10");
        assert_eq!(IncidentId::parse(&s).unwrap(), id);
    }

    #[test]
    fn parses_without_hyphens_too() {
        let id = IncidentId::from_bytes([0xab; 16]);
        let compact = "ab".repeat(16);
        assert_eq!(IncidentId::parse(&compact).unwrap(), id);
    }

    #[test]
    fn rejects_the_wrong_length() {
        assert_eq!(
            IncidentId::parse("deadbeef"),
            Err(IncidentIdParseError::WrongLength(8))
        );
    }

    #[test]
    fn rejects_non_hex() {
        let bad = "zz".repeat(16);
        assert_eq!(
            IncidentId::parse(&bad),
            Err(IncidentIdParseError::InvalidHex)
        );
    }

    #[test]
    fn serializes_as_its_canonical_string() {
        let id = IncidentId::from_bytes([0x11; 16]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.to_canonical_string()));
        let back: IncidentId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn the_placeholder_generator_never_repeats_within_one_instance() {
        let gen = PlaceholderIncidentGenerator::new();
        let ids: std::collections::BTreeSet<IncidentId> =
            (0..1000).map(|_| gen.generate().unwrap()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn two_placeholder_generators_do_not_share_a_salt() {
        let a = PlaceholderIncidentGenerator::new();
        let b = PlaceholderIncidentGenerator::new();
        assert_ne!(a.generate().unwrap(), b.generate().unwrap());
    }

    #[test]
    fn the_test_generator_is_strictly_increasing_and_reproducible() {
        let gen = TestIncidentGenerator::starting_at(7);
        let first = gen.generate().unwrap();
        let second = gen.generate().unwrap();
        assert_ne!(first, second);

        let replay = TestIncidentGenerator::starting_at(7);
        assert_eq!(replay.generate().unwrap(), first);
        assert_eq!(replay.generate().unwrap(), second);
    }

    /// The regression this crate's `version` overflow handling already
    /// covers for a different counter: an identity generator at the very
    /// edge of its counter space must refuse rather than repeat. Seeded
    /// one below `u64::MAX` so the first call consumes the last
    /// representable value and the second call must refuse instead of
    /// wrapping back to an id it already issued.
    #[test]
    fn the_test_generator_refuses_rather_than_repeats_at_counter_exhaustion() {
        let gen = TestIncidentGenerator::starting_at(u64::MAX - 1);
        let last = gen.generate().unwrap();
        let refused = gen.generate();
        assert_eq!(
            refused,
            Err(IncidentError::CapacityExceeded(
                "test incident identity counter exhausted"
            ))
        );
        // Confirms it truly refused rather than silently wrapping back to
        // an id already issued.
        assert_ne!(Ok(last), refused);
    }

    #[test]
    fn ordering_is_byte_lexicographic() {
        let low = IncidentId::from_bytes([0x00; 16]);
        let high = IncidentId::from_bytes([0xff; 16]);
        assert!(low < high);
    }
}
