//! The production incident identity generator: UUIDv7 (BQ-5, ADR 0019).
//!
//! `crates/incident` keeps `IncidentId` an opaque 16 bytes and never sees a
//! `uuid::Uuid`. This adapter owns the `uuid` dependency, as ADR 0019
//! requires, and replaces the domain's placeholder generator.
//!
//! An id is a version 7 UUID: a millisecond Unix timestamp, a counter that
//! keeps one generator's ids ordered within a millisecond, then random bits.
//! It uses only the `v7` feature ADR 0019 pinned: the counter is a
//! [`ContextV7`] held in a mutex, fed the system time, rather than
//! `Uuid::now_v7`, which needs the `std` feature.
//!
//! The embedded timestamp is when the id was generated. It is not a decision
//! time; ADR 0031's decisions use the database's `transaction_timestamp()`.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tidegard_incident::error::IncidentError;
use tidegard_incident::id::{IncidentGenerator, IncidentId};
use uuid::timestamp::context::ContextV7;
use uuid::{Timestamp, Uuid};

/// Generates UUIDv7 incident ids.
///
/// Like the domain's generators, it refuses rather than repeats: an id equal
/// to the last one this instance issued is returned as `CapacityExceeded`,
/// never handed out.
pub struct UuidV7IncidentGenerator {
    state: Mutex<State>,
}

struct State {
    context: ContextV7,
    last: Option<[u8; 16]>,
}

impl UuidV7IncidentGenerator {
    pub fn new() -> Self {
        UuidV7IncidentGenerator {
            state: Mutex::new(State {
                context: ContextV7::new(),
                last: None,
            }),
        }
    }
}

impl Default for UuidV7IncidentGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl IncidentGenerator for UuidV7IncidentGenerator {
    fn generate(&self) -> Result<IncidentId, IncidentError> {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            IncidentError::InternalInvariantViolation("the system clock is before 1970")
        })?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let timestamp = Timestamp::from_unix(
            &state.context,
            since_epoch.as_secs(),
            since_epoch.subsec_nanos(),
        );
        let bytes = *Uuid::new_v7(timestamp).as_bytes();
        if state.last == Some(bytes) {
            return Err(IncidentError::CapacityExceeded(
                "the UUIDv7 generator would repeat an id",
            ));
        }
        state.last = Some(bytes);
        Ok(IncidentId::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_version_7_and_print_as_the_uuid_does() {
        let id = UuidV7IncidentGenerator::new().generate().unwrap();
        let uuid = Uuid::from_bytes(id.as_bytes());
        assert_eq!(uuid.get_version_num(), 7);
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
        assert_eq!(id.to_canonical_string(), uuid.to_string());
    }

    #[test]
    fn one_generator_issues_strictly_increasing_ids() {
        let generator = UuidV7IncidentGenerator::new();
        let ids: Vec<IncidentId> = (0..10_000).map(|_| generator.generate().unwrap()).collect();
        assert!(
            ids.windows(2).all(|pair| pair[0] < pair[1]),
            "UUIDv7 ids from one generator sort in the order they were issued"
        );
    }
}
