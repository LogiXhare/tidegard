//! Rerunning a call whose failure was transient (ADR 0034 § Retry,
//! ADR 0026).
//!
//! A retry reruns the whole load–run–flush from a fresh load, so a decision
//! is never flushed against state it was not made from. There are at most
//! [`RetryPolicy::max_attempts`] attempts, with exponential backoff and
//! jitter between them; after the last one the error is returned.
//!
//! What counts as transient, mapping ADR 0026's matrix onto what the flush
//! actually does:
//!
//! - `40001` serialization failure and `40P01` deadlock: always.
//! - `23505` on an active-incident partial unique index: a concurrent create
//!   won the race. The rerun links to that incident instead.
//! - `23505` on `incident_detection_events (tenant_id, dedup_key)`: the same
//!   event was ingested concurrently. ADR 0026 treats that as a duplicate,
//!   not an error, and the rerun is how the call reads it back and reports
//!   `Duplicate`.
//! - [`PersistError::IdempotencyKeyTaken`]: ADR 0026 reads the conflicting
//!   record back and classifies it per ADR 0016. The rerun loads it, and the
//!   domain replays it or reports the key reuse.
//! - [`PersistError::VersionConflict`] from the flush guard: the rerun lets
//!   the domain decide against the current version. An operator command with
//!   a stale `expected_version` then gets the domain's own `VersionConflict`,
//!   returned and never silently applied (ADR 0016).
//!
//! Everything else is returned at once: any other constraint violation, a
//! closed connection (a commit may or may not have landed, so a rerun could
//! apply the call twice), a mapping error, an unloaded lookup, or a broken
//! domain invariant. Domain errors are committed outcomes, not failures, so
//! they are never retried.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::Duration;

use tokio_postgres::error::SqlState;

use crate::error::PersistError;

/// The V10 partial unique indexes that allow one active incident per target.
const ACTIVE_INCIDENT_INDEXES: [&str; 3] = [
    "incidents_active_host",
    "incidents_active_network",
    "incidents_active_hostgroup",
];

/// PostgreSQL's default name for V3's `UNIQUE (tenant_id, dedup_key)`.
const DEDUP_CONSTRAINT: &str = "incident_detection_events_tenant_id_dedup_key_key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, the first included. Values below 1 behave as 1.
    pub max_attempts: u32,
    /// The backoff step before the second attempt, doubled for each later one.
    pub base_delay: Duration,
    /// No backoff step is longer than this.
    pub max_delay: Duration,
}

impl RetryPolicy {
    /// ADR 0026 and ADR 0034: at most 3 attempts.
    pub const fn approved_default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(200),
        }
    }

    /// Every failure is returned at once.
    pub const fn no_retries() -> Self {
        RetryPolicy {
            max_attempts: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    /// The pause after failed attempt `attempt` (1-based), before the next.
    pub fn delay_after(&self, attempt: u32) -> Duration {
        self.delay_with_entropy(attempt, RandomState::new().build_hasher().finish())
    }

    /// Equal jitter: half of the exponential step, plus a random share of
    /// the other half, so concurrent losers do not retry in lockstep.
    fn delay_with_entropy(&self, attempt: u32, entropy: u64) -> Duration {
        let exponent = attempt.saturating_sub(1).min(20);
        let step = self
            .base_delay
            .saturating_mul(1u32 << exponent)
            .min(self.max_delay);
        let half = step / 2;
        let spread = u64::try_from(half.as_micros()).unwrap_or(u64::MAX);
        half + Duration::from_micros(entropy % spread.saturating_add(1))
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::approved_default()
    }
}

impl PersistError {
    /// Whether rerunning the call from a fresh load may succeed. See the
    /// module doc.
    pub fn is_retryable(&self) -> bool {
        match self {
            PersistError::IdempotencyKeyTaken | PersistError::VersionConflict { .. } => true,
            PersistError::Database(error) => error
                .as_db_error()
                .is_some_and(|db| retryable_sqlstate(db.code(), db.constraint())),
            #[cfg(feature = "fault-injection")]
            PersistError::InjectedFault { transient, .. } => *transient,
            _ => false,
        }
    }
}

fn retryable_sqlstate(code: &SqlState, constraint: Option<&str>) -> bool {
    if *code == SqlState::T_R_SERIALIZATION_FAILURE || *code == SqlState::T_R_DEADLOCK_DETECTED {
        return true;
    }
    *code == SqlState::UNIQUE_VIOLATION
        && constraint
            .is_some_and(|name| name == DEDUP_CONSTRAINT || ACTIVE_INCIDENT_INDEXES.contains(&name))
}

#[cfg(test)]
mod tests {
    use tidegard_incident::id::{IncidentGenerator, TestIncidentGenerator};

    use super::*;

    #[test]
    fn serialization_failures_and_deadlocks_are_retryable() {
        assert!(retryable_sqlstate(
            &SqlState::T_R_SERIALIZATION_FAILURE,
            None
        ));
        assert!(retryable_sqlstate(&SqlState::T_R_DEADLOCK_DETECTED, None));
        assert!(!retryable_sqlstate(&SqlState::CHECK_VIOLATION, None));
        assert!(!retryable_sqlstate(&SqlState::FOREIGN_KEY_VIOLATION, None));
    }

    #[test]
    fn only_the_race_constraints_make_a_unique_violation_retryable() {
        for index in ACTIVE_INCIDENT_INDEXES {
            assert!(retryable_sqlstate(&SqlState::UNIQUE_VIOLATION, Some(index)));
        }
        assert!(retryable_sqlstate(
            &SqlState::UNIQUE_VIOLATION,
            Some(DEDUP_CONSTRAINT)
        ));
        for other in ["incidents_pkey", "incidents_tenant_id_incident_number_key"] {
            assert!(!retryable_sqlstate(
                &SqlState::UNIQUE_VIOLATION,
                Some(other)
            ));
        }
        assert!(!retryable_sqlstate(&SqlState::UNIQUE_VIOLATION, None));
    }

    #[test]
    fn non_database_failures_follow_the_matrix() {
        let incident_id = TestIncidentGenerator::starting_at(1).generate().unwrap();
        assert!(PersistError::IdempotencyKeyTaken.is_retryable());
        assert!(PersistError::VersionConflict {
            incident_id,
            loaded_version: 1
        }
        .is_retryable());
        assert!(!PersistError::DomainInvariant("broken").is_retryable());
        assert!(!PersistError::UnloadedLookup(Vec::new()).is_retryable());
        assert!(!PersistError::corrupt("state", "unknown").is_retryable());
        assert!(!PersistError::unrepresentable("updated_by", "platform").is_retryable());
    }

    #[test]
    fn backoff_grows_by_attempt_stays_bounded_and_jitters_within_its_step() {
        let policy = RetryPolicy::approved_default();
        assert_eq!(policy.delay_with_entropy(1, 0), Duration::from_millis(5));
        assert!(policy.delay_with_entropy(1, u64::MAX) <= Duration::from_millis(10));
        assert_eq!(policy.delay_with_entropy(2, 0), Duration::from_millis(10));
        for attempt in 1..40 {
            for entropy in [0, 1, 12_345, u64::MAX] {
                let delay = policy.delay_with_entropy(attempt, entropy);
                assert!(delay <= policy.max_delay, "attempt {attempt}: {delay:?}");
                assert!(
                    delay >= policy.base_delay / 2,
                    "attempt {attempt}: {delay:?}"
                );
            }
        }
        assert_eq!(RetryPolicy::no_retries().delay_after(1), Duration::ZERO);
    }
}
