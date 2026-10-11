//! Retention jobs for the retention table in
//! `docs/architecture/incident-persistence.md`.
//!
//! [`run_retention`] deletes each class of row that is past its retention
//! and reports how many it deleted. Nothing here runs on a schedule; a later
//! milestone decides when to call it. These are platform maintenance jobs
//! that span every tenant, so they take a [`PlatformAuthority`] (ADR 0032).
//!
//! Deliberately never purged:
//!
//! - **Audit.** Its retention is "24 months minimum", with no maximum.
//!   Deleting an incident does not touch audit rows either, because
//!   `incident_audit` has no foreign key to `incidents`.
//! - **Unreviewed dead-letter rows**, at any age: one that aged out
//!   silently would be an incident nobody knew was missed.
//! - **Incidents that are not closed.**
//!
//! A purged closed incident takes its timeline, notes, tags, policy
//! references, assignments and detection-event links with it (`ON DELETE
//! CASCADE`). These are engineering defaults, not a legal or regulatory
//! claim (FU-20).

use std::time::Duration;

use tokio_postgres::GenericClient;

use crate::error::PersistError;
use crate::outbox::micros;
use crate::platform::PlatformAuthority;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Closed incidents are kept this many calendar months after closing.
    pub closed_incident_months: i32,
    /// Published outbox rows are kept this long after publishing.
    pub published_outbox_age: Duration,
    /// Processed detection-event inbox rows are kept this long after
    /// processing (ADR 0035).
    pub processed_inbox_age: Duration,
    /// Reviewed dead-letter rows are kept this long after first being seen.
    pub reviewed_dead_letter_age: Duration,
}

impl RetentionPolicy {
    /// The retention table's defaults. Idempotency records need no age of
    /// their own here: each carries its `expires_at`.
    pub const fn engineering_default() -> Self {
        RetentionPolicy {
            closed_incident_months: 24,
            published_outbox_age: Duration::from_secs(7 * 24 * 60 * 60),
            processed_inbox_age: Duration::from_secs(7 * 24 * 60 * 60),
            reviewed_dead_letter_age: Duration::from_secs(90 * 24 * 60 * 60),
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::engineering_default()
    }
}

/// How many rows each job deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub expired_idempotency: u64,
    pub published_outbox: u64,
    pub processed_inbox: u64,
    pub reviewed_dead_letter: u64,
    pub closed_incidents: u64,
    /// Browser sessions past their absolute expiry (ADR 0043).
    pub expired_sessions: u64,
}

const PURGE_IDEMPOTENCY: &str =
    "DELETE FROM incident_idempotency WHERE expires_at <= transaction_timestamp()";

const PURGE_PUBLISHED_OUTBOX: &str = "\
DELETE FROM incident_outbox
WHERE status = 'published'
  AND published_at <= transaction_timestamp() - $1::bigint * interval '1 microsecond'";

const PURGE_PROCESSED_INBOX: &str = "\
DELETE FROM detection_event_inbox
WHERE status = 'processed'
  AND processed_at <= transaction_timestamp() - $1::bigint * interval '1 microsecond'";

const PURGE_REVIEWED_DEAD_LETTER: &str = "\
DELETE FROM incident_dead_letter
WHERE reviewed_at IS NOT NULL
  AND first_seen_at <= transaction_timestamp() - $1::bigint * interval '1 microsecond'";

const PURGE_CLOSED_INCIDENTS: &str = "\
DELETE FROM incidents
WHERE state = 'closed'
  AND closed_at <= transaction_timestamp() - make_interval(months => $1::integer)";

/// A session idle too long is already refused; it goes once its absolute
/// expiry passes, at most 12 hours after sign-in (ADR 0043).
const PURGE_EXPIRED_SESSIONS: &str =
    "DELETE FROM api_sessions WHERE expires_at <= transaction_timestamp()";

/// Runs every retention job once, each as its own statement.
pub async fn run_retention(
    _authority: &PlatformAuthority,
    client: &impl GenericClient,
    policy: &RetentionPolicy,
) -> Result<RetentionReport, PersistError> {
    if policy.closed_incident_months < 1 {
        return Err(PersistError::unrepresentable(
            "closed_incident_months",
            "must be at least one month",
        ));
    }
    Ok(RetentionReport {
        expired_idempotency: client.execute(PURGE_IDEMPOTENCY, &[]).await?,
        published_outbox: client
            .execute(
                PURGE_PUBLISHED_OUTBOX,
                &[&micros(policy.published_outbox_age)],
            )
            .await?,
        processed_inbox: client
            .execute(
                PURGE_PROCESSED_INBOX,
                &[&micros(policy.processed_inbox_age)],
            )
            .await?,
        reviewed_dead_letter: client
            .execute(
                PURGE_REVIEWED_DEAD_LETTER,
                &[&micros(policy.reviewed_dead_letter_age)],
            )
            .await?,
        closed_incidents: client
            .execute(PURGE_CLOSED_INCIDENTS, &[&policy.closed_incident_months])
            .await?,
        expired_sessions: client.execute(PURGE_EXPIRED_SESSIONS, &[]).await?,
    })
}
