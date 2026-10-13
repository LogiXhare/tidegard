//! Errors from mapping incidents to rows and from the SQL that stores them.

use tidegard_incident::error::IncidentError;
use tidegard_incident::id::IncidentId;

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// The domain holds a value the schema has no column value for.
    #[error("{field} cannot be stored: {detail}")]
    Unrepresentable { field: &'static str, detail: String },

    /// A stored column holds something the domain cannot read.
    #[error("column {column} holds a value the domain cannot read: {detail}")]
    Corrupt {
        column: &'static str,
        detail: String,
    },

    /// Every column parsed, but the incident they describe is inconsistent.
    #[error("the stored incident failed reconstitution: {0}")]
    Rejected(#[source] IncidentError),

    /// The row is no longer at the version the call loaded, so another
    /// transaction changed it first (ADR 0034's flush guard).
    #[error("incident {incident_id} is no longer at version {loaded_version}")]
    VersionConflict {
        incident_id: IncidentId,
        loaded_version: u64,
    },

    /// The call looked up keys the load step never fetched, so its
    /// decision may rest on a false "absent" and was not flushed (ADR 0034).
    #[error("the call looked up {} key(s) the load step did not fetch", .0.len())]
    UnloadedLookup(Vec<crate::staging::UnloadedLookup>),

    /// The domain reported a broken internal invariant, so its in-memory
    /// changes may be partial and were not flushed.
    #[error("internal invariant violated: {0}")]
    DomainInvariant(&'static str),

    /// Another transaction recorded the same unexpired idempotency key
    /// first. Rerunning from a fresh load replays that record.
    #[error("the idempotency key was recorded concurrently by another request")]
    IdempotencyKeyTaken,

    /// A failure a test armed at a flush point ([`crate::fault`]). Only the
    /// `fault-injection` feature can produce it.
    #[cfg(feature = "fault-injection")]
    #[error("injected failure at {point:?} (transient: {transient})")]
    InjectedFault {
        point: crate::fault::FlushPoint,
        transient: bool,
    },

    /// No database connection was available in time: the pool was
    /// exhausted, or a connection could not be opened or verified (ADR
    /// 0022). Surfaced as unavailable (`503`) and not retried here.
    #[error("no database connection available: {0}")]
    Unavailable(String),

    /// The TLS configuration was refused before connecting: no usable
    /// trust anchors, an unreadable client identity, or a connection that
    /// could reach a non-loopback host without TLS (ADR 0023).
    #[error("TLS configuration refused: {0}")]
    TlsConfiguration(String),

    #[error("database error: {0}")]
    Database(#[from] tokio_postgres::Error),
}

impl PersistError {
    pub(crate) fn corrupt(column: &'static str, detail: impl Into<String>) -> Self {
        PersistError::Corrupt {
            column,
            detail: detail.into(),
        }
    }

    pub(crate) fn unrepresentable(field: &'static str, detail: impl Into<String>) -> Self {
        PersistError::Unrepresentable {
            field,
            detail: detail.into(),
        }
    }
}
