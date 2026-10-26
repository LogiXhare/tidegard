//! The database connection: the pool and startup migrations.
//!
//! **TLS (ADR 0023).** The pool comes from
//! `tidegard_incident_postgres::connect`: verified TLS with a CA file,
//! plaintext only for a loopback-only connection string, and the connection
//! string never echoed.
//!
//! **Migrations (ADR 0024).** Applied before any work starts, under a
//! session advisory lock, so several instances starting together apply
//! each migration once. An operator who runs migrations separately sets
//! `TIDEGARD_INCIDENT_MIGRATE=false`.

use deadpool_postgres::Pool;
use tidegard_incident_postgres::connect::ConnectError;
pub use tidegard_incident_postgres::connect::Transport;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::pool::acquire;

use crate::config::Config;

/// The advisory-lock key migrations run under: "wnm-mig" in ASCII, so it
/// is recognisable in `pg_locks` and unlikely to collide.
pub const MIGRATION_LOCK_KEY: i64 = 0x0077_6e6d_2d6d_6967;

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error(transparent)]
    Persist(#[from] PersistError),
    #[error("migrations failed: {0}")]
    Migration(String),
}

/// Builds the pool. Nothing connects yet: the first connection is opened
/// by the first use.
pub fn connect(config: &Config) -> Result<(Pool, Transport), DatabaseError> {
    Ok(tidegard_incident_postgres::connect::connect(
        &config.database_url,
        config.tls.as_ref(),
        config.pool,
    )?)
}

/// Applies pending migrations under [`MIGRATION_LOCK_KEY`]. Returns how
/// many were applied.
pub async fn migrate(pool: &Pool) -> Result<usize, DatabaseError> {
    let mut client = acquire(pool).await?;
    client
        .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map_err(PersistError::from)?;
    let applied = tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut **client)
        .await
        .map(|report| report.applied_migrations().len())
        .map_err(|error| DatabaseError::Migration(error.to_string()));
    // Released even when the run failed: the connection goes back to the
    // pool, and a held session lock would block every later start.
    let unlocked = client
        .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map_err(PersistError::from);
    let applied = applied?;
    unlocked?;
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DATABASE_URL_ENV_VAR;

    fn config(url: &str) -> Config {
        Config::from_lookup(|var| Ok((var == DATABASE_URL_ENV_VAR).then(|| url.to_string())))
            .unwrap()
    }

    #[test]
    fn the_configured_url_and_tls_reach_the_shared_connect() {
        let (_pool, transport) = connect(&config("host=localhost user=app")).unwrap();
        assert_eq!(transport, Transport::LoopbackPlaintext);
        assert!(matches!(
            connect(&config("host=db.example.net user=app")),
            Err(DatabaseError::Connect(ConnectError::TlsRequired))
        ));
    }
}
