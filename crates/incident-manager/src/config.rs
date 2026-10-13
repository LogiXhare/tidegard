//! Incident manager configuration.
//!
//! Plain environment variables, like the collector's, until the
//! Configuration Service exists (FR-15.1). An unparseable value is a
//! startup error, never a silent fallback to the default.
//!
//! The database connection string can carry a password, so neither it nor
//! anything derived from it is ever logged or put in an error message.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tidegard_incident_postgres::pool::PoolPolicy;

const DEFAULT_METRICS_BIND: &str = "0.0.0.0:9091";
const DEFAULT_WORKER_IDLE_MS: u64 = 1_000;
const DEFAULT_STATS_INTERVAL_SECS: u64 = 15;
const DEFAULT_MAINTENANCE_INTERVAL_SECS: u64 = 60;
const DEFAULT_RETENTION_INTERVAL_SECS: u64 = 3_600;

pub const DATABASE_URL_ENV_VAR: &str = "TIDEGARD_INCIDENT_DATABASE_URL";
pub const DATABASE_CA_FILE_ENV_VAR: &str = "TIDEGARD_INCIDENT_DATABASE_CA_FILE";
pub const DATABASE_CLIENT_CERT_FILE_ENV_VAR: &str = "TIDEGARD_INCIDENT_DATABASE_CLIENT_CERT_FILE";
pub const DATABASE_CLIENT_KEY_FILE_ENV_VAR: &str = "TIDEGARD_INCIDENT_DATABASE_CLIENT_KEY_FILE";
pub const POOL_MAX_SIZE_ENV_VAR: &str = "TIDEGARD_INCIDENT_POOL_MAX_SIZE";
pub const MIGRATE_ENV_VAR: &str = "TIDEGARD_INCIDENT_MIGRATE";
pub const METRICS_BIND_ENV_VAR: &str = "TIDEGARD_INCIDENT_METRICS_BIND";
pub const WORKER_ID_ENV_VAR: &str = "TIDEGARD_INCIDENT_WORKER_ID";
pub const WORKER_IDLE_MS_ENV_VAR: &str = "TIDEGARD_INCIDENT_WORKER_IDLE_MS";
pub const STATS_INTERVAL_SECS_ENV_VAR: &str = "TIDEGARD_INCIDENT_STATS_INTERVAL_SECS";
pub const MAINTENANCE_INTERVAL_SECS_ENV_VAR: &str = "TIDEGARD_INCIDENT_MAINTENANCE_INTERVAL_SECS";
pub const RETENTION_INTERVAL_SECS_ENV_VAR: &str = "TIDEGARD_INCIDENT_RETENTION_INTERVAL_SECS";

pub use tidegard_incident_postgres::connect::TlsFiles;

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// A libpq-style connection string. Never logged.
    pub database_url: String,
    /// `None` is allowed only for a loopback-only connection string; see
    /// [`crate::database`].
    pub tls: Option<TlsFiles>,
    pub pool: PoolPolicy,
    /// Apply pending migrations at startup, under an advisory lock.
    pub migrate: bool,
    pub metrics_bind: SocketAddr,
    /// Recorded in `locked_by` on claimed inbox rows. Two running
    /// processes must not share one (ADR 0033).
    pub worker_id: String,
    /// How long the worker waits after finding the inbox empty.
    pub worker_idle: Duration,
    /// How often the inbox and outbox depth gauges are refreshed.
    pub stats_interval: Duration,
    /// How often the staleness sweep, recovery confirmation and automatic
    /// closure run.
    pub maintenance_interval: Duration,
    /// How often the retention jobs run.
    pub retention_interval: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("tls", &self.tls)
            .field("pool", &self.pool)
            .field("migrate", &self.migrate)
            .field("metrics_bind", &self.metrics_bind)
            .field("worker_id", &self.worker_id)
            .field("worker_idle", &self.worker_idle)
            .field("stats_interval", &self.stats_interval)
            .field("maintenance_interval", &self.maintenance_interval)
            .field("retention_interval", &self.retention_interval)
            .finish()
    }
}

impl Config {
    /// Reads the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| match tidegard_common::env::var(var) {
            Ok(value) => Ok(value),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidValue {
                var: var.to_string(),
                value: "<non-utf8>".to_string(),
                expected: "a UTF-8 string",
            }),
        })
    }

    /// Reads configuration through `lookup`, so tests need not touch the
    /// process environment.
    pub fn from_lookup(
        lookup: impl Fn(&str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let get = |var: &str| -> Result<Option<String>, ConfigError> {
            Ok(lookup(var)?.filter(|value| !value.trim().is_empty()))
        };

        let database_url = get(DATABASE_URL_ENV_VAR)?.ok_or(ConfigError::Missing {
            var: DATABASE_URL_ENV_VAR,
        })?;
        let tls = TlsFiles::from_paths(
            get(DATABASE_CA_FILE_ENV_VAR)?.map(PathBuf::from),
            get(DATABASE_CLIENT_CERT_FILE_ENV_VAR)?.map(PathBuf::from),
            get(DATABASE_CLIENT_KEY_FILE_ENV_VAR)?.map(PathBuf::from),
        )
        .map_err(|detail| ConfigError::Incomplete { detail })?;

        let default_pool = PoolPolicy::starting_default();
        let pool = PoolPolicy {
            max_size: parse(&get, POOL_MAX_SIZE_ENV_VAR, "a positive integer")?
                .unwrap_or(default_pool.max_size),
            ..default_pool
        };
        if pool.max_size == 0 {
            return Err(ConfigError::InvalidValue {
                var: POOL_MAX_SIZE_ENV_VAR.to_string(),
                value: "0".to_string(),
                expected: "a positive integer",
            });
        }

        let migrate = match get(MIGRATE_ENV_VAR)?.as_deref() {
            None => true,
            Some("true") | Some("1") => true,
            Some("false") | Some("0") => false,
            Some(other) => {
                return Err(ConfigError::InvalidValue {
                    var: MIGRATE_ENV_VAR.to_string(),
                    value: other.to_string(),
                    expected: "true or false",
                })
            }
        };

        let metrics_bind = parse(&get, METRICS_BIND_ENV_VAR, "a socket address")?
            .unwrap_or_else(|| DEFAULT_METRICS_BIND.parse().expect("valid default"));
        let worker_id = get(WORKER_ID_ENV_VAR)?.unwrap_or_else(default_worker_id);

        Ok(Config {
            database_url,
            tls,
            pool,
            migrate,
            metrics_bind,
            worker_id,
            worker_idle: Duration::from_millis(
                positive(&get, WORKER_IDLE_MS_ENV_VAR)?.unwrap_or(DEFAULT_WORKER_IDLE_MS),
            ),
            stats_interval: Duration::from_secs(
                positive(&get, STATS_INTERVAL_SECS_ENV_VAR)?.unwrap_or(DEFAULT_STATS_INTERVAL_SECS),
            ),
            maintenance_interval: Duration::from_secs(
                positive(&get, MAINTENANCE_INTERVAL_SECS_ENV_VAR)?
                    .unwrap_or(DEFAULT_MAINTENANCE_INTERVAL_SECS),
            ),
            retention_interval: Duration::from_secs(
                positive(&get, RETENTION_INTERVAL_SECS_ENV_VAR)?
                    .unwrap_or(DEFAULT_RETENTION_INTERVAL_SECS),
            ),
        })
    }
}

fn parse<T: std::str::FromStr>(
    get: &impl Fn(&str) -> Result<Option<String>, ConfigError>,
    var: &'static str,
    expected: &'static str,
) -> Result<Option<T>, ConfigError> {
    match get(var)? {
        None => Ok(None),
        Some(value) => value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| ConfigError::InvalidValue {
                var: var.to_string(),
                value,
                expected,
            }),
    }
}

/// An interval: zero would spin, so it is refused.
fn positive(
    get: &impl Fn(&str) -> Result<Option<String>, ConfigError>,
    var: &'static str,
) -> Result<Option<u64>, ConfigError> {
    match parse::<u64>(get, var, "a positive integer")? {
        Some(0) => Err(ConfigError::InvalidValue {
            var: var.to_string(),
            value: "0".to_string(),
            expected: "a positive integer",
        }),
        other => Ok(other),
    }
}

/// Unique per running process without operator input: the host name tells
/// containers apart (they often all run as PID 1), the PID and start time
/// tell restarts and co-located processes apart.
fn default_worker_id() -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string());
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    format!("incident-manager:{host}:{}:{started}", std::process::id())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{var} must be set")]
    Missing { var: &'static str },
    #[error("{var} is set to '{value}', which is not valid: expected {expected}")]
    InvalidValue {
        var: String,
        value: String,
        expected: &'static str,
    },
    #[error("incomplete TLS configuration: {detail}")]
    Incomplete { detail: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|var| Ok(env.get(var).cloned()))
    }

    const URL: (&str, &str) = (DATABASE_URL_ENV_VAR, "host=localhost user=app");

    #[test]
    fn defaults_apply_when_only_the_database_is_set() {
        let config = config(&[URL]).unwrap();
        assert_eq!(config.tls, None);
        assert!(config.migrate);
        assert_eq!(config.pool, PoolPolicy::starting_default());
        assert_eq!(config.metrics_bind, DEFAULT_METRICS_BIND.parse().unwrap());
        assert_eq!(config.maintenance_interval, Duration::from_secs(60));
        assert_eq!(config.retention_interval, Duration::from_secs(3_600));
        assert!(config.worker_id.starts_with("incident-manager:"));
    }

    #[test]
    fn the_database_url_is_required() {
        assert_eq!(
            config(&[]).unwrap_err(),
            ConfigError::Missing {
                var: DATABASE_URL_ENV_VAR
            }
        );
        assert!(config(&[(DATABASE_URL_ENV_VAR, "  ")]).is_err());
    }

    #[test]
    fn the_database_url_never_reaches_debug_output() {
        let config = config(&[(DATABASE_URL_ENV_VAR, "host=db password=hunter2")]).unwrap();
        assert!(!format!("{config:?}").contains("hunter2"));
    }

    #[test]
    fn tls_files_are_read_and_must_be_complete() {
        let full = config(&[
            URL,
            (DATABASE_CA_FILE_ENV_VAR, "/etc/ca.pem"),
            (DATABASE_CLIENT_CERT_FILE_ENV_VAR, "/etc/client.pem"),
            (DATABASE_CLIENT_KEY_FILE_ENV_VAR, "/etc/client.key"),
        ])
        .unwrap();
        let tls = full.tls.unwrap();
        assert_eq!(tls.ca_file, PathBuf::from("/etc/ca.pem"));
        assert!(tls.client_identity.is_some());

        assert!(matches!(
            config(&[URL, (DATABASE_CLIENT_CERT_FILE_ENV_VAR, "/etc/client.pem")]),
            Err(ConfigError::Incomplete { .. })
        ));
        assert!(matches!(
            config(&[
                URL,
                (DATABASE_CLIENT_CERT_FILE_ENV_VAR, "/etc/client.pem"),
                (DATABASE_CLIENT_KEY_FILE_ENV_VAR, "/etc/client.key"),
            ]),
            Err(ConfigError::Incomplete { .. })
        ));
    }

    #[test]
    fn bad_values_fail_loudly() {
        for (var, value) in [
            (POOL_MAX_SIZE_ENV_VAR, "0"),
            (POOL_MAX_SIZE_ENV_VAR, "many"),
            (MIGRATE_ENV_VAR, "yes"),
            (METRICS_BIND_ENV_VAR, "not-an-address"),
            (MAINTENANCE_INTERVAL_SECS_ENV_VAR, "0"),
            (WORKER_IDLE_MS_ENV_VAR, "-1"),
        ] {
            assert!(
                matches!(
                    config(&[URL, (var, value)]),
                    Err(ConfigError::InvalidValue { .. })
                ),
                "{var}={value}"
            );
        }
    }

    #[test]
    fn explicit_values_override_the_defaults() {
        let config = config(&[
            URL,
            (MIGRATE_ENV_VAR, "false"),
            (POOL_MAX_SIZE_ENV_VAR, "4"),
            (WORKER_ID_ENV_VAR, "manager-a"),
            (MAINTENANCE_INTERVAL_SECS_ENV_VAR, "5"),
        ])
        .unwrap();
        assert!(!config.migrate);
        assert_eq!(config.pool.max_size, 4);
        assert_eq!(config.worker_id, "manager-a");
        assert_eq!(config.maintenance_interval, Duration::from_secs(5));
    }
}
