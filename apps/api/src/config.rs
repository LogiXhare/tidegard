//! API configuration from environment variables, like the other services.
//! An unparseable value stops startup with the variable named. The
//! database connection string is never logged.

use std::net::SocketAddr;
use std::path::PathBuf;

use wetechinetmon_incident_postgres::connect::TlsFiles as DatabaseTlsFiles;
use wetechinetmon_incident_postgres::pool::PoolPolicy;

use crate::server::TlsFiles;

const DEFAULT_BIND: &str = "127.0.0.1:8080";

pub const BIND_ENV_VAR: &str = "WETECHINETMON_API_BIND";
pub const TLS_CERT_FILE_ENV_VAR: &str = "WETECHINETMON_API_TLS_CERT_FILE";
pub const TLS_KEY_FILE_ENV_VAR: &str = "WETECHINETMON_API_TLS_KEY_FILE";
pub const DATABASE_URL_ENV_VAR: &str = "WETECHINETMON_API_DATABASE_URL";
pub const DATABASE_CA_FILE_ENV_VAR: &str = "WETECHINETMON_API_DATABASE_CA_FILE";
pub const DATABASE_CLIENT_CERT_FILE_ENV_VAR: &str = "WETECHINETMON_API_DATABASE_CLIENT_CERT_FILE";
pub const DATABASE_CLIENT_KEY_FILE_ENV_VAR: &str = "WETECHINETMON_API_DATABASE_CLIENT_KEY_FILE";
pub const POOL_MAX_SIZE_ENV_VAR: &str = "WETECHINETMON_API_POOL_MAX_SIZE";
pub const TRAFFIC_TENANT_ENV_VAR: &str = "WETECHINETMON_API_TRAFFIC_TENANT";
pub const CLICKHOUSE_URL_ENV_VAR: &str = "WETECHINETMON_API_CLICKHOUSE_URL";
pub const CLICKHOUSE_USER_ENV_VAR: &str = "WETECHINETMON_API_CLICKHOUSE_USER";
pub const CLICKHOUSE_PASSWORD_FILE_ENV_VAR: &str = "WETECHINETMON_API_CLICKHOUSE_PASSWORD_FILE";
pub const CLICKHOUSE_CA_FILE_ENV_VAR: &str = "WETECHINETMON_API_CLICKHOUSE_CA_FILE";
const DEFAULT_CLICKHOUSE_USER: &str = "default";

/// Traffic for the one traffic tenant (ADR 0042).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficConfig {
    pub tenant: String,
    pub clickhouse: crate::clickhouse::Endpoint,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// Where the API listens. Loopback by default; anything else needs TLS.
    pub bind: SocketAddr,
    pub tls: Option<TlsFiles>,
    /// A libpq-style connection string. Never logged.
    pub database_url: String,
    pub database_tls: Option<DatabaseTlsFiles>,
    pub pool: PoolPolicy,
    /// Off unless both the traffic tenant and ClickHouse are set.
    pub traffic: Option<TrafficConfig>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("tls", &self.tls)
            .field("database_url", &"<redacted>")
            .field("database_tls", &self.database_tls)
            .field("pool", &self.pool)
            .field("traffic", &self.traffic)
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{var} must be set")]
    Missing { var: &'static str },
    #[error("{var} is set to '{value}', which is not valid: expected {expected}")]
    InvalidValue {
        var: &'static str,
        value: String,
        expected: &'static str,
    },
    #[error("incomplete TLS configuration: {detail}")]
    Incomplete { detail: &'static str },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Reads configuration through `lookup`, so tests need not touch the
    /// process environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |var: &str| lookup(var).filter(|value| !value.trim().is_empty());

        let bind = match get(BIND_ENV_VAR) {
            None => DEFAULT_BIND.parse().expect("valid default"),
            Some(value) => value
                .trim()
                .parse()
                .map_err(|_| ConfigError::InvalidValue {
                    var: BIND_ENV_VAR,
                    value,
                    expected: "a socket address such as 127.0.0.1:8080",
                })?,
        };
        let tls = match (get(TLS_CERT_FILE_ENV_VAR), get(TLS_KEY_FILE_ENV_VAR)) {
            (Some(cert), Some(key)) => Some(TlsFiles {
                certificate_chain: PathBuf::from(cert),
                private_key: PathBuf::from(key),
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError::Incomplete {
                    detail: "the API certificate and its key must be set together",
                })
            }
        };
        let database_url = get(DATABASE_URL_ENV_VAR).ok_or(ConfigError::Missing {
            var: DATABASE_URL_ENV_VAR,
        })?;
        let database_tls = DatabaseTlsFiles::from_paths(
            get(DATABASE_CA_FILE_ENV_VAR).map(PathBuf::from),
            get(DATABASE_CLIENT_CERT_FILE_ENV_VAR).map(PathBuf::from),
            get(DATABASE_CLIENT_KEY_FILE_ENV_VAR).map(PathBuf::from),
        )
        .map_err(|detail| ConfigError::Incomplete { detail })?;
        let default_pool = PoolPolicy::starting_default();
        let max_size = match get(POOL_MAX_SIZE_ENV_VAR) {
            None => default_pool.max_size,
            Some(value) => match value.trim().parse::<usize>() {
                Ok(size) if size > 0 => size,
                _ => {
                    return Err(ConfigError::InvalidValue {
                        var: POOL_MAX_SIZE_ENV_VAR,
                        value,
                        expected: "a positive integer",
                    })
                }
            },
        };
        let traffic = match (get(TRAFFIC_TENANT_ENV_VAR), get(CLICKHOUSE_URL_ENV_VAR)) {
            (None, None) => None,
            (Some(tenant), Some(url)) => {
                let (scheme, host, port) =
                    crate::clickhouse::parse_url(url.trim()).map_err(|_| {
                        ConfigError::InvalidValue {
                            var: CLICKHOUSE_URL_ENV_VAR,
                            value: url.clone(),
                            expected: "http://host:port or https://host:port",
                        }
                    })?;
                Some(TrafficConfig {
                    tenant: tenant.trim().to_string(),
                    clickhouse: crate::clickhouse::Endpoint {
                        scheme,
                        host,
                        port,
                        user: get(CLICKHOUSE_USER_ENV_VAR)
                            .map(|user| user.trim().to_string())
                            .unwrap_or_else(|| DEFAULT_CLICKHOUSE_USER.to_string()),
                        password_file: get(CLICKHOUSE_PASSWORD_FILE_ENV_VAR).map(PathBuf::from),
                        ca_file: get(CLICKHOUSE_CA_FILE_ENV_VAR).map(PathBuf::from),
                    },
                })
            }
            _ => {
                return Err(ConfigError::Incomplete {
                    detail: "the traffic tenant and the ClickHouse URL must be set together",
                })
            }
        };
        Ok(Config {
            bind,
            tls,
            database_url,
            database_tls,
            pool: PoolPolicy {
                max_size,
                ..default_pool
            },
            traffic,
        })
    }
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
        Config::from_lookup(|var| env.get(var).cloned())
    }

    const URL: (&str, &str) = (DATABASE_URL_ENV_VAR, "host=localhost password=hunter2");

    #[test]
    fn defaults_bind_loopback_without_tls() {
        let config = config(&[URL]).unwrap();
        assert_eq!(config.bind, DEFAULT_BIND.parse().unwrap());
        assert_eq!(config.tls, None);
        assert!(!format!("{config:?}").contains("hunter2"));
    }

    #[test]
    fn the_database_is_required_and_tls_files_come_in_pairs() {
        assert_eq!(
            config(&[]).unwrap_err(),
            ConfigError::Missing {
                var: DATABASE_URL_ENV_VAR
            }
        );
        assert!(matches!(
            config(&[URL, (TLS_CERT_FILE_ENV_VAR, "/etc/api.crt")]),
            Err(ConfigError::Incomplete { .. })
        ));
        let with_tls = config(&[
            URL,
            (BIND_ENV_VAR, "0.0.0.0:8443"),
            (TLS_CERT_FILE_ENV_VAR, "/etc/api.crt"),
            (TLS_KEY_FILE_ENV_VAR, "/etc/api.key"),
        ])
        .unwrap();
        assert_eq!(with_tls.bind.port(), 8443);
        assert!(with_tls.tls.is_some());
    }

    #[test]
    fn traffic_needs_both_its_tenant_and_clickhouse() {
        assert_eq!(config(&[URL]).unwrap().traffic, None);
        assert!(matches!(
            config(&[URL, (TRAFFIC_TENANT_ENV_VAR, "acme")]),
            Err(ConfigError::Incomplete { .. })
        ));
        assert!(matches!(
            config(&[URL, (CLICKHOUSE_URL_ENV_VAR, "http://127.0.0.1:8123")]),
            Err(ConfigError::Incomplete { .. })
        ));
        assert!(matches!(
            config(&[
                URL,
                (TRAFFIC_TENANT_ENV_VAR, "acme"),
                (CLICKHOUSE_URL_ENV_VAR, "http://user:pw@ch:8123")
            ]),
            Err(ConfigError::InvalidValue { .. })
        ));
        let traffic = config(&[
            URL,
            (TRAFFIC_TENANT_ENV_VAR, "acme"),
            (CLICKHOUSE_URL_ENV_VAR, "https://ch.example.net:8443"),
            (CLICKHOUSE_CA_FILE_ENV_VAR, "/etc/ch-ca.pem"),
        ])
        .unwrap()
        .traffic
        .unwrap();
        assert_eq!(traffic.tenant, "acme");
        assert_eq!(traffic.clickhouse.user, "default");
        assert_eq!(traffic.clickhouse.port, 8443);
    }

    #[test]
    fn bad_values_fail_loudly() {
        for (var, value) in [(BIND_ENV_VAR, "everywhere"), (POOL_MAX_SIZE_ENV_VAR, "0")] {
            assert!(
                matches!(
                    config(&[URL, (var, value)]),
                    Err(ConfigError::InvalidValue { .. })
                ),
                "{var}={value}"
            );
        }
    }
}
