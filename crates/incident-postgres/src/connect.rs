//! Building the pool from operator configuration (ADR 0023), shared by
//! every process that connects: the incident manager and the collector's
//! inbox producer.
//!
//! - **With a CA file**, every connection uses the verifying rustls
//!   connector, and anything off loopback must say `sslmode=require`.
//! - **Without one**, the connection string must reach only this host.
//!   Plaintext is never a silent fallback for a remote server. The caller
//!   logs which [`Transport`] it got.
//! - **The connection string is never echoed.** It can carry a password, so
//!   a parse error is reported without its text.

use std::path::{Path, PathBuf};

use deadpool_postgres::Pool;

use crate::error::PersistError;
use crate::pool::{build_pool, PoolPolicy};
use crate::tls::{build_tls_pool, is_loopback_only, ClientIdentity, TlsSettings};

/// Paths to operator-managed PEM files. None of them belongs in Git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    pub ca_file: PathBuf,
    /// Mutual TLS: the client certificate chain and its private key.
    pub client_identity: Option<(PathBuf, PathBuf)>,
}

impl TlsFiles {
    /// Assembles the TLS configuration from optional paths. `Ok(None)` when
    /// none is set; an error when the set is incomplete.
    pub fn from_paths(
        ca_file: Option<PathBuf>,
        client_cert: Option<PathBuf>,
        client_key: Option<PathBuf>,
    ) -> Result<Option<Self>, &'static str> {
        let client_identity = match (client_cert, client_key) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (None, None) => None,
            _ => return Err("a client certificate and its key must be set together"),
        };
        match (ca_file, client_identity) {
            (Some(ca_file), client_identity) => Ok(Some(TlsFiles {
                ca_file,
                client_identity,
            })),
            (None, None) => Ok(None),
            (None, Some(_)) => {
                Err("a client certificate needs a CA file to verify the server with")
            }
        }
    }
}

/// Whether the pool encrypts, for the startup log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    VerifiedTls,
    LoopbackPlaintext,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("the database connection string is not valid")]
    InvalidUrl,
    #[error("the database is not on this host, so TLS is required: configure a CA file")]
    TlsRequired,
    #[error("could not read {what} from {path}: {source}")]
    ReadFile {
        what: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Persist(#[from] PersistError),
}

/// Builds the pool. Nothing connects yet: the first connection is opened
/// by the first use.
pub fn connect(
    database_url: &str,
    tls: Option<&TlsFiles>,
    policy: PoolPolicy,
) -> Result<(Pool, Transport), ConnectError> {
    // The parse error is not shown: its text can quote the connection
    // string, password included.
    let pg_config: tokio_postgres::Config =
        database_url.parse().map_err(|_| ConnectError::InvalidUrl)?;
    match tls {
        Some(files) => {
            let settings = tls_settings(files)?;
            Ok((
                build_tls_pool(pg_config, &settings, policy)?,
                Transport::VerifiedTls,
            ))
        }
        None if is_loopback_only(&pg_config) => Ok((
            build_pool(pg_config, tokio_postgres::NoTls, policy)?,
            Transport::LoopbackPlaintext,
        )),
        None => Err(ConnectError::TlsRequired),
    }
}

fn tls_settings(files: &TlsFiles) -> Result<TlsSettings, ConnectError> {
    let read = |what: &'static str, path: &Path| {
        std::fs::read(path).map_err(|source| ConnectError::ReadFile {
            what,
            path: path.display().to_string(),
            source,
        })
    };
    let mut settings = TlsSettings::trusting(read("the CA bundle", &files.ca_file)?);
    if let Some((cert, key)) = &files.client_identity {
        settings.client_identity = Some(ClientIdentity {
            certificate_chain_pem: read("the client certificate", cert)?,
            private_key_pem: read("the client key", key)?,
        });
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PoolPolicy {
        PoolPolicy::starting_default()
    }

    #[test]
    fn loopback_without_tls_is_allowed_and_reported() {
        let (_pool, transport) = connect("host=localhost user=app", None, policy()).unwrap();
        assert_eq!(transport, Transport::LoopbackPlaintext);
    }

    #[test]
    fn a_remote_database_without_tls_is_refused() {
        for url in [
            "host=db.example.net user=app",
            "host=db.example.net user=app sslmode=require",
            "host=localhost hostaddr=10.0.0.5 user=app",
        ] {
            assert!(
                matches!(connect(url, None, policy()), Err(ConnectError::TlsRequired)),
                "{url}"
            );
        }
    }

    #[test]
    fn a_missing_ca_file_is_reported_with_its_path() {
        let tls = TlsFiles {
            ca_file: std::env::temp_dir().join("tidegard-missing-ca.pem"),
            client_identity: None,
        };
        let Err(error) = connect("host=db.example.net sslmode=require", Some(&tls), policy())
        else {
            panic!("a missing CA file must be refused");
        };
        assert!(matches!(error, ConnectError::ReadFile { .. }), "{error}");
        assert!(error.to_string().contains("tidegard-missing-ca.pem"));
    }

    #[test]
    fn an_invalid_url_never_echoes_its_text() {
        let Err(error) = connect("host=db password=hunter2 port=notaport", None, policy()) else {
            panic!("an unparseable port is refused");
        };
        assert!(matches!(error, ConnectError::InvalidUrl));
        assert!(!error.to_string().contains("hunter2"));
    }
}
