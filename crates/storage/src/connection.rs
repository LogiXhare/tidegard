//! How the collector reaches ClickHouse (ADR 0053): a user and a password
//! from a file, and TLS verified against a configured CA bundle whenever
//! the server is not on this machine. Plain HTTP reaches loopback only,
//! as for the API's connection (ADR 0042).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use tidegard_common::http_endpoint::{authority_url, is_loopback, parse_url, Scheme};

/// The same as the `clickhouse` crate's own client.
const TCP_KEEPALIVE: Duration = Duration::from_secs(60);
/// ClickHouse closes idle connections after 3 s; let ours go first.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

/// What the operator configured. Nothing here is secret: the password is
/// in the file `password_file` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClickHouseSettings {
    /// `http://host:port` (loopback only) or `https://host:port`.
    pub url: String,
    /// ClickHouse's own default when `None`.
    pub user: Option<String>,
    pub password_file: Option<PathBuf>,
    /// Required for `https://`.
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ClickHouse is misconfigured: {0}")]
pub struct ConnectionError(String);

impl ClickHouseSettings {
    /// Checks the settings without touching the network or any file, so
    /// a configuration mistake stops the collector at startup.
    pub fn validate(&self) -> Result<(Scheme, String, u16), ConnectionError> {
        let (scheme, host, port) = parse_url(self.url.trim()).map_err(ConnectionError)?;
        match scheme {
            Scheme::Http if !is_loopback(&host) => Err(ConnectionError(format!(
                "{host} is not a loopback host, so ClickHouse needs https:// and a CA bundle"
            ))),
            Scheme::Https if self.ca_file.is_none() => Err(ConnectionError(
                "https:// needs a CA bundle; none is configured".into(),
            )),
            _ => Ok((scheme, host, port)),
        }
    }

    /// The URL as the logs may show it: scheme, host and port only.
    pub fn display_url(&self) -> String {
        match self.validate() {
            Ok((scheme, host, port)) => authority_url(scheme, &host, port),
            Err(_) => "<invalid>".into(),
        }
    }

    /// Reads the password and the CA bundle, and builds the client.
    pub fn connect(&self) -> Result<clickhouse::Client, ConnectionError> {
        let (scheme, host, port) = self.validate()?;
        let client = match scheme {
            Scheme::Http => clickhouse::Client::default(),
            Scheme::Https => {
                let ca_file = self.ca_file.as_ref().expect("validate requires it");
                let config = tls_config(ca_file)?;
                let mut tcp = HttpConnector::new();
                tcp.set_keepalive(Some(TCP_KEEPALIVE));
                tcp.enforce_http(false);
                let https = hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(config)
                    .https_only()
                    .enable_http1()
                    .wrap_connector(tcp);
                let http = HyperClient::builder(TokioExecutor::new())
                    .pool_idle_timeout(POOL_IDLE_TIMEOUT)
                    .build(https);
                clickhouse::Client::with_http_client(http)
            }
        };
        let mut client = client.with_url(authority_url(scheme, &host, port));
        if let Some(user) = &self.user {
            client = client.with_user(user);
        }
        if let Some(path) = &self.password_file {
            let password = std::fs::read_to_string(path)
                .map_err(|error| ConnectionError(format!("{}: {error}", path.display())))?;
            client = client.with_password(password.trim_end_matches(['\r', '\n']));
        }
        Ok(client)
    }
}

fn tls_config(path: &std::path::Path) -> Result<rustls::ClientConfig, ConnectionError> {
    let setup = |detail: String| ConnectionError(format!("{}: {detail}", path.display()));
    let pem = std::fs::read(path).map_err(|error| setup(error.to_string()))?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem) {
        let certificate = certificate.map_err(|_| setup("not a PEM bundle".into()))?;
        roots
            .add(certificate)
            .map_err(|error| setup(error.to_string()))?;
    }
    if roots.is_empty() {
        return Err(setup("holds no certificates".into()));
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| setup(error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(url: &str, ca_file: Option<&str>) -> ClickHouseSettings {
        ClickHouseSettings {
            url: url.into(),
            user: Some("collector".into()),
            password_file: None,
            ca_file: ca_file.map(PathBuf::from),
        }
    }

    #[test]
    fn plain_http_reaches_loopback_only() {
        assert!(settings("http://127.0.0.1:8123", None).validate().is_ok());
        assert!(settings("http://[::1]:8123", None).validate().is_ok());
        let refused = settings("http://clickhouse:8123", None).validate();
        assert!(refused
            .unwrap_err()
            .to_string()
            .contains("not a loopback host"));
        assert!(settings("http://192.0.2.10:8123", Some("/ca.pem"))
            .validate()
            .is_err());
    }

    #[test]
    fn https_needs_a_ca_bundle() {
        let refused = settings("https://clickhouse:8443", None).validate();
        assert!(refused.unwrap_err().to_string().contains("CA bundle"));
        assert!(settings("https://clickhouse:8443", Some("/ca.pem"))
            .validate()
            .is_ok());
    }

    #[test]
    fn credentials_never_ride_in_the_url() {
        let refused = settings("http://user:secret@127.0.0.1:8123", None).validate();
        assert!(!refused.unwrap_err().to_string().contains("secret"));
    }

    #[test]
    fn logs_show_only_scheme_host_and_port() {
        assert_eq!(
            settings("https://clickhouse/", Some("/ca.pem")).display_url(),
            "https://clickhouse:8443"
        );
        assert_eq!(
            settings("http://user:secret@127.0.0.1", None).display_url(),
            "<invalid>"
        );
    }

    #[test]
    fn a_missing_or_empty_ca_bundle_is_refused() {
        let missing = settings("https://clickhouse:8443", Some("/no/such/ca.pem")).connect();
        assert!(missing.is_err());
        let empty = std::env::temp_dir().join(format!("wnm-empty-ca-{}.pem", std::process::id()));
        std::fs::write(&empty, "").unwrap();
        let refused = settings("https://clickhouse:8443", empty.to_str()).connect();
        std::fs::remove_file(&empty).unwrap();
        let error = refused.err().expect("an empty bundle is refused");
        assert!(error.to_string().contains("holds no certificates"));
    }
}
