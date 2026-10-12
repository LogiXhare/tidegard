//! Read-only queries to ClickHouse over its HTTP interface (ADR 0042).
//!
//! - **No caller value is spliced into SQL.** Queries are fixed text with
//!   server-side parameters (`{from:UInt32}`), sent as `param_*`.
//! - **Every request is read-only and bounded:** `readonly=2`, a time
//!   limit, a row limit that throws, and a capped response size.
//! - **TLS off loopback**, verified against the configured CA bundle.
//!   Plain HTTP is accepted only for a loopback host.
//! - **The password is never logged** and travels as a sensitive header.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A query that takes longer is abandoned by the server.
pub const MAX_EXECUTION_SECONDS: u32 = 10;
/// More rows than this is an error, never a silently cut answer.
pub const MAX_RESULT_ROWS: u32 = 10_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

// Shared with the collector, so the plaintext rule is written once
// (ADR 0053).
pub use wetechinetmon_common::http_endpoint::{is_loopback, parse_url, Scheme};

/// Where ClickHouse is, and how to prove who we are.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password_file", &self.password_file)
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClickHouseError {
    /// The configuration cannot work; retrying will not help.
    #[error("ClickHouse is misconfigured: {0}")]
    Setup(String),
    /// ClickHouse could not be reached, or did not answer in time.
    #[error("ClickHouse is unreachable: {0}")]
    Unreachable(String),
    /// ClickHouse refused the query.
    #[error("ClickHouse refused a query with status {status}: {detail}")]
    Refused { status: u16, detail: String },
    /// The answer was not what the query promised.
    #[error("ClickHouse answered unreadably: {0}")]
    Unreadable(String),
}

/// A ClickHouse connection, set up once at startup.
pub struct ClickHouse {
    endpoint: Endpoint,
    password: Option<String>,
    tls: Option<TlsConnector>,
}

impl std::fmt::Debug for ClickHouse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClickHouse")
            .field("endpoint", &self.endpoint)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ClickHouse {
    /// Reads the password and the CA bundle, and refuses plaintext off
    /// loopback.
    pub fn new(endpoint: Endpoint) -> Result<Self, ClickHouseError> {
        let tls = match endpoint.scheme {
            Scheme::Http if is_loopback(&endpoint.host) => None,
            Scheme::Http => {
                return Err(ClickHouseError::Setup(format!(
                    "{} is not a loopback host, so ClickHouse needs https:// and a CA bundle",
                    endpoint.host
                )))
            }
            Scheme::Https => Some(connector(endpoint.ca_file.as_deref())?),
        };
        let password = match &endpoint.password_file {
            None => None,
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|error| {
                        ClickHouseError::Setup(format!("{}: {error}", path.display()))
                    })?
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            ),
        };
        Ok(ClickHouse {
            endpoint,
            password,
            tls,
        })
    }

    /// Runs `sql` with `params` bound server-side, and reads one `T` per
    /// row.
    pub async fn rows<T: DeserializeOwned>(
        &self,
        sql: &'static str,
        params: &[(&str, String)],
    ) -> Result<Vec<T>, ClickHouseError> {
        let body = tokio::time::timeout(REQUEST_TIMEOUT, self.send(sql, params))
            .await
            .map_err(|_| ClickHouseError::Unreachable("no answer in time".into()))??;
        let text = std::str::from_utf8(&body)
            .map_err(|_| ClickHouseError::Unreadable("not UTF-8".into()))?;
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .map_err(|error| ClickHouseError::Unreadable(error.to_string()))
            })
            .collect()
    }

    async fn send(
        &self,
        sql: &'static str,
        params: &[(&str, String)],
    ) -> Result<Bytes, ClickHouseError> {
        let request = self.request(sql, params)?;
        let unreachable = |error: std::io::Error| ClickHouseError::Unreachable(error.to_string());
        let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .map_err(unreachable)?;
        match &self.tls {
            None => exchange(TokioIo::new(tcp), request).await,
            Some(connector) => {
                let name = ServerName::try_from(self.endpoint.host.clone()).map_err(|_| {
                    ClickHouseError::Setup("the ClickHouse host is not a valid name".into())
                })?;
                let stream = connector.connect(name, tcp).await.map_err(unreachable)?;
                exchange(TokioIo::new(stream), request).await
            }
        }
    }

    fn request(
        &self,
        sql: &'static str,
        params: &[(&str, String)],
    ) -> Result<Request<Full<Bytes>>, ClickHouseError> {
        let mut query = vec![
            ("default_format".to_string(), "JSONEachRow".to_string()),
            ("readonly".to_string(), "2".to_string()),
            (
                "max_execution_time".to_string(),
                MAX_EXECUTION_SECONDS.to_string(),
            ),
            ("max_result_rows".to_string(), MAX_RESULT_ROWS.to_string()),
            ("result_overflow_mode".to_string(), "throw".to_string()),
            (
                "output_format_json_quote_64bit_integers".to_string(),
                "0".to_string(),
            ),
        ];
        query.extend(
            params
                .iter()
                .map(|(name, value)| (format!("param_{name}"), value.clone())),
        );
        let query_string = query
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name), encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let host = if self.endpoint.host.contains(':') {
            format!("[{}]:{}", self.endpoint.host, self.endpoint.port)
        } else {
            format!("{}:{}", self.endpoint.host, self.endpoint.port)
        };
        let setup = |error: hyper::http::Error| ClickHouseError::Setup(error.to_string());
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("/?{query_string}"))
            .header(HOST, host)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(
                "X-ClickHouse-User",
                HeaderValue::from_str(&self.endpoint.user)
                    .map_err(|_| ClickHouseError::Setup("the user is not a valid header".into()))?,
            );
        if let Some(password) = &self.password {
            let mut key = HeaderValue::from_str(password)
                .map_err(|_| ClickHouseError::Setup("the password is not a valid header".into()))?;
            key.set_sensitive(true);
            builder = builder.header("X-ClickHouse-Key", key);
        }
        builder
            .body(Full::new(Bytes::from_static(sql.as_bytes())))
            .map_err(setup)
    }
}

async fn exchange<S>(
    io: TokioIo<S>,
    request: Request<Full<Bytes>>,
) -> Result<Bytes, ClickHouseError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let unreachable = |error: hyper::Error| ClickHouseError::Unreachable(error.to_string());
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(unreachable)?;
    let driver = tokio::spawn(connection);
    let response = sender.send_request(request).await.map_err(unreachable)?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|error| ClickHouseError::Unreadable(error.to_string()))?
        .to_bytes();
    driver.abort();
    if status != StatusCode::OK {
        let detail: String = String::from_utf8_lossy(&body).chars().take(300).collect();
        return Err(ClickHouseError::Refused {
            status: status.as_u16(),
            detail: detail.trim().to_string(),
        });
    }
    Ok(body)
}

/// Percent-encodes a query-string component (RFC 3986 unreserved kept).
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A TLS connector trusting only the configured bundle.
fn connector(ca_file: Option<&Path>) -> Result<TlsConnector, ClickHouseError> {
    let path = ca_file.ok_or_else(|| {
        ClickHouseError::Setup("https:// needs a CA bundle; none is configured".into())
    })?;
    let setup = |detail: String| ClickHouseError::Setup(format!("{}: {detail}", path.display()));
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
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| setup(error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_scheme_host_and_port_only() {
        assert_eq!(
            parse_url("http://127.0.0.1:8123"),
            Ok((Scheme::Http, "127.0.0.1".into(), 8123))
        );
        assert_eq!(
            parse_url("https://ch.example.net/"),
            Ok((Scheme::Https, "ch.example.net".into(), 8443))
        );
        assert_eq!(
            parse_url("http://[::1]:9000"),
            Ok((Scheme::Http, "::1".into(), 9000))
        );
        for bad in [
            "ch.example.net:8123",
            "http://user:pw@ch:8123",
            "http://ch:8123/db",
            "http://ch:8123?x=1",
            "http://:8123",
            "http://ch:0",
            "http://ch:http",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    fn endpoint(scheme: Scheme, host: &str) -> Endpoint {
        Endpoint {
            scheme,
            host: host.into(),
            port: 8123,
            user: "wnm_api".into(),
            password_file: None,
            ca_file: None,
        }
    }

    #[test]
    fn plaintext_only_to_loopback_and_https_needs_a_bundle() {
        assert!(ClickHouse::new(endpoint(Scheme::Http, "127.0.0.1")).is_ok());
        assert!(ClickHouse::new(endpoint(Scheme::Http, "localhost")).is_ok());
        assert!(matches!(
            ClickHouse::new(endpoint(Scheme::Http, "10.0.0.5")),
            Err(ClickHouseError::Setup(_))
        ));
        assert!(matches!(
            ClickHouse::new(endpoint(Scheme::Https, "ch.example.net")),
            Err(ClickHouseError::Setup(_))
        ));
    }

    #[test]
    fn every_request_is_read_only_bounded_and_parameterised() {
        let clickhouse = ClickHouse::new(endpoint(Scheme::Http, "127.0.0.1")).unwrap();
        let request = clickhouse
            .request(
                "SELECT {x:String}",
                &[("x", "'; DROP TABLE t; --".to_string())],
            )
            .unwrap();
        let uri = request.uri().to_string();
        for setting in [
            "readonly=2",
            "max_execution_time=10",
            "max_result_rows=10000",
            "result_overflow_mode=throw",
        ] {
            assert!(uri.contains(setting), "{uri}");
        }
        assert!(
            uri.contains("param_x=%27%3B%20DROP%20TABLE%20t%3B%20--"),
            "{uri}"
        );
        assert!(request.headers().get("X-ClickHouse-Key").is_none());
    }

    #[test]
    fn the_password_is_sensitive_and_never_debug_printed() {
        let dir = std::env::temp_dir().join(format!("wnm-ch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("password");
        std::fs::write(&file, "s3cret-value\n").unwrap();
        let mut with_password = endpoint(Scheme::Http, "127.0.0.1");
        with_password.password_file = Some(file);
        let clickhouse = ClickHouse::new(with_password).unwrap();
        let request = clickhouse.request("SELECT 1", &[]).unwrap();
        let key = request.headers().get("X-ClickHouse-Key").unwrap();
        assert!(key.is_sensitive());
        assert_eq!(key, "s3cret-value");
        assert!(!format!("{clickhouse:?}").contains("s3cret"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
