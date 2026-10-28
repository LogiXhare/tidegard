//! HTTP to the API, one connection per request (ADR 0040).
//!
//! - **TLS is verified against the configured CA bundle,** always. There is
//!   no way to turn verification off.
//! - **Retries** happen only after a connection error or a `5xx`, at most
//!   [`MAX_ATTEMPTS`] times with backoff, and never after a `4xx`. A
//!   mutating request carries one `Idempotency-Key`, the same on every
//!   attempt, so a retry the server already applied is replayed rather
//!   than applied twice.
//! - **Bounded:** each attempt has a deadline, and a response body over
//!   [`MAX_BODY_BYTES`] is refused.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::{Endpoint, Scheme};

pub const MAX_ATTEMPTS: u32 = 3;
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// An export is the largest response; this leaves it ample room.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// What the server answered.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: StatusCode,
    pub content_disposition: Option<String>,
    pub body: Bytes,
}

/// Why no answer arrived. Never carries the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The CA bundle could not be used; retrying will not help.
    Tls(String),
    /// Connecting, the handshake or the exchange failed.
    Connection(String),
    TimedOut,
    BodyTooLarge,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Tls(detail) => write!(f, "TLS setup failed: {detail}"),
            TransportError::Connection(detail) => write!(f, "cannot reach the API: {detail}"),
            TransportError::TimedOut => write!(f, "the API did not answer in time"),
            TransportError::BodyTooLarge => write!(f, "the API's answer was too large"),
        }
    }
}

/// One request: method, path below the base URL (with any query), body.
#[derive(Debug, Clone)]
pub struct Call {
    pub method: Method,
    pub path: String,
    pub body: Option<Vec<u8>>,
    pub idempotency_key: Option<String>,
}

pub struct Client {
    endpoint: Endpoint,
    tls: Option<TlsConnector>,
    backoff: Duration,
}

impl Client {
    pub fn new(endpoint: Endpoint) -> Result<Self, TransportError> {
        let tls = match endpoint.base.scheme {
            Scheme::Http => None,
            Scheme::Https => Some(connector(&endpoint)?),
        };
        Ok(Client {
            endpoint,
            tls,
            backoff: Duration::from_millis(250),
        })
    }

    /// For tests: no wait between attempts.
    pub fn without_backoff(mut self) -> Self {
        self.backoff = Duration::ZERO;
        self
    }

    /// Sends `call`, retrying per the module rules.
    pub async fn send(&self, call: &Call) -> Result<Reply, TransportError> {
        let mut attempt = 1;
        loop {
            let result = tokio::time::timeout(ATTEMPT_TIMEOUT, self.once(call))
                .await
                .unwrap_or(Err(TransportError::TimedOut));
            let retryable = match &result {
                Ok(reply) => reply.status.is_server_error(),
                Err(TransportError::Connection(_) | TransportError::TimedOut) => true,
                Err(TransportError::Tls(_) | TransportError::BodyTooLarge) => false,
            };
            if !retryable || attempt >= MAX_ATTEMPTS {
                return result;
            }
            tokio::time::sleep(self.backoff * 2u32.pow(attempt - 1)).await;
            attempt += 1;
        }
    }

    async fn once(&self, call: &Call) -> Result<Reply, TransportError> {
        let base = &self.endpoint.base;
        let tcp = TcpStream::connect((base.host.as_str(), base.port))
            .await
            .map_err(|error| TransportError::Connection(error.to_string()))?;
        let request = self.request(call)?;
        match &self.tls {
            None => exchange(TokioIo::new(tcp), request).await,
            Some(connector) => {
                let name = ServerName::try_from(base.host.clone())
                    .map_err(|_| TransportError::Tls("the API host is not a valid name".into()))?;
                let stream = connector
                    .connect(name, tcp)
                    .await
                    .map_err(|error| TransportError::Connection(error.to_string()))?;
                exchange(TokioIo::new(stream), request).await
            }
        }
    }

    fn request(&self, call: &Call) -> Result<Request<Full<Bytes>>, TransportError> {
        let base = &self.endpoint.base;
        let host = if base.host.contains(':') {
            format!("[{}]:{}", base.host, base.port)
        } else {
            format!("{}:{}", base.host, base.port)
        };
        let mut builder = Request::builder()
            .method(call.method.clone())
            .uri(format!("{}{}", base.prefix, call.path))
            .header(HOST, host)
            .header(ACCEPT, "application/json, application/problem+json")
            .header(
                USER_AGENT,
                concat!("tidegardctl/", env!("CARGO_PKG_VERSION")),
            );
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", self.endpoint.token))
            .map_err(|_| TransportError::Connection("the token is not a valid header".into()))?;
        bearer.set_sensitive(true);
        builder = builder.header(AUTHORIZATION, bearer);
        if let Some(tenant) = &self.endpoint.tenant {
            builder = builder.header("Tidegard-Tenant", tenant.as_str());
        }
        if let Some(key) = &call.idempotency_key {
            builder = builder.header("Idempotency-Key", key.as_str());
        }
        let body = match &call.body {
            Some(body) => {
                builder = builder.header(CONTENT_TYPE, "application/json");
                Full::new(Bytes::from(body.clone()))
            }
            None => Full::new(Bytes::new()),
        };
        builder
            .body(body)
            .map_err(|error| TransportError::Connection(error.to_string()))
    }
}

async fn exchange<S>(io: TokioIo<S>, request: Request<Full<Bytes>>) -> Result<Reply, TransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    let status = response.status();
    let content_disposition = response
        .headers()
        .get(hyper::header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .map(String::from);
    let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|error| {
            if error.is::<http_body_util::LengthLimitError>() {
                TransportError::BodyTooLarge
            } else {
                TransportError::Connection(error.to_string())
            }
        })?
        .to_bytes();
    driver.abort();
    Ok(Reply {
        status,
        content_disposition,
        body,
    })
}

/// A TLS connector trusting only the configured bundle.
fn connector(endpoint: &Endpoint) -> Result<TlsConnector, TransportError> {
    let path = endpoint
        .ca_file
        .as_ref()
        .ok_or_else(|| TransportError::Tls("no CA bundle is configured".into()))?;
    let pem = std::fs::read(path)
        .map_err(|error| TransportError::Tls(format!("{}: {error}", path.display())))?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem) {
        let certificate = certificate
            .map_err(|_| TransportError::Tls(format!("{}: not a PEM bundle", path.display())))?;
        roots
            .add(certificate)
            .map_err(|error| TransportError::Tls(format!("{}: {error}", path.display())))?;
    }
    if roots.is_empty() {
        return Err(TransportError::Tls(format!(
            "{}: holds no certificates",
            path.display()
        )));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| TransportError::Tls(error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
