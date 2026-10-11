//! One HTTP POST to a vetted address (ADR 0045). The connection goes to the
//! address [`crate::destination::vet`] checked; TLS verifies the host name
//! against the configured CA bundle. Redirects are not followed, and the
//! response body is capped and thrown away: a receiver's answer is never
//! logged or stored.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::destination::{Scheme, Target};

pub const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// What became of one POST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    Status(StatusCode),
    /// Connecting, TLS or the exchange failed, or it timed out.
    Failed(String),
}

/// A TLS connector trusting only the configured bundle.
pub fn connector(ca_file: &Path) -> Result<TlsConnector, String> {
    let pem = std::fs::read(ca_file).map_err(|error| format!("{}: {error}", ca_file.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem) {
        let certificate =
            certificate.map_err(|_| format!("{}: not a PEM bundle", ca_file.display()))?;
        roots
            .add(certificate)
            .map_err(|error| format!("{}: {error}", ca_file.display()))?;
    }
    if roots.is_empty() {
        return Err(format!("{}: holds no certificates", ca_file.display()));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| error.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// POSTs `body` to `target` at `address`.
pub async fn post(
    target: &Target,
    address: SocketAddr,
    tls: Option<&TlsConnector>,
    headers: &[(&'static str, String)],
    body: Vec<u8>,
) -> Sent {
    match tokio::time::timeout(TIMEOUT, exchange(target, address, tls, headers, body)).await {
        Ok(Ok(status)) => Sent::Status(status),
        Ok(Err(detail)) => Sent::Failed(detail),
        Err(_) => Sent::Failed("no answer in time".into()),
    }
}

async fn exchange(
    target: &Target,
    address: SocketAddr,
    tls: Option<&TlsConnector>,
    headers: &[(&'static str, String)],
    body: Vec<u8>,
) -> Result<StatusCode, String> {
    let host = if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(target.path.as_str())
        .header(HOST, host)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header(
            USER_AGENT,
            concat!("wetechinetmon-notifier/", env!("CARGO_PKG_VERSION")),
        );
    for (name, value) in headers {
        let mut value =
            HeaderValue::from_str(value).map_err(|_| "a header is not valid".to_string())?;
        value.set_sensitive(true);
        builder = builder.header(HeaderName::from_static(name), value);
    }
    let request = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| error.to_string())?;
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|error| format!("connect: {error}"))?;
    match (target.scheme, tls) {
        (Scheme::Http, _) => send(TokioIo::new(tcp), request).await,
        (Scheme::Https, Some(connector)) => {
            let name = ServerName::try_from(target.host.clone())
                .map_err(|_| "the host is not a valid TLS name".to_string())?;
            let stream = connector
                .connect(name, tcp)
                .await
                .map_err(|error| format!("tls: {error}"))?;
            send(TokioIo::new(stream), request).await
        }
        (Scheme::Https, None) => Err("https needs a CA bundle".into()),
    }
}

async fn send<S>(io: TokioIo<S>, request: Request<Full<Bytes>>) -> Result<StatusCode, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| format!("handshake: {error}"))?;
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("exchange: {error}"))?;
    let status = response.status();
    // Read and discard a bounded body, so the connection ends cleanly.
    let _ = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await;
    driver.abort();
    Ok(status)
}
