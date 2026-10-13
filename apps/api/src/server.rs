//! Binding and serving, with the TLS rule (ADR 0038, gate 3).
//!
//! - **Loopback may be plaintext:** a reverse proxy on the same host
//!   terminates TLS and forwards to `127.0.0.1`.
//! - **Anything else requires TLS here,** with a certificate and key from
//!   operator-managed files. There is no switch that allows plaintext off
//!   loopback; [`bind`] refuses it.
//! - **Handshakes never block accepting.** Each runs in its own task with a
//!   deadline, so a client that connects and stalls costs one task, not
//!   the listener.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::serve::Listener;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// How long a client has to finish the TLS handshake.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Completed handshakes waiting for the server to take them.
const ACCEPTED_BACKLOG: usize = 128;

/// The certificate chain and key, PEM, from operator-managed files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFiles {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error(
        "{0} is not a loopback address, so TLS is required: set \
         TIDEGARD_API_TLS_CERT_FILE and TIDEGARD_API_TLS_KEY_FILE"
    )]
    TlsRequired(SocketAddr),
    #[error("could not read {what} from {path}: {source}")]
    ReadFile {
        what: &'static str,
        path: String,
        source: io::Error,
    },
    #[error("the TLS configuration was refused: {0}")]
    Tls(String),
    #[error("could not bind {addr}: {source}")]
    Bind { addr: SocketAddr, source: io::Error },
}

/// A bound listener, plaintext or TLS.
pub enum Bound {
    Plain(TcpListener),
    Tls(TlsListener),
}

/// Binds `addr`, refusing plaintext off loopback.
pub async fn bind(addr: SocketAddr, tls: Option<&TlsFiles>) -> Result<Bound, BindError> {
    let config = match tls {
        Some(files) => Some(server_config(files)?),
        None if addr.ip().is_loopback() => None,
        None => return Err(BindError::TlsRequired(addr)),
    };
    let tcp = TcpListener::bind(addr)
        .await
        .map_err(|source| BindError::Bind { addr, source })?;
    Ok(match config {
        None => Bound::Plain(tcp),
        Some(config) => Bound::Tls(TlsListener::start(tcp, Arc::new(config))?),
    })
}

fn server_config(files: &TlsFiles) -> Result<ServerConfig, BindError> {
    let read = |what: &'static str, path: &PathBuf| {
        std::fs::read(path).map_err(|source| BindError::ReadFile {
            what,
            path: path.display().to_string(),
            source,
        })
    };
    let chain_pem = read("the certificate chain", &files.certificate_chain)?;
    let key_pem = read("the private key", &files.private_key)?;
    let chain = CertificateDer::pem_slice_iter(&chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| BindError::Tls(format!("the certificate chain is not PEM: {error}")))?;
    if chain.is_empty() {
        return Err(BindError::Tls(
            "the certificate chain holds no certificate".into(),
        ));
    }
    // The key's own parse error is not shown: it could echo key material.
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|_| BindError::Tls("the private key is not a readable PEM key".into()))?;
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| BindError::Tls(format!("no safe protocol version: {error}")))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| BindError::Tls(format!("the certificate was refused: {error}")))
}

/// Accepts TCP, handshakes in separate tasks, and hands finished TLS
/// streams to the server.
pub struct TlsListener {
    accepted: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    fn start(tcp: TcpListener, config: Arc<ServerConfig>) -> Result<Self, BindError> {
        let local = tcp.local_addr().map_err(|source| BindError::Bind {
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            source,
        })?;
        let acceptor = TlsAcceptor::from(config);
        let (sender, accepted) = mpsc::channel(ACCEPTED_BACKLOG);
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match tcp.accept().await {
                    Ok(connection) => connection,
                    Err(error) => {
                        // EMFILE and friends: back off rather than spin.
                        tracing::warn!(error = %error, "accepting a TCP connection failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if sender.is_closed() {
                    break;
                }
                let acceptor = acceptor.clone();
                let sender = sender.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_DEADLINE, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = sender.send((tls, peer)).await;
                        }
                        Ok(Err(error)) => {
                            tracing::debug!(%peer, error = %error, "TLS handshake failed");
                        }
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(TlsListener { accepted, local })
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(connection) => connection,
            // The accept task only ends once this receiver is gone.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// The caller's address, for per-address limits. One type for both
/// listeners: axum provides `SocketAddr` connection info only for its own
/// `TcpListener`, and the orphan rule forbids adding it for ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddr(pub SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TcpListener>>
    for PeerAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TcpListener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for PeerAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        PeerAddr(*stream.remote_addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plaintext_is_refused_off_loopback_and_allowed_on_it() {
        for addr in ["0.0.0.0:0", "192.0.2.10:0", "[::]:0"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert!(
                matches!(bind(addr, None).await, Err(BindError::TlsRequired(_))),
                "{addr}"
            );
        }
        let Ok(Bound::Plain(listener)) = bind("127.0.0.1:0".parse().unwrap(), None).await else {
            panic!("loopback plaintext must bind");
        };
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn missing_or_bad_tls_files_are_reported_without_key_material() {
        let dir = std::env::temp_dir();
        let missing = TlsFiles {
            certificate_chain: dir.join("tidegard-api-missing.crt"),
            private_key: dir.join("tidegard-api-missing.key"),
        };
        let Err(error) = bind("0.0.0.0:0".parse().unwrap(), Some(&missing)).await else {
            panic!("a missing certificate must be refused");
        };
        assert!(matches!(error, BindError::ReadFile { .. }), "{error}");

        let key_path = dir.join(format!("tidegard-api-bad-{}.key", std::process::id()));
        let cert_path = dir.join(format!("tidegard-api-bad-{}.crt", std::process::id()));
        std::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(&cert_path, "not a certificate").unwrap();
        let bad = TlsFiles {
            certificate_chain: cert_path.clone(),
            private_key: key_path.clone(),
        };
        let Err(error) = bind("0.0.0.0:0".parse().unwrap(), Some(&bad)).await else {
            panic!("an unusable certificate must be refused");
        };
        assert!(matches!(error, BindError::Tls(_)), "{error}");
        assert!(!error.to_string().contains("c2VjcmV0"));
        let _ = std::fs::remove_file(key_path);
        let _ = std::fs::remove_file(cert_path);
    }
}
