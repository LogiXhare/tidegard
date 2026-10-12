//! A minimal `/metrics` HTTP endpoint for Prometheus scraping, with
//! `/healthz` and `/readyz` beside it (NFR-2, ADR 0052).
//!
//! Shared by every service binary except the API, which has its own:
//! the collector, the incident manager, the notifier and the mitigator.
//! Deliberately hand-rolled instead of pulling in a full HTTP framework
//! (axum/hyper): a service only needs to serve one static-ish
//! response body on one path, so a framework would be dependency weight
//! without a matching benefit at this phase. If the API/web crates need
//! a real HTTP framework later, that's evaluated on its own merits then
//! — see docs/dependency-license-matrix.md for the process.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use prometheus::{Encoder, Registry, TextEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Whether a service can do its work now. A service starts not ready,
/// marks itself ready once startup is done, and goes back to not ready
/// while, for example, its database is unreachable. Clones share one flag.
#[derive(Clone, Debug, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// Starts not ready.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Relaxed);
    }

    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Serves `GET /metrics`, `/healthz` (200 while the process runs) and
/// `/readyz` (200 when ready, 503 when not) on `addr`, and a 404 for
/// anything else, until the process exits. Runs forever — callers should
/// `tokio::spawn` this.
pub async fn serve(
    addr: std::net::SocketAddr,
    registry: Arc<Registry>,
    readiness: Readiness,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics endpoint listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let registry = Arc::clone(&registry);
        let readiness = readiness.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, &registry, &readiness).await {
                tracing::debug!(%peer, error = %err, "metrics connection ended early");
            }
        });
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    registry: &Registry,
    readiness: &Readiness,
) -> std::io::Result<()> {
    // We only need to know the request line to decide the response; the
    // body/headers of the request are irrelevant to us and are not read,
    // which is fine because we close the connection after responding
    // (no keep-alive to worry about).
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).await?;
    let request_line = String::from_utf8_lossy(&buf[..n]);

    let response = match request_line.split_whitespace().nth(1) {
        Some("/metrics") => render_metrics_response(registry),
        Some("/healthz") => text_response("200 OK", "ok\n"),
        Some("/readyz") if readiness.is_ready() => text_response("200 OK", "ready\n"),
        Some("/readyz") => text_response("503 Service Unavailable", "not ready\n"),
        _ => text_response("404 Not Found", "not found\n"),
    };

    stream.write_all(&response).await?;
    stream.shutdown().await?;
    Ok(())
}

fn render_metrics_response(registry: &Registry) -> Vec<u8> {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut body = Vec::new();
    // Encoding failures here would mean a bug in how we registered
    // metrics (e.g. a name collision would have failed at registration
    // time already); if it somehow still fails, degrade to an empty body
    // with a 200 rather than taking the whole endpoint down.
    let _ = encoder.encode(&metric_families, &mut body);

    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        encoder.format_type(),
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);
    response
}

fn text_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    /// Sends one request to a server that answers one connection.
    async fn get(path: &str, registry: Registry, readiness: Readiness) -> String {
        let registry = Arc::new(registry);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, &registry, &readiness)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_metrics_on_the_metrics_path() {
        let registry = Registry::new();
        let counter = prometheus::IntCounter::new("example_total", "An example.").unwrap();
        registry.register(Box::new(counter.clone())).unwrap();
        counter.inc();

        let response = get("/metrics", registry, Readiness::new()).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("example_total 1"));
    }

    #[tokio::test]
    async fn is_healthy_even_before_it_is_ready() {
        let response = get("/healthz", Registry::new(), Readiness::new()).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("\r\n\r\nok\n"));
    }

    #[tokio::test]
    async fn readiness_follows_the_flag_both_ways() {
        let readiness = Readiness::new();
        let response = get("/readyz", Registry::new(), readiness.clone()).await;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));

        readiness.set(true);
        let response = get("/readyz", Registry::new(), readiness.clone()).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("\r\n\r\nready\n"));

        readiness.set(false);
        let response = get("/readyz", Registry::new(), readiness).await;
        assert!(response.starts_with("HTTP/1.1 503"));
    }

    #[tokio::test]
    async fn returns_404_for_other_paths() {
        let response = get("/health", Registry::new(), Readiness::new()).await;
        assert!(response.starts_with("HTTP/1.1 404"));
        assert!(response.contains("Content-Length: 10\r\n"));
    }
}
