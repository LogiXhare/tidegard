//! The connection to GoBGP's gRPC API (BQ-13, ADR 0048).
//!
//! GoBGP's API has no authentication: whoever reaches it can announce
//! anything (R27). So plain HTTP is refused off loopback, and anything
//! else needs TLS verified against a configured CA bundle. Every call has a
//! deadline.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tidegard_common::http_endpoint;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::api;
use crate::api::go_bgp_service_client::GoBgpServiceClient;
use crate::route::{is_owned, read_back, OwnedRoute, RouteConfig, UnreadablePath};

#[derive(Debug, thiserror::Error)]
pub enum GoBgpError {
    /// The configuration cannot work; retrying will not help.
    #[error("the GoBGP endpoint is misconfigured: {0}")]
    Setup(String),
    #[error("GoBGP is unreachable: {0}")]
    Unreachable(String),
    /// GoBGP answered and refused.
    #[error("GoBGP refused the call: {0}")]
    Refused(String),
    #[error(transparent)]
    Unreadable(#[from] UnreadablePath),
}

impl From<tonic::Status> for GoBgpError {
    fn from(status: tonic::Status) -> Self {
        match status.code() {
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                GoBgpError::Unreachable(status.message().to_string())
            }
            _ => GoBgpError::Refused(format!("{:?}: {}", status.code(), status.message())),
        }
    }
}

/// Splits `http://host:port` or `https://host:port`, by the rule every
/// service's endpoints follow (ADR 0053). GoBGP has no customary port,
/// so the URL must give one.
pub fn parse_endpoint(url: &str) -> Result<(bool, String, u16), GoBgpError> {
    let (scheme, host, port) =
        http_endpoint::parse_url_with_port(url).map_err(GoBgpError::Setup)?;
    let port = port.ok_or_else(|| GoBgpError::Setup("the endpoint needs a port".into()))?;
    Ok((scheme == http_endpoint::Scheme::Https, host, port))
}

/// The families Tidegard announces in.
fn families() -> [api::Family; 4] {
    use api::family::{Afi, Safi};
    [
        (Afi::Ip, Safi::Unicast),
        (Afi::Ip6, Safi::Unicast),
        (Afi::Ip, Safi::FlowSpecUnicast),
        (Afi::Ip6, Safi::FlowSpecUnicast),
    ]
    .map(|(afi, safi)| api::Family {
        afi: afi as i32,
        safi: safi as i32,
    })
}

pub struct GoBgp {
    client: GoBgpServiceClient<Channel>,
}

/// Where GoBGP's API is, and how to trust it. From the mitigator's
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoBgpEndpoint {
    /// `http://127.0.0.1:50051`, or `https://host:port` off this machine.
    pub url: String,
    /// The CA bundle that signed GoBGP's certificate. Required for
    /// `https://`, refused for `http://`.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// A client certificate and key, for a `gobgpd` started with
    /// `--tls-client-ca-file`: then only holders of a certificate it
    /// trusts may call its API.
    #[serde(default)]
    pub client_cert_file: Option<PathBuf>,
    #[serde(default)]
    pub client_key_file: Option<PathBuf>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    5_000
}

impl GoBgpEndpoint {
    /// A loopback endpoint with the default timeout.
    pub fn loopback(url: &str) -> Self {
        GoBgpEndpoint {
            url: url.to_string(),
            ca_file: None,
            client_cert_file: None,
            client_key_file: None,
            timeout_ms: default_timeout_ms(),
        }
    }
}

async fn read_file(path: &Path, what: &str) -> Result<Vec<u8>, GoBgpError> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::read(owned))
        .await
        .map_err(|e| GoBgpError::Setup(e.to_string()))?
        .map_err(|e| GoBgpError::Setup(format!("the {what} cannot be read: {e}")))
}

impl GoBgp {
    /// Connects. Plain `http://` reaches loopback only; anything else is
    /// TLS verified against the configured CA, optionally with a client
    /// certificate.
    pub async fn connect(endpoint: &GoBgpEndpoint) -> Result<Self, GoBgpError> {
        let (tls, host, port) = parse_endpoint(&endpoint.url)?;
        let timeout = Duration::from_millis(endpoint.timeout_ms.max(1));
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut channel = Endpoint::from_shared(format!(
            "{}://{authority}",
            if tls { "https" } else { "http" }
        ))
        .map_err(|e| GoBgpError::Setup(e.to_string()))?
        .connect_timeout(timeout)
        .timeout(timeout);
        let identity = match (&endpoint.client_cert_file, &endpoint.client_key_file) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some((cert, key)),
            _ => {
                return Err(GoBgpError::Setup(
                    "a client certificate and its key come together".into(),
                ))
            }
        };
        match (tls, &endpoint.ca_file) {
            (false, None) if identity.is_some() => {
                return Err(GoBgpError::Setup(
                    "a client certificate was given for a plain http:// endpoint".into(),
                ))
            }
            (false, None) if http_endpoint::is_loopback(&host) => {}
            (false, None) => {
                return Err(GoBgpError::Setup(
                    "GoBGP's API has no authentication: plain HTTP is allowed to loopback only; \
                     use https:// with a CA bundle"
                        .into(),
                ))
            }
            (false, Some(_)) => {
                return Err(GoBgpError::Setup(
                    "a CA bundle was given for a plain http:// endpoint".into(),
                ))
            }
            (true, None) => {
                return Err(GoBgpError::Setup(
                    "an https:// endpoint needs a CA bundle".into(),
                ))
            }
            (true, Some(ca)) => {
                let mut config = ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(read_file(ca, "CA bundle").await?))
                    .domain_name(host.clone());
                if let Some((cert, key)) = identity {
                    config = config.identity(Identity::from_pem(
                        read_file(cert, "client certificate").await?,
                        read_file(key, "client key").await?,
                    ));
                }
                channel = channel
                    .tls_config(config)
                    .map_err(|e| GoBgpError::Setup(e.to_string()))?;
            }
        }
        let channel = channel
            .connect()
            .await
            .map_err(|e| GoBgpError::Unreachable(e.to_string()))?;
        Ok(GoBgp {
            client: GoBgpServiceClient::new(channel),
        })
    }

    /// Adds `path` to GoBGP's global table, which advertises it to every
    /// peer the operator configured. Returns GoBGP's id for it.
    pub async fn announce(&mut self, path: api::Path) -> Result<Vec<u8>, GoBgpError> {
        let response = self
            .client
            .add_path(api::AddPathRequest {
                table_type: api::TableType::Global as i32,
                vrf_id: String::new(),
                path: Some(path),
            })
            .await?;
        Ok(response.into_inner().uuid)
    }

    /// Removes the path with the same NLRI from the global table.
    pub async fn withdraw(&mut self, path: api::Path) -> Result<(), GoBgpError> {
        self.client
            .delete_path(api::DeletePathRequest {
                table_type: api::TableType::Global as i32,
                vrf_id: String::new(),
                family: path.family,
                path: Some(path),
                uuid: Vec::new(),
            })
            .await?;
        Ok(())
    }

    /// GoBGP's peers: address, ASN and session state, lower case.
    pub async fn peers(&mut self) -> Result<Vec<(String, u32, &'static str)>, GoBgpError> {
        use api::peer_state::SessionState;
        let mut stream = self
            .client
            .list_peer(api::ListPeerRequest::default())
            .await?
            .into_inner();
        let mut peers = Vec::new();
        while let Some(response) = stream.message().await? {
            let Some(peer) = response.peer else { continue };
            let (address, asn) = peer
                .conf
                .as_ref()
                .map(|c| (c.neighbor_address.clone(), c.peer_asn))
                .unwrap_or_default();
            let state = match peer
                .state
                .as_ref()
                .and_then(|s| SessionState::try_from(s.session_state).ok())
            {
                Some(SessionState::Idle) => "idle",
                Some(SessionState::Connect) => "connect",
                Some(SessionState::Active) => "active",
                Some(SessionState::Opensent) => "opensent",
                Some(SessionState::Openconfirm) => "openconfirm",
                Some(SessionState::Established) => "established",
                _ => "unknown",
            };
            peers.push((address, asn, state));
        }
        Ok(peers)
    }

    /// Every route in the global table that carries Tidegard's
    /// ownership community. Another speaker's routes are never returned,
    /// so nothing here can touch them.
    pub async fn owned_routes(
        &mut self,
        config: &RouteConfig,
    ) -> Result<Vec<OwnedRoute>, GoBgpError> {
        let mut owned = Vec::new();
        for family in families() {
            let mut stream = self
                .client
                .list_path(api::ListPathRequest {
                    table_type: api::TableType::Global as i32,
                    family: Some(family),
                    ..api::ListPathRequest::default()
                })
                .await?
                .into_inner();
            while let Some(response) = stream.message().await? {
                let Some(destination) = response.destination else {
                    continue;
                };
                for path in destination.paths {
                    if is_owned(&path, config) {
                        owned.push(read_back(&path)?);
                    }
                }
            }
        }
        Ok(owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_scheme_host_and_port_only() {
        assert_eq!(
            parse_endpoint("http://127.0.0.1:50051").unwrap(),
            (false, "127.0.0.1".into(), 50051)
        );
        assert_eq!(
            parse_endpoint("https://[2001:db8::1]:50051").unwrap(),
            (true, "2001:db8::1".into(), 50051)
        );
        for bad in [
            "127.0.0.1:50051",
            "grpc://127.0.0.1:50051",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://user@127.0.0.1:50051",
            "http://127.0.0.1:50051/api",
            "http://:50051",
        ] {
            assert!(parse_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn plain_http_is_refused_off_loopback_and_https_needs_a_bundle() {
        let with =
            |url: &str, ca: Option<&str>, cert: Option<&str>, key: Option<&str>| GoBgpEndpoint {
                url: url.into(),
                ca_file: ca.map(PathBuf::from),
                client_cert_file: cert.map(PathBuf::from),
                client_key_file: key.map(PathBuf::from),
                timeout_ms: 200,
            };
        for endpoint in [
            with("http://192.0.2.1:50051", None, None, None),
            with("http://gobgp.example.net:50051", None, None, None),
            with("https://gobgp.example.net:50051", None, None, None),
            with("http://127.0.0.1:50051", Some("ca.pem"), None, None),
            with("http://127.0.0.1:50051", None, Some("c.pem"), Some("k.pem")),
            with(
                "https://gobgp.example.net:50051",
                Some("ca.pem"),
                Some("c.pem"),
                None,
            ),
        ] {
            assert!(
                matches!(GoBgp::connect(&endpoint).await, Err(GoBgpError::Setup(_))),
                "{endpoint:?}"
            );
        }
        // Loopback is allowed: here it is merely unreachable.
        let mut closed = GoBgpEndpoint::loopback("http://127.0.0.1:1");
        closed.timeout_ms = 200;
        assert!(matches!(
            GoBgp::connect(&closed).await,
            Err(GoBgpError::Unreachable(_))
        ));
        let parsed: GoBgpEndpoint =
            serde_json::from_str(r#"{"url": "http://127.0.0.1:50051"}"#).unwrap();
        assert_eq!(parsed, GoBgpEndpoint::loopback("http://127.0.0.1:50051"));
    }
}
