//! Where a notification may go (ADR 0045, R23).
//!
//! A webhook URL is server-side request forgery waiting to happen: it can
//! point the notifier at a database, a cloud metadata service, or the
//! management interface of a router. So a destination must pass three
//! checks, and the connection goes to the address that passed:
//!
//! 1. its host is on the configured allowlist;
//! 2. **every** address the host resolves to is public, unless the channel
//!    allows private ones;
//! 3. it is `https`, unless the channel allows private ones.
//!
//! Connecting to the checked address, rather than resolving again, closes
//! the DNS-rebinding gap between the check and the use.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// A parsed destination URL.
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// The path and query, starting with `/`.
    pub path: String,
}

/// Never prints the path: for Slack, Teams and Telegram it holds the
/// secret.
impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}://{}:{}/<redacted>",
            self.scheme, self.host, self.port
        )
    }
}

/// Why a destination was refused. Never holds the URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the destination URL is malformed")]
    Malformed,
    #[error("{0} is not on the allowed hosts")]
    HostNotAllowed(String),
    #[error("{0} resolves to a non-public address")]
    PrivateAddress(String),
    #[error("plain HTTP is allowed only to a private receiver")]
    PlainHttp,
    #[error("{0} does not resolve")]
    Unresolvable(String),
}

pub fn parse(url: &str) -> Result<Target, Refusal> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else {
        return Err(Refusal::Malformed);
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if authority.contains(['@', '?', '#', ' ']) || path.contains(['#', ' ', '\r', '\n']) {
        return Err(Refusal::Malformed);
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or(Refusal::Malformed)?;
        (host.to_string(), after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(Refusal::Malformed);
    }
    let port = match port {
        Some(text) => text
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or(Refusal::Malformed)?,
        None => match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        },
    };
    Ok(Target {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_string(),
    })
}

/// `hooks.slack.com` matches only itself; `*.webhook.office.com` matches
/// any subdomain, never the bare suffix.
pub fn host_allowed(host: &str, allowlist: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowlist.iter().any(|pattern| {
        let pattern = pattern.to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) => host
                .strip_suffix(suffix)
                .is_some_and(|head| head.ends_with('.') && head.len() > 1),
            None => host == pattern,
        }
    })
}

/// Public, routable unicast only.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let segments = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00 // unique local
                || (segments[0] & 0xffc0) == 0xfe80 // link-local
                || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
                || (segments[0] == 0x0064 && segments[1] == 0xff9b) // NAT64
                || v6 == Ipv6Addr::from([0u16, 0, 0, 0, 0, 0, 0, 0]))
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || a == 0
        || a >= 240 // reserved
        || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // documentation
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || (a == 198 && (18..20).contains(&b))) // benchmarking
}

/// Checks `target` and resolves it to the one address to connect to.
pub async fn vet(
    target: &Target,
    allowlist: &[String],
    allow_private: bool,
) -> Result<SocketAddr, Refusal> {
    if target.scheme == Scheme::Http && !allow_private {
        return Err(Refusal::PlainHttp);
    }
    if !host_allowed(&target.host, allowlist) {
        return Err(Refusal::HostNotAllowed(target.host.clone()));
    }
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|_| Refusal::Unresolvable(target.host.clone()))?
        .collect();
    let first = *addresses
        .first()
        .ok_or_else(|| Refusal::Unresolvable(target.host.clone()))?;
    // Every answer must pass: a host with one public and one private
    // address is refused, not raced.
    if !allow_private && addresses.iter().any(|address| !is_public(address.ip())) {
        return Err(Refusal::PrivateAddress(target.host.clone()));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_without_credentials_or_fragments() {
        let target = parse("https://hooks.slack.com/services/T0/B0/xyz").unwrap();
        assert_eq!(target.scheme, Scheme::Https);
        assert_eq!(
            (target.host.as_str(), target.port),
            ("hooks.slack.com", 443)
        );
        assert_eq!(target.path, "/services/T0/B0/xyz");
        assert!(
            !format!("{target:?}").contains("xyz"),
            "the path is a secret"
        );
        assert_eq!(parse("http://127.0.0.1:9000").unwrap().path, "/");
        assert_eq!(
            parse("https://[2001:db8::1]:8443/x").unwrap().host,
            "2001:db8::1"
        );
        for bad in [
            "ftp://x/y",
            "https://user:pw@x/y",
            "https:///y",
            "https://x:0/",
            "https://x/y#frag",
            "https://x/a b",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_allowlist_is_exact_or_a_true_subdomain() {
        let list = vec![
            "hooks.slack.com".to_string(),
            "*.webhook.office.com".to_string(),
        ];
        assert!(host_allowed("hooks.slack.com", &list));
        assert!(host_allowed("HOOKS.SLACK.COM.", &list));
        assert!(host_allowed("acme.webhook.office.com", &list));
        assert!(!host_allowed("webhook.office.com", &list));
        assert!(!host_allowed("evilwebhook.office.com", &list));
        assert!(!host_allowed("hooks.slack.com.evil.net", &list));
        assert!(!host_allowed("slack.com", &list));
    }

    #[test]
    fn only_public_unicast_addresses_pass() {
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "192.0.2.1",
            "203.0.113.5",
            "198.18.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::a00:1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
    }

    #[tokio::test]
    async fn plain_http_private_and_unlisted_hosts_are_refused() {
        let allow = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let local = parse("http://127.0.0.1:9/hook").unwrap();
        assert_eq!(vet(&local, &allow, false).await, Err(Refusal::PlainHttp));
        let local_tls = parse("https://127.0.0.1:9/hook").unwrap();
        assert_eq!(
            vet(&local_tls, &allow, false).await,
            Err(Refusal::PrivateAddress("127.0.0.1".into()))
        );
        assert!(
            vet(&local, &allow, true).await.is_ok(),
            "a private receiver, allowed"
        );
        let unlisted = parse("https://169.254.169.254/latest/meta-data").unwrap();
        assert_eq!(
            vet(&unlisted, &allow, true).await,
            Err(Refusal::HostNotAllowed("169.254.169.254".into()))
        );
    }
}
