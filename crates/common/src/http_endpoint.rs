//! An `http://` or `https://` endpoint given as a setting, and the rule
//! every service applies to it: plaintext reaches this machine only
//! (ADR 0042, ADR 0053). Shared by the API's and the collector's
//! ClickHouse connections, so the rule is written once.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// Parses `http://host:port` or `https://host:port`. A path, query or
/// credentials in the URL are refused: credentials come from their own
/// settings, never a URL that ends up in a log. Without a port, ClickHouse's
/// HTTP ports are assumed: 8123, or 8443 for TLS.
pub fn parse_url(url: &str) -> Result<(Scheme, String, u16), String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else {
        return Err("the URL must start with http:// or https://".into());
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '?', '#', '@']) {
        return Err("the URL may hold only a host and a port".into());
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed
            .split_once(']')
            .ok_or("an IPv6 host needs its closing bracket")?;
        (host.to_string(), after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err("the URL has no host".into());
    }
    let port = match port {
        Some(text) => text
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or("the port is not a number from 1 to 65535")?,
        None => match scheme {
            Scheme::Http => 8123,
            Scheme::Https => 8443,
        },
    };
    Ok((scheme, host, port))
}

/// Plain HTTP only to this machine.
pub fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// `scheme://host:port`, with an IPv6 host in brackets.
pub fn authority_url(scheme: Scheme, host: &str, port: u16) -> String {
    let scheme = match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    if host.contains(':') {
        format!("{scheme}://[{host}]:{port}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_ports_and_defaults() {
        assert_eq!(
            parse_url("http://127.0.0.1:8123"),
            Ok((Scheme::Http, "127.0.0.1".into(), 8123))
        );
        assert_eq!(
            parse_url("https://ch.example.net/"),
            Ok((Scheme::Https, "ch.example.net".into(), 8443))
        );
        assert_eq!(
            parse_url("https://[2001:db8::1]:9440"),
            Ok((Scheme::Https, "2001:db8::1".into(), 9440))
        );
    }

    #[test]
    fn refuses_credentials_paths_and_bad_ports() {
        for url in [
            "http://user:secret@127.0.0.1:8123",
            "http://127.0.0.1:8123/db",
            "http://127.0.0.1:8123?user=x",
            "http://127.0.0.1:0",
            "http://127.0.0.1:70000",
            "ftp://127.0.0.1",
            "http://",
            "https://[2001:db8::1",
        ] {
            assert!(parse_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn only_this_machine_is_loopback() {
        for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.5.0.9", "::1"] {
            assert!(is_loopback(host), "{host}");
        }
        for host in [
            "clickhouse",
            "192.0.2.10",
            "2001:db8::1",
            "localhost.example.net",
        ] {
            assert!(!is_loopback(host), "{host}");
        }
    }

    #[test]
    fn writes_the_authority_back() {
        assert_eq!(
            authority_url(Scheme::Https, "2001:db8::1", 8443),
            "https://[2001:db8::1]:8443"
        );
        assert_eq!(
            authority_url(Scheme::Http, "127.0.0.1", 8123),
            "http://127.0.0.1:8123"
        );
    }
}
