//! Where the CLI connects and with what credential (ADR 0040).
//!
//! The environment overrides the config file, field by field:
//!
//! | Field | Environment | Config file profile |
//! |---|---|---|
//! | endpoint | `TIDEGARD_API_URL` | `url` |
//! | token | `TIDEGARD_API_TOKEN` | `token` |
//! | CA bundle | `TIDEGARD_API_CA_FILE` | `ca_file` |
//!
//! The file is JSON, at `$TIDEGARD_CONFIG` or the platform default,
//! and holds named profiles; `--profile` picks one, else
//! `default_profile`, else the one named `default`. A token is never
//! taken from a flag.
//!
//! - `https://` needs a CA bundle, and verification is never disabled.
//! - `http://` is accepted only for a loopback host, as the server
//!   refuses plaintext off loopback (ADR 0038).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::Deserialize;

pub const URL_VAR: &str = "TIDEGARD_API_URL";
pub const TOKEN_VAR: &str = "TIDEGARD_API_TOKEN";
pub const CA_FILE_VAR: &str = "TIDEGARD_API_CA_FILE";
pub const CONFIG_VAR: &str = "TIDEGARD_CONFIG";

/// The process environment, injectable for tests.
pub trait Environment {
    fn var(&self, name: &str) -> Option<String>;
    fn read_file(&self, path: &std::path::Path) -> std::io::Result<String>;
}

/// The real environment and file system.
pub struct ProcessEnvironment;

impl Environment for ProcessEnvironment {
    fn var(&self, name: &str) -> Option<String> {
        tidegard_common::env::var(name)
            .ok()
            .flatten()
            .filter(|value| !value.is_empty())
    }

    fn read_file(&self, path: &std::path::Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    url: Option<String>,
    token: Option<String>,
    ca_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    default_profile: Option<String>,
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// A parsed `http(s)://host[:port][/prefix]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrl {
    pub scheme: Scheme,
    /// As written, without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// Empty, or starting with `/` and without a trailing one.
    pub prefix: String,
}

impl BaseUrl {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (scheme, rest) = if let Some(rest) = text.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = text.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else {
            return Err("the API URL must start with https:// or http://".into());
        };
        let (authority, prefix) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].trim_end_matches('/')),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err("the API URL must not carry credentials".into());
        }
        let default_port = match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or("the API URL has an unclosed [")?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse().map_err(|_| "the API URL has a bad port")?,
                None if after.is_empty() => default_port,
                None => return Err("the API URL has a bad port".into()),
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (
                    host.to_string(),
                    port.parse().map_err(|_| "the API URL has a bad port")?,
                ),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty() {
            return Err("the API URL has no host".into());
        }
        if prefix.contains(['?', '#']) {
            return Err("the API URL must not carry a query or fragment".into());
        }
        Ok(BaseUrl {
            scheme,
            host,
            port,
            prefix: prefix.to_string(),
        })
    }

    pub fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<IpAddr>()
                .is_ok_and(|addr| addr.is_loopback())
    }
}

/// Everything a request needs.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub base: BaseUrl,
    pub token: String,
    pub ca_file: Option<PathBuf>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("base", &self.base)
            .field("token", &"<redacted>")
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

/// The default config file location.
fn default_config_path(env: &dyn Environment) -> Option<PathBuf> {
    if cfg!(windows) {
        env.var("APPDATA")
            .map(|dir| PathBuf::from(dir).join("tidegard").join("cli.json"))
    } else {
        env.var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env.var("HOME")
                    .map(|home| PathBuf::from(home).join(".config"))
            })
            .map(|dir| dir.join("tidegard").join("cli.json"))
    }
}

/// Resolves the endpoint for `profile`. Errors are for the operator and
/// never include the token.
pub fn resolve(env: &dyn Environment, profile: Option<&str>) -> Result<Endpoint, String> {
    let explicit_path = env.var(CONFIG_VAR).map(PathBuf::from);
    let path = explicit_path.clone().or_else(|| default_config_path(env));
    let file = match path {
        Some(path) => match env.read_file(&path) {
            Ok(text) => serde_json::from_str::<ConfigFile>(&text)
                .map_err(|error| format!("{}: {error}", path.display()))?,
            // A missing default file is normal; a missing explicit one is not.
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && explicit_path.is_none() =>
            {
                ConfigFile::default()
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        },
        None => ConfigFile::default(),
    };
    let chosen = profile
        .map(String::from)
        .or(file.default_profile.clone())
        .unwrap_or_else(|| "default".to_string());
    let stored = match file.profiles.get(&chosen) {
        Some(stored) => stored.clone(),
        None if profile.is_some() => return Err(format!("no profile named {chosen:?}")),
        None => Profile::default(),
    };

    let url = env
        .var(URL_VAR)
        .or(stored.url)
        .ok_or_else(|| format!("no API URL: set {URL_VAR} or a profile's url"))?;
    let base = BaseUrl::parse(&url)?;
    let token = env
        .var(TOKEN_VAR)
        .or(stored.token)
        .ok_or_else(|| format!("no API token: set {TOKEN_VAR} or a profile's token"))?;
    let ca_file = env.var(CA_FILE_VAR).map(PathBuf::from).or(stored.ca_file);
    match base.scheme {
        Scheme::Http if !base.is_loopback() => {
            return Err(
                "plain http:// is only for a loopback API; use https:// so the token is \
                 never sent in the clear"
                    .into(),
            )
        }
        Scheme::Https if ca_file.is_none() => {
            return Err(format!(
                "https:// needs a CA bundle: set {CA_FILE_VAR} or a profile's ca_file \
                 (on Linux, the system bundle such as /etc/ssl/certs/ca-certificates.crt)"
            ))
        }
        _ => {}
    }
    Ok(Endpoint {
        base,
        token,
        ca_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct FakeEnvironment {
        vars: HashMap<String, String>,
        files: HashMap<PathBuf, String>,
    }

    impl Environment for FakeEnvironment {
        fn var(&self, name: &str) -> Option<String> {
            self.vars.get(name).cloned()
        }

        fn read_file(&self, path: &std::path::Path) -> std::io::Result<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    fn env(vars: &[(&str, &str)]) -> FakeEnvironment {
        FakeEnvironment {
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            files: HashMap::new(),
        }
    }

    #[test]
    fn urls_parse_with_ports_prefixes_and_ipv6() {
        let url = BaseUrl::parse("https://api.example.net:8443/wnm/").unwrap();
        assert_eq!(
            (url.host.as_str(), url.port, url.prefix.as_str()),
            ("api.example.net", 8443, "/wnm")
        );
        let url = BaseUrl::parse("http://[::1]:8080").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("::1", 8080));
        assert!(url.is_loopback());
        for bad in [
            "ftp://x",
            "https://user:pw@x",
            "https://x:port",
            "https://",
            "https://x/?q",
        ] {
            assert!(BaseUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plaintext_only_to_loopback_and_tls_needs_a_ca() {
        let token = (TOKEN_VAR, "wnm_x");
        assert!(resolve(&env(&[(URL_VAR, "http://127.0.0.1:8080"), token]), None).is_ok());
        assert!(resolve(&env(&[(URL_VAR, "http://localhost:8080"), token]), None).is_ok());
        let error = resolve(&env(&[(URL_VAR, "http://10.0.0.5:8080"), token]), None).unwrap_err();
        assert!(error.contains("loopback"), "{error}");
        let error =
            resolve(&env(&[(URL_VAR, "https://api.example.net"), token]), None).unwrap_err();
        assert!(error.contains(CA_FILE_VAR), "{error}");
        assert!(resolve(
            &env(&[
                (URL_VAR, "https://api.example.net"),
                token,
                (CA_FILE_VAR, "/ca.pem")
            ]),
            None
        )
        .is_ok());
    }

    #[test]
    fn profiles_are_read_and_the_environment_wins() {
        let mut fake = env(&[(CONFIG_VAR, "/cli.json"), (TOKEN_VAR, "wnm_env")]);
        fake.files.insert(
            PathBuf::from("/cli.json"),
            r#"{"default_profile":"lab","profiles":{
                "lab":{"url":"http://127.0.0.1:9000","token":"wnm_file"},
                "prod":{"url":"https://api.example.net","ca_file":"/ca.pem","token":"wnm_prod"}}}"#
                .to_string(),
        );
        let lab = resolve(&fake, None).unwrap();
        assert_eq!(lab.base.port, 9000);
        assert_eq!(lab.token, "wnm_env", "the environment overrides the file");
        let prod = resolve(&fake, Some("prod")).unwrap();
        assert_eq!(prod.base.host, "api.example.net");
        assert!(resolve(&fake, Some("missing")).is_err());
    }

    #[test]
    fn errors_and_debug_never_show_the_token() {
        let fake = env(&[(URL_VAR, "http://10.0.0.5"), (TOKEN_VAR, "wnm_secret")]);
        assert!(!resolve(&fake, None).unwrap_err().contains("wnm_secret"));
        let ok = resolve(
            &env(&[(URL_VAR, "http://127.0.0.1"), (TOKEN_VAR, "wnm_secret")]),
            None,
        )
        .unwrap();
        assert!(!format!("{ok:?}").contains("wnm_secret"));
    }
}
