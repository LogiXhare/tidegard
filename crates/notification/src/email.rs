//! Email over SMTP (ADR 0045, 6E-2), with `lettre`.
//!
//! The relay is vetted like every other destination, and the connection
//! goes to the checked address, while TLS verifies the relay's own name
//! against the configured CA bundle. STARTTLS is required by default; plain
//! SMTP only with `allow_private`, for a relay on the operator's network.
//! Headers are built by `lettre`, which encodes them, so an untrusted title
//! in the subject cannot add a header or a recipient.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::{ChannelSpec, SmtpTls};
use crate::message::{clean, Notice};

const TIMEOUT: Duration = Duration::from_secs(10);
const SUBJECT_MAX_CHARS: usize = 200;

/// A ready email channel.
pub struct Email {
    host: String,
    tls: SmtpTls,
    credentials: Option<(String, String)>,
    from: Mailbox,
    to: Vec<Mailbox>,
    ca_pem: Option<Vec<u8>>,
}

/// Why a send failed: worth retrying, or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    Transient(String),
    Permanent(String),
}

impl Email {
    pub fn load(spec: &ChannelSpec, ca_file: &Path) -> Result<Self, String> {
        let host = spec.smtp_host.clone().ok_or("no smtp_host")?;
        let mailbox = |text: &str| {
            text.parse::<Mailbox>()
                .map_err(|_| format!("{text:?} is not an email address"))
        };
        let from = mailbox(spec.from.as_deref().ok_or("no from")?)?;
        let to = spec
            .to
            .iter()
            .map(|address| mailbox(address))
            .collect::<Result<Vec<_>, _>>()?;
        let credentials = match (&spec.username, &spec.password_file) {
            (Some(user), Some(file)) => {
                let password = std::fs::read_to_string(file)
                    .map_err(|error| format!("{}: {error}", file.display()))?
                    .trim()
                    .to_string();
                Some((user.clone(), password))
            }
            _ => None,
        };
        let ca_pem = match spec.smtp_tls {
            SmtpTls::None => None,
            _ => Some(
                std::fs::read(ca_file)
                    .map_err(|error| format!("{}: {error}", ca_file.display()))?,
            ),
        };
        Ok(Email {
            host,
            tls: spec.smtp_tls,
            credentials,
            from,
            to,
            ca_pem,
        })
    }

    /// The relay's port when the file names none.
    pub fn default_port(tls: SmtpTls) -> u16 {
        match tls {
            SmtpTls::Starttls => 587,
            SmtpTls::Implicit => 465,
            SmtpTls::None => 25,
        }
    }

    fn message(&self, notice: &Notice) -> Result<Message, String> {
        let mut builder = Message::builder().from(self.from.clone()).subject(clean(
            &format!("WetechiNetMon {}", notice.headline()),
            SUBJECT_MAX_CHARS,
        ));
        for recipient in &self.to {
            builder = builder.to(recipient.clone());
        }
        builder
            .header(ContentType::TEXT_PLAIN)
            .body(notice.plain_text())
            .map_err(|error| error.to_string())
    }

    fn tls(&self) -> Result<Tls, String> {
        let Some(pem) = &self.ca_pem else {
            return Ok(Tls::None);
        };
        let parameters = TlsParameters::builder(self.host.clone())
            .certificate_store(CertificateStore::None)
            .add_root_certificate(Certificate::from_pem(pem).map_err(|error| error.to_string())?)
            .build_rustls()
            .map_err(|error| error.to_string())?;
        Ok(match self.tls {
            SmtpTls::Starttls => Tls::Required(parameters),
            SmtpTls::Implicit => Tls::Wrapper(parameters),
            SmtpTls::None => Tls::None,
        })
    }

    /// Sends `notice` through the relay at the vetted `address`.
    pub async fn send(&self, address: SocketAddr, notice: &Notice) -> Result<(), Failure> {
        let message = self.message(notice).map_err(Failure::Permanent)?;
        let tls = self.tls().map_err(Failure::Permanent)?;
        let mut builder =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(address.ip().to_string())
                .port(address.port())
                .timeout(Some(TIMEOUT))
                .tls(tls);
        if let Some((user, password)) = &self.credentials {
            builder = builder.credentials(Credentials::new(user.clone(), password.clone()));
        }
        match builder.build().send(message).await {
            Ok(_) => Ok(()),
            Err(error) if error.is_permanent() => Err(Failure::Permanent(error.to_string())),
            Err(error) => Err(Failure::Transient(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(title: &str) -> Notice {
        Notice {
            event_type: "incident.opened".into(),
            tenant: "acme".into(),
            incident_id: "id".into(),
            incident_number: "WNM-2026-000001".into(),
            title: title.into(),
            severity: "major".into(),
            state: "open".into(),
            priority: "P2".into(),
            target: "203.0.113.10".into(),
            direction: "incoming".into(),
            link: None,
        }
    }

    fn email() -> Email {
        Email {
            host: "smtp.example.net".into(),
            tls: SmtpTls::None,
            credentials: None,
            from: "noc@example.net".parse().unwrap(),
            to: vec!["oncall@example.net".parse().unwrap()],
            ca_pem: None,
        }
    }

    #[test]
    fn a_hostile_title_cannot_add_a_header_or_a_recipient() {
        let message = email()
            .message(&notice(
                "flood\r\nBcc: attacker@evil.example\r\nX-Injected: 1",
            ))
            .unwrap();
        let raw = String::from_utf8(message.formatted()).unwrap();
        let headers = raw.split("\r\n\r\n").next().unwrap();
        assert!(
            !headers.lines().any(|line| line.starts_with("Bcc:")),
            "{headers}"
        );
        assert!(
            !headers.lines().any(|line| line.starts_with("X-Injected:")),
            "{headers}"
        );
        assert_eq!(message.envelope().to().len(), 1);
        assert!(raw.contains("Mitigation: none"));
    }

    #[test]
    fn the_default_ports_follow_the_tls_mode() {
        assert_eq!(Email::default_port(SmtpTls::Starttls), 587);
        assert_eq!(Email::default_port(SmtpTls::Implicit), 465);
    }
}
