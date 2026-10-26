//! Milestone 6E-2: the email channel against a mock SMTP relay on loopback.
//! Nothing leaves the machine, and no database is needed.

use std::sync::{Arc, Mutex};

use tidegard_notification::config::parse_file;
use tidegard_notification::message::Notice;
use tidegard_notification::worker::{Channel, Delivery};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Speaks just enough SMTP to accept one message, and records it.
async fn relay(transcript: Arc<Mutex<Vec<String>>>, refuse_recipients: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let transcript = transcript.clone();
            tokio::spawn(async move {
                let (read, mut write) = socket.into_split();
                let mut lines = BufReader::new(read).lines();
                write.write_all(b"220 mock ESMTP\r\n").await.unwrap();
                let mut in_data = false;
                while let Ok(Some(line)) = lines.next_line().await {
                    transcript.lock().unwrap().push(line.clone());
                    let reply: &[u8] = if in_data {
                        if line == "." {
                            in_data = false;
                            b"250 queued\r\n"
                        } else {
                            continue;
                        }
                    } else {
                        let verb = line.split(' ').next().unwrap_or("").to_ascii_uppercase();
                        match verb.as_str() {
                            "EHLO" | "HELO" => b"250-mock\r\n250 8BITMIME\r\n",
                            "MAIL" => b"250 ok\r\n",
                            "RCPT" if refuse_recipients => b"550 no such user\r\n",
                            "RCPT" => b"250 ok\r\n",
                            "DATA" => {
                                in_data = true;
                                b"354 go ahead\r\n"
                            }
                            "QUIT" => {
                                let _ = write.write_all(b"221 bye\r\n").await;
                                return;
                            }
                            _ => b"250 ok\r\n",
                        }
                    };
                    if write.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

fn channel(port: u16) -> Channel {
    let file = parse_file(&format!(
        r#"{{
            "channels": {{
                "noc-mail": {{"kind": "email", "smtp_host": "127.0.0.1", "smtp_port": {port},
                              "smtp_tls": "none", "allow_private": true,
                              "from": "Tidegard <noc@example.net>",
                              "to": ["oncall@example.net", "lead@example.net"]}}
            }},
            "routes": [],
            "allowed_hosts": ["127.0.0.1"],
            "ca_file": "/nonexistent/unused-for-plain-smtp.pem"
        }}"#
    ))
    .unwrap();
    Channel::load("noc-mail", &file.channels["noc-mail"], &file.ca_file).unwrap()
}

fn notice(title: &str) -> Notice {
    Notice {
        event_type: "incident.opened".into(),
        tenant: "acme".into(),
        incident_id: "0192f3c4-0000-7000-8000-000000000001".into(),
        incident_number: "WNM-2026-000001".into(),
        title: title.into(),
        severity: "critical".into(),
        state: "open".into(),
        priority: "P1".into(),
        target: "203.0.113.10".into(),
        direction: "incoming".into(),
        mitigation_status: "none".into(),
        link: Some("https://noc.example.net/incidents/0192f3c4".into()),
    }
}

#[tokio::test]
async fn an_email_reaches_the_relay_with_one_subject_and_no_injected_header() {
    let transcript = Arc::new(Mutex::new(Vec::new()));
    let port = relay(transcript.clone(), false).await;
    let allowed = vec!["127.0.0.1".to_string()];
    let delivery = channel(port)
        .deliver(
            &notice("UDP flood\r\nBcc: attacker@evil.example"),
            &allowed,
            None,
        )
        .await;
    assert_eq!(delivery, Delivery::Delivered);

    let lines = transcript.lock().unwrap().clone();
    let rcpt: Vec<&String> = lines.iter().filter(|l| l.starts_with("RCPT TO:")).collect();
    assert_eq!(
        rcpt.len(),
        2,
        "exactly the configured recipients: {lines:?}"
    );
    assert!(!lines
        .iter()
        .any(|l| l.contains("attacker@evil.example") && l.starts_with("RCPT")));
    let data = lines.join("\n");
    let headers: Vec<&String> = lines
        .iter()
        .skip_while(|l| !l.starts_with("DATA"))
        .skip(1)
        .take_while(|l| !l.is_empty())
        .collect();
    assert!(
        !headers.iter().any(|h| h.starts_with("Bcc:")),
        "{headers:?}"
    );
    assert_eq!(
        headers.iter().filter(|h| h.starts_with("Subject:")).count(),
        1
    );
    assert!(data.contains("Mitigation: none"), "{data}");
}

#[tokio::test]
async fn a_refused_recipient_is_permanent_and_a_dead_relay_is_transient() {
    let transcript = Arc::new(Mutex::new(Vec::new()));
    let port = relay(transcript, true).await;
    let allowed = vec!["127.0.0.1".to_string()];
    let refused = channel(port)
        .deliver(&notice("flood"), &allowed, None)
        .await;
    assert!(matches!(refused, Delivery::Permanent(_)), "{refused:?}");

    // Nothing listens on port 9: a connection failure is worth retrying.
    let down = channel(9).deliver(&notice("flood"), &allowed, None).await;
    assert!(matches!(down, Delivery::Transient(_)), "{down:?}");

    // A relay off the allowlist is refused before any connection.
    let elsewhere = channel(port)
        .deliver(&notice("flood"), &["mail.example.net".into()], None)
        .await;
    assert!(matches!(elsewhere, Delivery::Refused(_)), "{elsewhere:?}");
}
