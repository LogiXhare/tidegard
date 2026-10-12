//! The notifier's work (ADR 0045): claim outbox messages, decide who hears
//! of each, deliver, record each attempt on the incident's timeline, and
//! mark the message published or failed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use deadpool_postgres::Pool;
use tokio_rustls::TlsConnector;
use wetechinetmon_incident::authorization::AuthorizationContext;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::id::IncidentId;
use wetechinetmon_incident::timeline::NotificationOutcome;
use wetechinetmon_incident_postgres::error::PersistError;
use wetechinetmon_incident_postgres::outbox::{ClaimedMessage, FailureOutcome, OutboxConsumer};
use wetechinetmon_incident_postgres::pool::acquire;
use wetechinetmon_incident_postgres::queries;
use wetechinetmon_incident_postgres::row::IncidentRow;
use wetechinetmon_incident_postgres::service::IncidentPersistence;

use crate::config::{channels_for, ChannelKind, ChannelSpec, File};
use crate::destination::{self, Target};
use crate::http::{self, Sent};
use crate::limits::{Dedup, RateLimit};
use crate::message::{self, Notice};
use crate::metrics::NotifierMetrics;

const DEFAULT_TELEGRAM_API: &str = "https://api.telegram.org";
/// Outbox messages whose per-channel progress is remembered across retries.
const REMEMBERED_MESSAGES: usize = 10_000;

/// A channel, ready to send: its secrets read, its URL parsed.
pub struct Channel {
    pub name: String,
    pub kind: ChannelKind,
    target: Target,
    secret: Option<Vec<u8>>,
    chat_id: Option<String>,
    allow_private: bool,
    /// Set for an email channel; `target` then names its relay.
    email: Option<crate::email::Email>,
}

/// What one delivery came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Delivered,
    /// Worth retrying: a timeout, a connection failure, a 429 or a 5xx.
    Transient(String),
    /// Not worth retrying: a 4xx.
    Permanent(String),
    /// The destination failed the SSRF checks.
    Refused(String),
}

fn read_secret(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|text| text.trim().to_string())
        .map_err(|error| format!("{}: {error}", path.display()))
}

impl Channel {
    pub fn load(name: &str, spec: &ChannelSpec, ca_file: &std::path::Path) -> Result<Self, String> {
        let at = |detail: String| format!("channel {name}: {detail}");
        if spec.kind == ChannelKind::Email {
            let email = crate::email::Email::load(spec, ca_file).map_err(at)?;
            let host = spec.smtp_host.clone().unwrap_or_default();
            let port = spec
                .smtp_port
                .unwrap_or_else(|| crate::email::Email::default_port(spec.smtp_tls));
            // The relay is vetted like any destination; the scheme only
            // says whether TLS protects it.
            let scheme = if spec.smtp_tls == crate::config::SmtpTls::None {
                destination::Scheme::Http
            } else {
                destination::Scheme::Https
            };
            return Ok(Channel {
                name: name.to_string(),
                kind: spec.kind,
                target: Target {
                    scheme,
                    host: host.to_ascii_lowercase(),
                    port,
                    path: "/".into(),
                },
                secret: None,
                chat_id: None,
                allow_private: spec.allow_private,
                email: Some(email),
            });
        }
        let url = match (spec.kind, &spec.url, &spec.url_file) {
            (ChannelKind::Telegram, _, _) => {
                let token = read_secret(spec.bot_token_file.as_deref().ok_or("no bot token")?)
                    .map_err(at)?;
                let base = spec.api_base.as_deref().unwrap_or(DEFAULT_TELEGRAM_API);
                format!("{}/bot{token}/sendMessage", base.trim_end_matches('/'))
            }
            (_, Some(url), None) => url.clone(),
            (_, None, Some(file)) => read_secret(file).map_err(at)?,
            _ => return Err(at("needs exactly one of url and url_file".into())),
        };
        let target = destination::parse(&url).map_err(|refusal| at(refusal.to_string()))?;
        let secret = match &spec.secret_file {
            Some(file) => Some(read_secret(file).map_err(at)?.into_bytes()),
            None => None,
        };
        Ok(Channel {
            name: name.to_string(),
            kind: spec.kind,
            target,
            secret,
            chat_id: spec.chat_id.clone(),
            allow_private: spec.allow_private,
            email: None,
        })
    }

    fn body(&self, notice: &Notice) -> serde_json::Value {
        match self.kind {
            ChannelKind::Webhook => message::webhook(notice),
            ChannelKind::Slack => message::slack(notice),
            ChannelKind::Teams => message::teams(notice),
            ChannelKind::Telegram => {
                message::telegram(notice, self.chat_id.as_deref().unwrap_or(""))
            }
            ChannelKind::Email => serde_json::Value::Null,
        }
    }

    /// Vets the destination and posts `notice` to it.
    pub async fn deliver(
        &self,
        notice: &Notice,
        allowed_hosts: &[String],
        tls: Option<&TlsConnector>,
    ) -> Delivery {
        let address = match destination::vet(&self.target, allowed_hosts, self.allow_private).await
        {
            Ok(address) => address,
            Err(refusal) => return Delivery::Refused(refusal.to_string()),
        };
        if let Some(email) = &self.email {
            return match email.send(address, notice).await {
                Ok(()) => Delivery::Delivered,
                Err(crate::email::Failure::Transient(detail)) => Delivery::Transient(detail),
                Err(crate::email::Failure::Permanent(detail)) => Delivery::Permanent(detail),
            };
        }
        let body = self.body(notice).to_string().into_bytes();
        let mut headers = Vec::new();
        if let (ChannelKind::Webhook, Some(secret)) = (self.kind, &self.secret) {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            headers.push(("x-wnm-timestamp", timestamp.to_string()));
            headers.push((
                "x-wnm-signature",
                crate::hmac::signature(secret, timestamp, &body),
            ));
        }
        match http::post(&self.target, address, tls, &headers, body).await {
            Sent::Status(status) if status.is_success() => Delivery::Delivered,
            Sent::Status(status) if status.is_server_error() || status.as_u16() == 429 => {
                Delivery::Transient(format!("status {}", status.as_u16()))
            }
            Sent::Status(status) => Delivery::Permanent(format!("status {}", status.as_u16())),
            Sent::Failed(detail) => Delivery::Transient(detail),
        }
    }
}

/// What one batch did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchReport {
    pub claimed: usize,
    pub published: usize,
    pub retrying: usize,
    pub dead_lettered: usize,
    pub delivered: usize,
    pub failed: usize,
    pub refused: usize,
    pub duplicates: usize,
    pub rate_limited: usize,
}

pub struct Notifier {
    consumer_id: String,
    consumer: OutboxConsumer,
    service: IncidentPersistence,
    channels: BTreeMap<String, Channel>,
    file: File,
    tls: Option<TlsConnector>,
    dedup: Dedup,
    rate: RateLimit,
    /// For each message, the channels that already have it, so a retry
    /// sends only to the ones that failed.
    done: HashMap<i64, BTreeSet<String>>,
    metrics: NotifierMetrics,
}

impl Notifier {
    pub fn new(
        consumer_id: String,
        consumer: OutboxConsumer,
        service: IncidentPersistence,
        file: File,
        dedup_window: std::time::Duration,
        metrics: NotifierMetrics,
    ) -> Result<Self, String> {
        let channels = file
            .channels
            .iter()
            .map(|(name, spec)| {
                Channel::load(name, spec, &file.ca_file).map(|channel| (name.clone(), channel))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let needs_tls = channels.values().any(|channel| {
            channel.email.is_none() && channel.target.scheme == destination::Scheme::Https
        });
        let tls = if needs_tls {
            Some(http::connector(&file.ca_file)?)
        } else {
            None
        };
        Ok(Notifier {
            consumer_id,
            consumer,
            service,
            dedup: Dedup::new(dedup_window),
            rate: RateLimit::new(file.rate_limit_per_minute),
            channels,
            file,
            tls,
            done: HashMap::new(),
            metrics,
        })
    }

    /// Claims one batch and handles every message in it.
    pub async fn run_once(&mut self, pool: &Pool) -> Result<BatchReport, PersistError> {
        let mut client = acquire(pool).await?;
        let messages = self.consumer.claim(&**client).await?;
        let mut report = BatchReport {
            claimed: messages.len(),
            ..BatchReport::default()
        };
        for message in messages {
            let transient = self.handle(&mut client, &message, &mut report).await?;
            match transient {
                None => {
                    self.consumer
                        .mark_published(&**client, message.outbox_id)
                        .await?;
                    self.done.remove(&message.outbox_id);
                    report.published += 1;
                }
                Some(detail) => {
                    match self
                        .consumer
                        .mark_failed(&mut client, message.outbox_id, &detail)
                        .await?
                    {
                        FailureOutcome::DeadLettered { .. } => {
                            self.done.remove(&message.outbox_id);
                            report.dead_lettered += 1;
                        }
                        _ => report.retrying += 1,
                    }
                }
            }
        }
        self.metrics.record(&report);
        Ok(report)
    }

    /// Delivers one message. `Some` names why it must be retried.
    async fn handle(
        &mut self,
        client: &mut tokio_postgres::Client,
        message: &ClaimedMessage,
        report: &mut BatchReport,
    ) -> Result<Option<String>, PersistError> {
        if message.aggregate_type != "incident" {
            return Ok(None);
        }
        let Ok(incident_id) = IncidentId::parse(&message.aggregate_id) else {
            return Ok(None);
        };
        let auth = AuthorizationContext::notifier(
            TenantId::new(message.tenant_id.clone()),
            &self.consumer_id,
        );
        // Retention may have removed the incident since the message was
        // written; then there is no one to tell about it.
        let Ok(incident) = queries::get_incident(client, &auth, &incident_id).await? else {
            return Ok(None);
        };
        let row = IncidentRow::from_incident(&incident)?;
        let channels: Vec<String> = channels_for(
            &self.file,
            &message.tenant_id,
            &message.event_type,
            &row.severity,
        )
        .into_iter()
        .map(String::from)
        .collect();
        if channels.is_empty() {
            return Ok(None);
        }
        let notice = Notice {
            event_type: message.event_type.clone(),
            tenant: row.tenant_id.clone(),
            incident_id: row.incident_id.clone(),
            incident_number: row.incident_number.clone(),
            title: row.title.clone(),
            severity: row.severity.clone(),
            state: row.state.clone(),
            priority: row.priority.clone(),
            target: row
                .target_addr
                .clone()
                .or_else(|| row.target_network.clone())
                .or_else(|| row.target_hostgroup.clone())
                .unwrap_or_default(),
            direction: row.direction.clone(),
            link: self.file.ui_base_url.as_ref().map(|base| {
                format!(
                    "{}/incidents/{}",
                    base.trim_end_matches('/'),
                    row.incident_id
                )
            }),
        };

        let mut transient: Vec<String> = Vec::new();
        for name in channels {
            if self
                .done
                .get(&message.outbox_id)
                .is_some_and(|done| done.contains(&name))
            {
                continue;
            }
            let Some(channel) = self.channels.get(&name) else {
                continue;
            };
            let now = Instant::now();
            if self
                .dedup
                .is_duplicate(&name, &row.incident_id, &message.event_type, now)
            {
                report.duplicates += 1;
                continue;
            }
            if !self.rate.take(&name, now) {
                report.rate_limited += 1;
                tracing::warn!(channel = %name, "a notification was dropped: the channel's rate limit is reached");
                continue;
            }
            let delivery = channel
                .deliver(&notice, &self.file.allowed_hosts, self.tls.as_ref())
                .await;
            let (outcome, done) = match &delivery {
                Delivery::Delivered => {
                    report.delivered += 1;
                    self.dedup
                        .record(&name, &row.incident_id, &message.event_type, now);
                    (NotificationOutcome::Delivered, true)
                }
                Delivery::Transient(detail) => {
                    report.failed += 1;
                    tracing::warn!(channel = %name, detail = %detail, "a notification failed and will be retried");
                    transient.push(format!("{name}: {detail}"));
                    (NotificationOutcome::Failed, false)
                }
                Delivery::Permanent(detail) | Delivery::Refused(detail) => {
                    report.refused += 1;
                    tracing::warn!(channel = %name, detail = %detail, "a notification was refused");
                    (NotificationOutcome::Refused, true)
                }
            };
            if done {
                if self.done.len() >= REMEMBERED_MESSAGES {
                    self.done.clear();
                }
                self.done
                    .entry(message.outbox_id)
                    .or_default()
                    .insert(name.clone());
            }
            if let Err(error) = self
                .service
                .record_notification_result(
                    client,
                    &auth,
                    incident_id,
                    &name,
                    &message.event_type,
                    outcome,
                )
                .await?
            {
                tracing::warn!(error = %error, "a notification result could not be recorded");
            }
        }
        Ok((!transient.is_empty()).then(|| transient.join("; ")))
    }
}
