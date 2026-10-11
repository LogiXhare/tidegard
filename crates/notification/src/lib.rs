//! The WetechiNetMon notifier (Phase 6E, ADR 0045): the incident outbox's
//! first consumer. It tells people about incidents by webhook, Slack,
//! Microsoft Teams and Telegram, and records every attempt on the
//! incident's timeline.
//!
//! It never mitigates, and nothing in the detector or the incident domain
//! depends on it: the dependency closure test proves both.

pub mod config;
pub mod destination;
pub mod hmac;
pub mod http;
pub mod limits;
pub mod message;
pub mod metrics;
pub mod worker;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use wetechinetmon_incident::authorization::{Actor, AuthorizationContext, Permission};
use wetechinetmon_incident::clock::SystemClock;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::outbox::{OutboxConsumer, OutboxPolicy};
use wetechinetmon_incident_postgres::platform::PlatformAuthority;
use wetechinetmon_incident_postgres::service::IncidentPersistence;

pub use config::Config;

/// How long to wait when a batch was empty.
const IDLE_WAIT: Duration = Duration::from_secs(2);
/// How long to wait after a database error.
const ERROR_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("metrics: {0}")]
    Metrics(#[from] prometheus::Error),
    #[error("the incident database cannot be used: {0}")]
    Database(String),
    #[error("a channel cannot be used: {0}")]
    Channel(String),
}

/// The outbox consumer's authority: a platform actor holding
/// `PlatformIncidentAdmin` and nothing else, as the incident manager's jobs.
pub fn platform_authority() -> PlatformAuthority {
    let context = AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Platform {
            id: "notifier".to_string(),
        },
        vec![Permission::PlatformIncidentAdmin],
    );
    PlatformAuthority::from_context(&context).expect("the context holds PlatformIncidentAdmin")
}

/// Runs until `shutdown` resolves.
pub async fn run(
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), StartupError> {
    let (metrics, registry) = metrics::NotifierMetrics::new()?;
    let registry = Arc::new(registry);
    let bind = config.metrics_bind;
    let server = tokio::spawn(async move {
        if let Err(error) = wetechinetmon_common::metrics_server::serve(bind, registry).await {
            tracing::error!(error = %error, "the metrics server stopped");
        }
    });
    let tls = wetechinetmon_incident_postgres::connect::TlsFiles::from_paths(
        config.database_ca_file.clone(),
        None,
        None,
    )
    .map_err(|detail| StartupError::Database(detail.to_string()))?;
    let (pool, _) = wetechinetmon_incident_postgres::connect::connect(
        &config.database_url,
        tls.as_ref(),
        wetechinetmon_incident_postgres::pool::PoolPolicy::starting_default(),
    )
    .map_err(|error| StartupError::Database(error.to_string()))?;
    let platform = platform_authority();
    let consumer = OutboxConsumer::new(
        &platform,
        config.consumer_id.clone(),
        OutboxPolicy::default(),
    );
    let service = IncidentPersistence::new(
        Arc::new(UuidV7IncidentGenerator::new()),
        Arc::new(SystemClock),
    );
    let mut notifier = worker::Notifier::new(
        config.consumer_id.clone(),
        consumer,
        service,
        config.file.clone(),
        config.dedup,
        metrics,
    )
    .map_err(StartupError::Channel)?;

    tokio::pin!(shutdown);
    loop {
        let wait = match notifier.run_once(&pool).await {
            Ok(report) if report.claimed == 0 => IDLE_WAIT,
            Ok(_) => Duration::ZERO,
            Err(error) => {
                tracing::warn!(error = %error, "a notifier batch failed");
                ERROR_WAIT
            }
        };
        tokio::select! {
            () = &mut shutdown => break,
            () = tokio::time::sleep(wait) => {}
        }
    }
    server.abort();
    Ok(())
}
