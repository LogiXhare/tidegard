//! The mitigator (Phase 7, ADRs 0048 and 0049): the only code in
//! WetechiNetMon that speaks to GoBGP. It carries approved mitigations to
//! GoBGP and takes them down again, under the safety guard, and it never
//! approves anything itself.

/// GoBGP's API, generated from the vendored `.proto` files.
#[allow(clippy::all, clippy::pedantic, missing_docs, rustdoc::all)]
pub mod api {
    tonic::include_proto!("api");
}

pub mod config;
pub mod gobgp;
pub mod metrics;
pub mod route;
pub mod service;

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wetechinetmon_incident::authorization::{Actor, AuthorizationContext, Permission};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::mitigation::MitigationStore;
use wetechinetmon_incident_postgres::platform::PlatformAuthority;

pub use config::Config;

/// How long to wait after a database or GoBGP error.
const ERROR_WAIT: Duration = Duration::from_secs(5);
/// The advisory lock that keeps a second mitigator from acting alongside
/// the first: one writer to GoBGP per installation.
pub const SINGLE_MITIGATOR_LOCK: i64 = 0x574E_4D00_0007;

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("metrics: {0}")]
    Metrics(#[from] prometheus::Error),
    #[error("the incident database cannot be used: {0}")]
    Database(String),
    #[error("GoBGP cannot be used: {0}")]
    GoBgp(#[from] gobgp::GoBgpError),
}

/// The mitigator's cross-tenant authority, as the notifier's: a platform
/// actor holding `PlatformIncidentAdmin` and nothing else.
pub fn platform_authority() -> PlatformAuthority {
    let context = AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Platform {
            id: "mitigator".to_string(),
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
    let (metrics, registry) = metrics::MitigatorMetrics::new()?;
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

    tokio::pin!(shutdown);
    // One mitigator acts at a time; another waits here as a standby. The
    // lock lives as long as this connection.
    let lock = loop {
        match wetechinetmon_incident_postgres::pool::acquire(&pool).await {
            Ok(client) => {
                let held: bool = client
                    .query_one("SELECT pg_try_advisory_lock($1)", &[&SINGLE_MITIGATOR_LOCK])
                    .await
                    .map_err(|e| StartupError::Database(e.to_string()))?
                    .get(0);
                if held {
                    break client;
                }
                tracing::info!("another mitigator is active; waiting as a standby");
            }
            Err(error) => tracing::warn!(error = %error, "the database is unavailable"),
        }
        tokio::select! {
            () = &mut shutdown => {
                server.abort();
                return Ok(());
            }
            () = tokio::time::sleep(ERROR_WAIT) => {}
        }
    };

    let guard = config.guard.clone();
    // With BGP disabled there is no connection to GoBGP at all.
    let gobgp = if guard.config().bgp_enabled {
        Some(gobgp::GoBgp::connect(&config.file.gobgp).await?)
    } else {
        None
    };
    tracing::info!(
        bgp_enabled = guard.config().bgp_enabled,
        dry_run = guard.effective_dry_run(),
        allowlisted = guard.config().allowlist.len(),
        "the mitigator is active"
    );
    let store = MitigationStore::new(Arc::new(UuidV7IncidentGenerator::new()), Arc::new(guard));
    let mut mitigator = service::Mitigator::new(
        config.consumer_id.clone(),
        store,
        config.file.routes.clone(),
        config.file.proposals.clone(),
        platform_authority(),
        gobgp,
        metrics,
    );
    let reconcile_every = config.file.reconcile_interval();
    // Reconcile at start: a restart may have left routes behind or lost them.
    let mut next_reconcile = Instant::now();
    loop {
        if mitigator.has_bgp() && Instant::now() >= next_reconcile {
            match mitigator.reconcile(&pool).await {
                Ok(report) => tracing::debug!(?report, "reconciled"),
                Err(error) => tracing::warn!(error = %error, "reconciliation failed"),
            }
            if let Err(error) = mitigator.check_peers().await {
                tracing::warn!(error = %error, "GoBGP's peers could not be listed");
            }
            next_reconcile = Instant::now() + reconcile_every;
        }
        let wait = match mitigator.run_once(&pool).await {
            Ok(_) => config.file.poll_interval(),
            Err(error) => {
                tracing::warn!(error = %error, "a mitigator pass failed");
                ERROR_WAIT
            }
        };
        tokio::select! {
            () = &mut shutdown => break,
            () = tokio::time::sleep(wait) => {}
        }
    }
    drop(lock);
    server.abort();
    Ok(())
}
