//! WetechiNetMon Incident Manager (Milestone 5C, ADR 0036).
//!
//! The process that owns the incident lifecycle in the background:
//!
//! - **The correlation worker** claims detection events from the inbox the
//!   collector fills (ADR 0035) and ingests each into an incident.
//! - **The timers** ([`run_maintenance`]) move silent incidents to
//!   `Recovering`, confirm recovery, and close resolved incidents when the
//!   closure policy allows it.
//! - **Retention** purges what the retention table says may go.
//! - **Depth gauges** for the inbox and the outbox.
//!
//! Every job runs under the process's own [`PlatformAuthority`]. Nothing
//! here notifies anyone or mitigates anything: the outbox is filled, and its
//! consumers are later phases.
//!
//! **Shutdown.** The worker finishes the batch in flight and claims
//! nothing more (ADR 0012); a scheduled job in progress finishes, and no
//! new one starts.

pub mod config;
pub mod database;
pub mod metrics;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use wetechinetmon_common::metrics_server::Readiness;
use wetechinetmon_incident::authorization::{Actor, AuthorizationContext, Permission};
use wetechinetmon_incident::clock::SystemClock;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident_postgres::id::UuidV7IncidentGenerator;
use wetechinetmon_incident_postgres::inbox::{inbox_stats, InboxPolicy, InboxWorker, WorkerReport};
use wetechinetmon_incident_postgres::maintenance::{
    run_maintenance, timeline_pressure, MaintenancePolicy,
};
use wetechinetmon_incident_postgres::outbox::outbox_stats;
use wetechinetmon_incident_postgres::platform::PlatformAuthority;
use wetechinetmon_incident_postgres::pool::acquire;
use wetechinetmon_incident_postgres::retention::{run_retention, RetentionPolicy};
use wetechinetmon_incident_postgres::service::IncidentPersistence;

pub use config::Config;
pub use metrics::ManagerMetrics;

use crate::database::DatabaseError;
use crate::metrics::Job;

/// The process's own identity for cross-tenant work.
pub const PLATFORM_ACTOR_ID: &str = "incident-manager";

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("metrics could not be registered: {0}")]
    Metrics(#[from] prometheus::Error),
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

/// What one [`run`] did, for the shutdown log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunReport {
    pub migrations_applied: usize,
    pub worker: WorkerReport,
}

/// The authority every job runs under: a platform actor holding
/// `PlatformIncidentAdmin`, and nothing else.
pub fn platform_authority() -> PlatformAuthority {
    let context = AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Platform {
            id: PLATFORM_ACTOR_ID.to_string(),
        },
        vec![Permission::PlatformIncidentAdmin],
    );
    PlatformAuthority::from_context(&context).expect("the context holds PlatformIncidentAdmin")
}

/// Everything the jobs share.
struct Context {
    pool: Pool,
    service: IncidentPersistence,
    authority: PlatformAuthority,
    metrics: ManagerMetrics,
    maintenance: MaintenancePolicy,
    retention: RetentionPolicy,
}

/// Runs the manager until `shutdown` completes. A startup error (the
/// database cannot be reached or migrated) is returned at once; after
/// startup, database errors are logged, counted and retried, never fatal.
pub async fn run(
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<RunReport, StartupError> {
    let (metrics, registry) = ManagerMetrics::new()?;
    let registry = Arc::new(registry);
    let metrics_bind = config.metrics_bind;
    let readiness = Readiness::new();
    let served = readiness.clone();
    let metrics_server = tokio::spawn(async move {
        if let Err(error) =
            wetechinetmon_common::metrics_server::serve(metrics_bind, registry, served).await
        {
            tracing::error!(error = %error, "metrics server exited with an error");
        }
    });
    let result = run_with_metrics(config, metrics, readiness, shutdown).await;
    metrics_server.abort();
    result
}

async fn run_with_metrics(
    config: Config,
    metrics: ManagerMetrics,
    readiness: Readiness,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<RunReport, StartupError> {
    let (pool, transport) = database::connect(&config)?;
    match transport {
        database::Transport::VerifiedTls => {
            tracing::info!("database connections use verified TLS")
        }
        database::Transport::LoopbackPlaintext => tracing::warn!(
            "no CA file configured: database connections are plaintext, which is allowed \
             only because the connection string reaches this host alone"
        ),
    }
    let mut report = RunReport::default();
    if config.migrate {
        report.migrations_applied = database::migrate(&pool).await?;
        tracing::info!(
            applied = report.migrations_applied,
            "database migrations are up to date"
        );
    }

    let context = Context {
        pool,
        service: IncidentPersistence::new(
            Arc::new(UuidV7IncidentGenerator::new()),
            Arc::new(SystemClock),
        ),
        authority: platform_authority(),
        metrics,
        maintenance: MaintenancePolicy::documented_default(),
        retention: RetentionPolicy::engineering_default(),
    };

    // One shutdown future in, a receiver per loop out.
    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });

    let worker = InboxWorker::new(
        &context.authority,
        config.worker_id.clone(),
        InboxPolicy::starting_default(),
    );
    tracing::info!(worker_id = %config.worker_id, "correlation worker started");
    let (worker_report, ()) = tokio::join!(
        worker.run_observed(
            &context.service,
            &context.pool,
            config.worker_idle,
            stopped(stop_rx.clone()),
            |outcome| {
                // Ready while correlation batches succeed (ADR 0052).
                readiness.set(outcome.is_ok());
                observe_batch(&context.metrics, outcome);
            },
        ),
        housekeeping(&context, &config, stopped(stop_rx)),
    );
    report.worker = worker_report;
    Ok(report)
}

/// Resolves once a stop is signalled, or once the sender is gone.
async fn stopped(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

fn observe_batch(
    metrics: &ManagerMetrics,
    outcome: Result<
        &wetechinetmon_incident_postgres::inbox::BatchReport,
        &wetechinetmon_incident_postgres::error::PersistError,
    >,
) {
    match outcome {
        Ok(batch) => {
            metrics.record_batch(batch);
            if batch.claimed > 0 {
                tracing::debug!(
                    claimed = batch.claimed,
                    processed = batch.processed,
                    retrying = batch.retrying,
                    dead_lettered = batch.dead_lettered,
                    lease_lost = batch.lease_lost,
                    "correlation batch done"
                );
            }
            if batch.dead_lettered > 0 {
                tracing::warn!(
                    dead_lettered = batch.dead_lettered,
                    "detection events dead-lettered; see detection_event_inbox"
                );
            }
            if batch.clock_skew > 0 {
                // ADR 0031: recurring skew must be visible, not only
                // discoverable from timestamps afterwards.
                tracing::warn!(
                    clock_skew = batch.clock_skew,
                    "detection events refused because the decision time ran backward"
                );
            }
        }
        Err(error) => {
            metrics.record_failed_batch();
            tracing::warn!(error = %error, "correlation batch failed; backing off");
        }
    }
}

/// The scheduled jobs. Each interval's first tick fires at once, so a
/// fresh start refreshes the gauges and catches up on overdue timers
/// immediately.
async fn housekeeping(context: &Context, config: &Config, stop: impl Future<Output = ()>) {
    let mut stats = schedule(config.stats_interval);
    let mut maintenance = schedule(config.maintenance_interval);
    let mut retention = schedule(config.retention_interval);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            biased;
            () = &mut stop => break,
            _ = stats.tick() => {
                let ok = refresh_stats(context).await;
                context.metrics.record_job(Job::Stats, ok);
            }
            _ = maintenance.tick() => {
                let ok = maintain(context).await;
                context.metrics.record_job(Job::Maintenance, ok);
            }
            _ = retention.tick() => {
                let ok = retain(context).await;
                context.metrics.record_job(Job::Retention, ok);
            }
        }
    }
    tracing::info!("scheduled jobs stopped");
}

/// A slow job delays the next tick rather than bunching missed ones up.
fn schedule(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

async fn refresh_stats(context: &Context) -> bool {
    let result = async {
        let client = acquire(&context.pool).await?;
        let inbox = inbox_stats(&context.authority, &**client).await?;
        let outbox = outbox_stats(&context.authority, &**client).await?;
        let pressure = timeline_pressure(&context.authority, &**client).await?;
        Ok::<_, wetechinetmon_incident_postgres::error::PersistError>((inbox, outbox, pressure))
    }
    .await;
    match result {
        Ok((inbox, outbox, pressure)) => {
            context.metrics.record_stats(&inbox, &outbox, pressure);
            true
        }
        Err(error) => {
            tracing::warn!(error = %error, "the incident statistics could not be read");
            false
        }
    }
}

async fn maintain(context: &Context) -> bool {
    let result = async {
        let mut client = acquire(&context.pool).await?;
        run_maintenance(
            &context.authority,
            &context.service,
            &mut client,
            &context.maintenance,
        )
        .await
    }
    .await;
    match result {
        Ok(report) => {
            context.metrics.record_maintenance(&report);
            if report.entered_recovering + report.resolved + report.closed + report.failed > 0 {
                tracing::info!(
                    entered_recovering = report.entered_recovering,
                    resolved = report.resolved,
                    closed = report.closed,
                    not_due = report.not_due,
                    failed = report.failed,
                    "incident timers ran"
                );
            }
            true
        }
        Err(error) => {
            tracing::warn!(error = %error, "incident timers could not run");
            false
        }
    }
}

async fn retain(context: &Context) -> bool {
    let result = async {
        let client = acquire(&context.pool).await?;
        run_retention(&context.authority, &**client, &context.retention).await
    }
    .await;
    match result {
        Ok(report) => {
            context.metrics.record_retention(&report);
            tracing::info!(
                expired_idempotency = report.expired_idempotency,
                published_outbox = report.published_outbox,
                processed_inbox = report.processed_inbox,
                reviewed_dead_letter = report.reviewed_dead_letter,
                closed_incidents = report.closed_incidents,
                "retention ran"
            );
            true
        }
        Err(error) => {
            tracing::warn!(error = %error, "retention could not run");
            false
        }
    }
}

/// Resolves on Ctrl+C or, on Unix, SIGTERM (what systemd and container
/// runtimes send).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "SIGTERM handler unavailable; Ctrl+C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutdown requested");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_authority_is_the_manager_itself() {
        let authority = platform_authority();
        assert!(matches!(
            authority.actor(),
            Actor::Platform { id } if id == PLATFORM_ACTOR_ID
        ));
    }

    #[tokio::test]
    async fn a_dropped_sender_counts_as_a_stop() {
        let (tx, rx) = watch::channel(false);
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), stopped(rx))
            .await
            .expect("resolves at once");
    }
}
