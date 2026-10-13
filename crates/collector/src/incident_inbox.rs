//! Hands detection events to the incident manager through the PostgreSQL
//! inbox (ADR 0035, ADR 0036). Off unless an incident database is
//! configured.
//!
//! - **The detection tick never waits on the database.** The engine
//!   publishes into a [`TenantRouter`], which only pushes onto a bounded
//!   in-memory queue per tenant. A drain task per tenant writes the queue
//!   to `detection_event_inbox`.
//! - **A full queue refuses the newest event.** The detection metrics
//!   count it under `sink="postgres_inbox"`, as they do for any sink.
//! - **Shutdown flushes.** [`IncidentInbox::shutdown`] stops the queues
//!   accepting and lets each drain make a bounded final write.
//! - **The collector never migrates the incident database.** The incident
//!   manager owns the schema; until it has run, writes fail, are counted,
//!   and are retried.

use std::time::Duration;

use deadpool_postgres::Pool;
use prometheus::core::Collector;
use prometheus::{IntCounter, IntGauge, Registry};
use tidegard_detector::DetectionEventSink;
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::connect::{connect, ConnectError, Transport};
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::producer::{
    inbox_producers, DrainReport, ProducerPolicy, TenantRouter,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::IncidentDatabase;

/// How long shutdown waits for the drains' final writes.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct InboxMetrics {
    queued: IntGauge,
    written_total: IntCounter,
    write_failures_total: IntCounter,
}

impl InboxMetrics {
    fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let metrics = InboxMetrics {
            queued: IntGauge::new(
                "tidegard_collector_incident_inbox_queued",
                "Detection events waiting in memory to be written to the incident inbox.",
            )?,
            written_total: IntCounter::new(
                "tidegard_collector_incident_inbox_written_total",
                "Detection events written to the incident inbox.",
            )?,
            write_failures_total: IntCounter::new(
                "tidegard_collector_incident_inbox_write_failures_total",
                "Failed writes to the incident inbox; each is retried.",
            )?,
        };
        for collector in metrics.collectors() {
            registry.register(collector)?;
        }
        Ok(metrics)
    }
}

/// The incident inbox metrics, by name, for the Grafana dashboard check.
pub(crate) fn metric_names() -> Vec<String> {
    InboxMetrics::new(&Registry::new())
        .expect("a fresh registry has no collisions")
        .metric_names()
}

#[derive(Debug, thiserror::Error)]
pub enum InboxStartError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("incident inbox metrics could not be registered: {0}")]
    Metrics(#[from] prometheus::Error),
    #[error("no detection policy names a tenant, so there is nothing to route")]
    NoTenants,
}

pub struct IncidentInbox {
    router: TenantRouter,
    metrics: InboxMetrics,
    stop: watch::Sender<bool>,
    drains: Vec<JoinHandle<DrainReport>>,
}

impl IncidentInbox {
    /// Builds the pool and starts one drain task per tenant. Nothing
    /// connects until the first write.
    pub fn start(
        database: &IncidentDatabase,
        tenants: impl IntoIterator<Item = String>,
        registry: &Registry,
    ) -> Result<(Self, Transport), InboxStartError> {
        let tenants: Vec<TenantId> = tenants.into_iter().map(TenantId::new).collect();
        if tenants.is_empty() {
            return Err(InboxStartError::NoTenants);
        }
        let (pool, transport) = connect(
            &database.url,
            database.tls.as_ref(),
            PoolPolicy {
                max_size: 2,
                ..PoolPolicy::starting_default()
            },
        )?;
        let metrics = InboxMetrics::new(registry)?;
        let (router, drains) = inbox_producers(tenants, ProducerPolicy::starting_default());
        let (stop, stopped) = watch::channel(false);
        let drains = drains
            .into_iter()
            .map(|mut drain| {
                let pool: Pool = pool.clone();
                let metrics = metrics.clone();
                let mut stopped = stopped.clone();
                tokio::spawn(async move {
                    let tenant = drain.tenant().as_str().to_string();
                    let shutdown = async move {
                        let _ = stopped.wait_for(|stop| *stop).await;
                    };
                    drain
                        .run_observed(&pool, shutdown, |outcome| match outcome {
                            Ok(written) => metrics.written_total.inc_by(written),
                            Err(error) => {
                                metrics.write_failures_total.inc();
                                tracing::warn!(
                                    tenant = %tenant,
                                    error = %error,
                                    "detection events could not be written to the incident inbox; retrying"
                                );
                            }
                        })
                        .await
                })
            })
            .collect();
        Ok((
            IncidentInbox {
                router,
                metrics,
                stop,
                drains,
            },
            transport,
        ))
    }

    /// The sink the detection engine publishes into.
    pub fn sink(&self) -> Box<dyn DetectionEventSink> {
        Box::new(self.router.clone())
    }

    /// Updates the queued gauge. Cheap; called on the detection tick.
    pub fn refresh(&self) {
        self.metrics.queued.set(self.router.queued() as i64);
    }

    /// Stops the queues accepting, waits a bounded time for the final
    /// writes, and returns what every drain wrote and could not write.
    pub async fn shutdown(self) -> DrainReport {
        let _ = self.stop.send(true);
        let mut total = DrainReport::default();
        for drain in self.drains {
            match tokio::time::timeout(SHUTDOWN_GRACE, drain).await {
                Ok(Ok(report)) => {
                    total.enqueued += report.enqueued;
                    total.failed_writes += report.failed_writes;
                    total.abandoned += report.abandoned;
                }
                Ok(Err(error)) => {
                    tracing::error!(error = %error, "an incident inbox drain task failed");
                }
                Err(_) => {
                    tracing::error!("an incident inbox drain did not finish in time");
                }
            }
        }
        self.metrics.queued.set(self.router.queued() as i64);
        total
    }
}

impl InboxMetrics {
    /// Every metric this owns. `new` registers exactly these and
    /// `metric_names` reads them, so `/metrics` and the Grafana dashboard
    /// check (ADR 0041) cannot disagree about what exists.
    fn collectors(&self) -> Vec<Box<dyn Collector>> {
        vec![
            Box::new(self.queued.clone()),
            Box::new(self.written_total.clone()),
            Box::new(self.write_failures_total.clone()),
        ]
    }

    /// The fully qualified name of every metric this owns.
    pub(crate) fn metric_names(&self) -> Vec<String> {
        self.collectors()
            .iter()
            .flat_map(|collector| {
                collector
                    .desc()
                    .into_iter()
                    .map(|desc| desc.fq_name.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database(url: &str) -> IncidentDatabase {
        IncidentDatabase {
            url: url.to_string(),
            tls: None,
        }
    }

    #[tokio::test]
    async fn starts_without_connecting_and_registers_its_metrics() {
        let registry = Registry::new();
        let (inbox, transport) = IncidentInbox::start(
            &database("host=localhost port=1 user=app"),
            ["acme".to_string(), "globex".to_string()],
            &registry,
        )
        .unwrap();
        assert_eq!(transport, Transport::LoopbackPlaintext);
        let names: Vec<String> = registry
            .gather()
            .iter()
            .map(|family| family.name().to_string())
            .collect();
        assert!(names.contains(&"tidegard_collector_incident_inbox_queued".to_string()));
        // Nothing was queued, so shutdown has nothing to write and returns
        // promptly even though port 1 accepts no connection.
        let report = inbox.shutdown().await;
        assert_eq!(report.abandoned, 0);
    }

    #[tokio::test]
    async fn a_remote_database_without_tls_is_refused() {
        let Err(error) = IncidentInbox::start(
            &database("host=db.example.net user=app"),
            ["acme".to_string()],
            &Registry::new(),
        ) else {
            panic!("plaintext to a remote database must be refused");
        };
        assert!(matches!(
            error,
            InboxStartError::Connect(ConnectError::TlsRequired)
        ));
    }

    #[test]
    fn no_tenants_is_refused() {
        let Err(error) = IncidentInbox::start(
            &database("host=localhost user=app"),
            Vec::<String>::new(),
            &Registry::new(),
        ) else {
            panic!("an inbox with no tenants routes nothing");
        };
        assert!(matches!(error, InboxStartError::NoTenants));
    }
}
