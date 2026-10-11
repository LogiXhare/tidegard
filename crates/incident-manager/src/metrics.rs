//! The incident manager's Prometheus metrics.
//!
//! **Label sets are allowlisted** (Milestone 5C exit criterion). Every
//! label value comes from a constant in this module, never from data: no
//! tenant, incident id, scope or error text ever becomes a label, so the
//! number of series is fixed no matter what the database holds.
//! [`LABEL_ALLOWLIST`] is the complete list, and a test fails if a metric
//! carries a label name or value outside it.
//!
//! Names follow `docs/architecture/incident-observability.md`, which lists
//! what each one is for.

use prometheus::core::Collector;
use prometheus::{IntCounter, IntCounterVec, IntGauge, Opts, Registry};
use wetechinetmon_incident_postgres::inbox::{BatchReport, InboxStats};
use wetechinetmon_incident_postgres::maintenance::MaintenanceReport;
use wetechinetmon_incident_postgres::outbox::OutboxStats;
use wetechinetmon_incident_postgres::retention::RetentionReport;

const PREFIX: &str = "wetechinetmon_incident";

/// Every label name, and every value it may take.
pub const LABEL_ALLOWLIST: &[(&str, &[&str])] = &[
    (
        "result",
        &[
            "ok",
            "failed",
            "processed",
            "retrying",
            "dead_lettered",
            "lease_lost",
        ],
    ),
    ("transition", &["entered_recovering", "resolved", "closed"]),
    (
        "table",
        &[
            "idempotency",
            "outbox",
            "inbox",
            "dead_letter",
            "incidents",
            "sessions",
        ],
    ),
    ("job", &["stats", "maintenance", "retention"]),
];

#[derive(Clone)]
pub struct ManagerMetrics {
    /// Inbox rows still to be processed: pending or retrying.
    pub inbox_pending: IntGauge,
    /// Outbox rows still to be published: pending or retrying.
    pub outbox_pending: IntGauge,
    /// Unreviewed dead letters, from the inbox and the outbox alike.
    pub dead_letter_pending: IntGauge,
    /// The most timeline entries on any active incident (FU-32).
    pub timeline_pressure: IntGauge,
    /// Inbox events by what the worker did with them.
    pub inbox_events_total: IntCounterVec,
    /// Worker batches, `ok` or `failed` (a database error).
    pub inbox_batches_total: IntCounterVec,
    /// Events the domain refused on clock skew (ADR 0031).
    pub clock_skew_total: IntCounter,
    /// Automatic transitions the timers made.
    pub maintenance_transitions_total: IntCounterVec,
    /// Incidents a timer step could not advance on an error.
    pub maintenance_incident_failures_total: IntCounter,
    /// Rows the retention jobs deleted.
    pub retention_deleted_total: IntCounterVec,
    /// Scheduled job runs, by job and `ok` or `failed`.
    pub job_runs_total: IntCounterVec,
}

fn gauge(name: &str, help: &str) -> Result<IntGauge, prometheus::Error> {
    IntGauge::new(format!("{PREFIX}_{name}"), help)
}

fn counter(name: &str, help: &str) -> Result<IntCounter, prometheus::Error> {
    IntCounter::new(format!("{PREFIX}_{name}"), help)
}

fn counter_vec(
    name: &str,
    help: &str,
    labels: &[&str],
) -> Result<IntCounterVec, prometheus::Error> {
    IntCounterVec::new(Opts::new(format!("{PREFIX}_{name}"), help), labels)
}

impl ManagerMetrics {
    pub fn new() -> Result<(Self, Registry), prometheus::Error> {
        let metrics = ManagerMetrics {
            inbox_pending: gauge(
                "inbox_pending",
                "Detection events waiting to be processed, pending or retrying.",
            )?,
            outbox_pending: gauge(
                "outbox_pending",
                "Outbox messages waiting to be published, pending or retrying.",
            )?,
            dead_letter_pending: gauge(
                "dead_letter_pending",
                "Dead letters not yet reviewed, from the inbox and the outbox.",
            )?,
            timeline_pressure: gauge(
                "timeline_pressure",
                "The most timeline entries on any active incident. The limit is 50000, and the timeline is never truncated.",
            )?,
            inbox_events_total: counter_vec(
                "inbox_events_total",
                "Inbox events the correlation worker handled, by result.",
                &["result"],
            )?,
            inbox_batches_total: counter_vec(
                "inbox_batches_total",
                "Correlation worker batches, by result.",
                &["result"],
            )?,
            clock_skew_total: counter(
                "clock_skew_total",
                "Detection events refused because the decision time ran backward (ADR 0031).",
            )?,
            maintenance_transitions_total: counter_vec(
                "maintenance_transitions_total",
                "Automatic transitions made by the incident timers.",
                &["transition"],
            )?,
            maintenance_incident_failures_total: counter(
                "maintenance_incident_failures_total",
                "Incidents a timer step could not advance because of an error.",
            )?,
            retention_deleted_total: counter_vec(
                "retention_deleted_total",
                "Rows deleted by the retention jobs, by table.",
                &["table"],
            )?,
            job_runs_total: counter_vec(
                "job_runs_total",
                "Scheduled job runs, by job and result.",
                &["job", "result"],
            )?,
        };
        let registry = Registry::new();
        for collector in metrics.collectors() {
            registry.register(collector)?;
        }
        Ok((metrics, registry))
    }

    pub fn record_batch(&self, batch: &BatchReport) {
        self.inbox_batches_total.with_label_values(&["ok"]).inc();
        for (result, count) in [
            ("processed", batch.processed),
            ("retrying", batch.retrying),
            ("dead_lettered", batch.dead_lettered),
            ("lease_lost", batch.lease_lost),
        ] {
            self.inbox_events_total
                .with_label_values(&[result])
                .inc_by(count as u64);
        }
        self.clock_skew_total.inc_by(batch.clock_skew as u64);
    }

    pub fn record_failed_batch(&self) {
        self.inbox_batches_total
            .with_label_values(&["failed"])
            .inc();
    }

    pub fn record_stats(&self, inbox: &InboxStats, outbox: &OutboxStats, timeline_pressure: i64) {
        self.timeline_pressure.set(timeline_pressure);
        self.inbox_pending.set(inbox.pending + inbox.retrying);
        self.outbox_pending.set(outbox.pending + outbox.retrying);
        // The inbox copies what it dead-letters into `incident_dead_letter`,
        // so this one count covers both.
        self.dead_letter_pending.set(outbox.unreviewed_dead_letter);
    }

    pub fn record_maintenance(&self, report: &MaintenanceReport) {
        for (transition, count) in [
            ("entered_recovering", report.entered_recovering),
            ("resolved", report.resolved),
            ("closed", report.closed),
        ] {
            self.maintenance_transitions_total
                .with_label_values(&[transition])
                .inc_by(count);
        }
        self.maintenance_incident_failures_total
            .inc_by(report.failed);
    }

    pub fn record_retention(&self, report: &RetentionReport) {
        for (table, count) in [
            ("idempotency", report.expired_idempotency),
            ("outbox", report.published_outbox),
            ("inbox", report.processed_inbox),
            ("dead_letter", report.reviewed_dead_letter),
            ("incidents", report.closed_incidents),
            ("sessions", report.expired_sessions),
        ] {
            self.retention_deleted_total
                .with_label_values(&[table])
                .inc_by(count);
        }
    }

    pub fn record_job(&self, job: Job, ok: bool) {
        self.job_runs_total
            .with_label_values(&[job.as_str(), if ok { "ok" } else { "failed" }])
            .inc();
    }
}

/// The scheduled jobs, as their `job` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    Stats,
    Maintenance,
    Retention,
}

impl Job {
    pub fn as_str(self) -> &'static str {
        match self {
            Job::Stats => "stats",
            Job::Maintenance => "maintenance",
            Job::Retention => "retention",
        }
    }
}

impl ManagerMetrics {
    /// Every metric this owns. `new` registers exactly these and
    /// `metric_names` reads them, so `/metrics` and the Grafana dashboard
    /// check (ADR 0041) cannot disagree about what exists.
    fn collectors(&self) -> Vec<Box<dyn Collector>> {
        vec![
            Box::new(self.inbox_pending.clone()),
            Box::new(self.outbox_pending.clone()),
            Box::new(self.dead_letter_pending.clone()),
            Box::new(self.timeline_pressure.clone()),
            Box::new(self.inbox_events_total.clone()),
            Box::new(self.inbox_batches_total.clone()),
            Box::new(self.clock_skew_total.clone()),
            Box::new(self.maintenance_transitions_total.clone()),
            Box::new(self.maintenance_incident_failures_total.clone()),
            Box::new(self.retention_deleted_total.clone()),
            Box::new(self.job_runs_total.clone()),
        ]
    }

    /// The fully qualified name of every metric this owns.
    pub fn metric_names(&self) -> Vec<String> {
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

    /// Touches every series a running manager can produce.
    fn exercised() -> Registry {
        let (metrics, registry) = ManagerMetrics::new().unwrap();
        metrics.record_batch(&BatchReport {
            claimed: 5,
            processed: 1,
            retrying: 1,
            dead_lettered: 1,
            lease_lost: 1,
            clock_skew: 1,
        });
        metrics.record_failed_batch();
        metrics.record_stats(
            &InboxStats {
                pending: 1,
                retrying: 2,
                dead_letter: 3,
            },
            &OutboxStats {
                pending: 4,
                retrying: 5,
                unreviewed_dead_letter: 6,
            },
            7,
        );
        metrics.record_maintenance(&MaintenanceReport {
            entered_recovering: 1,
            resolved: 1,
            closed: 1,
            not_due: 1,
            failed: 1,
        });
        metrics.record_retention(&RetentionReport {
            expired_idempotency: 1,
            published_outbox: 1,
            processed_inbox: 1,
            reviewed_dead_letter: 1,
            closed_incidents: 1,
            expired_sessions: 1,
        });
        for job in [Job::Stats, Job::Maintenance, Job::Retention] {
            metrics.record_job(job, true);
            metrics.record_job(job, false);
        }
        registry
    }

    #[test]
    fn every_label_is_on_the_allowlist() {
        let families = exercised().gather();
        assert_eq!(families.len(), 11, "every metric is registered and touched");
        for family in &families {
            assert!(family.name().starts_with(PREFIX), "{}", family.name());
            for metric in family.get_metric() {
                for label in metric.get_label() {
                    let allowed = LABEL_ALLOWLIST
                        .iter()
                        .find(|(name, _)| *name == label.name())
                        .unwrap_or_else(|| {
                            panic!(
                                "{} has a label name off the allowlist: {}",
                                family.name(),
                                label.name()
                            )
                        });
                    assert!(
                        allowed.1.contains(&label.value()),
                        "{} has {}={} off the allowlist",
                        family.name(),
                        label.name(),
                        label.value()
                    );
                }
            }
        }
    }

    /// `metric_names` is what `/metrics` exports once every series is
    /// touched: the dashboard check (ADR 0041) relies on it.
    #[test]
    fn metric_names_are_exactly_the_exported_families() {
        let (metrics, _) = ManagerMetrics::new().unwrap();
        let mut named = metrics.metric_names();
        named.sort();
        let mut exported: Vec<String> = exercised()
            .gather()
            .iter()
            .map(|family| family.name().to_string())
            .collect();
        exported.sort();
        assert_eq!(named, exported);
    }

    #[test]
    fn no_label_can_identify_a_tenant_or_an_incident() {
        for (name, _) in LABEL_ALLOWLIST {
            assert!(
                ![
                    "tenant",
                    "tenant_id",
                    "incident",
                    "incident_id",
                    "scope",
                    "error"
                ]
                .contains(name),
                "{name}"
            );
        }
    }

    #[test]
    fn stats_set_the_gauges() {
        let (metrics, _registry) = ManagerMetrics::new().unwrap();
        metrics.record_stats(
            &InboxStats {
                pending: 7,
                retrying: 1,
                dead_letter: 2,
            },
            &OutboxStats {
                pending: 1,
                retrying: 2,
                unreviewed_dead_letter: 3,
            },
            41_000,
        );
        assert_eq!(metrics.timeline_pressure.get(), 41_000);
        assert_eq!(metrics.inbox_pending.get(), 8);
        assert_eq!(metrics.outbox_pending.get(), 3);
        assert_eq!(metrics.dead_letter_pending.get(), 3);
    }
}
