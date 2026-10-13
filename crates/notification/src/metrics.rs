//! The notifier's Prometheus metrics. Labels come from a closed set: a
//! result, never a channel name, tenant or incident.

use prometheus::core::Collector;
use prometheus::{IntCounterVec, Opts, Registry};

use crate::worker::BatchReport;

pub const LABEL_ALLOWLIST: &[(&str, &[&str])] = &[(
    "result",
    &[
        "delivered",
        "failed",
        "refused",
        "duplicate",
        "rate_limited",
        "published",
        "retrying",
        "dead_lettered",
    ],
)];

#[derive(Clone)]
pub struct NotifierMetrics {
    /// Delivery attempts and skips, by result.
    pub notifications_total: IntCounterVec,
    /// Outbox messages finished, by result.
    pub messages_total: IntCounterVec,
}

impl NotifierMetrics {
    pub fn new() -> Result<(Self, Registry), prometheus::Error> {
        let metrics = NotifierMetrics {
            notifications_total: IntCounterVec::new(
                Opts::new(
                    "tidegard_notifier_notifications_total",
                    "Notification attempts and skips, by result.",
                ),
                &["result"],
            )?,
            messages_total: IntCounterVec::new(
                Opts::new(
                    "tidegard_notifier_messages_total",
                    "Outbox messages the notifier finished, by result.",
                ),
                &["result"],
            )?,
        };
        let registry = Registry::new();
        for collector in metrics.collectors() {
            registry.register(collector)?;
        }
        Ok((metrics, registry))
    }

    fn collectors(&self) -> Vec<Box<dyn Collector>> {
        vec![
            Box::new(self.notifications_total.clone()),
            Box::new(self.messages_total.clone()),
        ]
    }

    /// The name of every metric, for the Grafana dashboard check (ADR 0041).
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

    pub fn record(&self, report: &BatchReport) {
        for (result, count) in [
            ("delivered", report.delivered),
            ("failed", report.failed),
            ("refused", report.refused),
            ("duplicate", report.duplicates),
            ("rate_limited", report.rate_limited),
        ] {
            self.notifications_total
                .with_label_values(&[result])
                .inc_by(count as u64);
        }
        for (result, count) in [
            ("published", report.published),
            ("retrying", report.retrying),
            ("dead_lettered", report.dead_lettered),
        ] {
            self.messages_total
                .with_label_values(&[result])
                .inc_by(count as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_is_on_the_allowlist() {
        let (metrics, registry) = NotifierMetrics::new().unwrap();
        metrics.record(&BatchReport {
            claimed: 1,
            published: 1,
            retrying: 1,
            dead_lettered: 1,
            delivered: 1,
            failed: 1,
            refused: 1,
            duplicates: 1,
            rate_limited: 1,
        });
        let families = registry.gather();
        assert_eq!(families.len(), 2);
        for family in &families {
            for metric in family.get_metric() {
                for label in metric.get_label() {
                    let allowed = LABEL_ALLOWLIST
                        .iter()
                        .find(|(name, _)| *name == label.name())
                        .expect("a known label");
                    assert!(allowed.1.contains(&label.value()), "{}", label.value());
                }
            }
        }
        assert_eq!(metrics.metric_names().len(), 2);
    }
}
