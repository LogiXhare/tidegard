//! The mitigator's Prometheus metrics (ADR 0049). Labels come from a
//! closed set: never a prefix, a tenant or a mitigation id.

use prometheus::core::Collector;
use prometheus::{IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};

use crate::service::{ReconcileReport, Report};

pub const LABEL_ALLOWLIST: &[(&str, &[&str])] = &[
    (
        "result",
        &[
            "announced",
            "dry_run",
            "withdrawn",
            "failed",
            "expired",
            "proposed",
            "refused",
            "error",
            "stale_withdrawn",
            "restored",
        ],
    ),
    ("state", &["established", "other"]),
];

#[derive(Clone)]
pub struct MitigatorMetrics {
    pub actions_total: IntCounterVec,
    pub reconcile_total: IntCounterVec,
    pub kill_switch: IntGauge,
    pub owned_routes: IntGauge,
    pub bgp_peers: IntGaugeVec,
}

impl MitigatorMetrics {
    pub fn new() -> Result<(Self, Registry), prometheus::Error> {
        let metrics = MitigatorMetrics {
            actions_total: IntCounterVec::new(
                Opts::new(
                    "tidegard_mitigator_actions_total",
                    "What the mitigator did with mitigations, by result.",
                ),
                &["result"],
            )?,
            reconcile_total: IntCounterVec::new(
                Opts::new(
                    "tidegard_mitigator_reconcile_total",
                    "Routes reconciliation withdrew or restored, by result.",
                ),
                &["result"],
            )?,
            kill_switch: IntGauge::new(
                "tidegard_mitigator_kill_switch",
                "1 while the kill switch is on.",
            )?,
            owned_routes: IntGauge::new(
                "tidegard_mitigator_owned_routes",
                "Routes in GoBGP carrying Tidegard's ownership community.",
            )?,
            bgp_peers: IntGaugeVec::new(
                Opts::new(
                    "tidegard_mitigator_bgp_peers",
                    "GoBGP's peers, by whether the session is established.",
                ),
                &["state"],
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
            Box::new(self.actions_total.clone()),
            Box::new(self.reconcile_total.clone()),
            Box::new(self.kill_switch.clone()),
            Box::new(self.owned_routes.clone()),
            Box::new(self.bgp_peers.clone()),
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

    pub fn record(&self, report: &Report) {
        for (result, count) in [
            ("announced", report.announced),
            ("dry_run", report.dry_run),
            ("withdrawn", report.withdrawn),
            ("failed", report.failed),
            ("expired", report.expired),
            ("proposed", report.proposed),
            ("refused", report.refused),
            ("error", report.errors),
        ] {
            self.actions_total
                .with_label_values(&[result])
                .inc_by(count as u64);
        }
        self.kill_switch.set(i64::from(report.kill_switch));
    }

    pub fn record_reconcile(&self, report: &ReconcileReport) {
        self.reconcile_total
            .with_label_values(&["stale_withdrawn"])
            .inc_by(report.stale_withdrawn as u64);
        self.reconcile_total
            .with_label_values(&["restored"])
            .inc_by(report.restored as u64);
        self.owned_routes.set(report.owned as i64);
    }

    pub fn record_peers(&self, established: usize, total: usize) {
        self.bgp_peers
            .with_label_values(&["established"])
            .set(established as i64);
        self.bgp_peers
            .with_label_values(&["other"])
            .set(total.saturating_sub(established) as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_is_on_the_allowlist() {
        let (metrics, registry) = MitigatorMetrics::new().unwrap();
        metrics.record(&Report {
            announced: 1,
            dry_run: 1,
            withdrawn: 1,
            failed: 1,
            expired: 1,
            proposed: 1,
            refused: 1,
            errors: 1,
            kill_switch: true,
        });
        metrics.record_reconcile(&ReconcileReport {
            owned: 2,
            stale_withdrawn: 1,
            restored: 1,
        });
        metrics.record_peers(1, 2);
        for family in registry.gather() {
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
        assert_eq!(metrics.metric_names().len(), 5);
    }
}
