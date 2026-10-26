//! What the detection engine reports about itself.
//!
//! A trait rather than a concrete Prometheus type, for two reasons. The
//! collector already owns this project's registry and every metric name
//! in it, and giving the detector its own registry would mean two
//! `/metrics` endpoints or a merge step. And the detector's tests need
//! to assert on what was counted, which is far easier against a plain
//! counter than against a scraped Prometheus text body.
//!
//! The Prometheus implementation therefore lives in the collector,
//! alongside the metrics it already exposes. See
//! `tidegard-collector`'s `metrics` module.
//!
//! # Label discipline
//!
//! Every method here takes only values from a closed set: a state, a
//! reason, a severity, a scope type, a direction, an event kind. None
//! takes an address, a tenant, a hostgroup, or a policy id. Phase 3
//! established that rule (see the collector's metrics module) and it
//! matters more here, not less — a detector labelled by target address
//! would grow one time series per attacked host.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::event::EventKind;
use crate::input::ScopeType;
use crate::state::{DetectionState, StepIgnored, Suppression, TransitionReason};

/// Counters and gauges the engine updates as it runs.
///
/// Every method takes `&self` so the engine can hold one behind an
/// `Arc` and never needs a lock to record a number.
pub trait DetectionMetrics: Send + Sync {
    /// A snapshot was handed to the engine.
    fn snapshot_evaluated(&self, scope_type: ScopeType);

    /// A snapshot matched no policy at all.
    fn snapshot_unmatched(&self, scope_type: ScopeType);

    /// A snapshot was not applied. The reason is a closed set.
    fn snapshot_ignored(&self, reason: StepIgnored);

    /// The state machine moved.
    fn transition(&self, from: DetectionState, to: DetectionState, reason: TransitionReason);

    /// A threshold crossing deliberately produced no detection.
    fn suppressed(&self, reason: Suppression);

    /// An event was built.
    fn event_built(&self, kind: EventKind);

    /// An event reached every sink it was offered to.
    fn event_published(&self, kind: EventKind);

    /// An event was refused by at least one sink. `sink` is the sink's
    /// fixed name, never operator-supplied text.
    fn event_failed(&self, kind: EventKind, sink: &'static str);

    /// A metric could not be evaluated because its source field was
    /// never present in the flow data.
    fn metric_skipped(&self);

    /// How many scopes are currently in each state. Called once per
    /// sweep rather than per transition, because a gauge derived from
    /// increments drifts and a gauge derived from a count cannot.
    fn scopes_in_state(&self, state: DetectionState, count: usize);

    /// How many scopes the windowing layer is currently accumulating.
    fn tracked_scopes(&self, count: usize);

    /// A scope was refused admission because the state table is full.
    /// This is a dropped detection, not a dropped datapoint.
    fn state_table_full(&self);

    /// An open detection was closed because its snapshots stopped
    /// arriving.
    fn detection_stale(&self);
}

/// Records nothing.
///
/// For tests that are not about metrics, and for a deployment that has
/// deliberately turned the endpoint off.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopMetrics;

impl DetectionMetrics for NoopMetrics {
    fn snapshot_evaluated(&self, _scope_type: ScopeType) {}
    fn snapshot_unmatched(&self, _scope_type: ScopeType) {}
    fn snapshot_ignored(&self, _reason: StepIgnored) {}
    fn transition(&self, _from: DetectionState, _to: DetectionState, _reason: TransitionReason) {}
    fn suppressed(&self, _reason: Suppression) {}
    fn event_built(&self, _kind: EventKind) {}
    fn event_published(&self, _kind: EventKind) {}
    fn event_failed(&self, _kind: EventKind, _sink: &'static str) {}
    fn metric_skipped(&self) {}
    fn scopes_in_state(&self, _state: DetectionState, _count: usize) {}
    fn tracked_scopes(&self, _count: usize) {}
    fn state_table_full(&self) {}
    fn detection_stale(&self) {}
}

/// Plain atomic counters, so a test can assert on what happened without
/// a metrics backend.
///
/// Also useful in production as a cheap always-on tally that a debug
/// endpoint can read, which is why it lives here rather than under
/// `#[cfg(test)]`.
#[derive(Debug, Default)]
pub struct CountingMetrics {
    pub snapshots_evaluated: AtomicU64,
    pub snapshots_unmatched: AtomicU64,
    pub snapshots_ignored: AtomicU64,
    pub transitions: AtomicU64,
    pub suppressions: AtomicU64,
    pub events_built: AtomicU64,
    pub events_published: AtomicU64,
    pub events_failed: AtomicU64,
    pub metrics_skipped: AtomicU64,
    pub state_table_full: AtomicU64,
    pub detections_stale: AtomicU64,
    /// Latest gauge reading, in the order [`DetectionState`] declares.
    active_gauge: AtomicU64,
    tracked_gauge: AtomicU64,
}

impl CountingMetrics {
    pub fn new() -> Self {
        CountingMetrics::default()
    }

    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// The most recent count of scopes reported as `Active`.
    pub fn active_scopes(&self) -> u64 {
        self.active_gauge.load(Ordering::Relaxed)
    }

    /// The most recent count of scopes the windowing layer is tracking.
    pub fn tracked(&self) -> u64 {
        self.tracked_gauge.load(Ordering::Relaxed)
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

impl DetectionMetrics for CountingMetrics {
    fn snapshot_evaluated(&self, _scope_type: ScopeType) {
        bump(&self.snapshots_evaluated);
    }

    fn snapshot_unmatched(&self, _scope_type: ScopeType) {
        bump(&self.snapshots_unmatched);
    }

    fn snapshot_ignored(&self, _reason: StepIgnored) {
        bump(&self.snapshots_ignored);
    }

    fn transition(&self, _from: DetectionState, _to: DetectionState, _reason: TransitionReason) {
        bump(&self.transitions);
    }

    fn suppressed(&self, _reason: Suppression) {
        bump(&self.suppressions);
    }

    fn event_built(&self, _kind: EventKind) {
        bump(&self.events_built);
    }

    fn event_published(&self, _kind: EventKind) {
        bump(&self.events_published);
    }

    fn event_failed(&self, _kind: EventKind, _sink: &'static str) {
        bump(&self.events_failed);
    }

    fn metric_skipped(&self) {
        bump(&self.metrics_skipped);
    }

    fn scopes_in_state(&self, state: DetectionState, count: usize) {
        if state == DetectionState::Active {
            self.active_gauge.store(count as u64, Ordering::Relaxed);
        }
    }

    fn tracked_scopes(&self, count: usize) {
        self.tracked_gauge.store(count as u64, Ordering::Relaxed);
    }

    fn state_table_full(&self) {
        bump(&self.state_table_full);
    }

    fn detection_stale(&self) {
        bump(&self.detections_stale);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_noop_implementation_accepts_every_call() {
        let metrics = NoopMetrics;
        metrics.snapshot_evaluated(ScopeType::Host);
        metrics.snapshot_unmatched(ScopeType::Host);
        metrics.snapshot_ignored(StepIgnored::Duplicate);
        metrics.transition(
            DetectionState::Idle,
            DetectionState::Active,
            TransitionReason::ThresholdCrossed,
        );
        metrics.suppressed(Suppression::Cooldown);
        metrics.event_built(EventKind::Started);
        metrics.event_published(EventKind::Started);
        metrics.event_failed(EventKind::Started, "memory");
        metrics.metric_skipped();
        metrics.scopes_in_state(DetectionState::Active, 3);
        metrics.tracked_scopes(9);
        metrics.state_table_full();
        metrics.detection_stale();
    }

    #[test]
    fn the_counting_implementation_tallies_each_call() {
        let metrics = CountingMetrics::new();
        metrics.snapshot_evaluated(ScopeType::Host);
        metrics.snapshot_evaluated(ScopeType::Prefix);
        metrics.snapshot_unmatched(ScopeType::Slash24);
        metrics.snapshot_ignored(StepIgnored::OutOfOrder);
        metrics.transition(
            DetectionState::Idle,
            DetectionState::PendingTrigger,
            TransitionReason::ThresholdCrossed,
        );
        metrics.event_built(EventKind::Started);
        metrics.event_published(EventKind::Started);
        metrics.event_failed(EventKind::Ended, "memory");
        metrics.metric_skipped();
        metrics.state_table_full();
        metrics.detection_stale();

        assert_eq!(CountingMetrics::get(&metrics.snapshots_evaluated), 2);
        assert_eq!(CountingMetrics::get(&metrics.snapshots_unmatched), 1);
        assert_eq!(CountingMetrics::get(&metrics.snapshots_ignored), 1);
        assert_eq!(CountingMetrics::get(&metrics.transitions), 1);
        assert_eq!(CountingMetrics::get(&metrics.events_built), 1);
        assert_eq!(CountingMetrics::get(&metrics.events_published), 1);
        assert_eq!(CountingMetrics::get(&metrics.events_failed), 1);
        assert_eq!(CountingMetrics::get(&metrics.metrics_skipped), 1);
        assert_eq!(CountingMetrics::get(&metrics.state_table_full), 1);
        assert_eq!(CountingMetrics::get(&metrics.detections_stale), 1);
    }

    #[test]
    fn a_gauge_reports_the_latest_value_not_a_running_total() {
        let metrics = CountingMetrics::new();
        metrics.scopes_in_state(DetectionState::Active, 5);
        metrics.scopes_in_state(DetectionState::Active, 2);
        metrics.tracked_scopes(100);
        metrics.tracked_scopes(40);
        assert_eq!(metrics.active_scopes(), 2);
        assert_eq!(metrics.tracked(), 40);
    }

    #[test]
    fn a_gauge_for_another_state_does_not_disturb_the_active_one() {
        let metrics = CountingMetrics::new();
        metrics.scopes_in_state(DetectionState::Active, 7);
        metrics.scopes_in_state(DetectionState::Cooldown, 900);
        assert_eq!(metrics.active_scopes(), 7);
    }

    #[test]
    fn counting_metrics_can_be_shared_across_threads() {
        let metrics = std::sync::Arc::new(CountingMetrics::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let metrics = metrics.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        metrics.event_built(EventKind::Updated);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("thread finished");
        }
        assert_eq!(CountingMetrics::get(&metrics.events_built), 400);
    }
}
