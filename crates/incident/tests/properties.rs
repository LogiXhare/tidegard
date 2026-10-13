//! Property tests, following Phase 4's use of `proptest`.
//!
//! A focused subset of the testing plan's thirteen properties — the
//! ones that exercise the unit-of-work's actual command/ingest surface
//! rather than restating what a single unit test already pins exactly
//! (e.g. the inclusive reopen boundary, already property-adjacent as
//! exact-value tests in `crate::reopen`).
//!
//! **Known gap, deliberately not modeled here (FU-30):** correlation's
//! `is_late` decision compares the unit-of-work's own clock reading at
//! call time, not any field the event itself carries (`sequence`,
//! `detected_at_ms`). Since [`TestClock`] and the production
//! `SystemClock` are both non-decreasing, an event that is semantically
//! older by its own declared `sequence` but is *delivered* later always
//! observes a clock reading `>=` what is already stored — so lateness by
//! declared order can never be detected by the current implementation.
//! The permutation property below therefore varies event *content*
//! (which metrics are matched, not delivery timing) to test genuine
//! order-independence of the correlation and category outcome, and the
//! monotonicity property below drives the shared clock explicitly rather
//! than pretending `sequence` affects delivery order.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use proptest::prelude::*;
use tidegard_detector::{
    ActionTaken, AddressFamily, Clock, DataCompleteness, DetectionEvent, DetectionState, EventKind,
    EventTarget, ExecutionMode, MatchedReason, MetricKind, MetricRates, SamplingStatus, ScopeId,
    ScopeType, Severity, TestClock, TrafficDirection, TransitionReason,
};
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::category::IncidentCategory;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident::number::InMemoryNumberAllocator;
use tidegard_incident::unit_of_work::{IncidentUnitOfWork, IngestOutcomeKind};

fn event_with_metric(
    detection_id: &str,
    sequence: u64,
    addr: IpAddr,
    metric: MetricKind,
    observed: u64,
) -> DetectionEvent {
    DetectionEvent {
        schema_version: tidegard_detector::EVENT_SCHEMA_VERSION,
        event_id: format!("{detection_id}-{sequence}"),
        detection_id: detection_id.to_string(),
        sequence,
        kind: if sequence == 0 {
            EventKind::Started
        } else {
            EventKind::Updated
        },
        dedup_key: format!("{detection_id}:updated:{sequence}"),
        policy_id: "p-host-bps".to_string(),
        policy_name: "host bps".to_string(),
        policy_version: 1,
        severity: Severity::Major,
        execution_mode: ExecutionMode::AlertOnly,
        action: ActionTaken::Alerted,
        labels: BTreeMap::new(),
        target: EventTarget {
            tenant: "acme".to_string(),
            scope_type: ScopeType::Host,
            scope_id: ScopeId::Host { addr },
            display: addr.to_string(),
            direction: TrafficDirection::Incoming,
            address_family: AddressFamily::Ipv4,
        },
        previous_state: DetectionState::PendingTrigger,
        state: DetectionState::Active,
        reason: TransitionReason::TriggerSustained,
        detected_at_ms: 1_700_000_000_000 + sequence,
        observed_at_ms: 1_700_000_000_000 + sequence,
        duration_ms: sequence,
        window_ms: 1000,
        matched: vec![MatchedReason {
            metric,
            observed,
            threshold: 1_000_000,
            excess: observed.saturating_sub(1_000_000),
            ratio_percent: observed * 100 / 1_000_000,
        }],
        peak: Vec::new(),
        skipped: Vec::new(),
        rates: MetricRates::default(),
        completeness: DataCompleteness::default(),
        sampling: SamplingStatus::default(),
        flows_observed: 1,
        exporters_observed: 1,
        snapshots_in_detection: sequence + 1,
        executed: false,
        summary: "test".to_string(),
    }
}

fn event_n(detection_id: &str, sequence: u64, addr: IpAddr, observed: u64) -> DetectionEvent {
    event_with_metric(detection_id, sequence, addr, MetricKind::Bps, observed)
}

fn fresh_uow() -> IncidentUnitOfWork {
    IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(1)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    )
}

/// A [`Clock`] that delegates to a shared, externally-advanceable
/// [`TestClock`] — `IncidentUnitOfWork::new` takes ownership of its clock
/// as a `Box<dyn Clock>`, so a test that needs to advance time *after*
/// construction needs a handle that outlives the move. `TestClock` itself
/// has no `rewind`, deliberately (see its own doc) — only forward
/// movement is representable, which is exactly what a genuine
/// monotonicity property needs to drive.
struct SharedClock(Arc<TestClock>);

impl Clock for SharedClock {
    fn monotonic(&self) -> Instant {
        self.0.monotonic()
    }

    fn wall(&self) -> SystemTime {
        self.0.wall()
    }
}

/// One of the six permutations of three elements, indexed `0..6`, used
/// instead of a `prop_oneof!` of `Just` arms so the property strategy
/// stays a plain integer range.
fn permutation_of_three(idx: u8) -> [usize; 3] {
    match idx {
        0 => [0, 1, 2],
        1 => [0, 2, 1],
        2 => [1, 0, 2],
        3 => [1, 2, 0],
        4 => [2, 0, 1],
        _ => [2, 1, 0],
    }
}

proptest! {
    /// Property 4 / correlation determinism: duplicate ingestion never
    /// creates a second incident, for any number of redeliveries.
    #[test]
    fn duplicate_ingestion_never_creates_a_second_incident(redeliveries in 0usize..20) {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let started = event_n("det-prop-1", 0, addr, 5_000_000);

        let first = uow.ingest_detection_event(&correlator, &started).unwrap();
        prop_assert_eq!(first.outcome_kind, IngestOutcomeKind::Created);

        for _ in 0..redeliveries {
            let replay = uow.ingest_detection_event(&correlator, &started).unwrap();
            prop_assert_eq!(replay.outcome_kind, IngestOutcomeKind::Duplicate);
        }
        prop_assert_eq!(uow.incident_count(), 1);
    }

    /// Property 3: version increases strictly monotonically per incident
    /// across an arbitrary number of linked updates.
    #[test]
    fn version_increases_strictly_monotonically(update_count in 1usize..15) {
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51));
        let started = event_n("det-prop-2", 0, addr, 5_000_000);
        let incident_id = uow.ingest_detection_event(&correlator, &started).unwrap().incident_id.unwrap();
        let mut last_version = uow.get(&incident_id).unwrap().version;

        for i in 1..=update_count {
            let updated = event_n("det-prop-2", i as u64, addr, 5_000_000 + i as u64);
            uow.ingest_detection_event(&correlator, &updated).unwrap();
            let version = uow.get(&incident_id).unwrap().version;
            prop_assert!(version > last_version, "version must strictly increase: {last_version} -> {version}");
            last_version = version;
        }
    }

    /// Property 12: `last_detected_at` tracks the clock exactly across an
    /// arbitrary sequence of advances (including a zero advance, the
    /// equal-timestamp boundary), driven through genuine, test-controlled
    /// clock advances (via [`SharedClock`]) rather than the event's
    /// unconsumed `sequence` field — see the module doc's FU-30 note on
    /// why `sequence` alone cannot exercise this path.
    ///
    /// **R1 correction:** the previous version of this property asserted
    /// `elapsed_since(...) >= Duration::ZERO`, which — because
    /// `elapsed_since` is built on
    /// [`Instant::saturating_duration_since`] and `Duration` is
    /// unsigned — cannot fail for *any* implementation, including one
    /// that silently regressed `last_detected_at`. This version compares
    /// the stored `DurableTimestamp`s directly (a real total order, with
    /// no saturating clamp to hide a regression) and additionally asserts
    /// the exact expected value, so a bug that assigned any timestamp
    /// other than the fresh clock reading — regressed, stale, or simply
    /// wrong — fails the property. The complementary "an older event is
    /// delivered after a newer one" case is deliberately not modeled
    /// here: with a forward-only clock (`TestClock` has no rewind, by
    /// design, matching production `SystemClock`), that ordering cannot
    /// be produced through the public ingestion API — see this module's
    /// own FU-30 note above. It is instead proven, by directly
    /// manufacturing the stored state, in
    /// `unit_of_work::tests::last_detected_at_does_not_regress_on_a_late_event`
    /// (crate-internal, since only crate-internal code can reach
    /// `IncidentUnitOfWork`'s private incident map to set that scenario
    /// up) — alongside its equal-timestamp and strictly-newer siblings.
    #[test]
    fn last_detected_at_is_monotonic_as_the_clock_advances(
        advances_ms in proptest::collection::vec(0u64..5_000, 1..8)
    ) {
        let clock = Arc::new(TestClock::new());
        let mut uow = IncidentUnitOfWork::new(
            Box::new(TestIncidentGenerator::starting_at(1)),
            Box::new(InMemoryNumberAllocator::new()),
            Box::new(SharedClock(clock.clone())),
        );
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 52));
        let started = event_n("det-prop-3", 0, addr, 5_000_000);
        let incident_id = uow.ingest_detection_event(&correlator, &started).unwrap().incident_id.unwrap();
        let mut last = uow.get(&incident_id).unwrap().last_detected_at;

        for (i, ms) in advances_ms.iter().enumerate() {
            clock.advance(Duration::from_millis(*ms));
            let updated = event_n("det-prop-3", (i + 1) as u64, addr, 5_000_001);
            uow.ingest_detection_event(&correlator, &updated).unwrap();
            let now = uow.get(&incident_id).unwrap().last_detected_at;
            prop_assert!(
                now >= last,
                "last_detected_at's stored reading moved backward: a real, non-saturating regression"
            );
            prop_assert_eq!(
                now,
                last.checked_plus(Duration::from_millis(*ms)).unwrap(),
                "a newer or equal-timestamp observation must advance last_detected_at by exactly the clock advance, not by more, less, or not at all"
            );
            last = now;
        }
    }

    /// Property 4 (restated): correlation and category derivation are
    /// order-independent. Three events matching distinct metric families
    /// (TCP-SYN, UDP, generic bandwidth) on one correlation key are
    /// delivered in every one of the six possible orders; the final
    /// incident count, category, and evidence totals must be identical
    /// regardless of delivery order, since none of those outcomes should
    /// depend on which event happened to arrive first.
    #[test]
    fn correlation_and_category_are_order_independent(perm_idx in 0u8..6) {
        let order = permutation_of_three(perm_idx);
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 61));
        let metrics = [MetricKind::Bps, MetricKind::TcpSynPps, MetricKind::UdpBps];
        let mut uow = fresh_uow();
        let correlator = AuthorizationContext::correlator(TenantId::new("acme"));

        let mut incident_id = None;
        for &i in order.iter() {
            let ev = event_with_metric("det-perm", i as u64, addr, metrics[i], 5_000_000 + i as u64);
            let result = uow.ingest_detection_event(&correlator, &ev).unwrap();
            if let Some(id) = result.incident_id {
                incident_id = Some(id);
            }
        }
        let incident_id = incident_id.expect("at least the first event must create an incident");

        prop_assert_eq!(uow.incident_count(), 1, "one correlation key must never split into two incidents regardless of arrival order");
        let incident = uow.get(&incident_id).unwrap();
        prop_assert_eq!(
            incident.category,
            IncidentCategory::MultiVector,
            "TCP-SYN + UDP crosses two families and must classify as multi_vector regardless of order"
        );
        prop_assert_eq!(incident.evidence.observed_total(), 3);
        prop_assert_eq!(incident.evidence.retained_count(), 3);
    }

    /// Property 7 (tenant isolation, scoped): an ingestion under tenant A
    /// never becomes visible or mutable under tenant B's context.
    #[test]
    fn tenant_a_events_never_correlate_under_tenant_b(seq in 0u64..5) {
        let mut uow = fresh_uow();
        let correlator_a = AuthorizationContext::correlator(TenantId::new("acme"));
        let correlator_b = AuthorizationContext::correlator(TenantId::new("globex"));
        let addr: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53));
        let mut event = event_n("det-prop-4", seq, addr, 5_000_000);
        event.target.tenant = "acme".to_string();

        let result_a = uow.ingest_detection_event(&correlator_a, &event);
        prop_assert!(result_a.is_ok());

        // The same event body claims tenant "acme" but is submitted
        // through tenant B's authorization context — must be rejected as
        // a tenant mismatch, never silently reattributed or correlated.
        let result_b = uow.ingest_detection_event(&correlator_b, &event);
        prop_assert!(result_b.is_err());
    }
}
