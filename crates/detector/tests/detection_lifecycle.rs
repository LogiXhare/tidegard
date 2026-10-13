//! End-to-end, property, and capacity tests for the detection engine.
//!
//! These drive the crate through its public API only — synthetic flows
//! in, detection events out — so they exercise the same path the
//! collector does, and would notice a component that works alone but not
//! in sequence.
//!
//! Everything here is synthetic. No captured traffic, no attack
//! payloads; the "attack" is a number in a counter going up. See
//! docs/security-principles.md.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use proptest::prelude::*;
use tidegard_classifier::{classify, PrefixRegistry};
use tidegard_common::{
    NormalizedFlow, NormalizedFlowBuilder, Protocol, SamplingRate, SamplingSource,
};
use tidegard_detector::{
    load_policies, DetectionEngine, DetectionEvent, DetectionState, DetectionWindows, EngineConfig,
    EventKind, InMemorySink, PolicySet, ScopeType, StateTableConfig, ThresholdDetectionEngine,
    TrafficDirection, WindowConfig,
};

/// A 1 Mbps host policy on a one-second window: two seconds to trigger,
/// two to clear, ten of cooldown.
const POLICIES: &str = r#"{
  "schemaVersion": 1,
  "tenants": [ { "tenant": "acme", "prefixes": ["203.0.113.0/24"] } ],
  "policies": [
    {
      "id": "p-host-inbound",
      "name": "host inbound bps",
      "tenant": "acme",
      "scopeType": "host",
      "direction": "incoming",
      "window": "1s",
      "thresholds": { "bps": "1M" },
      "triggerFor": "2s",
      "clearFor": "2s",
      "cooldown": "10s",
      "severity": "critical"
    }
  ]
}"#;

fn registry() -> PrefixRegistry {
    let mut registry = PrefixRegistry::new();
    registry
        .insert(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
            24,
            "acme",
            Some("edge".to_string()),
        )
        .expect("valid prefix");
    registry
}

fn inbound_flow(victim: u8, bytes: u64) -> NormalizedFlow {
    NormalizedFlowBuilder {
        source_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        destination_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, victim)),
        source_port: Some(51000),
        destination_port: Some(443),
        protocol: Some(Protocol::Udp),
        tcp_flags: None,
        raw_bytes: bytes,
        raw_packets: (bytes / 1000).max(1),
        input_interface: Some(1),
        output_interface: Some(2),
        source_asn: None,
        destination_asn: None,
        exporter: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        observation_domain_id: 0,
        start_time: None,
        end_time: None,
        fragmented: false,
        dropped: false,
        forwarding_status_known: true,
    }
    .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
    .expect("a flow with bytes is valid")
}

/// Everything the collector wires together, in one place.
struct Harness {
    registry: PrefixRegistry,
    windows: DetectionWindows,
    engine: ThresholdDetectionEngine,
    sink: Arc<InMemorySink>,
    start: Instant,
}

impl Harness {
    fn new(policies: PolicySet, max_scopes: usize) -> Self {
        Harness::with_caps(policies, max_scopes, max_scopes)
    }

    /// Separate caps so a test can pressure the state table without
    /// also evicting the scope it cares about from the windowing layer.
    fn with_caps(policies: PolicySet, max_windows: usize, max_states: usize) -> Self {
        let sink = Arc::new(InMemorySink::new(256));
        let start = Instant::now();
        Harness {
            registry: registry(),
            windows: DetectionWindows::new(
                WindowConfig {
                    window: Duration::from_secs(1),
                    max_hosts: max_windows,
                    max_networks: max_windows,
                    max_slash24: max_windows,
                    max_hostgroups: 1_000,
                },
                start,
            ),
            engine: ThresholdDetectionEngine::new(EngineConfig {
                state: StateTableConfig {
                    max_entries: max_states,
                    idle_ttl: Duration::from_secs(300),
                    stale_after: Duration::from_secs(180),
                },
            })
            .with_policies(policies)
            .with_sink(sink.clone()),
            sink,
            start,
        }
    }

    fn default_policies(max_scopes: usize) -> Self {
        let compiled = load_policies(POLICIES).expect("the bundled policy document is valid");
        Harness::new(compiled.policies, max_scopes)
    }

    /// Runs one second: ingests `bytes` toward `victim`, then closes the
    /// window and evaluates.
    fn second(&mut self, second: u64, victim: u8, bytes: u64) {
        let at = self.start + Duration::from_secs(second);
        let flow = inbound_flow(victim, bytes);
        let classification = classify(&self.registry, &flow);
        self.windows
            .ingest(&self.registry, &flow, &classification, at);
        let close = self.start + Duration::from_secs(second + 1);
        let snapshots = self.windows.tick(close, SystemTime::UNIX_EPOCH);
        self.engine.evaluate(&snapshots);
    }

    /// Runs one second with no traffic at all, so a window still closes.
    fn quiet_second(&mut self, second: u64) {
        let close = self.start + Duration::from_secs(second + 1);
        let snapshots = self.windows.tick(close, SystemTime::UNIX_EPOCH);
        self.engine.evaluate(&snapshots);
    }

    fn sweep(&mut self, second: u64) {
        self.engine.sweep(
            self.start + Duration::from_secs(second),
            SystemTime::UNIX_EPOCH,
        );
    }

    fn host_events(&self) -> Vec<DetectionEvent> {
        self.sink
            .events()
            .into_iter()
            .filter(|event| event.target.scope_type == ScopeType::Host)
            .collect()
    }
}

/// 10 Mbps in one second — ten times the 1 Mbps threshold.
const HEAVY: u64 = 1_250_000;
/// 80 kbps — well under the 800 kbps clear level.
const LIGHT: u64 = 10_000;

#[test]
fn a_synthetic_attack_produces_one_start_and_one_end() {
    let mut h = Harness::default_policies(10_000);

    for second in 0..6 {
        h.second(second, 7, HEAVY);
    }
    for second in 6..10 {
        h.second(second, 7, LIGHT);
    }

    let events = h.host_events();
    let kinds: Vec<EventKind> = events.iter().map(|event| event.kind).collect();
    assert_eq!(
        kinds,
        vec![EventKind::Started, EventKind::Ended],
        "one attack must produce one start and one end, got {kinds:?}"
    );

    let start = &events[0];
    assert_eq!(start.policy_id, "p-host-inbound");
    assert_eq!(start.target.tenant, "acme");
    assert_eq!(start.target.display, "203.0.113.7");
    assert_eq!(start.target.direction, TrafficDirection::Incoming);
    assert_eq!(start.state, DetectionState::Active);
    assert!(start.rates.bps >= 10_000_000, "{}", start.rates.bps);
    assert_eq!(start.matched.len(), 1);
    assert!(start.matched[0].ratio_percent >= 1000);

    let end = &events[1];
    assert_eq!(end.detection_id, start.detection_id);
    assert_eq!(end.sequence, 1);
    assert!(end.matched.is_empty());
    assert!(end.peak[0].observed >= 10_000_000);
    assert!(end.duration_ms > 0);
}

#[test]
fn quiet_traffic_produces_no_events_at_all() {
    let mut h = Harness::default_policies(10_000);
    for second in 0..20 {
        h.second(second, 7, LIGHT);
    }
    assert!(h.sink.is_empty());
}

#[test]
fn a_burst_shorter_than_trigger_for_produces_nothing() {
    let mut h = Harness::default_policies(10_000);
    h.second(0, 7, LIGHT);
    h.second(1, 7, HEAVY);
    for second in 2..8 {
        h.second(second, 7, LIGHT);
    }
    assert!(
        h.sink.is_empty(),
        "a one-second crossing is not a two-second trigger"
    );
}

#[test]
fn an_outbound_flood_is_not_matched_by_an_inbound_policy() {
    let mut h = Harness::default_policies(10_000);
    let registry = registry();
    for second in 0..8 {
        let at = h.start + Duration::from_secs(second);
        // Same volume, opposite direction.
        let flow = NormalizedFlowBuilder {
            source_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            destination_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
            source_port: Some(443),
            destination_port: Some(51000),
            protocol: Some(Protocol::Udp),
            tcp_flags: None,
            raw_bytes: HEAVY,
            raw_packets: 1000,
            input_interface: Some(1),
            output_interface: Some(2),
            source_asn: None,
            destination_asn: None,
            exporter: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            observation_domain_id: 0,
            start_time: None,
            end_time: None,
            fragmented: false,
            dropped: false,
            forwarding_status_known: true,
        }
        .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
        .expect("valid flow");
        let classification = classify(&registry, &flow);
        h.windows.ingest(&registry, &flow, &classification, at);
        let snapshots = h.windows.tick(
            h.start + Duration::from_secs(second + 1),
            SystemTime::UNIX_EPOCH,
        );
        h.engine.evaluate(&snapshots);
    }
    assert!(
        h.sink.is_empty(),
        "an incoming policy must not fire on outgoing traffic"
    );
}

#[test]
fn cooldown_collapses_a_flapping_attack_into_one_event_pair() {
    let mut h = Harness::default_policies(10_000);
    // Six seconds heavy, four light, six heavy again. Without cooldown
    // the second burst would open a second detection.
    for second in 0..6 {
        h.second(second, 7, HEAVY);
    }
    for second in 6..10 {
        h.second(second, 7, LIGHT);
    }
    for second in 10..16 {
        h.second(second, 7, HEAVY);
    }

    let starts = h
        .host_events()
        .iter()
        .filter(|event| event.kind == EventKind::Started)
        .count();
    assert_eq!(
        starts, 1,
        "cooldown must suppress the second crossing, got {starts} starts"
    );
}

#[test]
fn an_attack_whose_exporter_goes_silent_is_still_closed() {
    let mut h = Harness::default_policies(10_000);
    for second in 0..6 {
        h.second(second, 7, HEAVY);
    }
    assert_eq!(h.engine.open_detections(), 1);

    // No more flows, and no more snapshots either — the scope simply
    // stops being reported.
    h.sweep(400);
    assert_eq!(h.engine.open_detections(), 0);

    let events = h.host_events();
    assert_eq!(events.last().expect("an end event").kind, EventKind::Ended);
    assert_eq!(
        events.last().expect("an end event").rates.bps,
        0,
        "a stale close reports no rate, because none was observed"
    );
}

#[test]
fn a_scope_that_goes_quiet_still_closes_through_normal_windows() {
    let mut h = Harness::default_policies(10_000);
    for second in 0..6 {
        h.second(second, 7, HEAVY);
    }
    // Windows keep closing with nothing in them: no snapshot is produced
    // for a scope with no traffic, so this is the stale path, not the
    // clear path. Proves an empty window does not silently clear.
    for second in 6..10 {
        h.quiet_second(second);
    }
    assert_eq!(
        h.engine.open_detections(),
        1,
        "an absent scope is not a cleared scope"
    );
    h.sweep(400);
    assert_eq!(h.engine.open_detections(), 0);
}

#[test]
fn many_attacked_hosts_each_get_their_own_detection() {
    let mut h = Harness::default_policies(10_000);
    for second in 0..6 {
        for victim in 1..=20u8 {
            let at = h.start + Duration::from_secs(second);
            let flow = inbound_flow(victim, HEAVY);
            let classification = classify(&h.registry, &flow);
            h.windows.ingest(&h.registry, &flow, &classification, at);
        }
        let snapshots = h.windows.tick(
            h.start + Duration::from_secs(second + 1),
            SystemTime::UNIX_EPOCH,
        );
        h.engine.evaluate(&snapshots);
    }

    let starts: Vec<DetectionEvent> = h
        .host_events()
        .into_iter()
        .filter(|event| event.kind == EventKind::Started)
        .collect();
    assert_eq!(starts.len(), 20);
    let distinct: std::collections::BTreeSet<&str> = starts
        .iter()
        .map(|event| event.detection_id.as_str())
        .collect();
    assert_eq!(distinct.len(), 20, "each host needs its own detection id");
}

#[test]
fn the_state_table_stays_within_its_cap_under_many_scopes() {
    // Deliberately far more distinct hosts than the cap allows.
    let mut h = Harness::default_policies(64);
    for second in 0..3u64 {
        let at = h.start + Duration::from_secs(second);
        for victim in 1..=250u8 {
            let flow = inbound_flow(victim, HEAVY);
            let classification = classify(&h.registry, &flow);
            h.windows.ingest(&h.registry, &flow, &classification, at);
        }
        let snapshots = h.windows.tick(
            h.start + Duration::from_secs(second + 1),
            SystemTime::UNIX_EPOCH,
        );
        h.engine.evaluate(&snapshots);
    }

    let windows_stats = h.windows.stats();
    assert!(
        windows_stats.evicted > 0 || windows_stats.rejected > 0,
        "a cap smaller than the workload must be visibly enforced"
    );
    assert!(
        h.engine.state().len() <= 64,
        "the state table must never exceed max_entries, got {}",
        h.engine.state().len()
    );
    assert!(
        h.engine.state().stats().rejected_table_full > 0,
        "refused admissions must be counted, not silent"
    );
}

#[test]
fn a_full_state_table_never_drops_an_already_open_detection() {
    // Room for every scope in the windowing layer, but only one
    // detection state — so the pressure lands exactly where the test is
    // about, rather than evicting the victim from the counters instead.
    let compiled = load_policies(POLICIES).expect("the bundled policy document is valid");
    let mut h = Harness::with_caps(compiled.policies, 10_000, 1);
    // Host 7 opens a detection first, alone.
    for second in 0..6 {
        h.second(second, 7, HEAVY);
    }
    assert_eq!(h.engine.open_detections(), 1);

    // Now a hundred other hosts arrive against a table with no room.
    for second in 6..12u64 {
        let at = h.start + Duration::from_secs(second);
        for victim in 100..=200u8 {
            let flow = inbound_flow(victim, HEAVY);
            let classification = classify(&h.registry, &flow);
            h.windows.ingest(&h.registry, &flow, &classification, at);
        }
        let snapshots = h.windows.tick(
            h.start + Duration::from_secs(second + 1),
            SystemTime::UNIX_EPOCH,
        );
        h.engine.evaluate(&snapshots);
    }
    assert_eq!(
        h.engine.open_detections(),
        1,
        "the open detection must survive pressure from new scopes"
    );
}

#[test]
fn an_empty_policy_set_detects_nothing_and_costs_nothing() {
    let mut h = Harness::new(PolicySet::new(), 10_000);
    for second in 0..10 {
        h.second(second, 7, HEAVY);
    }
    assert!(h.sink.is_empty());
    assert_eq!(h.engine.open_detections(), 0);
    assert_eq!(h.engine.state().len(), 0);
}

/// Rebuilds the harness inside a property test, where `?` is not
/// available and a panic is the failure signal.
fn run_rate_sequence(rates: &[u64]) -> Vec<DetectionEvent> {
    let mut h = Harness::default_policies(1_000);
    for (second, bytes) in rates.iter().enumerate() {
        h.second(second as u64, 7, *bytes);
    }
    h.sink.events()
}

proptest! {
    /// Whatever the traffic does, the engine must never report a
    /// detection ending that never started, never start one that is
    /// already open, and never update one that is closed.
    ///
    /// This is the invariant every downstream consumer depends on: an
    /// incident tracker that receives two starts without an end between
    /// them has no way to know which detection the eventual end belongs
    /// to.
    #[test]
    fn events_always_form_well_nested_detections(
        rates in prop::collection::vec(1u64..2_000_000, 1..40)
    ) {
        let events = run_rate_sequence(&rates);
        let mut open: BTreeMap<String, bool> = BTreeMap::new();
        for event in &events {
            match event.kind {
                EventKind::Started => {
                    prop_assert!(
                        open.insert(event.detection_id.clone(), true).is_none(),
                        "detection {} started twice",
                        event.detection_id
                    );
                }
                EventKind::Updated => {
                    prop_assert!(
                        open.get(&event.detection_id) == Some(&true),
                        "detection {} updated while not open",
                        event.detection_id
                    );
                }
                EventKind::Ended => {
                    prop_assert!(
                        open.insert(event.detection_id.clone(), false) == Some(true),
                        "detection {} ended without being open",
                        event.detection_id
                    );
                }
            }
        }
    }

    /// A detection's sequence numbers start at zero and increase by one,
    /// with no gaps. A consumer that sees a gap must be able to conclude
    /// it lost an event, which only works if the engine never leaves one.
    #[test]
    fn sequence_numbers_are_gapless_within_a_detection(
        rates in prop::collection::vec(1u64..2_000_000, 1..40)
    ) {
        let events = run_rate_sequence(&rates);
        let mut expected: BTreeMap<String, u64> = BTreeMap::new();
        for event in &events {
            let next = expected.entry(event.detection_id.clone()).or_insert(0);
            prop_assert_eq!(
                event.sequence,
                *next,
                "detection {} jumped to sequence {}",
                event.detection_id,
                event.sequence
            );
            *next += 1;
        }
    }

    /// Every event carries a dedup key unique to its position in its
    /// detection, so an at-least-once transport can collapse repeats
    /// without collapsing distinct events.
    #[test]
    fn dedup_keys_are_unique_across_a_run(
        rates in prop::collection::vec(1u64..2_000_000, 1..40)
    ) {
        let events = run_rate_sequence(&rates);
        let keys: std::collections::BTreeSet<&str> =
            events.iter().map(|event| event.dedup_key.as_str()).collect();
        prop_assert_eq!(keys.len(), events.len());
    }

    /// An event that reports a threshold crossing must report a rate
    /// that actually crosses it. The engine may never say "over
    /// threshold" while carrying a figure that is not.
    #[test]
    fn a_matched_reason_is_always_consistent_with_its_rate(
        rates in prop::collection::vec(1u64..2_000_000, 1..40)
    ) {
        let events = run_rate_sequence(&rates);
        for event in &events {
            for reason in &event.matched {
                prop_assert!(
                    reason.observed >= reason.threshold,
                    "reported {} as crossed at {} against a threshold of {}",
                    reason.metric.as_str(),
                    reason.observed,
                    reason.threshold
                );
                prop_assert_eq!(reason.excess, reason.observed - reason.threshold);
                prop_assert_eq!(reason.observed, event.rates.get(reason.metric));
            }
        }
    }

    /// The detector must survive arbitrary traffic without panicking,
    /// including rates large enough to overflow a naive bits-per-second
    /// multiply.
    #[test]
    fn absurd_volumes_do_not_panic(
        rates in prop::collection::vec(
            prop_oneof![Just(u64::MAX), Just(u64::MAX / 8), 1u64..u64::MAX],
            1..10
        )
    ) {
        let events = run_rate_sequence(&rates);
        // Nothing to assert beyond "it returned": the property is the
        // absence of a panic, and any event produced must still be
        // internally consistent.
        for event in &events {
            prop_assert!(!event.detection_id.is_empty());
            prop_assert!(!event.summary.is_empty());
        }
    }
}
