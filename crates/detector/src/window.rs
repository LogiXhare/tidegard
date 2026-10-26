//! Turning Phase 3 flows into detection snapshots.
//!
//! Phase 3's aggregator is deliberately two-sided and direction-blind:
//! a flow between A and B counts against both A and B, and the entry
//! says nothing about which way the traffic was going. That is right for
//! analytics — "how much did this host move" — and wrong for detection,
//! where "10 Gbps arriving at this host" and "10 Gbps leaving it" mean
//! entirely different things and need separate thresholds.
//!
//! So the detector keeps its own counters rather than reading the
//! aggregator's. It reuses the aggregator's public [`BoundedMap`] and
//! [`TrafficCounters`], and does not modify Phase 3.
//!
//! # Tumbling, not rolling
//!
//! Counters accumulate for one window and are then emitted and cleared.
//! A rolling window would need a per-scope ring buffer, and at a hundred
//! thousand scopes that is the difference between a few megabytes and a
//! few hundred. The cost is that a burst straddling a window boundary is
//! split across two snapshots; `triggerFor` spanning at least one full
//! window is what makes that acceptable, and policy validation enforces
//! it.
//!
//! # Which side is the target
//!
//! A scope is always the *local* side of a flow:
//!
//! | Direction  | Scoped on             | Reported as        |
//! |------------|-----------------------|--------------------|
//! | `Incoming` | destination           | `Incoming`         |
//! | `Outgoing` | source                | `Outgoing`         |
//! | `Internal` | destination *and* source | `Incoming` and `Outgoing` |
//! | `Other`    | nothing               | counted as unscoped |
//! | `Unknown`  | nothing               | counted as unscoped |
//!
//! `Internal` counting both sides is what makes an internal host being
//! flooded visible as incoming, and an internal host doing the flooding
//! visible as outgoing, without a separate scope type for either.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime};

use tidegard_aggregator::{BoundedMap, BoundedMapConfig, TrafficCounters, UpsertOutcome};
use tidegard_classifier::{ClassificationResult, Direction, PrefixRegistry};
use tidegard_common::{NormalizedFlow, SamplingSource};

use crate::input::{
    AddressFamily, DataCompleteness, DetectionSnapshot, MetricRates, SamplingStatus, ScopeId,
    ScopeKey, ScopeType, TrafficDirection,
};

/// The tenant recorded when a flow's local side matched a prefix that
/// declares no tenant. Never a wildcard: a policy written for the
/// wildcard tenant matches every scope, whereas this is a real tenant
/// name that only unattributed traffic lands in.
pub const UNATTRIBUTED_TENANT: &str = "unattributed";

/// How the detector's own counters are bounded and shaped.
///
/// A `max_*` of zero disables that scope type outright, which is the
/// cheapest way to run the detector on hosts alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowConfig {
    /// How long counters accumulate before being emitted. Must match the
    /// `window` of any policy expected to evaluate these snapshots.
    pub window: Duration,
    pub max_hosts: usize,
    pub max_networks: usize,
    pub max_slash24: usize,
    pub max_hostgroups: usize,
}

impl Default for WindowConfig {
    fn default() -> Self {
        WindowConfig {
            window: Duration::from_secs(5),
            max_hosts: 100_000,
            max_networks: 20_000,
            max_slash24: 20_000,
            max_hostgroups: 1_000,
        }
    }
}

/// What the windowing layer did, for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowStats {
    pub flows_ingested: u64,
    /// Flows whose direction gave no local side to scope on.
    pub flows_unscoped: u64,
    pub snapshots_emitted: u64,
    /// Times a new scope displaced an existing one because a map was
    /// full. Unlike the detection state table, losing a counter here
    /// costs at most one window of visibility, so eviction is the right
    /// trade.
    pub evicted: u64,
    /// Times a new scope was refused because its map is configured with
    /// no capacity at all.
    pub rejected: u64,
    /// Ticks where the elapsed time differed from the configured window
    /// by more than 10%. Rates stay correct — they are computed from the
    /// time that actually elapsed — but a persistently skewed tick means
    /// the caller is not calling on schedule.
    pub skewed_ticks: u64,
}

/// A 64-bit sketch of which exporters contributed to one scope.
///
/// Eight bytes instead of a set of addresses, which matters at a hundred
/// thousand scopes. Two exporters whose addresses hash to the same bit
/// count as one, so the result **undercounts and never overcounts**.
/// That direction is the safe one: it can only ever understate how many
/// exporters agreed about a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ExporterSketch(u64);

impl ExporterSketch {
    fn observe(&mut self, exporter: IpAddr) {
        let mut hasher = DefaultHasher::new();
        exporter.hash(&mut hasher);
        self.0 |= 1u64 << (hasher.finish() % 64);
    }

    fn count(&self) -> u32 {
        self.0.count_ones()
    }
}

/// One scope's accumulated traffic for the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Accumulator {
    counters: TrafficCounters,
    completeness: DataCompleteness,
    sampling: SamplingStatus,
    exporters: ExporterSketch,
}

impl Accumulator {
    fn add(&mut self, flow: &NormalizedFlow) {
        self.counters.add(flow);
        self.completeness.merge(DataCompleteness {
            protocol_seen: flow.protocol.is_some(),
            tcp_flags_seen: flow.tcp_flags.is_some(),
            // A normalized flow carries no "fragmentation was reported"
            // flag, only whether this flow *was* fragmented. So the only
            // honest positive evidence is a fragmented flow. A scope
            // with none reports the field as unseen, which makes the
            // detector skip fragmentation thresholds rather than compare
            // them against zero — the same outcome, arrived at without
            // claiming to know something it does not.
            fragmentation_seen: flow.fragmented,
            forwarding_status_seen: flow.forwarding_status_known,
        });
        self.sampling.merge(SamplingStatus {
            corrected: flow.sampling_rate.get() > 1,
            used_global_default: matches!(flow.sampling_source, SamplingSource::GlobalDefault),
            max_rate: flow.sampling_rate.get(),
        });
        self.exporters.observe(flow.exporter);
    }
}

/// The detector's own direction-aware, bounded, per-scope counters.
///
/// No `Debug`: `BoundedMap` does not implement it, and a derived one
/// here would print every tracked scope, which is neither useful nor
/// safe to put in a log line.
pub struct DetectionWindows {
    config: WindowConfig,
    window_start: Instant,
    hosts: BoundedMap<ScopeKey, Accumulator>,
    networks: BoundedMap<ScopeKey, Accumulator>,
    slash24: BoundedMap<ScopeKey, Accumulator>,
    hostgroups: BoundedMap<ScopeKey, Accumulator>,
    stats: WindowStats,
}

/// Entries are cleared on every tick, so the map's own inactivity
/// expiry never has anything to do; the window is the shortest honest
/// value to give it.
fn map_config(max_entries: usize, window: Duration) -> BoundedMapConfig {
    BoundedMapConfig {
        max_entries,
        inactivity_ttl: window,
    }
}

impl DetectionWindows {
    pub fn new(config: WindowConfig, now: Instant) -> Self {
        let window = config.window;
        DetectionWindows {
            window_start: now,
            hosts: BoundedMap::new(map_config(config.max_hosts, window)),
            networks: BoundedMap::new(map_config(config.max_networks, window)),
            slash24: BoundedMap::new(map_config(config.max_slash24, window)),
            hostgroups: BoundedMap::new(map_config(config.max_hostgroups, window)),
            config,
            stats: WindowStats::default(),
        }
    }

    pub fn config(&self) -> &WindowConfig {
        &self.config
    }

    pub fn stats(&self) -> WindowStats {
        self.stats
    }

    /// Scopes currently accumulating, across every scope type.
    pub fn tracked(&self) -> usize {
        self.hosts.len() + self.networks.len() + self.slash24.len() + self.hostgroups.len()
    }

    /// Whether a tick would emit anything yet.
    pub fn is_due(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.window_start) >= self.config.window
    }

    /// Counts one classified flow against every scope it belongs to.
    ///
    /// `registry` is consulted for the prefix the local address matched,
    /// which [`ClassificationResult`] records the tenant and hostgroup of
    /// but not the length of. Looking it up here rather than widening
    /// the Phase 3 type keeps this phase additive.
    pub fn ingest(
        &mut self,
        registry: &PrefixRegistry,
        flow: &NormalizedFlow,
        classification: &ClassificationResult,
        now: Instant,
    ) {
        self.stats.flows_ingested = self.stats.flows_ingested.saturating_add(1);

        let mut scoped = false;
        for (addr, direction, tenant, hostgroup) in sides(flow, classification) {
            scoped = true;
            self.count(registry, flow, addr, direction, tenant, hostgroup, now);
        }
        if !scoped {
            self.stats.flows_unscoped = self.stats.flows_unscoped.saturating_add(1);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn count(
        &mut self,
        registry: &PrefixRegistry,
        flow: &NormalizedFlow,
        addr: IpAddr,
        direction: TrafficDirection,
        tenant: Option<&str>,
        hostgroup: Option<&str>,
        now: Instant,
    ) {
        let family = AddressFamily::of(addr);
        let tenant = tenant.unwrap_or(UNATTRIBUTED_TENANT).to_string();
        let key = |scope_type: ScopeType, scope_id: ScopeId| ScopeKey {
            tenant: tenant.clone(),
            scope_type,
            scope_id,
            direction,
            address_family: family,
        };

        Self::accumulate(
            &mut self.hosts,
            key(ScopeType::Host, ScopeId::Host { addr }),
            flow,
            now,
            &mut self.stats,
        );

        if let Some(matched) = registry.lookup(addr) {
            let prefix_len = matched.matched_prefix_len;
            Self::accumulate(
                &mut self.networks,
                key(
                    ScopeType::Prefix,
                    ScopeId::Network {
                        addr: mask(addr, prefix_len),
                        prefix_len,
                    },
                ),
                flow,
                now,
                &mut self.stats,
            );
        }

        // /24 is an IPv4 idea. IPv6 has no equivalent worth pretending
        // to, so it simply has no `Slash24` scope.
        if addr.is_ipv4() {
            Self::accumulate(
                &mut self.slash24,
                key(
                    ScopeType::Slash24,
                    ScopeId::Network {
                        addr: mask(addr, 24),
                        prefix_len: 24,
                    },
                ),
                flow,
                now,
                &mut self.stats,
            );
        }

        if let Some(name) = hostgroup {
            Self::accumulate(
                &mut self.hostgroups,
                key(
                    ScopeType::HostgroupTotal,
                    ScopeId::Hostgroup {
                        name: name.to_string(),
                    },
                ),
                flow,
                now,
                &mut self.stats,
            );
        }
    }

    fn accumulate(
        map: &mut BoundedMap<ScopeKey, Accumulator>,
        key: ScopeKey,
        flow: &NormalizedFlow,
        now: Instant,
        stats: &mut WindowStats,
    ) {
        let outcome = map.upsert(key, now, Accumulator::default, |entry| entry.add(flow));
        match outcome {
            UpsertOutcome::InsertedByEviction => stats.evicted = stats.evicted.saturating_add(1),
            UpsertOutcome::Rejected => stats.rejected = stats.rejected.saturating_add(1),
            UpsertOutcome::Inserted | UpsertOutcome::Updated => {}
        }
    }

    /// Closes the window if it is due, returning one snapshot per scope
    /// in deterministic key order and starting a fresh window.
    ///
    /// Returns empty — and changes nothing — when the window is not yet
    /// due, so a caller may tick as often as it likes.
    pub fn tick(&mut self, now: Instant, wall: SystemTime) -> Vec<DetectionSnapshot> {
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed < self.config.window {
            return Vec::new();
        }
        if skewed(elapsed, self.config.window) {
            self.stats.skewed_ticks = self.stats.skewed_ticks.saturating_add(1);
        }

        let window = self.config.window;
        let mut snapshots = Vec::new();
        for (map, cap) in [
            (&mut self.hosts, self.config.max_hosts),
            (&mut self.networks, self.config.max_networks),
            (&mut self.slash24, self.config.max_slash24),
            (&mut self.hostgroups, self.config.max_hostgroups),
        ] {
            for (key, accumulator) in map.iter() {
                snapshots.push(snapshot(key, accumulator, window, elapsed, now, wall));
            }
            // `BoundedMap` has no `clear`, and adding one would mean
            // editing a Phase 3 crate for a Phase 4 convenience.
            // Replacing the map is equivalent and keeps this phase
            // additive.
            *map = BoundedMap::new(map_config(cap, window));
        }
        snapshots.sort_by(|a, b| a.key.cmp(&b.key));

        self.stats.snapshots_emitted = self
            .stats
            .snapshots_emitted
            .saturating_add(snapshots.len() as u64);
        // Anchored to `now`, not advanced by exactly one window. A late
        // tick should not leave the next window short in an attempt to
        // catch up — that would understate the next window's rates.
        self.window_start = now;
        snapshots
    }
}

/// The local side or sides a flow should be counted against.
fn sides<'a>(
    flow: &NormalizedFlow,
    classification: &'a ClassificationResult,
) -> Vec<(IpAddr, TrafficDirection, Option<&'a str>, Option<&'a str>)> {
    let inbound = (
        flow.destination_addr,
        TrafficDirection::Incoming,
        classification.destination_matched_tenant.as_deref(),
        classification.destination_matched_hostgroup.as_deref(),
    );
    let outbound = (
        flow.source_addr,
        TrafficDirection::Outgoing,
        classification.source_matched_tenant.as_deref(),
        classification.source_matched_hostgroup.as_deref(),
    );
    match classification.direction {
        Direction::Incoming => vec![inbound],
        Direction::Outgoing => vec![outbound],
        Direction::Internal => vec![inbound, outbound],
        // No local side means nothing to defend, so nothing to scope.
        Direction::Other | Direction::Unknown => Vec::new(),
    }
}

fn snapshot(
    key: &ScopeKey,
    accumulator: &Accumulator,
    window: Duration,
    elapsed: Duration,
    now: Instant,
    wall: SystemTime,
) -> DetectionSnapshot {
    let counters = accumulator.counters;
    DetectionSnapshot {
        key: key.clone(),
        window,
        observed_at: now,
        observed_wall: wall,
        rates: MetricRates {
            bps: bits_per_second(counters.bytes, elapsed),
            pps: per_second(counters.packets, elapsed),
            fps: per_second(counters.flows, elapsed),
            tcp_bps: bits_per_second(counters.tcp_bytes, elapsed),
            tcp_pps: per_second(counters.tcp_packets, elapsed),
            udp_bps: bits_per_second(counters.udp_bytes, elapsed),
            udp_pps: per_second(counters.udp_packets, elapsed),
            icmp_bps: bits_per_second(counters.icmp_bytes, elapsed),
            icmp_pps: per_second(counters.icmp_packets, elapsed),
            // The counters track SYN *packets* only; there is no byte
            // counter for them upstream, so the bits-per-second twin is
            // reported as zero rather than invented from an average
            // packet size.
            tcp_syn_bps: 0,
            tcp_syn_pps: per_second(counters.tcp_syn_packets, elapsed),
            fragmented_bps: 0,
            fragmented_pps: per_second(counters.fragmented_packets, elapsed),
            dropped_bps: 0,
            dropped_pps: per_second(counters.dropped_packets, elapsed),
        },
        completeness: accumulator.completeness,
        sampling: accumulator.sampling,
        flows_observed: counters.flows,
        exporters_observed: accumulator.exporters.count(),
    }
}

/// `value * 8 / seconds`, in `u128` so a saturated byte counter cannot
/// overflow the multiply, saturating into `u64` at the end.
fn bits_per_second(bytes: u64, elapsed: Duration) -> u64 {
    per_second(bytes.saturating_mul(8), elapsed)
}

/// `value / seconds`, computed in nanosecond resolution so a sub-second
/// window is not rounded to zero.
fn per_second(value: u64, elapsed: Duration) -> u64 {
    let nanos = elapsed.as_nanos();
    if nanos == 0 {
        return 0;
    }
    let scaled = (value as u128).saturating_mul(1_000_000_000) / nanos;
    scaled.min(u64::MAX as u128) as u64
}

/// More than a tenth away from the configured window in either
/// direction.
fn skewed(elapsed: Duration, window: Duration) -> bool {
    let tolerance = window / 10;
    elapsed > window + tolerance || elapsed + tolerance < window
}

/// Clears the host bits below `prefix_len`.
///
/// An out-of-range length is clamped to the family's width rather than
/// panicking on the shift: this runs on data derived from the network,
/// and a detector that can be crashed by a malformed prefix is a
/// detector an attacker can switch off.
fn mask(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let len = prefix_len.min(32);
            let bits = u32::from(v4);
            let masked = if len == 0 {
                0
            } else {
                bits & (u32::MAX << (32 - len))
            };
            IpAddr::V4(Ipv4Addr::from(masked))
        }
        IpAddr::V6(v6) => {
            let len = prefix_len.min(128);
            let bits = u128::from(v6);
            let masked = if len == 0 {
                0
            } else {
                bits & (u128::MAX << (128 - len))
            };
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tidegard_classifier::classify;
    use tidegard_common::{NormalizedFlowBuilder, Protocol, SamplingRate};

    use super::*;

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

    fn flow(source: [u8; 4], destination: [u8; 4], bytes: u64, packets: u64) -> NormalizedFlow {
        NormalizedFlowBuilder {
            source_addr: IpAddr::V4(Ipv4Addr::from(source)),
            destination_addr: IpAddr::V4(Ipv4Addr::from(destination)),
            source_port: Some(51000),
            destination_port: Some(443),
            protocol: Some(Protocol::Udp),
            tcp_flags: None,
            raw_bytes: bytes,
            raw_packets: packets,
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
        .expect("valid flow")
    }

    fn windows(now: Instant) -> DetectionWindows {
        DetectionWindows::new(
            WindowConfig {
                window: Duration::from_secs(1),
                ..WindowConfig::default()
            },
            now,
        )
    }

    fn feed(windows: &mut DetectionWindows, flow: &NormalizedFlow, now: Instant) {
        let registry = registry();
        let classification = classify(&registry, flow);
        windows.ingest(&registry, flow, &classification, now);
    }

    fn find(
        snapshots: &[DetectionSnapshot],
        scope_type: ScopeType,
        direction: TrafficDirection,
    ) -> Option<&DetectionSnapshot> {
        snapshots
            .iter()
            .find(|s| s.key.scope_type == scope_type && s.key.direction == direction)
    }

    #[test]
    fn an_inbound_flow_is_scoped_on_its_destination() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([198, 51, 100, 9], [203, 0, 113, 7], 1_250_000, 1000),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);

        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming)
            .expect("an incoming host scope");
        assert_eq!(
            host.key.scope_id,
            ScopeId::Host {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
            }
        );
        assert_eq!(host.key.tenant, "acme");
        assert_eq!(host.rates.bps, 10_000_000);
        assert_eq!(host.rates.pps, 1000);
        assert_eq!(host.rates.fps, 1);
        assert_eq!(host.rates.udp_bps, 10_000_000);
        assert_eq!(host.flows_observed, 1);
        assert_eq!(host.exporters_observed, 1);
        assert!(find(&snapshots, ScopeType::Host, TrafficDirection::Outgoing).is_none());
    }

    #[test]
    fn an_outbound_flow_is_scoped_on_its_source() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([203, 0, 113, 7], [198, 51, 100, 9], 1_250_000, 1000),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Outgoing)
            .expect("an outgoing host scope");
        assert_eq!(
            host.key.scope_id,
            ScopeId::Host {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
            }
        );
        assert!(find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).is_none());
    }

    #[test]
    fn an_internal_flow_counts_both_ends_in_their_own_directions() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([203, 0, 113, 1], [203, 0, 113, 7], 1_250_000, 1000),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);

        let incoming = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming)
            .expect("the destination is scoped incoming");
        let outgoing = find(&snapshots, ScopeType::Host, TrafficDirection::Outgoing)
            .expect("the source is scoped outgoing");
        assert_eq!(
            incoming.key.scope_id,
            ScopeId::Host {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
            }
        );
        assert_eq!(
            outgoing.key.scope_id,
            ScopeId::Host {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
            }
        );
        assert_eq!(incoming.rates.bps, outgoing.rates.bps);
    }

    #[test]
    fn a_flow_between_two_remote_hosts_is_not_scoped_at_all() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([198, 51, 100, 1], [198, 51, 100, 2], 1_000_000, 100),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        assert!(snapshots.is_empty());
        assert_eq!(windows.stats().flows_unscoped, 1);
        assert_eq!(windows.stats().flows_ingested, 1);
    }

    #[test]
    fn an_unclassifiable_flow_is_not_scoped_and_does_not_panic() {
        let start = Instant::now();
        let mut windows = windows(start);
        let empty = PrefixRegistry::new();
        let sample = flow([198, 51, 100, 1], [203, 0, 113, 7], 1000, 10);
        let classification = classify(&empty, &sample);
        assert_eq!(classification.direction, Direction::Unknown);
        windows.ingest(&empty, &sample, &classification, start);
        assert!(windows
            .tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH)
            .is_empty());
        assert_eq!(windows.stats().flows_unscoped, 1);
    }

    #[test]
    fn one_flow_produces_every_enabled_scope_type() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        assert_eq!(snapshots.len(), 4);

        let prefix = find(&snapshots, ScopeType::Prefix, TrafficDirection::Incoming)
            .expect("a prefix scope");
        assert_eq!(
            prefix.key.scope_id,
            ScopeId::Network {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
                prefix_len: 24
            }
        );
        let slash24 =
            find(&snapshots, ScopeType::Slash24, TrafficDirection::Incoming).expect("a /24 scope");
        assert_eq!(
            slash24.key.scope_id,
            ScopeId::Network {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
                prefix_len: 24
            }
        );
        let hostgroup = find(
            &snapshots,
            ScopeType::HostgroupTotal,
            TrafficDirection::Incoming,
        )
        .expect("a hostgroup scope");
        assert_eq!(
            hostgroup.key.scope_id,
            ScopeId::Hostgroup {
                name: "edge".to_string()
            }
        );
    }

    #[test]
    fn a_disabled_scope_type_produces_nothing() {
        let start = Instant::now();
        let mut windows = DetectionWindows::new(
            WindowConfig {
                window: Duration::from_secs(1),
                max_networks: 0,
                max_slash24: 0,
                max_hostgroups: 0,
                ..WindowConfig::default()
            },
            start,
        );
        feed(
            &mut windows,
            &flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].key.scope_type, ScopeType::Host);
        assert_eq!(windows.stats().rejected, 3);
    }

    #[test]
    fn a_tick_before_the_window_is_due_changes_nothing() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10),
            start,
        );
        assert!(!windows.is_due(start + Duration::from_millis(999)));
        assert!(windows
            .tick(start + Duration::from_millis(999), SystemTime::UNIX_EPOCH)
            .is_empty());
        assert_eq!(windows.tracked(), 4, "counters must survive an early tick");

        assert!(windows.is_due(start + Duration::from_secs(1)));
        assert_eq!(
            windows
                .tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH)
                .len(),
            4
        );
    }

    #[test]
    fn a_window_starts_empty_after_a_tick() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10),
            start,
        );
        windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        assert_eq!(windows.tracked(), 0);
        assert!(windows
            .tick(start + Duration::from_secs(2), SystemTime::UNIX_EPOCH)
            .is_empty());
    }

    #[test]
    fn rates_are_computed_over_the_time_that_actually_elapsed() {
        let start = Instant::now();
        let mut windows = windows(start);
        feed(
            &mut windows,
            &flow([198, 51, 100, 9], [203, 0, 113, 7], 1_250_000, 1000),
            start,
        );
        // Twice the configured window, so the rate must be halved.
        let snapshots = windows.tick(start + Duration::from_secs(2), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).expect("a host");
        assert_eq!(host.rates.bps, 5_000_000);
        assert_eq!(
            host.window,
            Duration::from_secs(1),
            "the snapshot still reports the configured window, which is what a policy matches on"
        );
        assert_eq!(windows.stats().skewed_ticks, 1);
    }

    #[test]
    fn a_sub_second_window_is_not_rounded_to_zero() {
        let start = Instant::now();
        let mut windows = DetectionWindows::new(
            WindowConfig {
                window: Duration::from_millis(100),
                ..WindowConfig::default()
            },
            start,
        );
        feed(
            &mut windows,
            &flow([198, 51, 100, 9], [203, 0, 113, 7], 125_000, 100),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_millis(100), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).expect("a host");
        assert_eq!(host.rates.bps, 10_000_000);
        assert_eq!(host.rates.pps, 1000);
    }

    #[test]
    fn traffic_accumulates_across_a_window() {
        let start = Instant::now();
        let mut windows = windows(start);
        for tick in 0..4 {
            feed(
                &mut windows,
                &flow([198, 51, 100, 9], [203, 0, 113, 7], 312_500, 250),
                start + Duration::from_millis(tick * 200),
            );
        }
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).expect("a host");
        assert_eq!(host.rates.bps, 10_000_000);
        assert_eq!(host.rates.fps, 4);
        assert_eq!(host.flows_observed, 4);
    }

    #[test]
    fn completeness_reports_what_the_exporter_actually_sent() {
        let start = Instant::now();
        let mut windows = windows(start);
        let mut sample = flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10);
        sample.protocol = None;
        sample.tcp_flags = None;
        sample.forwarding_status_known = false;
        feed(&mut windows, &sample, start);
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).expect("a host");
        assert!(!host.completeness.protocol_seen);
        assert!(!host.completeness.tcp_flags_seen);
        assert!(!host.completeness.forwarding_status_seen);
        assert!(!host.completeness.fragmentation_seen);
    }

    #[test]
    fn one_flow_with_a_field_sets_completeness_for_the_whole_scope() {
        let start = Instant::now();
        let mut windows = windows(start);
        let mut without = flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10);
        without.tcp_flags = None;
        let mut with = flow([198, 51, 100, 8], [203, 0, 113, 7], 1000, 10);
        with.tcp_flags = Some(0x02);
        feed(&mut windows, &without, start);
        feed(&mut windows, &with, start);
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).expect("a host");
        assert!(host.completeness.tcp_flags_seen);
    }

    #[test]
    fn sampling_status_records_the_weakest_source_and_the_largest_rate() {
        let start = Instant::now();
        let mut windows = windows(start);
        let mut sampled = flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10);
        sampled.sampling_rate = SamplingRate::new(1000).expect("non-zero");
        sampled.sampling_source = SamplingSource::GlobalDefault;
        feed(&mut windows, &sampled, start);
        feed(
            &mut windows,
            &flow([198, 51, 100, 8], [203, 0, 113, 7], 1000, 10),
            start,
        );
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).expect("a host");
        assert!(host.sampling.corrected);
        assert!(host.sampling.used_global_default);
        assert_eq!(host.sampling.max_rate, 1000);
    }

    #[test]
    fn distinct_exporters_are_counted() {
        let start = Instant::now();
        let mut windows = windows(start);
        for last in 1..=3u8 {
            let mut sample = flow([198, 51, 100, 9], [203, 0, 113, 7], 1000, 10);
            sample.exporter = IpAddr::V4(Ipv4Addr::new(198, 51, 100, last));
            feed(&mut windows, &sample, start);
        }
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        let host = find(&snapshots, ScopeType::Host, TrafficDirection::Incoming).expect("a host");
        assert!(
            host.exporters_observed >= 1 && host.exporters_observed <= 3,
            "the sketch may undercount but never overcounts, got {}",
            host.exporters_observed
        );
    }

    #[test]
    fn a_full_map_evicts_and_counts_rather_than_growing() {
        let start = Instant::now();
        let mut windows = DetectionWindows::new(
            WindowConfig {
                window: Duration::from_secs(1),
                max_hosts: 2,
                max_networks: 0,
                max_slash24: 0,
                max_hostgroups: 0,
            },
            start,
        );
        for last in 1..=10u8 {
            feed(
                &mut windows,
                &flow([198, 51, 100, 9], [203, 0, 113, last], 1000, 10),
                start + Duration::from_millis(last as u64),
            );
        }
        assert_eq!(windows.tracked(), 2);
        assert_eq!(windows.stats().evicted, 8);
    }

    #[test]
    fn snapshots_come_back_in_a_stable_order() {
        let start = Instant::now();
        let mut windows = windows(start);
        for last in [7u8, 3, 9, 1] {
            feed(
                &mut windows,
                &flow([198, 51, 100, 9], [203, 0, 113, last], 1000, 10),
                start,
            );
        }
        let first = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        let keys: Vec<_> = first.iter().map(|s| s.key.clone()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn a_v6_flow_gets_no_slash24_scope() {
        let start = Instant::now();
        let mut registry = PrefixRegistry::new();
        registry
            .insert(
                "2001:db8::".parse::<IpAddr>().expect("valid"),
                32,
                "acme",
                None,
            )
            .expect("valid prefix");
        let mut windows = windows(start);
        let sample = NormalizedFlowBuilder {
            source_addr: "2001:db8:1::1".parse().expect("valid"),
            destination_addr: "2001:db8:2::2".parse().expect("valid"),
            source_port: None,
            destination_port: None,
            protocol: Some(Protocol::Tcp),
            tcp_flags: None,
            raw_bytes: 1000,
            raw_packets: 10,
            input_interface: None,
            output_interface: None,
            source_asn: None,
            destination_asn: None,
            exporter: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            observation_domain_id: 0,
            start_time: None,
            end_time: None,
            fragmented: false,
            dropped: false,
            forwarding_status_known: false,
        }
        .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
        .expect("valid flow");
        let classification = classify(&registry, &sample);
        assert_eq!(classification.direction, Direction::Internal);
        windows.ingest(&registry, &sample, &classification, start);
        let snapshots = windows.tick(start + Duration::from_secs(1), SystemTime::UNIX_EPOCH);
        assert!(snapshots
            .iter()
            .all(|s| s.key.scope_type != ScopeType::Slash24));
        assert!(snapshots
            .iter()
            .all(|s| s.key.address_family == AddressFamily::Ipv6));
        let prefix = find(&snapshots, ScopeType::Prefix, TrafficDirection::Incoming)
            .expect("a v6 prefix scope");
        assert_eq!(
            prefix.key.scope_id,
            ScopeId::Network {
                addr: "2001:db8::".parse::<IpAddr>().expect("valid"),
                prefix_len: 32
            }
        );
    }

    #[test]
    fn masking_clears_the_host_bits() {
        assert_eq!(
            mask(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)), 24),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0))
        );
        assert_eq!(
            mask(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)), 0),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            mask(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)), 32),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))
        );
        assert_eq!(
            mask("2001:db8:1:2::9".parse().expect("valid"), 48),
            "2001:db8:1::".parse::<IpAddr>().expect("valid")
        );
    }

    #[test]
    fn an_out_of_range_prefix_length_is_clamped_not_panicked_on() {
        assert_eq!(
            mask(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)), 255),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))
        );
        assert_eq!(
            mask("2001:db8::1".parse().expect("valid"), 255),
            "2001:db8::1".parse::<IpAddr>().expect("valid")
        );
    }

    #[test]
    fn rate_arithmetic_saturates_instead_of_overflowing() {
        assert_eq!(bits_per_second(u64::MAX, Duration::from_nanos(1)), u64::MAX);
        assert_eq!(per_second(1000, Duration::ZERO), 0);
        assert_eq!(per_second(0, Duration::from_secs(1)), 0);
    }

    #[test]
    fn skew_is_measured_against_a_ten_percent_tolerance() {
        let window = Duration::from_secs(10);
        assert!(!skewed(Duration::from_secs(10), window));
        assert!(!skewed(Duration::from_millis(10_999), window));
        assert!(!skewed(Duration::from_millis(9_001), window));
        assert!(skewed(Duration::from_millis(11_001), window));
        assert!(skewed(Duration::from_millis(8_999), window));
    }
}
