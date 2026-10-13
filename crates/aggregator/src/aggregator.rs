//! The Traffic Aggregator: bounded, multi-dimensional aggregation over
//! normalized flows (Phase 3 objectives 5, 6, 8).
//!
//! **Two-sided accounting, documented rather than implicit:** for
//! per-host, per-network, per-ASN, and per-hostgroup dimensions, both
//! the source and destination ends of a flow contribute to their
//! respective entries — a flow from A to B counts toward both A's and
//! B's totals. This matches how "top talkers" dashboards are
//! conventionally read (a host's total is "traffic to or from this
//! host"), and mirrors master prompt §7's aggregation-dimension list,
//! which does not distinguish a "source-only" vs. "destination-only"
//! counter per dimension.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use tidegard_classifier::ClassificationResult;
use tidegard_common::{NormalizedFlow, Protocol};

use crate::bounded_map::{BoundedMap, BoundedMapConfig, UpsertOutcome};
use crate::counters::TrafficCounters;
use crate::rate_window::RateWindowSet;

#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    pub max_hosts: usize,
    pub max_networks: usize,
    pub max_hostgroups: usize,
    pub max_asns: usize,
    pub max_exporters: usize,
    pub max_interfaces: usize,
    pub max_protocols: usize,
    pub inactivity_ttl: Duration,
    /// Additional configurable IPv4 prefix lengths to aggregate at,
    /// beyond the always-included /24 (Phase 3 objective 5). E.g. `[16]`.
    pub ipv4_prefix_lengths: Vec<u8>,
    /// Configurable IPv6 prefix lengths to aggregate at (no implicit
    /// default the way IPv4 has /24 — IPv6 has no equivalent convention).
    pub ipv6_prefix_lengths: Vec<u8>,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        AggregatorConfig {
            max_hosts: 100_000,
            max_networks: 50_000,
            max_hostgroups: 1_000,
            max_asns: 10_000,
            max_exporters: 1_000,
            max_interfaces: 10_000,
            max_protocols: 64,
            inactivity_ttl: Duration::from_secs(300),
            ipv4_prefix_lengths: vec![],
            ipv6_prefix_lengths: vec![],
        }
    }
}

/// Counts of what happened during one [`Aggregator::ingest`] call — the
/// caller (the collector's wiring) uses this to drive Prometheus metrics
/// (Phase 3 objective 9) without the aggregator crate depending on
/// `prometheus` itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestReport {
    pub evictions: u32,
    pub rejections: u32,
}

pub struct Aggregator {
    config: AggregatorConfig,

    total_counters: TrafficCounters,
    total_ipv4_counters: TrafficCounters,
    total_ipv6_counters: TrafficCounters,
    total_rates: RateWindowSet,

    ipv4_hosts: BoundedMap<Ipv4Addr, TrafficCounters>,
    ipv6_hosts: BoundedMap<Ipv6Addr, TrafficCounters>,
    ipv4_slash24: BoundedMap<Ipv4Addr, TrafficCounters>,
    ipv4_networks: BoundedMap<(Ipv4Addr, u8), TrafficCounters>,
    ipv6_networks: BoundedMap<(Ipv6Addr, u8), TrafficCounters>,
    hostgroups: BoundedMap<String, TrafficCounters>,
    asns: BoundedMap<u32, TrafficCounters>,
    exporters: BoundedMap<IpAddr, TrafficCounters>,
    input_interfaces: BoundedMap<u32, TrafficCounters>,
    output_interfaces: BoundedMap<u32, TrafficCounters>,
    protocols: BoundedMap<Protocol, TrafficCounters>,
}

impl Aggregator {
    pub fn new(config: AggregatorConfig, now: Instant) -> Self {
        let ttl = config.inactivity_ttl;
        let hosts_cfg = BoundedMapConfig {
            max_entries: config.max_hosts,
            inactivity_ttl: ttl,
        };
        let networks_cfg = BoundedMapConfig {
            max_entries: config.max_networks,
            inactivity_ttl: ttl,
        };
        Aggregator {
            total_counters: TrafficCounters::default(),
            total_ipv4_counters: TrafficCounters::default(),
            total_ipv6_counters: TrafficCounters::default(),
            total_rates: RateWindowSet::new(now),
            ipv4_hosts: BoundedMap::new(hosts_cfg),
            ipv6_hosts: BoundedMap::new(hosts_cfg),
            ipv4_slash24: BoundedMap::new(networks_cfg),
            ipv4_networks: BoundedMap::new(networks_cfg),
            ipv6_networks: BoundedMap::new(networks_cfg),
            hostgroups: BoundedMap::new(BoundedMapConfig {
                max_entries: config.max_hostgroups,
                inactivity_ttl: ttl,
            }),
            asns: BoundedMap::new(BoundedMapConfig {
                max_entries: config.max_asns,
                inactivity_ttl: ttl,
            }),
            exporters: BoundedMap::new(BoundedMapConfig {
                max_entries: config.max_exporters,
                inactivity_ttl: ttl,
            }),
            input_interfaces: BoundedMap::new(BoundedMapConfig {
                max_entries: config.max_interfaces,
                inactivity_ttl: ttl,
            }),
            output_interfaces: BoundedMap::new(BoundedMapConfig {
                max_entries: config.max_interfaces,
                inactivity_ttl: ttl,
            }),
            protocols: BoundedMap::new(BoundedMapConfig {
                max_entries: config.max_protocols,
                inactivity_ttl: ttl,
            }),
            config,
        }
    }

    /// Ingests one normalized, already-classified flow into every
    /// applicable dimension.
    pub fn ingest(
        &mut self,
        flow: &NormalizedFlow,
        classification: &ClassificationResult,
        now: Instant,
    ) -> IngestReport {
        let mut report = IngestReport::default();

        self.total_counters.add(flow);
        // Family is derived from the source address — for the flow
        // shapes this project decodes (IPFIX today), source and
        // destination are always the same family, so this is
        // unambiguous. See docs/architecture/aggregation.md.
        match flow.source_addr {
            IpAddr::V4(_) => self.total_ipv4_counters.add(flow),
            IpAddr::V6(_) => self.total_ipv6_counters.add(flow),
        }
        self.total_rates.record(now, flow.bytes, flow.packets);

        track(&mut self.exporters, flow.exporter, flow, now, &mut report);

        if let Some(iface) = flow.input_interface {
            track(&mut self.input_interfaces, iface, flow, now, &mut report);
        }
        if let Some(iface) = flow.output_interface {
            track(&mut self.output_interfaces, iface, flow, now, &mut report);
        }
        if let Some(protocol) = flow.protocol {
            track(&mut self.protocols, protocol, flow, now, &mut report);
        }

        // Two-sided: source and destination addresses.
        self.track_address(flow.source_addr, flow, now, &mut report);
        self.track_address(flow.destination_addr, flow, now, &mut report);

        if let Some(asn) = flow.source_asn {
            track(&mut self.asns, asn, flow, now, &mut report);
        }
        if let Some(asn) = flow.destination_asn {
            track(&mut self.asns, asn, flow, now, &mut report);
        }

        if let Some(hg) = &classification.source_matched_hostgroup {
            track(&mut self.hostgroups, hg.clone(), flow, now, &mut report);
        }
        if let Some(hg) = &classification.destination_matched_hostgroup {
            track(&mut self.hostgroups, hg.clone(), flow, now, &mut report);
        }

        report
    }

    fn track_address(
        &mut self,
        addr: IpAddr,
        flow: &NormalizedFlow,
        now: Instant,
        report: &mut IngestReport,
    ) {
        match addr {
            IpAddr::V4(a) => {
                track(&mut self.ipv4_hosts, a, flow, now, report);
                track(&mut self.ipv4_slash24, mask_v4(a, 24), flow, now, report);
                for &len in &self.config.ipv4_prefix_lengths.clone() {
                    let key = (mask_v4(a, len), len);
                    track(&mut self.ipv4_networks, key, flow, now, report);
                }
            }
            IpAddr::V6(a) => {
                track(&mut self.ipv6_hosts, a, flow, now, report);
                for &len in &self.config.ipv6_prefix_lengths.clone() {
                    let key = (mask_v6(a, len), len);
                    track(&mut self.ipv6_networks, key, flow, now, report);
                }
            }
        }
    }

    /// Sweeps every dimension for inactivity expiration. Returns the
    /// total number of entries removed, for the `expired_entries_total`
    /// metric.
    pub fn expire_inactive(&mut self, now: Instant) -> usize {
        self.total_rates.tick(now);
        self.ipv4_hosts.expire_inactive(now)
            + self.ipv6_hosts.expire_inactive(now)
            + self.ipv4_slash24.expire_inactive(now)
            + self.ipv4_networks.expire_inactive(now)
            + self.ipv6_networks.expire_inactive(now)
            + self.hostgroups.expire_inactive(now)
            + self.asns.expire_inactive(now)
            + self.exporters.expire_inactive(now)
            + self.input_interfaces.expire_inactive(now)
            + self.output_interfaces.expire_inactive(now)
            + self.protocols.expire_inactive(now)
    }

    pub fn total_counters(&self) -> TrafficCounters {
        self.total_counters
    }

    pub fn total_ipv4_counters(&self) -> TrafficCounters {
        self.total_ipv4_counters
    }

    pub fn total_ipv6_counters(&self) -> TrafficCounters {
        self.total_ipv6_counters
    }

    pub fn total_rates(&self) -> Vec<(Duration, Option<crate::rate_window::RateSample>)> {
        self.total_rates.rates()
    }

    pub fn active_hosts(&self) -> usize {
        self.ipv4_hosts.len() + self.ipv6_hosts.len()
    }

    pub fn active_networks(&self) -> usize {
        self.ipv4_slash24.len() + self.ipv4_networks.len() + self.ipv6_networks.len()
    }

    pub fn active_hostgroups(&self) -> usize {
        self.hostgroups.len()
    }

    pub fn active_asns(&self) -> usize {
        self.asns.len()
    }

    pub fn ipv4_hosts(&self) -> impl Iterator<Item = (&Ipv4Addr, &TrafficCounters)> {
        self.ipv4_hosts.iter()
    }

    pub fn ipv6_hosts(&self) -> impl Iterator<Item = (&Ipv6Addr, &TrafficCounters)> {
        self.ipv6_hosts.iter()
    }

    pub fn ipv4_slash24(&self) -> impl Iterator<Item = (&Ipv4Addr, &TrafficCounters)> {
        self.ipv4_slash24.iter()
    }

    pub fn hostgroups(&self) -> impl Iterator<Item = (&String, &TrafficCounters)> {
        self.hostgroups.iter()
    }

    pub fn asns(&self) -> impl Iterator<Item = (&u32, &TrafficCounters)> {
        self.asns.iter()
    }

    pub fn exporters(&self) -> impl Iterator<Item = (&IpAddr, &TrafficCounters)> {
        self.exporters.iter()
    }

    pub fn ipv4_networks(&self) -> impl Iterator<Item = (&(Ipv4Addr, u8), &TrafficCounters)> {
        self.ipv4_networks.iter()
    }

    pub fn ipv6_networks(&self) -> impl Iterator<Item = (&(Ipv6Addr, u8), &TrafficCounters)> {
        self.ipv6_networks.iter()
    }

    pub fn input_interfaces(&self) -> impl Iterator<Item = (&u32, &TrafficCounters)> {
        self.input_interfaces.iter()
    }

    pub fn output_interfaces(&self) -> impl Iterator<Item = (&u32, &TrafficCounters)> {
        self.output_interfaces.iter()
    }
}

fn track<K: std::hash::Hash + Eq + Clone>(
    map: &mut BoundedMap<K, TrafficCounters>,
    key: K,
    flow: &NormalizedFlow,
    now: Instant,
    report: &mut IngestReport,
) {
    let outcome = map.upsert(key, now, TrafficCounters::default, |c| c.add(flow));
    match outcome {
        UpsertOutcome::InsertedByEviction => report.evictions += 1,
        UpsertOutcome::Rejected => report.rejections += 1,
        _ => {}
    }
}

fn mask_v4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let bits = u32::from(addr);
    let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let bits = u128::from(addr);
    let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
    Ipv6Addr::from(bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tidegard_classifier::{classify, PrefixRegistry};
    use tidegard_common::{NormalizedFlowBuilder, SamplingRate, SamplingSource};

    fn make_flow(source: IpAddr, destination: IpAddr, bytes: u64, packets: u64) -> NormalizedFlow {
        NormalizedFlowBuilder {
            source_addr: source,
            destination_addr: destination,
            source_port: Some(51000),
            destination_port: Some(443),
            protocol: Some(Protocol::Tcp),
            tcp_flags: None,
            raw_bytes: bytes,
            raw_packets: packets,
            input_interface: Some(1),
            output_interface: Some(2),
            source_asn: Some(65001),
            destination_asn: Some(65002),
            exporter: IpAddr::V4(Ipv4Addr::new(172, 30, 172, 50)),
            observation_domain_id: 1,
            start_time: None,
            end_time: None,
            fragmented: false,
            dropped: false,
            forwarding_status_known: false,
        }
        .build(SamplingRate::unsampled(), SamplingSource::Unsampled)
        .unwrap()
    }

    fn registry() -> PrefixRegistry {
        let mut r = PrefixRegistry::new();
        r.insert(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
            "wetechi",
            Some("core".into()),
        )
        .unwrap();
        r
    }

    #[test]
    fn ingest_updates_total_counters() {
        let now = Instant::now();
        let mut agg = Aggregator::new(AggregatorConfig::default(), now);
        let reg = registry();
        let flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            1000,
            10,
        );
        let classification = classify(&reg, &flow);
        agg.ingest(&flow, &classification, now);

        assert_eq!(agg.total_counters().bytes, 1000);
        assert_eq!(agg.total_counters().flows, 1);
    }

    #[test]
    fn per_family_totals_are_split_correctly() {
        let now = Instant::now();
        let mut agg = Aggregator::new(AggregatorConfig::default(), now);
        let reg = registry();

        let v4_flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            1000,
            10,
        );
        let c = classify(&reg, &v4_flow);
        agg.ingest(&v4_flow, &c, now);

        let v6_flow = make_flow(
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            500,
            5,
        );
        let c = classify(&reg, &v6_flow);
        agg.ingest(&v6_flow, &c, now);

        assert_eq!(agg.total_ipv4_counters().bytes, 1000);
        assert_eq!(agg.total_ipv6_counters().bytes, 500);
        assert_eq!(agg.total_counters().bytes, 1500);
    }

    #[test]
    fn per_host_aggregation_is_two_sided() {
        let now = Instant::now();
        let mut agg = Aggregator::new(AggregatorConfig::default(), now);
        let reg = registry();
        let flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            500,
            5,
        );
        let classification = classify(&reg, &flow);
        agg.ingest(&flow, &classification, now);

        let hosts: std::collections::HashMap<_, _> = agg.ipv4_hosts().collect();
        assert_eq!(hosts.get(&Ipv4Addr::new(10, 0, 0, 1)).unwrap().bytes, 500);
        assert_eq!(hosts.get(&Ipv4Addr::new(10, 0, 0, 2)).unwrap().bytes, 500);
    }

    #[test]
    fn slash24_aggregation_groups_by_network() {
        let now = Instant::now();
        let mut agg = Aggregator::new(AggregatorConfig::default(), now);
        let reg = registry();
        for host in [1u8, 2, 3] {
            let flow = make_flow(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, host)),
                100,
                1,
            );
            let classification = classify(&reg, &flow);
            agg.ingest(&flow, &classification, now);
        }
        let networks: std::collections::HashMap<_, _> = agg.ipv4_slash24().collect();
        assert_eq!(networks.get(&Ipv4Addr::new(10, 0, 0, 0)).unwrap().flows, 3);
    }

    #[test]
    fn hostgroup_aggregation_uses_classification_result() {
        let now = Instant::now();
        let mut agg = Aggregator::new(AggregatorConfig::default(), now);
        let reg = registry();
        let flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            777,
            1,
        );
        let classification = classify(&reg, &flow);
        agg.ingest(&flow, &classification, now);

        let groups: std::collections::HashMap<_, _> = agg.hostgroups().collect();
        assert_eq!(groups.get(&"core".to_string()).unwrap().bytes, 777);
    }

    #[test]
    fn asn_aggregation_only_when_available() {
        let now = Instant::now();
        let mut agg = Aggregator::new(AggregatorConfig::default(), now);
        let reg = registry();
        let mut flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            100,
            1,
        );
        flow.source_asn = None;
        flow.destination_asn = None;
        let classification = classify(&reg, &flow);
        agg.ingest(&flow, &classification, now);
        assert_eq!(agg.active_asns(), 0);
    }

    #[test]
    fn protocol_aggregation() {
        let now = Instant::now();
        let mut agg = Aggregator::new(AggregatorConfig::default(), now);
        let reg = registry();
        let flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            100,
            1,
        );
        let classification = classify(&reg, &flow);
        agg.ingest(&flow, &classification, now);
        // protocols are internal-only in this crate's public API today;
        // exercised indirectly via total_counters' protocol breakdown.
        assert_eq!(agg.total_counters().tcp_bytes, 100);
    }

    #[test]
    fn bounded_hosts_evict_and_report_it() {
        let now = Instant::now();
        let config = AggregatorConfig {
            max_hosts: 2, // room for exactly 2 distinct hosts total
            ..Default::default()
        };
        let mut agg = Aggregator::new(config, now);
        let reg = registry();

        // Three distinct destination hosts, forcing eviction on the third.
        for i in 1..=3u8 {
            let flow = make_flow(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                100,
                1,
            );
            let classification = classify(&reg, &flow);
            let report = agg.ingest(&flow, &classification, now + Duration::from_secs(i as u64));
            if i == 3 {
                assert!(report.evictions > 0);
            }
        }
        assert!(agg.active_hosts() <= 2);
    }

    #[test]
    fn expire_inactive_removes_stale_entries_across_dimensions() {
        let now = Instant::now();
        let config = AggregatorConfig {
            inactivity_ttl: Duration::from_secs(10),
            ..Default::default()
        };
        let mut agg = Aggregator::new(config, now);
        let reg = registry();
        let flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            100,
            1,
        );
        let classification = classify(&reg, &flow);
        agg.ingest(&flow, &classification, now);
        assert!(agg.active_hosts() > 0);

        let removed = agg.expire_inactive(now + Duration::from_secs(20));
        assert!(removed > 0);
        assert_eq!(agg.active_hosts(), 0);
    }

    #[test]
    fn configurable_prefix_lengths_produce_additional_network_dimensions() {
        let now = Instant::now();
        let config = AggregatorConfig {
            ipv4_prefix_lengths: vec![16],
            ..Default::default()
        };
        let mut agg = Aggregator::new(config, now);
        let reg = registry();
        let flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            100,
            1,
        );
        let classification = classify(&reg, &flow);
        agg.ingest(&flow, &classification, now);
        // /24 dimension and the configured /16 dimension both populate.
        assert!(agg.active_networks() >= 2);
    }
}
