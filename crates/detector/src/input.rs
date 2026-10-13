//! What the detector evaluates: a protocol-independent snapshot of one
//! scope's traffic over one rate window.
//!
//! Nothing in this module mentions IPFIX, NetFlow, or sFlow. The detector
//! sees rates attached to a scope and a direction, which is the whole
//! reason `NormalizedFlow` exists upstream — a future sFlow collector
//! feeds the same detector without the detector changing.
//!
//! **Canonical units are integers.** Rates are bits per second, packets
//! per second, and flows per second, all `u64`. Operators think in Mbps
//! and Gbps, and policies are written that way, but every comparison the
//! engine performs happens in these units. Floating point is confined to
//! presentation: comparing an `f64` rate against an `f64` threshold makes
//! "exactly at the threshold" a coin toss, and "exactly at the threshold"
//! is precisely the boundary operators care about most.

use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use tidegard_classifier::Direction;

/// IP version of the traffic a snapshot describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AddressFamily::Ipv4 => "ipv4",
            AddressFamily::Ipv6 => "ipv6",
        }
    }
}

/// The detector's own direction enum.
///
/// This deliberately mirrors [`tidegard_classifier::Direction`]
/// rather than reusing it: direction is part of a hash-map key and of
/// every serialized event here, and the classifier's type derives
/// neither `Hash` nor `Serialize`. Adding those upstream would make the
/// classifier's public API answer to the detector's storage decisions.
/// The mapping is total and tested, so nothing can be silently lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    Incoming,
    Outgoing,
    Internal,
    Other,
    Unknown,
}

impl From<Direction> for TrafficDirection {
    fn from(d: Direction) -> Self {
        match d {
            Direction::Incoming => TrafficDirection::Incoming,
            Direction::Outgoing => TrafficDirection::Outgoing,
            Direction::Internal => TrafficDirection::Internal,
            Direction::Other => TrafficDirection::Other,
            Direction::Unknown => TrafficDirection::Unknown,
        }
    }
}

impl TrafficDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrafficDirection::Incoming => "incoming",
            TrafficDirection::Outgoing => "outgoing",
            TrafficDirection::Internal => "internal",
            TrafficDirection::Other => "other",
            TrafficDirection::Unknown => "unknown",
        }
    }
}

/// Which kind of thing a policy targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScopeType {
    /// A single address.
    Host,
    /// An explicitly configured prefix.
    Prefix,
    /// The implicit IPv4 /24 containing an address. Kept distinct from
    /// `Prefix` so a /24 policy and a configured-prefix policy that
    /// happen to cover the same addresses stay separately addressable.
    Slash24,
    /// Every address belonging to one hostgroup, summed.
    HostgroupTotal,
}

impl ScopeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScopeType::Host => "host",
            ScopeType::Prefix => "prefix",
            ScopeType::Slash24 => "slash24",
            ScopeType::HostgroupTotal => "hostgroupTotal",
        }
    }

    /// How specific this scope is, for precedence ordering. Higher wins.
    /// See ADR 0009.
    pub fn specificity(&self) -> u8 {
        match self {
            ScopeType::Host => 40,
            ScopeType::Prefix => 30,
            ScopeType::Slash24 => 20,
            ScopeType::HostgroupTotal => 10,
        }
    }
}

/// Which particular host, network, or hostgroup a snapshot describes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ScopeId {
    Host {
        addr: IpAddr,
    },
    Network {
        addr: IpAddr,
        #[serde(rename = "prefixLen")]
        prefix_len: u8,
    },
    Hostgroup {
        name: String,
    },
}

impl std::fmt::Display for ScopeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeId::Host { addr } => write!(f, "{addr}"),
            ScopeId::Network { addr, prefix_len } => write!(f, "{addr}/{prefix_len}"),
            ScopeId::Hostgroup { name } => write!(f, "{name}"),
        }
    }
}

/// Everything that identifies one evaluated series.
///
/// Ordering is derived and used for deterministic iteration — the engine
/// must never depend on hash-map ordering, or two runs over identical
/// input could report different policies as the winner.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeKey {
    pub tenant: String,
    pub scope_type: ScopeType,
    pub scope_id: ScopeId,
    pub direction: TrafficDirection,
    pub address_family: AddressFamily,
}

/// The metrics a threshold can be written against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MetricKind {
    Bps,
    Pps,
    Fps,
    TcpBps,
    TcpPps,
    UdpBps,
    UdpPps,
    IcmpBps,
    IcmpPps,
    TcpSynBps,
    TcpSynPps,
    FragmentedBps,
    FragmentedPps,
    DroppedBps,
    DroppedPps,
}

/// The unit a metric is measured in, which decides how a policy's
/// threshold number is converted into canonical units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricUnit {
    BitsPerSecond,
    PacketsPerSecond,
    FlowsPerSecond,
}

impl MetricUnit {
    /// The short form an operator reads on an event or a graph axis.
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricUnit::BitsPerSecond => "bps",
            MetricUnit::PacketsPerSecond => "pps",
            MetricUnit::FlowsPerSecond => "fps",
        }
    }
}

pub const ALL_METRIC_KINDS: [MetricKind; 15] = [
    MetricKind::Bps,
    MetricKind::Pps,
    MetricKind::Fps,
    MetricKind::TcpBps,
    MetricKind::TcpPps,
    MetricKind::UdpBps,
    MetricKind::UdpPps,
    MetricKind::IcmpBps,
    MetricKind::IcmpPps,
    MetricKind::TcpSynBps,
    MetricKind::TcpSynPps,
    MetricKind::FragmentedBps,
    MetricKind::FragmentedPps,
    MetricKind::DroppedBps,
    MetricKind::DroppedPps,
];

impl MetricKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricKind::Bps => "bps",
            MetricKind::Pps => "pps",
            MetricKind::Fps => "fps",
            MetricKind::TcpBps => "tcpBps",
            MetricKind::TcpPps => "tcpPps",
            MetricKind::UdpBps => "udpBps",
            MetricKind::UdpPps => "udpPps",
            MetricKind::IcmpBps => "icmpBps",
            MetricKind::IcmpPps => "icmpPps",
            MetricKind::TcpSynBps => "tcpSynBps",
            MetricKind::TcpSynPps => "tcpSynPps",
            MetricKind::FragmentedBps => "fragmentedBps",
            MetricKind::FragmentedPps => "fragmentedPps",
            MetricKind::DroppedBps => "droppedBps",
            MetricKind::DroppedPps => "droppedPps",
        }
    }

    pub fn unit(&self) -> MetricUnit {
        match self {
            MetricKind::Bps
            | MetricKind::TcpBps
            | MetricKind::UdpBps
            | MetricKind::IcmpBps
            | MetricKind::TcpSynBps
            | MetricKind::FragmentedBps
            | MetricKind::DroppedBps => MetricUnit::BitsPerSecond,
            MetricKind::Pps
            | MetricKind::TcpPps
            | MetricKind::UdpPps
            | MetricKind::IcmpPps
            | MetricKind::TcpSynPps
            | MetricKind::FragmentedPps
            | MetricKind::DroppedPps => MetricUnit::PacketsPerSecond,
            MetricKind::Fps => MetricUnit::FlowsPerSecond,
        }
    }

    /// Which completeness flag must be set for this metric to be
    /// meaningful. `None` means the metric is always meaningful.
    ///
    /// This is what stops the detector from reporting "0 dropped pps, so
    /// nothing is wrong" when the exporter never sent a forwarding-status
    /// field at all. Absent data and observed-zero are different facts,
    /// and only one of them is evidence.
    pub fn required_completeness(&self) -> Option<CompletenessFlag> {
        match self {
            MetricKind::TcpSynBps | MetricKind::TcpSynPps => Some(CompletenessFlag::TcpFlags),
            MetricKind::FragmentedBps | MetricKind::FragmentedPps => {
                Some(CompletenessFlag::Fragmentation)
            }
            MetricKind::DroppedBps | MetricKind::DroppedPps => {
                Some(CompletenessFlag::ForwardingStatus)
            }
            MetricKind::TcpBps
            | MetricKind::TcpPps
            | MetricKind::UdpBps
            | MetricKind::UdpPps
            | MetricKind::IcmpBps
            | MetricKind::IcmpPps => Some(CompletenessFlag::Protocol),
            MetricKind::Bps | MetricKind::Pps | MetricKind::Fps => None,
        }
    }
}

/// An optional field the upstream protocol may or may not have carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CompletenessFlag {
    Protocol,
    TcpFlags,
    Fragmentation,
    ForwardingStatus,
}

/// Which optional fields were actually observed during a window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataCompleteness {
    pub protocol_seen: bool,
    pub tcp_flags_seen: bool,
    pub fragmentation_seen: bool,
    pub forwarding_status_seen: bool,
}

impl DataCompleteness {
    pub fn has(&self, flag: CompletenessFlag) -> bool {
        match flag {
            CompletenessFlag::Protocol => self.protocol_seen,
            CompletenessFlag::TcpFlags => self.tcp_flags_seen,
            CompletenessFlag::Fragmentation => self.fragmentation_seen,
            CompletenessFlag::ForwardingStatus => self.forwarding_status_seen,
        }
    }

    pub fn merge(&mut self, other: DataCompleteness) {
        self.protocol_seen |= other.protocol_seen;
        self.tcp_flags_seen |= other.tcp_flags_seen;
        self.fragmentation_seen |= other.fragmentation_seen;
        self.forwarding_status_seen |= other.forwarding_status_seen;
    }
}

/// How much to trust the magnitude of a snapshot's rates.
///
/// A rate derived from flows corrected by a guessed global default is a
/// weaker basis for opening an event than one from an exporter-declared
/// rate, and an operator reading the event deserves to know which they
/// are looking at. Phase 4 records this on the event; it does not yet
/// change detection behaviour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SamplingStatus {
    /// Any contributing flow carried a sampling rate above 1.
    pub corrected: bool,
    /// Any contributing flow's rate came from a global default rather
    /// than from the exporter or the record itself — the weakest tier.
    pub used_global_default: bool,
    /// The largest sampling divisor seen. A 1-in-10000 sample means one
    /// observed packet is scaled to 10000, so a single stray record
    /// moves the rate a long way.
    pub max_rate: u32,
}

impl SamplingStatus {
    pub fn merge(&mut self, other: SamplingStatus) {
        self.corrected |= other.corrected;
        self.used_global_default |= other.used_global_default;
        self.max_rate = self.max_rate.max(other.max_rate);
    }
}

/// Canonical-unit rates for one scope over one window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricRates {
    pub bps: u64,
    pub pps: u64,
    pub fps: u64,
    pub tcp_bps: u64,
    pub tcp_pps: u64,
    pub udp_bps: u64,
    pub udp_pps: u64,
    pub icmp_bps: u64,
    pub icmp_pps: u64,
    pub tcp_syn_bps: u64,
    pub tcp_syn_pps: u64,
    pub fragmented_bps: u64,
    pub fragmented_pps: u64,
    pub dropped_bps: u64,
    pub dropped_pps: u64,
}

impl MetricRates {
    pub fn get(&self, kind: MetricKind) -> u64 {
        match kind {
            MetricKind::Bps => self.bps,
            MetricKind::Pps => self.pps,
            MetricKind::Fps => self.fps,
            MetricKind::TcpBps => self.tcp_bps,
            MetricKind::TcpPps => self.tcp_pps,
            MetricKind::UdpBps => self.udp_bps,
            MetricKind::UdpPps => self.udp_pps,
            MetricKind::IcmpBps => self.icmp_bps,
            MetricKind::IcmpPps => self.icmp_pps,
            MetricKind::TcpSynBps => self.tcp_syn_bps,
            MetricKind::TcpSynPps => self.tcp_syn_pps,
            MetricKind::FragmentedBps => self.fragmented_bps,
            MetricKind::FragmentedPps => self.fragmented_pps,
            MetricKind::DroppedBps => self.dropped_bps,
            MetricKind::DroppedPps => self.dropped_pps,
        }
    }
}

/// One scope's traffic over one finalized window — the unit of work the
/// detection engine consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionSnapshot {
    pub key: ScopeKey,
    /// Which rate window produced these figures.
    pub window: Duration,
    /// Monotonic time at which the window closed. Drives all duration
    /// comparisons and out-of-order rejection.
    pub observed_at: Instant,
    /// Wall time at which the window closed, for event correlation only.
    pub observed_wall: SystemTime,
    pub rates: MetricRates,
    pub completeness: DataCompleteness,
    pub sampling: SamplingStatus,
    /// How many flow records contributed. A window built from a single
    /// record is weak evidence however large its rate.
    pub flows_observed: u64,
    /// How many distinct exporters contributed. Bounded by construction —
    /// only the count is kept, never the addresses, so this can never
    /// grow without limit.
    pub exporters_observed: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn every_classifier_direction_maps_to_a_detector_direction() {
        assert_eq!(
            TrafficDirection::from(Direction::Incoming),
            TrafficDirection::Incoming
        );
        assert_eq!(
            TrafficDirection::from(Direction::Outgoing),
            TrafficDirection::Outgoing
        );
        assert_eq!(
            TrafficDirection::from(Direction::Internal),
            TrafficDirection::Internal
        );
        assert_eq!(
            TrafficDirection::from(Direction::Other),
            TrafficDirection::Other
        );
        assert_eq!(
            TrafficDirection::from(Direction::Unknown),
            TrafficDirection::Unknown
        );
    }

    #[test]
    fn address_family_follows_the_address() {
        assert_eq!(
            AddressFamily::of(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            AddressFamily::Ipv4
        );
        assert_eq!(
            AddressFamily::of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            AddressFamily::Ipv6
        );
    }

    #[test]
    fn scope_specificity_orders_host_above_prefix_above_slash24_above_hostgroup() {
        assert!(ScopeType::Host.specificity() > ScopeType::Prefix.specificity());
        assert!(ScopeType::Prefix.specificity() > ScopeType::Slash24.specificity());
        assert!(ScopeType::Slash24.specificity() > ScopeType::HostgroupTotal.specificity());
    }

    #[test]
    fn every_metric_kind_has_a_distinct_name() {
        let mut names: Vec<&str> = ALL_METRIC_KINDS.iter().map(|m| m.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "metric names must be unique");
    }

    #[test]
    fn metric_rates_get_covers_every_kind() {
        let rates = MetricRates {
            bps: 1,
            pps: 2,
            fps: 3,
            tcp_bps: 4,
            tcp_pps: 5,
            udp_bps: 6,
            udp_pps: 7,
            icmp_bps: 8,
            icmp_pps: 9,
            tcp_syn_bps: 10,
            tcp_syn_pps: 11,
            fragmented_bps: 12,
            fragmented_pps: 13,
            dropped_bps: 14,
            dropped_pps: 15,
        };
        let values: Vec<u64> = ALL_METRIC_KINDS.iter().map(|k| rates.get(*k)).collect();
        assert_eq!(values, (1..=15).collect::<Vec<u64>>());
    }

    #[test]
    fn protocol_derived_metrics_require_the_matching_completeness_flag() {
        assert_eq!(
            MetricKind::TcpSynPps.required_completeness(),
            Some(CompletenessFlag::TcpFlags)
        );
        assert_eq!(
            MetricKind::DroppedPps.required_completeness(),
            Some(CompletenessFlag::ForwardingStatus)
        );
        assert_eq!(MetricKind::Bps.required_completeness(), None);
    }

    #[test]
    fn completeness_merge_is_a_logical_or() {
        let mut a = DataCompleteness {
            protocol_seen: true,
            ..Default::default()
        };
        a.merge(DataCompleteness {
            tcp_flags_seen: true,
            ..Default::default()
        });
        assert!(a.protocol_seen && a.tcp_flags_seen);
        assert!(!a.fragmentation_seen);
    }

    #[test]
    fn sampling_status_merge_keeps_the_worst_case() {
        let mut a = SamplingStatus {
            corrected: true,
            used_global_default: false,
            max_rate: 100,
        };
        a.merge(SamplingStatus {
            corrected: false,
            used_global_default: true,
            max_rate: 10_000,
        });
        assert!(a.corrected);
        assert!(a.used_global_default);
        assert_eq!(a.max_rate, 10_000);
    }

    #[test]
    fn scope_id_displays_readably() {
        assert_eq!(
            ScopeId::Host {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))
            }
            .to_string(),
            "192.0.2.5"
        );
        assert_eq!(
            ScopeId::Network {
                addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix_len: 24
            }
            .to_string(),
            "198.51.100.0/24"
        );
        assert_eq!(
            ScopeId::Hostgroup {
                name: "customers".to_string()
            }
            .to_string(),
            "customers"
        );
    }

    #[test]
    fn scope_keys_order_deterministically() {
        let base = |t: ScopeType| ScopeKey {
            tenant: "t1".to_string(),
            scope_type: t,
            scope_id: ScopeId::Host {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            },
            direction: TrafficDirection::Incoming,
            address_family: AddressFamily::Ipv4,
        };
        let mut keys = [
            base(ScopeType::HostgroupTotal),
            base(ScopeType::Host),
            base(ScopeType::Slash24),
        ];
        keys.sort();
        let order: Vec<ScopeType> = keys.iter().map(|k| k.scope_type).collect();
        assert_eq!(
            order,
            vec![
                ScopeType::Host,
                ScopeType::Slash24,
                ScopeType::HostgroupTotal
            ]
        );
    }
}
