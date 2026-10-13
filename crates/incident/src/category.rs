//! Attack category, derived from the crossed metrics.
//!
//! Phase 4 has no category field. This is a pure, deterministic function
//! of the matched `MetricKind` set — evaluated in a fixed order, first
//! match wins, `multi_vector` checked first — recomputed on every linked
//! event rather than stored as a one-time decision.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tidegard_detector::MetricKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentCategory {
    TcpSynFlood,
    FragmentationFlood,
    IcmpFlood,
    UdpFlood,
    TcpFlood,
    PacketRate,
    Bandwidth,
    DropPressure,
    MultiVector,
    Unclassified,
}

impl IncidentCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentCategory::TcpSynFlood => "tcp_syn_flood",
            IncidentCategory::FragmentationFlood => "fragmentation_flood",
            IncidentCategory::IcmpFlood => "icmp_flood",
            IncidentCategory::UdpFlood => "udp_flood",
            IncidentCategory::TcpFlood => "tcp_flood",
            IncidentCategory::PacketRate => "packet_rate",
            IncidentCategory::Bandwidth => "bandwidth",
            IncidentCategory::DropPressure => "drop_pressure",
            IncidentCategory::MultiVector => "multi_vector",
            IncidentCategory::Unclassified => "unclassified",
        }
    }
}

/// Derives the category from the set of metrics matched so far across an
/// incident's linked evidence (not just the most recent event) — a
/// `udp_flood` that later crosses a TCP threshold too becomes
/// `multi_vector` because the *set* now spans two protocol families, not
/// because the newest event alone would classify that way.
pub fn derive_category(matched: &BTreeSet<MetricKind>) -> IncidentCategory {
    use MetricKind::*;

    let has_tcp_syn = matched.contains(&TcpSynBps) || matched.contains(&TcpSynPps);
    let has_fragmentation = matched.contains(&FragmentedBps) || matched.contains(&FragmentedPps);
    let has_icmp = matched.contains(&IcmpBps) || matched.contains(&IcmpPps);
    let has_udp = matched.contains(&UdpBps) || matched.contains(&UdpPps);
    let has_tcp = matched.contains(&TcpBps) || matched.contains(&TcpPps) || has_tcp_syn;
    let has_drop = matched.contains(&DroppedBps) || matched.contains(&DroppedPps);
    let has_generic_rate = matched.contains(&Pps) || matched.contains(&Fps);
    let has_bandwidth = matched.contains(&Bps);

    let families_crossed = [has_tcp, has_udp, has_icmp].iter().filter(|x| **x).count();
    if families_crossed >= 2 {
        return IncidentCategory::MultiVector;
    }

    if has_tcp_syn {
        return IncidentCategory::TcpSynFlood;
    }
    if has_fragmentation {
        return IncidentCategory::FragmentationFlood;
    }
    if has_icmp {
        return IncidentCategory::IcmpFlood;
    }
    if has_udp {
        return IncidentCategory::UdpFlood;
    }
    if has_tcp {
        return IncidentCategory::TcpFlood;
    }
    if has_generic_rate {
        return IncidentCategory::PacketRate;
    }
    if has_bandwidth {
        return IncidentCategory::Bandwidth;
    }
    if has_drop {
        return IncidentCategory::DropPressure;
    }
    IncidentCategory::Unclassified
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(kinds: &[MetricKind]) -> BTreeSet<MetricKind> {
        kinds.iter().copied().collect()
    }

    #[test]
    fn tcp_syn_wins_over_generic_packet_rate() {
        let matched = set(&[MetricKind::TcpSynPps, MetricKind::Pps]);
        assert_eq!(derive_category(&matched), IncidentCategory::TcpSynFlood);
    }

    #[test]
    fn multi_vector_checked_before_single_protocol_categories() {
        let matched = set(&[MetricKind::UdpBps, MetricKind::TcpBps]);
        assert_eq!(derive_category(&matched), IncidentCategory::MultiVector);
    }

    #[test]
    fn udp_alone_is_udp_flood() {
        let matched = set(&[MetricKind::UdpPps]);
        assert_eq!(derive_category(&matched), IncidentCategory::UdpFlood);
    }

    #[test]
    fn icmp_alone_is_icmp_flood() {
        let matched = set(&[MetricKind::IcmpBps]);
        assert_eq!(derive_category(&matched), IncidentCategory::IcmpFlood);
    }

    #[test]
    fn bandwidth_only_when_nothing_more_specific_matched() {
        let matched = set(&[MetricKind::Bps]);
        assert_eq!(derive_category(&matched), IncidentCategory::Bandwidth);
    }

    #[test]
    fn drop_pressure_is_the_last_specific_category() {
        let matched = set(&[MetricKind::DroppedBps]);
        assert_eq!(derive_category(&matched), IncidentCategory::DropPressure);
    }

    #[test]
    fn empty_set_is_unclassified() {
        assert_eq!(
            derive_category(&BTreeSet::new()),
            IncidentCategory::Unclassified
        );
    }

    #[test]
    fn a_growing_set_can_upgrade_udp_to_multi_vector() {
        let mut matched = set(&[MetricKind::UdpBps]);
        assert_eq!(derive_category(&matched), IncidentCategory::UdpFlood);
        matched.insert(MetricKind::TcpSynPps);
        assert_eq!(derive_category(&matched), IncidentCategory::MultiVector);
    }

    #[test]
    fn fragmentation_beats_generic_rate() {
        let matched = set(&[MetricKind::FragmentedPps]);
        assert_eq!(
            derive_category(&matched),
            IncidentCategory::FragmentationFlood
        );
    }
}
