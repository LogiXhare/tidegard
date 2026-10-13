//! Per-exporter state: template cache, sequence-number tracking, and
//! restart detection.
//!
//! Per RFC 7011 §8.1, template IDs are only meaningful within one
//! exporter's observation domain, and an exporter that restarts may
//! reuse template IDs to mean something different than before. This
//! module is what lets `tidegard-collector` keep one
//! `TemplateCache` per exporter and clear it when a restart is detected,
//! per docs/functional-requirements.md FR-1.4 ("handle exporter
//! restarts") and FR-1.5.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tidegard_protocol_ipfix::TemplateCache;

/// State tracked for one exporter, keyed by [`ExporterKey`] in
/// [`ExporterRegistry`].
pub struct ExporterState {
    pub template_cache: TemplateCache,
    pub last_sequence_number: Option<u32>,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub packets_received: u64,
}

impl ExporterState {
    fn new() -> Self {
        let now = Instant::now();
        ExporterState {
            template_cache: TemplateCache::new(),
            last_sequence_number: None,
            first_seen: now,
            last_seen: now,
            packets_received: 0,
        }
    }

    /// Records a newly received message's sequence number for this
    /// exporter, returning `true` if this looks like an exporter restart
    /// (the sequence number regressed), in which case the caller should
    /// treat any templates cached before this call as stale.
    ///
    /// **Known limitation:** this uses a plain regression check
    /// (`new < last`), not RFC 7011's full 32-bit-wraparound-aware
    /// comparison. A real wraparound (the exporter has sent 2^32 records
    /// since it started) will be misreported as a restart. Given typical
    /// export rates this takes a very long time to occur and the
    /// consequence — an unnecessary template-cache clear, causing a few
    /// seconds of "unknown template" until the exporter's next periodic
    /// template refresh — is safe, not silent data corruption. Tracked as
    /// a follow-up rather than adding wraparound-aware comparison logic
    /// this phase doesn't yet have a test fixture to validate against.
    pub fn observe_sequence(&mut self, sequence_number: u32) -> bool {
        self.last_seen = Instant::now();
        self.packets_received += 1;

        let is_restart = match self.last_sequence_number {
            Some(last) => sequence_number < last,
            None => false,
        };

        if is_restart {
            self.template_cache.clear();
        }

        self.last_sequence_number = Some(sequence_number);
        is_restart
    }
}

/// An exporter as RFC 7011 scopes templates and sequence numbers: its
/// source address and its observation domain. A router that exports
/// several domains from one socket gets one state for each.
pub type ExporterKey = (SocketAddr, u32);

/// The bounds on what senders can make the collector remember (Phase 9D,
/// ADR 0056). UDP carries no authentication, so without them anyone who
/// reaches the port could create exporters, each with a template cache,
/// until memory ran out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExporterLimits {
    /// Source networks the collector accepts datagrams from. Empty means
    /// any source, for a port only the routers can reach.
    pub allowed: Vec<AllowedNetwork>,
    /// The most exporters tracked at once. A new one past it is refused
    /// until an idle one is forgotten.
    pub max_exporters: usize,
    /// How long an exporter may stay silent before its state, templates
    /// included, is forgotten.
    pub idle_timeout: Duration,
}

pub const DEFAULT_MAX_EXPORTERS: usize = 1_000;
pub const DEFAULT_EXPORTER_IDLE_SECS: u64 = 3_600;

impl Default for ExporterLimits {
    fn default() -> Self {
        ExporterLimits {
            allowed: Vec::new(),
            max_exporters: DEFAULT_MAX_EXPORTERS,
            idle_timeout: Duration::from_secs(DEFAULT_EXPORTER_IDLE_SECS),
        }
    }
}

/// A network in `TIDEGARD_COLLECTOR_ALLOWED_EXPORTERS`, in canonical
/// form: no bit set below its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedNetwork {
    network: IpAddr,
    length: u8,
}

impl AllowedNetwork {
    /// `None` for a length past the address family's, or for an address
    /// with bits set below the length (`192.0.2.1/24` was most likely a
    /// typo, and it is refused rather than read as `192.0.2.0/24`).
    pub fn new(network: IpAddr, length: u8) -> Option<Self> {
        let network = network.to_canonical();
        let max = if network.is_ipv4() { 32 } else { 128 };
        if length > max || mask(network, length) != network {
            return None;
        }
        Some(AllowedNetwork { network, length })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        let addr = addr.to_canonical();
        addr.is_ipv4() == self.network.is_ipv4() && mask(addr, self.length) == self.network
    }
}

/// `addr` with every bit below `length` cleared. `length` is at most the
/// family's width; callers check.
fn mask(addr: IpAddr, length: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
            IpAddr::V4((u32::from(v4) & bits).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
            IpAddr::V6((u128::from(v6) & bits).into())
        }
    }
}

/// Tracks one [`ExporterState`] per [`ExporterKey`] that has sent this
/// collector a datagram, within [`ExporterLimits`].
pub struct ExporterRegistry {
    exporters: HashMap<ExporterKey, ExporterState>,
    limits: ExporterLimits,
}

impl Default for ExporterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ExporterRegistry {
    /// A registry with the default limits: any source, 1,000 exporters,
    /// an hour's silence.
    pub fn new() -> Self {
        Self::with_limits(ExporterLimits::default())
    }

    pub fn with_limits(limits: ExporterLimits) -> Self {
        ExporterRegistry {
            exporters: HashMap::new(),
            limits,
        }
    }

    /// Whether datagrams from `addr` are accepted at all.
    pub fn permits(&self, addr: IpAddr) -> bool {
        self.limits.allowed.is_empty() || self.limits.allowed.iter().any(|n| n.contains(addr))
    }

    /// Returns the state for `key`, creating it if this is the first
    /// datagram from it, or `None` when `max_exporters` are already
    /// tracked and `key` is not one of them.
    pub fn get_or_create(&mut self, key: ExporterKey) -> Option<&mut ExporterState> {
        let full = self.exporters.len() >= self.limits.max_exporters;
        match self.exporters.entry(key) {
            Entry::Occupied(entry) => Some(entry.into_mut()),
            Entry::Vacant(_) if full => None,
            Entry::Vacant(entry) => Some(entry.insert(ExporterState::new())),
        }
    }

    /// Forgets every exporter silent for longer than the idle timeout,
    /// and returns how many.
    pub fn evict_idle(&mut self, now: Instant) -> usize {
        let before = self.exporters.len();
        let timeout = self.limits.idle_timeout;
        self.exporters
            .retain(|_, state| now.saturating_duration_since(state.last_seen) <= timeout);
        before - self.exporters.len()
    }

    pub fn exporter_count(&self) -> usize {
        self.exporters.len()
    }

    pub fn total_template_count(&self) -> usize {
        self.exporters
            .values()
            .map(|e| e.template_cache.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn first_sequence_number_is_never_a_restart() {
        let mut state = ExporterState::new();
        assert!(!state.observe_sequence(0));
        assert_eq!(state.packets_received, 1);
    }

    #[test]
    fn increasing_sequence_numbers_are_not_a_restart() {
        let mut state = ExporterState::new();
        state.observe_sequence(10);
        assert!(!state.observe_sequence(20));
        assert!(!state.observe_sequence(21));
    }

    #[test]
    fn a_regression_is_detected_as_a_restart_and_clears_templates() {
        let mut state = ExporterState::new();
        state.observe_sequence(1000);
        state
            .template_cache
            .insert(tidegard_protocol_ipfix::Template {
                template_id: 256,
                scope_field_count: 0,
                fields: vec![],
            })
            .unwrap();
        assert_eq!(state.template_cache.len(), 1);

        let restarted = state.observe_sequence(5);
        assert!(restarted);
        assert_eq!(state.template_cache.len(), 0);
    }

    #[test]
    fn registry_creates_state_lazily_per_address() {
        let mut registry = ExporterRegistry::new();
        assert_eq!(registry.exporter_count(), 0);

        registry
            .get_or_create((addr(1), 0))
            .unwrap()
            .observe_sequence(1);
        registry
            .get_or_create((addr(2), 0))
            .unwrap()
            .observe_sequence(1);
        registry
            .get_or_create((addr(1), 0))
            .unwrap()
            .observe_sequence(2);

        assert_eq!(registry.exporter_count(), 2);
    }

    #[test]
    fn each_observation_domain_is_its_own_exporter() {
        let mut registry = ExporterRegistry::new();
        registry
            .get_or_create((addr(1), 1))
            .unwrap()
            .observe_sequence(100);
        // Domain 2's lower sequence number is its own, not a restart of 1.
        assert!(!registry
            .get_or_create((addr(1), 2))
            .unwrap()
            .observe_sequence(5));
        assert_eq!(registry.exporter_count(), 2);
    }

    #[test]
    fn a_new_exporter_past_the_limit_is_refused_until_one_goes_idle() {
        let mut registry = ExporterRegistry::with_limits(ExporterLimits {
            max_exporters: 2,
            idle_timeout: Duration::from_secs(60),
            ..ExporterLimits::default()
        });
        registry.get_or_create((addr(1), 0)).unwrap();
        registry.get_or_create((addr(2), 0)).unwrap();
        assert!(registry.get_or_create((addr(3), 0)).is_none());
        assert!(registry.get_or_create((addr(1), 7)).is_none());
        // Those already tracked carry on.
        assert!(registry.get_or_create((addr(1), 0)).is_some());

        let later = Instant::now() + Duration::from_secs(61);
        assert_eq!(registry.evict_idle(Instant::now()), 0);
        assert_eq!(registry.evict_idle(later), 2);
        assert!(registry.get_or_create((addr(3), 0)).is_some());
    }

    fn network(text: &str) -> Option<AllowedNetwork> {
        let (address, length) = text.split_once('/').unwrap();
        AllowedNetwork::new(address.parse().unwrap(), length.parse().unwrap())
    }

    #[test]
    fn the_allowlist_admits_its_networks_only() {
        let registry = ExporterRegistry::with_limits(ExporterLimits {
            allowed: vec![
                network("192.0.2.0/24").unwrap(),
                network("2001:db8::/32").unwrap(),
                network("198.51.100.7/32").unwrap(),
            ],
            ..ExporterLimits::default()
        });
        for allowed in [
            "192.0.2.1",
            "192.0.2.255",
            "198.51.100.7",
            "2001:db8::1",
            "::ffff:192.0.2.9",
        ] {
            assert!(registry.permits(allowed.parse().unwrap()), "{allowed}");
        }
        for refused in ["192.0.3.1", "198.51.100.8", "2001:db9::1", "10.0.0.1", "::"] {
            assert!(!registry.permits(refused.parse().unwrap()), "{refused}");
        }
        assert!(ExporterRegistry::new().permits("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn an_allowed_network_is_canonical() {
        assert!(network("192.0.2.1/24").is_none());
        assert!(network("192.0.2.0/33").is_none());
        assert!(network("2001:db8::1/32").is_none());
        assert!(network("0.0.0.0/0")
            .unwrap()
            .contains("203.0.113.1".parse().unwrap()));
        assert!(!network("0.0.0.0/0")
            .unwrap()
            .contains("2001:db8::1".parse().unwrap()));
        assert!(network("::/0")
            .unwrap()
            .contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn total_template_count_sums_across_exporters() {
        let mut registry = ExporterRegistry::new();
        registry
            .get_or_create((addr(1), 0))
            .unwrap()
            .template_cache
            .insert(tidegard_protocol_ipfix::Template {
                template_id: 1,
                scope_field_count: 0,
                fields: vec![],
            })
            .unwrap();
        registry
            .get_or_create((addr(2), 0))
            .unwrap()
            .template_cache
            .insert(tidegard_protocol_ipfix::Template {
                template_id: 2,
                scope_field_count: 0,
                fields: vec![],
            })
            .unwrap();
        assert_eq!(registry.total_template_count(), 2);
    }
}
