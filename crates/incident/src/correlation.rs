//! Deterministic correlation.
//!
//! The correlation key is built from **typed** target identity — the
//! detector's own [`ScopeId`] enum, whose address fields are
//! [`std::net::IpAddr`] — rather than from `EventTarget::display`, which
//! is only a human-readable rendering of the same value. This is not
//! merely a style preference: `IpAddr`'s `Eq`/`Hash`/`Ord` already
//! normalise on the parsed address bits, so `2001:DB8::1` and
//! `2001:db8:0:0:0:0:0:1` are the same key without any string
//! canonicalisation step, and there is no separate "canonical form" for a
//! bug to diverge from the "display form" of.
//!
//! Deliberately excluded from the key, per
//! [the correlation design](../../../docs/architecture/incident-correlation.md):
//! policy id, severity, and category. All three can change over an
//! incident's life without splitting it.

use serde::{Deserialize, Serialize};
use tidegard_detector::{AddressFamily, ScopeId, ScopeType, TrafficDirection};

use crate::id::IncidentId;

/// A tenant identifier. Wrapped rather than a bare `String` so a
/// tenant-context argument cannot be confused with any other string
/// parameter at a call site — the same reasoning that makes the
/// authorization seam take an [`crate::authorization::AuthorizationContext`]
/// instead of a loose `&str`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(value: impl Into<String>) -> Self {
        TenantId(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The five-dimension deterministic key.
///
/// `target_identity` is the detector's typed [`ScopeId`] — `Host{addr}`,
/// `Network{addr, prefix_len}`, or `Hostgroup{name}` — carried unchanged
/// rather than flattened to a string, so a `/32` and its parent `/24`
/// are unequal at the type level (different `ScopeId` variant *and*
/// value) with no risk of two different scopes ever rendering to the
/// same display string and colliding.
///
/// This type is `Deserialize`, unlike [`crate::incident::Incident`],
/// and the difference is not an inconsistency. ADR 0030 rejects a bare
/// `Deserialize` on the aggregate because the aggregate has guards to
/// bypass — combinations of field values its mutation methods refuse to
/// produce. A correlation key has none: five independent typed
/// components, all public, with an all-arguments public constructor that
/// checks nothing because there is nothing to check. Deriving here
/// grants a caller no power it does not already have through
/// [`CorrelationKey::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationKey {
    pub tenant: TenantId,
    pub target_type: ScopeType,
    pub target_identity: ScopeId,
    pub direction: TrafficDirection,
    pub address_family: AddressFamily,
}

impl CorrelationKey {
    pub fn new(
        tenant: TenantId,
        target_type: ScopeType,
        target_identity: ScopeId,
        direction: TrafficDirection,
        address_family: AddressFamily,
    ) -> Self {
        CorrelationKey {
            tenant,
            target_type,
            target_identity,
            direction,
            address_family,
        }
    }
}

/// What correlation decided for one arriving event, before the state
/// machine gets involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationOutcome {
    /// No open or reopenable incident exists; open a new one.
    Create,
    /// An open incident exists for this key; the event updates it.
    Update { incident_id: IncidentId },
    /// The most recent incident for this key closed within the reopen
    /// window; reopen it instead of creating a new one.
    Reopen { incident_id: IncidentId },
    /// An open incident exists but this event cannot change its state
    /// (it is late, or the state machine has nothing to do with it).
    LinkOnly { incident_id: IncidentId },
    /// This event's `dedup_key` has already been ingested.
    Duplicate,
    /// The event is malformed or its schema version is unsupported.
    Quarantine,
}

/// A bounded, structured conflict — never an unbounded retry loop.
///
/// Returned when the correlation decision cannot be applied as computed,
/// because the incident store changed between the decision and the
/// attempted write (in 5A's single-threaded in-memory model this can
/// only happen if a caller deliberately re-enters, but the type exists
/// so 5C's real concurrent correlator has a contract to retry against,
/// bounded by its own caller — never by a loop inside this crate).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CorrelationConflict {
    #[error("an open incident already exists for this correlation key: {0:?}")]
    OpenIncidentAlreadyExists(IncidentId),
    #[error("the incident to reopen no longer matches the expected key")]
    ReopenTargetChanged,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn ipv6_addresses_are_equal_regardless_of_written_form() {
        let expanded: IpAddr = "2001:db8:0:0:0:0:0:1".parse().unwrap();
        let compressed: IpAddr = "2001:DB8::1".parse().unwrap();
        let key_a = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Host,
            ScopeId::Host { addr: expanded },
            TrafficDirection::Incoming,
            AddressFamily::Ipv6,
        );
        let key_b = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Host,
            ScopeId::Host { addr: compressed },
            TrafficDirection::Incoming,
            AddressFamily::Ipv6,
        );
        assert_eq!(
            key_a, key_b,
            "expanded and compressed IPv6 forms must be one key"
        );
        assert_eq!(
            compressed,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn host_and_parent_prefix_are_different_keys() {
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        let host_key = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Host,
            ScopeId::Host { addr },
            TrafficDirection::Incoming,
            AddressFamily::Ipv4,
        );
        let prefix_key = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Slash24,
            ScopeId::Network {
                addr,
                prefix_len: 24,
            },
            TrafficDirection::Incoming,
            AddressFamily::Ipv4,
        );
        assert_ne!(host_key, prefix_key);
    }

    #[test]
    fn direction_is_part_of_the_key() {
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        let incoming = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Host,
            ScopeId::Host { addr },
            TrafficDirection::Incoming,
            AddressFamily::Ipv4,
        );
        let outgoing = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Host,
            ScopeId::Host { addr },
            TrafficDirection::Outgoing,
            AddressFamily::Ipv4,
        );
        assert_ne!(incoming, outgoing);
    }

    #[test]
    fn different_tenants_never_share_a_key() {
        let addr: IpAddr = "203.0.113.7".parse().unwrap();
        let a = CorrelationKey::new(
            TenantId::new("acme"),
            ScopeType::Host,
            ScopeId::Host { addr },
            TrafficDirection::Incoming,
            AddressFamily::Ipv4,
        );
        let b = CorrelationKey::new(
            TenantId::new("globex"),
            ScopeType::Host,
            ScopeId::Host { addr },
            TrafficDirection::Incoming,
            AddressFamily::Ipv4,
        );
        assert_ne!(a, b);
    }
}
