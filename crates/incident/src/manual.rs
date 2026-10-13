//! An incident opened by an operator, for something the detector cannot
//! see (ADR 0039).
//!
//! A manual incident names the same five-dimension target a detection
//! would, so it takes the same correlation key: while it is active, a
//! detection for that target **attaches to it** instead of opening a
//! second incident, and an operator cannot open one where an active
//! incident already exists (`incident.duplicate_active`). It is not the
//! ingestion path: detection events still arrive through the inbox, never
//! over HTTP.

use serde::Serialize;
use tidegard_detector::{AddressFamily, ScopeId, ScopeType, Severity, TrafficDirection};

use crate::correlation::{CorrelationKey, TenantId};
use crate::error::IncidentError;
use crate::limits::{DESCRIPTION_MAX_LEN, TITLE_MAX_LEN};
use crate::severity::Priority;

/// What an operator supplies to open an incident. `Serialize` only, for
/// the idempotency fingerprint, like [`crate::command::Command`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ManualIncident {
    pub title: String,
    pub description: Option<String>,
    pub severity: Severity,
    /// `None` takes the default for the severity.
    pub priority: Option<Priority>,
    pub target_type: ScopeType,
    pub target_identity: ScopeId,
    pub direction: TrafficDirection,
    pub address_family: AddressFamily,
}

impl ManualIncident {
    /// Refuses a request no detection could have produced: a blank or
    /// over-long title, an over-long description, or a target whose parts
    /// disagree with each other.
    pub fn validate(&self) -> Result<(), IncidentError> {
        let invalid = |detail: &str| Err(IncidentError::ValidationError(detail.to_string()));
        if self.title.trim().is_empty() {
            return invalid("the title is required");
        }
        if self.title.chars().count() > TITLE_MAX_LEN {
            return invalid("the title is longer than 200 characters");
        }
        if self
            .description
            .as_ref()
            .is_some_and(|d| d.chars().count() > DESCRIPTION_MAX_LEN)
        {
            return invalid("the description is longer than 8000 characters");
        }
        if matches!(
            self.direction,
            TrafficDirection::Other | TrafficDirection::Unknown
        ) {
            return invalid("the direction must be incoming, outgoing or internal");
        }
        let family_of = |addr: &std::net::IpAddr| AddressFamily::of(*addr);
        match (&self.target_type, &self.target_identity) {
            (ScopeType::Host, ScopeId::Host { addr }) if family_of(addr) == self.address_family => {
                Ok(())
            }
            (ScopeType::Prefix, ScopeId::Network { addr, prefix_len })
                if family_of(addr) == self.address_family
                    && *prefix_len <= max_prefix(self.address_family) =>
            {
                Ok(())
            }
            (
                ScopeType::Slash24,
                ScopeId::Network {
                    addr,
                    prefix_len: 24,
                },
            ) if addr.is_ipv4()
                && self.address_family == AddressFamily::Ipv4
                && is_network_address(addr, 24) =>
            {
                Ok(())
            }
            (ScopeType::HostgroupTotal, ScopeId::Hostgroup { name })
                if !name.trim().is_empty() && name.chars().count() <= 128 =>
            {
                Ok(())
            }
            _ => invalid("the target type, target and address family do not agree"),
        }
    }

    /// The key a detection for the same target would take.
    pub fn correlation_key(&self, tenant: &TenantId) -> CorrelationKey {
        CorrelationKey::new(
            tenant.clone(),
            self.target_type,
            self.target_identity.clone(),
            self.direction,
            self.address_family,
        )
    }
}

fn max_prefix(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4 => 32,
        AddressFamily::Ipv6 => 128,
    }
}

/// Whether `addr` has no host bits set below `prefix_len`. Only a /24 is
/// held to this: the detector computes it, so it is always canonical. A
/// configured prefix is matched as the policy spells it, host bits and
/// all, so a manual incident must spell it the same way to correlate.
fn is_network_address(addr: &std::net::IpAddr, prefix_len: u8) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let bits = u32::from(*v4);
            prefix_len >= 32 || bits & (u32::MAX >> prefix_len) == 0
        }
        std::net::IpAddr::V6(v6) => {
            let bits = u128::from(*v6);
            prefix_len >= 128 || bits & (u128::MAX >> prefix_len) == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(addr: &str) -> ManualIncident {
        ManualIncident {
            title: "Upstream reports spoofed sources".into(),
            description: None,
            severity: Severity::Major,
            priority: None,
            target_type: ScopeType::Host,
            target_identity: ScopeId::Host {
                addr: addr.parse().unwrap(),
            },
            direction: TrafficDirection::Incoming,
            address_family: AddressFamily::Ipv4,
        }
    }

    #[test]
    fn a_consistent_host_is_accepted() {
        assert!(host("203.0.113.5").validate().is_ok());
    }

    #[test]
    fn titles_are_required_and_bounded() {
        let mut blank = host("203.0.113.5");
        blank.title = "   ".into();
        assert!(blank.validate().is_err());
        let mut long = host("203.0.113.5");
        long.title = "x".repeat(TITLE_MAX_LEN + 1);
        assert!(long.validate().is_err());
    }

    #[test]
    fn target_parts_must_agree() {
        // An IPv6 address declared as IPv4.
        assert!(host("2001:db8::1").validate().is_err());
        // A host scope with a network identity.
        let mut mixed = host("203.0.113.5");
        mixed.target_identity = ScopeId::Network {
            addr: "203.0.113.0".parse().unwrap(),
            prefix_len: 24,
        };
        assert!(mixed.validate().is_err());
        // A configured prefix is taken as the policy spells it, host bits
        // and all, so it matches the detector's key.
        let mut prefix = host("203.0.113.5");
        prefix.target_type = ScopeType::Prefix;
        prefix.target_identity = ScopeId::Network {
            addr: "203.0.113.5".parse().unwrap(),
            prefix_len: 24,
        };
        assert!(prefix.validate().is_ok());
        prefix.target_identity = ScopeId::Network {
            addr: "203.0.113.0".parse().unwrap(),
            prefix_len: 24,
        };
        assert!(prefix.validate().is_ok());
        // slash24 is a canonical IPv4 /24 only.
        prefix.target_type = ScopeType::Slash24;
        prefix.target_identity = ScopeId::Network {
            addr: "203.0.113.5".parse().unwrap(),
            prefix_len: 24,
        };
        assert!(prefix.validate().is_err(), "host bits in a /24");
        prefix.target_identity = ScopeId::Network {
            addr: "203.0.113.0".parse().unwrap(),
            prefix_len: 24,
        };
        assert!(prefix.validate().is_ok());
        prefix.target_identity = ScopeId::Network {
            addr: "203.0.112.0".parse().unwrap(),
            prefix_len: 23,
        };
        assert!(prefix.validate().is_err());
    }

    #[test]
    fn only_a_real_direction_is_accepted() {
        let mut unknown = host("203.0.113.5");
        unknown.direction = TrafficDirection::Unknown;
        assert!(unknown.validate().is_err());
    }
}
