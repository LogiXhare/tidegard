//! An IP prefix in canonical form: no bit is set below its length.
//!
//! `192.0.2.1/24` is refused rather than quietly read as `192.0.2.0/24`.
//! A mitigation names exactly what it covers, and an operator who typed a
//! host address with a short length most likely meant something else.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    address: IpAddr,
    length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrefixError {
    #[error("a prefix is an address, a slash and a length, such as 192.0.2.1/32")]
    Form,
    #[error("the address is not an IPv4 or IPv6 address")]
    Address,
    #[error("the length is out of range for the address family")]
    Length,
    #[error("bits are set below the prefix length; the prefix is {0}")]
    HostBits(String),
}

impl Prefix {
    pub fn new(address: IpAddr, length: u8) -> Result<Self, PrefixError> {
        if length > max_length(address) {
            return Err(PrefixError::Length);
        }
        let masked = mask(address, length);
        if masked != address {
            return Err(PrefixError::HostBits(format!("{masked}/{length}")));
        }
        Ok(Prefix { address, length })
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn length(&self) -> u8 {
        self.length
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    /// 32 for IPv4, 128 for IPv6.
    pub fn max_length(&self) -> u8 {
        max_length(self.address)
    }

    /// A `/32` or a `/128`.
    pub fn is_host(&self) -> bool {
        self.length == self.max_length()
    }

    /// Whether `other` lies inside this prefix, or is it.
    pub fn contains(&self, other: &Prefix) -> bool {
        self.address.is_ipv4() == other.address.is_ipv4()
            && other.length >= self.length
            && mask(other.address, self.length) == self.address
    }
}

fn max_length(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn mask(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let kept = if length == 0 {
                0
            } else {
                bits & (u32::MAX << (32 - u32::from(length)))
            };
            IpAddr::V4(Ipv4Addr::from(kept))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let kept = if length == 0 {
                0
            } else {
                bits & (u128::MAX << (128 - u32::from(length)))
            };
            IpAddr::V6(Ipv6Addr::from(kept))
        }
    }
}

impl FromStr for Prefix {
    type Err = PrefixError;

    fn from_str(text: &str) -> Result<Self, PrefixError> {
        let (address, length) = text.split_once('/').ok_or(PrefixError::Form)?;
        // `u8::from_str` takes a leading `+`; a prefix length never has one.
        if length.is_empty() || length.len() > 3 || !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PrefixError::Form);
        }
        let address: IpAddr = address.parse().map_err(|_| PrefixError::Address)?;
        let length: u8 = length.parse().map_err(|_| PrefixError::Length)?;
        Prefix::new(address, length)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn p(text: &str) -> Prefix {
        text.parse().unwrap()
    }

    #[test]
    fn canonical_prefixes_parse_and_print_back() {
        for text in [
            "192.0.2.1/32",
            "198.51.100.0/24",
            "0.0.0.0/0",
            "2001:db8::1/128",
            "2001:db8::/32",
            "::/0",
        ] {
            assert_eq!(p(text).to_string(), text);
        }
        assert!(p("192.0.2.1/32").is_host());
        assert!(p("2001:db8::1/128").is_host());
        assert!(!p("198.51.100.0/24").is_host());
    }

    #[test]
    fn host_bits_lengths_and_forms_are_refused() {
        assert_eq!(
            "192.0.2.1/24".parse::<Prefix>(),
            Err(PrefixError::HostBits("192.0.2.0/24".into()))
        );
        assert_eq!(
            "2001:db8::1/64".parse::<Prefix>(),
            Err(PrefixError::HostBits("2001:db8::/64".into()))
        );
        for (text, error) in [
            ("192.0.2.1/33", PrefixError::Length),
            ("2001:db8::1/129", PrefixError::Length),
            ("192.0.2.1", PrefixError::Form),
            ("192.0.2.1/", PrefixError::Form),
            ("192.0.2.1/+32", PrefixError::Form),
            ("192.0.2.1/0032", PrefixError::Form),
            ("192.0.2.1/ 32", PrefixError::Form),
            ("example.net/32", PrefixError::Address),
            ("192.0.2.256/32", PrefixError::Address),
        ] {
            assert_eq!(text.parse::<Prefix>(), Err(error), "{text}");
        }
    }

    #[test]
    fn containment_respects_family_and_length() {
        let net = p("198.51.100.0/24");
        assert!(net.contains(&p("198.51.100.7/32")));
        assert!(net.contains(&net));
        assert!(!net.contains(&p("198.51.101.7/32")));
        assert!(!net.contains(&p("198.51.0.0/16")));
        assert!(!p("::/0").contains(&p("192.0.2.1/32")));
        assert!(p("0.0.0.0/0").contains(&p("192.0.2.1/32")));
        assert!(p("2001:db8::/32").contains(&p("2001:db8:ffff::1/128")));
    }

    proptest! {
        /// Masking any address to any length gives a prefix that parses
        /// back to itself and contains the original host.
        #[test]
        fn masked_addresses_round_trip(bits in any::<u32>(), length in 0u8..=32) {
            let host = Prefix::new(IpAddr::V4(Ipv4Addr::from(bits)), 32).unwrap();
            let net = Prefix::new(mask(host.address(), length), length).unwrap();
            prop_assert_eq!(net.to_string().parse::<Prefix>().unwrap(), net);
            prop_assert!(net.contains(&host));
        }

        #[test]
        fn masked_v6_addresses_round_trip(bits in any::<u128>(), length in 0u8..=128) {
            let host = Prefix::new(IpAddr::V6(Ipv6Addr::from(bits)), 128).unwrap();
            let net = Prefix::new(mask(host.address(), length), length).unwrap();
            prop_assert_eq!(net.to_string().parse::<Prefix>().unwrap(), net);
            prop_assert!(net.contains(&host));
        }
    }
}
