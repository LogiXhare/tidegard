//! The unauthorized-prefix suite (Phase 7 acceptance criteria, R25).
//!
//! The guard must refuse every prefix outside the allowlist, every prefix
//! another tenant owns, and every prefix wider than its bounds, for every
//! action. Fixed hostile cases first, then properties over generated
//! prefixes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use proptest::prelude::*;
use tidegard_incident::correlation::TenantId;
use tidegard_mitigation::guard::{AllowlistEntry, Guard, GuardConfig, GuardRefusal, MinLength};
use tidegard_mitigation::{Action, ActionKind, FlowMatch, Prefix};

const ALL: [ActionKind; 4] = [
    ActionKind::Rtbh,
    ActionKind::ParentPrefix,
    ActionKind::FlowspecDiscard,
    ActionKind::FlowspecRateLimit,
];

const HOUR: Duration = Duration::from_secs(3600);

fn p(text: &str) -> Prefix {
    text.parse().unwrap()
}

/// acme owns 192.0.2.0/24 and 2001:db8:a::/48, and 172.16.0.0/16 with
/// every action; globex owns 203.0.113.0/24.
fn guard() -> Guard {
    let entry = |prefix: &str, tenant: &str| AllowlistEntry {
        prefix: p(prefix),
        tenant: tenant.into(),
        actions: ALL.to_vec(),
    };
    Guard::new(GuardConfig {
        min_length: MinLength { ipv4: 24, ipv6: 56 },
        allowlist: vec![
            entry("192.0.2.0/24", "acme"),
            entry("2001:db8:a::/48", "acme"),
            entry("172.16.0.0/16", "acme"),
            entry("203.0.113.0/24", "globex"),
        ],
        ..GuardConfig::default()
    })
    .unwrap()
}

/// Every action that is structurally valid for `prefix`.
fn actions_for(prefix: &Prefix) -> Vec<Action> {
    let flow = FlowMatch::default();
    let mut actions = vec![
        Action::FlowspecDiscard(flow.clone()),
        Action::FlowspecRateLimit {
            flow,
            bytes_per_second: 1_000_000,
        },
    ];
    actions.push(if prefix.is_host() {
        Action::Rtbh
    } else {
        Action::ParentPrefix
    });
    actions
}

fn refused_for_everyone(guard: &Guard, prefix: &Prefix) {
    for tenant in ["acme", "globex", "nobody"] {
        for action in actions_for(prefix) {
            assert!(
                guard
                    .check(&TenantId::new(tenant), prefix, &action, HOUR, false)
                    .is_err(),
                "{tenant} may not have {action:?} on {prefix}"
            );
        }
    }
}

#[test]
fn hostile_prefixes_are_refused_for_every_tenant_and_action() {
    let g = guard();
    for text in [
        "0.0.0.0/0",
        "0.0.0.0/1",
        "128.0.0.0/1",
        "192.0.0.0/8",
        // Wider than an allowlisted /24, though it covers it.
        "192.0.2.0/23",
        "::/0",
        "2000::/3",
        "2001:db8::/32",
        // An IPv4 host written as IPv6 is a different family: not covered.
        "::ffff:192.0.2.1/128",
        // Neighbours.
        "192.0.1.255/32",
        "192.0.3.0/32",
        "203.0.112.255/32",
    ] {
        refused_for_everyone(&g, &p(text));
    }
}

#[test]
fn another_tenants_space_is_refused_with_the_same_answer_as_nobodys() {
    let g = guard();
    let theirs = p("203.0.113.7/32");
    let nobodys = p("198.18.0.7/32");
    let acme = TenantId::new("acme");
    let a = g
        .check(&acme, &theirs, &Action::Rtbh, HOUR, false)
        .unwrap_err();
    let b = g
        .check(&acme, &nobodys, &Action::Rtbh, HOUR, false)
        .unwrap_err();
    assert_eq!(a.code(), b.code());
    assert!(matches!(a, GuardRefusal::NotAllowlisted(_)));
    assert!(!a.to_string().contains("globex"));
}

fn v4(bits: u32, length: u8) -> Prefix {
    let mask = if length == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(length))
    };
    Prefix::new(IpAddr::V4(Ipv4Addr::from(bits & mask)), length).unwrap()
}

fn v6(bits: u128, length: u8) -> Prefix {
    let mask = if length == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(length))
    };
    Prefix::new(IpAddr::V6(Ipv6Addr::from(bits & mask)), length).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Outside every allowlist entry, nothing is ever accepted.
    #[test]
    fn nothing_outside_the_allowlist_is_accepted(bits in any::<u32>(), length in 0u8..=32) {
        let g = guard();
        let prefix = v4(bits, length);
        let covered = g.config().allowlist.iter().any(|entry| entry.prefix.contains(&prefix));
        prop_assume!(!covered);
        refused_for_everyone(&g, &prefix);
    }

    #[test]
    fn nothing_outside_the_v6_allowlist_is_accepted(bits in any::<u128>(), length in 0u8..=128) {
        let g = guard();
        let prefix = v6(bits, length);
        let covered = g.config().allowlist.iter().any(|entry| entry.prefix.contains(&prefix));
        prop_assume!(!covered);
        refused_for_everyone(&g, &prefix);
    }

    /// Inside globex's entry, acme gets nothing, whatever the length.
    #[test]
    fn another_tenants_prefixes_are_never_accepted(host in any::<u8>(), length in 24u8..=32) {
        let g = guard();
        let prefix = v4(u32::from(Ipv4Addr::new(203, 0, 113, host)), length);
        for action in actions_for(&prefix) {
            prop_assert!(g.check(&TenantId::new("acme"), &prefix, &action, HOUR, false).is_err());
        }
    }

    /// Inside acme's /16, a non-host prefix is accepted exactly when it is
    /// at least the minimum length.
    #[test]
    fn width_is_bounded_inside_the_tenants_own_space(bits in any::<u16>(), length in 16u8..=31) {
        let g = guard();
        let prefix = v4(u32::from(Ipv4Addr::new(172, 16, 0, 0)) | u32::from(bits), length);
        for action in actions_for(&prefix) {
            let verdict = g.check(&TenantId::new("acme"), &prefix, &action, HOUR, false);
            if length >= 24 {
                prop_assert_eq!(verdict, Ok(()));
            } else {
                prop_assert_eq!(verdict, Err(GuardRefusal::TooWide(prefix, 24)));
            }
        }
    }

    /// The kill switch refuses even what is otherwise allowed.
    #[test]
    fn the_kill_switch_refuses_everything(host in any::<u8>()) {
        let g = guard();
        let prefix = v4(u32::from(Ipv4Addr::new(192, 0, 2, host)), 32);
        for action in actions_for(&prefix) {
            prop_assert_eq!(
                g.check(&TenantId::new("acme"), &prefix, &action, HOUR, true),
                Err(GuardRefusal::KillSwitch)
            );
        }
    }
}
