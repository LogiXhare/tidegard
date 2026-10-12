//! Phase 7C (ADR 0048): every action is announced to a real `gobgpd`,
//! read back with its attributes, and withdrawn. A route without the
//! ownership community is never listed as WetechiNetMon's.
//!
//! Needs `WETECHINETMON_GOBGP_TEST_ENDPOINT`, a throwaway `gobgpd` on
//! loopback (`http://127.0.0.1:50051`) that this test fills and empties.
//! Without it the test says why and passes; CI starts one and fails on the
//! skip message. Only documentation prefixes and private ASNs are used.

use wetechinetmon_mitigation::{Action, FlowMatch, Prefix};
use wetechinetmon_mitigator::api;
use wetechinetmon_mitigator::api::attribute::Attr;
use wetechinetmon_mitigator::api::extended_community::Extcom;
use wetechinetmon_mitigator::gobgp::{GoBgp, GoBgpEndpoint};
use wetechinetmon_mitigator::route::{announcement, withdrawal, RouteConfig, BLACKHOLE, NO_EXPORT};

const ENDPOINT_VAR: &str = "WETECHINETMON_GOBGP_TEST_ENDPOINT";

fn p(text: &str) -> Prefix {
    text.parse().unwrap()
}

fn config() -> RouteConfig {
    serde_json::from_str(
        r#"{"local_asn": 65001, "rtbh_next_hop_ipv4": "192.0.2.254",
            "rtbh_next_hop_ipv6": "2001:db8::254",
            "communities": ["65535:666", "65001:777"]}"#,
    )
    .unwrap()
}

fn communities(path: &api::Path) -> Vec<u32> {
    path.pattrs
        .iter()
        .find_map(|a| match &a.attr {
            Some(Attr::Communities(c)) => Some(c.communities.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn next_hop(path: &api::Path) -> Option<String> {
    path.pattrs.iter().find_map(|a| match &a.attr {
        Some(Attr::NextHop(n)) => Some(n.next_hop.clone()),
        Some(Attr::MpReach(m)) => m.next_hops.first().cloned(),
        _ => None,
    })
}

fn traffic_rate(path: &api::Path) -> Option<f32> {
    path.pattrs.iter().find_map(|a| match &a.attr {
        Some(Attr::ExtendedCommunities(e)) => e.communities.iter().find_map(|c| match &c.extcom {
            Some(Extcom::TrafficRate(r)) => Some(r.rate),
            _ => None,
        }),
        _ => None,
    })
}

#[tokio::test]
async fn every_action_is_announced_read_back_and_withdrawn() {
    let Some(url) = std::env::var(ENDPOINT_VAR).ok() else {
        eprintln!(
            "skipping gobgp_lab: {ENDPOINT_VAR} is not set. This test requires a throwaway gobgpd \
             on loopback."
        );
        return;
    };
    let config = config();
    let mut gobgp = GoBgp::connect(&GoBgpEndpoint::loopback(&url))
        .await
        .expect("the lab gobgpd is reachable");
    assert!(
        gobgp.owned_routes(&config).await.unwrap().is_empty(),
        "the lab starts empty"
    );

    let dns = FlowMatch {
        protocol: Some(17),
        source_port: Some(53),
        ..FlowMatch::default()
    };
    let cases = [
        (p("192.0.2.10/32"), Action::Rtbh),
        (p("2001:db8::10/128"), Action::Rtbh),
        (p("198.51.100.0/24"), Action::ParentPrefix),
        (p("192.0.2.20/32"), Action::FlowspecDiscard(dns.clone())),
        (
            p("192.0.2.30/32"),
            Action::FlowspecRateLimit {
                flow: FlowMatch {
                    source: Some(p("203.0.113.0/24")),
                    ..dns.clone()
                },
                bytes_per_second: 125_000,
            },
        ),
        (
            p("2001:db8:1::/64"),
            Action::FlowspecDiscard(FlowMatch {
                protocol: Some(6),
                destination_port: Some(80),
                ..FlowMatch::default()
            }),
        ),
    ];

    // --- Announce each, and read each back exactly ---
    for (prefix, action) in &cases {
        gobgp
            .announce(announcement(prefix, action, &config))
            .await
            .unwrap_or_else(|e| panic!("{action:?} on {prefix}: {e}"));
    }
    let owned = gobgp.owned_routes(&config).await.unwrap();
    assert_eq!(owned.len(), cases.len(), "{owned:#?}");
    for (prefix, action) in &cases {
        let key = action.duplicate_key(prefix);
        let route = owned
            .iter()
            .find(|r| r.key == key)
            .unwrap_or_else(|| panic!("{key} was not read back"));
        assert_eq!(&route.prefix, prefix);
        assert_eq!(&route.action, action);
        match action {
            Action::Rtbh | Action::ParentPrefix => {
                let expected = if prefix.is_ipv4() {
                    "192.0.2.254"
                } else {
                    "2001:db8::254"
                };
                assert_eq!(next_hop(&route.path).as_deref(), Some(expected), "{key}");
                let c = communities(&route.path);
                assert!(
                    c.contains(&BLACKHOLE) && c.contains(&NO_EXPORT),
                    "{key}: {c:?}"
                );
            }
            Action::FlowspecDiscard(_) => {
                assert_eq!(traffic_rate(&route.path), Some(0.0), "{key}");
                assert!(!communities(&route.path).contains(&BLACKHOLE), "{key}");
            }
            Action::FlowspecRateLimit { .. } => {
                assert_eq!(traffic_rate(&route.path), Some(125_000.0), "{key}");
            }
        }
    }

    // --- Another speaker's route is never listed as ours ---
    let mut foreign = announcement(&p("192.0.2.99/32"), &Action::Rtbh, &config);
    foreign
        .pattrs
        .retain(|a| !matches!(a.attr, Some(Attr::LargeCommunities(_))));
    gobgp.announce(foreign).await.unwrap();
    let owned = gobgp.owned_routes(&config).await.unwrap();
    assert_eq!(owned.len(), cases.len());
    assert!(owned.iter().all(|r| r.prefix != p("192.0.2.99/32")));

    // --- Withdraw each: nothing of ours is left ---
    for (prefix, action) in &cases {
        gobgp
            .withdraw(withdrawal(prefix, action))
            .await
            .unwrap_or_else(|e| panic!("withdrawing {action:?} on {prefix}: {e}"));
    }
    assert!(gobgp.owned_routes(&config).await.unwrap().is_empty());
    gobgp
        .withdraw(withdrawal(&p("192.0.2.99/32"), &Action::Rtbh))
        .await
        .unwrap();
}
