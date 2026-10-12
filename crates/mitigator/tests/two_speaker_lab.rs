//! Phase 7F (ADR 0051): what the edge router receives. WetechiNetMon's
//! speaker announces every action; a second `gobgpd`, standing in for the
//! edge router and peered over iBGP, must receive exactly those routes,
//! with their next hops, communities and FlowSpec actions, and nothing
//! once they are withdrawn.
//!
//! Needs the two-speaker lab of `scripts/start-gobgp-lab.sh`:
//! `WETECHINETMON_GOBGP_LAB_SPEAKER` (`http://127.0.0.1:50061`) and
//! `WETECHINETMON_GOBGP_LAB_EDGE` (`http://127.0.0.1:50062`). Both listen
//! on loopback and peer only with each other. Without them the test says
//! why and passes; CI starts them and fails on the skip message. Only
//! documentation prefixes and a private ASN are used.

use std::time::{Duration, Instant};

use wetechinetmon_mitigation::{Action, FlowMatch, Prefix};
use wetechinetmon_mitigator::api;
use wetechinetmon_mitigator::api::attribute::Attr;
use wetechinetmon_mitigator::api::extended_community::Extcom;
use wetechinetmon_mitigator::gobgp::{GoBgp, GoBgpEndpoint};
use wetechinetmon_mitigator::route::{
    announcement, withdrawal, OwnedRoute, RouteConfig, BLACKHOLE, NO_EXPORT,
};

const SPEAKER_VAR: &str = "WETECHINETMON_GOBGP_LAB_SPEAKER";
const EDGE_VAR: &str = "WETECHINETMON_GOBGP_LAB_EDGE";
/// Sessions come up and updates propagate within seconds on loopback.
const PATIENCE: Duration = Duration::from_secs(30);

fn p(text: &str) -> Prefix {
    text.parse().unwrap()
}

fn config() -> RouteConfig {
    serde_json::from_str(
        r#"{"local_asn": 65001, "rtbh_next_hop_ipv4": "192.0.2.1",
            "rtbh_next_hop_ipv6": "2001:db8::1",
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

/// Polls the edge's table until `done` holds, or panics with what it saw.
async fn edge_until(
    edge: &mut GoBgp,
    config: &RouteConfig,
    what: &str,
    done: impl Fn(&[OwnedRoute]) -> bool,
) -> Vec<OwnedRoute> {
    let start = Instant::now();
    loop {
        let routes = edge.owned_routes(config).await.unwrap();
        if done(&routes) {
            return routes;
        }
        assert!(
            start.elapsed() < PATIENCE,
            "the edge never {what}: it holds {routes:#?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn the_edge_receives_exactly_what_was_announced_and_nothing_after() {
    let (Some(speaker_url), Some(edge_url)) = (
        std::env::var(SPEAKER_VAR).ok(),
        std::env::var(EDGE_VAR).ok(),
    ) else {
        eprintln!(
            "skipping two_speaker_lab: {SPEAKER_VAR} or {EDGE_VAR} is not set. This test \
             requires the loopback two-speaker lab of scripts/start-gobgp-lab.sh."
        );
        return;
    };
    let config = config();
    let mut speaker = GoBgp::connect(&GoBgpEndpoint::loopback(&speaker_url))
        .await
        .expect("the lab speaker is reachable");
    let mut edge = GoBgp::connect(&GoBgpEndpoint::loopback(&edge_url))
        .await
        .expect("the lab edge is reachable");

    // --- The iBGP session comes up, and the edge starts empty ---
    let start = Instant::now();
    loop {
        let peers = speaker.peers().await.unwrap();
        if peers.iter().any(|(address, asn, state)| {
            address == "127.0.0.2" && *asn == 65001 && *state == "established"
        }) {
            break;
        }
        assert!(
            start.elapsed() < PATIENCE,
            "the session never came up: {peers:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(edge.owned_routes(&config).await.unwrap().is_empty());

    let dns = FlowMatch {
        protocol: Some(17),
        source_port: Some(53),
        ..FlowMatch::default()
    };
    let cases = [
        (p("203.0.113.10/32"), Action::Rtbh),
        (p("2001:db8::10/128"), Action::Rtbh),
        (p("198.51.100.0/24"), Action::ParentPrefix),
        (p("203.0.113.20/32"), Action::FlowspecDiscard(dns.clone())),
        (
            p("203.0.113.30/32"),
            Action::FlowspecRateLimit {
                flow: FlowMatch {
                    source: Some(p("192.0.2.0/24")),
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

    // --- Announced on our speaker; received, exactly, at the edge ---
    for (prefix, action) in &cases {
        speaker
            .announce(announcement(prefix, action, &config))
            .await
            .unwrap_or_else(|e| panic!("{action:?} on {prefix}: {e}"));
    }
    let received = edge_until(&mut edge, &config, "received every route", |routes| {
        routes.len() >= cases.len()
    })
    .await;
    assert_eq!(received.len(), cases.len(), "nothing extra: {received:#?}");
    for (prefix, action) in &cases {
        let key = action.duplicate_key(prefix);
        let route = received
            .iter()
            .find(|r| r.key == key)
            .unwrap_or_else(|| panic!("the edge did not receive {key}"));
        assert_eq!(&route.prefix, prefix, "{key}");
        assert_eq!(&route.action, action, "{key}");
        match action {
            Action::Rtbh | Action::ParentPrefix => {
                let expected = if prefix.is_ipv4() {
                    "192.0.2.1"
                } else {
                    "2001:db8::1"
                };
                assert_eq!(next_hop(&route.path).as_deref(), Some(expected), "{key}");
                let c = communities(&route.path);
                assert!(
                    c.contains(&BLACKHOLE) && c.contains(&NO_EXPORT),
                    "{key}: the edge sees BLACKHOLE and NO_EXPORT: {c:?}"
                );
            }
            Action::FlowspecDiscard(_) => {
                assert_eq!(traffic_rate(&route.path), Some(0.0), "{key}");
            }
            Action::FlowspecRateLimit { .. } => {
                assert_eq!(traffic_rate(&route.path), Some(125_000.0), "{key}");
            }
        }
    }

    // --- Withdrawn on our speaker; gone from the edge ---
    for (prefix, action) in &cases {
        speaker
            .withdraw(withdrawal(prefix, action))
            .await
            .unwrap_or_else(|e| panic!("withdrawing {action:?} on {prefix}: {e}"));
    }
    edge_until(
        &mut edge,
        &config,
        "dropped every route",
        <[OwnedRoute]>::is_empty,
    )
    .await;
    assert!(speaker.owned_routes(&config).await.unwrap().is_empty());
}
