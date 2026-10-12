//! Gate 2's structural safety property: nothing in the detection or
//! incident path can act on traffic or deliver a notification (ADR 0007,
//! ADR 0011, FU-9), proven from the dependency graph, not by review.
//!
//! - The detector's, the incident domain's and the mitigation domain's
//!   normal-dependency closures must stay inside a reviewed allowlist. A
//!   new crate fails this test until someone reviews it and adds it here.
//! - No crate anywhere in the workspace may be a routing, device-access or
//!   packet crate.
//! - Mail and chat crates are allowed in the notifier alone (Phase 6E,
//!   ADR 0045), and nothing else in the workspace may depend on it.
//! - gRPC, and with it GoBGP's API, is allowed in the mitigator alone
//!   (Phase 7C, ADR 0048), and nothing else may depend on it.
//!
//! The graph comes from `cargo tree`, which reads `Cargo.lock`. Only the
//! host platform's dependencies appear, so the allowlist also holds the
//! Windows-only crates and the check is a subset, not an equality.

use std::collections::BTreeSet;
use std::process::Command;

/// Every crate the detector and incident domain may depend on, directly or
/// not. Reviewed 2026-10-05: logging, serialisation, errors and the
/// workspace's own pure crates. None does I/O beyond writing logs.
const ALLOWED: &[&str] = &[
    "cfg-if",
    "itoa",
    "lazy_static",
    "log",
    "matchers",
    "memchr",
    "nu-ansi-term",
    "once_cell",
    "pin-project-lite",
    "proc-macro2",
    "quote",
    "regex-automata",
    "regex-syntax",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_json",
    "sharded-slab",
    "smallvec",
    "syn",
    "thiserror",
    "thiserror-impl",
    "thread_local",
    "tracing",
    "tracing-attributes",
    "tracing-core",
    "tracing-log",
    "tracing-serde",
    "tracing-subscriber",
    "unicode-ident",
    "wetechinetmon-aggregator",
    "wetechinetmon-classifier",
    "wetechinetmon-common",
    "wetechinetmon-detector",
    "wetechinetmon-incident",
    "wetechinetmon-mitigation",
    "windows-link",
    "windows-sys",
    "zmij",
];

/// Name fragments no crate in the workspace may carry: a BGP speaker,
/// device control and packet I/O. The mitigator reaches GoBGP over its API
/// and embeds no speaker (ADR 0048).
const NEVER: &[&str] = &[
    "bgp", "netconf", "snmp", "ssh", "telnet", "pnet", "netlink", "nftables", "iptables",
];

/// Mail and chat delivery: the notifier's business, nobody else's.
const DELIVERY: &[&str] = &[
    "smtp", "lettre", "mail", "sendgrid", "twilio", "telegram", "teloxide", "slack", "discord",
    "serenity", "webhook",
];

const NOTIFIER: &str = "wetechinetmon-notification";

/// gRPC: the mitigator's way to GoBGP, nobody else's.
const GRPC: &[&str] = &["tonic", "prost", "grpc", "h2"];

const MITIGATOR: &str = "wetechinetmon-mitigator";

/// The crate names in the normal-dependency closure that `args` selects.
fn closure(args: &[&str]) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args(["tree", "--quiet", "--edges", "normal", "--prefix", "none"])
        .args(["--format", "{p}"])
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree must run");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let names: BTreeSet<String> = String::from_utf8(output.stdout)
        .expect("cargo tree prints UTF-8")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect();
    assert!(!names.is_empty(), "cargo tree listed nothing");
    names
}

fn assert_allowed(package: &str) {
    let unreviewed: Vec<String> = closure(&["--package", package])
        .into_iter()
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    assert!(
        unreviewed.is_empty(),
        "{package} now depends on {unreviewed:?}. Review each against ADR 0007 and ADR 0011 \
         (it must not act on traffic or deliver anything) before adding it to ALLOWED."
    );
}

#[test]
fn the_detector_depends_only_on_reviewed_crates() {
    assert_allowed("wetechinetmon-detector");
}

#[test]
fn the_incident_domain_depends_only_on_reviewed_crates() {
    assert_allowed("wetechinetmon-incident");
}

/// The mitigation domain (ADR 0046) is as pure as the incident domain:
/// GoBGP and gRPC belong to the mitigator alone.
#[test]
fn the_mitigation_domain_depends_only_on_reviewed_crates() {
    assert_allowed("wetechinetmon-mitigation");
}

fn carrying<'a>(names: &'a BTreeSet<String>, fragments: &[&str]) -> Vec<&'a String> {
    names
        .iter()
        .filter(|name| fragments.iter().any(|fragment| name.contains(fragment)))
        .collect()
}

#[test]
fn no_crate_in_the_workspace_can_route_or_reach_a_device() {
    let workspace = closure(&["--workspace"]);
    let forbidden = carrying(&workspace, NEVER);
    assert!(
        forbidden.is_empty(),
        "the workspace depends on {forbidden:?}; nothing may embed a BGP speaker or reach a device"
    );
    // The check is only meaningful if it saw the whole graph.
    assert!(workspace.contains("tokio-postgres") && workspace.contains("hyper"));
}

#[test]
fn only_the_notifier_can_deliver_a_message() {
    let others = closure(&["--workspace", "--exclude", NOTIFIER]);
    let forbidden = carrying(&others, DELIVERY);
    assert!(
        forbidden.is_empty(),
        "{forbidden:?} is outside the notifier; only it may deliver messages (ADR 0045)"
    );
    assert!(
        !others.contains(NOTIFIER),
        "another workspace crate depends on the notifier"
    );
    // And the notifier really is where delivery lives.
    assert!(closure(&["--package", NOTIFIER]).contains("lettre"));
}

#[test]
fn only_the_mitigator_speaks_grpc() {
    let others = closure(&["--workspace", "--exclude", MITIGATOR]);
    let forbidden = carrying(&others, GRPC);
    assert!(
        forbidden.is_empty(),
        "{forbidden:?} is outside the mitigator; only it may reach GoBGP (ADR 0048)"
    );
    assert!(
        !others.contains(MITIGATOR),
        "another workspace crate depends on the mitigator"
    );
    // And the mitigator really is where gRPC lives.
    assert!(closure(&["--package", MITIGATOR]).contains("tonic"));
}
