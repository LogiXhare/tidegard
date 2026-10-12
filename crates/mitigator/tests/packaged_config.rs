//! The configuration the release tarball installs (ADR 0052): a fresh
//! install from it is dry-run with BGP off, and the mitigator accepts it
//! as shipped (the Phase 9 "Defaults" criterion).

use wetechinetmon_mitigation::{Guard, GuardConfig};
use wetechinetmon_mitigator::config::parse_file;

const GUARD: &str = include_str!("../../../deployments/config/guard.json");
const MITIGATOR: &str = include_str!("../../../deployments/config/mitigator.json");

#[test]
fn the_shipped_guard_is_the_fresh_install() {
    let shipped: GuardConfig = serde_json::from_str(GUARD).expect("guard.json parses");
    assert_eq!(shipped, GuardConfig::default());
    assert!(!shipped.bgp_enabled, "BGP is off");
    assert!(shipped.allowlist.is_empty(), "nothing is allowlisted");
    let guard = Guard::new(shipped).expect("guard.json is a valid guard");
    assert!(guard.effective_dry_run(), "dry-run is on");
}

#[test]
fn the_shipped_mitigator_file_shares_the_guard_and_proposes_nothing() {
    let file = parse_file(MITIGATOR).expect("mitigator.json is accepted");
    assert_eq!(
        file.guard_file.as_deref(),
        Some(std::path::Path::new("/etc/wetechinetmon/guard.json"))
    );
    assert_eq!(file.guard, GuardConfig::default(), "no inline guard");
    assert!(
        !file.proposals.enabled,
        "no proposals until an operator asks"
    );
    assert!(
        file.gobgp.url.starts_with("http://127.0.0.1:"),
        "GoBGP's API is reached on loopback only"
    );
}
