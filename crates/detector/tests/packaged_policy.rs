//! The example detection policy the release tarball installs (ADR 0052)
//! compiles, uses only documentation prefixes, and never asks for
//! mitigation.

use std::time::Duration;

use tidegard_detector::config::{load_policies, parse_duration, PolicyDocument};
use tidegard_detector::ExecutionMode;

const POLICY: &str = include_str!("../../../deployments/config/detection-policy.json");

#[test]
fn the_shipped_policy_compiles_and_is_dry_run() {
    load_policies(POLICY).expect("detection-policy.json compiles");
    let document = PolicyDocument::from_json(POLICY).expect("detection-policy.json parses");
    assert!(!document.policies.is_empty());
    for policy in &document.policies {
        // The collector's default TIDEGARD_COLLECTOR_DETECTION_WINDOW_SECS.
        // A policy with another window is never evaluated.
        assert_eq!(
            parse_duration(&policy.window),
            Ok(Duration::from_secs(5)),
            "{}",
            policy.id
        );
        assert_eq!(
            policy.execution_mode,
            Some(ExecutionMode::DryRun),
            "{}",
            policy.id
        );
    }
    for tenant in &document.tenants {
        for prefix in &tenant.prefixes {
            assert!(
                prefix.starts_with("192.0.2.")
                    || prefix.starts_with("198.51.100.")
                    || prefix.starts_with("203.0.113.")
                    || prefix.starts_with("2001:db8:"),
                "{prefix} is not a documentation prefix"
            );
        }
    }
}
