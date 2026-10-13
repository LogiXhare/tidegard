//! Closure policy — BQ-8.
//!
//! Typed, validated, defaulted in code. **No environment-variable
//! parsing happens in this crate.** Reading `INCIDENT_CRITICAL_MANUAL_CLOSURE_REQUIRED`
//! or any other setting from the process environment, and reporting the
//! effective value in diagnostics, belongs to a later integration
//! milestone that owns startup — this crate only defines the typed value
//! and its validated default.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tidegard_detector::Severity;

/// `Resolved -> Closed` policy.
///
/// The secure default (`critical_manual_closure_required: true`) matches
/// BQ-8: a `critical` incident may auto-advance to `Recovering` and to
/// `Resolved`, but never automatically to `Closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosurePolicy {
    pub critical_manual_closure_required: bool,
    pub automatic_closure_enabled: bool,
    pub automatic_closure_delay: Duration,
}

impl ClosurePolicy {
    /// The BQ-8 approved defaults: manual closure required for critical,
    /// automatic closure enabled for everything else after 30 minutes.
    pub const fn approved_default() -> Self {
        ClosurePolicy {
            critical_manual_closure_required: true,
            automatic_closure_enabled: true,
            automatic_closure_delay: Duration::from_secs(30 * 60),
        }
    }

    /// Whether `severity` may auto-close under this policy. `critical`
    /// under the default (`critical_manual_closure_required: true`) is
    /// the one case this returns `false` for.
    pub fn allows_automatic_closure(&self, severity: Severity) -> bool {
        if !self.automatic_closure_enabled {
            return false;
        }
        if severity == Severity::Critical && self.critical_manual_closure_required {
            return false;
        }
        true
    }
}

impl Default for ClosurePolicy {
    fn default() -> Self {
        Self::approved_default()
    }
}

/// Why an incident was closed. Required on every `CloseIncident` command;
/// `Other` requires free text, carried separately on the command rather
/// than in this enum so the enum itself stays `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosureReason {
    Resolved,
    FalsePositive,
    Duplicate,
    ExpectedTraffic,
    NoActionRequired,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_forbids_automatic_critical_closure() {
        let policy = ClosurePolicy::approved_default();
        assert!(!policy.allows_automatic_closure(Severity::Critical));
        assert!(policy.allows_automatic_closure(Severity::Major));
        assert!(policy.allows_automatic_closure(Severity::Minor));
        assert!(policy.allows_automatic_closure(Severity::Info));
    }

    #[test]
    fn disabling_automatic_closure_forbids_every_severity() {
        let mut policy = ClosurePolicy::approved_default();
        policy.automatic_closure_enabled = false;
        for severity in [
            Severity::Critical,
            Severity::Major,
            Severity::Minor,
            Severity::Info,
        ] {
            assert!(!policy.allows_automatic_closure(severity));
        }
    }

    #[test]
    fn an_explicit_override_allows_automatic_critical_closure() {
        let mut policy = ClosurePolicy::approved_default();
        policy.critical_manual_closure_required = false;
        assert!(policy.allows_automatic_closure(Severity::Critical));
    }

    #[test]
    fn the_default_delay_is_thirty_minutes() {
        assert_eq!(
            ClosurePolicy::approved_default().automatic_closure_delay,
            Duration::from_secs(1800)
        );
    }
}
