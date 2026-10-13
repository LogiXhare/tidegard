//! Severity and priority.
//!
//! Severity is reused exactly from the detector's four-value scale —
//! [`tidegard_detector::Severity`] — rather than a parallel incident
//! scale that would need a lossy mapping in both directions. Priority is
//! a separate, incident-domain-only concept: how urgently a human should
//! act, independent of the traffic's technical impact.

use serde::{Deserialize, Serialize};
pub use tidegard_detector::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Priority {
    P1,
    P2,
    P3,
    P4,
}

impl Priority {
    /// The default mapping from a severity, overridable per-incident by
    /// an operator holding `incident.priority.change`.
    pub fn default_for(severity: Severity) -> Self {
        match severity {
            Severity::Critical => Priority::P1,
            Severity::Major => Priority::P2,
            Severity::Minor => Priority::P3,
            Severity::Info => Priority::P4,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::P1 => "P1",
            Priority::P2 => "P2",
            Priority::P3 => "P3",
            Priority::P4 => "P4",
        }
    }
}

/// Where a severity value came from, so an operator override is never
/// silently re-overwritten by the next correlated event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeveritySource {
    Detection,
    Operator,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mapping_matches_the_domain_model() {
        assert_eq!(Priority::default_for(Severity::Critical), Priority::P1);
        assert_eq!(Priority::default_for(Severity::Major), Priority::P2);
        assert_eq!(Priority::default_for(Severity::Minor), Priority::P3);
        assert_eq!(Priority::default_for(Severity::Info), Priority::P4);
    }
}
