//! Linked detection evidence, and its bounded, explicit retention.
//!
//! Owner decision: evidence capacity exhaustion must be explicit. Once
//! [`EVIDENCE_RETAINED_LIMIT`] references are retained, further links
//! **stop growing the retained list but keep counting**, and
//! [`EvidenceLedger::is_truncated`] reports it. The incident is never
//! silently presented as complete when evidence was actually dropped —
//! every reader of [`EvidenceLedger`] can see the retained count, the
//! total observed count, and the truncation flag together.

use serde::{Deserialize, Serialize};

use tidegard_detector::MetricKind;

pub const EVIDENCE_RETAINED_LIMIT: usize = 10_000;

/// How one detection event relates to the incident it is linked to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLinkType {
    Opening,
    Update,
    Closing,
    Late,
}

/// A pointer to a detection event, not the event itself — the
/// authoritative copy stays wherever the ingestion pipeline puts it
/// (ClickHouse, in later milestones). 5A stores only what correlation
/// and category derivation need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub detection_event_id: String,
    pub dedup_key: String,
    pub detection_id: String,
    pub link_type: EvidenceLinkType,
    pub matched_metrics: Vec<MetricKind>,
}

/// Retained evidence for one incident, with explicit, never-silent
/// exhaustion behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvidenceLedger {
    retained: Vec<EvidenceReference>,
    observed_total: u64,
}

impl EvidenceLedger {
    pub fn new() -> Self {
        EvidenceLedger::default()
    }

    /// Records one observed link. Retains it if there is room; otherwise
    /// counts it without growing the retained list.
    ///
    /// `observed_total` uses `saturating_add`, not a wrapping `+= 1`:
    /// documented overflow behavior for a counter that has no natural
    /// upper bound (unlike `retained`, which `EVIDENCE_RETAINED_LIMIT`
    /// already caps). Saturating at `u64::MAX` — reachable only after
    /// more observed links than any real incident could ever accumulate
    /// — can never wrap to a small number and silently understate how
    /// much evidence was actually observed.
    pub fn record(&mut self, reference: EvidenceReference) {
        self.observed_total = self.observed_total.saturating_add(1);
        if self.retained.len() < EVIDENCE_RETAINED_LIMIT {
            self.retained.push(reference);
        }
    }

    pub fn retained(&self) -> &[EvidenceReference] {
        &self.retained
    }

    pub fn retained_count(&self) -> usize {
        self.retained.len()
    }

    pub fn observed_total(&self) -> u64 {
        self.observed_total
    }

    /// Evidence links that were observed but not retained. Always
    /// present as a real number, including zero — never hidden.
    pub fn omitted_count(&self) -> u64 {
        self.observed_total
            .saturating_sub(self.retained.len() as u64)
    }

    pub fn is_truncated(&self) -> bool {
        self.omitted_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(id: &str) -> EvidenceReference {
        EvidenceReference {
            detection_event_id: id.to_string(),
            dedup_key: format!("{id}:started:0"),
            detection_id: id.to_string(),
            link_type: EvidenceLinkType::Update,
            matched_metrics: vec![MetricKind::Bps],
        }
    }

    #[test]
    fn recording_within_the_limit_is_not_truncated() {
        let mut ledger = EvidenceLedger::new();
        for i in 0..5 {
            ledger.record(reference(&i.to_string()));
        }
        assert_eq!(ledger.retained_count(), 5);
        assert_eq!(ledger.observed_total(), 5);
        assert_eq!(ledger.omitted_count(), 0);
        assert!(!ledger.is_truncated());
    }

    #[test]
    fn exceeding_the_limit_keeps_counting_without_growing_retained() {
        let mut ledger = EvidenceLedger::new();
        for i in 0..(EVIDENCE_RETAINED_LIMIT + 10) {
            ledger.record(reference(&i.to_string()));
        }
        assert_eq!(ledger.retained_count(), EVIDENCE_RETAINED_LIMIT);
        assert_eq!(
            ledger.observed_total(),
            (EVIDENCE_RETAINED_LIMIT + 10) as u64
        );
        assert_eq!(ledger.omitted_count(), 10);
        assert!(ledger.is_truncated());
    }
}
