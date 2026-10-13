//! Sampling rate resolution and correction — protocol-independent.
//!
//! Implements the documented priority order (highest first):
//! record-level sampling info → options-template sampling info →
//! exporter-specific configured sampling → global default sampling →
//! `1` (unsampled) when nothing else is declared. A declared rate of
//! exactly `0` is never usable (it would make every counter `0` or,
//! worse, division-by-zero-shaped downstream) — it is treated as "not
//! declared" and the resolver falls through to the next tier.

use std::num::NonZeroU32;

/// A sampling rate of at least 1 — by construction, `0` is unrepresentable.
/// `SamplingRate::unsampled()` (rate `1`) is used when nothing declares a
/// rate, so "unsampled" and "sampled at 1:1" are the same value, which is
/// correct: both mean "count every packet once."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SamplingRate(NonZeroU32);

impl SamplingRate {
    /// Returns `None` for a rate of `0` — callers must not construct a
    /// zero sampling rate; use [`resolve`] instead, which already
    /// implements the "reject zero, fall back" policy.
    pub fn new(rate: u32) -> Option<Self> {
        NonZeroU32::new(rate).map(SamplingRate)
    }

    pub fn unsampled() -> Self {
        SamplingRate(NonZeroU32::new(1).expect("1 is non-zero"))
    }

    pub fn get(&self) -> u32 {
        self.0.get()
    }

    /// Applies this rate to a raw (pre-correction) counter value.
    /// Overflow is never silently wrapped — it is reported so the caller
    /// can reject the flow and count the failure (see
    /// `tidegard-aggregator`'s `sampling_errors_total`-style metric).
    pub fn apply(&self, raw: u64) -> Result<u64, SamplingOverflow> {
        raw.checked_mul(self.get() as u64).ok_or(SamplingOverflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("sampling correction overflowed u64")]
pub struct SamplingOverflow;

/// Which priority tier actually supplied the resolved sampling rate —
/// carried alongside the rate for diagnostics/metrics, so an operator can
/// see *why* a given flow was corrected the way it was (mirrors the
/// explainability goal already established for direction classification,
/// FR-3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingSource {
    RecordLevel,
    OptionsTemplate,
    ExporterConfigured,
    GlobalDefault,
    /// No tier declared a usable (non-zero) rate; rate `1` was used.
    Unsampled,
}

/// The candidate sampling rate from each priority tier, highest priority
/// first. Each is `None` if that tier didn't declare anything, or
/// `Some(0)` if it declared an explicitly unusable zero rate (distinct
/// from "didn't declare," so callers can tell the two apart if they want
/// to log it — `resolve` treats both as "skip this tier" the same way).
#[derive(Debug, Clone, Copy, Default)]
pub struct SamplingInputs {
    pub record_level: Option<u32>,
    pub options_template: Option<u32>,
    pub exporter_configured: Option<u32>,
    pub global_default: Option<u32>,
}

/// The result of resolving [`SamplingInputs`] down the priority chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSampling {
    pub rate: SamplingRate,
    pub source: SamplingSource,
    /// `true` if one or more higher-priority tiers declared an explicit
    /// `0` that had to be skipped (as opposed to simply being absent).
    /// Callers should count this via a metric — a declared-but-unusable
    /// rate is worth an operator's attention even though it's handled
    /// safely.
    pub zero_rate_skipped: bool,
}

/// Resolves a sampling rate per the documented priority order. Never
/// returns a rate of `0` — this is the single place that guarantee is
/// enforced, so every caller downstream can rely on it without
/// re-checking.
pub fn resolve(inputs: &SamplingInputs) -> ResolvedSampling {
    let mut zero_rate_skipped = false;
    let mut consider = |value: Option<u32>| -> Option<SamplingRate> {
        match value {
            Some(0) => {
                zero_rate_skipped = true;
                None
            }
            Some(r) => SamplingRate::new(r),
            None => None,
        }
    };

    if let Some(rate) = consider(inputs.record_level) {
        return ResolvedSampling {
            rate,
            source: SamplingSource::RecordLevel,
            zero_rate_skipped,
        };
    }
    if let Some(rate) = consider(inputs.options_template) {
        return ResolvedSampling {
            rate,
            source: SamplingSource::OptionsTemplate,
            zero_rate_skipped,
        };
    }
    if let Some(rate) = consider(inputs.exporter_configured) {
        return ResolvedSampling {
            rate,
            source: SamplingSource::ExporterConfigured,
            zero_rate_skipped,
        };
    }
    if let Some(rate) = consider(inputs.global_default) {
        return ResolvedSampling {
            rate,
            source: SamplingSource::GlobalDefault,
            zero_rate_skipped,
        };
    }

    ResolvedSampling {
        rate: SamplingRate::unsampled(),
        source: SamplingSource::Unsampled,
        zero_rate_skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_not_a_constructible_rate() {
        assert_eq!(SamplingRate::new(0), None);
        assert_eq!(SamplingRate::new(1).unwrap().get(), 1);
        assert_eq!(SamplingRate::new(100).unwrap().get(), 100);
    }

    #[test]
    fn apply_multiplies_raw_counters() {
        let rate = SamplingRate::new(100).unwrap();
        assert_eq!(rate.apply(50).unwrap(), 5000);
        assert_eq!(SamplingRate::unsampled().apply(50).unwrap(), 50);
    }

    #[test]
    fn apply_reports_overflow_instead_of_wrapping() {
        let rate = SamplingRate::new(u32::MAX).unwrap();
        let result = rate.apply(u64::MAX);
        assert_eq!(result, Err(SamplingOverflow));
    }

    #[test]
    fn priority_record_level_wins_over_everything() {
        let inputs = SamplingInputs {
            record_level: Some(10),
            options_template: Some(20),
            exporter_configured: Some(30),
            global_default: Some(40),
        };
        let resolved = resolve(&inputs);
        assert_eq!(resolved.rate.get(), 10);
        assert_eq!(resolved.source, SamplingSource::RecordLevel);
        assert!(!resolved.zero_rate_skipped);
    }

    #[test]
    fn falls_through_to_options_template_when_record_level_absent() {
        let inputs = SamplingInputs {
            record_level: None,
            options_template: Some(20),
            exporter_configured: Some(30),
            global_default: Some(40),
        };
        let resolved = resolve(&inputs);
        assert_eq!(resolved.rate.get(), 20);
        assert_eq!(resolved.source, SamplingSource::OptionsTemplate);
    }

    #[test]
    fn falls_through_to_exporter_configured() {
        let inputs = SamplingInputs {
            exporter_configured: Some(30),
            global_default: Some(40),
            ..Default::default()
        };
        let resolved = resolve(&inputs);
        assert_eq!(resolved.rate.get(), 30);
        assert_eq!(resolved.source, SamplingSource::ExporterConfigured);
    }

    #[test]
    fn falls_through_to_global_default() {
        let inputs = SamplingInputs {
            global_default: Some(40),
            ..Default::default()
        };
        let resolved = resolve(&inputs);
        assert_eq!(resolved.rate.get(), 40);
        assert_eq!(resolved.source, SamplingSource::GlobalDefault);
    }

    #[test]
    fn falls_back_to_unsampled_when_nothing_declared() {
        let resolved = resolve(&SamplingInputs::default());
        assert_eq!(resolved.rate.get(), 1);
        assert_eq!(resolved.source, SamplingSource::Unsampled);
        assert!(!resolved.zero_rate_skipped);
    }

    #[test]
    fn an_explicit_zero_rate_is_rejected_and_falls_through() {
        let inputs = SamplingInputs {
            record_level: Some(0),
            options_template: Some(0),
            exporter_configured: Some(50),
            global_default: None,
        };
        let resolved = resolve(&inputs);
        assert_eq!(resolved.rate.get(), 50);
        assert_eq!(resolved.source, SamplingSource::ExporterConfigured);
        assert!(resolved.zero_rate_skipped);
    }

    #[test]
    fn all_tiers_zero_falls_back_to_unsampled_and_flags_it() {
        let inputs = SamplingInputs {
            record_level: Some(0),
            options_template: Some(0),
            exporter_configured: Some(0),
            global_default: Some(0),
        };
        let resolved = resolve(&inputs);
        assert_eq!(resolved.rate.get(), 1);
        assert_eq!(resolved.source, SamplingSource::Unsampled);
        assert!(resolved.zero_rate_skipped);
    }
}
