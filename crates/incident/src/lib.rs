//! Tidegard's Incident Management domain — Phase 5A.
//!
//! Dependency-free beyond the workspace, database-independent,
//! HTTP-independent, notification-independent, mitigation-independent.
//! See `docs/architecture/phase5-incident-management-plan.md` and
//! [ADR 0011](../../../docs/architecture/decisions/0011-incident-domain-boundary.md).
//!
//! # The detector import boundary
//!
//! This crate depends on `tidegard-detector` for exactly one
//! reason: to read [`tidegard_detector::DetectionEvent`] and reuse
//! its `Clock` trait. The **only** items imported from that crate,
//! anywhere in this one, are:
//!
//! `DetectionEvent, EventKind, EventTarget, ActionTaken, MatchedReason,
//! SkippedMetric, MetricRates, MetricKind, ScopeType, ScopeId,
//! TrafficDirection, AddressFamily, DataCompleteness, SamplingStatus,
//! Severity, DetectionState, TransitionReason, EVENT_SCHEMA_VERSION,
//! Clock, SystemClock, TestClock`.
//!
//! This crate must **never** import `StateTable`, `ScopeState`,
//! `DetectionEngine`, `evaluate`, `PolicyDraft`/`DetectionPolicy`/
//! `PolicySelector`, anything from `precedence`, `sink`, `window`, or
//! `config` — the detector's mutable engine machinery, as opposed to its
//! published event vocabulary. [ADR 0011](../../../docs/architecture/decisions/0011-incident-domain-boundary.md)
//! states this as a rule; **nothing enforces it mechanically today**,
//! because `tidegard-detector`'s `lib.rs` re-exports both the event
//! vocabulary and the engine internals as public items at the same crate
//! root — Cargo's dependency graph cannot express "may import module A
//! but not module B of the same crate." A grep-based or `cargo-deny`-style
//! check enforcing this boundary mechanically is recorded as a follow-up
//! for before Milestone 5B, when a second crate (persistence) will make
//! the boundary matter more.

pub mod assignment;
pub mod audit;
pub mod authorization;
pub mod category;
pub mod clock;
pub mod closure;
pub mod command;
pub mod correlation;
pub mod durable_time;
pub mod error;
pub mod evidence;
pub mod id;
pub mod idempotency;
pub mod incident;
pub mod limits;
pub mod manual;
pub mod number;
pub mod outbox;
pub mod reconstitute;
pub mod reopen;
pub mod severity;
pub mod snapshot;
pub mod state;
pub mod store;

pub mod suppression;
#[cfg(test)]
pub(crate) mod test_fixtures;
pub mod timeline;
pub mod transition;
pub mod unit_of_work;
