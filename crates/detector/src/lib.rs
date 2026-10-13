//! Tidegard's detection engine.
//!
//! Consumes protocol-independent traffic snapshots produced from the
//! Phase 3 pipeline, evaluates them against operator-written policies,
//! and emits explainable detection events. See
//! docs/architecture/detection-engine.md.
//!
//! **This crate cannot mitigate traffic.** It has no network client, no
//! command execution, and no dependency that could reach a router. That
//! is a property of the dependency graph, not a runtime check — see
//! docs/security/detection-safety.md and ADR 0007.

pub mod clock;
pub mod config;
pub mod engine;
pub mod evaluate;
pub mod event;
pub mod input;
pub mod metrics;
pub mod policy;
pub mod precedence;
pub mod sink;
pub mod state;
pub mod window;

pub use clock::{Clock, SystemClock, TestClock};
pub use config::{
    load_policies, CompiledPolicies, ConfigError, Magnitude, PolicyDefaults, PolicyDocument,
    PolicyEntry, TenantEntry, POLICY_SCHEMA_VERSION,
};
pub use engine::{cycle, DetectionEngine, EngineConfig, EngineReport, ThresholdDetectionEngine};
pub use evaluate::{evaluate, Evaluation, MatchedReason, SkipReason, SkippedMetric};
pub use event::{
    dedup_key, ActionTaken, DetectionEvent, EventFactory, EventKind, EventTarget,
    EVENT_SCHEMA_VERSION,
};
pub use input::{
    AddressFamily, CompletenessFlag, DataCompleteness, DetectionSnapshot, MetricKind, MetricRates,
    MetricUnit, SamplingStatus, ScopeId, ScopeKey, ScopeType, TrafficDirection, ALL_METRIC_KINDS,
};
pub use metrics::{CountingMetrics, DetectionMetrics, NoopMetrics};
pub use policy::{
    ClearPercent, DetectionPolicy, ExecutionMode, PolicyDraft, PolicyError, PolicySelector,
    Severity, TenantPrefixes, Thresholds, WILDCARD_TENANT,
};
pub use precedence::{Candidate, PolicySet, PrecedenceReason, Selection};
pub use sink::{DetectionEventSink, FanOutSink, InMemorySink, NullSink, SinkError, TracingSink};
pub use state::{
    DetectionContext, DetectionState, Expiry, ScopeState, Signal, SignalRecord, StateTable,
    StateTableConfig, StateTableStats, StateTransition, StepIgnored, StepOutcome, Suppression,
    TransitionReason,
};
pub use window::{DetectionWindows, WindowConfig, WindowStats, UNATTRIBUTED_TENANT};
