//! WetechiNetMon's mitigation domain — Phase 7A
//! ([ADR 0046](../../../docs/architecture/decisions/0046-phase7a-mitigation-record.md)).
//!
//! The record of a mitigation and the commands that move it, separate from
//! the incident lifecycle (BQ-6). Dependency-free beyond the workspace:
//! no database, no BGP, no network. Persistence is in
//! `wetechinetmon-incident-postgres`; talking to GoBGP is the mitigator's
//! alone (`crates/mitigator`, 7C).

pub mod action;
pub mod mitigation;
pub mod prefix;
pub mod state;

pub use action::{Action, ActionKind, FlowMatch};
pub use mitigation::{
    ApprovalPolicy, Mitigation, MitigationError, MitigationId, MitigationRecord, MitigationRequest,
    Transition, WithdrawalCause,
};
pub use prefix::Prefix;
pub use state::MitigationState;
