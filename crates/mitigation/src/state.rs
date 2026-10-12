//! The mitigation lifecycle (ADR 0046).
//!
//! Separate from the incident's, by BQ-6: a mitigation never moves an
//! incident, and an incident never moves a mitigation.
//!
//! ```text
//! proposed ─┐
//!           ├─► approved ─► announcing ─► active ─► withdrawing ─► withdrawn
//! requested ┘      │            │  └──────────────────►┘
//!   │              └────────────┼──────────────────────────────────► withdrawn
//!   ├─► rejected                └─► failed
//!   └─► expired
//! ```
//!
//! Nothing before `approved` can hold a route, and every state that might
//! (`announcing`, `active`, `withdrawing`) leads only to `withdrawn` or
//! `failed`. A failed announcement may have left a partial route; the
//! mitigator's reconciliation removes anything it owns that no live
//! mitigation claims (7D).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationState {
    /// Detection suggested it. Announces nothing.
    Proposed,
    /// An operator asked for it. Announces nothing.
    Requested,
    /// An approver agreed. The mitigator will announce it.
    Approved,
    Announcing,
    Active,
    Withdrawing,
    Withdrawn,
    Rejected,
    /// Nobody approved it in time.
    Expired,
    Failed,
}

pub const ALL_STATES: [MitigationState; 10] = [
    MitigationState::Proposed,
    MitigationState::Requested,
    MitigationState::Approved,
    MitigationState::Announcing,
    MitigationState::Active,
    MitigationState::Withdrawing,
    MitigationState::Withdrawn,
    MitigationState::Rejected,
    MitigationState::Expired,
    MitigationState::Failed,
];

impl MitigationState {
    pub fn as_str(self) -> &'static str {
        match self {
            MitigationState::Proposed => "proposed",
            MitigationState::Requested => "requested",
            MitigationState::Approved => "approved",
            MitigationState::Announcing => "announcing",
            MitigationState::Active => "active",
            MitigationState::Withdrawing => "withdrawing",
            MitigationState::Withdrawn => "withdrawn",
            MitigationState::Rejected => "rejected",
            MitigationState::Expired => "expired",
            MitigationState::Failed => "failed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        ALL_STATES.into_iter().find(|state| state.as_str() == text)
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            MitigationState::Withdrawn
                | MitigationState::Rejected
                | MitigationState::Expired
                | MitigationState::Failed
        )
    }

    /// Waiting for an approver.
    pub fn awaits_approval(self) -> bool {
        matches!(self, MitigationState::Proposed | MitigationState::Requested)
    }

    /// A route may exist for it in GoBGP.
    pub fn may_hold_a_route(self) -> bool {
        matches!(
            self,
            MitigationState::Announcing | MitigationState::Active | MitigationState::Withdrawing
        )
    }

    pub fn can_transition_to(self, next: MitigationState) -> bool {
        use MitigationState::*;
        matches!(
            (self, next),
            (Proposed, Approved)
                | (Requested, Approved)
                | (Proposed, Rejected)
                | (Requested, Rejected)
                | (Proposed, Expired)
                | (Requested, Expired)
                | (Approved, Announcing)
                // Withdrawn before anything was announced.
                | (Approved, Withdrawn)
                | (Announcing, Active)
                | (Announcing, Failed)
                // A withdrawal or the kill switch while announcing.
                | (Announcing, Withdrawing)
                | (Active, Withdrawing)
                | (Withdrawing, Withdrawn)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use MitigationState::*;

    const LEGAL: [(MitigationState, MitigationState); 13] = [
        (Proposed, Approved),
        (Requested, Approved),
        (Proposed, Rejected),
        (Requested, Rejected),
        (Proposed, Expired),
        (Requested, Expired),
        (Approved, Announcing),
        (Approved, Withdrawn),
        (Announcing, Active),
        (Announcing, Failed),
        (Announcing, Withdrawing),
        (Active, Withdrawing),
        (Withdrawing, Withdrawn),
    ];

    #[test]
    fn exactly_the_listed_edges_are_legal() {
        for from in ALL_STATES {
            for to in ALL_STATES {
                assert_eq!(
                    from.can_transition_to(to),
                    LEGAL.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn terminal_states_have_no_way_out() {
        for from in ALL_STATES.into_iter().filter(|s| s.is_terminal()) {
            for to in ALL_STATES {
                assert!(!from.can_transition_to(to), "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn nothing_reaches_a_route_without_approval() {
        // Every path into a route-holding state passes through Approved.
        for (from, to) in LEGAL {
            if to.may_hold_a_route() && !from.may_hold_a_route() {
                assert_eq!(from, Approved, "{from:?} -> {to:?}");
            }
        }
        // And a route-holding state ends only in Withdrawn or Failed.
        for (from, to) in LEGAL {
            if from.may_hold_a_route() && !to.may_hold_a_route() {
                assert!(matches!(to, Withdrawn | Failed), "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn names_round_trip() {
        for state in ALL_STATES {
            assert_eq!(MitigationState::parse(state.as_str()), Some(state));
        }
        assert_eq!(MitigationState::parse("mitigating"), None);
    }
}
