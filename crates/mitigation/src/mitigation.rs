//! The mitigation record and the commands that move it (ADR 0046).
//!
//! Every command takes an [`AuthorizationContext`], checks the tenant
//! first (another tenant's mitigation does not exist, as for incidents),
//! then the permission, then the state. A successful command bumps the
//! version by one and returns the [`Transition`] that persistence writes
//! to the history, the audit trail and the outbox in one transaction.

use std::time::Duration;

use wetechinetmon_incident::authorization::{Actor, AuthorizationContext, Permission};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::id::IncidentId;

use crate::action::Action;
use crate::prefix::Prefix;
use crate::state::MitigationState;

/// The shortest mitigation anyone may ask for.
pub const MIN_DURATION: Duration = Duration::from_secs(60);
/// The longest, whatever a deployment configures: nothing is permanent.
/// The guard's own maximum (7B) is usually far shorter.
pub const MAX_DURATION: Duration = Duration::from_secs(7 * 24 * 3600);
pub const MAX_REASON_CHARS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MitigationId(String);

impl MitigationId {
    /// A canonical UUID, the same form incident ids take.
    pub fn parse(text: &str) -> Result<Self, MitigationError> {
        IncidentId::parse(text)
            .map(|id| MitigationId(id.to_canonical_string()))
            .map_err(|_| MitigationError::NotFound)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MitigationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a mitigation that was approved came down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WithdrawalCause {
    /// An operator withdrew it.
    Operator,
    /// It reached its duration.
    DurationReached,
    /// The global kill switch.
    KillSwitch,
}

impl WithdrawalCause {
    pub fn as_str(self) -> &'static str {
        match self {
            WithdrawalCause::Operator => "operator",
            WithdrawalCause::DurationReached => "duration_reached",
            WithdrawalCause::KillSwitch => "kill_switch",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            WithdrawalCause::Operator,
            WithdrawalCause::DurationReached,
            WithdrawalCause::KillSwitch,
        ]
        .into_iter()
        .find(|cause| cause.as_str() == text)
    }
}

/// What a requester asks for. Route attributes are not here: the
/// mitigator applies the deployment's (7C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitigationRequest {
    pub prefix: Prefix,
    pub action: Action,
    pub reason: String,
    pub duration: Duration,
    /// The incident it answers, if any. A link, never a dependency: the
    /// two lifecycles are independent (BQ-6).
    pub incident_id: Option<String>,
}

/// Everything persisted about a mitigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitigationRecord {
    pub id: MitigationId,
    pub tenant: TenantId,
    pub incident_id: Option<String>,
    pub prefix: Prefix,
    pub action: Action,
    pub reason: String,
    pub duration: Duration,
    pub state: MitigationState,
    pub version: u64,
    pub requested_by: Actor,
    pub approved_by: Option<Actor>,
    /// Set when announcing starts: whether the mitigator was in dry-run.
    pub dry_run: Option<bool>,
    pub withdrawal: Option<WithdrawalCause>,
    pub last_error: Option<String>,
}

/// One state change, for the history, the audit trail and the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub from: Option<MitigationState>,
    pub to: MitigationState,
    pub actor: Actor,
    pub permission: Permission,
    /// A reason, an error, or a withdrawal cause.
    pub detail: Option<String>,
}

impl Transition {
    /// The outbox event type, such as `mitigation.approved`.
    pub fn event_type(&self) -> String {
        format!("mitigation.{}", self.to.as_str())
    }
}

/// Whether a requester may approve their own mitigation. Off by default:
/// two people for every announcement. A small NOC with one person on shift
/// may turn it on, and every self-approval is still audited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApprovalPolicy {
    pub allow_self_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MitigationError {
    #[error("the caller lacks {}", .0.name())]
    Forbidden(Permission),
    #[error("no such mitigation")]
    NotFound,
    #[error("a {} mitigation cannot become {}", .from.as_str(), .to.as_str())]
    IllegalTransition {
        from: MitigationState,
        to: MitigationState,
    },
    #[error("the requester cannot approve their own mitigation here")]
    SelfApproval,
    #[error("{0}")]
    Invalid(String),
    #[error("a live mitigation already does this")]
    Duplicate,
    #[error("the mitigation has changed since version {0}")]
    VersionConflict(u64),
}

impl MitigationError {
    /// Stable: an API client may switch on it.
    pub fn code(&self) -> &'static str {
        match self {
            MitigationError::Forbidden(_) => "mitigation.forbidden",
            MitigationError::NotFound => "mitigation.not_found",
            MitigationError::IllegalTransition { .. } => "mitigation.illegal_transition",
            MitigationError::SelfApproval => "mitigation.self_approval",
            MitigationError::Invalid(_) => "mitigation.invalid",
            MitigationError::Duplicate => "mitigation.duplicate",
            MitigationError::VersionConflict(_) => "mitigation.version_conflict",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mitigation {
    record: MitigationRecord,
}

impl Mitigation {
    /// Detection suggests a mitigation for an incident. It announces
    /// nothing until approved (BQ-14).
    pub fn propose(
        ctx: &AuthorizationContext,
        id: MitigationId,
        request: MitigationRequest,
    ) -> Result<(Self, Transition), MitigationError> {
        Self::create(
            ctx,
            id,
            request,
            Permission::MitigationPropose,
            MitigationState::Proposed,
        )
    }

    /// An operator asks for a mitigation.
    pub fn request(
        ctx: &AuthorizationContext,
        id: MitigationId,
        request: MitigationRequest,
    ) -> Result<(Self, Transition), MitigationError> {
        Self::create(
            ctx,
            id,
            request,
            Permission::MitigationRequest,
            MitigationState::Requested,
        )
    }

    fn create(
        ctx: &AuthorizationContext,
        id: MitigationId,
        request: MitigationRequest,
        permission: Permission,
        state: MitigationState,
    ) -> Result<(Self, Transition), MitigationError> {
        require(ctx, permission)?;
        request
            .action
            .validate_for(&request.prefix)
            .map_err(|error| MitigationError::Invalid(error.to_string()))?;
        let reason = validate_reason(&request.reason)?;
        if request.duration < MIN_DURATION || request.duration > MAX_DURATION {
            return Err(MitigationError::Invalid(format!(
                "the duration must be between {} and {} seconds",
                MIN_DURATION.as_secs(),
                MAX_DURATION.as_secs()
            )));
        }
        let incident_id = request
            .incident_id
            .map(|text| {
                IncidentId::parse(&text)
                    .map(|id| id.to_canonical_string())
                    .map_err(|_| MitigationError::Invalid("the incident id is not a UUID".into()))
            })
            .transpose()?;
        let record = MitigationRecord {
            id,
            tenant: ctx.tenant().clone(),
            incident_id,
            prefix: request.prefix,
            action: request.action,
            reason: reason.clone(),
            duration: request.duration,
            state,
            version: 1,
            requested_by: ctx.actor().clone(),
            approved_by: None,
            dry_run: None,
            withdrawal: None,
            last_error: None,
        };
        let transition = Transition {
            from: None,
            to: state,
            actor: ctx.actor().clone(),
            permission,
            detail: Some(reason),
        };
        Ok((Mitigation { record }, transition))
    }

    pub fn from_record(record: MitigationRecord) -> Self {
        Mitigation { record }
    }

    pub fn record(&self) -> &MitigationRecord {
        &self.record
    }

    pub fn into_record(self) -> MitigationRecord {
        self.record
    }

    /// Ties a duplicate check to the action and the prefix.
    pub fn duplicate_key(&self) -> String {
        self.record.action.duplicate_key(&self.record.prefix)
    }

    pub fn approve(
        &mut self,
        ctx: &AuthorizationContext,
        policy: ApprovalPolicy,
    ) -> Result<Transition, MitigationError> {
        self.check(ctx, Permission::MitigationApprove)?;
        self.allowed(MitigationState::Approved)?;
        if !policy.allow_self_approval && self.record.requested_by == *ctx.actor() {
            return Err(MitigationError::SelfApproval);
        }
        self.record.approved_by = Some(ctx.actor().clone());
        Ok(self.apply(
            ctx,
            Permission::MitigationApprove,
            MitigationState::Approved,
            None,
        ))
    }

    pub fn reject(
        &mut self,
        ctx: &AuthorizationContext,
        reason: &str,
    ) -> Result<Transition, MitigationError> {
        self.check(ctx, Permission::MitigationApprove)?;
        let reason = validate_reason(reason)?;
        self.allowed(MitigationState::Rejected)?;
        Ok(self.apply(
            ctx,
            Permission::MitigationApprove,
            MitigationState::Rejected,
            Some(reason),
        ))
    }

    /// An operator takes an approved mitigation down, or stops it before
    /// it is announced.
    pub fn withdraw(
        &mut self,
        ctx: &AuthorizationContext,
        reason: &str,
    ) -> Result<Transition, MitigationError> {
        self.check(ctx, Permission::MitigationWithdraw)?;
        let reason = validate_reason(reason)?;
        self.take_down(
            ctx,
            Permission::MitigationWithdraw,
            WithdrawalCause::Operator,
            Some(reason),
        )
    }

    /// The mitigator takes a mitigation down at its duration or on the
    /// kill switch.
    pub fn begin_withdrawal(
        &mut self,
        ctx: &AuthorizationContext,
        cause: WithdrawalCause,
    ) -> Result<Transition, MitigationError> {
        self.check(ctx, Permission::MitigationExecute)?;
        self.take_down(ctx, Permission::MitigationExecute, cause, None)
    }

    fn take_down(
        &mut self,
        ctx: &AuthorizationContext,
        permission: Permission,
        cause: WithdrawalCause,
        reason: Option<String>,
    ) -> Result<Transition, MitigationError> {
        let next = if self.record.state == MitigationState::Approved {
            MitigationState::Withdrawn
        } else {
            MitigationState::Withdrawing
        };
        self.allowed(next)?;
        self.record.withdrawal = Some(cause);
        let detail = Some(match reason {
            Some(reason) => format!("{}: {reason}", cause.as_str()),
            None => cause.as_str().to_string(),
        });
        Ok(self.apply(ctx, permission, next, detail))
    }

    pub fn begin_announcing(
        &mut self,
        ctx: &AuthorizationContext,
        dry_run: bool,
    ) -> Result<Transition, MitigationError> {
        self.check(ctx, Permission::MitigationExecute)?;
        self.allowed(MitigationState::Announcing)?;
        self.record.dry_run = Some(dry_run);
        let detail = dry_run.then(|| "dry_run".to_string());
        Ok(self.apply(
            ctx,
            Permission::MitigationExecute,
            MitigationState::Announcing,
            detail,
        ))
    }

    pub fn mark_active(
        &mut self,
        ctx: &AuthorizationContext,
    ) -> Result<Transition, MitigationError> {
        self.execute(ctx, MitigationState::Active, None)
    }

    pub fn mark_withdrawn(
        &mut self,
        ctx: &AuthorizationContext,
    ) -> Result<Transition, MitigationError> {
        if self.record.state == MitigationState::Approved {
            // Only `take_down` may end an approved mitigation: it records why.
            return Err(MitigationError::IllegalTransition {
                from: self.record.state,
                to: MitigationState::Withdrawn,
            });
        }
        self.execute(ctx, MitigationState::Withdrawn, None)
    }

    pub fn mark_failed(
        &mut self,
        ctx: &AuthorizationContext,
        error: &str,
    ) -> Result<Transition, MitigationError> {
        let error: String = error
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_REASON_CHARS)
            .collect();
        self.record.last_error = Some(error.clone());
        self.execute(ctx, MitigationState::Failed, Some(error))
    }

    /// Nobody approved it in time.
    pub fn expire(&mut self, ctx: &AuthorizationContext) -> Result<Transition, MitigationError> {
        self.execute(ctx, MitigationState::Expired, None)
    }

    fn execute(
        &mut self,
        ctx: &AuthorizationContext,
        next: MitigationState,
        detail: Option<String>,
    ) -> Result<Transition, MitigationError> {
        self.check(ctx, Permission::MitigationExecute)?;
        self.allowed(next)?;
        Ok(self.apply(ctx, Permission::MitigationExecute, next, detail))
    }

    fn check(
        &self,
        ctx: &AuthorizationContext,
        permission: Permission,
    ) -> Result<(), MitigationError> {
        if ctx.tenant() != &self.record.tenant {
            return Err(MitigationError::NotFound);
        }
        require(ctx, permission)
    }

    fn allowed(&self, next: MitigationState) -> Result<(), MitigationError> {
        if self.record.state.can_transition_to(next) {
            Ok(())
        } else {
            Err(MitigationError::IllegalTransition {
                from: self.record.state,
                to: next,
            })
        }
    }

    fn apply(
        &mut self,
        ctx: &AuthorizationContext,
        permission: Permission,
        next: MitigationState,
        detail: Option<String>,
    ) -> Transition {
        let from = self.record.state;
        self.record.state = next;
        self.record.version += 1;
        Transition {
            from: Some(from),
            to: next,
            actor: ctx.actor().clone(),
            permission,
            detail,
        }
    }
}

fn require(ctx: &AuthorizationContext, permission: Permission) -> Result<(), MitigationError> {
    if ctx.has(permission) {
        Ok(())
    } else {
        Err(MitigationError::Forbidden(permission))
    }
}

fn validate_reason(reason: &str) -> Result<String, MitigationError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(MitigationError::Invalid("a reason is required".into()));
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(MitigationError::Invalid(format!(
            "a reason is at most {MAX_REASON_CHARS} characters"
        )));
    }
    if reason.chars().any(char::is_control) {
        return Err(MitigationError::Invalid(
            "a reason cannot hold control characters".into(),
        ));
    }
    Ok(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::FlowMatch;
    use wetechinetmon_incident::authorization::{FixedBundleResolver, PermissionResolver};

    const ID: &str = "01900000-0000-7000-8000-000000000001";
    const INCIDENT: &str = "01900000-0000-7000-8000-0000000000aa";

    fn person(tenant: &str, id: &str, role: &str) -> AuthorizationContext {
        AuthorizationContext::new(
            TenantId::new(tenant),
            Actor::Operator { id: id.into() },
            FixedBundleResolver.permissions_for(role),
        )
    }

    fn mitigator(tenant: &str) -> AuthorizationContext {
        AuthorizationContext::mitigator(TenantId::new(tenant), "mitigator-1")
    }

    fn rtbh() -> MitigationRequest {
        MitigationRequest {
            prefix: "192.0.2.10/32".parse().unwrap(),
            action: Action::Rtbh,
            reason: "UDP flood on a customer host".into(),
            duration: Duration::from_secs(3600),
            incident_id: Some(INCIDENT.to_uppercase()),
        }
    }

    fn requested() -> Mitigation {
        let ctx = person("acme", "alice", "senior_operator");
        Mitigation::request(&ctx, MitigationId::parse(ID).unwrap(), rtbh())
            .unwrap()
            .0
    }

    fn approved() -> Mitigation {
        let mut m = requested();
        m.approve(
            &person("acme", "lead", "noc_lead"),
            ApprovalPolicy::default(),
        )
        .unwrap();
        m
    }

    #[test]
    fn a_request_is_validated_and_recorded() {
        let m = requested();
        let r = m.record();
        assert_eq!(r.state, MitigationState::Requested);
        assert_eq!(r.version, 1);
        assert_eq!(r.incident_id.as_deref(), Some(INCIDENT), "canonical form");
        assert_eq!(m.duplicate_key(), "rtbh|192.0.2.10/32|");

        let ctx = person("acme", "alice", "senior_operator");
        let id = || MitigationId::parse(ID).unwrap();
        for (request, needle) in [
            (
                MitigationRequest {
                    prefix: "192.0.2.0/24".parse().unwrap(),
                    ..rtbh()
                },
                "/32 or /128",
            ),
            (
                MitigationRequest {
                    reason: "  ".into(),
                    ..rtbh()
                },
                "reason is required",
            ),
            (
                MitigationRequest {
                    reason: "a\u{7}b".into(),
                    ..rtbh()
                },
                "control",
            ),
            (
                MitigationRequest {
                    duration: Duration::from_secs(59),
                    ..rtbh()
                },
                "duration",
            ),
            (
                MitigationRequest {
                    duration: MAX_DURATION + Duration::from_secs(1),
                    ..rtbh()
                },
                "duration",
            ),
            (
                MitigationRequest {
                    incident_id: Some("WNM-2026-000001".into()),
                    ..rtbh()
                },
                "UUID",
            ),
        ] {
            let error = Mitigation::request(&ctx, id(), request).unwrap_err();
            assert!(error.to_string().contains(needle), "{error}");
            assert_eq!(error.code(), "mitigation.invalid");
        }
    }

    #[test]
    fn only_the_right_roles_may_request_propose_and_approve() {
        let id = || MitigationId::parse(ID).unwrap();
        for role in ["viewer", "operator"] {
            assert_eq!(
                Mitigation::request(&person("acme", "bob", role), id(), rtbh()).unwrap_err(),
                MitigationError::Forbidden(Permission::MitigationRequest)
            );
        }
        // A person cannot propose; only the mitigator can.
        assert_eq!(
            Mitigation::propose(&person("acme", "lead", "noc_lead"), id(), rtbh()).unwrap_err(),
            MitigationError::Forbidden(Permission::MitigationPropose)
        );
        let (proposed, transition) = Mitigation::propose(&mitigator("acme"), id(), rtbh()).unwrap();
        assert_eq!(proposed.record().state, MitigationState::Proposed);
        assert_eq!(transition.event_type(), "mitigation.proposed");

        let mut m = requested();
        assert_eq!(
            m.approve(
                &person("acme", "carol", "senior_operator"),
                ApprovalPolicy::default()
            )
            .unwrap_err(),
            MitigationError::Forbidden(Permission::MitigationApprove)
        );
        // The mitigator cannot approve either.
        assert_eq!(
            m.approve(&mitigator("acme"), ApprovalPolicy::default())
                .unwrap_err(),
            MitigationError::Forbidden(Permission::MitigationApprove)
        );
        assert_eq!(m.record().version, 1, "nothing changed");
    }

    #[test]
    fn another_tenant_sees_nothing() {
        let mut m = requested();
        assert_eq!(
            m.approve(
                &person("other", "lead", "noc_lead"),
                ApprovalPolicy::default()
            )
            .unwrap_err(),
            MitigationError::NotFound
        );
        assert_eq!(
            m.begin_announcing(&mitigator("other"), true).unwrap_err(),
            MitigationError::NotFound
        );
    }

    #[test]
    fn a_requester_cannot_approve_their_own_unless_allowed() {
        let lead = person("acme", "lead", "noc_lead");
        let mut m = Mitigation::request(&lead, MitigationId::parse(ID).unwrap(), rtbh())
            .unwrap()
            .0;
        assert_eq!(
            m.approve(&lead, ApprovalPolicy::default()).unwrap_err(),
            MitigationError::SelfApproval
        );
        let transition = m
            .approve(
                &lead,
                ApprovalPolicy {
                    allow_self_approval: true,
                },
            )
            .unwrap();
        assert_eq!(transition.to, MitigationState::Approved);
        assert_eq!(m.record().approved_by, Some(lead.actor().clone()));
    }

    #[test]
    fn the_mitigator_carries_an_approved_mitigation_to_withdrawn() {
        let ctx = mitigator("acme");
        let mut m = approved();
        assert_eq!(m.record().version, 2);
        m.begin_announcing(&ctx, true).unwrap();
        assert_eq!(m.record().dry_run, Some(true));
        m.mark_active(&ctx).unwrap();
        let t = m
            .begin_withdrawal(&ctx, WithdrawalCause::DurationReached)
            .unwrap();
        assert_eq!(t.detail.as_deref(), Some("duration_reached"));
        m.mark_withdrawn(&ctx).unwrap();
        let r = m.record();
        assert_eq!(r.state, MitigationState::Withdrawn);
        assert_eq!(r.withdrawal, Some(WithdrawalCause::DurationReached));
        assert_eq!(r.version, 6);
    }

    #[test]
    fn people_cannot_drive_the_mitigators_steps() {
        let lead = person("acme", "lead", "platform_admin");
        let mut m = approved();
        assert_eq!(
            m.begin_announcing(&lead, false).unwrap_err(),
            MitigationError::Forbidden(Permission::MitigationExecute)
        );
        assert_eq!(
            m.mark_active(&lead).unwrap_err(),
            MitigationError::Forbidden(Permission::MitigationExecute)
        );
    }

    #[test]
    fn nothing_announces_before_approval() {
        let ctx = mitigator("acme");
        let mut m = requested();
        assert_eq!(
            m.begin_announcing(&ctx, false).unwrap_err(),
            MitigationError::IllegalTransition {
                from: MitigationState::Requested,
                to: MitigationState::Announcing
            }
        );
        m.expire(&ctx).unwrap();
        assert_eq!(m.record().state, MitigationState::Expired);
    }

    #[test]
    fn withdrawal_before_announcing_ends_at_once() {
        let mut m = approved();
        let t = m
            .withdraw(&person("acme", "dave", "senior_operator"), "false positive")
            .unwrap();
        assert_eq!(t.to, MitigationState::Withdrawn);
        assert_eq!(t.detail.as_deref(), Some("operator: false positive"));
        assert_eq!(
            m.withdraw(&person("acme", "dave", "senior_operator"), "again")
                .unwrap_err()
                .code(),
            "mitigation.illegal_transition"
        );
        assert_eq!(
            approved()
                .withdraw(&person("acme", "erin", "operator"), "no")
                .unwrap_err(),
            MitigationError::Forbidden(Permission::MitigationWithdraw)
        );
    }

    #[test]
    fn the_kill_switch_takes_down_what_is_announcing() {
        let ctx = mitigator("acme");
        let mut m = approved();
        m.begin_announcing(&ctx, false).unwrap();
        m.begin_withdrawal(&ctx, WithdrawalCause::KillSwitch)
            .unwrap();
        assert_eq!(m.record().state, MitigationState::Withdrawing);
        // `mark_withdrawn` cannot skip the record of why on an approved one.
        let mut fresh = approved();
        assert!(fresh.mark_withdrawn(&ctx).is_err());
    }

    #[test]
    fn a_failure_records_a_clean_error() {
        let ctx = mitigator("acme");
        let mut m = Mitigation::request(
            &person("acme", "alice", "senior_operator"),
            MitigationId::parse(ID).unwrap(),
            MitigationRequest {
                action: Action::FlowspecDiscard(FlowMatch {
                    protocol: Some(17),
                    ..FlowMatch::default()
                }),
                ..rtbh()
            },
        )
        .unwrap()
        .0;
        m.approve(
            &person("acme", "lead", "noc_lead"),
            ApprovalPolicy::default(),
        )
        .unwrap();
        m.begin_announcing(&ctx, false).unwrap();
        m.mark_failed(&ctx, "peer\nrefused").unwrap();
        assert_eq!(m.record().state, MitigationState::Failed);
        assert_eq!(m.record().last_error.as_deref(), Some("peerrefused"));
    }

    #[test]
    fn ids_are_canonical_uuids() {
        assert_eq!(
            MitigationId::parse(&ID.to_uppercase()).unwrap().as_str(),
            ID
        );
        assert_eq!(
            MitigationId::parse("not-a-uuid").unwrap_err(),
            MitigationError::NotFound
        );
    }
}
