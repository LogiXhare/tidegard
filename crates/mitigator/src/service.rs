//! The mitigator's work (ADR 0049).
//!
//! Each pass looks at every live mitigation and moves it one step:
//!
//! - waiting too long for an approver: **expired**;
//! - approved: the route is built and recorded, the guard decides once
//!   more, and the route is **announced**, or only recorded in dry-run;
//! - active past its duration, or anything up while the kill switch is
//!   on: **withdrawn**;
//! - withdrawing: the route is taken down, and retried until it is.
//!
//! Reconciliation, on its own timer, compares the routes in GoBGP that
//! carry the ownership community with the mitigations that should have
//! one: it withdraws what nothing claims and restores what is missing.
//! It never sees a route without the ownership community.
//!
//! With BGP disabled the mitigator has no GoBGP connection at all. With
//! BGP enabled but dry-run on, it connects (to withdraw and reconcile what
//! an earlier live run announced) and announces nothing.

use std::collections::HashSet;
use std::time::Duration;

use deadpool_postgres::Pool;
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::mitigation::{
    MitigationStore, MitigationStoreError, ProposalCandidate, WorkItem,
};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::pool::acquire;
use tidegard_mitigation::{
    Action, Guard, MitigationError, MitigationRecord, MitigationRequest, MitigationState,
    WithdrawalCause,
};

use crate::config::ProposalPolicy;
use crate::gobgp::{GoBgp, GoBgpError};
use crate::metrics::MitigatorMetrics;
use crate::route::{announcement, summary, withdrawal, RouteConfig};

/// How many live mitigations one pass looks at.
const BATCH: u32 = 500;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub announced: usize,
    pub dry_run: usize,
    pub withdrawn: usize,
    pub failed: usize,
    pub expired: usize,
    pub proposed: usize,
    /// Refused by the guard as announcing would begin.
    pub refused: usize,
    /// Steps that failed and will be retried.
    pub errors: usize,
    pub kill_switch: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    pub owned: usize,
    pub stale_withdrawn: usize,
    pub restored: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum MitigatorError {
    #[error(transparent)]
    Store(#[from] MitigationStoreError),
    #[error(transparent)]
    Database(#[from] PersistError),
    #[error(transparent)]
    GoBgp(#[from] GoBgpError),
    #[error("reconciliation needs a GoBGP connection, and BGP is disabled")]
    NoBgp,
}

pub struct Mitigator {
    consumer_id: String,
    store: MitigationStore,
    guard: Guard,
    routes: RouteConfig,
    proposals: ProposalPolicy,
    platform: PlatformAuthority,
    /// Present exactly when BGP is enabled.
    gobgp: Option<GoBgp>,
    metrics: MitigatorMetrics,
}

impl Mitigator {
    pub fn new(
        consumer_id: String,
        store: MitigationStore,
        routes: RouteConfig,
        proposals: ProposalPolicy,
        platform: PlatformAuthority,
        gobgp: Option<GoBgp>,
        metrics: MitigatorMetrics,
    ) -> Self {
        let guard = store.guard().clone();
        Mitigator {
            consumer_id,
            store,
            guard,
            routes,
            proposals,
            platform,
            gobgp,
            metrics,
        }
    }

    /// Whether it holds a GoBGP connection: BGP is enabled.
    pub fn has_bgp(&self) -> bool {
        self.gobgp.is_some()
    }

    /// Whether this mitigator announces nothing.
    pub fn dry_run(&self) -> bool {
        self.guard.effective_dry_run() || self.gobgp.is_none()
    }

    fn context(&self, record: &MitigationRecord) -> AuthorizationContext {
        AuthorizationContext::mitigator(record.tenant.clone(), &self.consumer_id)
    }

    /// One pass over every live mitigation, then proposals.
    pub async fn run_once(&mut self, pool: &Pool) -> Result<Report, MitigatorError> {
        let mut client = acquire(pool).await?;
        let mut report = Report {
            kill_switch: self.store.kill_switch(&**client).await?.engaged
                || self.guard.config().kill_switch,
            ..Report::default()
        };
        let work = self.store.work(&self.platform, &**client, BATCH).await?;
        for item in work {
            let outcome = self
                .step(&mut client, &item, report.kill_switch, &mut report)
                .await;
            if let Err(error) = outcome {
                report.errors += 1;
                tracing::warn!(
                    mitigation_id = %item.record.id,
                    state = item.record.state.as_str(),
                    error = %error,
                    "a mitigation step failed; it will be retried"
                );
                if matches!(error, MitigatorError::Database(_)) {
                    break;
                }
            }
        }
        if self.proposals.enabled && !report.kill_switch {
            self.propose(&mut client, &mut report).await?;
        }
        self.metrics.record(&report);
        Ok(report)
    }

    async fn step(
        &mut self,
        client: &mut tokio_postgres::Client,
        item: &WorkItem,
        kill_switch: bool,
        report: &mut Report,
    ) -> Result<(), MitigatorError> {
        let record = &item.record;
        let ctx = self.context(record);
        match record.state {
            MitigationState::Proposed | MitigationState::Requested if item.approval_expired => {
                self.store.expire(client, &ctx, &record.id).await?;
                report.expired += 1;
            }
            MitigationState::Approved if kill_switch => {
                self.store
                    .begin_withdrawal(client, &ctx, &record.id, WithdrawalCause::KillSwitch)
                    .await?;
                report.withdrawn += 1;
            }
            MitigationState::Approved => self.announce(client, &ctx, record, report).await?,
            MitigationState::Announcing | MitigationState::Active if kill_switch => {
                let down = self
                    .store
                    .begin_withdrawal(client, &ctx, &record.id, WithdrawalCause::KillSwitch)
                    .await?;
                self.take_down(client, &ctx, &down, report).await?;
            }
            MitigationState::Active if item.duration_reached => {
                let down = self
                    .store
                    .begin_withdrawal(client, &ctx, &record.id, WithdrawalCause::DurationReached)
                    .await?;
                self.take_down(client, &ctx, &down, report).await?;
            }
            // Left half-way by a restart: finish announcing. AddPath with the
            // same NLRI replaces, so repeating it is safe.
            MitigationState::Announcing => {
                if record.dry_run == Some(false) {
                    let path = announcement(&record.prefix, &record.action, &self.routes);
                    self.live()?.announce(path).await?;
                }
                self.store.mark_active(client, &ctx, &record.id).await?;
            }
            MitigationState::Withdrawing => self.take_down(client, &ctx, record, report).await?,
            _ => {}
        }
        Ok(())
    }

    fn live(&mut self) -> Result<&mut GoBgp, MitigatorError> {
        self.gobgp.as_mut().ok_or(MitigatorError::NoBgp)
    }

    async fn announce(
        &mut self,
        client: &mut tokio_postgres::Client,
        ctx: &AuthorizationContext,
        record: &MitigationRecord,
        report: &mut Report,
    ) -> Result<(), MitigatorError> {
        let dry_run = self.dry_run();
        let route = summary(&record.prefix, &record.action, &self.routes, dry_run);
        match self
            .store
            .begin_announcing(client, ctx, &record.id, dry_run, &route)
            .await
        {
            Ok(_) => {}
            // The configuration changed since approval: it ends here, and the
            // refusal is already audited.
            Err(MitigationStoreError::Mitigation(MitigationError::Refused(refusal))) => {
                self.store
                    .mark_failed(
                        client,
                        ctx,
                        &record.id,
                        &format!("refused by the guard: {refusal}"),
                    )
                    .await?;
                report.refused += 1;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        if dry_run {
            self.store.mark_active(client, ctx, &record.id).await?;
            report.dry_run += 1;
            tracing::info!(mitigation_id = %record.id, route = %route, "dry-run: recorded, not announced");
            return Ok(());
        }
        let path = announcement(&record.prefix, &record.action, &self.routes);
        match self.live()?.announce(path).await {
            Ok(_) => {
                self.store.mark_active(client, ctx, &record.id).await?;
                report.announced += 1;
            }
            Err(error) => {
                // Take down anything partial before giving up on it.
                let _ = self
                    .live()?
                    .withdraw(withdrawal(&record.prefix, &record.action))
                    .await;
                self.store
                    .mark_failed(client, ctx, &record.id, &error.to_string())
                    .await?;
                report.failed += 1;
            }
        }
        Ok(())
    }

    async fn take_down(
        &mut self,
        client: &mut tokio_postgres::Client,
        ctx: &AuthorizationContext,
        record: &MitigationRecord,
        report: &mut Report,
    ) -> Result<(), MitigatorError> {
        if record.state == MitigationState::Withdrawn {
            report.withdrawn += 1;
            return Ok(());
        }
        // A route was sent only if announcing ran live. A dry-run mitigation
        // has nothing in GoBGP to take down.
        if record.dry_run == Some(false) {
            self.live()?
                .withdraw(withdrawal(&record.prefix, &record.action))
                .await?;
        }
        self.store.mark_withdrawn(client, ctx, &record.id).await?;
        report.withdrawn += 1;
        Ok(())
    }

    async fn propose(
        &mut self,
        client: &mut tokio_postgres::Client,
        report: &mut Report,
    ) -> Result<(), MitigatorError> {
        let candidates = self
            .store
            .proposal_candidates(
                &self.platform,
                &*client,
                &self.proposals.severities,
                Duration::from_secs(self.proposals.within_seconds),
                BATCH,
            )
            .await?;
        let duration = Duration::from_secs(self.proposals.duration_seconds);
        for ProposalCandidate {
            tenant,
            incident_id,
            target,
            severity,
        } in candidates
        {
            // Outside the allowlist there is nothing to propose; checking
            // here keeps the audit trail for real attempts.
            if self
                .guard
                .check(&tenant, &target, &Action::Rtbh, duration, false)
                .is_err()
            {
                continue;
            }
            let ctx = AuthorizationContext::mitigator(tenant, &self.consumer_id);
            let request = MitigationRequest {
                prefix: target,
                action: Action::Rtbh,
                reason: format!("proposed for a {severity} incoming attack on {target}"),
                duration,
                incident_id: Some(incident_id),
            };
            match self.store.propose(client, &ctx, request).await {
                Ok(_) => report.proposed += 1,
                // Someone already asked for the same thing.
                Err(MitigationStoreError::Mitigation(MitigationError::Duplicate)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Compares GoBGP with the mitigations that should have a route there,
    /// withdraws what nothing claims and restores what is missing.
    pub async fn reconcile(&mut self, pool: &Pool) -> Result<ReconcileReport, MitigatorError> {
        let client = acquire(pool).await?;
        let work = self.store.work(&self.platform, &**client, BATCH).await?;
        drop(client);
        let routes = self.routes.clone();
        let gobgp = self.live()?;
        let owned = gobgp.owned_routes(&routes).await?;
        let mut report = ReconcileReport {
            owned: owned.len(),
            ..ReconcileReport::default()
        };
        // Only routes that were really sent should be in GoBGP.
        let claimed: Vec<&MitigationRecord> = work
            .iter()
            .map(|item| &item.record)
            .filter(|r| {
                matches!(
                    r.state,
                    MitigationState::Announcing | MitigationState::Active
                ) && r.dry_run == Some(false)
            })
            .collect();
        let claimed_keys: HashSet<String> = claimed
            .iter()
            .map(|r| r.action.duplicate_key(&r.prefix))
            .collect();
        let owned_keys: HashSet<&str> = owned.iter().map(|r| r.key.as_str()).collect();
        for route in &owned {
            if !claimed_keys.contains(&route.key) {
                gobgp
                    .withdraw(withdrawal(&route.prefix, &route.action))
                    .await?;
                report.stale_withdrawn += 1;
                tracing::warn!(key = %route.key, "reconciliation withdrew a route no mitigation claims");
            }
        }
        for record in claimed {
            if record.state == MitigationState::Active
                && !owned_keys.contains(record.action.duplicate_key(&record.prefix).as_str())
            {
                gobgp
                    .announce(announcement(&record.prefix, &record.action, &routes))
                    .await?;
                report.restored += 1;
                tracing::warn!(mitigation_id = %record.id, "reconciliation restored a missing route");
            }
        }
        report.owned = report.owned - report.stale_withdrawn + report.restored;
        self.metrics.record_reconcile(&report);
        Ok(report)
    }

    /// Records GoBGP's peers for the API (V21) and the metrics.
    pub async fn check_peers(&mut self, pool: &Pool) -> Result<(usize, usize), MitigatorError> {
        let peers = self.live()?.peers().await?;
        let established = peers.iter().filter(|(_, _, s)| *s == "established").count();
        let mut client = acquire(pool).await?;
        let changes = self
            .store
            .record_peers(&self.platform, &mut client, &peers)
            .await?;
        for change in &changes {
            tracing::warn!(
                neighbor = %change.neighbor_address,
                event = change.event_type,
                state = %change.session_state,
                was = %change.previous_state,
                "a BGP session changed"
            );
        }
        self.metrics.record_peers(established, peers.len());
        Ok((established, peers.len()))
    }
}
