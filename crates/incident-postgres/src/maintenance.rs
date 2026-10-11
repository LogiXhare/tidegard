//! The incident timers (5C): the staleness sweep, recovery confirmation and
//! automatic closure, run as one pass across tenants.
//!
//! - **The query only proposes.** Each pass selects incidents that look due
//!   by PostgreSQL's `transaction_timestamp()`, then runs the domain call for
//!   each one as its own transaction. The domain call re-checks the timer
//!   against the incident as it reads it, so an event that arrived after
//!   the query keeps an incident open, and a resolved incident reopened
//!   and resolved again waits a full closure delay (FU-40).
//! - **One failure does not stop the pass.** A refused or failed incident
//!   is counted and the pass moves on; the next pass proposes it again.
//! - **Bounded.** Each of the three queries takes at most `batch_limit`
//!   incidents, oldest first. A backlog is worked off over several passes.
//! - **Scope.** The pass reads every tenant, so it takes a
//!   [`PlatformAuthority`] (ADR 0032). Each transition then runs under its
//!   own incident's tenant as the correlator, which holds `IncidentIngest`.
//! - **Critical incidents** are not proposed for automatic closure while
//!   the closure policy requires manual closure for them (BQ-8).

use std::time::Duration;

use tokio_postgres::{Client, Row};
use wetechinetmon_incident::authorization::AuthorizationContext;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::id::IncidentId;

use crate::error::PersistError;
use crate::outbox::micros;
use crate::platform::PlatformAuthority;
use crate::service::{IncidentPersistence, Outcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenancePolicy {
    /// Silence after which an active incident moves to `Recovering` as
    /// `detector_silent`. The state machine's default is three detection
    /// windows, at least 5 minutes; one value covers every policy here.
    pub silent_after: Duration,
    /// How long `Recovering` must hold before `Resolved`.
    pub recovery_confirmation: Duration,
    /// The most incidents each of the three steps takes in one pass.
    pub batch_limit: u32,
}

impl MaintenancePolicy {
    /// The state machine's documented defaults.
    pub const fn documented_default() -> Self {
        MaintenancePolicy {
            silent_after: Duration::from_secs(5 * 60),
            recovery_confirmation: Duration::from_secs(5 * 60),
            batch_limit: 500,
        }
    }
}

impl Default for MaintenancePolicy {
    fn default() -> Self {
        Self::documented_default()
    }
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub entered_recovering: u64,
    pub resolved: u64,
    pub closed: u64,
    /// Proposed, but the domain found the timer not yet due.
    pub not_due: u64,
    /// Proposed, but refused by the domain or failed in the database.
    pub failed: u64,
}

const SILENT: &str = "\
SELECT tenant_id, incident_id::text AS incident_id FROM incidents
WHERE state IN ('open', 'acknowledged', 'investigating', 'monitoring')
  AND last_detected_at <= transaction_timestamp() - $1::bigint * interval '1 microsecond'
ORDER BY last_detected_at
LIMIT $2";

const RECOVERY_DUE: &str = "\
SELECT tenant_id, incident_id::text AS incident_id FROM incidents
WHERE state = 'recovering'
  AND recovering_since <= transaction_timestamp() - $1::bigint * interval '1 microsecond'
ORDER BY recovering_since
LIMIT $2";

const CLOSURE_DUE: &str = "\
SELECT tenant_id, incident_id::text AS incident_id FROM incidents
WHERE state = 'resolved'
  AND resolved_at <= transaction_timestamp() - $1::bigint * interval '1 microsecond'
  AND ($3::boolean OR (NOT ever_critical AND severity <> 'critical'))
ORDER BY resolved_at
LIMIT $2";

/// Each active incident's timeline is counted through the V4
/// `(incident_id, occurred_at, timeline_id)` index, so the cost follows the
/// active incidents' own entries, never the whole table.
const TIMELINE_PRESSURE: &str = "\
SELECT coalesce(max(entries), 0) AS pressure FROM (
    SELECT (SELECT count(*) FROM incident_timeline t WHERE t.incident_id = i.incident_id)
        AS entries
    FROM incidents i
    WHERE i.state NOT IN ('resolved', 'closed')
) counted";

/// The most timeline entries on any active incident, for the
/// `timeline_pressure` gauge. The timeline is never truncated: an incident
/// nearing `TIMELINE_ENTRY_LIMIT` (50,000) is an operational fault, most
/// likely a flapping detection, and the answer is an alert, not data
/// loss (incident-domain-model.md, FU-32).
pub async fn timeline_pressure(
    _authority: &PlatformAuthority,
    client: &impl tokio_postgres::GenericClient,
) -> Result<i64, PersistError> {
    Ok(client
        .query_one(TIMELINE_PRESSURE, &[])
        .await?
        .try_get("pressure")?)
}

/// Runs the three timer steps once, in state-machine order.
pub async fn run_maintenance(
    _authority: &PlatformAuthority,
    service: &IncidentPersistence,
    client: &mut Client,
    policy: &MaintenancePolicy,
) -> Result<MaintenanceReport, PersistError> {
    let mut report = MaintenanceReport::default();
    let limit = i64::from(policy.batch_limit);

    let silent_after = micros(policy.silent_after);
    for (tenant, id) in proposed(client, SILENT, &silent_after, limit, None).await? {
        let auth = AuthorizationContext::correlator(tenant);
        let outcome = service
            .enter_recovering_if_silent(client, &auth, id, policy.silent_after)
            .await;
        if report.record(outcome) {
            report.entered_recovering += 1;
        }
    }

    let confirmation = micros(policy.recovery_confirmation);
    for (tenant, id) in proposed(client, RECOVERY_DUE, &confirmation, limit, None).await? {
        let auth = AuthorizationContext::correlator(tenant);
        let outcome = service
            .confirm_recovery_if_due(client, &auth, id, policy.recovery_confirmation)
            .await;
        if report.record(outcome) {
            report.resolved += 1;
        }
    }

    let closure = service.closure_policy();
    if closure.automatic_closure_enabled {
        let delay = micros(closure.automatic_closure_delay);
        let critical_allowed = !closure.critical_manual_closure_required;
        for (tenant, id) in
            proposed(client, CLOSURE_DUE, &delay, limit, Some(critical_allowed)).await?
        {
            let auth = AuthorizationContext::correlator(tenant);
            let outcome = service.attempt_automatic_closure(client, &auth, id).await;
            if report.record(outcome) {
                report.closed += 1;
            }
        }
    }
    Ok(report)
}

async fn proposed(
    client: &Client,
    sql: &str,
    age: &i64,
    limit: i64,
    critical_allowed: Option<bool>,
) -> Result<Vec<(TenantId, IncidentId)>, PersistError> {
    let rows = match critical_allowed {
        None => client.query(sql, &[age, &limit]).await?,
        Some(allowed) => client.query(sql, &[age, &limit, &allowed]).await?,
    };
    rows.iter().map(proposal).collect()
}

fn proposal(row: &Row) -> Result<(TenantId, IncidentId), PersistError> {
    let tenant: String = row.try_get("tenant_id")?;
    let id: String = row.try_get("incident_id")?;
    let id = IncidentId::parse(&id)
        .map_err(|error| PersistError::corrupt("incident_id", error.to_string()))?;
    Ok((TenantId::new(tenant), id))
}

impl MaintenanceReport {
    /// Counts a not-due or failed outcome, and says whether the transition
    /// happened so the caller counts it under its own step.
    fn record(&mut self, outcome: Outcome<bool>) -> bool {
        match outcome {
            Ok(Ok(true)) => true,
            Ok(Ok(false)) => {
                self.not_due += 1;
                false
            }
            Ok(Err(_)) | Err(_) => {
                self.failed += 1;
                false
            }
        }
    }
}
