//! Mitigation persistence (Phase 7A, ADR 0046).
//!
//! A mitigation lives in `mitigations` (V19), separate from the incident
//! tables (BQ-6). Every change runs in one transaction that writes the new
//! state, a `mitigation_history` row, an `incident_audit` row and an
//! `incident_outbox` event, or none of them. A refused command is audited
//! as `denied` after its transaction rolls back.
//!
//! The domain decides; this module loads, saves and guards:
//!
//! - **Duplicates** are refused by the `mitigations_one_live_per_action`
//!   partial unique index, so two concurrent requests for the same thing
//!   cannot both succeed.
//! - **Lost updates** are refused by the version: the row is locked, and
//!   the update matches the version it loaded.
//! - **Retried requests** replay through `incident_idempotency`, keyed by
//!   tenant and key, with the request's fingerprint compared byte for byte.
//! - **The safety guard** (ADR 0047) runs when a mitigation is requested or
//!   proposed, when it is approved, and when announcing begins, with the
//!   runtime kill switch read in the same transaction (ADR 0049). Its
//!   refusals are audited as `denied`, like a missing permission.
//! - **The kill switch** lives in `mitigation_controls` (V20). Turning it
//!   on or off is audited and emits an outbox event.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, GenericClient, Row};
use wetechinetmon_incident::authorization::{Actor, AuthorizationContext, Permission};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::id::IncidentGenerator;
use wetechinetmon_mitigation::mitigation::MAX_REASON_CHARS;
use wetechinetmon_mitigation::{
    Action, ActionKind, ApprovalPolicy, FlowMatch, Guard, Mitigation, MitigationError,
    MitigationId, MitigationRecord, MitigationRequest, MitigationState, Prefix, Transition,
    WithdrawalCause,
};

use crate::error::PersistError;
use crate::platform::PlatformAuthority;
use crate::row::{actor_columns, actor_from, ActorColumns};

const AUDIT_SCHEMA_VERSION: i32 = 1;
/// The most rows one list returns.
pub const MAX_PAGE: u32 = 500;
const IDEMPOTENCY_KEY_MIN: usize = 16;
const IDEMPOTENCY_KEY_MAX: usize = 255;

const COLUMNS: &str = "\
mitigation_id::text AS mitigation_id, tenant_id, incident_id::text AS incident_id,
prefix::text AS prefix, action, flow_match::text AS flow_match, rate_bytes_per_second,
reason, duration_seconds, state, version, requested_by_type, requested_by,
approved_by_type, approved_by, dry_run, withdrawal_cause, last_error";

const INSERT: &str = "\
INSERT INTO mitigations (
    mitigation_id, tenant_id, incident_id, prefix, action, flow_match,
    rate_bytes_per_second, reason, duration_seconds, state, version, duplicate_key,
    requested_by_type, requested_by
) VALUES (
    $1::text::uuid, $2, $3::text::uuid, $4::text::cidr, $5, $6::text::jsonb,
    $7, $8, $9, $10, $11, $12, $13, $14
)";

const UPDATE: &str = "\
UPDATE mitigations SET
    state = $3,
    version = $4,
    approved_by_type = $5,
    approved_by = $6,
    dry_run = $7,
    withdrawal_cause = $8,
    last_error = $9,
    updated_at = transaction_timestamp(),
    approved_at = CASE WHEN $3 = 'approved' THEN transaction_timestamp() ELSE approved_at END,
    active_since = CASE WHEN $3 = 'active' THEN transaction_timestamp() ELSE active_since END,
    expires_at = CASE WHEN $3 = 'active'
        THEN transaction_timestamp() + duration_seconds * interval '1 second'
        ELSE expires_at END,
    ended_at = CASE WHEN $3 IN ('withdrawn', 'rejected', 'expired', 'failed')
        THEN transaction_timestamp() ELSE ended_at END,
    route = COALESCE($10::text::jsonb, route)
WHERE mitigation_id = $1::text::uuid AND version = $2";

const INSERT_HISTORY: &str = "\
INSERT INTO mitigation_history (
    mitigation_id, tenant_id, version, from_state, to_state, actor_type, actor_id, detail
) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8)";

const INSERT_AUDIT: &str = "\
INSERT INTO incident_audit (
    tenant_id, schema_version, actor_type, actor_id, action,
    resource_type, resource_id, result, reason, before, after
) VALUES ($1, $2, $3, $4, $5, $11, $6, $7, $8, $9::text::jsonb, $10::text::jsonb)";

const SELECT_CONTROLS: &str = "\
SELECT kill_switch, version, changed_at::text AS changed_at, changed_by_type, changed_by, reason
FROM mitigation_controls";

const UPDATE_CONTROLS: &str = "\
UPDATE mitigation_controls SET
    kill_switch = $1,
    version = version + 1,
    changed_at = transaction_timestamp(),
    changed_by_type = $2,
    changed_by = $3,
    reason = $4
RETURNING kill_switch, version, changed_at::text AS changed_at, changed_by_type, changed_by, reason";

const INSERT_CONTROLS_OUTBOX: &str = "\
INSERT INTO incident_outbox (
    tenant_id, aggregate_type, aggregate_id, aggregate_version, event_type, payload
) VALUES ($1, 'mitigation_controls', 'kill_switch', $2, $3, $4::text::jsonb)";

const WORK: &str = "\
, (state IN ('proposed', 'requested')
      AND created_at + $1::bigint * interval '1 second' <= transaction_timestamp()) AS approval_expired,
  (state = 'active' AND expires_at <= transaction_timestamp()) AS duration_reached
FROM mitigations
WHERE state IN ('proposed', 'requested', 'approved', 'announcing', 'active', 'withdrawing')
ORDER BY created_at, mitigation_id
LIMIT $2";

/// Times as microseconds since the epoch, for the API to format.
const TIMES: &str = "\
, (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us,
  (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us,
  (extract(epoch FROM approved_at) * 1000000)::bigint AS approved_at_us,
  (extract(epoch FROM active_since) * 1000000)::bigint AS active_since_us,
  (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_us,
  (extract(epoch FROM ended_at) * 1000000)::bigint AS ended_at_us,
  route::text AS route_json";

const HISTORY: &str = "\
SELECT version, (extract(epoch FROM occurred_at) * 1000000)::bigint AS occurred_at_us,
    from_state, to_state, actor_type, actor_id, detail
FROM mitigation_history
WHERE mitigation_id = $1::text::uuid AND tenant_id = $2
ORDER BY version";

const PEERS: &str = "\
SELECT neighbor_address, peer_asn, session_state,
    (extract(epoch FROM updated_at) * 1000000)::bigint AS updated_at_us
FROM bgp_peers
ORDER BY neighbor_address";

const CANDIDATES: &str = "\
SELECT i.tenant_id, i.incident_id::text AS incident_id, host(i.target_addr) AS address,
    i.severity
FROM incidents i
WHERE i.target_type = 'host'
  AND i.target_addr IS NOT NULL
  AND i.direction = 'incoming'
  AND i.state IN ('open', 'acknowledged', 'investigating', 'monitoring')
  AND i.severity = ANY($1)
  AND i.opened_at >= transaction_timestamp() - $2::bigint * interval '1 second'
  AND NOT EXISTS (SELECT 1 FROM mitigations m WHERE m.incident_id = i.incident_id)
ORDER BY i.opened_at, i.incident_id
LIMIT $3";

const INSERT_OUTBOX: &str = "\
INSERT INTO incident_outbox (
    tenant_id, aggregate_type, aggregate_id, aggregate_version, event_type, payload
) VALUES ($1, 'mitigation', $2, $3, $4, $5::text::jsonb)";

const SELECT_IDEMPOTENCY: &str = "\
SELECT request_fingerprint, resource_type, resource_id
FROM incident_idempotency
WHERE tenant_id = $1 AND idempotency_key = $2 AND expires_at > transaction_timestamp()";

const UPSERT_IDEMPOTENCY: &str = "\
INSERT INTO incident_idempotency (
    tenant_id, idempotency_key, operation, resource_type, resource_id,
    request_fingerprint, response_status, expires_at
) VALUES (
    $1, $2, $3, 'mitigation', $4, $5, 'created', transaction_timestamp() + interval '24 hours'
)
ON CONFLICT (tenant_id, idempotency_key) DO UPDATE SET
    operation = EXCLUDED.operation,
    resource_type = EXCLUDED.resource_type,
    resource_id = EXCLUDED.resource_id,
    request_fingerprint = EXCLUDED.request_fingerprint,
    response_status = EXCLUDED.response_status,
    created_at = transaction_timestamp(),
    expires_at = EXCLUDED.expires_at
WHERE incident_idempotency.expires_at <= transaction_timestamp()";

#[derive(Debug, thiserror::Error)]
pub enum MitigationStoreError {
    #[error(transparent)]
    Mitigation(#[from] MitigationError),
    /// The key was recorded for a different request.
    #[error("the idempotency key was used for a different request")]
    IdempotencyMismatch,
    #[error(transparent)]
    Persist(#[from] PersistError),
}

impl From<tokio_postgres::Error> for MitigationStoreError {
    fn from(error: tokio_postgres::Error) -> Self {
        MitigationStoreError::Persist(PersistError::Database(error))
    }
}

/// The kill switch, and who last moved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSwitch {
    pub engaged: bool,
    pub version: u64,
    pub changed_at: Option<String>,
    pub changed_by: Option<Actor>,
    pub reason: Option<String>,
}

/// A mitigation with its times and its recorded route, for the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitigationDetail {
    pub record: MitigationRecord,
    /// Microseconds since the epoch.
    pub created_at_us: i64,
    pub updated_at_us: i64,
    pub approved_at_us: Option<i64>,
    pub active_since_us: Option<i64>,
    pub expires_at_us: Option<i64>,
    pub ended_at_us: Option<i64>,
    /// The route recorded when announcing began, as JSON text.
    pub route: Option<String>,
}

/// One state change in a mitigation's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub version: u64,
    pub occurred_at_us: i64,
    pub from_state: Option<String>,
    pub to_state: String,
    pub actor: Actor,
    pub detail: Option<String>,
}

/// One of GoBGP's peers, as the mitigator last saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    pub neighbor_address: String,
    pub peer_asn: u32,
    /// `established`, `idle`, `active` and the rest, lower case.
    pub session_state: String,
    pub updated_at_us: i64,
}

/// Which mitigations a list returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFilter {
    All,
    /// Not yet ended.
    Live,
    /// Announced live, with a route that may be in GoBGP now.
    Routed,
}

/// One live mitigation, as the mitigator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    pub record: MitigationRecord,
    /// Still waiting for an approver after the approval window.
    pub approval_expired: bool,
    /// Active for its whole duration.
    pub duration_reached: bool,
}

/// An incident the mitigator may propose a mitigation for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalCandidate {
    pub tenant: TenantId,
    pub incident_id: String,
    /// The attacked host, as a /32 or /128.
    pub target: Prefix,
    pub severity: String,
}

/// Reads and changes mitigations, for people (through the API) and for
/// the mitigator.
pub struct MitigationStore {
    generator: Arc<dyn IncidentGenerator>,
    guard: Arc<Guard>,
    approval: ApprovalPolicy,
}

impl MitigationStore {
    pub fn new(generator: Arc<dyn IncidentGenerator>, guard: Arc<Guard>) -> Self {
        let approval = guard.approval_policy();
        MitigationStore {
            generator,
            guard,
            approval,
        }
    }

    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    /// The guard's verdict on a mitigation as it stands, with the runtime
    /// kill switch as it was just read.
    fn guarded(&self, record: &MitigationRecord, kill_switch: bool) -> Result<(), MitigationError> {
        self.guard
            .check(
                &record.tenant,
                &record.prefix,
                &record.action,
                record.duration,
                kill_switch,
            )
            .map_err(MitigationError::Refused)
    }

    /// An operator asks for a mitigation. A retry with the same key and
    /// the same request returns the first result; with another request it
    /// is refused.
    pub async fn request(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        request: MitigationRequest,
        idempotency_key: Option<&str>,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.create(client, ctx, request, idempotency_key, false)
            .await
    }

    /// The mitigator proposes a mitigation for an incident.
    pub async fn propose(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        request: MitigationRequest,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.create(client, ctx, request, None, true).await
    }

    async fn create(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        request: MitigationRequest,
        idempotency_key: Option<&str>,
        propose: bool,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        let operation = if propose {
            "mitigation.propose"
        } else {
            "mitigation.request"
        };
        if let Some(key) = idempotency_key {
            if !(IDEMPOTENCY_KEY_MIN..=IDEMPOTENCY_KEY_MAX).contains(&key.len()) {
                return Err(MitigationError::Invalid(format!(
                    "an idempotency key is {IDEMPOTENCY_KEY_MIN} to {IDEMPOTENCY_KEY_MAX} characters"
                ))
                .into());
            }
        }
        let fingerprint = fingerprint(operation, &request);
        let generated = self
            .generator
            .generate()
            .map_err(|_| PersistError::DomainInvariant("the id generator refused"))?;
        let id = MitigationId::parse(&generated.to_canonical_string())?;
        let built = if propose {
            Mitigation::propose(ctx, id.clone(), request)
        } else {
            Mitigation::request(ctx, id.clone(), request)
        };
        let attempted = if propose {
            Permission::MitigationPropose
        } else {
            Permission::MitigationRequest
        };
        let (mitigation, transition) = match built {
            Ok(built) => built,
            Err(error) => {
                return Err(self
                    .refused(client, ctx, ("mitigation", id.as_str()), error, attempted)
                    .await)
            }
        };
        let kill_switch = read_controls(&*client).await?.engaged;
        if let Err(error) = self.guarded(mitigation.record(), kill_switch) {
            return Err(self
                .refused(client, ctx, ("mitigation", id.as_str()), error, attempted)
                .await);
        }

        let tx = client.transaction().await?;
        let tenant = ctx.tenant().as_str();
        if let Some(key) = idempotency_key {
            if let Some(row) = tx.query_opt(SELECT_IDEMPOTENCY, &[&tenant, &key]).await? {
                let stored: Vec<u8> = row.try_get("request_fingerprint")?;
                let resource_type: String = row.try_get("resource_type")?;
                let resource_id: Option<String> = row.try_get("resource_id")?;
                if stored != fingerprint || resource_type != "mitigation" {
                    return Err(MitigationStoreError::IdempotencyMismatch);
                }
                let id = MitigationId::parse(resource_id.as_deref().unwrap_or_default())?;
                let record = load(&tx, &id, false)
                    .await?
                    .ok_or(MitigationError::NotFound)?;
                tx.commit().await?;
                return Ok(record);
            }
        }

        let record = mitigation.record();
        let requested = actor_columns(&record.requested_by, "requested_by")?;
        let flow = record
            .action
            .flow()
            .map(|flow| serde_json::to_string(flow).expect("a flow match always serialises"));
        let rate = record
            .action
            .bytes_per_second()
            .map(|rate| i64::try_from(rate).expect("bounded by MAX_RATE_BYTES_PER_SECOND"));
        let duration = duration_seconds(record.duration)?;
        let version = version_column(record.version)?;
        let inserted = tx
            .execute(
                INSERT,
                &[
                    &record.id.as_str(),
                    &tenant,
                    &record.incident_id,
                    &record.prefix.to_string(),
                    &record.action.kind().as_str(),
                    &flow,
                    &rate,
                    &record.reason,
                    &duration,
                    &record.state.as_str(),
                    &version,
                    &mitigation.duplicate_key(),
                    &requested.actor_type,
                    &requested.actor_id,
                ],
            )
            .await;
        if let Err(error) = inserted {
            return Err(duplicate_or(error));
        }
        record_change(&tx, record, &transition).await?;
        if let Some(key) = idempotency_key {
            let recorded = tx
                .execute(
                    UPSERT_IDEMPOTENCY,
                    &[&tenant, &key, &operation, &record.id.as_str(), &fingerprint],
                )
                .await?;
            if recorded == 0 {
                return Err(PersistError::IdempotencyKeyTaken.into());
            }
        }
        tx.commit().await?;
        Ok(mitigation.into_record())
    }

    /// One mitigation, if the caller's tenant owns it.
    pub async fn get(
        &self,
        client: &impl GenericClient,
        ctx: &AuthorizationContext,
        id: &MitigationId,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        if !ctx.has(Permission::MitigationRead) {
            return Err(MitigationError::Forbidden(Permission::MitigationRead).into());
        }
        match load(client, id, false).await? {
            Some(record) if record.tenant == *ctx.tenant() => Ok(record),
            _ => Err(MitigationError::NotFound.into()),
        }
    }

    /// The tenant's mitigations, newest first.
    pub async fn list(
        &self,
        client: &impl GenericClient,
        ctx: &AuthorizationContext,
        limit: u32,
    ) -> Result<Vec<MitigationRecord>, MitigationStoreError> {
        if !ctx.has(Permission::MitigationRead) {
            return Err(MitigationError::Forbidden(Permission::MitigationRead).into());
        }
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let rows = client
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM mitigations WHERE tenant_id = $1 \
                     ORDER BY created_at DESC, mitigation_id DESC LIMIT $2"
                ),
                &[&ctx.tenant().as_str(), &limit],
            )
            .await?;
        rows.iter()
            .map(|row| from_row(row).map_err(Into::into))
            .collect()
    }

    pub async fn approve(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        expected_version: u64,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        let policy = self.approval;
        self.change(
            client,
            ctx,
            id,
            Some(expected_version),
            Permission::MitigationApprove,
            |m, ctx| m.approve(ctx, policy),
        )
        .await
    }

    pub async fn reject(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        expected_version: u64,
        reason: &str,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            Some(expected_version),
            Permission::MitigationApprove,
            |m, ctx| m.reject(ctx, reason),
        )
        .await
    }

    pub async fn withdraw(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        expected_version: u64,
        reason: &str,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            Some(expected_version),
            Permission::MitigationWithdraw,
            |m, ctx| m.withdraw(ctx, reason),
        )
        .await
    }

    /// The mitigator's steps (7D). Each takes the mitigation as it is now:
    /// the mitigator is the only actor in these states, and the row lock
    /// orders it against an operator's withdrawal.
    /// Announcing begins. `route` is the exact route the mitigator built,
    /// recorded whether or not it will be sent (dry-run).
    pub async fn begin_announcing(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        dry_run: bool,
        route: &serde_json::Value,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change_recording(
            client,
            ctx,
            id,
            None,
            Permission::MitigationExecute,
            Some(route.to_string()),
            |m, ctx| m.begin_announcing(ctx, dry_run),
        )
        .await
    }

    pub async fn mark_active(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            None,
            Permission::MitigationExecute,
            |m, ctx| m.mark_active(ctx),
        )
        .await
    }

    pub async fn mark_failed(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        error: &str,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            None,
            Permission::MitigationExecute,
            |m, ctx| m.mark_failed(ctx, error),
        )
        .await
    }

    pub async fn begin_withdrawal(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        cause: WithdrawalCause,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            None,
            Permission::MitigationExecute,
            |m, ctx| m.begin_withdrawal(ctx, cause),
        )
        .await
    }

    pub async fn mark_withdrawn(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            None,
            Permission::MitigationExecute,
            |m, ctx| m.mark_withdrawn(ctx),
        )
        .await
    }

    pub async fn expire(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            None,
            Permission::MitigationExecute,
            |m, ctx| m.expire(ctx),
        )
        .await
    }

    async fn change<F>(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        expected_version: Option<u64>,
        attempted: Permission,
        command: F,
    ) -> Result<MitigationRecord, MitigationStoreError>
    where
        F: FnOnce(&mut Mitigation, &AuthorizationContext) -> Result<Transition, MitigationError>,
    {
        self.change_recording(client, ctx, id, expected_version, attempted, None, command)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn change_recording<F>(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        expected_version: Option<u64>,
        attempted: Permission,
        route: Option<String>,
        command: F,
    ) -> Result<MitigationRecord, MitigationStoreError>
    where
        F: FnOnce(&mut Mitigation, &AuthorizationContext) -> Result<Transition, MitigationError>,
    {
        let tx = client.transaction().await?;
        let record = match load(&tx, id, true).await? {
            // Another tenant's mitigation does not exist, and its version
            // is not reported.
            Some(record) if record.tenant == *ctx.tenant() => record,
            _ => return Err(MitigationError::NotFound.into()),
        };
        let loaded = record.version;
        if let Some(expected) = expected_version {
            if expected != loaded {
                return Err(MitigationError::VersionConflict(loaded).into());
            }
        }
        let kill_switch = read_controls(&tx).await?.engaged;
        let mut mitigation = Mitigation::from_record(record);
        let checked = command(&mut mitigation, ctx).and_then(|transition| {
            // Approval and announcing are the last moments a mitigation can
            // be stopped before a route exists: the guard decides again,
            // under the configuration in force now.
            if matches!(
                transition.to,
                MitigationState::Approved | MitigationState::Announcing
            ) {
                self.guarded(mitigation.record(), kill_switch)?;
            }
            Ok(transition)
        });
        let transition = match checked {
            Ok(transition) => transition,
            Err(error) => {
                tx.rollback().await?;
                return Err(self
                    .refused(client, ctx, ("mitigation", id.as_str()), error, attempted)
                    .await);
            }
        };
        let record = mitigation.record();
        let approved = record
            .approved_by
            .as_ref()
            .map(|actor| actor_columns(actor, "approved_by"))
            .transpose()?;
        let updated = tx
            .execute(
                UPDATE,
                &[
                    &id.as_str(),
                    &version_column(loaded)?,
                    &record.state.as_str(),
                    &version_column(record.version)?,
                    &approved.as_ref().map(|a| a.actor_type.clone()),
                    &approved.and_then(|a| a.actor_id),
                    &record.dry_run,
                    &record.withdrawal.map(WithdrawalCause::as_str),
                    &record.last_error,
                    &route,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(MitigationError::VersionConflict(loaded).into());
        }
        record_change(&tx, record, &transition).await?;
        tx.commit().await?;
        Ok(mitigation.into_record())
    }

    /// One mitigation with its times and route, if the caller's tenant
    /// owns it.
    pub async fn detail(
        &self,
        client: &impl GenericClient,
        ctx: &AuthorizationContext,
        id: &MitigationId,
    ) -> Result<MitigationDetail, MitigationStoreError> {
        if !ctx.has(Permission::MitigationRead) {
            return Err(MitigationError::Forbidden(Permission::MitigationRead).into());
        }
        let row = client
            .query_opt(
                &format!(
                    "SELECT {COLUMNS}{TIMES} FROM mitigations WHERE mitigation_id = $1::text::uuid"
                ),
                &[&id.as_str()],
            )
            .await?;
        match row.as_ref().map(detail_from_row).transpose()? {
            Some(detail) if detail.record.tenant == *ctx.tenant() => Ok(detail),
            _ => Err(MitigationError::NotFound.into()),
        }
    }

    /// The tenant's mitigations, newest first.
    pub async fn list_details(
        &self,
        client: &impl GenericClient,
        ctx: &AuthorizationContext,
        filter: ListFilter,
        limit: u32,
    ) -> Result<Vec<MitigationDetail>, MitigationStoreError> {
        if !ctx.has(Permission::MitigationRead) {
            return Err(MitigationError::Forbidden(Permission::MitigationRead).into());
        }
        let condition = match filter {
            ListFilter::All => "",
            ListFilter::Live => " AND state NOT IN ('withdrawn', 'rejected', 'expired', 'failed')",
            ListFilter::Routed => {
                " AND state IN ('announcing', 'active', 'withdrawing') \
                 AND dry_run = FALSE AND route IS NOT NULL"
            }
        };
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let rows = client
            .query(
                &format!(
                    "SELECT {COLUMNS}{TIMES} FROM mitigations WHERE tenant_id = $1{condition} \
                     ORDER BY created_at DESC, mitigation_id DESC LIMIT $2"
                ),
                &[&ctx.tenant().as_str(), &limit],
            )
            .await?;
        rows.iter()
            .map(|row| detail_from_row(row).map_err(Into::into))
            .collect()
    }

    /// A mitigation's state changes, oldest first.
    pub async fn history(
        &self,
        client: &impl GenericClient,
        ctx: &AuthorizationContext,
        id: &MitigationId,
    ) -> Result<Vec<HistoryEntry>, MitigationStoreError> {
        // Existence and the tenant are checked first, so another tenant's
        // mitigation is `not_found` and never an empty history.
        self.get(client, ctx, id).await?;
        let rows = client
            .query(HISTORY, &[&id.as_str(), &ctx.tenant().as_str()])
            .await?;
        rows.iter()
            .map(|row| {
                Ok(HistoryEntry {
                    version: u64::try_from(row.try_get::<_, i64>("version")?)
                        .map_err(|_| PersistError::corrupt("version", "negative"))?,
                    occurred_at_us: row.try_get("occurred_at_us")?,
                    from_state: row.try_get("from_state")?,
                    to_state: row.try_get("to_state")?,
                    actor: actor_from(
                        ActorColumns {
                            actor_type: row.try_get("actor_type")?,
                            actor_id: row.try_get("actor_id")?,
                        },
                        "actor",
                    )?,
                    detail: row.try_get("detail")?,
                })
            })
            .collect::<Result<_, PersistError>>()
            .map_err(Into::into)
    }

    /// GoBGP's peers as the mitigator last saw them. Deployment-wide:
    /// held by those who may pull the kill switch (FU-65).
    pub async fn peers(
        &self,
        client: &impl GenericClient,
        ctx: &AuthorizationContext,
    ) -> Result<Vec<PeerStatus>, MitigationStoreError> {
        if !ctx.has(Permission::MitigationKillSwitchEngage) {
            return Err(MitigationError::Forbidden(Permission::MitigationKillSwitchEngage).into());
        }
        let rows = client.query(PEERS, &[]).await?;
        rows.iter()
            .map(|row| {
                Ok(PeerStatus {
                    neighbor_address: row.try_get("neighbor_address")?,
                    peer_asn: u32::try_from(row.try_get::<_, i64>("peer_asn")?)
                        .map_err(|_| PersistError::corrupt("peer_asn", "out of range"))?,
                    session_state: row.try_get("session_state")?,
                    updated_at_us: row.try_get("updated_at_us")?,
                })
            })
            .collect::<Result<_, PersistError>>()
            .map_err(Into::into)
    }

    /// Replaces the peer snapshot with what the mitigator sees now.
    pub async fn record_peers(
        &self,
        _platform: &PlatformAuthority,
        client: &mut Client,
        peers: &[(String, u32, &'static str)],
    ) -> Result<(), MitigationStoreError> {
        let tx = client.transaction().await?;
        tx.execute("DELETE FROM bgp_peers", &[]).await?;
        for (address, asn, state) in peers {
            tx.execute(
                "INSERT INTO bgp_peers (neighbor_address, peer_asn, session_state) VALUES ($1, $2, $3)",
                &[address, &i64::from(*asn), state],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The kill switch as it stands.
    pub async fn kill_switch(
        &self,
        client: &impl GenericClient,
    ) -> Result<KillSwitch, MitigationStoreError> {
        read_controls(client).await
    }

    /// Turns the kill switch on (`mitigation.kill_switch.engage`) or off
    /// (`mitigation.kill_switch.release`), with a reason. Setting it to
    /// what it already is changes nothing and writes nothing.
    pub async fn set_kill_switch(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        engaged: bool,
        reason: &str,
    ) -> Result<KillSwitch, MitigationStoreError> {
        let permission = if engaged {
            Permission::MitigationKillSwitchEngage
        } else {
            Permission::MitigationKillSwitchRelease
        };
        if !ctx.has(permission) {
            return Err(self
                .refused(
                    client,
                    ctx,
                    ("mitigation_controls", "kill_switch"),
                    MitigationError::Forbidden(permission),
                    permission,
                )
                .await);
        }
        let reason = reason.trim();
        if reason.is_empty()
            || reason.chars().count() > MAX_REASON_CHARS
            || reason.chars().any(char::is_control)
        {
            return Err(MitigationError::Invalid(format!(
                "a reason of 1 to {MAX_REASON_CHARS} characters, without control characters, is required"
            ))
            .into());
        }
        let actor = actor_columns(ctx.actor(), "actor")?;
        let tx = client.transaction().await?;
        let before = read_controls_locked(&tx).await?;
        if before.engaged == engaged {
            tx.commit().await?;
            return Ok(before);
        }
        let row = tx
            .query_one(
                UPDATE_CONTROLS,
                &[&engaged, &actor.actor_type, &actor.actor_id, &reason],
            )
            .await?;
        let after = controls_from(&row)?;
        let tenant = ctx.tenant().as_str();
        tx.execute(
            INSERT_AUDIT,
            &[
                &tenant,
                &AUDIT_SCHEMA_VERSION,
                &actor.actor_type,
                &actor.actor_id,
                &permission.name(),
                &"kill_switch",
                &"allowed",
                &Some(reason.to_string()),
                &Some(json!({ "kill_switch": before.engaged }).to_string()),
                &Some(json!({ "kill_switch": after.engaged }).to_string()),
                &"mitigation_controls",
            ],
        )
        .await?;
        let event = if engaged {
            "mitigation.kill_switch_engaged"
        } else {
            "mitigation.kill_switch_released"
        };
        tx.execute(
            INSERT_CONTROLS_OUTBOX,
            &[
                &tenant,
                &version_column(after.version)?,
                &event,
                &json!({ "kill_switch": engaged, "reason": reason, "version": after.version })
                    .to_string(),
            ],
        )
        .await?;
        tx.commit().await?;
        Ok(after)
    }

    /// Everything the mitigator has to look at, across every tenant: live
    /// mitigations, with whether each has waited too long for an approver
    /// or reached its duration. Oldest first.
    pub async fn work(
        &self,
        _platform: &PlatformAuthority,
        client: &impl GenericClient,
        limit: u32,
    ) -> Result<Vec<WorkItem>, MitigationStoreError> {
        let window = i64::try_from(self.guard.approval_window().as_secs()).unwrap_or(i64::MAX);
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let rows = client
            .query(&format!("SELECT {COLUMNS}{WORK}"), &[&window, &limit])
            .await?;
        rows.iter()
            .map(|row| {
                Ok(WorkItem {
                    record: from_row(row)?,
                    approval_expired: row.try_get("approval_expired")?,
                    duration_reached: row.try_get("duration_reached")?,
                })
            })
            .collect::<Result<_, PersistError>>()
            .map_err(Into::into)
    }

    /// Incoming attacks on one host, opened within `since`, of one of
    /// `severities`, with no mitigation yet: what the mitigator may
    /// propose an RTBH for (BQ-14). Oldest first.
    pub async fn proposal_candidates(
        &self,
        _platform: &PlatformAuthority,
        client: &impl GenericClient,
        severities: &[String],
        since: Duration,
        limit: u32,
    ) -> Result<Vec<ProposalCandidate>, MitigationStoreError> {
        let since = i64::try_from(since.as_secs()).unwrap_or(i64::MAX);
        let limit = i64::from(limit.clamp(1, MAX_PAGE));
        let rows = client
            .query(CANDIDATES, &[&severities, &since, &limit])
            .await?;
        let mut candidates = Vec::with_capacity(rows.len());
        for row in &rows {
            let address: String = row.try_get("address")?;
            let address: std::net::IpAddr = address
                .parse()
                .map_err(|_| PersistError::corrupt("target_addr", "not an address"))?;
            let length = if address.is_ipv4() { 32 } else { 128 };
            candidates.push(ProposalCandidate {
                tenant: TenantId::new(row.try_get::<_, String>("tenant_id")?),
                incident_id: row.try_get("incident_id")?,
                target: Prefix::new(address, length)
                    .map_err(|e| PersistError::corrupt("target_addr", e.to_string()))?,
                severity: row.try_get("severity")?,
            });
        }
        Ok(candidates)
    }

    /// Audits a refusal that the caller is entitled to see as one, and
    /// passes the error on. Refusals of permission, of self-approval and by
    /// the guard are audited: an attempt on another tenant's prefix is a
    /// security event. A missing mitigation or an illegal transition is not.
    async fn refused(
        &self,
        client: &Client,
        ctx: &AuthorizationContext,
        (resource_type, resource_id): (&str, &str),
        error: MitigationError,
        attempted: Permission,
    ) -> MitigationStoreError {
        let action = match &error {
            MitigationError::Forbidden(permission) => permission.name(),
            MitigationError::SelfApproval | MitigationError::Refused(_) => attempted.name(),
            _ => return error.into(),
        };
        let actor = match actor_columns(ctx.actor(), "actor") {
            Ok(actor) => actor,
            Err(persist) => return persist.into(),
        };
        let written = client
            .execute(
                INSERT_AUDIT,
                &[
                    &ctx.tenant().as_str(),
                    &AUDIT_SCHEMA_VERSION,
                    &actor.actor_type,
                    &actor.actor_id,
                    &action,
                    &resource_id,
                    &"denied",
                    &error.code(),
                    &None::<String>,
                    &None::<String>,
                    &resource_type,
                ],
            )
            .await;
        match written {
            Ok(_) => error.into(),
            Err(database) => database.into(),
        }
    }
}

fn detail_from_row(row: &Row) -> Result<MitigationDetail, PersistError> {
    Ok(MitigationDetail {
        record: from_row(row)?,
        created_at_us: row.try_get("created_at_us")?,
        updated_at_us: row.try_get("updated_at_us")?,
        approved_at_us: row.try_get("approved_at_us")?,
        active_since_us: row.try_get("active_since_us")?,
        expires_at_us: row.try_get("expires_at_us")?,
        ended_at_us: row.try_get("ended_at_us")?,
        route: row.try_get("route_json")?,
    })
}

/// What an incident's `mitigation_status` says for its most relevant
/// mitigation (FU-64).
pub fn mitigation_status(state: MitigationState, dry_run: Option<bool>) -> &'static str {
    match state {
        MitigationState::Proposed | MitigationState::Requested => "pending_approval",
        MitigationState::Approved => "approved",
        MitigationState::Announcing | MitigationState::Active if dry_run == Some(true) => "dry_run",
        MitigationState::Announcing | MitigationState::Active => "active",
        MitigationState::Withdrawing => "withdrawing",
        MitigationState::Withdrawn => "withdrawn",
        MitigationState::Rejected => "rejected",
        MitigationState::Expired => "expired",
        MitigationState::Failed => "failed",
    }
}

async fn read_controls(client: &impl GenericClient) -> Result<KillSwitch, MitigationStoreError> {
    let row = client.query_one(SELECT_CONTROLS, &[]).await?;
    Ok(controls_from(&row)?)
}

async fn read_controls_locked(
    client: &impl GenericClient,
) -> Result<KillSwitch, MitigationStoreError> {
    let row = client
        .query_one(&format!("{SELECT_CONTROLS} FOR UPDATE"), &[])
        .await?;
    Ok(controls_from(&row)?)
}

fn controls_from(row: &Row) -> Result<KillSwitch, PersistError> {
    let changed_by = match row.try_get::<_, Option<String>>("changed_by_type")? {
        Some(actor_type) => Some(actor_from(
            ActorColumns {
                actor_type,
                actor_id: row.try_get("changed_by")?,
            },
            "changed_by",
        )?),
        None => None,
    };
    Ok(KillSwitch {
        engaged: row.try_get("kill_switch")?,
        version: u64::try_from(row.try_get::<_, i64>("version")?)
            .map_err(|_| PersistError::corrupt("version", "negative"))?,
        changed_at: row.try_get("changed_at")?,
        changed_by,
        reason: row.try_get("reason")?,
    })
}

/// The history row, the audit row and the outbox event for one change.
async fn record_change(
    client: &impl GenericClient,
    record: &MitigationRecord,
    transition: &Transition,
) -> Result<(), MitigationStoreError> {
    let actor = actor_columns(&transition.actor, "actor")?;
    let version = version_column(record.version)?;
    let tenant = record.tenant.as_str();
    let from = transition.from.map(MitigationState::as_str);
    let to = transition.to.as_str();
    client
        .execute(
            INSERT_HISTORY,
            &[
                &record.id.as_str(),
                &tenant,
                &version,
                &from,
                &to,
                &actor.actor_type,
                &actor.actor_id,
                &transition.detail,
            ],
        )
        .await?;
    let before = from.map(|state| json!({ "state": state }).to_string());
    let after = json!({ "state": to, "version": record.version }).to_string();
    client
        .execute(
            INSERT_AUDIT,
            &[
                &tenant,
                &AUDIT_SCHEMA_VERSION,
                &actor.actor_type,
                &actor.actor_id,
                &transition.permission.name(),
                &record.id.as_str(),
                &"allowed",
                &transition.detail,
                &before,
                &Some(after),
                &"mitigation",
            ],
        )
        .await?;
    client
        .execute(
            INSERT_OUTBOX,
            &[
                &tenant,
                &record.id.as_str(),
                &version,
                &transition.event_type(),
                &event_payload(record, transition).to_string(),
            ],
        )
        .await?;
    Ok(())
}

/// What the outbox carries: enough to notify, nothing secret. Route
/// attributes are the mitigator's and are not here.
fn event_payload(record: &MitigationRecord, transition: &Transition) -> serde_json::Value {
    json!({
        "mitigation_id": record.id.as_str(),
        "tenant_id": record.tenant.as_str(),
        "incident_id": record.incident_id,
        "prefix": record.prefix.to_string(),
        "action": record.action.kind().as_str(),
        "state": record.state.as_str(),
        "previous_state": transition.from.map(MitigationState::as_str),
        "version": record.version,
        "dry_run": record.dry_run,
        "withdrawal_cause": record.withdrawal.map(WithdrawalCause::as_str),
        "reason": record.reason,
        "detail": transition.detail,
    })
}

async fn load(
    client: &impl GenericClient,
    id: &MitigationId,
    for_update: bool,
) -> Result<Option<MitigationRecord>, MitigationStoreError> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let row = client
        .query_opt(
            &format!(
                "SELECT {COLUMNS} FROM mitigations WHERE mitigation_id = $1::text::uuid{lock}"
            ),
            &[&id.as_str()],
        )
        .await?;
    row.as_ref().map(from_row).transpose().map_err(Into::into)
}

fn from_row(row: &Row) -> Result<MitigationRecord, PersistError> {
    let text = |column: &'static str| -> Result<String, PersistError> {
        Ok(row.try_get::<_, String>(column)?)
    };
    let id = MitigationId::parse(&text("mitigation_id")?)
        .map_err(|_| PersistError::corrupt("mitigation_id", "not a UUID"))?;
    let prefix = text("prefix")?
        .parse()
        .map_err(|error| PersistError::corrupt("prefix", format!("{error}")))?;
    let kind = ActionKind::parse(&text("action")?)
        .ok_or_else(|| PersistError::corrupt("action", "unknown action"))?;
    let flow = row
        .try_get::<_, Option<String>>("flow_match")?
        .map(|json| serde_json::from_str::<FlowMatch>(&json))
        .transpose()
        .map_err(|error| PersistError::corrupt("flow_match", error.to_string()))?;
    let rate = row
        .try_get::<_, Option<i64>>("rate_bytes_per_second")?
        .map(|rate| {
            u64::try_from(rate)
                .map_err(|_| PersistError::corrupt("rate_bytes_per_second", "negative"))
        })
        .transpose()?;
    let action = Action::from_parts(kind, flow, rate)
        .map_err(|error| PersistError::corrupt("action", error.to_string()))?;
    let duration = row.try_get::<_, i32>("duration_seconds")?;
    let duration = u64::try_from(duration)
        .map(Duration::from_secs)
        .map_err(|_| PersistError::corrupt("duration_seconds", "negative"))?;
    let state = MitigationState::parse(&text("state")?)
        .ok_or_else(|| PersistError::corrupt("state", "unknown state"))?;
    let version = u64::try_from(row.try_get::<_, i64>("version")?)
        .map_err(|_| PersistError::corrupt("version", "negative"))?;
    let requested_by = actor_from(
        ActorColumns {
            actor_type: text("requested_by_type")?,
            actor_id: row.try_get("requested_by")?,
        },
        "requested_by",
    )?;
    let approved_by = match row.try_get::<_, Option<String>>("approved_by_type")? {
        Some(actor_type) => Some(actor_from(
            ActorColumns {
                actor_type,
                actor_id: row.try_get("approved_by")?,
            },
            "approved_by",
        )?),
        None => None,
    };
    let withdrawal = row
        .try_get::<_, Option<String>>("withdrawal_cause")?
        .map(|cause| {
            WithdrawalCause::parse(&cause)
                .ok_or_else(|| PersistError::corrupt("withdrawal_cause", "unknown cause"))
        })
        .transpose()?;
    Ok(MitigationRecord {
        id,
        tenant: TenantId::new(text("tenant_id")?),
        incident_id: row.try_get("incident_id")?,
        prefix,
        action,
        reason: text("reason")?,
        duration,
        state,
        version,
        requested_by,
        approved_by,
        dry_run: row.try_get("dry_run")?,
        withdrawal,
        last_error: row.try_get("last_error")?,
    })
}

/// The exact request, as bytes, for the idempotency comparison.
fn fingerprint(operation: &str, request: &MitigationRequest) -> Vec<u8> {
    format!(
        "{operation}\n{}\n{}\n{}\n{}\n{}\n{}",
        request.action.duplicate_key(&request.prefix),
        request
            .action
            .bytes_per_second()
            .map_or(String::new(), |rate| rate.to_string()),
        request.reason.trim(),
        request.duration.as_secs(),
        request
            .incident_id
            .as_deref()
            .unwrap_or_default()
            .to_lowercase(),
        request.prefix,
    )
    .into_bytes()
}

fn duplicate_or(error: tokio_postgres::Error) -> MitigationStoreError {
    let duplicate = error.as_db_error().is_some_and(|db| {
        *db.code() == SqlState::UNIQUE_VIOLATION
            && db.constraint() == Some("mitigations_one_live_per_action")
    });
    if duplicate {
        MitigationError::Duplicate.into()
    } else {
        error.into()
    }
}

fn duration_seconds(duration: Duration) -> Result<i32, PersistError> {
    i32::try_from(duration.as_secs())
        .map_err(|_| PersistError::unrepresentable("duration", "too long"))
}

fn version_column(version: u64) -> Result<i64, PersistError> {
    i64::try_from(version).map_err(|_| PersistError::unrepresentable("version", "too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reason: &str) -> MitigationRequest {
        MitigationRequest {
            prefix: "192.0.2.10/32".parse().unwrap(),
            action: Action::Rtbh,
            reason: reason.into(),
            duration: Duration::from_secs(600),
            incident_id: None,
        }
    }

    #[test]
    fn the_fingerprint_tells_requests_apart_and_ignores_padding() {
        let a = fingerprint("mitigation.request", &request("flood"));
        assert_eq!(a, fingerprint("mitigation.request", &request("  flood ")));
        assert_ne!(a, fingerprint("mitigation.request", &request("other")));
        assert_ne!(a, fingerprint("mitigation.propose", &request("flood")));
        let longer = MitigationRequest {
            duration: Duration::from_secs(601),
            ..request("flood")
        };
        assert_ne!(a, fingerprint("mitigation.request", &longer));
    }

    #[test]
    fn the_payload_carries_no_route_attributes() {
        let ctx = AuthorizationContext::new(
            TenantId::new("acme"),
            Actor::Operator { id: "alice".into() },
            vec![Permission::MitigationRequest],
        );
        let (m, t) = Mitigation::request(
            &ctx,
            MitigationId::parse("01900000-0000-7000-8000-000000000001").unwrap(),
            request("flood"),
        )
        .unwrap();
        let payload = event_payload(m.record(), &t);
        assert_eq!(payload["state"], "requested");
        assert_eq!(payload["previous_state"], serde_json::Value::Null);
        for absent in ["next_hop", "communities", "large_communities"] {
            assert!(payload.get(absent).is_none(), "{absent}");
        }
    }
}
