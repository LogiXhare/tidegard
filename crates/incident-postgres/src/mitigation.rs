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
//!   proposed, when it is approved, and when announcing begins. Its
//!   refusals are audited as `denied`, like a missing permission.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, GenericClient, Row};
use wetechinetmon_incident::authorization::{Actor, AuthorizationContext, Permission};
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::id::IncidentGenerator;
use wetechinetmon_mitigation::{
    Action, ActionKind, ApprovalPolicy, FlowMatch, Guard, Mitigation, MitigationError,
    MitigationId, MitigationRecord, MitigationRequest, MitigationState, Transition,
    WithdrawalCause,
};

use crate::error::PersistError;
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
        THEN transaction_timestamp() ELSE ended_at END
WHERE mitigation_id = $1::text::uuid AND version = $2";

const INSERT_HISTORY: &str = "\
INSERT INTO mitigation_history (
    mitigation_id, tenant_id, version, from_state, to_state, actor_type, actor_id, detail
) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8)";

const INSERT_AUDIT: &str = "\
INSERT INTO incident_audit (
    tenant_id, schema_version, actor_type, actor_id, action,
    resource_type, resource_id, result, reason, before, after
) VALUES ($1, $2, $3, $4, $5, 'mitigation', $6, $7, $8, $9::text::jsonb, $10::text::jsonb)";

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

    /// The guard's verdict on a mitigation as it stands.
    fn guarded(&self, record: &MitigationRecord) -> Result<(), MitigationError> {
        self.guard
            .check(
                &record.tenant,
                &record.prefix,
                &record.action,
                record.duration,
                false,
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
            Err(error) => return Err(self.refused(client, ctx, &id, error, attempted).await),
        };
        if let Err(error) = self.guarded(mitigation.record()) {
            return Err(self.refused(client, ctx, &id, error, attempted).await);
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
    pub async fn begin_announcing(
        &self,
        client: &mut Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
        dry_run: bool,
    ) -> Result<MitigationRecord, MitigationStoreError> {
        self.change(
            client,
            ctx,
            id,
            None,
            Permission::MitigationExecute,
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
        let mut mitigation = Mitigation::from_record(record);
        let checked = command(&mut mitigation, ctx).and_then(|transition| {
            // Approval and announcing are the last moments a mitigation can
            // be stopped before a route exists: the guard decides again,
            // under the configuration in force now.
            if matches!(
                transition.to,
                MitigationState::Approved | MitigationState::Announcing
            ) {
                self.guarded(mitigation.record())?;
            }
            Ok(transition)
        });
        let transition = match checked {
            Ok(transition) => transition,
            Err(error) => {
                tx.rollback().await?;
                return Err(self.refused(client, ctx, id, error, attempted).await);
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

    /// Audits a refusal that the caller is entitled to see as one, and
    /// passes the error on. Refusals of permission, of self-approval and by
    /// the guard are audited: an attempt on another tenant's prefix is a
    /// security event. A missing mitigation or an illegal transition is not.
    async fn refused(
        &self,
        client: &Client,
        ctx: &AuthorizationContext,
        id: &MitigationId,
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
                    &id.as_str(),
                    &"denied",
                    &error.code(),
                    &None::<String>,
                    &None::<String>,
                ],
            )
            .await;
        match written {
            Ok(_) => error.into(),
            Err(database) => database.into(),
        }
    }
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
