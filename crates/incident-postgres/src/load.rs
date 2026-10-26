//! The load step of ADR 0034: fetch one call's working set, under the
//! locks the ADR's load table names, into a [`StagingStore`].
//!
//! Every query is filtered by tenant (ADR 0032). Whatever a load does not
//! fetch, the staging store reports as a miss if the call looks it up, and
//! the call is then not flushed.

use tidegard_detector::DetectionEvent;
use tidegard_incident::correlation::{CorrelationKey, TenantId};
use tidegard_incident::id::IncidentId;
use tidegard_incident::idempotency::{IdempotencyKey, RequestFingerprint};
use tokio_postgres::{GenericClient, Row};

use crate::error::PersistError;
use crate::history;
use crate::sql::{self, Locking};
use crate::staging::StagingStore;

const SELECT_DEDUP: &str = "\
SELECT incident_id::text AS incident_id FROM incident_detection_events
WHERE tenant_id = $1 AND dedup_key = $2";

const ENSURE_ALLOCATOR: &str = "\
INSERT INTO incident_number_allocators (tenant_id) VALUES ($1)
ON CONFLICT (tenant_id) DO NOTHING";

const LOCK_ALLOCATOR: &str = "\
SELECT next_value FROM incident_number_allocators WHERE tenant_id = $1 FOR UPDATE";

const SELECT_IDEMPOTENCY: &str = "\
SELECT request_fingerprint, response_status, resource_id, response_body_ref
FROM incident_idempotency
WHERE tenant_id = $1 AND idempotency_key = $2 AND expires_at > transaction_timestamp()";

/// What an ingest load found.
#[derive(Debug)]
pub struct IngestLoad {
    pub store: StagingStore,
    /// The tenant's next incident number, when the allocator row was locked
    /// because the call could create an incident.
    pub next_number: Option<u64>,
}

/// Loads what `ingest_detection_event` can look up for `event`.
///
/// - The dedup link. If it exists the call only reports a duplicate, so
///   nothing else is loaded.
/// - The key's active incident, `FOR UPDATE`. If there is none, the tenant's
///   allocator row is locked (created first if absent) and the active
///   incident is queried again. A concurrent creator for the same key holds
///   that lock until it commits, so the second query sees its incident and
///   this call links to it instead of colliding on the partial unique index.
/// - With still no active incident, the reopen candidate, `FOR UPDATE`.
pub async fn load_for_ingest(
    client: &impl GenericClient,
    tenant: &TenantId,
    event: &DetectionEvent,
) -> Result<IngestLoad, PersistError> {
    let mut store = StagingStore::new();

    let linked = client
        .query_opt(SELECT_DEDUP, &[&tenant.as_str(), &event.dedup_key])
        .await?
        .map(|row| id_column(&row))
        .transpose()?;
    store.load_dedup(tenant.clone(), event.dedup_key.clone(), linked);
    if linked.is_some() {
        return Ok(IngestLoad {
            store,
            next_number: None,
        });
    }

    let key = CorrelationKey::new(
        tenant.clone(),
        event.target.scope_type,
        event.target.scope_id.clone(),
        event.target.direction,
        event.target.address_family,
    );
    let mut next_number = None;
    let mut active = sql::load_active_incident(client, &key).await?;
    if active.is_none() {
        next_number = Some(lock_allocator(client, tenant).await?);
        active = sql::load_active_incident(client, &key).await?;
    }

    match active {
        Some(incident) => {
            store.load_open_index(key, Some(incident.incident_id));
            store.load_incident(incident);
        }
        None => {
            let candidate = sql::load_reopen_candidate(client, &key).await?;
            store.load_open_index(key.clone(), None);
            store.load_reopen_candidate(
                key,
                tenant.clone(),
                candidate.as_ref().map(|incident| incident.incident_id),
            );
            if let Some(incident) = candidate {
                store.load_incident(incident);
            }
        }
    }
    Ok(IngestLoad { store, next_number })
}

/// Loads what a call on one existing incident can look up: the incident
/// `FOR UPDATE` (or the fact that the tenant has none with that id), whether
/// its key has an active incident (an operator reopen checks this), and the
/// command's unexpired idempotency record, if it carries a key.
pub async fn load_for_incident(
    client: &impl GenericClient,
    tenant: &TenantId,
    incident_id: IncidentId,
    idempotency_key: Option<&IdempotencyKey>,
) -> Result<StagingStore, PersistError> {
    let mut store = StagingStore::new();
    match sql::load_incident(client, tenant, &incident_id, Locking::ForUpdate).await? {
        Some(incident) => {
            let key = incident.correlation_key.clone();
            let active = sql::active_incident_id(client, &key).await?;
            store.load_open_index(key, active);
            store.load_incident(incident);
        }
        None => store.load_absent_incident(incident_id),
    }

    if let Some(key) = idempotency_key {
        load_idempotency(client, tenant, key, &mut store).await?;
    }
    Ok(store)
}

/// Loads what opening a manual incident can look up (ADR 0039): the
/// tenant's number allocator, locked; whether the key already has an
/// active incident; and the request's unexpired idempotency record.
pub async fn load_for_create(
    client: &impl GenericClient,
    tenant: &TenantId,
    key: &CorrelationKey,
    idempotency_key: Option<&IdempotencyKey>,
) -> Result<IngestLoad, PersistError> {
    let mut store = StagingStore::new();
    // Locked first, as ingestion does, so two creates for one tenant
    // serialize and the active check below sees the other's commit.
    let next_number = lock_allocator(client, tenant).await?;
    let active = sql::active_incident_id(client, key).await?;
    store.load_open_index(key.clone(), active);
    if let Some(idempotency_key) = idempotency_key {
        load_idempotency(client, tenant, idempotency_key, &mut store).await?;
    }
    Ok(IngestLoad {
        store,
        next_number: Some(next_number),
    })
}

/// Stages the unexpired idempotency record for `key`, if there is one.
async fn load_idempotency(
    client: &impl GenericClient,
    tenant: &TenantId,
    key: &IdempotencyKey,
    store: &mut StagingStore,
) -> Result<(), PersistError> {
    if let Some(row) = client
        .query_opt(SELECT_IDEMPOTENCY, &[&tenant.as_str(), &key.as_str()])
        .await?
    {
        let status: String = row.try_get("response_status")?;
        let resource_id: Option<String> = row.try_get("resource_id")?;
        let body: Option<String> = row.try_get("response_body_ref")?;
        let body = body.ok_or_else(|| {
            PersistError::corrupt("response_body_ref", "an idempotency record has no outcome")
        })?;
        let outcome = history::stored_outcome(&status, resource_id.as_deref(), &body)?;
        store.load_idempotency(
            tenant.clone(),
            key.clone(),
            RequestFingerprint::from_persisted(row.try_get("request_fingerprint")?),
            outcome,
        );
    }
    Ok(())
}

async fn lock_allocator(
    client: &impl GenericClient,
    tenant: &TenantId,
) -> Result<u64, PersistError> {
    client
        .execute(ENSURE_ALLOCATOR, &[&tenant.as_str()])
        .await?;
    let row = client
        .query_one(LOCK_ALLOCATOR, &[&tenant.as_str()])
        .await?;
    let next: i64 = row.try_get("next_value")?;
    u64::try_from(next).map_err(|_| PersistError::corrupt("next_value", "is negative"))
}

fn id_column(row: &Row) -> Result<IncidentId, PersistError> {
    let id: String = row.try_get("incident_id")?;
    IncidentId::parse(&id).map_err(|e| PersistError::corrupt("incident_id", e.to_string()))
}
