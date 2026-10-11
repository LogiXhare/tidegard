//! The flush step of ADR 0034: write one call's [`ChangeSet`] inside the
//! caller's transaction. Nothing here commits.
//!
//! Incidents are written first because every other row references one.
//! Idempotency records are kept for 24 hours, the retention
//! `docs/architecture/incident-persistence.md` sets; an expired record for
//! the same key is overwritten. After each group of writes the flush passes
//! a [`FlushPoint`], where a test can inject a failure ([`crate::fault`]).

use std::collections::HashMap;

use tokio_postgres::GenericClient;
use wetechinetmon_detector::DetectionEvent;
use wetechinetmon_incident::correlation::TenantId;
use wetechinetmon_incident::id::IncidentId;
use wetechinetmon_incident::incident::Incident;

use crate::error::PersistError;
use crate::fault::{self, FlushPoint};
use crate::history::{self, IDEMPOTENCY_OPERATION};
use crate::sql;
use crate::staging::ChangeSet;

const INSERT_DETECTION_LINK: &str = "\
INSERT INTO incident_detection_events (
    incident_id, detection_event_id, tenant_id, dedup_key, detection_id, policy_id,
    policy_version, kind, severity, observed_at, detected_at, matched, rates, link_type
) VALUES (
    $1::text::uuid, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11, $12::text::jsonb, $13::text::jsonb, $14
)";

const INSERT_TIMELINE: &str = "\
INSERT INTO incident_timeline (
    incident_id, tenant_id, schema_version, entry_type, actor_type, actor_id, payload
) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7::text::jsonb)";

const INSERT_AUDIT: &str = "\
INSERT INTO incident_audit (
    tenant_id, schema_version, actor_type, actor_id, action,
    resource_type, resource_id, result, reason, before, after
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::jsonb, $11::text::jsonb)";

const INSERT_OUTBOX: &str = "\
INSERT INTO incident_outbox (
    tenant_id, aggregate_type, aggregate_id, aggregate_version, event_type, payload
) VALUES ($1, 'incident', $2, $3, $4, $5::text::jsonb)";

const UPSERT_IDEMPOTENCY: &str = "\
INSERT INTO incident_idempotency (
    tenant_id, idempotency_key, operation, resource_type, resource_id,
    request_fingerprint, response_status, response_body_ref, expires_at
) VALUES (
    $1, $2, $3, 'incident', $4, $5, $6, $7, transaction_timestamp() + interval '24 hours'
)
ON CONFLICT (tenant_id, idempotency_key) DO UPDATE SET
    operation = EXCLUDED.operation,
    resource_type = EXCLUDED.resource_type,
    resource_id = EXCLUDED.resource_id,
    request_fingerprint = EXCLUDED.request_fingerprint,
    response_status = EXCLUDED.response_status,
    response_body_ref = EXCLUDED.response_body_ref,
    created_at = transaction_timestamp(),
    expires_at = EXCLUDED.expires_at
WHERE incident_idempotency.expires_at <= transaction_timestamp()";

const UPDATE_ALLOCATOR: &str =
    "UPDATE incident_number_allocators SET next_value = $2 WHERE tenant_id = $1";

/// Writes `changes` for one call by `tenant`.
///
/// `event` is the detection event an ingest call ran on; dedup links need
/// its fields. `next_number` is the allocator's new `next_value`, only when
/// the call consumed a number.
pub async fn flush(
    client: &impl GenericClient,
    tenant: &TenantId,
    changes: &ChangeSet,
    event: Option<&DetectionEvent>,
    next_number: Option<u64>,
) -> Result<(), PersistError> {
    for incident in &changes.inserted {
        sql::insert_incident(client, incident).await?;
    }
    for updated in &changes.updated {
        sql::update_incident(client, &updated.incident, updated.loaded_version).await?;
    }
    fault::check(FlushPoint::Incidents)?;

    let incidents: HashMap<IncidentId, &Incident> = changes
        .inserted
        .iter()
        .chain(changes.updated.iter().map(|updated| &updated.incident))
        .map(|incident| (incident.incident_id, incident))
        .collect();

    for ((_, dedup_key), incident_id) in &changes.dedup_records {
        let event = event
            .filter(|event| &event.dedup_key == dedup_key)
            .ok_or_else(|| {
                PersistError::unrepresentable(
                    "dedup_records",
                    "a dedup link without the detection event it records",
                )
            })?;
        let row = history::detection_link_row(
            tenant,
            *incident_id,
            event,
            incidents.get(incident_id).copied(),
        )?;
        client
            .execute(
                INSERT_DETECTION_LINK,
                &[
                    &row.incident_id,
                    &row.detection_event_id,
                    &row.tenant_id,
                    &row.dedup_key,
                    &row.detection_id,
                    &row.policy_id,
                    &row.policy_version,
                    &row.kind,
                    &row.severity,
                    &row.observed_at,
                    &row.detected_at,
                    &row.matched,
                    &row.rates,
                    &row.link_type,
                ],
            )
            .await?;
    }
    fault::check(FlushPoint::DetectionLinks)?;

    for entry in &changes.timeline {
        let row = history::timeline_row(tenant, entry)?;
        client
            .execute(
                INSERT_TIMELINE,
                &[
                    &row.incident_id,
                    &row.tenant_id,
                    &row.schema_version,
                    &row.entry_type,
                    &row.actor.actor_type,
                    &row.actor.actor_id,
                    &row.payload,
                ],
            )
            .await?;
    }
    fault::check(FlushPoint::Timeline)?;

    for entry in &changes.audit {
        let row = history::audit_row(entry)?;
        client
            .execute(
                INSERT_AUDIT,
                &[
                    &row.tenant_id,
                    &row.schema_version,
                    &row.actor.actor_type,
                    &row.actor.actor_id,
                    &row.action,
                    &row.resource_type,
                    &row.resource_id,
                    &row.result,
                    &row.reason,
                    &row.before,
                    &row.after,
                ],
            )
            .await?;
    }
    fault::check(FlushPoint::Audit)?;

    for message in &changes.outbox {
        let version = incidents
            .get(&message.incident_id)
            .map(|incident| incident.version)
            .ok_or_else(|| {
                PersistError::unrepresentable(
                    "outbox",
                    "a message for an incident the call did not change",
                )
            })?;
        let row = history::outbox_row(message, version)?;
        client
            .execute(
                INSERT_OUTBOX,
                &[
                    &row.tenant_id,
                    &row.aggregate_id,
                    &row.aggregate_version,
                    &row.event_type,
                    &row.payload,
                ],
            )
            .await?;
    }
    fault::check(FlushPoint::Outbox)?;

    for record in &changes.idempotency {
        let row = history::idempotency_row(record)?;
        let written = client
            .execute(
                UPSERT_IDEMPOTENCY,
                &[
                    &row.tenant_id,
                    &row.idempotency_key,
                    &IDEMPOTENCY_OPERATION,
                    &row.resource_id,
                    &row.request_fingerprint,
                    &row.response_status,
                    &row.response_body,
                ],
            )
            .await?;
        if written == 0 {
            return Err(PersistError::IdempotencyKeyTaken);
        }
    }
    fault::check(FlushPoint::Idempotency)?;

    if let Some(next) = next_number {
        let next = i64::try_from(next)
            .map_err(|_| PersistError::unrepresentable("next_value", "exceeds BIGINT"))?;
        client
            .execute(UPDATE_ALLOCATOR, &[&tenant.as_str(), &next])
            .await?;
    }
    fault::check(FlushPoint::Allocator)?;
    Ok(())
}
