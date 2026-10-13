//! Insert, version-guarded update, and load of one incident with its
//! notes, tags and policy references.
//!
//! Every function takes any [`GenericClient`], so the caller runs them
//! inside the one transaction ADR 0034 wraps each unit-of-work call in.
//! Nothing here opens, commits or retries a transaction.
//!
//! Binding notes:
//!
//! - `uuid`, `inet`, `cidr` and `jsonb` values are bound as text and cast
//!   in SQL (`$1::text::uuid`). A bare `$1::uuid` makes PostgreSQL infer
//!   the parameter as `uuid`, which a Rust string cannot be bound to, and
//!   this crate does not enable `postgres-types`' uuid/json features.
//! - The network target goes through `network(...)`; see [`crate::row`].
//! - The typed target columns are written, never read back: the load
//!   rebuilds scope from `correlation_key`.
//! - Lookups by correlation key compare `correlation_key` text. It is
//!   always written by [`crate::row`] from the same serializer, so equal
//!   keys give equal text.
//! - Notes are append-only in the domain, so an update inserts only notes
//!   whose index is not stored yet. Tags and policy references are
//!   rewritten in full.

use std::time::SystemTime;

use tidegard_incident::correlation::{CorrelationKey, TenantId};
use tidegard_incident::durable_time::DurableTimestamp;
use tidegard_incident::id::IncidentId;
use tidegard_incident::incident::Incident;
use tokio_postgres::types::ToSql;
use tokio_postgres::{GenericClient, Row};

use crate::error::PersistError;
use crate::row::{
    ActorColumns, IncidentRow, NoteRedactionColumns, NoteRow, PolicyRefRow, SuppressionColumns,
};

/// Whether a load takes the row lock ADR 0034's load step needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locking {
    NoLock,
    ForUpdate,
}

const INSERT_INCIDENT: &str = "\
INSERT INTO incidents (
    incident_id, incident_number, schema_version, tenant_id, correlation_key,
    address_family, direction, target_type, target_addr, target_network,
    target_hostgroup, created_by_type, created_by_id, title, description,
    state, severity, severity_source, ever_critical, maximum_detected_severity,
    priority, closure_reason, state_before_recovering, suppressed_until,
    suppression_reason, suppressed_by_type, suppressed_by_id, version, category,
    matched_metrics, first_detected_at, opened_at, last_detected_at,
    last_updated_at, acknowledged_at, recovering_since, resolved_at, closed_at,
    reopened_at, reopen_count, assigned_kind, assigned_id, updated_by_type,
    updated_by_id, evidence_summary, policy_refs_omitted
) VALUES (
    $1::text::uuid, $2, $3, $4, $5,
    $6, $7, $8, $9::text::inet, network($10::text::inet),
    $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20,
    $21, $22, $23, $24,
    $25, $26, $27, $28, $29,
    $30::text::jsonb, $31, $32, $33,
    $34, $35, $36, $37, $38,
    $39, $40, $41, $42, $43,
    $44, $45::text::jsonb, $46
)";

/// Same parameter numbering as [`INSERT_INCIDENT`], plus `$47`, the
/// version the call loaded.
const UPDATE_INCIDENT: &str = "\
UPDATE incidents SET
    incident_number = $2,
    schema_version = $3,
    correlation_key = $5,
    address_family = $6,
    direction = $7,
    target_type = $8,
    target_addr = $9::text::inet,
    target_network = network($10::text::inet),
    target_hostgroup = $11,
    created_by_type = $12,
    created_by_id = $13,
    title = $14,
    description = $15,
    state = $16,
    severity = $17,
    severity_source = $18,
    ever_critical = $19,
    maximum_detected_severity = $20,
    priority = $21,
    closure_reason = $22,
    state_before_recovering = $23,
    suppressed_until = $24,
    suppression_reason = $25,
    suppressed_by_type = $26,
    suppressed_by_id = $27,
    version = $28,
    category = $29,
    matched_metrics = $30::text::jsonb,
    first_detected_at = $31,
    opened_at = $32,
    last_detected_at = $33,
    last_updated_at = $34,
    acknowledged_at = $35,
    recovering_since = $36,
    resolved_at = $37,
    closed_at = $38,
    reopened_at = $39,
    reopen_count = $40,
    assigned_kind = $41,
    assigned_id = $42,
    updated_by_type = $43,
    updated_by_id = $44,
    evidence_summary = $45::text::jsonb,
    policy_refs_omitted = $46
WHERE incident_id = $1::text::uuid AND tenant_id = $4 AND version = $47";

/// Every column the load reads, without a `WHERE` clause.
const SELECT_COLUMNS: &str = "\
SELECT incident_id::text AS incident_id, incident_number, schema_version, tenant_id,
    correlation_key, address_family, direction, target_type, created_by_type,
    created_by_id, title, description, state, severity, severity_source,
    ever_critical, maximum_detected_severity, priority, closure_reason,
    state_before_recovering, suppressed_until, suppression_reason,
    suppressed_by_type, suppressed_by_id, version, category,
    matched_metrics::text AS matched_metrics, first_detected_at, opened_at,
    last_detected_at, last_updated_at, acknowledged_at, recovering_since,
    resolved_at, closed_at, reopened_at, reopen_count, assigned_kind, assigned_id,
    updated_by_type, updated_by_id, evidence_summary::text AS evidence_summary,
    policy_refs_omitted
FROM incidents";

/// The states the V10 partial unique indexes cover, and the ones the
/// domain's open index holds: everything before `Resolved`.
const ACTIVE: &str = "state NOT IN ('resolved', 'closed')";

/// `$8` is the `note_index` an edit replaces, resolved to that row's
/// `note_id`. Notes are written in index order, so it already exists.
const INSERT_NOTE_IF_ABSENT: &str = "\
INSERT INTO incident_notes (
    incident_id, tenant_id, note_index, body, visibility, created_by_type, created_by_id,
    supersedes_note_id
)
SELECT $1::text::uuid, $2::text, $3::integer, $4::text, $5::text, $6::text, $7::text, (
    SELECT note_id FROM incident_notes
    WHERE incident_id = $1::text::uuid AND note_index = $8::integer
)
WHERE NOT EXISTS (
    SELECT 1 FROM incident_notes
    WHERE incident_id = $1::text::uuid AND note_index = $3::integer
)";

/// Stamps a replaced note once. The `IS NULL` guard keeps the first
/// time and actor when the incident is saved again.
const MARK_NOTE_SUPERSEDED: &str = "\
UPDATE incident_notes
SET superseded_at = transaction_timestamp(), superseded_by_type = $4, superseded_by_id = $5
WHERE tenant_id = $2 AND incident_id = $1::text::uuid AND note_index = $3::integer
    AND superseded_at IS NULL";

/// The one in-place change to a note: the body goes, the record stays.
const REDACT_NOTE: &str = "\
UPDATE incident_notes
SET body = '', redacted_at = transaction_timestamp(), redacted_by_type = $4,
    redacted_by_id = $5, redaction_reason = $6
WHERE tenant_id = $2 AND incident_id = $1::text::uuid AND note_index = $3::integer
    AND redacted_at IS NULL";

/// `earlier` must be on the same incident: the foreign key only holds
/// the tenant, so a row pointing elsewhere is read as corrupt.
const SELECT_NOTES: &str = "\
SELECT n.note_index, n.body, n.visibility, n.created_by_type, n.created_by_id,
    n.supersedes_note_id IS NOT NULL AS has_supersedes,
    earlier.note_index AS supersedes_index,
    n.redacted_at IS NOT NULL AS redacted, n.redacted_by_type, n.redacted_by_id,
    n.redaction_reason
FROM incident_notes n
LEFT JOIN incident_notes earlier
    ON earlier.tenant_id = n.tenant_id
    AND earlier.note_id = n.supersedes_note_id
    AND earlier.incident_id = n.incident_id
WHERE n.tenant_id = $1 AND n.incident_id = $2::text::uuid
ORDER BY n.note_index";

const DELETE_TAGS: &str =
    "DELETE FROM incident_tags WHERE tenant_id = $1 AND incident_id = $2::text::uuid";

const INSERT_TAG: &str = "\
INSERT INTO incident_tags (incident_id, tenant_id, tag_key, tag_value)
VALUES ($1::text::uuid, $2, $3, $4)";

const SELECT_TAGS: &str = "\
SELECT tag_key, tag_value FROM incident_tags
WHERE tenant_id = $1 AND incident_id = $2::text::uuid
ORDER BY tag_key";

const DELETE_POLICY_REFS: &str =
    "DELETE FROM incident_policy_references WHERE tenant_id = $1 AND incident_id = $2::text::uuid";

const INSERT_POLICY_REF: &str = "\
INSERT INTO incident_policy_references (
    incident_id, tenant_id, ref_index, policy_id, policy_version,
    first_seen_sequence, last_seen_sequence
) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)";

const SELECT_POLICY_REFS: &str = "\
SELECT ref_index, policy_id, policy_version, first_seen_sequence, last_seen_sequence
FROM incident_policy_references
WHERE tenant_id = $1 AND incident_id = $2::text::uuid
ORDER BY ref_index";

/// Inserts a new incident and its child rows.
pub async fn insert_incident(
    client: &impl GenericClient,
    incident: &Incident,
) -> Result<(), PersistError> {
    let row = IncidentRow::from_incident(incident)?;
    let bound = Bound::new(&row)?;
    client.execute(INSERT_INCIDENT, &bound.params()).await?;
    write_children(client, &row).await
}

/// Rewrites a loaded incident, only if it is still at `loaded_version`.
///
/// Zero matched rows means another transaction changed it first, and
/// returns [`PersistError::VersionConflict`] before any child row is
/// touched.
pub async fn update_incident(
    client: &impl GenericClient,
    incident: &Incident,
    loaded_version: u64,
) -> Result<(), PersistError> {
    let row = IncidentRow::from_incident(incident)?;
    let bound = Bound::new(&row)?;
    let loaded = i64::try_from(loaded_version)
        .map_err(|_| PersistError::unrepresentable("loaded_version", "exceeds BIGINT"))?;
    let mut params = bound.params().to_vec();
    params.push(&loaded);
    if client.execute(UPDATE_INCIDENT, &params).await? == 0 {
        return Err(PersistError::VersionConflict {
            incident_id: incident.incident_id,
            loaded_version,
        });
    }
    write_children(client, &row).await
}

/// Loads one tenant's incident and reconstitutes it. `None` if the tenant
/// has no incident with that id.
pub async fn load_incident(
    client: &impl GenericClient,
    tenant: &TenantId,
    incident_id: &IncidentId,
    locking: Locking,
) -> Result<Option<Incident>, PersistError> {
    let lock = match locking {
        Locking::NoLock => "",
        Locking::ForUpdate => " FOR UPDATE",
    };
    let statement =
        format!("{SELECT_COLUMNS} WHERE tenant_id = $1 AND incident_id = $2::text::uuid{lock}");
    let id = incident_id.to_canonical_string();
    match client
        .query_opt(statement.as_str(), &[&tenant.as_str(), &id])
        .await?
    {
        Some(row) => incident_from_row(client, row).await.map(Some),
        None => Ok(None),
    }
}

/// The key's active incident, locked `FOR UPDATE`. At most one can exist:
/// the V10 partial unique indexes enforce it.
pub async fn load_active_incident(
    client: &impl GenericClient,
    key: &CorrelationKey,
) -> Result<Option<Incident>, PersistError> {
    let (tenant, key_text) = key_params(key)?;
    let statement = format!(
        "{SELECT_COLUMNS} WHERE tenant_id = $1 AND correlation_key = $2 AND {ACTIVE} FOR UPDATE"
    );
    match client
        .query_opt(statement.as_str(), &[&tenant, &key_text])
        .await?
    {
        Some(row) => incident_from_row(client, row).await.map(Some),
        None => Ok(None),
    }
}

/// The id of the key's active incident, without locking it. Used where
/// the domain only asks whether one exists; claiming the key is still
/// guarded by the partial unique index at flush.
pub async fn active_incident_id(
    client: &impl GenericClient,
    key: &CorrelationKey,
) -> Result<Option<IncidentId>, PersistError> {
    let (tenant, key_text) = key_params(key)?;
    let statement = format!(
        "SELECT incident_id::text AS incident_id FROM incidents \
         WHERE tenant_id = $1 AND correlation_key = $2 AND {ACTIVE}"
    );
    client
        .query_opt(statement.as_str(), &[&tenant, &key_text])
        .await?
        .map(|row| {
            let id: String = row.try_get("incident_id")?;
            IncidentId::parse(&id).map_err(|e| PersistError::corrupt("incident_id", e.to_string()))
        })
        .transpose()
}

/// The row `InMemoryIncidentStore::reopen_candidate` would pick: among the
/// key's resolved or closed incidents, the one resolved or closed most
/// recently. Locked `FOR UPDATE`.
pub async fn load_reopen_candidate(
    client: &impl GenericClient,
    key: &CorrelationKey,
) -> Result<Option<Incident>, PersistError> {
    let (tenant, key_text) = key_params(key)?;
    let statement = format!(
        "{SELECT_COLUMNS} WHERE tenant_id = $1 AND correlation_key = $2 \
         AND state IN ('resolved', 'closed') \
         ORDER BY CASE WHEN state = 'resolved' THEN resolved_at ELSE closed_at END DESC NULLS LAST, \
         incident_id LIMIT 1 FOR UPDATE"
    );
    match client
        .query_opt(statement.as_str(), &[&tenant, &key_text])
        .await?
    {
        Some(row) => incident_from_row(client, row).await.map(Some),
        None => Ok(None),
    }
}

fn key_params(key: &CorrelationKey) -> Result<(&str, String), PersistError> {
    let text = serde_json::to_string(key)
        .map_err(|e| PersistError::unrepresentable("correlation_key", e.to_string()))?;
    Ok((key.tenant.as_str(), text))
}

/// Reads the child rows for an `incidents` row and reconstitutes it.
async fn incident_from_row(client: &impl GenericClient, r: Row) -> Result<Incident, PersistError> {
    let tenant: String = r.try_get("tenant_id")?;
    let id: String = r.try_get("incident_id")?;
    let (tenant, id) = (tenant.as_str(), id.as_str());

    let notes = client
        .query(SELECT_NOTES, &[&tenant, &id])
        .await?
        .iter()
        .map(|n| {
            let supersedes: Option<i32> = n.try_get("supersedes_index")?;
            if n.try_get::<_, bool>("has_supersedes")? != supersedes.is_some() {
                return Err(PersistError::corrupt(
                    "supersedes_note_id",
                    "names a note on another incident",
                ));
            }
            Ok(NoteRow {
                note_index: n.try_get("note_index")?,
                body: n.try_get("body")?,
                visibility: n.try_get("visibility")?,
                created_by: actor(n, "created_by_type", "created_by_id")?,
                supersedes,
                redaction: NoteRedactionColumns::from_nullable(
                    n.try_get("redacted")?,
                    n.try_get("redacted_by_type")?,
                    n.try_get("redacted_by_id")?,
                    n.try_get("redaction_reason")?,
                )?,
            })
        })
        .collect::<Result<Vec<_>, PersistError>>()?;
    let tags = client
        .query(SELECT_TAGS, &[&tenant, &id])
        .await?
        .iter()
        .map(|t| Ok((t.try_get("tag_key")?, t.try_get("tag_value")?)))
        .collect::<Result<Vec<_>, PersistError>>()?;
    let policy_refs = client
        .query(SELECT_POLICY_REFS, &[&tenant, &id])
        .await?
        .iter()
        .map(|p| {
            Ok(PolicyRefRow {
                ref_index: p.try_get("ref_index")?,
                policy_id: p.try_get("policy_id")?,
                policy_version: p.try_get("policy_version")?,
                first_seen_sequence: p.try_get("first_seen_sequence")?,
                last_seen_sequence: p.try_get("last_seen_sequence")?,
            })
        })
        .collect::<Result<Vec<_>, PersistError>>()?;

    let row = IncidentRow {
        incident_id: id.to_string(),
        incident_number: r.try_get("incident_number")?,
        schema_version: r.try_get("schema_version")?,
        tenant_id: tenant.to_string(),
        correlation_key: r.try_get("correlation_key")?,
        address_family: r.try_get("address_family")?,
        direction: r.try_get("direction")?,
        target_type: r.try_get("target_type")?,
        target_addr: None,
        target_network: None,
        target_hostgroup: None,
        created_by: actor(&r, "created_by_type", "created_by_id")?,
        title: r.try_get("title")?,
        description: r.try_get("description")?,
        state: r.try_get("state")?,
        severity: r.try_get("severity")?,
        severity_source: r.try_get("severity_source")?,
        ever_critical: r.try_get("ever_critical")?,
        maximum_detected_severity: r.try_get("maximum_detected_severity")?,
        priority: r.try_get("priority")?,
        closure_reason: r.try_get("closure_reason")?,
        state_before_recovering: r.try_get("state_before_recovering")?,
        suppression: SuppressionColumns::from_nullable(
            optional_micros(&r, "suppressed_until")?,
            r.try_get("suppression_reason")?,
            r.try_get("suppressed_by_type")?,
            r.try_get("suppressed_by_id")?,
        )?,
        version: r.try_get("version")?,
        category: r.try_get("category")?,
        matched_metrics: r.try_get("matched_metrics")?,
        first_detected_at: required_micros(&r, "first_detected_at")?,
        opened_at: required_micros(&r, "opened_at")?,
        last_detected_at: required_micros(&r, "last_detected_at")?,
        last_updated_at: required_micros(&r, "last_updated_at")?,
        acknowledged_at: optional_micros(&r, "acknowledged_at")?,
        recovering_since: optional_micros(&r, "recovering_since")?,
        resolved_at: optional_micros(&r, "resolved_at")?,
        closed_at: optional_micros(&r, "closed_at")?,
        reopened_at: optional_micros(&r, "reopened_at")?,
        reopen_count: r.try_get("reopen_count")?,
        assigned_kind: r.try_get("assigned_kind")?,
        assigned_id: r.try_get("assigned_id")?,
        updated_by: actor(&r, "updated_by_type", "updated_by_id")?,
        evidence_summary: r.try_get("evidence_summary")?,
        notes,
        tags,
        policy_refs,
        policy_refs_omitted: r.try_get("policy_refs_omitted")?,
    };
    row.into_incident()
}

async fn write_children(
    client: &impl GenericClient,
    row: &IncidentRow,
) -> Result<(), PersistError> {
    let (id, tenant) = (&row.incident_id, &row.tenant_id);
    for note in &row.notes {
        client
            .execute(
                INSERT_NOTE_IF_ABSENT,
                &[
                    id,
                    tenant,
                    &note.note_index,
                    &note.body,
                    &note.visibility,
                    &note.created_by.actor_type,
                    &note.created_by.actor_id,
                    &note.supersedes,
                ],
            )
            .await?;
        if let Some(earlier) = note.supersedes {
            client
                .execute(
                    MARK_NOTE_SUPERSEDED,
                    &[
                        id,
                        tenant,
                        &earlier,
                        &note.created_by.actor_type,
                        &note.created_by.actor_id,
                    ],
                )
                .await?;
        }
        if let Some(redaction) = &note.redaction {
            client
                .execute(
                    REDACT_NOTE,
                    &[
                        id,
                        tenant,
                        &note.note_index,
                        &redaction.by.actor_type,
                        &redaction.by.actor_id,
                        &redaction.reason,
                    ],
                )
                .await?;
        }
    }
    client.execute(DELETE_TAGS, &[tenant, id]).await?;
    for (key, value) in &row.tags {
        client
            .execute(INSERT_TAG, &[id, tenant, key, value])
            .await?;
    }
    client.execute(DELETE_POLICY_REFS, &[tenant, id]).await?;
    for reference in &row.policy_refs {
        client
            .execute(
                INSERT_POLICY_REF,
                &[
                    id,
                    tenant,
                    &reference.ref_index,
                    &reference.policy_id,
                    &reference.policy_version,
                    &reference.first_seen_sequence,
                    &reference.last_seen_sequence,
                ],
            )
            .await?;
    }
    Ok(())
}

/// The owned values an incident statement binds beside the row's own.
struct Bound<'a> {
    row: &'a IncidentRow,
    first_detected_at: SystemTime,
    opened_at: SystemTime,
    last_detected_at: SystemTime,
    last_updated_at: SystemTime,
    acknowledged_at: Option<SystemTime>,
    recovering_since: Option<SystemTime>,
    resolved_at: Option<SystemTime>,
    closed_at: Option<SystemTime>,
    reopened_at: Option<SystemTime>,
    suppressed_until: Option<SystemTime>,
    suppression_reason: Option<&'a str>,
    suppressed_by_type: Option<&'a str>,
    suppressed_by_id: Option<&'a str>,
}

impl<'a> Bound<'a> {
    fn new(row: &'a IncidentRow) -> Result<Self, PersistError> {
        let suppression = row.suppression.as_ref();
        Ok(Bound {
            row,
            first_detected_at: system_time(row.first_detected_at, "first_detected_at")?,
            opened_at: system_time(row.opened_at, "opened_at")?,
            last_detected_at: system_time(row.last_detected_at, "last_detected_at")?,
            last_updated_at: system_time(row.last_updated_at, "last_updated_at")?,
            acknowledged_at: optional_system_time(row.acknowledged_at, "acknowledged_at")?,
            recovering_since: optional_system_time(row.recovering_since, "recovering_since")?,
            resolved_at: optional_system_time(row.resolved_at, "resolved_at")?,
            closed_at: optional_system_time(row.closed_at, "closed_at")?,
            reopened_at: optional_system_time(row.reopened_at, "reopened_at")?,
            suppressed_until: optional_system_time(
                suppression.map(|s| s.until),
                "suppressed_until",
            )?,
            suppression_reason: suppression.map(|s| s.reason.as_str()),
            suppressed_by_type: suppression.map(|s| s.by.actor_type.as_str()),
            suppressed_by_id: suppression.and_then(|s| s.by.actor_id.as_deref()),
        })
    }

    /// `$1` to `$46`, in the column order of [`INSERT_INCIDENT`].
    fn params(&self) -> [&(dyn ToSql + Sync); 46] {
        let r = self.row;
        [
            &r.incident_id,
            &r.incident_number,
            &r.schema_version,
            &r.tenant_id,
            &r.correlation_key,
            &r.address_family,
            &r.direction,
            &r.target_type,
            &r.target_addr,
            &r.target_network,
            &r.target_hostgroup,
            &r.created_by.actor_type,
            &r.created_by.actor_id,
            &r.title,
            &r.description,
            &r.state,
            &r.severity,
            &r.severity_source,
            &r.ever_critical,
            &r.maximum_detected_severity,
            &r.priority,
            &r.closure_reason,
            &r.state_before_recovering,
            &self.suppressed_until,
            &self.suppression_reason,
            &self.suppressed_by_type,
            &self.suppressed_by_id,
            &r.version,
            &r.category,
            &r.matched_metrics,
            &self.first_detected_at,
            &self.opened_at,
            &self.last_detected_at,
            &self.last_updated_at,
            &self.acknowledged_at,
            &self.recovering_since,
            &self.resolved_at,
            &self.closed_at,
            &self.reopened_at,
            &r.reopen_count,
            &r.assigned_kind,
            &r.assigned_id,
            &r.updated_by.actor_type,
            &r.updated_by.actor_id,
            &r.evidence_summary,
            &r.policy_refs_omitted,
        ]
    }
}

fn actor(row: &Row, type_column: &str, id_column: &str) -> Result<ActorColumns, PersistError> {
    Ok(ActorColumns {
        actor_type: row.try_get(type_column)?,
        actor_id: row.try_get(id_column)?,
    })
}

fn system_time(micros: i64, field: &'static str) -> Result<SystemTime, PersistError> {
    DurableTimestamp::from_micros(micros)
        .to_system_time()
        .ok_or_else(|| PersistError::unrepresentable(field, "outside this platform's SystemTime"))
}

fn optional_system_time(
    micros: Option<i64>,
    field: &'static str,
) -> Result<Option<SystemTime>, PersistError> {
    micros.map(|m| system_time(m, field)).transpose()
}

fn micros_of(value: SystemTime, column: &'static str) -> Result<i64, PersistError> {
    DurableTimestamp::from_system_time(value)
        .map(|t| t.as_micros())
        .map_err(|e| PersistError::corrupt(column, e.to_string()))
}

pub(crate) fn required_micros(row: &Row, column: &'static str) -> Result<i64, PersistError> {
    micros_of(row.try_get(column)?, column)
}

fn optional_micros(row: &Row, column: &'static str) -> Result<Option<i64>, PersistError> {
    let value: Option<SystemTime> = row.try_get(column)?;
    value.map(|v| micros_of(v, column)).transpose()
}
