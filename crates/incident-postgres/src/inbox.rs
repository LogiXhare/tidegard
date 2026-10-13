//! The detection-event inbox (ADR 0035): the detector's producer enqueues
//! events, and the correlation worker claims them under a lease, ingests
//! each one, and records the outcome.
//!
//! - **Enqueue is idempotent.** A row is unique on `(tenant_id, dedup_key)`,
//!   so a batch sent twice adds nothing the second time.
//! - **Processing is effectively once.** A worker that ingests an event and
//!   crashes before [`InboxWorker::mark_processed`] leaves the row to be
//!   reclaimed when its lease expires; the second ingest is a `Duplicate`.
//! - **A poison event is never guessed at.** A payload that does not
//!   deserialize is dead-lettered at once. An event that deserializes with a
//!   newer `schema_version` reaches the domain, whose schema gate records it
//!   as `Quarantined`.
//! - **Other failures back off**, and are dead-lettered at the retry limit,
//!   into the same `incident_dead_letter` the outbox uses.
//! - **Clocks.** Every lease and backoff comparison uses PostgreSQL's
//!   `transaction_timestamp()`, as in [`crate::outbox`].
//! - **Scope.** Enqueueing is for one tenant. Claiming is across tenants and
//!   takes a [`PlatformAuthority`]; each event is then ingested under its own
//!   row's tenant.

use std::future::Future;
use std::time::Duration;

use deadpool_postgres::Pool;
use tidegard_detector::DetectionEvent;
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::error::IncidentError;
use tidegard_incident::unit_of_work::IngestOutcomeKind;
use tokio_postgres::{Client, GenericClient, IsolationLevel, Row};

use crate::error::PersistError;
use crate::outbox::{micros, FailureOutcome, OutboxPolicy};
use crate::platform::PlatformAuthority;
use crate::pool::acquire;
use crate::service::IncidentPersistence;

/// Batch size, lease and retry limit for the worker. The same shape, and
/// the same unmeasured starting values, as the outbox consumer's.
pub type InboxPolicy = OutboxPolicy;

/// An event this worker now holds the lease on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedEvent {
    pub inbox_id: i64,
    pub tenant_id: String,
    pub dedup_key: String,
    /// The event as JSON text.
    pub payload: String,
    /// Failed processing attempts so far.
    pub attempts: i32,
}

/// What one [`InboxWorker::process_batch`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchReport {
    pub claimed: usize,
    pub processed: usize,
    pub retrying: usize,
    pub dead_lettered: usize,
    /// Rows whose lease another worker took over before this one finished.
    pub lease_lost: usize,
    /// Events the domain refused on clock skew (ADR 0031). They are also
    /// counted as retrying or dead-lettered; this count makes recurring
    /// skew visible.
    pub clock_skew: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboxStats {
    pub pending: i64,
    pub retrying: i64,
    pub dead_letter: i64,
}

const ENQUEUE: &str = "\
INSERT INTO detection_event_inbox (
    tenant_id, dedup_key, detection_id, event_id, schema_version, payload
)
SELECT $1, e.dedup_key, e.detection_id, e.event_id, e.schema_version, e.payload::jsonb
FROM unnest($2::text[], $3::text[], $4::text[], $5::integer[], $6::text[])
    AS e(dedup_key, detection_id, event_id, schema_version, payload)
ON CONFLICT (tenant_id, dedup_key) DO NOTHING";

/// ADR 0033's lease-aware claim, over the inbox.
const CLAIM: &str = "\
WITH claimable AS (
    SELECT inbox_id FROM detection_event_inbox
    WHERE status IN ('pending', 'retrying')
      AND available_at <= transaction_timestamp()
      AND (
        locked_at IS NULL
        OR locked_at + $1::bigint * interval '1 microsecond' <= transaction_timestamp()
      )
    ORDER BY inbox_id
    FOR UPDATE SKIP LOCKED
    LIMIT $2
)
UPDATE detection_event_inbox AS i
SET locked_at = transaction_timestamp(), locked_by = $3
FROM claimable
WHERE i.inbox_id = claimable.inbox_id
RETURNING i.inbox_id, i.tenant_id, i.dedup_key, i.payload::text AS payload, i.attempts";

const MARK_PROCESSED: &str = "\
UPDATE detection_event_inbox
SET status = 'processed', outcome = $3, processed_at = transaction_timestamp(),
    locked_at = NULL, locked_by = NULL, last_error = NULL
WHERE inbox_id = $1 AND locked_by = $2 AND status IN ('pending', 'retrying')";

const LOCK_HELD: &str = "\
SELECT attempts FROM detection_event_inbox
WHERE inbox_id = $1 AND locked_by = $2 AND status IN ('pending', 'retrying')
FOR UPDATE";

const SCHEDULE_RETRY: &str = "\
UPDATE detection_event_inbox
SET status = 'retrying', attempts = $2, last_error = $3,
    locked_at = NULL, locked_by = NULL,
    available_at = transaction_timestamp() + $4::bigint * interval '1 microsecond'
WHERE inbox_id = $1";

const COPY_TO_DEAD_LETTER: &str = "\
INSERT INTO incident_dead_letter (
    tenant_id, aggregate_type, aggregate_id, event_type, payload, failure_reason, attempts
)
SELECT tenant_id, 'detection_event', dedup_key, payload->>'kind', payload, $2::text, $3::integer
FROM detection_event_inbox WHERE inbox_id = $1";

const MARK_DEAD_LETTER: &str = "\
UPDATE detection_event_inbox
SET status = 'dead_letter', attempts = $2, last_error = $3,
    locked_at = NULL, locked_by = NULL
WHERE inbox_id = $1";

const STATS: &str = "\
SELECT
    count(*) FILTER (WHERE status = 'pending') AS pending,
    count(*) FILTER (WHERE status = 'retrying') AS retrying,
    count(*) FILTER (WHERE status = 'dead_letter') AS dead_letter
FROM detection_event_inbox";

/// Enqueues events for one tenant in one statement. Returns how many were
/// new; an event already in the inbox for this tenant is skipped. Refused
/// as a whole, before anything is written, if any event targets another
/// tenant.
pub async fn enqueue(
    client: &impl GenericClient,
    tenant: &TenantId,
    events: &[DetectionEvent],
) -> Result<u64, PersistError> {
    if events.is_empty() {
        return Ok(0);
    }
    if events
        .iter()
        .any(|event| event.target.tenant != tenant.as_str())
    {
        return Err(PersistError::Rejected(IncidentError::TenantMismatch));
    }
    let mut dedup_keys = Vec::with_capacity(events.len());
    let mut detection_ids = Vec::with_capacity(events.len());
    let mut event_ids = Vec::with_capacity(events.len());
    let mut schema_versions = Vec::with_capacity(events.len());
    let mut payloads = Vec::with_capacity(events.len());
    for event in events {
        dedup_keys.push(event.dedup_key.as_str());
        detection_ids.push(event.detection_id.as_str());
        event_ids.push(event.event_id.as_str());
        schema_versions.push(i32::try_from(event.schema_version).map_err(|_| {
            PersistError::unrepresentable("schema_version", "exceeds the integer column")
        })?);
        payloads.push(serde_json::to_string(event).map_err(|error| {
            PersistError::unrepresentable("detection_event", error.to_string())
        })?);
    }
    Ok(client
        .execute(
            ENQUEUE,
            &[
                &tenant.as_str(),
                &dedup_keys,
                &detection_ids,
                &event_ids,
                &schema_versions,
                &payloads,
            ],
        )
        .await?)
}

/// The outcome column's value for each ingest outcome.
pub fn outcome_code(kind: IngestOutcomeKind) -> &'static str {
    match kind {
        IngestOutcomeKind::Created => "created",
        IngestOutcomeKind::Updated => "updated",
        IngestOutcomeKind::Reopened => "reopened",
        IngestOutcomeKind::LinkedLate => "linked_late",
        IngestOutcomeKind::Duplicate => "duplicate",
        IngestOutcomeKind::Quarantined => "quarantined",
        IngestOutcomeKind::ObserveOnly => "observe_only",
    }
}

/// One named worker. `worker_id` is recorded in `locked_by`; two processes
/// must not share one.
#[derive(Debug, Clone)]
pub struct InboxWorker {
    worker_id: String,
    policy: InboxPolicy,
}

impl InboxWorker {
    /// The authority is checked here, at construction, as for
    /// [`crate::outbox::OutboxConsumer`].
    pub fn new(
        _authority: &PlatformAuthority,
        worker_id: impl Into<String>,
        policy: InboxPolicy,
    ) -> Self {
        InboxWorker {
            worker_id: worker_id.into(),
            policy,
        }
    }

    /// Leases up to `batch_size` claimable events, oldest first.
    pub async fn claim(
        &self,
        client: &impl GenericClient,
    ) -> Result<Vec<ClaimedEvent>, PersistError> {
        let lease = micros(self.policy.lease);
        let limit = i64::from(self.policy.batch_size);
        let mut events = client
            .query(CLAIM, &[&lease, &limit, &self.worker_id])
            .await?
            .iter()
            .map(claimed_event)
            .collect::<Result<Vec<_>, PersistError>>()?;
        events.sort_by_key(|event| event.inbox_id);
        Ok(events)
    }

    /// Records the ingest outcome of an event this worker holds. `false` if
    /// it no longer holds it.
    pub async fn mark_processed(
        &self,
        client: &impl GenericClient,
        inbox_id: i64,
        outcome: IngestOutcomeKind,
    ) -> Result<bool, PersistError> {
        let updated = client
            .execute(
                MARK_PROCESSED,
                &[&inbox_id, &self.worker_id, &outcome_code(outcome)],
            )
            .await?;
        Ok(updated == 1)
    }

    /// Records one failed attempt. At the retry limit the event is
    /// dead-lettered; otherwise it is scheduled again after the backoff.
    pub async fn mark_failed(
        &self,
        client: &mut Client,
        inbox_id: i64,
        error: &str,
    ) -> Result<FailureOutcome, PersistError> {
        self.fail(client, inbox_id, error, false).await
    }

    /// Dead-letters an event this worker holds at once, without retries:
    /// its payload cannot be read.
    pub async fn quarantine(
        &self,
        client: &mut Client,
        inbox_id: i64,
        error: &str,
    ) -> Result<FailureOutcome, PersistError> {
        self.fail(client, inbox_id, error, true).await
    }

    async fn fail(
        &self,
        client: &mut Client,
        inbox_id: i64,
        error: &str,
        poison: bool,
    ) -> Result<FailureOutcome, PersistError> {
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let Some(row) = transaction
            .query_opt(LOCK_HELD, &[&inbox_id, &self.worker_id])
            .await?
        else {
            return Ok(FailureOutcome::LeaseLost);
        };
        let previous: i32 = row.try_get("attempts")?;
        let attempts = previous
            .checked_add(1)
            .ok_or_else(|| PersistError::corrupt("attempts", "is at its maximum"))?;
        let attempts_u32 = u32::try_from(attempts)
            .map_err(|_| PersistError::corrupt("attempts", "is negative"))?;

        let outcome = if poison || attempts_u32 >= self.policy.retry.max_attempts.max(1) {
            transaction
                .execute(COPY_TO_DEAD_LETTER, &[&inbox_id, &error, &attempts])
                .await?;
            transaction
                .execute(MARK_DEAD_LETTER, &[&inbox_id, &attempts, &error])
                .await?;
            FailureOutcome::DeadLettered {
                attempts: attempts_u32,
            }
        } else {
            let backoff = micros(self.policy.retry.delay_after(attempts_u32));
            transaction
                .execute(SCHEDULE_RETRY, &[&inbox_id, &attempts, &error, &backoff])
                .await?;
            FailureOutcome::Retrying {
                attempts: attempts_u32,
            }
        };
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Claims one batch and processes it in `inbox_id` order: each event is
    /// ingested under its row's tenant, then marked processed, retried or
    /// dead-lettered. An error from the database while marking stops the
    /// batch; the rows it did not reach are reclaimed after their lease.
    pub async fn process_batch(
        &self,
        service: &IncidentPersistence,
        client: &mut Client,
    ) -> Result<BatchReport, PersistError> {
        let claimed = self.claim(&*client).await?;
        let mut report = BatchReport {
            claimed: claimed.len(),
            ..BatchReport::default()
        };
        for event in claimed {
            let failure = match serde_json::from_str::<DetectionEvent>(&event.payload) {
                Err(error) => {
                    let reason = format!("incident.inbox_unreadable_payload: {error}");
                    count(
                        &mut report,
                        self.quarantine(client, event.inbox_id, &reason).await?,
                    );
                    continue;
                }
                Ok(detection) => {
                    let auth =
                        AuthorizationContext::correlator(TenantId::new(event.tenant_id.as_str()));
                    match service
                        .ingest_detection_event(client, &auth, &detection)
                        .await
                    {
                        Ok(Ok(result)) => {
                            if self
                                .mark_processed(&*client, event.inbox_id, result.outcome_kind)
                                .await?
                            {
                                report.processed += 1;
                            } else {
                                report.lease_lost += 1;
                            }
                            continue;
                        }
                        Ok(Err(domain)) => {
                            if matches!(domain, IncidentError::ClockSkew { .. }) {
                                report.clock_skew += 1;
                            }
                            format!("{}: {domain}", domain.code())
                        }
                        Err(persist) => format!("incident.persistence: {persist}"),
                    }
                }
            };
            count(
                &mut report,
                self.mark_failed(client, event.inbox_id, &failure).await?,
            );
        }
        Ok(report)
    }

    /// Processes batches until `shutdown` completes (ADR 0012's shutdown
    /// drain).
    ///
    /// - A batch is never interrupted: shutdown is only noticed between
    ///   batches, so the batch in flight finishes and commits, and nothing
    ///   more is claimed after it.
    /// - After an empty claim the loop waits `idle_wait`, and after a failed
    ///   batch it backs off with the policy's delays. Shutdown cuts either
    ///   wait short.
    /// - A failed batch never stops the loop. Rows it left leased are
    ///   reclaimed when their lease expires.
    pub async fn run(
        &self,
        service: &IncidentPersistence,
        pool: &Pool,
        idle_wait: Duration,
        shutdown: impl Future<Output = ()>,
    ) -> WorkerReport {
        self.run_observed(service, pool, idle_wait, shutdown, |_| {})
            .await
    }

    /// [`Self::run`], calling `observe` after every batch, so a service can
    /// count and log each one as it happens.
    pub async fn run_observed(
        &self,
        service: &IncidentPersistence,
        pool: &Pool,
        idle_wait: Duration,
        shutdown: impl Future<Output = ()>,
        mut observe: impl FnMut(Result<&BatchReport, &PersistError>),
    ) -> WorkerReport {
        let mut report = WorkerReport::default();
        let mut failures: u32 = 0;
        tokio::pin!(shutdown);
        loop {
            let outcome = match acquire(pool).await {
                Ok(mut client) => self.process_batch(service, &mut client).await,
                Err(error) => Err(error),
            };
            observe(outcome.as_ref());
            let wait = match outcome {
                Ok(batch) => {
                    failures = 0;
                    report.batches += 1;
                    report.processed += batch.processed;
                    report.retrying += batch.retrying;
                    report.dead_lettered += batch.dead_lettered;
                    report.lease_lost += batch.lease_lost;
                    report.clock_skew += batch.clock_skew;
                    if batch.claimed > 0 {
                        Duration::ZERO
                    } else {
                        idle_wait
                    }
                }
                Err(_) => {
                    report.failed_batches += 1;
                    failures = failures.saturating_add(1);
                    self.policy.retry.delay_after(failures)
                }
            };
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                () = tokio::time::sleep(wait) => {}
            }
        }
        report
    }
}

/// Totals across one [`InboxWorker::run`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkerReport {
    /// Batches that completed, empty ones included.
    pub batches: u64,
    /// Batches that failed on a database error.
    pub failed_batches: u64,
    pub processed: usize,
    pub retrying: usize,
    pub dead_lettered: usize,
    pub lease_lost: usize,
    pub clock_skew: usize,
}

fn count(report: &mut BatchReport, outcome: FailureOutcome) {
    match outcome {
        FailureOutcome::Retrying { .. } => report.retrying += 1,
        FailureOutcome::DeadLettered { .. } => report.dead_lettered += 1,
        FailureOutcome::LeaseLost => report.lease_lost += 1,
    }
}

/// Counts for the inbox depth metrics.
pub async fn inbox_stats(
    _authority: &PlatformAuthority,
    client: &impl GenericClient,
) -> Result<InboxStats, PersistError> {
    let row = client.query_one(STATS, &[]).await?;
    Ok(InboxStats {
        pending: row.try_get("pending")?,
        retrying: row.try_get("retrying")?,
        dead_letter: row.try_get("dead_letter")?,
    })
}

fn claimed_event(row: &Row) -> Result<ClaimedEvent, PersistError> {
    Ok(ClaimedEvent {
        inbox_id: row.try_get("inbox_id")?,
        tenant_id: row.try_get("tenant_id")?,
        dedup_key: row.try_get("dedup_key")?,
        payload: row.try_get("payload")?,
        attempts: row.try_get("attempts")?,
    })
}
