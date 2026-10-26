//! One load–run–flush transaction per `IncidentUnitOfWork` entry point
//! (ADR 0034).
//!
//! Each method opens a Read Committed transaction on the caller's client,
//! loads the working set ([`crate::load`]), runs the unchanged domain call
//! over a [`StagingStore`], flushes what it changed ([`crate::flush`]), and
//! commits. A transient failure rolls back and reruns all of that from a
//! fresh load, under the [`RetryPolicy`] ([`crate::retry`]).
//!
//! The return type separates the two ways a call ends:
//!
//! - `Err(PersistError)`: nothing was committed. The load or flush failed
//!   and was not retryable, or still failed on the last attempt; the call
//!   looked up a key the load did not fetch; or the domain reported a broken
//!   invariant.
//! - `Ok(domain_result)`: the transaction committed. A domain `Err` still
//!   commits what the call recorded about it, such as a denied-permission
//!   audit entry or a failed-outcome idempotency record, just as the
//!   in-memory store keeps them.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tidegard_detector::DetectionEvent;
use tidegard_incident::authorization::AuthorizationContext;
use tidegard_incident::clock::Clock;
use tidegard_incident::closure::ClosurePolicy;
use tidegard_incident::command::Command;
use tidegard_incident::correlation::{CorrelationKey, TenantId};
use tidegard_incident::error::IncidentError;
use tidegard_incident::id::{IncidentGenerator, IncidentId};
use tidegard_incident::idempotency::IdempotencyKey;
use tidegard_incident::manual::ManualIncident;
use tidegard_incident::number::{IncidentNumber, NumberAllocator};
use tidegard_incident::reopen::ReopenPolicy;
use tidegard_incident::transition::DetectionEndReason;
use tidegard_incident::unit_of_work::{IncidentUnitOfWork, IngestResult};
use tokio_postgres::{Client, IsolationLevel};

use crate::error::PersistError;
use crate::flush::flush;
use crate::load::{load_for_create, load_for_incident, load_for_ingest};
use crate::retry::RetryPolicy;
use crate::staging::StagingStore;

/// The outer `Result` says whether the call committed; the inner one is
/// the domain's own result. See the module doc.
pub type Outcome<T> = Result<Result<T, IncidentError>, PersistError>;

/// The shared, long-lived half of every call: id generation, the clock, the
/// retry policy, and the unit of work's configuration.
pub struct IncidentPersistence {
    generator: Arc<dyn IncidentGenerator>,
    clock: Arc<dyn Clock>,
    decision_time: DecisionTime,
    retry: RetryPolicy,
    number_allocation_year: Option<u32>,
    policies: Option<(ClosurePolicy, ReopenPolicy)>,
}

/// Where a call's wall-clock decision time comes from (ADR 0031).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionTime {
    /// PostgreSQL's `transaction_timestamp()`, read at the start of each
    /// attempt. Authoritative for every reopen, suppression and lifecycle
    /// decision, so application servers' clocks never disagree about it.
    Database,
    /// The injected clock's wall time.
    Injected,
}

#[derive(Clone, Copy)]
enum Load<'a> {
    Ingest(&'a DetectionEvent),
    Create {
        key: &'a CorrelationKey,
        idempotency_key: Option<&'a IdempotencyKey>,
    },
    Incident {
        id: IncidentId,
        idempotency_key: Option<&'a IdempotencyKey>,
    },
}

impl IncidentPersistence {
    /// Uses [`RetryPolicy::approved_default`]. Decisions are made at the
    /// database's `transaction_timestamp()` (ADR 0031); `clock` supplies
    /// only monotonic time, unless [`Self::with_injected_decision_time`].
    pub fn new(generator: Arc<dyn IncidentGenerator>, clock: Arc<dyn Clock>) -> Self {
        IncidentPersistence {
            generator,
            clock,
            decision_time: DecisionTime::Database,
            retry: RetryPolicy::approved_default(),
            number_allocation_year: None,
            policies: None,
        }
    }

    /// Makes decisions at the injected clock's wall time instead of the
    /// database's. ADR 0031 makes the database authoritative, so this is for
    /// tests that need to control time, not for production.
    pub fn with_injected_decision_time(mut self) -> Self {
        self.decision_time = DecisionTime::Injected;
        self
    }

    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    pub fn with_number_allocation_year(mut self, year: u32) -> Self {
        self.number_allocation_year = Some(year);
        self
    }

    pub fn with_policies(
        mut self,
        closure_policy: ClosurePolicy,
        reopen_policy: ReopenPolicy,
    ) -> Self {
        self.policies = Some((closure_policy, reopen_policy));
        self
    }

    /// The closure policy every call runs under: the configured one, or the
    /// domain's approved default.
    pub fn closure_policy(&self) -> ClosurePolicy {
        self.policies
            .map_or_else(ClosurePolicy::approved_default, |(closure, _)| closure)
    }

    pub async fn ingest_detection_event(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        event: &DetectionEvent,
    ) -> Outcome<IngestResult> {
        self.run(client, auth.tenant(), Load::Ingest(event), |uow| {
            uow.ingest_detection_event(auth, event)
        })
        .await
    }

    pub async fn handle_command(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        command: Command,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Outcome<u64> {
        let load = Load::Incident {
            id: incident_id,
            idempotency_key: idempotency_key.as_ref(),
        };
        self.run(client, auth.tenant(), load, |uow| {
            uow.handle_command(auth, incident_id, command.clone(), idempotency_key.clone())
        })
        .await
    }

    /// Opens an incident an operator asked for (ADR 0039).
    pub async fn create_manual_incident(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        request: &ManualIncident,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Outcome<IncidentId> {
        let key = request.correlation_key(auth.tenant());
        let load = Load::Create {
            key: &key,
            idempotency_key: idempotency_key.as_ref(),
        };
        self.run(client, auth.tenant(), load, |uow| {
            uow.create_manual_incident(auth, request.clone(), idempotency_key.clone())
        })
        .await
    }

    /// Audits an export before it is read (`queries::export`).
    pub async fn record_export(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
    ) -> Outcome<()> {
        self.run(client, auth.tenant(), by_id(incident_id), |uow| {
            uow.record_export(auth, incident_id)
        })
        .await
    }

    /// The notifier's record of one attempt (ADR 0045).
    pub async fn record_notification_result(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        channel: &str,
        event_type: &str,
        outcome: tidegard_incident::timeline::NotificationOutcome,
    ) -> Outcome<()> {
        self.run(client, auth.tenant(), by_id(incident_id), |uow| {
            uow.record_notification_result(auth, incident_id, channel, event_type, outcome)
        })
        .await
    }

    pub async fn enter_recovering(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        reason: DetectionEndReason,
    ) -> Outcome<()> {
        self.run(client, auth.tenant(), by_id(incident_id), |uow| {
            uow.enter_recovering(auth, incident_id, reason)
        })
        .await
    }

    /// The staleness sweep's call: see
    /// `IncidentUnitOfWork::enter_recovering_if_silent`.
    pub async fn enter_recovering_if_silent(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        silent_after: Duration,
    ) -> Outcome<bool> {
        self.run(client, auth.tenant(), by_id(incident_id), |uow| {
            uow.enter_recovering_if_silent(auth, incident_id, silent_after)
        })
        .await
    }

    pub async fn confirm_recovery_if_due(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
        recovery_confirmation: Duration,
    ) -> Outcome<bool> {
        self.run(client, auth.tenant(), by_id(incident_id), |uow| {
            uow.confirm_recovery_if_due(auth, incident_id, recovery_confirmation)
        })
        .await
    }

    pub async fn abort_recovery(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
    ) -> Outcome<()> {
        self.run(client, auth.tenant(), by_id(incident_id), |uow| {
            uow.abort_recovery(auth, incident_id)
        })
        .await
    }

    pub async fn attempt_automatic_closure(
        &self,
        client: &mut Client,
        auth: &AuthorizationContext,
        incident_id: IncidentId,
    ) -> Outcome<bool> {
        self.run(client, auth.tenant(), by_id(incident_id), |uow| {
            uow.attempt_automatic_closure(auth, incident_id)
        })
        .await
    }

    /// Reruns [`Self::attempt`] while it fails retryably and attempts remain.
    async fn run<T>(
        &self,
        client: &mut Client,
        tenant: &TenantId,
        load: Load<'_>,
        mut call: impl FnMut(&mut IncidentUnitOfWork) -> Result<T, IncidentError>,
    ) -> Outcome<T> {
        let mut attempt = 1;
        loop {
            match self.attempt(client, tenant, load, &mut call).await {
                Err(error) if error.is_retryable() && attempt < self.retry.max_attempts => {
                    tokio::time::sleep(self.retry.delay_after(attempt)).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    /// One load–run–flush transaction. Any `Err` leaves it uncommitted:
    /// dropping the transaction rolls it back.
    async fn attempt<T>(
        &self,
        client: &mut Client,
        tenant: &TenantId,
        load: Load<'_>,
        call: &mut impl FnMut(&mut IncidentUnitOfWork) -> Result<T, IncidentError>,
    ) -> Outcome<T> {
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let decided_at = match self.decision_time {
            DecisionTime::Database => Some(
                transaction
                    .query_one("SELECT transaction_timestamp()", &[])
                    .await?
                    .try_get::<_, SystemTime>(0)?,
            ),
            DecisionTime::Injected => None,
        };

        let event = match load {
            Load::Ingest(event) => Some(event),
            Load::Incident { .. } | Load::Create { .. } => None,
        };
        let (store, next_number) = match load {
            Load::Ingest(event) if event.target.tenant == tenant.as_str() => {
                let loaded = load_for_ingest(&transaction, tenant, event).await?;
                (loaded.store, loaded.next_number)
            }
            // The domain refuses a cross-tenant event before any lookup, so
            // there is nothing to load for it.
            Load::Ingest(_) => (StagingStore::new(), None),
            Load::Incident {
                id,
                idempotency_key,
            } => (
                load_for_incident(&transaction, tenant, id, idempotency_key).await?,
                None,
            ),
            Load::Create {
                key,
                idempotency_key,
            } => {
                let loaded = load_for_create(&transaction, tenant, key, idempotency_key).await?;
                (loaded.store, loaded.next_number)
            }
        };

        // The domain call is synchronous and awaits nothing.
        let numbers = Arc::new(Mutex::new(next_number));
        let (outcome, store, final_number) = {
            let mut uow = IncidentUnitOfWork::new(
                Box::new(SharedGenerator(Arc::clone(&self.generator))),
                Box::new(StagedNumbers(Arc::clone(&numbers))),
                Box::new(DecisionClock {
                    clock: Arc::clone(&self.clock),
                    decided_at,
                }),
            )
            .with_store(Box::new(store));
            if let Some(year) = self.number_allocation_year {
                uow = uow.with_number_allocation_year(year);
            }
            if let Some((closure_policy, reopen_policy)) = self.policies {
                uow = uow.with_policies(closure_policy, reopen_policy);
            }
            let outcome = call(&mut uow);
            let store = StagingStore::recover(uow.into_store());
            let final_number = *numbers.lock().expect("number allocator lock poisoned");
            (outcome, store, final_number)
        };

        if let Err(IncidentError::InternalInvariantViolation(detail)) = &outcome {
            return Err(PersistError::DomainInvariant(detail));
        }
        let store = store.ok_or(PersistError::DomainInvariant(
            "the unit of work did not hand back its staging store",
        ))?;
        let changes = store.into_changes().map_err(PersistError::UnloadedLookup)?;
        let consumed = match (next_number, final_number) {
            (Some(loaded), Some(now)) if now != loaded => Some(now),
            _ => None,
        };

        flush(&transaction, tenant, &changes, event, consumed).await?;
        crate::fault::check(crate::fault::FlushPoint::BeforeCommit)?;
        transaction.commit().await?;
        Ok(outcome)
    }
}

fn by_id(id: IncidentId) -> Load<'static> {
    Load::Incident {
        id,
        idempotency_key: None,
    }
}

struct SharedGenerator(Arc<dyn IncidentGenerator>);

impl IncidentGenerator for SharedGenerator {
    fn generate(&self) -> Result<IncidentId, IncidentError> {
        self.0.generate()
    }
}

/// One attempt's clock: monotonic time from the injected clock, and wall time
/// from the transaction when the service decides on database time.
struct DecisionClock {
    clock: Arc<dyn Clock>,
    decided_at: Option<SystemTime>,
}

impl Clock for DecisionClock {
    fn monotonic(&self) -> Instant {
        self.clock.monotonic()
    }

    fn wall(&self) -> SystemTime {
        self.decided_at.unwrap_or_else(|| self.clock.wall())
    }
}

/// The allocator row the load step locked, as its `next_value`. `None` when
/// the load did not lock it: the domain then gets an internal error instead
/// of a number, and the call is rolled back.
struct StagedNumbers(Arc<Mutex<Option<u64>>>);

impl NumberAllocator for StagedNumbers {
    fn allocate(
        &self,
        _tenant: &str,
        allocation_year: u32,
    ) -> Result<IncidentNumber, IncidentError> {
        let mut next = self.0.lock().expect("number allocator lock poisoned");
        let value = next.ok_or(IncidentError::InternalInvariantViolation(
            "the number allocator row was not loaded for this call",
        ))?;
        let following = value.checked_add(1).ok_or(IncidentError::CapacityExceeded(
            "incident number counter exhausted",
        ))?;
        *next = Some(following);
        Ok(IncidentNumber::from_sequence(allocation_year, value))
    }
}
