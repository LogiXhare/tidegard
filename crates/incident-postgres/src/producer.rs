//! The detector's side of the inbox (ADR 0035): a sink that never blocks,
//! and a drain task that writes what it holds to `detection_event_inbox`.
//!
//! - **The sink never touches the database.** [`InboxSink::publish`] only
//!   pushes onto a bounded in-memory queue, so a slow or unavailable
//!   database never reaches the detection tick (ADR 0011, and the sink
//!   contract in `crates/detector/src/sink.rs`).
//! - **A full queue refuses the newest event** and reports
//!   [`SinkError::Full`], which the engine counts. Unlike `InMemorySink`,
//!   it never evicts an event it already accepted: an accepted `Started`
//!   must still reach the inbox ahead of its updates.
//! - **An event leaves the queue only once its batch commits.** A failed
//!   write keeps the batch at the head of the queue and backs off, and
//!   `enqueue`'s idempotency makes a batch that did commit, but whose
//!   reply was lost, harmless to send again.
//! - **Loss window.** Events still queued when the process dies are lost;
//!   ADR 0035 states why that is acceptable and what covers it.
//!   [`InboxDrain::run`] shrinks the window on a clean shutdown: it stops
//!   the sink accepting, then flushes what is left, and reports anything it
//!   could not write.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use deadpool_postgres::Pool;
use tidegard_detector::{DetectionEvent, DetectionEventSink, SinkError};
use tidegard_incident::correlation::TenantId;
use tokio_postgres::GenericClient;

use crate::error::PersistError;
use crate::inbox::enqueue;
use crate::pool::acquire;
use crate::retry::RetryPolicy;

const SINK_NAME: &str = "postgres_inbox";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProducerPolicy {
    /// The most events held in memory. Values below 1 behave as 1.
    pub capacity: usize,
    /// The most events written in one statement. Values below 1 behave as 1.
    pub batch_size: usize,
    /// How long the drain waits when the queue is empty.
    pub flush_interval: Duration,
    /// Backoff between failed writes. `max_attempts` bounds only the final
    /// flush at shutdown; while running, the drain keeps retrying.
    pub retry: RetryPolicy,
}

impl ProducerPolicy {
    /// Starting values, not measured ones.
    pub const fn starting_default() -> Self {
        ProducerPolicy {
            capacity: 10_000,
            batch_size: 500,
            flush_interval: Duration::from_millis(200),
            retry: RetryPolicy {
                max_attempts: 5,
                base_delay: Duration::from_millis(200),
                max_delay: Duration::from_secs(30),
            },
        }
    }
}

impl Default for ProducerPolicy {
    fn default() -> Self {
        Self::starting_default()
    }
}

#[derive(Debug)]
struct Shared {
    tenant: TenantId,
    capacity: usize,
    queue: Mutex<VecDeque<DetectionEvent>>,
    closed: AtomicBool,
    dropped_full: AtomicU64,
    refused_tenant: AtomicU64,
}

impl Shared {
    /// A poisoned lock means a thread panicked while holding it; a
    /// `VecDeque` push or drain cannot be left half done, so recover rather
    /// than take the detection path down.
    fn locked(&self) -> MutexGuard<'_, VecDeque<DetectionEvent>> {
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The detector-facing half. Cheap to clone; every clone feeds one queue.
#[derive(Debug, Clone)]
pub struct InboxSink {
    shared: Arc<Shared>,
}

/// The half that writes to PostgreSQL. One per producer.
#[derive(Debug)]
pub struct InboxDrain {
    shared: Arc<Shared>,
    policy: ProducerPolicy,
}

/// What a drain run wrote, and what it could not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Events newly added to the inbox. A re-sent event is not counted.
    pub enqueued: u64,
    /// Failed writes. Each was retried.
    pub failed_writes: u64,
    /// Events still queued when the run returned: lost if the process exits.
    pub abandoned: usize,
}

/// Builds the producer for one tenant: every event published must target
/// it (ADR 0035).
pub fn inbox_producer(tenant: TenantId, policy: ProducerPolicy) -> (InboxSink, InboxDrain) {
    let shared = Arc::new(Shared {
        tenant,
        capacity: policy.capacity.max(1),
        queue: Mutex::new(VecDeque::new()),
        closed: AtomicBool::new(false),
        dropped_full: AtomicU64::new(0),
        refused_tenant: AtomicU64::new(0),
    });
    (
        InboxSink {
            shared: Arc::clone(&shared),
        },
        InboxDrain { shared, policy },
    )
}

impl InboxSink {
    /// Events refused because the queue was full.
    pub fn dropped_full(&self) -> u64 {
        self.shared.dropped_full.load(Ordering::Relaxed)
    }

    /// Events refused because they targeted another tenant.
    pub fn refused_tenant(&self) -> u64 {
        self.shared.refused_tenant.load(Ordering::Relaxed)
    }

    /// Events accepted and not yet written.
    pub fn queued(&self) -> usize {
        self.shared.locked().len()
    }
}

impl DetectionEventSink for InboxSink {
    fn publish(&self, event: &DetectionEvent) -> Result<(), SinkError> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(SinkError::Closed { sink: SINK_NAME });
        }
        // Checked here, not at write time: `enqueue` refuses a whole batch
        // holding another tenant's event, and a batch that can never be
        // written would stall the queue behind it.
        if event.target.tenant != self.shared.tenant.as_str() {
            self.shared.refused_tenant.fetch_add(1, Ordering::Relaxed);
            return Err(SinkError::Backend {
                sink: SINK_NAME,
                detail: "the event targets a tenant this producer does not serve".to_string(),
            });
        }
        let mut queue = self.shared.locked();
        if queue.len() >= self.shared.capacity {
            drop(queue);
            self.shared.dropped_full.fetch_add(1, Ordering::Relaxed);
            return Err(SinkError::Full { sink: SINK_NAME });
        }
        queue.push_back(event.clone());
        Ok(())
    }

    fn name(&self) -> &'static str {
        SINK_NAME
    }
}

/// One producer per tenant behind a single sink, for a detector that serves
/// several tenants. Each event goes to its own tenant's queue, so one
/// tenant's backlog or refused batch never holds up another's.
#[derive(Debug, Clone)]
pub struct TenantRouter {
    sinks: Arc<HashMap<String, InboxSink>>,
    unrouted: Arc<AtomicU64>,
}

/// Builds a [`TenantRouter`] and one drain per distinct tenant. Each drain
/// needs its own task running [`InboxDrain::run`].
pub fn inbox_producers(
    tenants: impl IntoIterator<Item = TenantId>,
    policy: ProducerPolicy,
) -> (TenantRouter, Vec<InboxDrain>) {
    let mut sinks = HashMap::new();
    let mut drains = Vec::new();
    for tenant in tenants {
        if sinks.contains_key(tenant.as_str()) {
            continue;
        }
        let key = tenant.as_str().to_string();
        let (sink, drain) = inbox_producer(tenant, policy);
        sinks.insert(key, sink);
        drains.push(drain);
    }
    (
        TenantRouter {
            sinks: Arc::new(sinks),
            unrouted: Arc::new(AtomicU64::new(0)),
        },
        drains,
    )
}

impl TenantRouter {
    /// Events accepted and not yet written, across every tenant.
    pub fn queued(&self) -> usize {
        self.sinks.values().map(InboxSink::queued).sum()
    }

    /// Events refused because their tenant's queue was full.
    pub fn dropped_full(&self) -> u64 {
        self.sinks.values().map(InboxSink::dropped_full).sum()
    }

    /// Events refused because no producer serves their tenant.
    pub fn unrouted(&self) -> u64 {
        self.unrouted.load(Ordering::Relaxed)
    }

    /// How many tenants have a producer.
    pub fn tenants(&self) -> usize {
        self.sinks.len()
    }
}

impl DetectionEventSink for TenantRouter {
    fn publish(&self, event: &DetectionEvent) -> Result<(), SinkError> {
        match self.sinks.get(&event.target.tenant) {
            Some(sink) => sink.publish(event),
            None => {
                self.unrouted.fetch_add(1, Ordering::Relaxed);
                Err(SinkError::Backend {
                    sink: SINK_NAME,
                    detail: "no inbox producer serves this event's tenant".to_string(),
                })
            }
        }
    }

    fn name(&self) -> &'static str {
        SINK_NAME
    }
}

impl InboxDrain {
    /// The tenant this drain writes for.
    pub fn tenant(&self) -> &TenantId {
        &self.shared.tenant
    }

    /// Writes the batch at the head of the queue, and removes it only once
    /// the write succeeded. `Ok(None)` when the queue is empty.
    pub async fn flush_batch(
        &mut self,
        client: &impl GenericClient,
    ) -> Result<Option<u64>, PersistError> {
        let batch: Vec<DetectionEvent> = {
            let queue = self.shared.locked();
            queue
                .iter()
                .take(self.policy.batch_size.max(1))
                .cloned()
                .collect()
        };
        if batch.is_empty() {
            return Ok(None);
        }
        let added = enqueue(client, &self.shared.tenant, &batch).await?;
        // Only this drain removes events, and the sink only appends, so the
        // head of the queue is still exactly this batch.
        self.shared.locked().drain(..batch.len());
        Ok(Some(added))
    }

    async fn flush_from_pool(&mut self, pool: &Pool) -> Result<Option<u64>, PersistError> {
        // An idle producer holds no connection, and an unreachable database
        // is not reported while there is nothing to write.
        if self.shared.locked().is_empty() {
            return Ok(None);
        }
        let client = acquire(pool).await?;
        self.flush_batch(&**client).await
    }

    /// Drains until `shutdown` completes, then stops the sink accepting and
    /// makes a bounded final flush.
    ///
    /// This and [`Self::flush_batch`] take `&mut self`, which keeps one
    /// writer per queue: the batch a flush removes must be the batch it
    /// wrote.
    pub async fn run(&mut self, pool: &Pool, shutdown: impl Future<Output = ()>) -> DrainReport {
        self.run_observed(pool, shutdown, |_| {}).await
    }

    /// [`Self::run`], calling `observe` after every write that wrote
    /// something or failed, so a service can count and log each one.
    pub async fn run_observed(
        &mut self,
        pool: &Pool,
        shutdown: impl Future<Output = ()>,
        mut observe: impl FnMut(Result<u64, &PersistError>),
    ) -> DrainReport {
        let mut report = DrainReport::default();
        let mut failures: u32 = 0;
        tokio::pin!(shutdown);
        loop {
            let outcome = self.flush_from_pool(pool).await;
            match &outcome {
                Ok(Some(added)) => observe(Ok(*added)),
                Ok(None) => {}
                Err(error) => observe(Err(error)),
            }
            let wait = match outcome {
                Ok(Some(added)) => {
                    report.enqueued += added;
                    failures = 0;
                    continue;
                }
                Ok(None) => self.policy.flush_interval,
                Err(_) => {
                    report.failed_writes += 1;
                    failures = failures.saturating_add(1);
                    self.policy.retry.delay_after(failures)
                }
            };
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(wait) => {}
            }
        }

        self.shared.closed.store(true, Ordering::Release);
        let mut attempts: u32 = 0;
        loop {
            match self.flush_from_pool(pool).await {
                Ok(Some(added)) => {
                    observe(Ok(added));
                    report.enqueued += added;
                }
                Ok(None) => break,
                Err(error) => {
                    observe(Err(&error));
                    report.failed_writes += 1;
                    attempts += 1;
                    if attempts >= self.policy.retry.max_attempts.max(1) {
                        break;
                    }
                    tokio::time::sleep(self.policy.retry.delay_after(attempts)).await;
                }
            }
        }
        report.abandoned = self.shared.locked().len();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_for(tenant: &str, sequence: u64) -> DetectionEvent {
        let mut event: DetectionEvent =
            serde_json::from_str(include_str!("../tests/fixtures/detection_event.json"))
                .expect("fixture event");
        event.target.tenant = tenant.to_string();
        event.sequence = sequence;
        event.dedup_key = format!("{}:{sequence}", event.detection_id);
        event
    }

    #[test]
    fn a_full_queue_refuses_the_newest_event_and_keeps_the_rest() {
        let (sink, _drain) = inbox_producer(
            TenantId::new("acme"),
            ProducerPolicy {
                capacity: 2,
                ..ProducerPolicy::starting_default()
            },
        );
        assert!(sink.publish(&event_for("acme", 0)).is_ok());
        assert!(sink.publish(&event_for("acme", 1)).is_ok());
        assert_eq!(
            sink.publish(&event_for("acme", 2)),
            Err(SinkError::Full { sink: SINK_NAME })
        );
        assert_eq!(sink.dropped_full(), 1);
        let kept: Vec<u64> = sink.shared.locked().iter().map(|e| e.sequence).collect();
        assert_eq!(kept, [0, 1], "accepted events are never evicted");
    }

    #[test]
    fn another_tenants_event_is_refused_and_counted() {
        let (sink, _drain) = inbox_producer(TenantId::new("acme"), ProducerPolicy::default());
        assert!(matches!(
            sink.publish(&event_for("globex", 0)),
            Err(SinkError::Backend { .. })
        ));
        assert_eq!(sink.refused_tenant(), 1);
        assert_eq!(sink.queued(), 0);
    }

    #[test]
    fn the_router_sends_each_event_to_its_own_tenant() {
        let (router, drains) = inbox_producers(
            ["acme", "globex", "acme"].map(TenantId::new),
            ProducerPolicy {
                capacity: 1,
                ..ProducerPolicy::starting_default()
            },
        );
        assert_eq!(drains.len(), 2, "one drain per distinct tenant");
        assert_eq!(router.tenants(), 2);
        assert!(router.publish(&event_for("acme", 0)).is_ok());
        assert!(router.publish(&event_for("globex", 0)).is_ok());
        assert_eq!(router.queued(), 2);

        // acme's full queue does not stop globex's.
        assert_eq!(
            router.publish(&event_for("acme", 1)),
            Err(SinkError::Full { sink: SINK_NAME })
        );
        assert_eq!(router.dropped_full(), 1);
        for drain in &drains {
            let queued: Vec<String> = drain
                .shared
                .locked()
                .iter()
                .map(|e| e.target.tenant.clone())
                .collect();
            assert_eq!(queued, [drain.tenant().as_str()]);
        }
    }

    #[test]
    fn the_router_refuses_an_unknown_tenant_and_counts_it() {
        let (router, _drains) = inbox_producers([TenantId::new("acme")], ProducerPolicy::default());
        assert!(matches!(
            router.publish(&event_for("initech", 0)),
            Err(SinkError::Backend { .. })
        ));
        assert_eq!(router.unrouted(), 1);
        assert_eq!(router.queued(), 0);
    }

    #[test]
    fn a_closed_sink_refuses_everything() {
        let (sink, drain) = inbox_producer(TenantId::new("acme"), ProducerPolicy::default());
        drain.shared.closed.store(true, Ordering::Release);
        assert_eq!(
            sink.publish(&event_for("acme", 0)),
            Err(SinkError::Closed { sink: SINK_NAME })
        );
    }
}
