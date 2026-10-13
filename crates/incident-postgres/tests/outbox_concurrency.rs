//! Milestone 5B-5: ADR 0033's outbox concurrency and crash tests, under real
//! concurrency on separate connections rather than sequential calls on one.
//!
//! `tests/outbox_and_retention.rs` already covers, sequentially: an active
//! lease is skipped, a published row is never claimed, a retrying row waits
//! out its backoff, and the retry limit dead-letters. This binary adds
//! simultaneous claimers, a rolled-back claim, a worker crashing before and
//! after its claim commits, lease expiry measured on PostgreSQL's
//! `transaction_timestamp()`, `attempts` under a lease race, and a
//! dead-letter transition that claim timing cannot move.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::outbox::{
    ClaimedMessage, FailureOutcome, OutboxConsumer, OutboxPolicy,
};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::retry::RetryPolicy;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

/// A lease short enough to wait out, long enough that the checks made right
/// after a claim land well inside it.
const SHORT_LEASE: Duration = Duration::from_secs(2);
/// Comfortably past [`SHORT_LEASE`] and every backoff this test schedules.
const PAST_SHORT_LEASE: Duration = Duration::from_millis(2_500);
const LONG: Duration = Duration::from_secs(60);
/// A claim still running after this is taken to be waiting on a lock.
const NOT_BLOCKED: Duration = Duration::from_secs(5);

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("must be able to connect to the configured ephemeral test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection closed: {error}");
        }
    });
    client
}

async fn scalar(client: &Client, sql: &str, params: &[&(dyn ToSql + Sync)]) -> i64 {
    client
        .query_one(sql, params)
        .await
        .expect("scalar query")
        .get(0)
}

/// Empties the outbox and dead-letter tables between sections, so each
/// section's claims see only its own rows.
async fn reset_outbox(client: &Client) {
    client
        .batch_execute("TRUNCATE incident_outbox, incident_dead_letter RESTART IDENTITY")
        .await
        .expect("truncate outbox");
}

async fn insert_messages(client: &Client, count: usize) -> Vec<i64> {
    static NEXT_AGGREGATE: AtomicUsize = AtomicUsize::new(0);
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let aggregate_id = format!("agg-{}", NEXT_AGGREGATE.fetch_add(1, Ordering::Relaxed));
        let id: i64 = client
            .query_one(
                "INSERT INTO incident_outbox (
                    tenant_id, aggregate_type, aggregate_id, aggregate_version, event_type, payload
                 ) VALUES ('acme', 'incident', $1, 1, 'incident.opened', '{}')
                 RETURNING outbox_id",
                &[&aggregate_id],
            )
            .await
            .expect("insert outbox message")
            .get(0);
        ids.push(id);
    }
    ids
}

fn ids(messages: &[ClaimedMessage]) -> Vec<i64> {
    messages.iter().map(|message| message.outbox_id).collect()
}

async fn attempts(client: &Client, outbox_id: i64) -> i64 {
    scalar(
        client,
        "SELECT attempts::bigint FROM incident_outbox WHERE outbox_id = $1",
        &[&outbox_id],
    )
    .await
}

async fn backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("backend pid")
        .get(0)
}

/// Kills a backend the way a crashed worker's connection ends: without a
/// commit or a rollback from the client.
async fn crash(admin: &Client, pid: i32) {
    let terminated: bool = admin
        .query_one("SELECT pg_terminate_backend($1, 5000)", &[&pid])
        .await
        .expect("terminate backend")
        .get(0);
    assert!(terminated, "backend {pid} must terminate");
}

fn policy(lease: Duration) -> OutboxPolicy {
    OutboxPolicy {
        batch_size: 2,
        lease,
        // A long backoff, so a retrying row cannot come back mid-section.
        retry: RetryPolicy {
            max_attempts: 10,
            base_delay: LONG,
            max_delay: LONG,
        },
    }
}

/// Claims and publishes until a claim comes back empty.
async fn drain(consumer: &OutboxConsumer, client: &Client) -> Vec<i64> {
    let mut published = Vec::new();
    loop {
        let batch = consumer.claim(client).await.expect("claim");
        if batch.is_empty() {
            return published;
        }
        for message in batch {
            assert!(
                consumer
                    .mark_published(client, message.outbox_id)
                    .await
                    .expect("mark published"),
                "a consumer publishes what it just claimed"
            );
            published.push(message.outbox_id);
        }
    }
}

#[tokio::test]
async fn outbox_claims_stay_disjoint_survive_crashes_and_count_attempts_once() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping outbox_concurrency: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };
    let mut admin = connect(&url).await;
    admin
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut admin)
        .await
        .expect("migrations must apply");

    let platform = PlatformAuthority::from_context(&AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Operator {
            id: "platform-admin".to_string(),
        },
        FixedBundleResolver.permissions_for("platform_admin"),
    ))
    .expect("a platform admin is authorized");
    let consumer = |id: &str, policy| OutboxConsumer::new(&platform, id, policy);
    let mut client_a = connect(&url).await;
    let mut client_b = connect(&url).await;

    // --- Two simultaneous claimers get disjoint rows; SKIP LOCKED never waits ---
    reset_outbox(&admin).await;
    let rows = insert_messages(&admin, 4).await;
    let a = consumer("claimer-a", policy(LONG));
    let b = consumer("claimer-b", policy(LONG));
    let held = client_a.transaction().await.unwrap();
    assert_eq!(ids(&a.claim(&held).await.unwrap()), rows[..2]);
    let beside = tokio::time::timeout(NOT_BLOCKED, b.claim(&client_b))
        .await
        .expect("a claim skips rows an uncommitted claim holds instead of waiting")
        .unwrap();
    assert_eq!(ids(&beside), rows[2..]);
    held.commit().await.unwrap();

    // --- Many claimers draining one backlog at once each take every row once ---
    reset_outbox(&admin).await;
    let backlog: BTreeSet<i64> = insert_messages(&admin, 40).await.into_iter().collect();
    let mut drainer_clients = Vec::new();
    for _ in 0..4 {
        drainer_clients.push(connect(&url).await);
    }
    let drainers: Vec<OutboxConsumer> = (0..4)
        .map(|n| {
            consumer(
                &format!("drainer-{n}"),
                OutboxPolicy {
                    batch_size: 3,
                    ..policy(LONG)
                },
            )
        })
        .collect();
    let (d0, d1, d2, d3) = tokio::join!(
        drain(&drainers[0], &drainer_clients[0]),
        drain(&drainers[1], &drainer_clients[1]),
        drain(&drainers[2], &drainer_clients[2]),
        drain(&drainers[3], &drainer_clients[3]),
    );
    let published = [d0, d1, d2, d3].concat();
    let distinct: BTreeSet<i64> = published.iter().copied().collect();
    assert_eq!(published.len(), distinct.len(), "no row was claimed twice");
    assert_eq!(distinct, backlog, "every row was claimed");
    assert_eq!(
        scalar(
            &admin,
            "SELECT count(*) FROM incident_outbox WHERE status <> 'published'",
            &[]
        )
        .await,
        0
    );

    // --- A claim that rolls back leased nothing ---
    reset_outbox(&admin).await;
    let rows = insert_messages(&admin, 1).await;
    let held = client_a.transaction().await.unwrap();
    assert_eq!(ids(&a.claim(&held).await.unwrap()), rows);
    held.rollback().await.unwrap();
    assert_eq!(
        ids(&b.claim(&client_b).await.unwrap()),
        rows,
        "the rolled-back claim's locked_at and locked_by never committed"
    );

    // --- A worker crashing mid-claim loses nothing and blocks no one ---
    reset_outbox(&admin).await;
    let rows = insert_messages(&admin, 1).await;
    let crashing = connect(&url).await;
    let pid = backend_pid(&crashing).await;
    crashing.batch_execute("BEGIN").await.unwrap();
    assert_eq!(ids(&a.claim(&crashing).await.unwrap()), rows);
    crash(&admin, pid).await;
    let recovered = tokio::time::timeout(NOT_BLOCKED, b.claim(&client_b))
        .await
        .expect("the crashed claim's row locks are released")
        .unwrap();
    assert_eq!(ids(&recovered), rows);

    // --- A worker crashing after its claim commits: reclaimed only once the lease expires ---
    reset_outbox(&admin).await;
    let rows = insert_messages(&admin, 1).await;
    let short_a = consumer("worker-a", policy(SHORT_LEASE));
    let short_b = consumer("worker-b", policy(SHORT_LEASE));
    let crashing = connect(&url).await;
    let pid = backend_pid(&crashing).await;
    let delivered = short_a.claim(&crashing).await.unwrap();
    assert_eq!(ids(&delivered), rows);
    assert!(
        short_b.claim(&client_b).await.unwrap().is_empty(),
        "a committed claim is not reclaimable while its lease is active"
    );
    crash(&admin, pid).await;
    assert!(
        short_b.claim(&client_b).await.unwrap().is_empty(),
        "the holder crashing does not end its lease early"
    );
    tokio::time::sleep(PAST_SHORT_LEASE).await;
    let redelivered = short_b.claim(&client_b).await.unwrap();
    assert_eq!(
        redelivered, delivered,
        "the crashed worker's message is redelivered unchanged, so the downstream \
         can de-duplicate on (aggregate_id, aggregate_version, event_type)"
    );
    assert_eq!(
        attempts(&admin, rows[0]).await,
        0,
        "a crash is not a failure"
    );
    assert!(
        !short_a.mark_published(&client_a, rows[0]).await.unwrap(),
        "the crashed worker's identity no longer holds the lease"
    );
    assert!(short_b.mark_published(&client_b, rows[0]).await.unwrap());
    assert!(
        consumer("worker-zero-lease", policy(Duration::ZERO))
            .claim(&client_b)
            .await
            .unwrap()
            .is_empty(),
        "a published row is not reclaimable by any lease"
    );

    // --- Lease and backoff are measured on transaction_timestamp(), not wall time ---
    reset_outbox(&admin).await;
    let mut rows = insert_messages(&admin, 1).await;
    assert_eq!(ids(&short_a.claim(&client_a).await.unwrap()), rows);
    rows.extend(insert_messages(&admin, 1).await);
    let backoff = consumer(
        "worker-backoff",
        OutboxPolicy {
            retry: RetryPolicy {
                max_attempts: 10,
                base_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(1),
            },
            ..policy(LONG)
        },
    );
    assert_eq!(
        ids(&backoff.claim(&client_a).await.unwrap()),
        rows[1..],
        "the first row is still under worker-a's lease"
    );
    assert_eq!(
        backoff
            .mark_failed(&mut client_a, rows[1], "clickhouse unavailable")
            .await
            .unwrap(),
        FailureOutcome::Retrying { attempts: 1 }
    );
    let early = client_b.transaction().await.unwrap();
    early.query_one("SELECT 1", &[]).await.unwrap();
    tokio::time::sleep(PAST_SHORT_LEASE).await;
    assert!(
        short_b.claim(&early).await.unwrap().is_empty(),
        "a transaction that began inside the lease and the backoff still sees both \
         in force, however long ago it began"
    );
    early.commit().await.unwrap();
    assert_eq!(ids(&short_b.claim(&client_b).await.unwrap()), rows);

    // --- attempts rises once per genuine claim-and-fail, even when two holders race ---
    reset_outbox(&admin).await;
    let rows = insert_messages(&admin, 1).await;
    let stale = consumer("race-stale", policy(Duration::ZERO));
    let current = consumer("race-current", policy(Duration::ZERO));
    assert_eq!(ids(&stale.claim(&client_a).await.unwrap()), rows);
    for _ in 0..3 {
        let again = current.claim(&client_b).await.unwrap();
        assert_eq!(ids(&again), rows);
        assert_eq!(
            again[0].attempts, 0,
            "claiming alone never counts an attempt"
        );
    }
    let (lost, counted) = tokio::join!(
        stale.mark_failed(&mut client_a, rows[0], "stale holder"),
        current.mark_failed(&mut client_b, rows[0], "current holder"),
    );
    assert_eq!(lost.unwrap(), FailureOutcome::LeaseLost);
    assert_eq!(counted.unwrap(), FailureOutcome::Retrying { attempts: 1 });
    assert_eq!(attempts(&admin, rows[0]).await, 1);

    // --- The retry limit dead-letters on the third failure, whatever the claims between ---
    reset_outbox(&admin).await;
    let rows = insert_messages(&admin, 1).await;
    let row = rows[0];
    let limited = |id: &str| {
        consumer(
            id,
            OutboxPolicy {
                batch_size: 2,
                lease: Duration::ZERO,
                retry: RetryPolicy {
                    max_attempts: 3,
                    base_delay: Duration::ZERO,
                    max_delay: Duration::ZERO,
                },
            },
        )
    };
    let d = limited("limit-d");
    let e = limited("limit-e");
    assert_eq!(ids(&d.claim(&admin).await.unwrap()), rows);
    assert_eq!(ids(&e.claim(&admin).await.unwrap()), rows);
    assert_eq!(ids(&e.claim(&admin).await.unwrap()), rows);
    assert_eq!(
        d.mark_failed(&mut admin, row, "x").await.unwrap(),
        FailureOutcome::LeaseLost
    );
    assert_eq!(
        e.mark_failed(&mut admin, row, "x").await.unwrap(),
        FailureOutcome::Retrying { attempts: 1 }
    );
    for claimer in [&d, &e, &d] {
        let claimed = claimer.claim(&admin).await.unwrap();
        assert_eq!(ids(&claimed), rows);
        assert_eq!(claimed[0].attempts, 1);
    }
    assert_eq!(
        d.mark_failed(&mut admin, row, "x").await.unwrap(),
        FailureOutcome::Retrying { attempts: 2 }
    );
    for claimer in [&e, &d] {
        assert_eq!(claimer.claim(&admin).await.unwrap()[0].attempts, 2);
    }
    assert_eq!(
        d.mark_failed(&mut admin, row, "final").await.unwrap(),
        FailureOutcome::DeadLettered { attempts: 3 }
    );
    assert_eq!(
        scalar(
            &admin,
            "SELECT count(*) FROM incident_dead_letter \
             WHERE attempts = 3 AND failure_reason = 'final'",
            &[]
        )
        .await,
        1
    );
    for claimer in [&d, &e] {
        assert!(claimer.claim(&admin).await.unwrap().is_empty());
    }
}
