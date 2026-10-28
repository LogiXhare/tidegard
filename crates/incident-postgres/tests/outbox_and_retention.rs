//! Milestone 5B-4: the outbox consumer's claim, lease, retry and
//! dead-letter behavior (ADR 0033), and retention purging only what it may.
//! 5B-5: both are reachable only with a `PlatformAuthority` (ADR 0032).
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{event, host_scope, network_scope_with_host_bits};
use tidegard_detector::{EventKind, MetricKind, TestClock};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::TestIncidentGenerator;
use tidegard_incident_postgres::outbox::{
    outbox_stats, ClaimedMessage, FailureOutcome, OutboxConsumer, OutboxPolicy, OutboxStats,
};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::retention::{run_retention, RetentionPolicy, RetentionReport};
use tidegard_incident_postgres::retry::RetryPolicy;
use tidegard_incident_postgres::service::IncidentPersistence;
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

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

async fn insert_message(client: &Client, aggregate_id: &str) -> i64 {
    client
        .query_one(
            "INSERT INTO incident_outbox (
                tenant_id, aggregate_type, aggregate_id, aggregate_version, event_type, payload
             ) VALUES ('acme', 'incident', $1, 1, 'incident.opened', '{}')
             RETURNING outbox_id",
            &[&aggregate_id],
        )
        .await
        .expect("insert outbox message")
        .get(0)
}

fn ids(messages: Vec<ClaimedMessage>) -> Vec<i64> {
    messages
        .into_iter()
        .map(|message| message.outbox_id)
        .collect()
}

fn platform_context(role: &str) -> AuthorizationContext {
    AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Operator {
            id: "platform-admin".to_string(),
        },
        FixedBundleResolver.permissions_for(role),
    )
}

#[tokio::test]
async fn the_outbox_leases_retries_and_dead_letters_and_retention_purges_only_what_it_may() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping outbox_and_retention: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md."
        );
        return;
    };
    let mut client = connect(&url).await;
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("migrations must apply");

    // --- Only a platform-admin context reaches the cross-tenant paths ---
    assert!(PlatformAuthority::from_context(&platform_context("noc_lead")).is_err());
    let platform = PlatformAuthority::from_context(&platform_context("platform_admin"))
        .expect("a platform admin is authorized");

    let first = insert_message(&client, "agg-1").await;
    let second = insert_message(&client, "agg-2").await;
    let third = insert_message(&client, "agg-3").await;

    // A long backoff, so a retrying row cannot become available mid-test.
    let policy = OutboxPolicy {
        batch_size: 2,
        retry: RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_secs(20),
            max_delay: Duration::from_secs(60),
        },
        ..OutboxPolicy::starting_default()
    };
    let a = OutboxConsumer::new(&platform, "consumer-a", policy);
    let b = OutboxConsumer::new(&platform, "consumer-b", policy);

    // --- A claim takes the oldest batch; an active lease is not reclaimable ---
    assert_eq!(ids(a.claim(&client).await.unwrap()), [first, second]);
    assert_eq!(
        ids(b.claim(&client).await.unwrap()),
        [third],
        "rows under another consumer's active lease are skipped"
    );

    // --- A published row is never claimed again ---
    assert!(a.mark_published(&client, first).await.unwrap());
    assert!(ids(b.claim(&client).await.unwrap()).is_empty());

    // --- A failure schedules a retry after its backoff ---
    assert_eq!(
        a.mark_failed(&mut client, second, "clickhouse unavailable")
            .await
            .unwrap(),
        FailureOutcome::Retrying { attempts: 1 }
    );
    assert!(
        ids(b.claim(&client).await.unwrap()).is_empty(),
        "a retrying row waits out its backoff even though it is unleased"
    );

    // --- An expired lease is reclaimable, and the old holder loses it ---
    let reclaimer = OutboxConsumer::new(
        &platform,
        "consumer-c",
        OutboxPolicy {
            lease: Duration::ZERO,
            ..policy
        },
    );
    assert_eq!(ids(reclaimer.claim(&client).await.unwrap()), [third]);
    assert!(
        !b.mark_published(&client, third).await.unwrap(),
        "a consumer that lost its lease cannot publish"
    );
    assert_eq!(
        b.mark_failed(&mut client, third, "late").await.unwrap(),
        FailureOutcome::LeaseLost
    );

    // --- At the retry limit a message is dead-lettered ---
    let strict = OutboxConsumer::new(
        &platform,
        "consumer-d",
        OutboxPolicy {
            retry: RetryPolicy {
                max_attempts: 2,
                ..policy.retry
            },
            ..policy
        },
    );
    client
        .execute(
            "UPDATE incident_outbox SET available_at = transaction_timestamp() - interval '1 second' \
             WHERE outbox_id = $1",
            &[&second],
        )
        .await
        .unwrap();
    assert_eq!(ids(strict.claim(&client).await.unwrap()), [second]);
    assert_eq!(
        strict
            .mark_failed(&mut client, second, "still unavailable")
            .await
            .unwrap(),
        FailureOutcome::DeadLettered { attempts: 2 }
    );
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_dead_letter \
             WHERE aggregate_id = 'agg-2' AND failure_reason = 'still unavailable' AND attempts = 2",
            &[]
        )
        .await,
        1
    );
    assert!(
        ids(strict.claim(&client).await.unwrap()).is_empty(),
        "a dead-lettered row is never claimed, and the reclaimed row is leased again"
    );
    assert_eq!(
        outbox_stats(&platform, &client).await.unwrap(),
        OutboxStats {
            pending: 1,
            retrying: 0,
            unreviewed_dead_letter: 1,
        }
    );

    // --- Retention purges only what it may ---
    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    );
    let scope = host_scope();
    let closed = service
        .ingest_detection_event(
            &mut client,
            &AuthorizationContext::correlator(TenantId::new(scope.tenant)),
            &event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps),
        )
        .await
        .unwrap()
        .unwrap()
        .incident_id
        .unwrap()
        .to_canonical_string();
    let open_scope = network_scope_with_host_bits();
    service
        .ingest_detection_event(
            &mut client,
            &AuthorizationContext::correlator(TenantId::new(open_scope.tenant)),
            &event(
                &open_scope,
                1,
                EventKind::Started,
                "p-opening",
                MetricKind::Bps,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    client
        .execute(
            "UPDATE incidents SET state = 'closed', \
             closed_at = transaction_timestamp() - interval '25 months' \
             WHERE incident_id = $1::text::uuid",
            &[&closed],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE incident_outbox SET published_at = transaction_timestamp() - interval '8 days' \
             WHERE outbox_id = $1",
            &[&first],
        )
        .await
        .unwrap();
    client
        .batch_execute(
            "INSERT INTO incident_idempotency (
                tenant_id, idempotency_key, operation, resource_type, request_fingerprint,
                response_status, response_body_ref, expires_at
             ) VALUES
                ('acme', 'expired-request-key-01', 'handle_command', 'incident', '\\x00',
                 'mutated', '{}', transaction_timestamp() - interval '1 hour'),
                ('acme', 'current-request-key-01', 'handle_command', 'incident', '\\x00',
                 'mutated', '{}', transaction_timestamp() + interval '1 hour');
             INSERT INTO incident_dead_letter (
                tenant_id, failure_reason, first_seen_at, reviewed_at, reviewed_by_type, reviewed_by_id
             ) VALUES
                ('acme', 'old reviewed', now() - interval '91 days', now() - interval '1 day',
                 'operator', 'op-7'),
                ('acme', 'old unreviewed', now() - interval '400 days', NULL, NULL, NULL);
             INSERT INTO tenants (tenant_id, display_name) VALUES ('acme', 'Acme');
             INSERT INTO api_tokens (
                token_id, tenant_id, actor_type, actor_id, role, token_hash, expires_at
             ) VALUES (
                '0192f3c4-0000-7000-8000-000000000001', 'acme', 'operator', 'op-7', 'viewer',
                decode(repeat('11', 32), 'hex'), now() + interval '1 day'
             );
             INSERT INTO api_sessions (session_hash, token_id, created_at, last_seen_at, expires_at)
             VALUES
                (decode(repeat('aa', 32), 'hex'), '0192f3c4-0000-7000-8000-000000000001',
                 now() - interval '2 hours', now() - interval '2 hours', now() - interval '1 hour'),
                (decode(repeat('bb', 32), 'hex'), '0192f3c4-0000-7000-8000-000000000001',
                 now(), now(), now() + interval '12 hours');",
        )
        .await
        .unwrap();
    const UNPUBLISHED: &str = "SELECT count(*) FROM incident_outbox WHERE status <> 'published'";
    let unpublished_before = scalar(&client, UNPUBLISHED, &[]).await;
    let audit_before = scalar(&client, "SELECT count(*) FROM incident_audit", &[]).await;
    assert!(audit_before >= 2);

    let report = run_retention(&platform, &client, &RetentionPolicy::engineering_default())
        .await
        .unwrap();
    assert_eq!(
        report,
        RetentionReport {
            expired_idempotency: 1,
            published_outbox: 1,
            processed_inbox: 0,
            reviewed_dead_letter: 1,
            closed_incidents: 1,
            expired_sessions: 1,
        }
    );
    assert_eq!(
        scalar(&client, "SELECT count(*) FROM api_sessions", &[]).await,
        1,
        "the live session stays"
    );

    for (what, sql, expected) in [
        (
            "the closed incident",
            "SELECT count(*) FROM incidents WHERE incident_id = $1::text::uuid",
            0,
        ),
        (
            "its timeline",
            "SELECT count(*) FROM incident_timeline WHERE incident_id = $1::text::uuid",
            0,
        ),
        (
            "its detection-event links",
            "SELECT count(*) FROM incident_detection_events WHERE incident_id = $1::text::uuid",
            0,
        ),
    ] {
        assert_eq!(scalar(&client, sql, &[&closed]).await, expected, "{what}");
    }
    for (what, sql, expected) in [
        ("the open incident", "SELECT count(*) FROM incidents", 1),
        (
            "the unexpired idempotency record",
            "SELECT count(*) FROM incident_idempotency",
            1,
        ),
        (
            "the unreviewed dead letters, however old",
            "SELECT count(*) FROM incident_dead_letter WHERE reviewed_at IS NULL",
            2,
        ),
    ] {
        assert_eq!(scalar(&client, sql, &[]).await, expected, "{what}");
    }
    assert_eq!(
        scalar(&client, UNPUBLISHED, &[]).await,
        unpublished_before,
        "retention never deletes an unpublished outbox row"
    );
    assert_eq!(
        scalar(&client, "SELECT count(*) FROM incident_audit", &[]).await,
        audit_before,
        "retention never deletes audit rows"
    );
}
