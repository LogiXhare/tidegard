//! Milestone 5F: the backup and restore drill (NFR-2). An untested restore
//! is not a backup.
//!
//! Both tests are `#[ignore]`d: they are the two halves of one drill that
//! `scripts/postgres-backup-restore-drill.sh` runs around a real `pg_dump`
//! and `pg_restore`, and they mean nothing on their own.
//!
//! - `drill_seed` resets the opt-in, ephemeral database named by
//!   `TIDEGARD_INCIDENT_POSTGRES_TEST_URL` and fills it through the
//!   service, so every table the incident schema has carries rows.
//! - `drill_verify` runs against the restored copy, named by
//!   `TIDEGARD_INCIDENT_POSTGRES_DRILL_RESTORED_URL`, and proves it is
//!   a working database, not just one with the same rows: the schema is
//!   current, every incident reconstitutes, idempotency replays, numbering
//!   continues, a command commits, and pending outbox rows are claimable.
//!
//! The script compares the two databases row for row in between.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use support::{all_scopes, event, in_episode, operator};
use tidegard_detector::{EventKind, MetricKind, ScopeId, TestClock};
use tidegard_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use tidegard_incident::command::Command;
use tidegard_incident::correlation::TenantId;
use tidegard_incident::id::{IncidentId, TestIncidentGenerator};
use tidegard_incident::idempotency::IdempotencyKey;
use tidegard_incident::incident::NoteVisibility;
use tidegard_incident::unit_of_work::IngestOutcomeKind;
use tidegard_incident_postgres::outbox::{outbox_stats, OutboxConsumer, OutboxPolicy};
use tidegard_incident_postgres::platform::PlatformAuthority;
use tidegard_incident_postgres::service::IncidentPersistence;
use tidegard_incident_postgres::sql::{load_incident, Locking};
use tokio_postgres::Client;

const SOURCE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const RESTORED_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_DRILL_RESTORED_URL";

/// The acknowledgement the seed makes with a key, replayed after restore.
const ACK_KEY: &str = "drill-ack-request-0001";

async fn connect(var: &str) -> Client {
    let url = std::env::var(var).unwrap_or_else(|_| {
        panic!("{var} must name an ephemeral test database; run this through the drill script")
    });
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("must be able to connect to the drill database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection closed: {error}");
        }
    });
    client
}

async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.expect(sql).get(0)
}

fn version_of(outcome: Result<Result<u64, impl std::fmt::Debug>, impl std::fmt::Debug>) -> u64 {
    outcome.expect("committed").expect("the domain accepts it")
}

#[tokio::test]
#[ignore = "half of the backup and restore drill; run by scripts/postgres-backup-restore-drill.sh"]
async fn drill_seed() {
    let mut client = connect(SOURCE_URL_VAR).await;
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("migrations must apply");

    for (scope, seed) in all_scopes() {
        let service = IncidentPersistence::new(
            Arc::new(TestIncidentGenerator::starting_at(seed)),
            Arc::new(TestClock::new()),
        );
        let correlator = AuthorizationContext::correlator(TenantId::new(scope.tenant));
        let noc = operator(scope.tenant);
        let id = service
            .ingest_detection_event(
                &mut client,
                &correlator,
                &event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps),
            )
            .await
            .expect("committed")
            .expect("the domain accepts the event")
            .incident_id
            .expect("the first event creates an incident");
        service
            .ingest_detection_event(
                &mut client,
                &correlator,
                &event(
                    &scope,
                    2,
                    EventKind::Updated,
                    "p-second",
                    MetricKind::TcpSynPps,
                ),
            )
            .await
            .expect("committed")
            .expect("the domain accepts the event");

        let mut version = version_of(
            service
                .handle_command(
                    &mut client,
                    &noc,
                    id,
                    Command::AcknowledgeIncident {
                        expected_version: 2,
                    },
                    Some(IdempotencyKey::new(ACK_KEY).unwrap()),
                )
                .await,
        );
        for command in [
            Command::AddNote {
                body: "drill: seen from the NOC".to_string(),
                visibility: NoteVisibility::Internal,
            },
            Command::AddTag {
                key: "site".to_string(),
                value: "dhaka-1".to_string(),
            },
        ] {
            version = version_of(
                service
                    .handle_command(&mut client, &noc, id, command, None)
                    .await,
            );
        }
        // The first tenant's incident is resolved, so the restored copy also
        // holds one in the reopen window.
        if seed == 1 {
            version_of(
                service
                    .handle_command(
                        &mut client,
                        &noc,
                        id,
                        Command::ResolveIncident {
                            expected_version: version,
                            resolution_note: Some("drill: upstream filtered".to_string()),
                        },
                        None,
                    )
                    .await,
            );
        }
    }

    for table in [
        "incidents",
        "incident_detection_events",
        "incident_timeline",
        "incident_audit",
        "incident_notes",
        "incident_tags",
        "incident_idempotency",
        "incident_outbox",
        "incident_policy_references",
        "incident_number_allocators",
    ] {
        let rows = count(&client, &format!("SELECT count(*) FROM {table}")).await;
        assert!(rows > 0, "the seed must leave rows in {table}");
    }
}

#[tokio::test]
#[ignore = "half of the backup and restore drill; run by scripts/postgres-backup-restore-drill.sh"]
async fn drill_verify() {
    let mut client = connect(RESTORED_URL_VAR).await;

    // The schema history came back with the schema: nothing left to apply.
    let report = tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("the migration history must be readable");
    assert!(
        report.applied_migrations().is_empty(),
        "a restored database must already be at the current schema"
    );

    // Every incident reconstitutes: its invariants hold after the round trip.
    let rows = client
        .query(
            "SELECT tenant_id, incident_id::text FROM incidents ORDER BY tenant_id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), all_scopes().len());
    for row in &rows {
        let tenant = TenantId::new(row.get::<_, String>(0));
        let id = IncidentId::parse(row.get(1)).unwrap();
        load_incident(&client, &tenant, &id, Locking::NoLock)
            .await
            .expect("a restored incident must reconstitute")
            .expect("the restored incident is visible to its tenant");
    }

    for (scope, seed) in all_scopes() {
        let tenant = TenantId::new(scope.tenant);
        let id_text: String = client
            .query_one(
                "SELECT incident_id::text FROM incidents WHERE tenant_id = $1",
                &[&scope.tenant],
            )
            .await
            .unwrap()
            .get(0);
        let id = IncidentId::parse(&id_text).unwrap();
        // Ids the seed never used, so nothing created here collides.
        let service = IncidentPersistence::new(
            Arc::new(TestIncidentGenerator::starting_at(seed + 500)),
            Arc::new(TestClock::new()),
        );
        let noc = operator(scope.tenant);

        // The idempotency record survived: the same request replays.
        let replayed = version_of(
            service
                .handle_command(
                    &mut client,
                    &noc,
                    id,
                    Command::AcknowledgeIncident {
                        expected_version: 2,
                    },
                    Some(IdempotencyKey::new(ACK_KEY).unwrap()),
                )
                .await,
        );
        assert_eq!(replayed, 3, "a replay answers what the first request did");

        // The restored incident takes new work at its restored version.
        let current = load_incident(&client, &tenant, &id, Locking::NoLock)
            .await
            .unwrap()
            .unwrap();
        let next = version_of(
            service
                .handle_command(
                    &mut client,
                    &noc,
                    id,
                    Command::AddNote {
                        body: "drill: written after restore".to_string(),
                        visibility: NoteVisibility::Internal,
                    },
                    None,
                )
                .await,
        );
        assert_eq!(next, current.version + 1);

        // A new detection episode reopens the resolved incident and links
        // to the open ones, exactly as before the backup.
        let correlator = AuthorizationContext::correlator(tenant.clone());
        let recurrence = in_episode(
            event(&scope, 9, EventKind::Started, "p-opening", MetricKind::Bps),
            "det-after-restore",
        );
        let outcome = service
            .ingest_detection_event(&mut client, &correlator, &recurrence)
            .await
            .expect("committed")
            .expect("the domain accepts the event");
        let expected = if seed == 1 {
            IngestOutcomeKind::Reopened
        } else {
            IngestOutcomeKind::Updated
        };
        assert_eq!(outcome.outcome_kind, expected);
    }

    // Numbering continues from the restored allocator: a new target opens a
    // new incident with the next number, never a reused one.
    let (mut scope, seed) = all_scopes().remove(0);
    scope.scope_id = ScopeId::Host {
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 91)),
    };
    const NEXT_NUMBER: &str =
        "SELECT next_value FROM incident_number_allocators WHERE tenant_id = $1";
    let before: i64 = client
        .query_one(NEXT_NUMBER, &[&scope.tenant])
        .await
        .unwrap()
        .get(0);
    let created = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(seed + 900)),
        Arc::new(TestClock::new()),
    )
    .ingest_detection_event(
        &mut client,
        &AuthorizationContext::correlator(TenantId::new(scope.tenant)),
        &in_episode(
            event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps),
            "det-new-target",
        ),
    )
    .await
    .expect("committed")
    .expect("the domain accepts the event");
    assert_eq!(created.outcome_kind, IngestOutcomeKind::Created);
    let after: i64 = client
        .query_one(NEXT_NUMBER, &[&scope.tenant])
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, before + 1);
    let numbers = count(
        &client,
        "SELECT count(*) - count(DISTINCT (tenant_id, incident_number)) FROM incidents",
    )
    .await;
    assert_eq!(numbers, 0, "no incident number is reused after restore");

    // Messages that were pending at backup time are still deliverable.
    let platform = PlatformAuthority::from_context(&AuthorizationContext::new(
        TenantId::new("platform"),
        Actor::Operator {
            id: "platform-admin".to_string(),
        },
        FixedBundleResolver.permissions_for("super_admin"),
    ))
    .expect("platform_admin is a platform authority");
    let stats = outbox_stats(&platform, &client).await.unwrap();
    assert!(stats.pending > 0, "pending outbox rows survive the restore");
    let consumer = OutboxConsumer::new(&platform, "drill-consumer", OutboxPolicy::default());
    let claimed = consumer.claim(&client).await.unwrap();
    assert!(!claimed.is_empty(), "a restored pending row is claimable");
}
