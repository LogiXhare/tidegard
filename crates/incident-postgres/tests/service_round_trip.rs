//! Milestone 5B-3(b): the load–run–flush service against PostgreSQL, and
//! FU-44's gate: a connection killed mid-flush commits nothing.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `WETECHINETMON_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

mod support;

use std::sync::Arc;

use support::{event, host_scope, operator, Scope};
use tokio_postgres::types::ToSql;
use tokio_postgres::Client;
use wetechinetmon_detector::{EventKind, MetricKind, TestClock};
use wetechinetmon_incident::authorization::{
    Actor, AuthorizationContext, FixedBundleResolver, PermissionResolver,
};
use wetechinetmon_incident::command::Command;
use wetechinetmon_incident::correlation::{CorrelationKey, TenantId};
use wetechinetmon_incident::error::IncidentError;
use wetechinetmon_incident::id::TestIncidentGenerator;
use wetechinetmon_incident::idempotency::IdempotencyKey;
use wetechinetmon_incident::incident::NoteVisibility;
use wetechinetmon_incident::number::InMemoryNumberAllocator;
use wetechinetmon_incident::unit_of_work::{IncidentUnitOfWork, IngestOutcomeKind};
use wetechinetmon_incident_postgres::flush::flush;
use wetechinetmon_incident_postgres::service::IncidentPersistence;
use wetechinetmon_incident_postgres::sql::{load_incident, Locking};
use wetechinetmon_incident_postgres::staging::StagingStore;

const TEST_DATABASE_URL_VAR: &str = "WETECHINETMON_INCIDENT_POSTGRES_TEST_URL";

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

#[tokio::test]
async fn the_service_commits_each_call_whole_and_a_killed_flush_commits_nothing() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping service_round_trip: {TEST_DATABASE_URL_VAR} is not set. \
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
    wetechinetmon_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("migrations must apply");

    let service = IncidentPersistence::new(
        Arc::new(TestIncidentGenerator::starting_at(1)),
        Arc::new(TestClock::new()),
    );
    let scope = host_scope();
    let tenant = TenantId::new(scope.tenant);
    let correlator = AuthorizationContext::correlator(tenant.clone());
    const NEXT_NUMBER: &str =
        "SELECT next_value FROM incident_number_allocators WHERE tenant_id = $1";
    const TIMELINE: &str =
        "SELECT count(*) FROM incident_timeline WHERE incident_id = $1::text::uuid";

    // --- A first detection creates an incident with its history ---
    let started = event(&scope, 1, EventKind::Started, "p-opening", MetricKind::Bps);
    let created = service
        .ingest_detection_event(&mut client, &correlator, &started)
        .await
        .expect("committed")
        .expect("the domain accepts the event");
    assert_eq!(created.outcome_kind, IngestOutcomeKind::Created);
    let id = created.incident_id.unwrap();
    let id_text = id.to_canonical_string();
    let incident = load_incident(&client, &tenant, &id, Locking::NoLock)
        .await
        .unwrap()
        .expect("the created incident is stored");
    assert_eq!(incident.incident_number.as_str(), "WNM-2026-000001");
    assert_eq!(scalar(&client, NEXT_NUMBER, &[&scope.tenant]).await, 2);
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_detection_events \
             WHERE incident_id = $1::text::uuid AND link_type = 'opening'",
            &[&id_text]
        )
        .await,
        1
    );
    let timeline_after_create = scalar(&client, TIMELINE, &[&id_text]).await;
    assert!(timeline_after_create >= 1);
    assert!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_outbox WHERE aggregate_id = $1 AND aggregate_version = 1",
            &[&id_text]
        )
        .await
            >= 1
    );
    assert!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_audit WHERE tenant_id = $1 AND result = 'allowed'",
            &[&scope.tenant]
        )
        .await
            >= 1
    );

    // --- The same event again is a duplicate and writes nothing ---
    let again = service
        .ingest_detection_event(&mut client, &correlator, &started)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (again.outcome_kind, again.incident_id),
        (IngestOutcomeKind::Duplicate, Some(id))
    );
    assert_eq!(
        scalar(&client, TIMELINE, &[&id_text]).await,
        timeline_after_create
    );

    // --- A later event under another policy links to the open incident ---
    let updated = event(
        &scope,
        2,
        EventKind::Updated,
        "p-second",
        MetricKind::TcpSynPps,
    );
    let linked = service
        .ingest_detection_event(&mut client, &correlator, &updated)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(linked.outcome_kind, IngestOutcomeKind::Updated);
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_detection_events \
             WHERE incident_id = $1::text::uuid AND link_type = 'update'",
            &[&id_text]
        )
        .await,
        1
    );
    let incident = load_incident(&client, &tenant, &id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((incident.version, incident.policy_refs.len()), (2, 2));
    assert_eq!(
        scalar(&client, NEXT_NUMBER, &[&scope.tenant]).await,
        2,
        "linking to an open incident consumes no number"
    );

    // --- An idempotent command commits once and then replays ---
    let noc = operator(scope.tenant);
    let ack_key = IdempotencyKey::new("ack-request-key-0001").unwrap();
    let acked = service
        .handle_command(
            &mut client,
            &noc,
            id,
            Command::AcknowledgeIncident {
                expected_version: 2,
            },
            Some(ack_key.clone()),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(acked, 3);
    let timeline_after_ack = scalar(&client, TIMELINE, &[&id_text]).await;
    let replayed = service
        .handle_command(
            &mut client,
            &noc,
            id,
            Command::AcknowledgeIncident {
                expected_version: 2,
            },
            Some(ack_key),
        )
        .await
        .unwrap();
    assert_eq!(replayed, Ok(3));
    assert_eq!(
        scalar(&client, TIMELINE, &[&id_text]).await,
        timeline_after_ack
    );

    // --- A failed outcome is recorded and replays as the same error ---
    // A version conflict is refused before the domain records anything, so
    // this uses a refusal from inside the command itself: customer-visible
    // notes are not honoured yet.
    let refused_key = IdempotencyKey::new("refused-request-key1").unwrap();
    let customer_note = || Command::AddNote {
        body: "visible to the customer".to_string(),
        visibility: NoteVisibility::CustomerVisible,
    };
    let first = service
        .handle_command(
            &mut client,
            &noc,
            id,
            customer_note(),
            Some(refused_key.clone()),
        )
        .await
        .unwrap();
    assert!(first.is_err(), "a customer-visible note must be refused");
    let second = service
        .handle_command(&mut client, &noc, id, customer_note(), Some(refused_key))
        .await
        .unwrap();
    assert_eq!(second, first);
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_idempotency WHERE response_status = 'failed'",
            &[]
        )
        .await,
        1
    );

    // --- A denied command commits only its audit entry ---
    let viewer = AuthorizationContext::new(
        tenant.clone(),
        Actor::Operator {
            id: "viewer-1".to_string(),
        },
        FixedBundleResolver.permissions_for("viewer"),
    );
    let denied = service
        .handle_command(
            &mut client,
            &viewer,
            id,
            Command::AddNote {
                body: "not allowed".to_string(),
                visibility: NoteVisibility::Internal,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(denied, Err(IncidentError::Unauthorized));
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_audit WHERE actor_id = 'viewer-1' AND result = 'denied'",
            &[]
        )
        .await,
        1
    );

    // --- Another tenant cannot reach the incident ---
    let outsider = operator("other-tenant");
    let hidden = service
        .handle_command(
            &mut client,
            &outsider,
            id,
            Command::AddNote {
                body: "wrong tenant".to_string(),
                visibility: NoteVisibility::Internal,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(hidden, Err(IncidentError::NotFound));

    // --- FU-63: an edit supersedes, a redaction empties the body ---
    let first_new = scalar(
        &client,
        "SELECT count(*) FROM incident_notes WHERE incident_id = $1::text::uuid",
        &[&id_text],
    )
    .await as u32;
    for command in [
        Command::AddNote {
            body: "router password is hunter2".to_string(),
            visibility: NoteVisibility::Internal,
        },
        Command::EditNote {
            note_index: first_new,
            body: "router password rotated".to_string(),
        },
        Command::RedactNote {
            note_index: first_new,
            reason: "pasted a credential".to_string(),
        },
    ] {
        service
            .handle_command(&mut client, &noc, id, command, None)
            .await
            .unwrap()
            .expect("the note command commits");
    }
    const NOTE_PAIR: &str = "\
SELECT original.body, original.superseded_at IS NOT NULL AS superseded,
    original.superseded_by_type, original.superseded_by_id,
    original.redacted_at IS NOT NULL AS redacted, original.redacted_by_id,
    original.redaction_reason, original.redacted_at::text AS redacted_at,
    edit.supersedes_note_id = original.note_id AS linked, edit.body AS edit_body
FROM incident_notes original
JOIN incident_notes edit
    ON edit.incident_id = original.incident_id AND edit.note_index = original.note_index + 1
WHERE original.incident_id = $1::text::uuid AND original.note_index = $2::integer";
    let original_index = first_new as i32;
    let pair = client
        .query_one(NOTE_PAIR, &[&id_text, &original_index])
        .await
        .unwrap();
    assert_eq!(pair.get::<_, String>("body"), "");
    assert!(pair.get::<_, bool>("superseded"));
    assert_eq!(
        pair.get::<_, Option<String>>("superseded_by_type")
            .as_deref(),
        Some("operator")
    );
    assert_eq!(
        pair.get::<_, Option<String>>("superseded_by_id").as_deref(),
        Some("op-7")
    );
    assert!(pair.get::<_, bool>("redacted"));
    assert_eq!(
        pair.get::<_, Option<String>>("redacted_by_id").as_deref(),
        Some("op-7")
    );
    assert_eq!(
        pair.get::<_, Option<String>>("redaction_reason").as_deref(),
        Some("pasted a credential")
    );
    assert!(pair.get::<_, bool>("linked"));
    assert_eq!(
        pair.get::<_, String>("edit_body"),
        "router password rotated"
    );
    let redacted_at: String = pair.get("redacted_at");
    assert_eq!(
        scalar(
            &client,
            "SELECT count(*) FROM incident_timeline WHERE incident_id = $1::text::uuid \
             AND entry_type IN ('note_superseded', 'note_redacted')",
            &[&id_text]
        )
        .await,
        2
    );
    for table in ["incident_notes", "incident_timeline", "incident_audit"] {
        let sql = format!("SELECT count(*) FROM {table} t WHERE t::text LIKE '%hunter2%'");
        assert_eq!(scalar(&client, &sql, &[]).await, 0, "{table}");
    }

    // A later save rewrites every note: the stamps keep their first value.
    service
        .handle_command(
            &mut client,
            &noc,
            id,
            Command::AddNote {
                body: "after the redaction".to_string(),
                visibility: NoteVisibility::Internal,
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let again = client
        .query_one(NOTE_PAIR, &[&id_text, &original_index])
        .await
        .unwrap();
    assert_eq!(again.get::<_, String>("redacted_at"), redacted_at);
    let reloaded = load_incident(&client, &tenant, &id, Locking::NoLock)
        .await
        .unwrap()
        .unwrap();
    let original = &reloaded.notes[first_new as usize];
    assert_eq!(
        original.redaction.as_ref().map(|r| r.reason.as_str()),
        Some("pasted a credential")
    );
    assert_eq!(
        reloaded.notes[first_new as usize + 1].supersedes,
        Some(first_new)
    );
    assert_eq!(reloaded.note_superseded_by(first_new), Some(first_new + 1));

    // --- FU-44: a connection killed mid-flush commits nothing ---
    let killer = connect(&url).await;
    let umbrella = TenantId::new("umbrella");
    let umbrella_scope = Scope {
        tenant: "umbrella",
        scope_type: scope.scope_type,
        scope_id: scope.scope_id.clone(),
    };
    let doomed = event(
        &umbrella_scope,
        1,
        EventKind::Started,
        "p-opening",
        MetricKind::Bps,
    );
    let key = CorrelationKey::new(
        umbrella.clone(),
        doomed.target.scope_type,
        doomed.target.scope_id.clone(),
        doomed.target.direction,
        doomed.target.address_family,
    );
    let mut staged = StagingStore::new();
    staged.load_dedup(umbrella.clone(), doomed.dedup_key.clone(), None);
    staged.load_open_index(key.clone(), None);
    staged.load_reopen_candidate(key, umbrella.clone(), None);
    let mut uow = IncidentUnitOfWork::new(
        Box::new(TestIncidentGenerator::starting_at(9_000)),
        Box::new(InMemoryNumberAllocator::new()),
        Box::new(TestClock::new()),
    )
    .with_store(Box::new(staged));
    let doomed_id = uow
        .ingest_detection_event(&AuthorizationContext::correlator(umbrella.clone()), &doomed)
        .unwrap()
        .incident_id
        .unwrap();
    let changes = StagingStore::recover(uow.into_store())
        .unwrap()
        .into_changes()
        .unwrap();

    let pid: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let transaction = client.transaction().await.unwrap();
    flush(&transaction, &umbrella, &changes, Some(&doomed), None)
        .await
        .expect("every flush statement succeeds before the kill");
    // Waits up to 5 s for the backend to actually exit.
    let terminated: bool = killer
        .query_one("SELECT pg_terminate_backend($1, 5000)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(terminated);
    assert!(
        transaction.commit().await.is_err(),
        "a killed connection must not be able to commit"
    );

    let doomed_text = doomed_id.to_canonical_string();
    for table in [
        "incidents",
        "incident_timeline",
        "incident_detection_events",
    ] {
        let rows = scalar(
            &killer,
            &format!("SELECT count(*) FROM {table} WHERE incident_id = $1::text::uuid"),
            &[&doomed_text],
        )
        .await;
        assert_eq!(
            rows, 0,
            "{table} must hold nothing from the killed transaction"
        );
    }
    for table in ["incident_outbox", "incident_audit"] {
        let rows = scalar(
            &killer,
            &format!("SELECT count(*) FROM {table} WHERE tenant_id = 'umbrella'"),
            &[],
        )
        .await;
        assert_eq!(
            rows, 0,
            "{table} must hold nothing from the killed transaction"
        );
    }
}
