//! Milestone 5B-2 migration smoke test.
//!
//! Applies every migration under `migrations/` to a real, ephemeral
//! PostgreSQL instance, asserts they apply cleanly, asserts re-running is
//! a no-op (refinery's own idempotency guarantee — a checksum-matched,
//! already-applied migration is skipped rather than re-executed), and
//! asserts the resulting schema shape matches what this milestone
//! actually built: the three active-incident partial unique indexes,
//! every table's presence, and a handful of load-bearing column types
//! (`incident_id` as `uuid`, the three `BIGINT GENERATED ALWAYS AS
//! IDENTITY` durable record ids, `request_fingerprint` as `bytea`, the
//! typed `target_addr`/`target_network` columns).
//!
//! **This test never touches a real or production database.** It
//! requires an explicit, opt-in connection string — there is no default
//! that could accidentally point at something real — and connects over
//! plain TCP to what must be an isolated loopback instance (matching ADR
//! 0023's "TLS optional only for an isolated loopback test database"
//! rule). See `README.md` for how to start one with the compose file
//! next to this crate.
//!
//! # Running this test
//!
//! ```text
//! docker compose -f crates/incident-postgres/docker-compose.yml up -d --wait
//! TIDEGARD_INCIDENT_POSTGRES_TEST_URL="host=127.0.0.1 port=55432 user=tidegard_test password=tidegard_test_only dbname=tidegard_incident_test" \
//!     cargo test -p tidegard-incident-postgres --test migration_smoke_test
//! docker compose -f crates/incident-postgres/docker-compose.yml down -v
//! ```
//!
//! Without that environment variable set, this test prints why it is
//! skipping and passes trivially — `cargo test --workspace` must stay
//! green in an environment with no Docker/PostgreSQL available, and a
//! hard failure on missing opt-in infrastructure would make every
//! ordinary contributor's `cargo test` red for a reason unrelated to
//! their change. CI is different: the `rust` job in
//! `.github/workflows/validate.yml` provisions a PostgreSQL service
//! container, sets the variable, and fails the job if this test prints
//! its skip message anyway (FU-46) — so a skip can never pass silently
//! there.

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

/// Every table this milestone's migrations create, independent of which
/// migration file created it — used to assert nothing silently failed to
/// apply.
const EXPECTED_TABLES: &[&str] = &[
    "incidents",
    "incident_detection_events",
    "incident_timeline",
    "incident_audit",
    "incident_notes",
    "incident_tags",
    "incident_assignments",
    "incident_policy_references",
    "incident_number_allocators",
    "incident_idempotency",
    "incident_outbox",
    "incident_dead_letter",
    "detection_event_inbox",
    "api_tokens",
    "api_sessions",
    "mitigations",
    "mitigation_history",
    "mitigation_controls",
    "bgp_peers",
    "tenants",
    "tenant_prefixes",
];

/// The three target-type-specific partial unique indexes that make the
/// active-incident invariant a database-enforced fact rather than an
/// application promise (incident-persistence.md's "Active-incident
/// invariant" section, V10__active_incident_partial_indexes.sql).
const EXPECTED_ACTIVE_INDEXES: &[&str] = &[
    "incidents_active_host",
    "incidents_active_network",
    "incidents_active_hostgroup",
];

#[tokio::test]
async fn migrations_apply_cleanly_are_idempotent_and_produce_the_expected_schema() {
    let Some(connection_string) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping migration_smoke_test: {TEST_DATABASE_URL_VAR} is not set. \
             This test requires a real, ephemeral, local-or-CI-only PostgreSQL \
             instance — see crates/incident-postgres/README.md and \
             docker-compose.yml for how to start one. Not a failure: an \
             environment with no Docker/PostgreSQL available must still be able \
             to run `cargo test --workspace` cleanly."
        );
        return;
    };

    let (mut client, connection) =
        tokio_postgres::connect(&connection_string, tokio_postgres::NoTls)
            .await
            .expect("must be able to connect to the configured ephemeral test database");

    // tokio_postgres requires the connection future to be polled
    // concurrently with any query; a dropped/failed connection surfaces
    // here rather than corrupting later assertions silently.
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("postgres connection error: {error}");
        }
    });

    // Start from an empty `public` schema every run, so this test is
    // repeatable against one long-lived local compose instance across
    // multiple `cargo test` invocations without requiring `docker compose
    // down -v` between each one. This only ever targets the throwaway
    // schema inside the opt-in test database above — never anything
    // reachable without TIDEGARD_INCIDENT_POSTGRES_TEST_URL set.
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .expect("must be able to reset the public schema in the test database");

    // --- Forward application ---
    let report = tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("all migrations must apply cleanly against an empty schema");
    assert_eq!(
        report.applied_migrations().len(),
        22,
        "expected all 22 migration files (V1..V22) to apply on a fresh schema"
    );

    // --- Idempotency: refinery's own guarantee ---
    // A second run against the same, now-migrated database must apply
    // nothing — every migration is already recorded, checksum-matched, in
    // refinery's own history table.
    let second_report = tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .expect("re-running already-applied migrations must not error");
    assert_eq!(
        second_report.applied_migrations().len(),
        0,
        "re-running the migrations must be a no-op"
    );

    // --- Schema shape: every expected table exists ---
    let table_rows = client
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
            &[],
        )
        .await
        .expect("must be able to list tables");
    let actual_tables: std::collections::HashSet<String> = table_rows
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect();
    for expected in EXPECTED_TABLES {
        assert!(
            actual_tables.contains(*expected),
            "expected table `{expected}` to exist after migrating; found {actual_tables:?}"
        );
    }

    // --- Schema shape: the three active-incident partial unique indexes ---
    let index_rows = client
        .query(
            "SELECT indexname FROM pg_indexes \
             WHERE schemaname = 'public' AND tablename = 'incidents'",
            &[],
        )
        .await
        .expect("must be able to list indexes on incidents");
    let actual_indexes: std::collections::HashSet<String> = index_rows
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect();
    for expected in EXPECTED_ACTIVE_INDEXES {
        assert!(
            actual_indexes.contains(*expected),
            "expected partial unique index `{expected}` on incidents; found {actual_indexes:?}"
        );
    }

    // --- Schema shape: load-bearing column types ---
    assert_column_type(&client, "incidents", "incident_id", "uuid").await;
    assert_column_type(&client, "incidents", "target_addr", "inet").await;
    assert_column_type(&client, "incidents", "target_network", "cidr").await;
    assert_column_type(&client, "incidents", "version", "bigint").await;
    assert_column_type(&client, "incident_timeline", "timeline_id", "bigint").await;
    assert_column_type(&client, "incident_audit", "audit_id", "bigint").await;
    assert_column_type(&client, "incident_outbox", "outbox_id", "bigint").await;
    assert_column_type(
        &client,
        "incident_idempotency",
        "request_fingerprint",
        "bytea",
    )
    .await;
    assert_column_type(
        &client,
        "incident_timeline",
        "occurred_at",
        "timestamp with time zone",
    )
    .await;
    assert_column_type(
        &client,
        "incident_audit",
        "occurred_at",
        "timestamp with time zone",
    )
    .await;

    // --- The three durable-identity columns are actually
    //     `GENERATED ALWAYS AS IDENTITY`, not merely `BIGINT`. ---
    assert_is_identity_column(&client, "incident_timeline", "timeline_id").await;
    assert_is_identity_column(&client, "incident_audit", "audit_id").await;
    assert_is_identity_column(&client, "incident_outbox", "outbox_id").await;

    // --- ADR 0032: the application runtime role exists and does not
    //     carry BYPASSRLS. ---
    let role_rows = client
        .query(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname = 'wetechinetmon_app'",
            &[],
        )
        .await
        .expect("must be able to query pg_roles");
    assert_eq!(
        role_rows.len(),
        1,
        "expected the wetechinetmon_app role to have been created by V11"
    );
    let bypasses_rls: bool = role_rows[0].get(0);
    assert!(
        !bypasses_rls,
        "wetechinetmon_app must not carry BYPASSRLS (ADR 0032)"
    );
}

async fn assert_column_type(
    client: &tokio_postgres::Client,
    table: &str,
    column: &str,
    expected_type: &str,
) {
    let rows = client
        .query(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
            &[&table, &column],
        )
        .await
        .unwrap_or_else(|error| panic!("querying column type for {table}.{column}: {error}"));
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one column {table}.{column}, found {}",
        rows.len()
    );
    let actual_type: String = rows[0].get(0);
    assert_eq!(
        actual_type, expected_type,
        "expected {table}.{column} to be {expected_type}, found {actual_type}"
    );
}

async fn assert_is_identity_column(client: &tokio_postgres::Client, table: &str, column: &str) {
    let rows = client
        .query(
            "SELECT is_identity FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
            &[&table, &column],
        )
        .await
        .unwrap_or_else(|error| panic!("querying identity-ness of {table}.{column}: {error}"));
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one column {table}.{column}"
    );
    let is_identity: String = rows[0].get(0);
    assert_eq!(
        is_identity, "YES",
        "expected {table}.{column} to be GENERATED ALWAYS AS IDENTITY (ADR 0027)"
    );
}
