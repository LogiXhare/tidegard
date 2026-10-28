//! Milestone 6B: the traffic endpoints against a real ClickHouse and a
//! real PostgreSQL (ADR 0042).
//!
//! The collector's own schema is created in ClickHouse, known rows are
//! written, and the API must report them: rates per second, top talkers
//! in order, exporters with their silence. Another tenant gets `404`.
//!
//! Like the other database tests, this connects only to the opt-in,
//! throwaway services named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`
//! and `TIDEGARD_CLICKHOUSE_TEST_URL`, skips with a message when
//! either is unset, and fails CI if it skips there.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::Value;
use tidegard_api::auth::Role;
use tidegard_api::clickhouse::{parse_url, ClickHouse, Endpoint};
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_api::traffic::TrafficSource;
use tidegard_api::{router, AppState};
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::pool::PoolPolicy;
use tokio_postgres::Client;
use tower::ServiceExt;

const POSTGRES_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const CLICKHOUSE_VAR: &str = "TIDEGARD_CLICKHOUSE_TEST_URL";
const CLICKHOUSE_USER_VAR: &str = "TIDEGARD_CLICKHOUSE_TEST_USER";
const CLICKHOUSE_PASSWORD_VAR: &str = "TIDEGARD_CLICKHOUSE_TEST_PASSWORD";

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

async fn token(client: &Client, tenant: &str, role: Role) -> String {
    // A token names a registered tenant (ADR 0060).
    tidegard_incident_postgres::tenants::ensure(client, tenant)
        .await
        .unwrap();
    token_admin::create(
        client,
        &NewToken {
            tenant: tenant.to_string(),
            actor_type: ActorType::Operator,
            actor_id: format!("{tenant}-{}", role.as_str()),
            role,
            lifetime_days: 1,
            description: String::new(),
        },
    )
    .await
    .unwrap()
    .secret
}

async fn get(app: &axum::Router, path: &str, token: &str) -> (StatusCode, Value) {
    let request = Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn traffic_is_read_from_clickhouse_for_the_traffic_tenant_only() {
    let (Some(postgres), Some(clickhouse_url)) = (
        std::env::var(POSTGRES_VAR).ok(),
        std::env::var(CLICKHOUSE_VAR).ok(),
    ) else {
        eprintln!(
            "skipping traffic: {POSTGRES_VAR} or {CLICKHOUSE_VAR} is not set. \
             This test needs real, ephemeral PostgreSQL and ClickHouse instances."
        );
        return;
    };
    let user = std::env::var(CLICKHOUSE_USER_VAR).unwrap_or_else(|_| "default".into());
    let password = std::env::var(CLICKHOUSE_PASSWORD_VAR).unwrap_or_default();

    // --- ClickHouse: the collector's schema and known rows ---
    let writer = tidegard_storage::Client::default()
        .with_url(&clickhouse_url)
        .with_user(&user)
        .with_password(&password);
    tidegard_storage::run_migrations(&writer)
        .await
        .expect("the collector's schema applies");
    for (table, _) in tidegard_storage::schema::CREATE_TABLE_STATEMENTS {
        writer
            .query(&format!("TRUNCATE TABLE {table}"))
            .execute()
            .await
            .unwrap();
    }
    // Ten minutes ago, aligned to a step boundary so one bucket holds both
    // families. Computed once here: two now() calls can straddle a boundary.
    let bucket = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 600;
    let bucket = bucket - bucket % 10;
    for statement in [
        format!(
            "INSERT INTO wetechinetmon_total_ipv4_traffic (timestamp, bytes, packets, flows) \
             VALUES (toDateTime({bucket}), 1000000, 2000, 10)"
        ),
        format!(
            "INSERT INTO wetechinetmon_total_ipv6_traffic (timestamp, bytes, packets, flows) \
             VALUES (toDateTime({bucket}), 500000, 1000, 5)"
        ),
    ] {
        writer.query(&statement).execute().await.unwrap();
    }
    for statement in [
        "INSERT INTO wetechinetmon_host_traffic (timestamp, address, family, bytes, packets, flows) VALUES \
         (now() - 300, '203.0.113.10', 4, 900, 9, 1), \
         (now() - 300, '203.0.113.20', 4, 700, 7, 1), \
         (now() - 200, '203.0.113.10', 4, 100, 1, 1), \
         (now() - 300, '203.0.113.30', 4, 100, 1, 1)",
        "INSERT INTO wetechinetmon_exporter_traffic (timestamp, exporter, bytes, packets, flows) VALUES \
         (now() - 60, '192.0.2.1', 30000, 300, 3), \
         (now() - 7200, '192.0.2.2', 1, 1, 1)",
    ] {
        writer.query(statement).execute().await.unwrap();
    }

    // --- PostgreSQL: tokens ---
    let mut admin = connect(&postgres).await;
    admin
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .unwrap();
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut admin)
        .await
        .unwrap();
    let viewer = token(&admin, "acme", Role::Viewer).await;
    let outsider = token(&admin, "globex", Role::NocLead).await;
    let (pool, _) = tidegard_incident_postgres::connect::connect(
        &postgres,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .unwrap();

    let password_file = std::env::temp_dir().join(format!("wnm-ch-test-{}", std::process::id()));
    std::fs::write(&password_file, &password).unwrap();
    let (scheme, host, port) = parse_url(&clickhouse_url).unwrap();
    let clickhouse = ClickHouse::new(Endpoint {
        scheme,
        host,
        port,
        user,
        password_file: Some(password_file.clone()),
        ca_file: None,
    })
    .unwrap();
    std::fs::remove_file(&password_file).unwrap();
    let app = router(AppState::new(pool).with_traffic(TrafficSource {
        tenant: TenantId::new("acme"),
        clickhouse,
    }));

    // --- Summary: one bucket, as rates per second ---
    let (status, summary) = get(&app, "/api/v1/traffic/summary", &viewer).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["step_seconds"], 10, "{summary}");
    let points = summary["points"].as_array().unwrap();
    assert_eq!(points.len(), 1, "{summary}");
    assert_eq!(
        points[0]["ipv4_bps"], 800_000.0,
        "1,000,000 bytes over 10 s"
    );
    assert_eq!(points[0]["ipv4_pps"], 200.0);
    assert_eq!(points[0]["ipv6_bps"], 400_000.0);
    assert_eq!(points[0]["ipv6_pps"], 100.0);

    // --- Top hosts: summed over the range, largest first, limited ---
    let (status, top) = get(&app, "/api/v1/traffic/top?dimension=host&limit=2", &viewer).await;
    assert_eq!(status, StatusCode::OK, "{top}");
    let keys: Vec<(&str, u64)> = top["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["key"].as_str().unwrap(),
                item["bytes"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(keys, vec![("203.0.113.10", 1000), ("203.0.113.20", 700)]);
    for bad in [
        "/api/v1/traffic/top?dimension=hosts",
        "/api/v1/traffic/top?dimension=host;DROP",
        "/api/v1/traffic/top?dimension=host&limit=0",
        "/api/v1/traffic/top?dimension=host&limit=51",
        "/api/v1/traffic/top",
        "/api/v1/traffic/summary?from=2026-01-01T00:00:00Z&to=2026-06-01T00:00:00Z",
        "/api/v1/traffic/summary?step=1",
    ] {
        let (status, problem) = get(&app, bad, &viewer).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {problem}");
    }

    // --- Exporters: last seen, silence, and the five-minute rate ---
    let (status, exporters) = get(&app, "/api/v1/exporters", &viewer).await;
    assert_eq!(status, StatusCode::OK, "{exporters}");
    let items = exporters["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{exporters}");
    assert_eq!(items[0]["exporter"], "192.0.2.1");
    assert_eq!(items[0]["bps"], 800.0, "30,000 bytes over 300 s");
    assert!(items[0]["silent_seconds"].as_i64().unwrap() < 600);
    assert_eq!(items[1]["exporter"], "192.0.2.2");
    assert_eq!(items[1]["bps"], 0.0, "nothing in the last five minutes");
    assert!(items[1]["silent_seconds"].as_i64().unwrap() >= 7_000);

    // --- Another tenant learns nothing ---
    for path in [
        "/api/v1/traffic/summary",
        "/api/v1/traffic/top?dimension=host",
        "/api/v1/exporters",
    ] {
        let (status, problem) = get(&app, path, &outsider).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {problem}");
    }
}
