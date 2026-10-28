//! The single-mitigator lock (ADR 0052, review finding R-11). The lock
//! belongs to one database session: when that session ends, a standby
//! may take it, so the active mitigator must stop rather than act
//! alongside it.
//!
//! Needs `TIDEGARD_INCIDENT_POSTGRES_TEST_URL` (an ephemeral database
//! this test wipes). Without it the test says why and passes; CI sets it
//! and fails on the skip message. BGP stays off: no GoBGP is needed.

use std::time::Duration;

use tidegard_mitigator::config::{CONFIG_FILE_ENV_VAR, DATABASE_URL_ENV_VAR, METRICS_BIND_ENV_VAR};
use tidegard_mitigator::{Config, StartupError};
use tokio_postgres::NoTls;

const DATABASE_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

#[tokio::test]
async fn the_mitigator_stops_when_its_lock_is_lost() {
    let Some(url) = std::env::var(DATABASE_VAR).ok() else {
        eprintln!(
            "skipping mitigator_lock: {DATABASE_VAR} is not set. This test requires an \
             ephemeral PostgreSQL."
        );
        return;
    };
    let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .unwrap();
    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .unwrap();

    let dir = std::env::temp_dir().join(format!("tidegard-mitigator-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("mitigator.json");
    std::fs::write(
        &file,
        r#"{
          "routes": {
            "local_asn": 64512,
            "rtbh_next_hop_ipv4": "192.0.2.1",
            "rtbh_next_hop_ipv6": "2001:db8::1"
          },
          "gobgp": { "url": "http://127.0.0.1:50051" },
          "poll_interval_ms": 100
        }"#,
    )
    .unwrap();
    let file = file.to_str().unwrap().to_string();
    let config = Config::from_lookup(|var| match var {
        DATABASE_URL_ENV_VAR => Some(url.clone()),
        CONFIG_FILE_ENV_VAR => Some(file.clone()),
        METRICS_BIND_ENV_VAR => Some("127.0.0.1:0".to_string()),
        _ => None,
    })
    .unwrap();

    // Once the mitigator holds the lock, end the session that holds it,
    // as a database restart or failover would.
    let end_the_lock_session = async {
        for _ in 0..300 {
            let rows = client
                .query(
                    "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted",
                    &[],
                )
                .await
                .unwrap();
            if let Some(row) = rows.first() {
                let pid: i32 = row.get(0);
                client
                    .execute("SELECT pg_terminate_backend($1)", &[&pid])
                    .await
                    .unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the mitigator never took the lock");
    };
    let (outcome, ()) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(60),
            tidegard_mitigator::run(config, std::future::pending()),
        ),
        end_the_lock_session,
    );
    let _ = std::fs::remove_dir_all(&dir);
    let result = outcome.expect("the mitigator kept running without its lock");
    assert!(matches!(result, Err(StartupError::LockLost)), "{result:?}");
}
