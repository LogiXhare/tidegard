//! The collector's ClickHouse connection over TLS against a real server
//! (ADR 0053). CI's grafana job starts ClickHouse with an HTTPS port and
//! a certificate from a throwaway CA, and sets:
//!
//! - `TIDEGARD_CLICKHOUSE_TLS_TEST_URL`: `https://localhost:<port>`;
//! - `TIDEGARD_CLICKHOUSE_TLS_TEST_CA` and `_OTHER_CA`: the CA that
//!   signed the server's certificate, and one that did not;
//! - `TIDEGARD_CLICKHOUSE_TLS_TEST_USER` and `_PASSWORD_FILE`.
//!
//! Without them the test skips, and says so; the job fails if it does.

use std::path::PathBuf;

use tidegard_storage::{run_migrations, ClickHouseSettings};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[tokio::test]
async fn exports_over_verified_tls_with_credentials() {
    let Some(url) = env("TIDEGARD_CLICKHOUSE_TLS_TEST_URL") else {
        eprintln!(
            "skipping exports_over_verified_tls_with_credentials: \
             TIDEGARD_CLICKHOUSE_TLS_TEST_URL is not set"
        );
        return;
    };
    let ca = env("TIDEGARD_CLICKHOUSE_TLS_TEST_CA").expect("the CA is set");
    let other_ca = env("TIDEGARD_CLICKHOUSE_TLS_TEST_OTHER_CA").expect("the other CA is set");
    let user = env("TIDEGARD_CLICKHOUSE_TLS_TEST_USER").expect("the user is set");
    let password_file =
        env("TIDEGARD_CLICKHOUSE_TLS_TEST_PASSWORD_FILE").expect("the password file is set");
    let settings = |ca: &str, password_file: &str| ClickHouseSettings {
        url: url.clone(),
        user: Some(user.clone()),
        password_file: Some(PathBuf::from(password_file)),
        ca_file: Some(PathBuf::from(ca)),
    };

    // The right CA and credentials: the collector's own schema is created
    // over TLS, as at startup.
    let client = settings(&ca, &password_file)
        .connect()
        .expect("the client is built");
    run_migrations(&client)
        .await
        .expect("the migrations run over verified TLS");
    let tables: Vec<String> = client
        .query("SELECT name FROM system.tables WHERE database = currentDatabase() AND name LIKE 'wetechinetmon_%'")
        .fetch_all()
        .await
        .expect("the tables are listed over TLS");
    assert!(
        tables
            .iter()
            .any(|name| name == "wetechinetmon_host_traffic"),
        "{tables:?}"
    );

    // A server certificate the configured CA did not sign is refused.
    let client = settings(&other_ca, &password_file)
        .connect()
        .expect("the client is built");
    assert!(
        run_migrations(&client).await.is_err(),
        "a certificate from another CA must be refused"
    );

    // The right CA and the wrong password: ClickHouse refuses.
    let wrong = std::env::temp_dir().join(format!("wnm-ch-wrong-{}", std::process::id()));
    std::fs::write(&wrong, "not-the-password\n").unwrap();
    let client = settings(&ca, wrong.to_str().unwrap())
        .connect()
        .expect("the client is built");
    let refused = run_migrations(&client).await;
    std::fs::remove_file(&wrong).unwrap();
    assert!(refused.is_err(), "a wrong password must be refused");
}
