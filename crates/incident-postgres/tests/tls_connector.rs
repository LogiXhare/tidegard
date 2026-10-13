//! ADR 0023's TLS requirements against a real PostgreSQL server with TLS on:
//! - The production pool connects over TLS when the server's certificate
//!   chains to the trusted CA and names the host being connected to.
//! - A certificate from a CA the connector does not trust is refused.
//! - A certificate that does not name the host is refused, even from the
//!   trusted CA.
//! - A refused handshake is `Unavailable`, is not retried, and never falls
//!   back to plaintext.
//!
//! CI turns TLS on in the ephemeral service container with a throwaway CA
//! it generates per run, and passes the CA files as
//! `TIDEGARD_INCIDENT_POSTGRES_TEST_TLS_CA` and
//! `TIDEGARD_INCIDENT_POSTGRES_TEST_TLS_OTHER_CA`. The server
//! certificate names only `localhost`. Like the other PostgreSQL tests, this
//! skips with a message when a variable is unset, and CI fails on the skip.

use std::time::Duration;

use tidegard_incident_postgres::error::PersistError;
use tidegard_incident_postgres::pool::{acquire, PoolPolicy};
use tidegard_incident_postgres::tls::{build_tls_pool, TlsSettings};
use tokio_postgres::config::SslMode;
use tokio_postgres::Config;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";
const TRUSTED_CA_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_TLS_CA";
const OTHER_CA_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_TLS_OTHER_CA";

fn over_tls(base: &Config, host: &str) -> Config {
    let mut config = Config::new();
    config
        .host(host)
        .port(base.get_ports()[0])
        .user(base.get_user().expect("the test URL names a user"))
        .password(base.get_password().expect("the test URL has a password"))
        .dbname(base.get_dbname().expect("the test URL names a database"))
        .ssl_mode(SslMode::Require)
        .connect_timeout(Duration::from_secs(5));
    config
}

fn policy() -> PoolPolicy {
    PoolPolicy {
        max_size: 1,
        ..PoolPolicy::starting_default()
    }
}

async fn refused(config: Config, settings: &TlsSettings) -> PersistError {
    let pool = build_tls_pool(config, settings, policy()).expect("the settings are well formed");
    match acquire(&pool).await {
        Ok(_) => panic!("the handshake must be refused"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn tls_connections_verify_the_chain_and_the_host_name() {
    let mut values = Vec::new();
    for var in [TEST_DATABASE_URL_VAR, TRUSTED_CA_VAR, OTHER_CA_VAR] {
        let Ok(value) = std::env::var(var) else {
            eprintln!(
                "skipping tls_connector: {var} is not set. This test requires a real, \
                 ephemeral, local-or-CI-only PostgreSQL instance with TLS on — see \
                 crates/incident-postgres/README.md."
            );
            return;
        };
        values.push(value);
    }
    let base: Config = values[0]
        .parse()
        .expect("the test URL is a valid connection string");
    let trusted = TlsSettings::trusting(std::fs::read(&values[1]).expect("trusted CA file"));
    let other = TlsSettings::trusting(std::fs::read(&values[2]).expect("other CA file"));

    // --- Trusted chain, matching name: connected, and really over TLS ---
    let pool = build_tls_pool(over_tls(&base, "localhost"), &trusted, policy()).unwrap();
    let client = acquire(&pool).await.expect("a verified TLS connection");
    let row = client
        .query_one(
            "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            &[],
        )
        .await
        .unwrap();
    let (ssl, version): (bool, Option<String>) = (row.get(0), row.get(1));
    assert!(ssl, "the session is encrypted");
    assert!(
        matches!(version.as_deref(), Some("TLSv1.2" | "TLSv1.3")),
        "negotiated {version:?}"
    );
    drop(client);

    // --- A CA the connector does not trust ---
    let untrusted = refused(over_tls(&base, "localhost"), &other).await;
    assert!(
        matches!(untrusted, PersistError::Unavailable(_)),
        "got {untrusted:?}"
    );
    assert!(!untrusted.is_retryable());

    // --- The trusted CA, but the certificate does not name 127.0.0.1 ---
    let wrong_name = refused(over_tls(&base, "127.0.0.1"), &trusted).await;
    assert!(
        matches!(wrong_name, PersistError::Unavailable(_)),
        "got {wrong_name:?}"
    );
    assert!(!wrong_name.is_retryable());
}
