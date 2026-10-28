//! Phase 8A (ADR 0060): the tenant registry and prefix ownership against
//! a real PostgreSQL.
//!
//! - An upgrade from V21 registers every tenant id already in use, from
//!   any table that carries one, and never `platform`.
//! - The database itself refuses overlapping prefixes, in one tenant or
//!   two, a claim wider than `/8` or `/16`, a tenant named `platform`, and
//!   a token for an unregistered tenant.
//!
//! Needs `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`, an ephemeral database
//! this test wipes. Without it the test says why and passes; CI sets it and
//! fails on the skip message. One test function, because it resets the
//! `public` schema.

use std::net::IpAddr;

use tidegard_incident_postgres::tenants::{self, RegistryError, TenantStatus};
use tidegard_mitigation::Prefix;
use tokio_postgres::Client;

const TEST_DATABASE_URL_VAR: &str = "TIDEGARD_INCIDENT_POSTGRES_TEST_URL";

fn prefix(text: &str) -> Prefix {
    text.parse().unwrap()
}

async fn count(client: &Client, sql: &str) -> i64 {
    client.query_one(sql, &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn the_registry_upgrades_in_place_and_refuses_overlaps() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping tenant_registry: {TEST_DATABASE_URL_VAR} is not set. This test requires \
             a real, ephemeral, local-or-CI-only PostgreSQL instance."
        );
        return;
    };
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .await
        .unwrap();

    // --- A v1.0.0 database: tenants exist only as ids on rows ---
    tidegard_incident_postgres::migrations::migrations::runner()
        .set_target(refinery::Target::Version(21))
        .run_async(&mut client)
        .await
        .unwrap();
    client
        .batch_execute(
            "INSERT INTO api_tokens (
                token_id, tenant_id, actor_type, actor_id, role, token_hash, expires_at
             ) VALUES
                (gen_random_uuid(), 'acme', 'operator', 'alice', 'viewer',
                 decode(repeat('11', 32), 'hex'), now() + interval '1 day'),
                (gen_random_uuid(), 'acme', 'operator', 'bob', 'viewer',
                 decode(repeat('22', 32), 'hex'), now() + interval '1 day');
             -- Any table with a tenant_id counts, and `platform` never does.
             CREATE TABLE legacy_rows (tenant_id TEXT NOT NULL);
             INSERT INTO legacy_rows VALUES ('globex'), ('platform'), ('globex');",
        )
        .await
        .unwrap();

    tidegard_incident_postgres::migrations::migrations::runner()
        .run_async(&mut client)
        .await
        .unwrap();
    client
        .batch_execute("DROP TABLE legacy_rows")
        .await
        .unwrap();

    let registered = tenants::list(&client).await.unwrap();
    let ids: Vec<&str> = registered.iter().map(|t| t.tenant_id.as_str()).collect();
    assert_eq!(ids, ["acme", "globex"]);
    for tenant in &registered {
        assert_eq!(tenant.display_name, tenant.tenant_id);
        assert_eq!(tenant.status, TenantStatus::Active);
    }

    // --- Tenants: created once, never `platform` ---
    let initech = tenants::create(&client, "initech", "Initech Ltd")
        .await
        .unwrap();
    assert_eq!(initech.display_name, "Initech Ltd");
    assert!(matches!(
        tenants::create(&client, "initech", "Again").await,
        Err(RegistryError::Exists(id)) if id == "initech"
    ));
    assert!(matches!(
        tenants::create(&client, "platform", "Platform").await,
        Err(RegistryError::InvalidId)
    ));
    assert!(
        client
            .execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ('platform', 'p')",
                &[],
            )
            .await
            .is_err(),
        "the table refuses `platform` whatever the application does"
    );
    assert!(!tenants::ensure(&client, "initech").await.unwrap());
    assert!(tenants::ensure(&client, "umbrella").await.unwrap());
    assert_eq!(
        tenants::get(&client, "umbrella")
            .await
            .unwrap()
            .unwrap()
            .display_name,
        "umbrella"
    );
    assert!(tenants::get(&client, "nobody").await.unwrap().is_none());

    // --- Status: suspend and reactivate ---
    let suspended = tenants::set_status(&client, "globex", TenantStatus::Suspended)
        .await
        .unwrap();
    assert_eq!(suspended.status, TenantStatus::Suspended);
    let again = tenants::set_status(&client, "globex", TenantStatus::Suspended)
        .await
        .unwrap();
    assert_eq!(
        again.updated_at, suspended.updated_at,
        "setting the same status changes nothing"
    );
    tenants::set_status(&client, "globex", TenantStatus::Active)
        .await
        .unwrap();
    assert!(matches!(
        tenants::set_status(&client, "nobody", TenantStatus::Active).await,
        Err(RegistryError::NoSuchTenant(_))
    ));

    // --- Prefixes: one owner, no overlap anywhere ---
    tenants::add_prefix(&client, "acme", prefix("192.0.2.0/24"))
        .await
        .unwrap();
    tenants::add_prefix(&client, "acme", prefix("2001:db8:a::/48"))
        .await
        .unwrap();
    tenants::add_prefix(&client, "globex", prefix("198.51.100.0/24"))
        .await
        .unwrap();
    tenants::add_prefix(&client, "globex", prefix("2001:db8:b::/48"))
        .await
        .unwrap();
    for (tenant, inside, existing, owner) in [
        ("globex", "192.0.2.128/25", "192.0.2.0/24", "acme"),
        ("acme", "192.0.2.0/24", "192.0.2.0/24", "acme"),
        ("acme", "192.0.2.7/32", "192.0.2.0/24", "acme"),
        ("initech", "198.51.0.0/16", "198.51.100.0/24", "globex"),
        ("initech", "2001:db8::/32", "2001:db8:a::/48", "acme"),
    ] {
        match tenants::add_prefix(&client, tenant, prefix(inside)).await {
            Err(RegistryError::Overlaps {
                prefix: refused,
                existing: found,
                owner: named,
            }) => {
                assert_eq!(refused, prefix(inside));
                assert_eq!(found, prefix(existing), "{inside}");
                assert_eq!(named, owner, "{inside}");
            }
            other => panic!("{tenant} {inside}: expected an overlap, got {other:?}"),
        }
    }
    assert!(
        client
            .execute(
                "INSERT INTO tenant_prefixes (prefix, tenant_id) VALUES ('192.0.2.64/26', 'globex')",
                &[],
            )
            .await
            .is_err(),
        "the table refuses an overlap whatever the application does"
    );
    for wide in ["8.0.0.0/7", "2000::/15"] {
        assert!(matches!(
            tenants::add_prefix(&client, "initech", prefix(wide)).await,
            Err(RegistryError::TooWide(_))
        ));
        assert!(
            client
                .execute(
                    "INSERT INTO tenant_prefixes (prefix, tenant_id) VALUES ($1::text::cidr, 'initech')",
                    &[&wide],
                )
                .await
                .is_err(),
            "the table refuses {wide}"
        );
    }
    assert!(matches!(
        tenants::add_prefix(&client, "nobody", prefix("203.0.113.0/24")).await,
        Err(RegistryError::NoSuchTenant(_))
    ));

    assert_eq!(
        tenants::prefixes(&client, "acme").await.unwrap(),
        [prefix("192.0.2.0/24"), prefix("2001:db8:a::/48")]
    );
    let owner = |address: &str| {
        let client = &client;
        let address: IpAddr = address.parse().unwrap();
        async move {
            tenants::owner_of(client, address)
                .await
                .unwrap()
                .map(|found| (found.tenant_id, found.prefix.to_string()))
        }
    };
    assert_eq!(
        owner("192.0.2.200").await,
        Some(("acme".into(), "192.0.2.0/24".into()))
    );
    assert_eq!(
        owner("2001:db8:b::1").await,
        Some(("globex".into(), "2001:db8:b::/48".into()))
    );
    assert_eq!(owner("203.0.113.1").await, None);
    assert_eq!(tenants::ownership(&client).await.unwrap().len(), 4);

    // --- Removing: only the owner's own row ---
    assert!(
        !tenants::remove_prefix(&client, "globex", prefix("192.0.2.0/24"))
            .await
            .unwrap()
    );
    assert!(
        tenants::remove_prefix(&client, "acme", prefix("192.0.2.0/24"))
            .await
            .unwrap()
    );
    tenants::add_prefix(&client, "globex", prefix("192.0.2.128/25"))
        .await
        .unwrap();
    assert_eq!(owner("192.0.2.200").await.unwrap().0, "globex");

    // --- A token names a registered tenant ---
    assert!(
        client
            .execute(
                "INSERT INTO api_tokens (
                    token_id, tenant_id, actor_type, actor_id, role, token_hash, expires_at
                 ) VALUES (gen_random_uuid(), 'nobody', 'operator', 'eve', 'viewer',
                           decode(repeat('33', 32), 'hex'), now() + interval '1 day')",
                &[],
            )
            .await
            .is_err(),
        "a token for an unregistered tenant is refused"
    );
    assert_eq!(count(&client, "SELECT count(*) FROM api_tokens").await, 2);
}
