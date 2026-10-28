//! Milestone 5D-2: API tokens against PostgreSQL (ADR 0038, gate 4).
//! - An issued token authenticates as its tenant, actor and role.
//! - Only the hash is stored; listing never shows a secret.
//! - A wrong, revoked or expired token is refused the same way.
//! - The table itself refuses `platform_admin`, an unbounded lifetime and a
//!   short hash, whatever the application does.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

use tidegard_api::auth::{
    token_hash, AuthError, Authenticator, Principal, Role, TokenAuthenticator,
};
use tidegard_api::token_admin::{self, ActorType, NewToken};
use tidegard_incident::authorization::Actor;
use tidegard_incident::correlation::TenantId;
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::tenants::{self, TenantStatus};
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

fn alice(role: Role) -> NewToken {
    NewToken {
        tenant: "acme".to_string(),
        actor_type: ActorType::Operator,
        actor_id: "alice".to_string(),
        role,
        lifetime_days: 30,
        description: "laptop".to_string(),
    }
}

#[tokio::test]
async fn issued_tokens_authenticate_until_revoked_or_expired() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping token_auth: {TEST_DATABASE_URL_VAR} is not set. \
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
    let (pool, _) = tidegard_incident_postgres::connect::connect(
        &url,
        None,
        PoolPolicy {
            max_size: 2,
            ..PoolPolicy::starting_default()
        },
    )
    .expect("a loopback test database");
    let authenticator = TokenAuthenticator::new(pool);

    // --- A token names a registered tenant (ADR 0060) ---
    assert!(matches!(
        token_admin::create(&admin, &alice(Role::Operator)).await,
        Err(token_admin::AdminError::UnknownTenant(tenant)) if tenant == "acme"
    ));
    tenants::create(&admin, "acme", "Acme").await.unwrap();

    // --- Issue: the secret authenticates; only its hash is stored ---
    let issued = token_admin::create(&admin, &alice(Role::Operator))
        .await
        .unwrap();
    let principal = authenticator.authenticate(&issued.secret).await.unwrap();
    assert_eq!(
        principal,
        Principal {
            tenant: TenantId::new("acme"),
            actor: Actor::Operator {
                id: "alice".to_string()
            },
            role: Role::Operator,
        }
    );
    let stored: Vec<u8> = admin
        .query_one("SELECT token_hash FROM api_tokens", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, token_hash(&issued.secret));
    let dump: String = admin
        .query_one("SELECT row_to_json(t)::text FROM api_tokens t", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        !dump.contains(&issued.secret[4..]),
        "the secret is stored nowhere"
    );

    // --- A suspended tenant's token is refused, and works again on
    // reactivation (ADR 0060) ---
    tenants::set_status(&admin, "acme", TenantStatus::Suspended)
        .await
        .unwrap();
    assert_eq!(
        authenticator.authenticate(&issued.secret).await,
        Err(AuthError::Rejected)
    );
    tenants::set_status(&admin, "acme", TenantStatus::Active)
        .await
        .unwrap();
    assert!(authenticator.authenticate(&issued.secret).await.is_ok());

    // --- A wrong token, even well-formed, is refused ---
    let mut wrong = issued.secret.clone();
    wrong.replace_range(10..11, if &wrong[10..11] == "0" { "1" } else { "0" });
    assert_eq!(
        authenticator.authenticate(&wrong).await,
        Err(AuthError::Rejected)
    );

    // --- Listing shows the token but no secret ---
    let listed = token_admin::list(&admin, "acme").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].token_id, issued.token_id);
    assert_eq!(listed[0].revoked_at, None);
    assert!(token_admin::list(&admin, "globex")
        .await
        .unwrap()
        .is_empty());

    // --- Revoked: refused, and revoking again changes nothing ---
    assert!(token_admin::revoke(&admin, &issued.token_id).await.unwrap());
    assert!(!token_admin::revoke(&admin, &issued.token_id).await.unwrap());
    assert_eq!(
        authenticator.authenticate(&issued.secret).await,
        Err(AuthError::Rejected)
    );

    // --- Expired: refused ---
    let expiring = token_admin::create(&admin, &alice(Role::Viewer))
        .await
        .unwrap();
    assert!(authenticator.authenticate(&expiring.secret).await.is_ok());
    admin
        .execute(
            "UPDATE api_tokens SET created_at = created_at - interval '2 days',
                                   expires_at = created_at - interval '1 day'
             WHERE token_id = $1::text::uuid",
            &[&expiring.token_id],
        )
        .await
        .unwrap();
    assert_eq!(
        authenticator.authenticate(&expiring.secret).await,
        Err(AuthError::Rejected)
    );

    // --- The application refuses an out-of-range lifetime ---
    let mut too_long = alice(Role::Viewer);
    too_long.lifetime_days = 367;
    assert!(matches!(
        token_admin::create(&admin, &too_long).await,
        Err(token_admin::AdminError::Lifetime(367))
    ));

    // --- The table refuses what the application never sends ---
    for (role, days, hash_len) in [
        ("platform_admin", 30, 32),
        ("operator", 400, 32),
        ("operator", 30, 16),
    ] {
        let refused = admin
            .execute(
                "INSERT INTO api_tokens
                     (token_id, tenant_id, actor_type, actor_id, role, token_hash, expires_at)
                 VALUES (gen_random_uuid(), 'acme', 'operator', 'mallory', $1,
                         decode(repeat('ab', $3), 'hex'),
                         transaction_timestamp() + $2::integer * interval '1 day')",
                &[&role, &days, &hash_len],
            )
            .await;
        assert!(
            refused.is_err(),
            "{role} / {days} days / {hash_len}-byte hash"
        );
    }

    // --- Platform tokens (ADR 0060): a provider role, no tenant, at most
    // 90 days ---
    let provider = token_admin::NewPlatformToken {
        actor_type: ActorType::Operator,
        actor_id: "nora".to_string(),
        role: Role::NocAdmin,
        lifetime_days: 90,
        description: String::new(),
    };
    let issued = token_admin::create_platform(&admin, &provider)
        .await
        .unwrap();
    assert_eq!(
        authenticator.authenticate(&issued.secret).await.unwrap(),
        Principal {
            tenant: TenantId::new(tidegard_api::auth::PLATFORM_TENANT),
            actor: Actor::Operator {
                id: "nora".to_string()
            },
            role: Role::NocAdmin,
        }
    );
    let listed = token_admin::list_platform(&admin).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].role, "noc_admin");
    assert!(
        token_admin::list(&admin, "acme")
            .await
            .unwrap()
            .iter()
            .all(|token| token.token_id != issued.token_id),
        "a platform token is in no tenant's list"
    );
    // Suspending a tenant does not touch a platform token.
    tenants::set_status(&admin, "acme", TenantStatus::Suspended)
        .await
        .unwrap();
    assert!(authenticator.authenticate(&issued.secret).await.is_ok());
    tenants::set_status(&admin, "acme", TenantStatus::Active)
        .await
        .unwrap();

    // --- The application keeps each role in its scope ---
    assert!(matches!(
        token_admin::create_platform(
            &admin,
            &token_admin::NewPlatformToken {
                lifetime_days: 91,
                ..provider.clone()
            }
        )
        .await,
        Err(token_admin::AdminError::PlatformLifetime(91))
    ));
    assert!(matches!(
        token_admin::create_platform(
            &admin,
            &token_admin::NewPlatformToken {
                role: Role::NocLead,
                ..provider.clone()
            }
        )
        .await,
        Err(token_admin::AdminError::WrongScope(Role::NocLead))
    ));
    assert!(matches!(
        token_admin::create(&admin, &alice(Role::SuperAdmin)).await,
        Err(token_admin::AdminError::WrongScope(Role::SuperAdmin))
    ));
    assert!(matches!(
        token_admin::create(&admin, &alice(Role::Automation)).await,
        Err(token_admin::AdminError::AutomationIsAService)
    ));
    let robot = token_admin::create(
        &admin,
        &NewToken {
            actor_type: ActorType::ServiceAccount,
            actor_id: "soar".to_string(),
            ..alice(Role::Automation)
        },
    )
    .await
    .unwrap();
    assert_eq!(
        authenticator
            .authenticate(&robot.secret)
            .await
            .unwrap()
            .role,
        Role::Automation
    );

    // --- And so does the table ---
    for (scope, tenant, role, actor_type, days) in [
        ("tenant", Some("acme"), "noc_admin", "operator", 30),
        ("platform", None, "noc_lead", "operator", 30),
        ("platform", Some("acme"), "noc_admin", "operator", 30),
        ("tenant", None, "viewer", "operator", 30),
        ("platform", None, "noc_admin", "operator", 91),
        ("tenant", Some("acme"), "automation", "operator", 30),
        ("other", None, "noc_admin", "operator", 30),
    ] {
        let refused = admin
            .execute(
                "INSERT INTO api_tokens
                     (token_id, tenant_id, actor_type, actor_id, role, token_hash, expires_at, scope)
                 VALUES (gen_random_uuid(), $2, $4, 'mallory', $3,
                         decode(repeat('cd', 32), 'hex'),
                         transaction_timestamp() + $5::integer * interval '1 day', $1)",
                &[&scope, &tenant, &role, &actor_type, &days],
            )
            .await;
        assert!(
            refused.is_err(),
            "{scope} / {tenant:?} / {role} / {actor_type} / {days} days"
        );
    }
}
