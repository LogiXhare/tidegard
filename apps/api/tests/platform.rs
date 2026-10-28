//! Phase 8A-3 (ADR 0060): the tenant registry and a tenant's tokens over
//! the API, against PostgreSQL.
//!
//! - Only platform roles reach `/platform/*`; only `platform.tenant.admin`
//!   changes anything there.
//! - The database's rules come back as problems that name what is wrong.
//! - A provider onboards a tenant's first `customer_admin`, who then
//!   manages the tenant's tokens, and nobody else's.
//! - Every change is on the tenant's audit trail.
//!
//! Like the other PostgreSQL tests, this only connects to the opt-in,
//! ephemeral database named by `TIDEGARD_INCIDENT_POSTGRES_TEST_URL`,
//! skips with a message when it is unset, and fails CI if it skips there
//! (FU-46). One test function, because it resets the `public` schema.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use tidegard_api::auth::{Role, TENANT_HEADER};
use tidegard_api::token_admin::{self, ActorType, NewPlatformToken, NewToken};
use tidegard_api::{router, AppState};
use tidegard_incident_postgres::pool::PoolPolicy;
use tidegard_incident_postgres::tenants;
use tokio_postgres::Client;
use tower::ServiceExt;

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

async fn platform_token(client: &Client, id: &str, role: Role) -> String {
    token_admin::create_platform(
        client,
        &NewPlatformToken {
            actor_type: ActorType::Operator,
            actor_id: id.to_string(),
            role,
            lifetime_days: 1,
            description: String::new(),
        },
    )
    .await
    .unwrap()
    .secret
}

async fn tenant_token(client: &Client, tenant: &str, id: &str, role: Role) -> String {
    tenants::ensure(client, tenant).await.unwrap();
    token_admin::create(
        client,
        &NewToken {
            tenant: tenant.to_string(),
            actor_type: ActorType::Operator,
            actor_id: id.to_string(),
            role,
            lifetime_days: 1,
            description: String::new(),
        },
    )
    .await
    .unwrap()
    .secret
}

async fn call(
    app: &axum::Router,
    method: Method,
    path: &str,
    token: &str,
    tenant: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(tenant) = tenant {
        request = request.header(TENANT_HEADER, tenant);
    }
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn the_registry_and_tokens_over_the_api() {
    let Some(url) = std::env::var(TEST_DATABASE_URL_VAR).ok() else {
        eprintln!(
            "skipping platform: {TEST_DATABASE_URL_VAR} is not set. \
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
            max_size: 4,
            ..PoolPolicy::starting_default()
        },
    )
    .expect("a loopback test database");
    let app = router(AppState::new(pool));

    let lead = tenant_token(&admin, "acme", "acme-lead", Role::NocLead).await;
    let globex = tenant_token(&admin, "globex", "globex-lead", Role::NocLead).await;
    let nora = platform_token(&admin, "nora", Role::NocOperator).await;
    let pat = platform_token(&admin, "pat", Role::PlatformAdmin).await;

    // --- Only platform roles read the registry; only platform.tenant.admin
    // changes it ---
    let (status, body) = call(
        &app,
        Method::GET,
        "/api/v1/platform/tenants",
        &lead,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "api.forbidden");
    let (status, body) = call(
        &app,
        Method::GET,
        "/api/v1/platform/tenants",
        &nora,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids: Vec<&str> = body["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["tenant_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["acme", "globex"]);
    let initech = json!({"tenant_id": "initech", "display_name": "Initech Ltd"});
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/v1/platform/tenants",
        &nora,
        None,
        Some(initech.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a noc_operator registers nothing"
    );

    // --- Registering tenants ---
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/v1/platform/tenants",
        &pat,
        None,
        Some(initech.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["display_name"], "Initech Ltd");
    assert_eq!(body["status"], "active");
    for (tenant, code, error) in [
        (initech.clone(), StatusCode::CONFLICT, "tenant.exists"),
        (
            json!({"tenant_id": "platform"}),
            StatusCode::UNPROCESSABLE_ENTITY,
            "tenant.invalid",
        ),
        (
            json!({"tenant_id": ""}),
            StatusCode::UNPROCESSABLE_ENTITY,
            "tenant.invalid",
        ),
    ] {
        let (status, body) = call(
            &app,
            Method::POST,
            "/api/v1/platform/tenants",
            &pat,
            None,
            Some(tenant.clone()),
        )
        .await;
        assert_eq!(status, code, "{tenant}: {body}");
        assert_eq!(body["error"], error, "{tenant}");
    }

    // --- Prefixes: one owner, no overlap, nothing too wide ---
    let prefixes = "/api/v1/platform/tenants/acme/prefixes";
    for prefix in ["192.0.2.0/24", "2001:db8:a::/48"] {
        let (status, body) = call(
            &app,
            Method::POST,
            prefixes,
            &pat,
            None,
            Some(json!({"prefix": prefix})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["tenant_id"], "acme");
    }
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/v1/platform/tenants/globex/prefixes",
        &pat,
        None,
        Some(json!({"prefix": "192.0.2.128/25"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "tenant.prefix_overlap");
    assert_eq!(body["existing"], "192.0.2.0/24");
    assert_eq!(body["owner"], "acme");
    for (path, prefix, code, error) in [
        (
            prefixes,
            "8.0.0.0/7",
            StatusCode::UNPROCESSABLE_ENTITY,
            "tenant.invalid",
        ),
        (
            prefixes,
            "192.0.2.1/24",
            StatusCode::UNPROCESSABLE_ENTITY,
            "tenant.invalid",
        ),
        (
            prefixes,
            "not a prefix",
            StatusCode::UNPROCESSABLE_ENTITY,
            "tenant.invalid",
        ),
        (
            "/api/v1/platform/tenants/nobody/prefixes",
            "203.0.113.0/24",
            StatusCode::NOT_FOUND,
            "tenant.not_found",
        ),
    ] {
        let (status, body) = call(
            &app,
            Method::POST,
            path,
            &pat,
            None,
            Some(json!({"prefix": prefix})),
        )
        .await;
        assert_eq!(status, code, "{prefix}: {body}");
        assert_eq!(body["error"], error, "{prefix}");
    }
    let (status, body) = call(
        &app,
        Method::GET,
        "/api/v1/platform/tenants/acme",
        &nora,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["prefixes"], json!(["192.0.2.0/24", "2001:db8:a::/48"]));
    let (status, _) = call(
        &app,
        Method::GET,
        "/api/v1/platform/tenants/nobody",
        &nora,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let remove = "/api/v1/platform/tenants/acme/prefixes/2001:db8:a::/48";
    let (status, _) = call(&app, Method::DELETE, remove, &pat, None, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = call(&app, Method::DELETE, remove, &pat, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "tenant.prefix_not_found");

    // --- Suspension takes effect at once ---
    let suspend = "/api/v1/platform/tenants/acme/suspend";
    let (status, body) = call(&app, Method::POST, suspend, &pat, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "suspended");
    let (status, _) = call(&app, Method::GET, "/api/v1/incidents", &lead, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, Method::POST, suspend, &pat, None, None).await;
    assert_eq!(status, StatusCode::OK, "suspending again changes nothing");
    let (status, _) = call(
        &app,
        Method::POST,
        "/api/v1/platform/tenants/acme/activate",
        &pat,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&app, Method::GET, "/api/v1/incidents", &lead, None, None).await;
    assert_eq!(status, StatusCode::OK);

    // --- A provider onboards a customer_admin; it manages its own tenant's
    // tokens ---
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/v1/tokens",
        &pat,
        Some("acme"),
        Some(json!({"actor_id": "carol", "role": "customer_admin", "lifetime_days": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let carol = body["token"].as_str().unwrap().to_string();
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/v1/tokens",
        &carol,
        None,
        Some(json!({"actor_id": "dave", "role": "operator", "lifetime_days": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let dave = body["token"].as_str().unwrap().to_string();
    let dave_id = body["token_id"].as_str().unwrap().to_string();
    let (status, _) = call(&app, Method::GET, "/api/v1/incidents", &dave, None, None).await;
    assert_eq!(status, StatusCode::OK);
    for (request, code, error) in [
        (
            json!({"actor_id": "eve", "role": "noc_admin"}),
            StatusCode::UNPROCESSABLE_ENTITY,
            "token.invalid",
        ),
        (
            json!({"actor_id": "eve", "role": "automation"}),
            StatusCode::UNPROCESSABLE_ENTITY,
            "token.invalid",
        ),
        (
            json!({"actor_id": "eve", "role": "viewer", "lifetime_days": 400}),
            StatusCode::UNPROCESSABLE_ENTITY,
            "token.invalid",
        ),
        (
            json!({"actor_id": "eve", "role": "root"}),
            StatusCode::UNPROCESSABLE_ENTITY,
            "token.invalid",
        ),
    ] {
        let (status, body) = call(
            &app,
            Method::POST,
            "/api/v1/tokens",
            &carol,
            None,
            Some(request.clone()),
        )
        .await;
        assert_eq!(status, code, "{request}: {body}");
        assert_eq!(body["error"], error, "{request}");
    }
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/v1/tokens",
        &carol,
        None,
        Some(json!({"actor_id": "soar", "role": "automation", "actor_type": "service_account"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    // A lead without tenant.token.admin, and a tenant naming another.
    let (status, _) = call(&app, Method::GET, "/api/v1/tokens", &lead, None, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &app,
        Method::GET,
        "/api/v1/tokens",
        &carol,
        Some("globex"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = call(&app, Method::GET, "/api/v1/tokens", &carol, None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Vec<&str> = body["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["actor_id"].as_str().unwrap())
        .collect();
    assert!(
        listed.contains(&"dave") && listed.contains(&"acme-lead"),
        "{listed:?}"
    );
    assert!(!listed.contains(&"globex-lead"), "{listed:?}");
    assert!(
        !body.to_string().contains(&dave[4..]),
        "no secret is listed"
    );

    // --- Revoking: the tenant's own live tokens only ---
    let globex_id: String = admin
        .query_one(
            "SELECT token_id::text FROM api_tokens WHERE actor_id = 'globex-lead'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    for id in [
        globex_id.as_str(),
        "not-a-uuid",
        "0192f3c4-0000-7000-8000-000000000009",
    ] {
        let (status, body) = call(
            &app,
            Method::POST,
            &format!("/api/v1/tokens/{id}/revoke"),
            &carol,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{id}");
        assert_eq!(body["error"], "token.not_found");
    }
    let (status, _) = call(&app, Method::GET, "/api/v1/incidents", &globex, None, None).await;
    assert_eq!(status, StatusCode::OK, "globex's token is untouched");
    let revoke = format!("/api/v1/tokens/{dave_id}/revoke");
    let (status, _) = call(&app, Method::POST, &revoke, &carol, None, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(&app, Method::GET, "/api/v1/incidents", &dave, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, Method::POST, &revoke, &carol, None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "already revoked");

    // --- Every change is on the tenant's own audit trail, by who made it ---
    let rows = admin
        .query(
            "SELECT action, actor_id, resource_type FROM incident_audit \
             WHERE tenant_id = 'acme' ORDER BY audit_id",
            &[],
        )
        .await
        .unwrap();
    let trail: Vec<(String, String, String)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let expected = [
        ("tenant.prefix.add", "pat", "tenant_prefix"),
        ("tenant.prefix.add", "pat", "tenant_prefix"),
        ("tenant.prefix.remove", "pat", "tenant_prefix"),
        ("tenant.suspend", "pat", "tenant"),
        ("tenant.activate", "pat", "tenant"),
        ("token.create", "pat", "api_token"),
        ("token.create", "carol", "api_token"),
        ("token.create", "carol", "api_token"),
        ("token.revoke", "carol", "api_token"),
    ];
    assert_eq!(
        trail,
        expected
            .iter()
            .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
            .collect::<Vec<_>>()
    );
    let created: i64 = admin
        .query_one(
            "SELECT count(*) FROM incident_audit WHERE tenant_id = 'initech' AND action = 'tenant.create'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(created, 1);
    let secrets: i64 = admin
        .query_one(
            "SELECT count(*) FROM incident_audit WHERE after::text LIKE '%wnm_%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(secrets, 0, "no secret is audited");
}
