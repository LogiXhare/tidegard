//! Thin binary entry point; the logic is in the library so tests can run
//! it in-process.

use tidegard_api::server::{bind, Bound};
use tidegard_api::{config::Config, router, AppState};

#[tokio::main]
async fn main() {
    tidegard_common::logging::init();

    let config = Config::from_env().unwrap_or_else(|error| {
        tracing::error!(error = %error, "invalid configuration");
        std::process::exit(1);
    });
    let (pool, transport) = tidegard_incident_postgres::connect::connect(
        &config.database_url,
        config.database_tls.as_ref(),
        config.pool,
    )
    .unwrap_or_else(|error| {
        tracing::error!(error = %error, "the incident database cannot be used");
        std::process::exit(1);
    });

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("token") {
        std::process::exit(token_command(&pool, &args[1..]).await);
    }
    if args.first().map(String::as_str) == Some("kill-switch") {
        std::process::exit(kill_switch_command(&pool, &args[1..]).await);
    }
    if args.first().map(String::as_str) == Some("tenant") {
        std::process::exit(tenant_command(&pool, &args[1..]).await);
    }

    let listener = bind(config.bind, config.tls.as_ref())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "the API cannot listen");
            std::process::exit(1);
        });
    tracing::info!(
        bind = %config.bind,
        tls = config.tls.is_some(),
        database_transport = ?transport,
        "starting tidegard-api"
    );

    let mut state = AppState::new(pool);
    if let Some(root) = &config.web_root {
        let web = tidegard_api::web::WebRoot::new(root).unwrap_or_else(|error| {
            tracing::error!(error = %error, "the NOC UI cannot be served");
            std::process::exit(1);
        });
        tracing::info!(web_root = %root.display(), "serving the NOC UI");
        state = state.with_web(web);
    }
    // A plain-HTTP API is loopback-only (ADR 0038), where a Secure cookie
    // would not always be kept.
    state.secure_cookies = config.tls.is_some();
    if let Some(traffic) = &config.traffic {
        let clickhouse = tidegard_api::clickhouse::ClickHouse::new(traffic.clickhouse.clone())
            .unwrap_or_else(|error| {
                tracing::error!(error = %error, "traffic cannot be served");
                std::process::exit(1);
            });
        tracing::info!(
            tenant = %traffic.tenant,
            clickhouse_host = %traffic.clickhouse.host,
            "serving traffic to one tenant"
        );
        state = state.with_traffic(tidegard_api::traffic::TrafficSource {
            tenant: tidegard_incident::correlation::TenantId::new(&traffic.tenant),
            clickhouse,
        });
    }
    if let Some(path) = &config.mitigation_guard_file {
        let guard = std::fs::read_to_string(path)
            .map_err(|error| error.to_string())
            .and_then(|text| {
                serde_json::from_str::<tidegard_mitigation::GuardConfig>(&text)
                    .map_err(|error| error.to_string())
            })
            .and_then(|config| {
                tidegard_mitigation::Guard::new(config).map_err(|error| error.to_string())
            })
            .unwrap_or_else(|error| {
                tracing::error!(error = %error, "the mitigation guard file is invalid");
                std::process::exit(1);
            });
        tracing::info!(
            allowlisted = guard.config().allowlist.len(),
            "checking mitigation requests against the guard file"
        );
        state = state.with_guard(guard);
    }
    let app = router(state).into_make_service_with_connect_info::<tidegard_api::server::PeerAddr>();
    let served = match listener {
        Bound::Plain(tcp) => {
            axum::serve(tcp, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
        }
        Bound::Tls(tls) => {
            axum::serve(tls, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
        }
    };
    if let Err(error) = served {
        tracing::error!(error = %error, "the API stopped with an error");
        std::process::exit(1);
    }
    tracing::info!("tidegard-api stopped");
}

/// Ctrl+C, or SIGTERM on Unix (what systemd and containers send).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

const KILL_SWITCH_USAGE: &str = "\
usage:
  tidegard-api kill-switch status
  tidegard-api kill-switch engage --actor-id ID --reason TEXT
  tidegard-api kill-switch release --actor-id ID --reason TEXT
Releasing is host-only: no API token can turn the kill switch off.";

/// `tidegard-api kill-switch ...`: the break-glass path on the API
/// host (ADR 0050). Audited under the given actor id.
async fn kill_switch_command(pool: &deadpool_postgres::Pool, args: &[String]) -> i32 {
    let flag = |name: &str| {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
    };
    let mut client = match tidegard_incident_postgres::pool::acquire(pool).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!("the incident database cannot be reached: {error}");
            return 1;
        }
    };
    let store = AppState::new(pool.clone()).mitigations;
    let engaged = match args.first().map(String::as_str) {
        Some("status") => None,
        Some("engage") => Some(true),
        Some("release") => Some(false),
        _ => {
            eprintln!("{KILL_SWITCH_USAGE}");
            return 2;
        }
    };
    let result = match engaged {
        None => store.kill_switch(&**client).await,
        Some(engaged) => {
            let (Some(actor_id), Some(reason)) = (flag("--actor-id"), flag("--reason")) else {
                eprintln!("{KILL_SWITCH_USAGE}");
                return 2;
            };
            let ctx = tidegard_api::mitigations::host_admin_context(&actor_id);
            store
                .set_kill_switch(&mut client, &ctx, engaged, &reason)
                .await
        }
    };
    match result {
        Ok(state) => {
            println!(
                "kill switch: {}  (version {}, changed {} by {}: {})",
                if state.engaged { "ON" } else { "off" },
                state.version,
                state.changed_at.as_deref().unwrap_or("never"),
                state
                    .changed_by
                    .as_ref()
                    .map(tidegard_api::incidents::actor_label)
                    .unwrap_or_else(|| "nobody".to_string()),
                state.reason.as_deref().unwrap_or("-"),
            );
            0
        }
        Err(error) => {
            eprintln!("the kill switch could not be changed: {error}");
            1
        }
    }
}

const TOKEN_USAGE: &str = "\
usage:
  tidegard-api token create --tenant T --actor-id ID --role ROLE
                                 [--actor-type operator|service_account]
                                 [--days 1-366 (default 90)] [--description TEXT]
  tidegard-api token revoke --token-id UUID
  tidegard-api token list --tenant T
roles: viewer, operator, senior_operator, noc_lead";

/// `tidegard-api token ...`: the bootstrap path for API tokens. Output
/// goes to stdout for the operator; the secret is printed once.
async fn token_command(pool: &deadpool_postgres::Pool, args: &[String]) -> i32 {
    use tidegard_api::auth::Role;
    use tidegard_api::token_admin::{self, ActorType, NewToken};

    let flag = |name: &str| {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
    };
    let client = match tidegard_incident_postgres::pool::acquire(pool).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!("the incident database cannot be reached: {error}");
            return 1;
        }
    };
    let result = match args.first().map(String::as_str) {
        Some("create") => {
            let (Some(tenant), Some(actor_id), Some(role)) =
                (flag("--tenant"), flag("--actor-id"), flag("--role"))
            else {
                eprintln!("{TOKEN_USAGE}");
                return 2;
            };
            let Some(role) = Role::parse(&role) else {
                eprintln!("unknown role '{role}'\n{TOKEN_USAGE}");
                return 2;
            };
            let actor_type = flag("--actor-type").unwrap_or_else(|| "operator".to_string());
            let Some(actor_type) = ActorType::parse(&actor_type) else {
                eprintln!("unknown actor type '{actor_type}'\n{TOKEN_USAGE}");
                return 2;
            };
            let Ok(lifetime_days) = flag("--days").unwrap_or_else(|| "90".to_string()).parse()
            else {
                eprintln!("--days must be a number\n{TOKEN_USAGE}");
                return 2;
            };
            // A tenant named for the first time is registered, as v1.0.0
            // scripts expect (ADR 0060). The API itself never does this.
            match tidegard_incident_postgres::tenants::ensure(&**client, &tenant).await {
                Ok(true) => eprintln!("registered tenant '{tenant}'"),
                Ok(false) => {}
                Err(error) => {
                    eprintln!("{error}");
                    return 1;
                }
            }
            let new = NewToken {
                tenant,
                actor_type,
                actor_id,
                role,
                lifetime_days,
                description: flag("--description").unwrap_or_default(),
            };
            token_admin::create(&**client, &new).await.map(|issued| {
                println!("token_id:   {}", issued.token_id);
                println!("expires_at: {}", issued.expires_at);
                println!("token:      {}", issued.secret);
                println!("Store the token now: it is not shown again and cannot be recovered.");
            })
        }
        Some("revoke") => {
            let Some(token_id) = flag("--token-id") else {
                eprintln!("{TOKEN_USAGE}");
                return 2;
            };
            token_admin::revoke(&**client, &token_id)
                .await
                .map(|revoked| {
                    if revoked {
                        println!("revoked {token_id}");
                    } else {
                        println!("no live token {token_id}");
                    }
                })
        }
        Some("list") => {
            let Some(tenant) = flag("--tenant") else {
                eprintln!("{TOKEN_USAGE}");
                return 2;
            };
            token_admin::list(&**client, &tenant).await.map(|tokens| {
                for token in tokens {
                    println!(
                        "{}  {}:{}  {}  created {}  expires {}  {}  {}",
                        token.token_id,
                        token.actor_type,
                        token.actor_id,
                        token.role,
                        token.created_at,
                        token.expires_at,
                        token
                            .revoked_at
                            .map_or("live".to_string(), |at| format!("revoked {at}")),
                        token.description,
                    );
                }
            })
        }
        _ => {
            eprintln!("{TOKEN_USAGE}");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

const TENANT_USAGE: &str = "\
usage:
  tidegard-api tenant create --tenant T [--name NAME]
  tidegard-api tenant list
  tidegard-api tenant suspend|activate --tenant T
  tidegard-api tenant prefix add|remove --tenant T --prefix P
  tidegard-api tenant prefix list --tenant T";

/// `tidegard-api tenant ...`: the tenant registry from the host (ADR
/// 0060), for the first tenant and for an install without a platform
/// token.
async fn tenant_command(pool: &deadpool_postgres::Pool, args: &[String]) -> i32 {
    use tidegard_incident_postgres::tenants::{self, TenantStatus};
    use tidegard_mitigation::Prefix;

    let flag = |name: &str| {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
    };
    let words: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .take_while(|word| !word.starts_with("--"))
        .collect();
    let tenant = flag("--tenant");
    let prefix = match flag("--prefix").map(|text| text.parse::<Prefix>()) {
        Some(Ok(prefix)) => Some(prefix),
        Some(Err(error)) => {
            eprintln!("--prefix: {error}");
            return 2;
        }
        None => None,
    };
    let client = match tidegard_incident_postgres::pool::acquire(pool).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!("the incident database cannot be reached: {error}");
            return 1;
        }
    };
    let show = |tenant: &tenants::Tenant| {
        println!(
            "{}  {}  {}  created {}",
            tenant.tenant_id,
            tenant.status.as_str(),
            tenant.display_name,
            tenant.created_at
        );
    };
    let result = match (words.as_slice(), tenant, prefix) {
        (["create"], Some(tenant), None) => {
            let name = flag("--name").unwrap_or_else(|| tenant.clone());
            tenants::create(&**client, &tenant, &name)
                .await
                .map(|created| show(&created))
        }
        (["list"], None, None) => tenants::list(&**client)
            .await
            .map(|all| all.iter().for_each(show)),
        ([verb @ ("suspend" | "activate")], Some(tenant), None) => {
            let status = if *verb == "suspend" {
                TenantStatus::Suspended
            } else {
                TenantStatus::Active
            };
            tenants::set_status(&**client, &tenant, status)
                .await
                .map(|changed| show(&changed))
        }
        (["prefix", "add"], Some(tenant), Some(prefix)) => {
            tenants::add_prefix(&**client, &tenant, prefix)
                .await
                .map(|()| println!("{prefix} registered to {tenant}"))
        }
        (["prefix", "remove"], Some(tenant), Some(prefix)) => {
            tenants::remove_prefix(&**client, &tenant, prefix)
                .await
                .map(|removed| {
                    if removed {
                        println!("{prefix} removed from {tenant}");
                    } else {
                        println!("{tenant} has no prefix {prefix}");
                    }
                })
        }
        (["prefix", "list"], Some(tenant), None) => tenants::prefixes(&**client, &tenant)
            .await
            .map(|all| all.iter().for_each(|prefix| println!("{prefix}"))),
        _ => {
            eprintln!("{TENANT_USAGE}");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}
