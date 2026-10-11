//! Thin binary entry point; the logic is in the library so tests can run
//! it in-process.

use wetechinetmon_api::server::{bind, Bound};
use wetechinetmon_api::{config::Config, router, AppState};

#[tokio::main]
async fn main() {
    wetechinetmon_common::logging::init();

    let config = Config::from_env().unwrap_or_else(|error| {
        tracing::error!(error = %error, "invalid configuration");
        std::process::exit(1);
    });
    let (pool, transport) = wetechinetmon_incident_postgres::connect::connect(
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
        "starting wetechinetmon-api"
    );

    let mut state = AppState::new(pool);
    // A plain-HTTP API is loopback-only (ADR 0038), where a Secure cookie
    // would not always be kept.
    state.secure_cookies = config.tls.is_some();
    if let Some(traffic) = &config.traffic {
        let clickhouse = wetechinetmon_api::clickhouse::ClickHouse::new(traffic.clickhouse.clone())
            .unwrap_or_else(|error| {
                tracing::error!(error = %error, "traffic cannot be served");
                std::process::exit(1);
            });
        tracing::info!(
            tenant = %traffic.tenant,
            clickhouse_host = %traffic.clickhouse.host,
            "serving traffic to one tenant"
        );
        state = state.with_traffic(wetechinetmon_api::traffic::TrafficSource {
            tenant: wetechinetmon_incident::correlation::TenantId::new(&traffic.tenant),
            clickhouse,
        });
    }
    let app =
        router(state).into_make_service_with_connect_info::<wetechinetmon_api::server::PeerAddr>();
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
    tracing::info!("wetechinetmon-api stopped");
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

const TOKEN_USAGE: &str = "\
usage:
  wetechinetmon-api token create --tenant T --actor-id ID --role ROLE
                                 [--actor-type operator|service_account]
                                 [--days 1-366 (default 90)] [--description TEXT]
  wetechinetmon-api token revoke --token-id UUID
  wetechinetmon-api token list --tenant T
roles: viewer, operator, senior_operator, noc_lead";

/// `wetechinetmon-api token ...`: the bootstrap path for API tokens. Output
/// goes to stdout for the operator; the secret is printed once.
async fn token_command(pool: &deadpool_postgres::Pool, args: &[String]) -> i32 {
    use wetechinetmon_api::auth::Role;
    use wetechinetmon_api::token_admin::{self, ActorType, NewToken};

    let flag = |name: &str| {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
    };
    let client = match wetechinetmon_incident_postgres::pool::acquire(pool).await {
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
