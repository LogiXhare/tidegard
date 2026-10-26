//! Thin binary entry point — all real logic lives in the library
//! (`tidegard_collector`) so it can be exercised by integration
//! tests without spawning a separate process.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tidegard_common::logging::init();

    let config = tidegard_collector::Config::from_env().unwrap_or_else(|err| {
        tracing::error!(error = %err, "invalid configuration");
        std::process::exit(1);
    });

    tracing::info!(
        bind = %config.bind,
        metrics_bind = %config.metrics_bind,
        "starting tidegard-collector"
    );

    tidegard_collector::run(config).await
}
