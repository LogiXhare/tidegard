//! Thin binary entry point; the logic is in the library so tests can run
//! it in-process.

#[tokio::main]
async fn main() {
    wetechinetmon_common::logging::init();
    let config = wetechinetmon_mitigator::Config::from_env().unwrap_or_else(|error| {
        tracing::error!(error = %error, "invalid configuration");
        std::process::exit(1);
    });
    tracing::info!(
        consumer_id = %config.consumer_id,
        metrics_bind = %config.metrics_bind,
        "starting wetechinetmon-mitigator"
    );
    if let Err(error) = wetechinetmon_mitigator::run(config, shutdown_signal()).await {
        tracing::error!(error = %error, "wetechinetmon-mitigator could not start");
        std::process::exit(1);
    }
    tracing::info!("wetechinetmon-mitigator stopped");
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
