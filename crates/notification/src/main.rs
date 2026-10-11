//! Thin binary entry point; the logic is in the library so tests can run
//! it in-process.

#[tokio::main]
async fn main() {
    wetechinetmon_common::logging::init();
    let config = wetechinetmon_notification::Config::from_env().unwrap_or_else(|error| {
        tracing::error!(error = %error, "invalid configuration");
        std::process::exit(1);
    });
    tracing::info!(
        consumer_id = %config.consumer_id,
        metrics_bind = %config.metrics_bind,
        channels = config.file.channels.len(),
        routes = config.file.routes.len(),
        "starting wetechinetmon-notifier"
    );
    if let Err(error) = wetechinetmon_notification::run(config, shutdown_signal()).await {
        tracing::error!(error = %error, "wetechinetmon-notifier could not start");
        std::process::exit(1);
    }
    tracing::info!("wetechinetmon-notifier stopped");
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
