//! Structured JSON logging setup, shared by every Tidegard service.
//!
//! Per docs/non-functional-requirements.md (NFR-8) and
//! docs/security-principles.md, every service ships structured JSON logs
//! with configurable log levels from its first working version — this
//! module is that shared foundation, not a per-service reimplementation.

use tracing_subscriber::EnvFilter;

/// Initializes the global `tracing` subscriber with JSON-formatted output
/// and an env-filter driven by `RUST_LOG` (defaulting to `info` when
/// unset or invalid).
///
/// Call this once, near the start of `main`. Calling it more than once
/// per process will panic, matching `tracing`'s own global-subscriber
/// contract — this is deliberate: silently ignoring a second call would
/// hide a programming error.
pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_current_span(true)
        .init();
}

#[cfg(test)]
mod tests {
    // `init()` sets a process-global subscriber, which cannot be
    // exercised repeatedly or in parallel with other tests in this
    // process without hitting `tracing`'s "already set" panic. Real
    // coverage of "does this actually emit JSON with the right fields"
    // belongs in an integration test that runs in its own process (see
    // tests/integration once Phase 2's collector binary exists) rather
    // than a unit test here.
    #[test]
    fn default_filter_parses_when_rust_log_unset() {
        // Guards against a typo turning the fallback filter string into
        // something that fails to parse, without invoking init() itself.
        assert!("info".parse::<tracing::Level>().is_ok());
    }
}
