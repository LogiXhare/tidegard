//! Shared types and utilities used across Tidegard crates.
//!
//! This crate is intentionally small. It exists to avoid duplicating
//! logging setup and a couple of cross-cutting types across the
//! collector, aggregator, and future service crates — it is not a
//! dumping ground for unrelated helpers.

pub mod env;
pub mod flow;
pub mod http_endpoint;
pub mod logging;
#[cfg(feature = "metrics-server")]
pub mod metrics_server;
pub mod rfc3339;
pub mod sampling;

pub use flow::{FlowError, NormalizedFlow, NormalizedFlowBuilder, Protocol};
pub use sampling::{
    resolve as resolve_sampling, ResolvedSampling, SamplingInputs, SamplingRate, SamplingSource,
};

/// Errors that can cross crate boundaries within Tidegard.
///
/// Individual crates should generally define their own, more specific
/// error enums (see `tidegard_protocol_ipfix::DecodeError`, for
/// example) and only reach for this shared type at service boundaries
/// where a caller genuinely needs a crate-agnostic error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
