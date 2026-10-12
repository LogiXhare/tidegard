//! ClickHouse output for WetechiNetMon analytics: original schemas
//! (docs/clean-room-boundary.md), bounded batching, and bounded-retry
//! writes. See docs/architecture/decisions/0005-clickhouse-batching-and-retry.md
//! and docs/integrations/clickhouse.md.

pub mod batch;
pub mod connection;
pub mod retry;
pub mod schema;
pub mod writer;

pub use batch::{BatchConfig, BatchQueue};
pub use connection::{ClickHouseSettings, ConnectionError};
pub use retry::{EnqueueOutcome, RequeueOutcome, RetryConfig, RetryQueue};
pub use schema::DetectionEventRow;
pub use writer::{run_migrations, ClickHouseWriter, FlushReport};

pub use clickhouse::Client;
