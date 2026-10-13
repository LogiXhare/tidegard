//! Bundles the Direction Classifier's prefix registry, the Aggregator,
//! and exporter-sampling configuration into the state one collector
//! process owns and threads through its processing loop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use tidegard_aggregator::{Aggregator, AggregatorConfig};
use tidegard_classifier::PrefixRegistry;

use crate::normalize::ExternalSamplingConfig;

#[derive(Debug, Clone, Default)]
pub struct SamplingConfig {
    pub global_default: Option<u32>,
    pub per_exporter: HashMap<IpAddr, u32>,
}

impl SamplingConfig {
    pub fn for_exporter(&self, exporter: IpAddr) -> ExternalSamplingConfig {
        ExternalSamplingConfig {
            exporter_configured: self.per_exporter.get(&exporter).copied(),
            global_default: self.global_default,
        }
    }
}

pub struct Pipeline {
    pub prefixes: PrefixRegistry,
    pub aggregator: Aggregator,
    pub sampling: SamplingConfig,
}

impl Pipeline {
    pub fn new(
        prefixes: PrefixRegistry,
        aggregator_config: AggregatorConfig,
        sampling: SamplingConfig,
        now: Instant,
    ) -> Self {
        Pipeline {
            prefixes,
            aggregator: Aggregator::new(aggregator_config, now),
            sampling,
        }
    }
}
