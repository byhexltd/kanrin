use std::time::{Duration, Instant};

use async_trait::async_trait;

/// Context available to stealth modules during transformation.
#[derive(Debug, Clone)]
pub struct StealthContext {
    pub current_time: Instant,
    pub bytes_sent_total: u64,
    pub bytes_recv_total: u64,
    pub connection_duration: Duration,
    pub transport_name: String,
}

/// Core stealth module trait. Each module transforms traffic to avoid detection.
#[async_trait]
pub trait StealthModule: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Transform outgoing data before it hits the transport.
    async fn transform_outgoing(&self, data: &[u8], ctx: &StealthContext) -> Vec<u8>;

    /// Transform incoming data after transport delivers it.
    async fn transform_incoming(&self, data: &[u8], ctx: &StealthContext) -> Vec<u8>;

    /// Generate cover traffic (called periodically when idle).
    /// Returns None if no cover traffic needed.
    async fn generate_cover_traffic(&self, ctx: &StealthContext) -> Option<Vec<u8>>;
}

/// Pipeline that chains multiple stealth modules.
pub struct StealthPipeline {
    modules: Vec<Box<dyn StealthModule>>,
}

impl StealthPipeline {
    pub fn new() -> Self {
        Self { modules: Vec::new() }
    }

    pub fn add_module(&mut self, module: Box<dyn StealthModule>) {
        self.modules.push(module);
    }

    /// Apply all modules to outgoing data (in order).
    pub async fn apply_outgoing(&self, mut data: Vec<u8>, ctx: &StealthContext) -> Vec<u8> {
        for module in &self.modules {
            data = module.transform_outgoing(&data, ctx).await;
        }
        data
    }

    /// Apply all modules to incoming data (in reverse order).
    pub async fn apply_incoming(&self, mut data: Vec<u8>, ctx: &StealthContext) -> Vec<u8> {
        for module in self.modules.iter().rev() {
            data = module.transform_incoming(&data, ctx).await;
        }
        data
    }

    /// Collect cover traffic from all modules.
    pub async fn collect_cover_traffic(&self, ctx: &StealthContext) -> Vec<Vec<u8>> {
        let mut traffic = Vec::new();
        for module in &self.modules {
            if let Some(data) = module.generate_cover_traffic(ctx).await {
                traffic.push(data);
            }
        }
        traffic
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }
}
