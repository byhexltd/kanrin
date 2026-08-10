use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kanrin_transport::{Endpoint, ProbeResult, Transport};
use parking_lot::RwLock;
use tokio::time;

/// History of probe results for a single endpoint.
#[derive(Debug, Clone)]
pub struct ProbeHistory {
    pub results: VecDeque<ProbeEntry>,
    pub avg_latency_ms: f64,
    pub success_rate: f64,
    pub last_checked: Instant,
    max_history: usize,
}

#[derive(Debug, Clone)]
pub struct ProbeEntry {
    pub result: ProbeResult,
    pub timestamp: Instant,
}

impl ProbeHistory {
    pub fn new(max_history: usize) -> Self {
        Self {
            results: VecDeque::new(),
            avg_latency_ms: 0.0,
            success_rate: 0.0,
            last_checked: Instant::now(),
            max_history,
        }
    }

    pub fn record(&mut self, result: ProbeResult) {
        self.results.push_back(ProbeEntry {
            result,
            timestamp: Instant::now(),
        });

        if self.results.len() > self.max_history {
            self.results.pop_front();
        }

        self.recalculate();
        self.last_checked = Instant::now();
    }

    fn recalculate(&mut self) {
        if self.results.is_empty() {
            self.avg_latency_ms = 0.0;
            self.success_rate = 0.0;
            return;
        }

        let mut total_latency = 0u64;
        let mut success_count = 0u64;
        let mut latency_count = 0u64;

        for entry in &self.results {
            match &entry.result {
                ProbeResult::Available { latency_ms } => {
                    success_count += 1;
                    total_latency += *latency_ms as u64;
                    latency_count += 1;
                }
                ProbeResult::Blocked { .. } => {}
                ProbeResult::Unknown => {}
            }
        }

        self.success_rate = success_count as f64 / self.results.len() as f64;
        self.avg_latency_ms = if latency_count > 0 {
            total_latency as f64 / latency_count as f64
        } else {
            f64::MAX
        };
    }

    /// Calculate a composite score (higher = better).
    pub fn score(&self) -> f64 {
        if self.success_rate == 0.0 {
            return 0.0;
        }
        // Score = success_rate * (1000 / latency)
        // Normalize so that 20ms = 50, 100ms = 10, 500ms = 2
        let latency_factor = if self.avg_latency_ms > 0.0 {
            1000.0 / self.avg_latency_ms
        } else {
            50.0
        };
        self.success_rate * latency_factor
    }
}

/// Background prober that periodically checks endpoint health.
pub struct Prober {
    endpoints: Vec<Endpoint>,
    transports: Vec<Arc<dyn Transport>>,
    results: Arc<RwLock<HashMap<String, ProbeHistory>>>,
    interval: Duration,
    max_history: usize,
}

impl Prober {
    pub fn new(
        endpoints: Vec<Endpoint>,
        transports: Vec<Arc<dyn Transport>>,
        interval: Duration,
    ) -> Self {
        Self {
            endpoints,
            transports,
            results: Arc::new(RwLock::new(HashMap::new())),
            interval,
            max_history: 10,
        }
    }

    /// Get shared results handle (for ScoreBoard).
    pub fn results(&self) -> Arc<RwLock<HashMap<String, ProbeHistory>>> {
        self.results.clone()
    }

    /// Start the background probing loop.
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut interval = time::interval(self.interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.probe_all().await;
                }
                _ = shutdown.changed() => {
                    tracing::info!("prober shutting down");
                    break;
                }
            }
        }
    }

    /// Probe all endpoints with all transports.
    async fn probe_all(&self) {
        for endpoint in &self.endpoints {
            for transport in &self.transports {
                let result = transport.probe(endpoint).await;
                let key = format!("{}:{}:{}", transport.name(), endpoint.host, endpoint.port);

                let mut results = self.results.write();
                let history = results
                    .entry(key.clone())
                    .or_insert_with(|| ProbeHistory::new(self.max_history));
                history.record(result.clone());

                tracing::trace!(
                    endpoint = %endpoint.addr_string(),
                    transport = transport.name(),
                    result = ?result,
                    score = history.score(),
                    "probe complete"
                );
            }
        }
    }

    /// Get the best endpoint+transport combination right now.
    pub fn best(&self) -> Option<(String, f64)> {
        let results = self.results.read();
        results
            .iter()
            .max_by(|a, b| a.1.score().partial_cmp(&b.1.score()).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, v)| (k.clone(), v.score()))
    }
}
