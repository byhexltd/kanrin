use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::prober::ProbeHistory;

/// Weights for combining different score sources.
#[derive(Debug, Clone)]
pub struct ScoreWeights {
    pub local: f64,
    pub collective: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            local: 0.8,
            collective: 0.2,
        }
    }
}

/// Aggregated score for an endpoint combining local probes and collective reports.
#[derive(Debug, Clone)]
pub struct EndpointScore {
    pub key: String,
    pub local_score: f64,
    pub collective_score: f64,
    pub combined_score: f64,
}

/// ScoreBoard combines local probe data with collective reports from Admiral.
pub struct ScoreBoard {
    local_results: Arc<RwLock<HashMap<String, ProbeHistory>>>,
    collective_scores: Arc<RwLock<HashMap<String, f64>>>,
    weights: ScoreWeights,
}

impl ScoreBoard {
    pub fn new(
        local_results: Arc<RwLock<HashMap<String, ProbeHistory>>>,
        weights: ScoreWeights,
    ) -> Self {
        Self {
            local_results,
            collective_scores: Arc::new(RwLock::new(HashMap::new())),
            weights,
        }
    }

    /// Update collective scores (received from Admiral API).
    pub fn update_collective(&self, scores: HashMap<String, f64>) {
        let mut collective = self.collective_scores.write();
        *collective = scores;
    }

    /// Get the best endpoint key based on combined score.
    pub fn best_endpoint(&self) -> Option<EndpointScore> {
        self.ranked_list().into_iter().next()
    }

    /// Get all endpoints ranked by combined score (descending).
    pub fn ranked_list(&self) -> Vec<EndpointScore> {
        let local = self.local_results.read();
        let collective = self.collective_scores.read();

        let mut scores: Vec<EndpointScore> = local
            .iter()
            .map(|(key, history)| {
                let local_score = history.score();
                let collective_score = collective.get(key).copied().unwrap_or(0.5);
                let combined = self.weights.local * local_score
                    + self.weights.collective * collective_score;

                EndpointScore {
                    key: key.clone(),
                    local_score,
                    collective_score,
                    combined_score: combined,
                }
            })
            .collect();

        scores.sort_by(|a, b| {
            b.combined_score
                .partial_cmp(&a.combined_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        scores
    }

    /// Generate a score report to send to Admiral (anonymized).
    pub fn generate_report(&self) -> Vec<(String, f64)> {
        let local = self.local_results.read();
        local
            .iter()
            .map(|(key, history)| (key.clone(), history.score()))
            .collect()
    }
}
