use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::prober::ProbeHistory;

/// Weights for combining different score sources.
#[derive(Debug, Clone)]
pub struct ScoreWeights {
    pub local: f64,
    pub collective: f64,
    /// Weight of live, in-band path measurements (Phase 16.3.4).
    ///
    /// Applied only to paths that are actually carrying traffic, where it
    /// dominates: a probe estimates whether a path *might* work, while these
    /// numbers record what it is doing right now.
    pub measured: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            local: 0.8,
            collective: 0.2,
            measured: 0.6,
        }
    }
}

/// Aggregated score for an endpoint combining local probes and collective reports.
#[derive(Debug, Clone)]
pub struct EndpointScore {
    pub key: String,
    pub local_score: f64,
    pub collective_score: f64,
    /// Live measurement from the multipath scheduler, if this path is in use.
    pub measured_score: Option<f64>,
    pub combined_score: f64,
}

/// ScoreBoard combines local probe data with collective reports from Admiral.
pub struct ScoreBoard {
    local_results: Arc<RwLock<HashMap<String, ProbeHistory>>>,
    collective_scores: Arc<RwLock<HashMap<String, f64>>>,
    /// Per-path health from the live data plane (16.3.4).
    measured_scores: Arc<RwLock<HashMap<String, f64>>>,
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
            measured_scores: Arc::new(RwLock::new(HashMap::new())),
            weights,
        }
    }

    /// Feed in live per-path health from the multipath scheduler (16.3.4).
    ///
    /// Replaces the whole set rather than merging: a path that has dropped out
    /// of the active set has no current measurement, and keeping its last good
    /// number would recommend a path nothing is testing any more.
    pub fn update_measured(&self, scores: HashMap<String, f64>) {
        *self.measured_scores.write() = scores;
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
        let measured = self.measured_scores.read();

        let mut scores: Vec<EndpointScore> = local
            .iter()
            .map(|(key, history)| {
                let local_score = history.score();
                let collective_score = collective.get(key).copied().unwrap_or(0.5);
                let estimated = self.weights.local * local_score
                    + self.weights.collective * collective_score;

                // A live measurement is evidence; a probe is a guess. Where
                // both exist the measurement is blended in with its own
                // weight, so a path that is demonstrably failing cannot keep
                // a high rank on the strength of an old successful probe.
                let measured_score = measured.get(key).copied();
                let combined = match measured_score {
                    Some(m) => {
                        let w = self.weights.measured.clamp(0.0, 1.0);
                        w * m + (1.0 - w) * estimated
                    }
                    None => estimated,
                };

                EndpointScore {
                    key: key.clone(),
                    local_score,
                    collective_score,
                    measured_score,
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
