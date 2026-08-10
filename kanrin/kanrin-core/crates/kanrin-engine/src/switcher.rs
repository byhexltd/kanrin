use std::time::{Duration, Instant};

use crate::scoreboard::ScoreBoard;

/// Switcher decides when to change transport/endpoint and executes the switch.
pub struct Switcher {
    /// Score threshold — switch if current drops below this.
    switch_threshold: f64,
    /// Minimum time between switches (prevent thrashing).
    cooldown: Duration,
    /// Last time a switch was performed.
    last_switch: Instant,
    /// Key of current endpoint+transport.
    current_key: Option<String>,
}

/// Decision from the switcher.
#[derive(Debug, Clone)]
pub enum SwitchDecision {
    /// Stay on current endpoint.
    Stay,
    /// Switch to a better endpoint.
    Switch { from: String, to: String, reason: String },
}

impl Switcher {
    pub fn new(switch_threshold: f64, cooldown: Duration) -> Self {
        Self {
            switch_threshold,
            cooldown,
            last_switch: Instant::now() - cooldown, // Allow immediate first switch
            current_key: None,
        }
    }

    /// Set the current endpoint key.
    pub fn set_current(&mut self, key: String) {
        self.current_key = Some(key);
    }

    /// Evaluate whether a switch should happen.
    pub fn evaluate(&self, scoreboard: &ScoreBoard) -> SwitchDecision {
        // Check cooldown
        if self.last_switch.elapsed() < self.cooldown {
            return SwitchDecision::Stay;
        }

        let current_key = match &self.current_key {
            Some(k) => k,
            None => return SwitchDecision::Stay,
        };

        let ranked = scoreboard.ranked_list();
        if ranked.is_empty() {
            return SwitchDecision::Stay;
        }

        // Find current endpoint score
        let current_score = ranked
            .iter()
            .find(|e| &e.key == current_key)
            .map(|e| e.combined_score)
            .unwrap_or(0.0);

        // Find best alternative
        let best = &ranked[0];

        // Switch if current is below threshold AND there's a better option
        if current_score < self.switch_threshold && best.key != *current_key {
            return SwitchDecision::Switch {
                from: current_key.clone(),
                to: best.key.clone(),
                reason: format!(
                    "current score ({:.2}) below threshold ({:.2}), better option available ({:.2})",
                    current_score, self.switch_threshold, best.combined_score
                ),
            };
        }

        // Also switch if best is significantly better (>2x score)
        if best.key != *current_key && best.combined_score > current_score * 2.0 {
            return SwitchDecision::Switch {
                from: current_key.clone(),
                to: best.key.clone(),
                reason: format!(
                    "much better option available: {:.2} vs current {:.2}",
                    best.combined_score, current_score
                ),
            };
        }

        SwitchDecision::Stay
    }

    /// Record that a switch was performed.
    pub fn record_switch(&mut self, new_key: String) {
        self.current_key = Some(new_key);
        self.last_switch = Instant::now();
    }

    pub fn current_key(&self) -> Option<&str> {
        self.current_key.as_deref()
    }

    pub fn time_since_last_switch(&self) -> Duration {
        self.last_switch.elapsed()
    }
}
