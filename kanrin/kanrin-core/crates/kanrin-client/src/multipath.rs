//! Multipath scheduling (Phase 16.3).
//!
//! Once the continuity layer makes a chunk transport-independent — carrying
//! its own sequence, decryptable in any order, de-duplicated on arrival — then
//! using several transports at once needs no new protocol machinery. What it
//! needs is a decision about *which* path each chunk takes, and an honest
//! measurement of how each path is behaving.
//!
//! That decision is pure arithmetic, so it lives here, apart from the IO:
//!
//! - [`PathHealth`] — per-path accounting: capacity, latency, loss, and
//!   whether the path is fit to carry anything at all.
//! - [`Scheduler`] — stripes chunks across healthy paths in proportion to
//!   measured capacity, and decides when a chunk is worth hedging.
//!
//! Ordering is explicitly *not* a goal here. Striping reorders by design; the
//! receiver's reorder buffer (16.1.4) is what turns that back into a stream,
//! which is why the scheduler is free to optimise purely for throughput.

use std::time::{Duration, Instant};

/// Smoothing factor for the capacity and latency estimates.
///
/// Low enough that one slow chunk does not evict a good path, high enough to
/// react inside a few round trips — a path that has just started failing must
/// lose its share quickly, not after a minute of averaging.
const EWMA_ALPHA: f64 = 0.25;

/// Loss above this fraction takes a path out of the rotation. Well above
/// ordinary congestion loss, low enough to catch a path being actively
/// degraded rather than merely busy.
const UNHEALTHY_LOSS: f64 = 0.20;

/// A path with no successful chunk in this long is presumed unusable.
const STALE_AFTER: Duration = Duration::from_secs(5);

/// Starting capacity estimate, in bytes per second, for a path with no history.
/// Deliberately modest: a new path earns its share by delivering, rather than
/// being handed a large slice on optimism.
const INITIAL_CAPACITY: f64 = 256.0 * 1024.0;

/// Rolling measurements for one transport in the active set.
#[derive(Debug, Clone)]
pub struct PathHealth {
    pub name: String,
    /// Smoothed throughput estimate, bytes per second.
    capacity_bps: f64,
    /// Smoothed round-trip estimate.
    rtt: Option<Duration>,
    sent: u64,
    acknowledged: u64,
    lost: u64,
    /// Recent loss, smoothed the same way as capacity.
    ///
    /// Deliberately *not* `lost / sent` over the lifetime: that never forgives.
    /// On a long-lived tunnel a path that had one bad minute would stay
    /// disqualified for hours, and the set of usable paths could only ever
    /// shrink. Health has to be a statement about now.
    loss_ewma: f64,
    last_success: Instant,
    /// Set when a switch or error takes the path out of service.
    disabled: bool,
}

impl PathHealth {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capacity_bps: INITIAL_CAPACITY,
            rtt: None,
            sent: 0,
            acknowledged: 0,
            lost: 0,
            loss_ewma: 0.0,
            last_success: Instant::now(),
            disabled: false,
        }
    }

    /// A chunk was handed to this path.
    pub fn record_sent(&mut self) {
        self.sent += 1;
    }

    /// A chunk came back acknowledged: the strongest evidence a path works.
    pub fn record_delivered(&mut self, bytes: usize, rtt: Duration) {
        self.acknowledged += 1;
        self.last_success = Instant::now();
        self.loss_ewma = ewma(self.loss_ewma, 0.0);

        let observed = bytes as f64 / rtt.as_secs_f64().max(0.001);
        self.capacity_bps = ewma(self.capacity_bps, observed);
        self.rtt = Some(match self.rtt {
            Some(prev) => Duration::from_secs_f64(ewma(prev.as_secs_f64(), rtt.as_secs_f64())),
            None => rtt,
        });
    }

    /// A chunk sent on this path had to be replayed elsewhere.
    pub fn record_lost(&mut self) {
        self.lost += 1;
        self.loss_ewma = ewma(self.loss_ewma, 1.0);
        // Loss is charged against the estimate immediately. Waiting for the
        // average to drift down would keep feeding a dying path.
        self.capacity_bps = ewma(self.capacity_bps, self.capacity_bps * 0.5);
    }

    pub fn disable(&mut self) {
        self.disabled = true;
    }

    pub fn enable(&mut self) {
        self.disabled = false;
        self.last_success = Instant::now();
    }

    /// Recent loss as a fraction, smoothed. A path that starts delivering
    /// again recovers within a few chunks.
    pub fn loss_rate(&self) -> f64 {
        self.loss_ewma
    }

    /// Chunks lost over the whole life of the path (diagnostics only — health
    /// decisions use [`Self::loss_rate`]).
    pub fn lifetime_lost(&self) -> u64 {
        self.lost
    }

    /// Whether this path should currently carry traffic.
    ///
    /// A path that has simply been idle is *not* unhealthy — only one that has
    /// been given work and failed to deliver it. Otherwise a quiet tunnel
    /// would disqualify all of its own paths.
    pub fn is_healthy(&self) -> bool {
        if self.disabled {
            return false;
        }
        if self.loss_rate() > UNHEALTHY_LOSS {
            return false;
        }
        let awaiting = self.sent > self.acknowledged + self.lost;
        !(awaiting && self.last_success.elapsed() > STALE_AFTER)
    }

    pub fn capacity_bps(&self) -> f64 {
        self.capacity_bps
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Score in the 0.0–1.0 range the scoreboard expects (16.3.4).
    pub fn score(&self) -> f32 {
        if !self.is_healthy() {
            return 0.0;
        }
        let throughput = (self.capacity_bps / (4.0 * 1024.0 * 1024.0)).min(1.0);
        let latency = match self.rtt {
            Some(rtt) => (1.0 - rtt.as_secs_f64() / 0.5).clamp(0.0, 1.0),
            None => 0.5,
        };
        (0.6 * throughput + 0.4 * latency) as f32
    }
}

fn ewma(previous: f64, sample: f64) -> f64 {
    EWMA_ALPHA * sample + (1.0 - EWMA_ALPHA) * previous
}

/// Where a chunk should go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The path that carries the chunk.
    pub primary: String,
    /// A second path to send the same chunk on (16.3.3). The receiver drops
    /// whichever copy arrives second, so hedging costs bandwidth and nothing
    /// else.
    pub hedge: Option<String>,
}

/// Chooses paths for outgoing chunks.
#[derive(Debug, Default)]
pub struct Scheduler {
    paths: Vec<PathHealth>,
    /// Fractional credit per path, so proportional striping does not need
    /// floating-point comparisons at send time.
    credits: Vec<f64>,
    hedging: bool,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a transport to the active set (16.3.1).
    pub fn add_path(&mut self, name: impl Into<String>) {
        let name = name.into();
        if self.paths.iter().any(|p| p.name == name) {
            return;
        }
        self.paths.push(PathHealth::new(name));
        self.credits.push(0.0);
    }

    pub fn remove_path(&mut self, name: &str) {
        if let Some(i) = self.paths.iter().position(|p| p.name == name) {
            self.paths.remove(i);
            self.credits.remove(i);
        }
    }

    /// Enable duplicating latency-critical chunks onto a second path.
    pub fn set_hedging(&mut self, enabled: bool) {
        self.hedging = enabled;
    }

    pub fn path_mut(&mut self, name: &str) -> Option<&mut PathHealth> {
        self.paths.iter_mut().find(|p| p.name == name)
    }

    pub fn paths(&self) -> &[PathHealth] {
        &self.paths
    }

    /// Per-path scores for `ScoreBoard::update_measured` (16.3.4).
    ///
    /// Every known path is reported, including unhealthy ones at zero: the
    /// scoreboard replaces its whole measured set, so omitting a failing path
    /// would quietly restore it to whatever its last probe suggested.
    pub fn health_report(&self) -> std::collections::HashMap<String, f64> {
        self.paths
            .iter()
            .map(|p| (p.name.clone(), p.score() as f64))
            .collect()
    }

    pub fn healthy_count(&self) -> usize {
        self.paths.iter().filter(|p| p.is_healthy()).count()
    }

    /// Pick a path for the next chunk.
    ///
    /// Credit-based rather than random: over any window the split matches the
    /// measured capacity ratio exactly, which random selection only approaches
    /// in the limit and never on the short flows that dominate a tunnel.
    ///
    /// `latency_critical` marks a chunk worth duplicating — a small, delay-
    /// sensitive packet where the cost of a second copy is trivial next to the
    /// cost of waiting for a retransmission.
    pub fn assign(&mut self, latency_critical: bool) -> Option<Assignment> {
        let healthy: Vec<usize> = (0..self.paths.len())
            .filter(|&i| self.paths[i].is_healthy())
            .collect();
        if healthy.is_empty() {
            return None;
        }

        let total: f64 = healthy.iter().map(|&i| self.paths[i].capacity_bps).sum();
        for &i in &healthy {
            self.credits[i] += self.paths[i].capacity_bps / total;
        }

        // Highest credit wins; its credit is then spent.
        let chosen = *healthy
            .iter()
            .max_by(|&&a, &&b| self.credits[a].total_cmp(&self.credits[b]))
            .expect("healthy is non-empty");
        self.credits[chosen] -= 1.0;
        self.paths[chosen].record_sent();

        let hedge = if latency_critical && self.hedging {
            // Hedge on the lowest-latency alternative — the point is to beat
            // the primary, not to add a second slow copy.
            healthy
                .iter()
                .filter(|&&i| i != chosen)
                .min_by(|&&a, &&b| {
                    let ra = self.paths[a].rtt.unwrap_or(Duration::MAX);
                    let rb = self.paths[b].rtt.unwrap_or(Duration::MAX);
                    ra.cmp(&rb)
                })
                .map(|&i| {
                    self.paths[i].record_sent();
                    self.paths[i].name.clone()
                })
        } else {
            None
        };

        Some(Assignment {
            primary: self.paths[chosen].name.clone(),
            hedge,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deliver(scheduler: &mut Scheduler, name: &str, bytes: usize, rtt_ms: u64) {
        scheduler
            .path_mut(name)
            .unwrap()
            .record_delivered(bytes, Duration::from_millis(rtt_ms));
    }

    /// How many of `n` chunks each path was given.
    fn share(scheduler: &mut Scheduler, n: usize) -> Vec<(String, usize)> {
        let mut counts: Vec<(String, usize)> =
            scheduler.paths().iter().map(|p| (p.name.clone(), 0)).collect();
        for _ in 0..n {
            let assignment = scheduler.assign(false).expect("a healthy path");
            let entry = counts
                .iter_mut()
                .find(|(name, _)| *name == assignment.primary)
                .unwrap();
            entry.1 += 1;
        }
        counts
    }

    #[test]
    fn test_two_paths_can_be_active_at_once() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("quic");
        scheduler.add_path("tls");
        assert_eq!(scheduler.healthy_count(), 2);

        // With equal estimates the split is even, not all-to-one.
        let counts = share(&mut scheduler, 100);
        for (name, n) in counts {
            assert_eq!(n, 50, "{name} should carry half");
        }
    }

    #[test]
    fn test_adding_the_same_path_twice_is_a_no_op() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("quic");
        scheduler.add_path("quic");
        assert_eq!(scheduler.paths().len(), 1);
    }

    #[test]
    fn test_striping_follows_measured_capacity() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("fast");
        scheduler.add_path("slow");

        // Drive the estimates apart: same payload, very different RTTs.
        for _ in 0..20 {
            deliver(&mut scheduler, "fast", 64_000, 10);
            deliver(&mut scheduler, "slow", 64_000, 100);
        }

        let fast = scheduler.path_mut("fast").unwrap().capacity_bps();
        let slow = scheduler.path_mut("slow").unwrap().capacity_bps();
        let expected_fast_share = 1000.0 * fast / (fast + slow);

        let counts = share(&mut scheduler, 1000);
        let got = counts.iter().find(|(n, _)| n == "fast").unwrap().1 as f64;
        assert!(
            (got - expected_fast_share).abs() < 20.0,
            "fast path took {got} of 1000, expected about {expected_fast_share:.0}"
        );
        assert!(got > 600.0, "the faster path must clearly dominate");
    }

    #[test]
    fn test_a_lossy_path_is_taken_out_of_rotation() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("good");
        scheduler.add_path("bad");

        for _ in 0..10 {
            deliver(&mut scheduler, "good", 1400, 20);
            scheduler.path_mut("bad").unwrap().record_lost();
        }

        assert!(scheduler.path_mut("bad").unwrap().loss_rate() > UNHEALTHY_LOSS);
        assert_eq!(scheduler.healthy_count(), 1);

        // Everything now goes to the survivor — degraded throughput, but no
        // stall, which is the property that matters under partial failure.
        let counts = share(&mut scheduler, 50);
        assert_eq!(counts.iter().find(|(n, _)| n == "good").unwrap().1, 50);
    }

    #[test]
    fn test_loss_is_forgiven_once_a_path_delivers_again() {
        // Health must describe the present. A lifetime ratio would leave a
        // path that had one bad minute disqualified for the rest of a
        // long-lived tunnel, so the usable set could only ever shrink.
        let mut path = PathHealth::new("recovering");
        for _ in 0..20 {
            path.record_lost();
        }
        assert!(!path.is_healthy());
        let lifetime_losses = path.lifetime_lost();

        for _ in 0..20 {
            path.record_delivered(1400, Duration::from_millis(20));
        }
        assert!(path.is_healthy(), "a delivering path must be usable again");
        assert_eq!(
            path.lifetime_lost(),
            lifetime_losses,
            "recovery must not rewrite the diagnostic history"
        );
    }

    #[test]
    fn test_no_healthy_path_is_reported_rather_than_guessed() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("only");
        scheduler.path_mut("only").unwrap().disable();
        assert!(scheduler.assign(false).is_none());
    }

    #[test]
    fn test_an_idle_path_is_not_treated_as_broken() {
        // Idleness means no traffic, not failure. Judging paths on silence
        // would make a quiet tunnel disqualify every path it has.
        let mut path = PathHealth::new("idle");
        assert!(path.is_healthy());
        path.record_delivered(1400, Duration::from_millis(20));
        assert!(path.is_healthy());
    }

    #[test]
    fn test_hedging_duplicates_onto_the_lowest_latency_alternative() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("primary");
        scheduler.add_path("quick");
        scheduler.add_path("sluggish");
        scheduler.set_hedging(true);

        for _ in 0..10 {
            deliver(&mut scheduler, "quick", 1400, 10);
            deliver(&mut scheduler, "sluggish", 1400, 200);
        }

        let assignment = scheduler.assign(true).expect("a healthy path");
        let hedge = assignment.hedge.expect("a latency-critical chunk is hedged");
        assert_ne!(hedge, assignment.primary, "hedging onto itself is pointless");
        if assignment.primary != "quick" {
            assert_eq!(hedge, "quick", "hedge should take the fastest alternative");
        }
    }

    #[test]
    fn test_hedging_is_opt_in_and_only_for_critical_chunks() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("a");
        scheduler.add_path("b");

        // Off by default: duplicating bulk traffic would halve throughput.
        assert!(scheduler.assign(true).unwrap().hedge.is_none());

        scheduler.set_hedging(true);
        assert!(scheduler.assign(false).unwrap().hedge.is_none());
        assert!(scheduler.assign(true).unwrap().hedge.is_some());
    }

    #[test]
    fn test_hedging_needs_somewhere_to_hedge_to() {
        let mut scheduler = Scheduler::new();
        scheduler.add_path("lonely");
        scheduler.set_hedging(true);
        assert!(scheduler.assign(true).unwrap().hedge.is_none());
    }

    #[test]
    fn test_score_reflects_health_and_collapses_when_unhealthy() {
        let mut path = PathHealth::new("p");
        path.record_delivered(1_000_000, Duration::from_millis(10));
        let healthy_score = path.score();
        assert!(healthy_score > 0.0);

        path.disable();
        assert_eq!(path.score(), 0.0, "an unusable path must not be recommended");
    }

    #[test]
    fn test_health_report_includes_failing_paths_at_zero() {
        // The scoreboard replaces its measured set wholesale, so a failing
        // path must be reported as bad rather than omitted — omission would
        // silently hand it back to its last optimistic probe score.
        let mut scheduler = Scheduler::new();
        scheduler.add_path("good");
        scheduler.add_path("bad");
        deliver(&mut scheduler, "good", 1400, 20);
        scheduler.path_mut("bad").unwrap().disable();

        let report = scheduler.health_report();
        assert_eq!(report.len(), 2);
        assert_eq!(report["bad"], 0.0);
        assert!(report["good"] > 0.0);
    }

    #[test]
    fn test_one_path_failing_under_load_degrades_without_stalling() {
        // 16.3.5: throughput should dip, not stop. Everything the failing
        // path would have carried must still find a route.
        let mut scheduler = Scheduler::new();
        scheduler.add_path("a");
        scheduler.add_path("b");
        for _ in 0..10 {
            deliver(&mut scheduler, "a", 64_000, 20);
            deliver(&mut scheduler, "b", 64_000, 20);
        }

        let before = share(&mut scheduler, 200);
        assert!(before.iter().all(|(_, n)| *n > 50), "both paths should be loaded");

        // "b" starts black-holing under load.
        for _ in 0..20 {
            scheduler.path_mut("b").unwrap().record_lost();
        }
        assert_eq!(scheduler.healthy_count(), 1);

        let after = share(&mut scheduler, 200);
        let carried: usize = after.iter().map(|(_, n)| n).sum();
        assert_eq!(carried, 200, "no chunk may be left without a path");
        assert_eq!(after.iter().find(|(n, _)| n == "b").unwrap().1, 0);

        // And it comes back once it recovers, rather than being written off.
        scheduler.path_mut("b").unwrap().enable();
        deliver(&mut scheduler, "b", 64_000, 20);
        for _ in 0..40 {
            deliver(&mut scheduler, "b", 64_000, 20);
        }
        assert_eq!(scheduler.healthy_count(), 2);
    }

    #[test]
    fn test_removing_a_path_keeps_credits_aligned() {
        // The credit vector is indexed in parallel with the path vector; a
        // mismatch would silently misroute every subsequent chunk.
        let mut scheduler = Scheduler::new();
        scheduler.add_path("a");
        scheduler.add_path("b");
        scheduler.add_path("c");
        scheduler.assign(false);
        scheduler.remove_path("a");

        assert_eq!(scheduler.paths().len(), scheduler.credits.len());
        let counts = share(&mut scheduler, 100);
        assert_eq!(counts.len(), 2);
        assert!(counts.iter().all(|(_, n)| *n > 0));
    }
}
