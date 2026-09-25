//! Adaptive posture (Phase 16.4).
//!
//! Every evasion measure costs something — padding costs bandwidth, rhythm
//! shaping costs latency, cover traffic costs both. Paying that cost
//! permanently is the wrong trade on a network that is not interfering, and
//! not paying it is the wrong trade on one that is. A posture is the choice
//! between those, made continuously from evidence rather than once from
//! configuration.
//!
//! The asymmetry that shapes the whole design: **being caught is far more
//! expensive than being slow.** So escalation is immediate on the first
//! credible adverse signal, while relaxation is slow and requires a sustained
//! clean record. Hysteresis is not a tuning detail here; it is what stops an
//! attacker from inducing a cheap oscillation between postures, which would
//! itself be a recognisable signature.

use std::time::{Duration, Instant};

/// How the client trades performance against resistance to detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Posture {
    /// Nothing is interfering: minimal padding, no cover traffic, no shaping.
    Performance,
    /// Default. Modest padding, no cover traffic.
    Balanced,
    /// Something is interfering: the full shaping pipeline.
    Evasion,
}

impl Posture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::Balanced => "balanced",
            Self::Evasion => "evasion",
        }
    }

    /// The knobs this posture implies (16.4.2, 16.4.3).
    pub fn profile(&self) -> ShapingProfile {
        match self {
            // 16.4.2 — get out of the way. Padding is capped at a few bytes
            // purely to blur exact plaintext lengths, which is nearly free.
            Self::Performance => ShapingProfile {
                max_padding: 16,
                pad_to_uniform_size: false,
                rhythm_shaping: false,
                cover_traffic_interval: None,
                fragment_handshake: false,
                max_chunk_bytes: 65535,
            },
            Self::Balanced => ShapingProfile {
                max_padding: 64,
                pad_to_uniform_size: false,
                rhythm_shaping: false,
                cover_traffic_interval: None,
                fragment_handshake: true,
                max_chunk_bytes: 65535,
            },
            // 16.4.3 — everything on. Uniform sizing removes length as a
            // feature, cover traffic removes idleness as one, and capping the
            // chunk size keeps the packet-length distribution inside the range
            // ordinary traffic occupies.
            Self::Evasion => ShapingProfile {
                max_padding: 255,
                pad_to_uniform_size: true,
                rhythm_shaping: true,
                cover_traffic_interval: Some(Duration::from_secs(5)),
                fragment_handshake: true,
                max_chunk_bytes: 1400,
            },
        }
    }
}

/// Concrete shaping settings derived from a posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapingProfile {
    pub max_padding: u8,
    /// Pad every chunk to the same size, so length carries no information.
    pub pad_to_uniform_size: bool,
    /// Delay sends to match a traffic pattern.
    pub rhythm_shaping: bool,
    /// Emit padding chunks when idle, or `None` to stay silent.
    pub cover_traffic_interval: Option<Duration>,
    pub fragment_handshake: bool,
    pub max_chunk_bytes: usize,
}

/// Evidence the controller reacts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// A handshake failed outright.
    HandshakeFailed,
    /// A connection was reset in a way that looks like injection rather than
    /// ordinary teardown.
    SuspiciousReset,
    /// A path disappeared abruptly while healthy.
    SuddenPathLoss,
    /// The detector or prober reports interference.
    CensorshipDetected,
    /// A period passed with no adverse signal at all.
    CleanPeriod,
}

impl Signal {
    /// Whether this signal demands immediate demotion to `Evasion` (16.4.5).
    pub fn is_adverse(&self) -> bool {
        !matches!(self, Self::CleanPeriod)
    }
}

/// Minimum time at a posture before it may be relaxed, and the clean streak
/// required. Both must be satisfied: time alone would relax during a quiet
/// moment in an active block, and a streak alone would relax too fast on a
/// busy link.
pub const MIN_TIME_AT_POSTURE: Duration = Duration::from_secs(120);

/// Consecutive clean periods needed to relax one step.
pub const CLEAN_PERIODS_TO_RELAX: u32 = 5;

/// Decides the current posture from accumulated evidence.
#[derive(Debug)]
pub struct PostureController {
    current: Posture,
    /// The lowest posture the user permits. Escalation above it is automatic;
    /// relaxation below it never happens.
    floor: Posture,
    changed_at: Instant,
    clean_streak: u32,
    adverse_total: u64,
    min_time_at_posture: Duration,
    clean_periods_to_relax: u32,
}

impl PostureController {
    pub fn new(initial: Posture) -> Self {
        Self::with_floor(initial, Posture::Performance)
    }

    /// `floor` is the most relaxed posture permitted — a user in a hostile
    /// network can pin the client to `Evasion` and never be optimised out of
    /// it by a quiet hour.
    pub fn with_floor(initial: Posture, floor: Posture) -> Self {
        Self {
            current: initial.max(floor),
            floor,
            changed_at: Instant::now(),
            clean_streak: 0,
            adverse_total: 0,
            min_time_at_posture: MIN_TIME_AT_POSTURE,
            clean_periods_to_relax: CLEAN_PERIODS_TO_RELAX,
        }
    }

    /// Shorter timings for tests.
    pub fn with_timing(mut self, min_time: Duration, clean_periods: u32) -> Self {
        self.min_time_at_posture = min_time;
        self.clean_periods_to_relax = clean_periods;
        self
    }

    pub fn current(&self) -> Posture {
        self.current
    }

    pub fn profile(&self) -> ShapingProfile {
        self.current.profile()
    }

    pub fn time_at_posture(&self) -> Duration {
        self.changed_at.elapsed()
    }

    pub fn clean_streak(&self) -> u32 {
        self.clean_streak
    }

    pub fn adverse_total(&self) -> u64 {
        self.adverse_total
    }

    /// Feed in evidence. Returns the new posture if it changed.
    pub fn observe(&mut self, signal: Signal) -> Option<Posture> {
        if signal.is_adverse() {
            self.adverse_total += 1;
            // 16.4.5 — no averaging, no threshold, no delay. One credible
            // adverse signal is enough, because the cost of escalating
            // unnecessarily is some bandwidth while the cost of escalating too
            // late is the connection.
            self.clean_streak = 0;
            return self.set(Posture::Evasion);
        }

        self.clean_streak += 1;
        if self.clean_streak < self.clean_periods_to_relax {
            return None;
        }
        if self.time_at_posture() < self.min_time_at_posture {
            return None;
        }

        let relaxed = match self.current {
            Posture::Evasion => Posture::Balanced,
            Posture::Balanced => Posture::Performance,
            Posture::Performance => return None,
        };
        self.clean_streak = 0;
        self.set(relaxed)
    }

    /// Apply a posture, respecting the floor. Returns `Some` only on a change.
    fn set(&mut self, target: Posture) -> Option<Posture> {
        let target = target.max(self.floor);
        if target == self.current {
            return None;
        }
        self.current = target;
        self.changed_at = Instant::now();
        Some(target)
    }

    /// Force a posture, as a user override.
    pub fn force(&mut self, target: Posture) -> Option<Posture> {
        self.clean_streak = 0;
        self.set(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUICK: Duration = Duration::from_millis(20);

    fn controller() -> PostureController {
        PostureController::new(Posture::Balanced).with_timing(QUICK, 3)
    }

    #[test]
    fn test_postures_are_ordered_by_caution() {
        // Ordering is relied on by the floor logic, so it is worth pinning.
        assert!(Posture::Performance < Posture::Balanced);
        assert!(Posture::Balanced < Posture::Evasion);
        assert_eq!(Posture::Performance.max(Posture::Evasion), Posture::Evasion);
    }

    #[test]
    fn test_performance_profile_gets_out_of_the_way() {
        let p = Posture::Performance.profile();
        assert!(!p.rhythm_shaping);
        assert!(p.cover_traffic_interval.is_none());
        assert!(p.max_padding <= 16, "padding should be nearly free");
        assert_eq!(p.max_chunk_bytes, 65535, "no artificial chunk cap");
    }

    #[test]
    fn test_evasion_profile_turns_everything_on() {
        let p = Posture::Evasion.profile();
        assert!(p.rhythm_shaping);
        assert!(p.pad_to_uniform_size);
        assert!(p.cover_traffic_interval.is_some());
        assert!(p.fragment_handshake);
        assert!(
            p.max_chunk_bytes <= 1400,
            "chunks must stay inside the range ordinary traffic occupies"
        );
    }

    #[test]
    fn test_profiles_are_strictly_more_cautious_as_posture_rises() {
        let (perf, bal, eva) = (
            Posture::Performance.profile(),
            Posture::Balanced.profile(),
            Posture::Evasion.profile(),
        );
        assert!(perf.max_padding <= bal.max_padding);
        assert!(bal.max_padding <= eva.max_padding);
        assert!(perf.max_chunk_bytes >= eva.max_chunk_bytes);
    }

    #[test]
    fn test_any_adverse_signal_escalates_immediately() {
        // The whole point of 16.4.5: no threshold, no averaging window.
        for signal in [
            Signal::HandshakeFailed,
            Signal::SuspiciousReset,
            Signal::SuddenPathLoss,
            Signal::CensorshipDetected,
        ] {
            let mut c = controller();
            assert_eq!(c.observe(signal.clone()), Some(Posture::Evasion));
            assert_eq!(c.current(), Posture::Evasion);
        }
    }

    #[test]
    fn test_escalation_when_already_at_evasion_is_not_a_change() {
        let mut c = controller();
        c.observe(Signal::HandshakeFailed);
        assert_eq!(c.observe(Signal::SuspiciousReset), None, "no spurious event");
        assert_eq!(c.current(), Posture::Evasion);
        assert_eq!(c.adverse_total(), 2, "but the evidence is still counted");
    }

    #[test]
    fn test_relaxation_needs_both_a_clean_streak_and_time() {
        let mut c = PostureController::new(Posture::Evasion)
            .with_timing(Duration::from_secs(3600), 2);
        // Streak satisfied, time not.
        c.observe(Signal::CleanPeriod);
        assert_eq!(c.observe(Signal::CleanPeriod), None);
        assert_eq!(c.current(), Posture::Evasion);
    }

    #[test]
    fn test_relaxation_is_one_step_at_a_time() {
        let mut c = PostureController::new(Posture::Evasion).with_timing(QUICK, 2);
        std::thread::sleep(QUICK * 2);

        c.observe(Signal::CleanPeriod);
        assert_eq!(c.observe(Signal::CleanPeriod), Some(Posture::Balanced));

        std::thread::sleep(QUICK * 2);
        c.observe(Signal::CleanPeriod);
        assert_eq!(c.observe(Signal::CleanPeriod), Some(Posture::Performance));

        // And it stops there.
        std::thread::sleep(QUICK * 2);
        c.observe(Signal::CleanPeriod);
        assert_eq!(c.observe(Signal::CleanPeriod), None);
    }

    #[test]
    fn test_one_adverse_signal_resets_a_nearly_complete_streak() {
        // Otherwise an attacker could interfere at just under the streak
        // length and still ride the client down to Performance.
        let mut c = PostureController::new(Posture::Evasion).with_timing(QUICK, 3);
        std::thread::sleep(QUICK * 2);
        c.observe(Signal::CleanPeriod);
        c.observe(Signal::CleanPeriod);
        assert_eq!(c.clean_streak(), 2);

        c.observe(Signal::SuspiciousReset);
        assert_eq!(c.clean_streak(), 0);

        std::thread::sleep(QUICK * 2);
        c.observe(Signal::CleanPeriod);
        assert_eq!(c.observe(Signal::CleanPeriod), None, "streak must start over");
        assert_eq!(c.current(), Posture::Evasion);
    }

    #[test]
    fn test_hysteresis_makes_induced_flapping_pointless() {
        // An attacker who can inject one reset per clean period should never
        // be able to walk the client down out of Evasion.
        let mut c = PostureController::new(Posture::Balanced).with_timing(QUICK, 2);
        for _ in 0..20 {
            c.observe(Signal::CleanPeriod);
            c.observe(Signal::SuspiciousReset);
            std::thread::sleep(QUICK / 4);
        }
        assert_eq!(c.current(), Posture::Evasion);
    }

    #[test]
    fn test_floor_is_never_breached_by_relaxation() {
        // A user in a hostile network pins the client to Evasion; a quiet hour
        // must not optimise them out of it.
        let mut c = PostureController::with_floor(Posture::Evasion, Posture::Evasion)
            .with_timing(QUICK, 1);
        std::thread::sleep(QUICK * 2);
        for _ in 0..10 {
            assert_eq!(c.observe(Signal::CleanPeriod), None);
        }
        assert_eq!(c.current(), Posture::Evasion);
    }

    #[test]
    fn test_floor_also_lifts_a_too_relaxed_initial_posture() {
        let c = PostureController::with_floor(Posture::Performance, Posture::Balanced);
        assert_eq!(c.current(), Posture::Balanced);
    }

    #[test]
    fn test_force_respects_the_floor() {
        let mut c = PostureController::with_floor(Posture::Evasion, Posture::Balanced);
        assert_eq!(c.force(Posture::Performance), Some(Posture::Balanced));
        assert_eq!(c.current(), Posture::Balanced);
    }

    #[test]
    fn test_posture_has_a_stable_name_for_status_output() {
        assert_eq!(Posture::Performance.as_str(), "performance");
        assert_eq!(Posture::Balanced.as_str(), "balanced");
        assert_eq!(Posture::Evasion.as_str(), "evasion");
    }
}
