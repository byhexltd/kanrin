//! Phase 16.4.7 — posture escalates under pressure and relaxes when clean.
//!
//! The unit tests in `posture.rs` cover each rule in isolation. What matters
//! in practice is the trajectory over a whole session, so these drive the
//! controller through realistic sequences and assert on the path it takes, not
//! just its final state.
//!
//! The property being defended throughout is the asymmetry: escalation is
//! cheap and immediate, relaxation is expensive and slow. Anything that lets
//! an attacker walk the client down to `Performance` is a failure, even if the
//! client eventually recovers.

use std::time::Duration;

use kanrin_client::posture::{Posture, PostureController, Signal};

const STEP: Duration = Duration::from_millis(30);

fn controller(initial: Posture) -> PostureController {
    PostureController::new(initial).with_timing(STEP, 3)
}

/// Feed a run of clean periods, waiting long enough that time is not the
/// limiting factor.
fn quiet(controller: &mut PostureController, periods: usize) -> Vec<Posture> {
    let mut transitions = Vec::new();
    for _ in 0..periods {
        std::thread::sleep(STEP / 2);
        if let Some(p) = controller.observe(Signal::CleanPeriod) {
            transitions.push(p);
        }
    }
    transitions
}

#[test]
fn a_single_block_escalates_a_performance_client_all_the_way() {
    // A client that had been optimised down must not need several strikes to
    // protect itself — by the time a second arrives the session may be gone.
    let mut c = controller(Posture::Performance);
    assert_eq!(c.current(), Posture::Performance);

    assert_eq!(c.observe(Signal::CensorshipDetected), Some(Posture::Evasion));
    assert_eq!(c.current(), Posture::Evasion);

    let profile = c.profile();
    assert!(profile.rhythm_shaping);
    assert!(profile.cover_traffic_interval.is_some());
}

#[test]
fn sustained_pressure_keeps_the_client_pinned() {
    let mut c = controller(Posture::Balanced);

    // Interference arrives faster than the clean streak can ever complete.
    for round in 0..30 {
        c.observe(Signal::CleanPeriod);
        c.observe(Signal::CleanPeriod);
        c.observe(if round % 2 == 0 {
            Signal::HandshakeFailed
        } else {
            Signal::SuspiciousReset
        });
        std::thread::sleep(STEP / 3);
    }

    assert_eq!(c.current(), Posture::Evasion, "pressure must hold the posture");
    assert_eq!(c.clean_streak(), 0);
    assert_eq!(c.adverse_total(), 30);
}

#[test]
fn a_network_that_clears_up_relaxes_step_by_step() {
    let mut c = controller(Posture::Balanced);
    c.observe(Signal::SuddenPathLoss);
    assert_eq!(c.current(), Posture::Evasion);

    // Long enough to satisfy both the streak and the dwell time.
    let transitions = quiet(&mut c, 20);
    assert_eq!(
        transitions,
        vec![Posture::Balanced, Posture::Performance],
        "relaxation must pass through Balanced, never jump"
    );
    assert_eq!(c.current(), Posture::Performance);
}

#[test]
fn escalation_is_always_faster_than_relaxation() {
    // The asymmetry stated numerically: one signal up, many periods down.
    let mut c = controller(Posture::Performance);

    c.observe(Signal::SuspiciousReset);
    assert_eq!(c.current(), Posture::Evasion, "one signal to escalate fully");

    let mut periods_to_return = 0;
    while c.current() != Posture::Performance {
        std::thread::sleep(STEP / 2);
        c.observe(Signal::CleanPeriod);
        periods_to_return += 1;
        assert!(periods_to_return < 100, "relaxation failed to converge");
    }

    assert!(
        periods_to_return >= 6,
        "returning took only {periods_to_return} periods — relaxation is too cheap"
    );
}

#[test]
fn an_attacker_pacing_signals_cannot_walk_the_client_down() {
    // The adversary knows the streak length and injects one signal just
    // before it completes, trying to keep the client oscillating — which is
    // itself a distinctive pattern, quite apart from the reduced protection.
    let mut c = controller(Posture::Balanced);
    c.observe(Signal::CensorshipDetected);

    let mut postures = Vec::new();
    for _ in 0..40 {
        std::thread::sleep(STEP / 2);
        c.observe(Signal::CleanPeriod);
        c.observe(Signal::CleanPeriod);
        c.observe(Signal::SuspiciousReset);
        postures.push(c.current());
    }

    assert!(
        postures.iter().all(|p| *p == Posture::Evasion),
        "the client must not oscillate under paced interference"
    );
}

#[test]
fn a_pinned_client_stays_pinned_through_a_long_quiet_spell() {
    // Someone who knows their network is hostile can pin the floor. An hour
    // of quiet is not evidence that the censor went away.
    let mut c = PostureController::with_floor(Posture::Evasion, Posture::Evasion)
        .with_timing(STEP, 1);

    let transitions = quiet(&mut c, 50);
    assert!(transitions.is_empty(), "the floor must hold");
    assert_eq!(c.current(), Posture::Evasion);
    assert!(c.profile().pad_to_uniform_size);
}

#[test]
fn the_cost_of_each_posture_is_ordered_as_advertised() {
    // Users choose a posture on the promise that a higher one is strictly
    // more cautious; a regression here would quietly break that promise.
    let profiles = [
        Posture::Performance.profile(),
        Posture::Balanced.profile(),
        Posture::Evasion.profile(),
    ];

    for pair in profiles.windows(2) {
        let (lower, higher) = (pair[0], pair[1]);
        assert!(lower.max_padding <= higher.max_padding);
        assert!(lower.max_chunk_bytes >= higher.max_chunk_bytes);
        assert!(!lower.rhythm_shaping || higher.rhythm_shaping);
        assert!(lower.cover_traffic_interval.is_none() || higher.cover_traffic_interval.is_some());
    }
}
