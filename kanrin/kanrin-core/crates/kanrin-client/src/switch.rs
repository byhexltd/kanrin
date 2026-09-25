//! Transport switching policy (Phase 16.2.3 – 16.2.5).
//!
//! The decision logic lives here, separate from the IO that carries it out, so
//! the timing rules that matter can be tested without sockets or sleeps.
//!
//! Two jobs:
//!
//! - [`LivenessMonitor`] — notice a dead transport fast enough that the
//!   tunnelled TCP stacks never do. A guest TCP retransmits after roughly one
//!   second, so detection has to land well inside that.
//! - [`SwitchPolicy`] — stop a flapping network from turning into a switch
//!   loop, without slowing down the first switch, which is the one the user
//!   actually feels.

use std::time::{Duration, Instant};

use kanrin_protocol::continuity::{Replay, SendBuffer};
use kanrin_protocol::crypto::SessionKeys;
use kanrin_protocol::resume::{ResumeRequest, ResumeResponse, ResumeStatus};
use kanrin_protocol::session::SessionId;
use kanrin_protocol::wire::{Chunk, ChunkHeader, ChunkType, HEADER_SIZE};
use kanrin_transport::{Connection, Endpoint, TransportRegistry};

use crate::ClientError;

/// A replacement transport that has completed the resumption handshake and is
/// carrying nothing yet (16.2.1).
pub struct Standby {
    pub connection: Box<dyn Connection>,
    pub transport: String,
    /// The server's receive position, reported in its resume response. Applied
    /// to our send buffer so the replay resends only what is genuinely missing.
    pub server_next_expected: u64,
}

/// Bring up a transport and attach it to an existing session.
///
/// Establishing the link and proving session ownership both happen here, while
/// the old transport is still live — so the switch itself is a pointer swap
/// rather than a reconnect, and the user-visible gap is the swap, not the
/// handshake (16.2.4, make-before-break).
pub async fn prepare_standby(
    registry: &TransportRegistry,
    endpoint: &Endpoint,
    exclude: &str,
    session_id: SessionId,
    keys: &SessionKeys,
    next_expected: u64,
) -> Result<Standby, ClientError> {
    let mut last_error = None;

    for transport in registry.all() {
        // A standby on the transport that is already failing is no standby.
        if transport.name() == exclude {
            continue;
        }

        let mut connection = match transport.connect(endpoint).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(transport = transport.name(), error = %e, "standby connect failed");
                last_error = Some(e.to_string());
                continue;
            }
        };

        match resume_on(&mut connection, session_id, keys, next_expected).await {
            Ok(server_next_expected) => {
                tracing::info!(transport = transport.name(), "standby transport ready");
                return Ok(Standby {
                    connection,
                    transport: transport.name().to_string(),
                    server_next_expected,
                });
            }
            Err(e) => {
                tracing::debug!(transport = transport.name(), error = %e, "resume failed");
                last_error = Some(e.to_string());
                let _ = connection.close().await;
            }
        }
    }

    Err(ClientError::ConnectionFailed(
        last_error.unwrap_or_else(|| "no standby transport available".into()),
    ))
}

/// Run the resumption handshake (16.1.6) over a freshly opened connection.
/// Returns the server's receive position.
async fn resume_on(
    connection: &mut Box<dyn Connection>,
    session_id: SessionId,
    keys: &SessionKeys,
    next_expected: u64,
) -> Result<u64, ClientError> {
    let fail = |m: String| ClientError::ConnectionFailed(m);

    let request = ResumeRequest::new(session_id, next_expected, keys)
        .map_err(|e| fail(format!("build resume request: {e}")))?;

    // Sent under the same all-zero key as the initial handshake: the request
    // carries its own MAC, so chunk-level encryption would add nothing, and
    // the server has to read it before it knows which keys to use.
    let encoded = Chunk::new_resume(request.encode())
        .encode_encrypted(&[0u8; 32], &[0u8; 12])
        .map_err(|e| fail(format!("encode resume request: {e}")))?;
    connection
        .send(&encoded)
        .await
        .map_err(|e| fail(format!("send resume request: {e}")))?;

    let data = connection
        .recv()
        .await
        .map_err(|e| fail(format!("recv resume response: {e}")))?;

    if data.len() < HEADER_SIZE {
        return Err(fail("resume response too short".into()));
    }
    let header = ChunkHeader::decode(&mut &data[..HEADER_SIZE])
        .map_err(|e| fail(format!("decode resume header: {e}")))?;
    if header.chunk_type != ChunkType::Resume {
        return Err(fail(format!("expected a Resume chunk, got {:?}", header.chunk_type)));
    }

    let chunk = Chunk::decode_encrypted(&data, &[0u8; 32], &[0u8; 12])
        .map_err(|e| fail(format!("decode resume response: {e}")))?;
    let response = ResumeResponse::decode(&chunk.payload)
        .map_err(|e| fail(format!("parse resume response: {e}")))?;

    // Verifying matters as much as being verified: without it, anything able
    // to answer on this port could take over the session's traffic.
    if !response
        .verify(&request, keys)
        .map_err(|e| fail(format!("verify resume response: {e}")))?
    {
        return Err(fail("resume response failed verification".into()));
    }
    if response.status != ResumeStatus::Ok {
        return Err(fail(format!("server refused resume: {:?}", response.status)));
    }

    Ok(response.next_expected)
}

/// Push every unacknowledged chunk onto the new transport, in order (16.1.5).
///
/// Returns how many were resent. A failure part-way is not fatal: the cursor
/// is discarded and the whole thing is retried on the next transport, since
/// anything resent twice is dropped by the peer as a duplicate.
pub async fn replay_onto(
    connection: &mut Box<dyn Connection>,
    buffer: &SendBuffer,
) -> Result<usize, ClientError> {
    let mut replay = Replay::new();
    while let Some((sequence, data)) = replay.next_chunk(buffer) {
        connection
            .send(data)
            .await
            .map_err(|e| ClientError::ConnectionFailed(format!("replay failed: {e}")))?;
        replay.confirm_sent(sequence);
    }
    Ok(replay.replayed())
}

/// Silence after which the active transport is presumed dead.
///
/// Sized against the guest TCP retransmission timer (~1 s at the low end):
/// detect inside 750 ms, switch inside 200 ms, and the inner connection never
/// sees a gap long enough to retransmit, let alone reset.
pub const LIVENESS_TIMEOUT: Duration = Duration::from_millis(750);

/// How often to probe when the link has gone quiet. Traffic of any kind counts
/// as liveness, so on a busy tunnel no probe is ever sent.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// Minimum gap between switches. Anything faster is thrash, not adaptation.
pub const BASE_COOLDOWN: Duration = Duration::from_secs(5);

/// Ceiling for the backoff applied to repeated switches.
pub const MAX_COOLDOWN: Duration = Duration::from_secs(120);

/// A switch is "repeated" if it follows the previous one within this window.
/// Beyond it the network is considered to have settled and the backoff resets.
pub const FLAP_WINDOW: Duration = Duration::from_secs(60);

/// Why a switch is being considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchReason {
    /// Nothing has arrived within [`LIVENESS_TIMEOUT`].
    LinkSilent,
    /// A send or receive failed outright.
    TransportError(String),
    /// The scoreboard prefers a different path.
    BetterPathAvailable(String),
}

impl SwitchReason {
    /// Whether the current transport is unusable, as opposed to merely worse.
    ///
    /// A broken link is switched even inside the cooldown: refusing would mean
    /// sitting on a transport that cannot carry anything, which is strictly
    /// worse than the thrash the cooldown exists to prevent.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::LinkSilent | Self::TransportError(_))
    }

    /// Human-readable text for the user-facing event (16.2.6).
    pub fn describe(&self) -> String {
        match self {
            Self::LinkSilent => "link went silent".to_string(),
            Self::TransportError(e) => format!("transport error: {e}"),
            Self::BetterPathAvailable(to) => format!("better path available: {to}"),
        }
    }
}

/// Tracks whether the active transport is still carrying traffic.
#[derive(Debug)]
pub struct LivenessMonitor {
    last_inbound: Instant,
    last_probe: Instant,
    timeout: Duration,
    probe_interval: Duration,
}

impl LivenessMonitor {
    pub fn new() -> Self {
        Self::with_timing(LIVENESS_TIMEOUT, PROBE_INTERVAL)
    }

    pub fn with_timing(timeout: Duration, probe_interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            last_inbound: now,
            last_probe: now,
            timeout,
            probe_interval,
        }
    }

    /// Any inbound frame proves the link is alive — data, ack, or pong alike.
    pub fn record_inbound(&mut self) {
        self.last_inbound = Instant::now();
    }

    /// Whether to send a keepalive now.
    ///
    /// Only when the link has already been quiet for a probe interval, so a
    /// busy tunnel pays nothing: its own traffic is the liveness signal, and
    /// adding periodic beacons to it would be a timing fingerprint for free.
    pub fn should_probe(&mut self) -> bool {
        let quiet = self.last_inbound.elapsed() >= self.probe_interval;
        let due = self.last_probe.elapsed() >= self.probe_interval;
        if quiet && due {
            self.last_probe = Instant::now();
            return true;
        }
        false
    }

    pub fn is_dead(&self) -> bool {
        self.last_inbound.elapsed() >= self.timeout
    }

    pub fn silent_for(&self) -> Duration {
        self.last_inbound.elapsed()
    }

    /// Reset after a switch, so the replacement is not judged on the silence
    /// of the transport it replaced.
    pub fn reset(&mut self) {
        let now = Instant::now();
        self.last_inbound = now;
        self.last_probe = now;
    }
}

impl Default for LivenessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate-limits switching so a flapping network cannot induce a switch loop.
#[derive(Debug)]
pub struct SwitchPolicy {
    last_switch: Option<Instant>,
    /// Switches that followed their predecessor inside [`FLAP_WINDOW`].
    consecutive: u32,
    base_cooldown: Duration,
    max_cooldown: Duration,
    flap_window: Duration,
}

impl SwitchPolicy {
    pub fn new() -> Self {
        Self::with_timing(BASE_COOLDOWN, MAX_COOLDOWN, FLAP_WINDOW)
    }

    pub fn with_timing(
        base_cooldown: Duration,
        max_cooldown: Duration,
        flap_window: Duration,
    ) -> Self {
        Self {
            last_switch: None,
            consecutive: 0,
            base_cooldown,
            max_cooldown,
            flap_window,
        }
    }

    /// Current cooldown: doubles per consecutive switch, capped.
    pub fn cooldown(&self) -> Duration {
        self.base_cooldown
            .saturating_mul(1u32 << self.consecutive.min(16))
            .min(self.max_cooldown)
    }

    /// Whether a switch for `reason` may proceed now.
    pub fn allows(&self, reason: &SwitchReason) -> bool {
        // A dead link is switched regardless: waiting out a cooldown on a
        // transport that carries nothing helps no one.
        if reason.is_failure() {
            return true;
        }
        match self.last_switch {
            None => true,
            Some(at) => at.elapsed() >= self.cooldown(),
        }
    }

    /// Record a completed switch.
    pub fn record(&mut self) {
        let flapping = self
            .last_switch
            .is_some_and(|at| at.elapsed() < self.flap_window);
        self.consecutive = if flapping { self.consecutive + 1 } else { 0 };
        self.last_switch = Some(Instant::now());
    }

    pub fn consecutive_switches(&self) -> u32 {
        self.consecutive
    }

    pub fn since_last_switch(&self) -> Option<Duration> {
        self.last_switch.map(|at| at.elapsed())
    }
}

impl Default for SwitchPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICK: Duration = Duration::from_millis(20);

    #[test]
    fn test_detection_budget_leaves_room_for_the_switch() {
        // The whole point of the timeout is to fit inside a guest TCP's
        // retransmission timer together with the switch that follows.
        assert!(LIVENESS_TIMEOUT + Duration::from_millis(200) < Duration::from_secs(1));
        assert!(PROBE_INTERVAL < LIVENESS_TIMEOUT);
    }

    #[test]
    fn test_inbound_traffic_keeps_the_link_alive() {
        let mut monitor = LivenessMonitor::with_timing(TICK * 3, TICK);
        for _ in 0..5 {
            std::thread::sleep(TICK);
            monitor.record_inbound();
            assert!(!monitor.is_dead());
        }
    }

    #[test]
    fn test_silence_is_eventually_fatal() {
        let monitor = LivenessMonitor::with_timing(TICK, TICK);
        std::thread::sleep(TICK * 2);
        assert!(monitor.is_dead());
        assert!(monitor.silent_for() >= TICK);
    }

    #[test]
    fn test_busy_link_is_never_probed() {
        // Probes exist to test a quiet link. On a busy one they would be pure
        // overhead and an easy timing signature.
        let mut monitor = LivenessMonitor::with_timing(TICK * 10, TICK * 5);
        for _ in 0..5 {
            monitor.record_inbound();
            assert!(!monitor.should_probe());
        }
    }

    #[test]
    fn test_quiet_link_is_probed_once_per_interval() {
        let mut monitor = LivenessMonitor::with_timing(TICK * 10, TICK);
        std::thread::sleep(TICK * 2);
        assert!(monitor.should_probe());
        // Not again until the next interval elapses.
        assert!(!monitor.should_probe());
        std::thread::sleep(TICK * 2);
        assert!(monitor.should_probe());
    }

    #[test]
    fn test_reset_does_not_blame_the_replacement_for_the_old_silence() {
        let mut monitor = LivenessMonitor::with_timing(TICK, TICK);
        std::thread::sleep(TICK * 2);
        assert!(monitor.is_dead());
        monitor.reset();
        assert!(!monitor.is_dead());
    }

    #[test]
    fn test_first_switch_is_never_delayed() {
        let policy = SwitchPolicy::new();
        assert!(policy.allows(&SwitchReason::BetterPathAvailable("quic".into())));
        assert!(policy.allows(&SwitchReason::LinkSilent));
    }

    #[test]
    fn test_cooldown_blocks_only_opportunistic_switches() {
        let mut policy = SwitchPolicy::with_timing(TICK * 10, TICK * 100, TICK * 50);
        policy.record();

        assert!(
            !policy.allows(&SwitchReason::BetterPathAvailable("quic".into())),
            "a merely-better path must wait"
        );
        assert!(
            policy.allows(&SwitchReason::LinkSilent),
            "a dead link must switch immediately"
        );
        assert!(policy.allows(&SwitchReason::TransportError("reset".into())));
    }

    #[test]
    fn test_repeated_switches_back_off_exponentially() {
        let mut policy = SwitchPolicy::with_timing(TICK, TICK * 1000, TICK * 1000);
        assert_eq!(policy.cooldown(), TICK);
        policy.record();
        assert_eq!(policy.consecutive_switches(), 0);
        policy.record();
        assert_eq!(policy.cooldown(), TICK * 2);
        policy.record();
        assert_eq!(policy.cooldown(), TICK * 4);
        policy.record();
        assert_eq!(policy.cooldown(), TICK * 8);
    }

    #[test]
    fn test_backoff_is_capped() {
        let mut policy = SwitchPolicy::with_timing(TICK, TICK * 4, TICK * 1000);
        for _ in 0..20 {
            policy.record();
        }
        assert_eq!(policy.cooldown(), TICK * 4, "backoff must not run away");
    }

    #[test]
    fn test_a_settled_network_clears_the_backoff() {
        // Backoff punishes flapping, not a long-lived connection that switches
        // once an hour.
        let mut policy = SwitchPolicy::with_timing(TICK, TICK * 100, TICK);
        policy.record();
        policy.record();
        assert_eq!(policy.consecutive_switches(), 1);

        std::thread::sleep(TICK * 2);
        policy.record();
        assert_eq!(policy.consecutive_switches(), 0, "quiet period should reset it");
        assert_eq!(policy.cooldown(), TICK);
    }

    #[test]
    fn test_reasons_classify_correctly() {
        assert!(SwitchReason::LinkSilent.is_failure());
        assert!(SwitchReason::TransportError("boom".into()).is_failure());
        assert!(!SwitchReason::BetterPathAvailable("ws".into()).is_failure());
        assert!(SwitchReason::LinkSilent.describe().contains("silent"));
    }
}
