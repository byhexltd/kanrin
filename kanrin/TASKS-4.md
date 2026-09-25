# Kanrin — Task Breakdown (Phases 16-17)

> Continues `TASKS.md` (0-3), `TASKS-2.md` (4-8), `TASKS-3.md` (9-15).
>
> Rationale for Phase 16 lives in `ROADMAP.md`. Rationale for Phase 17 lives in
> `DESIGN-EVASION.md`. Those files explain the reasoning; this file is the single
> place that lists the concrete work items. Tasks are not restated elsewhere.

---

## Document contract

| File | Owns |
|------|------|
| `TASKS.md`, `TASKS-2.md`, `TASKS-3.md`, `TASKS-4.md` | The task inventory. Nothing else lists tasks |
| `ROADMAP.md` | Priority, execution order, North Star, invariants I1-I3 |
| `DESIGN-EVASION.md` | Threat model, prior-art analysis, mechanism design |
| `README.md` | Architecture overview |
| `STRUCTS.md` | Data structure reference |

---

## Supersede notice — Phase 9.3

`TASKS-3.md` section 9.3 ("Masquerade") predates the analysis in
`DESIGN-EVASION.md` §1. Its items assume two distinct server code paths selected
by request type, which the design doc identifies as the weak point. The replacement
is Phase 17.1 (a single code path).

| Old item | Disposition |
|----------|-------------|
| 9.3.1 request classification → alternate response | Superseded by 17.1 (the branch is the problem) |
| 9.3.2 static file serving | Folded into 17.1.4 |
| 9.3.3 reverse proxy mode | Folded into 17.1.5 |
| 9.3.4 response timing normalization | Folded into 17.1.7 |
| 9.3.5 client fingerprint checking | Dropped (introduces a branch; conflicts with 17.1) |
| 9.3.6 HTTP header correctness | Folded into 17.1.4 |
| 9.3.7, 9.3.8 tests | Superseded by 17.1.9-17.1.12 |

Implement 17.1 instead of 9.3.x. Mark 9.3 superseded once 17.1 lands.

---

## Phase 16 — Continuity & Adaptation

Rationale: `ROADMAP.md` § Phase 16.

### 16.1 — Session Continuity Layer
- [x] **16.1.1** Add a monotonic sequence number to every data chunk, scoped to the session and independent of transport — carried on the wire (`ChunkHeader.sequence`), authenticated as AAD, and used to derive the AEAD nonce (`crypto::nonce_from_sequence`) so decryption is order-independent. Verified by `test_out_of_order_decrypt`. Client/server compiled with zero changes.
- [x] **16.1.2** Send buffer retaining unacknowledged chunks — `continuity::SendBuffer` keyed by sequence (`BTreeMap`), stores transport-independent encoded bytes for replay (16.1.5), byte-bounded with `SendBufferFull` back-pressure signal (wired in 16.1.7), cumulative + selective ack. 8 unit tests.
- [x] **16.1.3** Cumulative + selective acknowledgement chunk type — `ControlMessage::Ack { next_expected, ranges }` (type `0x07`) carrying a TCP-style cumulative point plus up to `MAX_SACK_RANGES` (32) inclusive `SackRange`s, so one ack fits a single control chunk (522 bytes). Decode enforces a canonical form (well-formed, ascending, disjoint, non-adjacent, strictly above the cumulative point) and rejects anything else, keeping the peer's input space small and processing linear. Consumed by `SendBuffer::apply_ack`, which is idempotent under stale/duplicated/reordered acks. 7 unit tests.
- [x] **16.1.4** Receive-side reorder buffer and duplicate suppression — `continuity::ReceiveBuffer` delivers strictly in sequence order, so everything below `next_expected` is known-delivered and duplicate detection is exact (not probabilistic) with no history retained. Out-of-order chunks are held in a `BTreeMap` until the gap fills, then released as a run; `build_ack()` coalesces adjacent held sequences into the `Ack` of 16.1.3, capped at `MAX_SACK_RANGES` (lowest holes first). Byte-bounded with `ReceiveBufferFull`, but an in-order chunk is never refused since accepting it is what drains the buffer. 6 unit tests, including a round-trip proving the generated ack releases exactly the right chunks from a peer `SendBuffer`.
- [x] **16.1.5** Replay of unacknowledged chunks onto a new transport — `continuity::Replay`, a cursor over the live `SendBuffer` rather than a snapshot, so acks landing mid-replay prune chunks instead of resending them, and a replacement transport that also dies needs no unwinding (carry the same cursor to the next one). Sync and transport-agnostic, keeping `kanrin-protocol` free of any dependency on `kanrin-transport`; the driving loop lands with the transport swap in 16.2.2. 6 unit tests including an end-to-end `SendBuffer` → `Replay` → `ReceiveBuffer` case proving the stream is restored exactly once, in order, with resends absorbed as duplicates.
- [x] **16.1.6** Resumption handshake: prove session ownership without a full key exchange; report last contiguous sequence received — new `resume` module: `ResumeRequest` (96 B) / `ResumeResponse` (73 B), two messages, no X25519. Ownership is proved by HMAC-SHA256 under a dedicated key from `crypto::derive_resumption_key` (HKDF over both write keys, distinct `info` so the MAC never shares a key with the AEAD); **no bearer token is ever transmitted**, so capturing a resume message does not let it be reused. Freshness from bounded timestamp drift + 32-byte client nonce; the response's proof covers that nonce, so an old response cannot be replayed at the client. All MAC inputs are fixed-width, making the transcript unambiguous. Each side reports its `ReceiveBuffer::next_expected()`, which feeds the 16.1.5 replay. 8 unit tests covering tampering of every covered field, stale requests, wrong keys, and response replay.
- [x] **16.1.7** Bound the send buffer and apply back-pressure to the TUN reader — first task to wire the continuity layer into the live data plane. Client (`kanrin-client/src/pipeline.rs`): every data chunk is retained in a bounded `SendBuffer` and released by incoming `Ack` control chunks; the TUN→encrypt queue became a **bounded** channel and its `select!` branch is gated on `!send_buffer.is_full()`, so a stalled transport parks the TUN reader instead of growing memory. Chunks are retained even when the send itself fails, since those are precisely the ones a replay must resend. Server (`kanrin-server/src/session.rs`): data chunks now pass through a `ReceiveBuffer` (reorder + duplicate suppression) before the forwarder, and acks are emitted every 32 chunks or 200 ms via a channel to the writer task — without this the client's buffer could never drain. Ack timing is checked on chunk arrival rather than from a `select!` timer because `read_exact` is not cancel-safe.
- [x] **16.1.8** Tests: drop the transport mid-transfer; byte stream stays intact, no inner TCP resets — integration suite `crates/kanrin-protocol/tests/transport_switch.rs` (4 tests) driving 16.1.1–16.1.7 together over a `Link` that can be cut, discarding whatever was in flight. Every test asserts the same application-visible property that keeps inner TCP alive: exactly the payloads sent, exactly once each, in order. Covers a single mid-transfer drop, a link cut every 40 packets for 300 packets, a lost ack whose resends must all be absorbed as duplicates, and chunks interleaved across two live transports. Verified non-vacuous: temporarily suppressing the replay makes the two switch tests fail (60/200 and 36/300 delivered).
- [x] **16.1.9** Tests: buffer bound respected under a stalled transport — `crates/kanrin-protocol/tests/buffer_bounds.rs` (5 tests). A stall is nastier than a drop: nothing errors, so the sender keeps producing while acks never arrive, and the retention that makes replay possible becomes unbounded growth. Asserts memory is capped, that a refused chunk surfaces as `SendBufferFull` rather than being silently dropped (discarding unacked data tears the stream as badly as losing it on the wire), that an ack releases exactly the space it covers, that three stall/drain cycles lose nothing, that one oversized chunk is admitted but the next is not, and that the receive side is bounded when a gap never fills while still accepting the chunk that fills it.

### 16.2 — Hot Standby & Seamless Switch
- [x] **16.2.1** Keep the next-best transport fully handshaked and idle — required a server-side foundation first: a session used to *be* a TLS connection, so any replacement transport got a new identity and a new tunnel address, which is visible to every tunnelled TCP connection. New `kanrin-server/src/registry.rs` lifts the durable state (keys, tunnel IP, sequence counters, both continuity buffers, forwarder queue) into a `SessionRegistry`; a connection is now a temporary *attachment*. New `ChunkType::Resume` (0x05) lets the server tell "attach" from "new" by reading the plaintext chunk header, with no ambiguity between a `ClientHello` and a random-looking `ResumeRequest`. `ServerFinished.session_token` became `tunnel_ip(4) || session_id(16)` so the client holds the handle it needs to reattach. Address ownership moved from connections to registry entries, reclaimed by a reaper (`SESSION_LINGER` 120 s) that also unregisters the forwarder queue — otherwise a reused address would inherit a stale queue. An attached session is never reaped, however idle. Server now keeps its own `SendBuffer` and the client acks, so an interrupted download can be replayed. 5 registry unit tests.
- [x] **16.2.2** Switch as an atomic swap of the active transport handle, followed by 16.1.5 replay — `pipeline::attempt_switch` + `client/src/switch.rs` (`prepare_standby`, `resume_on`, `replay_onto`). The replacement is connected, resumed and has carried the entire replay *before* `std::mem::replace` swaps the active handle, so a failed switch costs nothing and the old transport still owns the session. `resume_on` verifies the server's response proof, not just its status — without that, anything able to answer on the port could take over the session's traffic. Send failures and recv failures now switch instead of tearing the tunnel down; only `MAX_FAILED_SWITCHES` consecutive failures end it.
- [x] **16.2.3** Liveness detection fast enough to switch before the inner TCP stack notices (detect <1s, switch <200ms) — `switch::LivenessMonitor`. A blocked transport often does not error: the socket stays open and nothing arrives, which is precisely what filtering looks like, so silence is treated as death. `LIVENESS_TIMEOUT` 750 ms + a 200 ms switch budget fits inside the ~1 s guest-TCP retransmission timer (asserted by a test). Any inbound frame counts as liveness, so a busy tunnel never emits a probe — periodic beacons on a loaded link would be pure overhead and a free timing fingerprint. Server answers `Ping` with `Pong`, otherwise a quiet link would always look dead.
- [x] **16.2.4** Make-before-break ordering: never tear down the old transport until the new one has carried an acknowledged chunk — `attempt_switch` returns the displaced handle instead of closing it; the pipeline parks it in `draining` and closes it only when the *next inbound frame* arrives on the replacement, which is the proof that the new path works in both directions. Server side mirrors this: `SessionEntry::attach` evicts the previous connection only after the replay has been written to the new one.
- [x] **16.2.5** Switch cooldown and flap damping — `switch::SwitchPolicy`. Cooldown doubles per switch inside `FLAP_WINDOW` (60 s), capped at `MAX_COOLDOWN`, and resets once the network settles, so backoff punishes flapping rather than a long-lived connection that switches occasionally. Crucially the cooldown gates only *opportunistic* switches: `SwitchReason::is_failure()` bypasses it, because waiting out a cooldown on a transport that carries nothing is strictly worse than the thrash the cooldown exists to prevent.
- [x] **16.2.6** Emit a user-facing event describing the switch, never an error — the existing `KanrinEvent::TransportSwitched { from, to, reason }` is emitted with `SwitchReason::describe()`; no error path is taken on a successful switch. Reporting a recovery as an error would train users to distrust the feature that just saved their connection.
- [x] **16.2.7** Tests: transport interrupted mid-download, download still completes — `crates/kanrin-protocol/tests/download_survives_switch.rs`. 16.1.8 covered client→server; a download is the direction users notice and carries an extra hazard, since the origin keeps producing while the link is gone. Modelled end-to-end over the real primitives (server `SendBuffer` + `Session`, client `ReceiveBuffer` + `Session`, wire-encoded `Ack`, real resumption handshake). 500 × 1400-byte blocks with the transport dead for 50 of them: the transfer completes byte-exact.
- [x] **16.2.8** Tests: repeated forced switches do not corrupt the stream — same suite, 5 tests: a switch every 30 blocks over 600 blocks (20+ switches), a switch while a gap is open (only the contiguous prefix may be delivered, order restored afterwards), and the two halves of the de-duplication story — an **exact** resumption position makes replay precise with zero resends, while a **stale** one (client switches before draining what arrived) causes resends that must be absorbed rather than double-delivered.

### 16.3 — Multipath
- [x] **16.3.1** Allow two or more healthy transports active at once — `kanrin-client/src/multipath.rs`. Because 16.1 made a chunk transport-independent (carries its own sequence, decrypts in any order, de-duplicated on arrival), multipath needs no new protocol machinery — only a routing decision, kept as pure arithmetic apart from the IO. Reordering is not a hazard here but a design consequence: the receiver's reorder buffer is what turns striping back into a stream, which frees the scheduler to optimise purely for throughput.
- [x] **16.3.2** Scheduler striping chunks across paths by measured capacity — `Scheduler::assign` uses credit-based selection rather than weighted-random: over any window the split matches the capacity ratio exactly, where random selection only approaches it in the limit and never on the short flows that dominate a tunnel. Capacity and RTT are EWMA-smoothed (α 0.25), and a loss is charged against the estimate immediately rather than left to drift, so a dying path stops being fed at once.
- [x] **16.3.3** Hedging: duplicate latency-critical chunks on a second path, deduplicated by 16.1.4 — opt-in and only for chunks marked latency-critical (duplicating bulk traffic would halve throughput). The hedge goes to the lowest-RTT *alternative*, since the point is to beat the primary rather than add a second slow copy; the loser is dropped by the receiver as a duplicate, so hedging costs bandwidth and nothing else.
- [x] **16.3.4** Per-path health accounting feeding the scoreboard — `PathHealth` plus `Scheduler::health_report()`, consumed by a new `ScoreBoard::update_measured` and a `ScoreWeights::measured` term. A live measurement outranks a probe: a probe estimates whether a path *might* work, the measurement records what it is doing now, so a demonstrably failing path can no longer keep its rank on an old successful probe. Failing paths are reported at zero rather than omitted, because the scoreboard replaces its measured set wholesale and omission would quietly restore the stale probe score. An idle path is explicitly not unhealthy — only one given work that failed to deliver — otherwise a quiet tunnel would disqualify all of its own paths.
- [x] **16.3.5** Tests: one path fails under load, throughput dips but no stall — 16 unit tests. The load-failure test asserts every chunk still finds a route once one of two loaded paths starts black-holing. Writing it exposed a real design bug: loss was a *lifetime* ratio, so a path that had one bad minute stayed disqualified for the rest of a long-lived tunnel and the usable set could only ever shrink. Fixed by making loss an EWMA (lifetime counters kept for diagnostics), with `test_loss_is_forgiven_once_a_path_delivers_again` pinning the recovery behaviour.

### 16.4 — Adaptive Posture
- [x] **16.4.1** Define postures: `Performance`, `Balanced`, `Evasion` — `kanrin-client/src/posture.rs`. Every evasion measure costs something, so paying for it permanently is wrong on a clean network and not paying is wrong on a hostile one; a posture is that choice made continuously from evidence. `Posture` is `Ord` by caution, which the floor logic relies on, and each maps to a concrete `ShapingProfile`.
- [x] **16.4.2** `Performance` — minimal padding, no cover traffic, largest window, lowest latency — padding capped at 16 bytes purely to blur exact plaintext lengths (nearly free), no rhythm shaping, no cover traffic, no artificial chunk cap.
- [x] **16.4.3** `Evasion` — full shaping pipeline: rhythm shaping, padding, fragmentation, cover traffic — uniform-size padding removes length as a feature, cover traffic removes idleness as one, and a 1400-byte chunk cap keeps the packet-length distribution inside the range ordinary traffic occupies. A test asserts the three profiles are monotonically more cautious, so the promise users choose on cannot silently regress.
- [x] **16.4.4** Promotion/demotion driven by detector, prober and scoreboard, with hysteresis — `PostureController`. Relaxation requires **both** a clean streak and a minimum dwell time: time alone would relax during a quiet moment inside an active block, a streak alone would relax too fast on a busy link. Relaxation is one step at a time. A `floor` lets a user pin the client so a quiet hour cannot optimise them out of protection.
- [x] **16.4.5** Immediate demotion to `Evasion` on adverse signals — no threshold, no averaging window: one credible signal escalates fully, because the cost of escalating unnecessarily is bandwidth while the cost of escalating late is the connection. A single adverse signal also resets the clean streak, which is what makes paced interference useless — `an_attacker_pacing_signals_cannot_walk_the_client_down` drives 40 rounds of "two clean periods then one reset" and asserts the posture never oscillates.
- [x] **16.4.6** Surface current posture in status output — `ConnectionStats.posture` plus a `KanrinEvent::PostureChanged`. Reported as a state change rather than a warning: escalation is the client working as intended, and labelling it a problem would push users to disable what is protecting them. Wired into the pipeline, driven by real signals (`SuddenPathLoss` on liveness timeout, `SuspiciousReset` on recv failure, `CleanPeriod` on a 30 s tick).
- [x] **16.4.7** Tests: posture escalates under simulated pressure, relaxes when clean — 14 unit tests plus `crates/kanrin-client/tests/posture_under_pressure.rs` (7 trajectory tests). These assert the *path* taken over a session, not just the end state, and pin the central asymmetry numerically: one signal to escalate fully, at least six clean periods to return.

---

## Phase 17 — Single-Path Consistency & Shaping

Rationale: `DESIGN-EVASION.md` §2 Round 4.

### 17.1 — Single-Stack Invariance
- [ ] **17.1.1** Audit every place where authenticated and unauthenticated connections diverge; document each divergence
- [ ] **17.1.2** Unify TLS termination so one implementation handles both
- [ ] **17.1.3** Serve real content from the same process and code path
- [ ] **17.1.4** One HTTP response path (headers, static files) shared by all clients
- [ ] **17.1.5** Optional upstream reverse-proxy target, same path for everyone
- [ ] **17.1.6** Discover authentication inside an already-established session, never as a branch that selects a different stack
- [ ] **17.1.7** Normalize response timing so the auth outcome is not observable
- [ ] **17.1.8** Port the reference consistency-probe methodology into the testbed
- [ ] **17.1.9** Tests: non-advancing-record tolerance identical in both cases
- [ ] **17.1.10** Tests: replayed handshake produces identical observable behavior
- [ ] **17.1.11** Tests: error responses byte-identical to the genuine site
- [ ] **17.1.12** Tests: response timing distribution independent of auth outcome

### 17.2 — Volume-Plausible Carriers
- [ ] **17.2.1** Define the `Carrier` trait: byte envelope, shape, plausible duration
- [ ] **17.2.2** Implement `WebBrowsing`, `VideoStreaming`, `FileSync`, `VideoCall`
- [ ] **17.2.3** Carrier selection from workload class and posture
- [ ] **17.2.4** Genuine cover fetch during connection establishment
- [ ] **17.2.5** Volume accounting so tunnel bytes stay inside the envelope
- [ ] **17.2.6** Graceful degradation when the tunnel exceeds the envelope
- [ ] **17.2.7** Tests: flow-level statistics match the claimed carrier class

### 17.3 — Live-Corpus Shaping
- [ ] **17.3.1** Passive reference collection from existing user traffic
- [ ] **17.3.2** Packet-length distribution matching
- [ ] **17.3.3** Inter-arrival-time distribution matching
- [ ] **17.3.4** First-N-seconds fidelity as a hard constraint
- [ ] **17.3.5** Corpus aging and refresh
- [ ] **17.3.6** Tests: KL divergence against the reference stays under threshold

### 17.4 — Constraint Distribution
- [ ] **17.4.1** Define the constraint schema `(function, value, comparison, targets)`
- [ ] **17.4.2** Constraint evaluator in the shaping pipeline
- [ ] **17.4.3** Ed25519-signed constraint-set distribution via Admiral
- [ ] **17.4.4** Client-side hot reload without reconnect
- [ ] **17.4.5** Automatic fallback to an alternate set when a set stops working
- [ ] **17.4.6** Tests: a pushed constraint set changes observable output

### 17.5 — Front Door Consistency
- [ ] **17.5.1** Authenticated admission for non-443 transports (single-packet marker)
- [ ] **17.5.2** Port 443 always behaves as a normal web server (never silent)
- [ ] **17.5.3** Per-source-IP response-consistency caching
- [ ] **17.5.4** Tests: an external prober cannot distinguish us from the genuine origin
