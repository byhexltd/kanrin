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
- [ ] **16.1.1** Add a monotonic sequence number to every data chunk, scoped to the session and independent of transport
- [ ] **16.1.2** Send buffer retaining unacknowledged chunks
- [ ] **16.1.3** Cumulative + selective acknowledgement chunk type
- [ ] **16.1.4** Receive-side reorder buffer and duplicate suppression
- [ ] **16.1.5** Replay of unacknowledged chunks onto a new transport
- [ ] **16.1.6** Resumption handshake: prove session ownership without a full key exchange; report last contiguous sequence received
- [ ] **16.1.7** Bound the send buffer and apply back-pressure to the TUN reader
- [ ] **16.1.8** Tests: drop the transport mid-transfer; byte stream stays intact, no inner TCP resets
- [ ] **16.1.9** Tests: buffer bound respected under a stalled transport

### 16.2 — Hot Standby & Seamless Switch
- [ ] **16.2.1** Keep the next-best transport fully handshaked and idle
- [ ] **16.2.2** Switch as an atomic swap of the active transport handle, followed by 16.1.5 replay
- [ ] **16.2.3** Liveness detection fast enough to switch before the inner TCP stack notices (detect <1s, switch <200ms)
- [ ] **16.2.4** Make-before-break ordering: never tear down the old transport until the new one has carried an acknowledged chunk
- [ ] **16.2.5** Switch cooldown and flap damping
- [ ] **16.2.6** Emit a user-facing event describing the switch, never an error
- [ ] **16.2.7** Tests: transport interrupted mid-download, download still completes
- [ ] **16.2.8** Tests: repeated forced switches do not corrupt the stream

### 16.3 — Multipath
- [ ] **16.3.1** Allow two or more healthy transports active at once
- [ ] **16.3.2** Scheduler striping chunks across paths by measured capacity
- [ ] **16.3.3** Hedging: duplicate latency-critical chunks on a second path, deduplicated by 16.1.4
- [ ] **16.3.4** Per-path health accounting feeding the scoreboard
- [ ] **16.3.5** Tests: one path fails under load, throughput dips but no stall

### 16.4 — Adaptive Posture
- [ ] **16.4.1** Define postures: `Performance`, `Balanced`, `Evasion`
- [ ] **16.4.2** `Performance` — minimal padding, no cover traffic, largest window, lowest latency
- [ ] **16.4.3** `Evasion` — full shaping pipeline: rhythm shaping, padding, fragmentation, cover traffic
- [ ] **16.4.4** Promotion/demotion driven by detector, prober and scoreboard, with hysteresis
- [ ] **16.4.5** Immediate demotion to `Evasion` on adverse signals (repeated handshake failures, RST patterns, sudden path loss)
- [ ] **16.4.6** Surface current posture in status output
- [ ] **16.4.7** Tests: posture escalates under simulated pressure, relaxes when clean

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
