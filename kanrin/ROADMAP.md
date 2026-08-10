# Kanrin — Prioritized Roadmap

> **This file is the single source of truth for _what to build next and why_.**
>
> It does **not** restate tasks. `TASKS.md`, `TASKS-2.md`, `TASKS-3.md` own the
> task inventory (~469 items). This file owns **priority, rationale, and the
> capabilities that were missing from those files entirely** (Phase 16).
>
> `DESIGN-EVASION.md` owns the **evasion thesis and Phase 17** — threat
> intelligence, why each incumbent protocol was broken, and the mechanisms that
> answer it. Read it before touching masquerade, stealth or posture work.
>
> When priority changes, edit this file. When a task is added, edit `TASKS*.md`.

---

## North Star

Kanrin is not competing on raw throughput with Hysteria2 or VLESS. Those are
single static transports: the day they are fingerprinted, they are dead until a
human ships a new config.

Kanrin's thesis is **survivability with no user-visible interruption**:

1. **The connection never drops.** Switching transport, server, or network path
   must be invisible to the applications running on top of it.
2. **Speed first when the network is clean.** Defensive posture costs latency and
   bandwidth; only pay for it when the network is actually hostile.
3. **Every layer contributes.** Detector, prober, scoreboard, switcher, stealth
   pipeline and routing engine all feed one decision loop.
4. **Blocking it must cost more than allowing it.** No single fingerprint, IP,
   port, or protocol whose removal kills the system.

Target adversaries: Iran's DPI, China's GFW (active probing), Russia's TSPU.

---

## Three Invariants

Every design decision is checked against these. If a change breaks one, it is
wrong regardless of how much faster it is.

| # | Invariant | Consequence if violated |
|---|-----------|-------------------------|
| **I1** | A transport failure must never surface as a broken TCP connection to the app | User sees dropped downloads, logged-out sessions — the thing every other tool does |
| **I2** | An active probe must never receive a response that a real web server would not send | Server is enumerable; IP burned permanently |
| **I3** | No claim of "undetectable" or "works under X" is made without a testbed scenario proving it | We ship confidence, not evidence |

---

## Current Build State

Verified working end-to-end on 2026-08-10 (client on Windows, server on Linux):

| Area | State |
|------|-------|
| Handshake, session keys, auth | Works |
| P2 TLS/TCP transport | **Only transport that works end-to-end** |
| Server TUN + kernel NAT forwarding | Works |
| Client TUN, routing, kill switch | Works (Windows verified) |
| Full-tunnel browsing incl. filtered sites | Verified, ~20 MB transferred |
| P1 QUIC | Code exists, loses auto-selection, has the `read_exact` cancel-safety bug |
| P3 WebSocket | Code exists, same cancel-safety bug, no Fleet behind it |
| P4/P5/P6 | Not built |
| Masquerade (anti active-probe) | **Not built — server serves a self-signed cert, trivially fingerprinted** |
| Self-healing switch | Scaffolding only, never fires |
| Stealth pipeline | Crate exists, **not wired into the data path** |
| Admiral / Fleet / Testbed | Empty directories |

### Known structural issue

`kanrin/kanrin-server/` is an **empty directory**, but the real server lives at
`kanrin/kanrin-core/crates/kanrin-server/`. `README.md` documents the former.
Resolve before it causes duplicate work: either move the crate or fix the docs.
Do not create a second server implementation.

---

## Phase 16 — Continuity & Adaptation (NEW)

These capabilities are the core of the North Star and **do not appear anywhere
in `TASKS.md`, `TASKS-2.md`, or `TASKS-3.md`.** Existing tasks 1.4.4, 1.4.5 and
7.3.4, 7.3.5 gesture at migration but assume a reconnect, which breaks **I1**.

### 16.1 — Session Continuity Layer

A reliable, ordered, transport-agnostic pipe that outlives any individual
connection. This is the foundation everything else in Phase 16 stands on.

- [ ] **16.1.1** Add monotonic sequence number to every data chunk, scoped to the
      session and independent of transport
- [ ] **16.1.2** Implement send buffer retaining unacknowledged chunks
- [ ] **16.1.3** Implement cumulative + selective acknowledgement chunk type
- [ ] **16.1.4** Implement receive-side reorder buffer and duplicate suppression
- [ ] **16.1.5** Implement replay of unacknowledged chunks onto a new transport
- [ ] **16.1.6** Implement resumption handshake: prove session ownership without
      a full key exchange, and report the last contiguous sequence received
- [ ] **16.1.7** Bound the send buffer and apply back-pressure to the TUN reader
- [ ] **16.1.8** Tests: kill the transport mid-transfer, verify byte stream is
      intact and no inner TCP connection resets
- [ ] **16.1.9** Tests: buffer bound is respected under a stalled transport

### 16.2 — Hot Standby & Seamless Switch

- [ ] **16.2.1** Keep the next-best transport fully handshaked and idle
- [ ] **16.2.2** Implement switch as an atomic swap of the active transport
      handle, followed by 16.1.5 replay
- [ ] **16.2.3** Implement liveness detection fast enough to switch before the
      inner TCP stack notices (target: detect under 1s, switch under 200ms)
- [ ] **16.2.4** Implement make-before-break ordering: never tear down the old
      transport until the new one has carried an acknowledged chunk
- [ ] **16.2.5** Implement switch cooldown and flap damping
- [ ] **16.2.6** Emit a user-facing event describing the switch, never an error
- [ ] **16.2.7** Tests: transport blocked mid-download, download completes
- [ ] **16.2.8** Tests: repeated forced switches do not corrupt the stream

### 16.3 — Multipath

Beyond anything Hysteria2 or VLESS offer today.

- [ ] **16.3.1** Allow two or more healthy transports to be active at once
- [ ] **16.3.2** Implement scheduler striping chunks across paths by measured
      capacity
- [ ] **16.3.3** Implement hedging: duplicate latency-critical chunks on a second
      path, deduplicated by 16.1.4
- [ ] **16.3.4** Implement per-path health accounting feeding the scoreboard
- [ ] **16.3.5** Tests: one path dies under load, throughput dips but no stall

### 16.4 — Adaptive Posture

The mechanism that satisfies North Star #2: pay for stealth only when needed.

- [ ] **16.4.1** Define postures: `Performance`, `Balanced`, `Evasion`
- [ ] **16.4.2** `Performance` — minimal padding, no cover traffic, largest
      window, lowest latency. Used when detection reports a clean network
- [ ] **16.4.3** `Evasion` — full stealth pipeline: rhythm shaping, padding,
      fragmentation, cover traffic
- [ ] **16.4.4** Implement promotion and demotion driven by detector, prober and
      scoreboard, with hysteresis to prevent oscillation
- [ ] **16.4.5** Implement immediate demotion to `Evasion` on probe-like events
      (repeated handshake failures, RST patterns, sudden path loss)
- [ ] **16.4.6** Surface current posture in status output
- [ ] **16.4.7** Tests: posture escalates under simulated DPI, relaxes when clean

---

## Execution Order

Rationale-first. Each priority block is gated on the previous one.

### P0 — Foundation Integrity

Small, high-leverage work that makes the current system honest. Nothing new is
worth building on a server that a single probe can identify.

- Masquerade + real certificate — `TASKS-3.md` 9.3.1-9.3.8, 9.1.4, plus
  `DESIGN-EVASION.md` **17.1** (single-stack invariance) and **17.5** (front
  door). **Satisfies I2.** Do the 17.1 form, not the naive one: a masquerade
  whose authenticated and unauthenticated paths behave differently is worse than
  no masquerade, because it advertises that something is hiding. This is exactly
  how Reality was broken in October 2025
- Cancel-safety parity for QUIC and WebSocket transports (the `read_exact` bug
  already fixed in TLS/TCP; the others will reproduce the exact same silent
  stall the moment auto-selection picks them)
- Resolve the empty `kanrin-server/` directory discrepancy
- Cheap performance wins, low risk: remove the per-packet `spawn_blocking` on the
  TUN read path, set `TCP_NODELAY`, coalesce the length prefix and payload into a
  single write

### P1 — Continuity Core

**This is the differentiator.** Without it, every added transport is just another
way to drop the user's connection.

- Phase **16.1** Session Continuity Layer
- Phase **16.2** Hot Standby & Seamless Switch
- Wire the existing `Switcher` (7.3.x) to drive 16.2 instead of reconnecting

### P2 — Proving Ground

**Satisfies I3.** No further anti-censorship claim is credible until scenarios
can be run on demand.

- Phase **12** Testbed: DPI simulator, network conditions, active prober
- Scenarios `iran-normal`, `iran-shutdown`, `china-gfw` (12.4.1-12.4.6)
- Wire 16.2.7 and 16.4.7 tests into these scenarios

### P3 — Transport Ladder

Breadth is what makes blocking expensive. Ordered by value per unit of effort.

- **P1 QUIC** healthy and preferred — 3.2.x, including Brutal congestion control
  (3.2.5) and adaptive BBR/Brutal (3.2.6). Removes TCP-over-TCP meltdown
- **P3 CF Worker WebSocket** — 3.4.x plus Phase 11 Fleet. The answer to a burned
  server IP: Cloudflare's edge cannot be blocked wholesale
- **P4/P5/P6** — HTTP/2 CDN, domain fronting, DNS tunnel (3.5-3.7)

### P4 — Adaptive Posture & Stealth

- Phase **16.4** Adaptive Posture
- Phase **5** Stealth actually wired into the data path: JA3 mimicry (5.3),
  fragmentation (5.4), rhythm engine (5.2)

### P5 — Multipath

- Phase **16.3**

### P6 — Automation & Scale

- Phase **10** Admiral: rotation, config distribution, collective scoreboard
- Phase **11** Fleet automation

### P7 — Hardening & Launch

- Phases **13**, **14**, **15**
- Cryptographic review before any public release. The handshake is custom;
  WireGuard uses Noise and everything else uses TLS 1.3 for a reason

---

## Deferred Deliberately

| Item | Why |
|------|-----|
| Throughput tuning beyond the P0 cheap wins | A fast tunnel that gets fingerprinted is worth nothing. Revisit at P7 with 13.2 benchmarks |
| Plugin system (Phase 2) | Extensibility before a stable core multiplies churn |
| Mobile builds (14.1.3, 14.1.4) | Needs the FFI surface to settle first |
