# Kanrin — Evasion Design (Phase 17)

> Companion to `ROADMAP.md`. This file owns the **evasion thesis**: why Kanrin
> should be hard to block, and the concrete mechanisms that deliver it.
> Priority and sequencing stay in `ROADMAP.md`. Task inventory stays in `TASKS*.md`.
>
> **Want the plain-language version first?** Read `EXPLAIN-SIMPLE.md` — the same
> reasoning as a story, no jargon. `README.md` is the documentation map.

---

## 1. Threat Intelligence (as of 2026-08)

Everything below is sourced from published measurement work or from the vendor
docs vendored in this workspace. Design decisions cite these by tag.

| Tag | Finding | Source |
|-----|---------|--------|
| **T1** | GFW detects *fully encrypted protocols* passively using ad-hoc heuristics: fraction of printable ASCII in the first payload (>50% exempts), fraction of set bits, contiguous ASCII runs, and known protocol fingerprints. "Looks like random" is itself the signal. | Wu et al., USENIX Security '23 |
| **T2** | Those heuristics change frequently. Any design that hardcodes a way to satisfy them goes stale. | Wilson et al. (Shaperd), FOCI '25 |
| **T3** | **Reality is detectable.** Replaying a handshake and counting tolerated non-advancing TLS records reveals that the authenticated path uses Go's stack while the forwarded path uses the origin's BoringSSL/OpenSSL. Behavioral divergence between the two branches is the flaw. | net4people/bbs#576, Oct 2025 |
| **T4** | **uTLS-style ClientHello copying is not sufficient and is now discouraged.** Browsers use different TLS stacks (BoringSSL, NSS) with implementation behaviors that a copied handshake format does not reproduce. | sing-box 1.14 docs, `utls` field |
| **T5** | GFW decrypts QUIC Initial packets at scale to extract SNI, and a **single** Initial packet triggers residual blocking of the 3-tuple for ~3 minutes. Decryption is expensive and degrades under load. | Zohaib et al., USENIX Security '25 |
| **T6** | **Packet timing is a detection vector independent of payload and length.** Most circumvention shaping addresses lengths only. | Wails et al., 2024 |
| **T7** | Classifiers are most accurate on the **first few seconds** of a connection; early-connection features dominate. | Pereira et al., FOCI '25 |
| **T8** | GFW-derived commercial stacks (Tiangou Secure Gateway) bundling DPI, active probing and ML classifiers are being exported to Myanmar, Pakistan, Ethiopia, Kazakhstan. Assume Iran-grade capability spreads. | Geedge/MESA leak, InterSecLab '25 |

### What the incumbents actually do

| Tool | Evasion mechanism | Known weakness |
|------|-------------------|----------------|
| VMess / Shadowsocks | Fully encrypted, "looks like nothing" | **T1** — passively detectable |
| VLESS + Reality | Borrows a real site's TLS handshake | **T3** — behavioral divergence between branches |
| Trojan | Real TLS + real cert, fallback to web server | Fallback path differs from proxy path; same class of flaw as **T3** |
| Hysteria2 | QUIC + HTTP/3 masquerade, `Salamander` XOR obfuscation | **T5** — QUIC Initial is inspected; Brutal's fixed-rate output is a strong timing signature (**T6**) |
| NaiveProxy | Uses the **real Chromium network stack**, so the fingerprint is genuinely a browser's | Strongest of the set. Cost: tied to Chromium, heavy, hard to embed |
| AnyTLS / ShadowTLS | Real TLS to a real site | Behavioral divergence on the authenticated branch |

**The pattern:** every tool that got broken was broken because it *imitated*
something rather than *being* it, and the imitation diverged under probing.

---

## 2. Design Iteration

The user asked for four rounds of proposal and self-critique. Each round's
critique is what produced the next round.

### Round 1 — "Polymorphic Wire Format"

**Proposal.** Derive the framing, header layout, padding distribution and even
field ordering from the user's pre-shared secret, so every deployment has a
unique wire signature. No two Kanrin servers look alike; signature rules cannot
generalize.

**Critique.**

- **Fatally mistargeted.** Per **T1**, the GFW stopped relying on per-protocol
  signatures for this class years ago. It applies *statistical exemption*
  heuristics. Polymorphism increases randomness, which is precisely the property
  that fails the entropy and printable-ASCII checks. This proposal makes
  detection *easier*, not harder.
- Does nothing against active probing.
- Does nothing against **T6** timing analysis.
- Operationally hostile: per-deployment wire formats make debugging and
  interoperability miserable for zero security gain.

**Verdict: rejected.** Solving a problem the censor no longer has.

---

### Round 2 — "Statistical Camouflage + Single Packet Authorization"

**Proposal.** Two mechanisms:
1. Shape the byte stream so the first payload satisfies the known GFW exemption
   heuristics (printable-ASCII ratio, set-bit fraction).
2. **SPA (Single Packet Authorization):** the server does not respond at all
   unless the first packet carries an authenticated marker. To any prober, the
   port is closed.

**Critique.**

- SPA genuinely defeats active probing, which Round 1 ignored. Keep the idea.
- **But a silent port 443 is itself anomalous.** A VPS that accepts TCP and
  never completes a TLS handshake, or that drops SYNs on 443 while responding on
  other ports, is a strong outlier. In a country that scans its own edge, "invisible"
  and "normal" are different targets, and we need **normal**.
- Shaping to satisfy *published* heuristics hardcodes today's rule set —
  directly contradicted by **T2**. The rules change; a compiled-in constant does not.
- Still nothing for **T6** (timing) or **T7** (first-seconds discriminability).
- Encoding payloads to raise printable-ASCII ratio costs real bandwidth.

**Verdict: partially salvaged.** SPA survives as a mechanism but cannot be the
front door on 443. Static heuristic-satisfaction must become dynamic.

---

### Round 3 — "Real Site Co-Residency"

**Proposal.** The server *is* a genuine website: real domain, real ACME
certificate, real content, real visitors. Kanrin clients are admitted through
the same front door. Unauthenticated requests get the real site. This is
Trojan/Reality territory, done properly.

**Critique.**

- **T3 kills the naive version.** Reality already does approximately this and was
  broken not on the handshake but on *behavioral divergence*: the authenticated
  path and the forwarded path ran different TLS implementations, and a prober
  measured the difference in tolerance for non-advancing records. Any design
  where "proxy mode" and "website mode" are different code paths inherits this.
- **Volume implausibility.** A 20 MB tunnel session hidden behind a 200 KB
  brochure site is absurd under flow-level analysis. The cover must plausibly
  account for the tunnel's byte budget.
- **Operator identity.** A real domain with a real certificate binds the operator.
  Acceptable for some threat models, disqualifying for others. Must be explicit.
- Still nothing for **T6** timing.

**Verdict: right direction, wrong execution.** "Be a real site" is necessary but
insufficient. The requirement is stronger: **be behaviorally indistinguishable in
every branch, including the branches you did not think about.**

---

### Round 4 — Synthesis: "Carrier Occupancy"

The refinement that answers every critique above.

**Proposal.** Kanrin never has an identity of its own to detect. Four mechanisms:

**4.1 — Single-stack invariance (answers T3, T4)**

There is exactly **one** TLS implementation and **one** code path terminating
connections. The server genuinely serves the website: same stack, same buffer
sizes, same timers, same error handling, for authenticated and unauthenticated
clients alike. Authentication is a fact discovered *inside* an already-normal
session, never a branch that selects a different stack.

The test is mechanical and belongs in the testbed: run the published
`replay_behavior_detector` methodology against ourselves. If any measurable
behavior differs between an authenticated and an unauthenticated session,
that is a bug of the same severity as a memory-safety bug.

**4.2 — Volume-plausible carriers (answers the Round 3 volume critique)**

The cover is chosen so its natural byte budget accommodates the tunnel. Carriers
are ranked by how much volume they can plausibly absorb:

| Carrier | Plausible volume | Natural shape |
|---------|-----------------|---------------|
| Video streaming session | GB | Large sustained chunks, periodic buffer refills |
| Large file sync | GB | Steady high-rate transfer |
| Video conference | 100s MB | Symmetric, latency-sensitive, jittery |
| Web browsing | 10s MB | Bursts separated by human-scale idle |

The routing engine already knows the traffic class. The posture selector picks a
carrier whose envelope fits the workload, and the tunnel lives inside that envelope.

**4.3 — Live-corpus shaping, both length and timing (answers T6, T7)**

Not a hardcoded "video streaming profile". The client captures a **reference
distribution from real traffic on the same network** — the same ISP, the same
time of day, the same access technology — and matches both packet-length and
inter-arrival distributions to it.

**T7** is answered structurally: the first seconds of a Kanrin connection are
statistically identical to a real page load **because they are one**. The client
genuinely fetches real resources from the real site before any tunnel data flows.
There is nothing to imitate.

**4.4 — Pushable constraint sets (answers T2)**

Following Shaperd's insight: shaping rules are **data, not code**. A constraint
is `(function, value, comparison, target packets)`. Constraint sets are signed by
Admiral and distributed like config. When the censor's heuristics change, we push
a new constraint set — no client update, no app-store review, no user action.

This is the difference between a tool that decays and a tool that adapts.

**Residual critique — honest limitations.**

- Carrier occupancy costs bandwidth. `Evasion` posture is genuinely slower.
  This is exactly why **16.4 Adaptive Posture** exists: pay only under pressure.
- Requires a real domain, real content, real certificate. Binds operator identity.
  Must be a documented, deliberate operator choice.
- Live-corpus shaping needs a reference capture, which is itself observable.
  Collect passively from traffic the user is already generating; never synthesize
  probe traffic to build the corpus.
- **Nothing here survives a total shutdown.** That is what P6 DNS tunnel is for,
  at 500ms latency and near-zero throughput.
- Single-stack invariance constrains implementation freedom permanently. Every
  future feature must be checked against it.

---

## 3. Phase 17 — Tasks

**The Phase 17 task checklist lives in `TASKS-4.md`** (groups 17.1 through 17.5).
It is not restated here. This document owns only the reasoning above; the task
inventory has a single home.

Summary of the five groups, each expanded in `TASKS-4.md`:

- **17.1 Single-Stack Invariance** — one TLS implementation, one code path for
  every client; the mechanism behind §2 Round 4.1.
- **17.2 Volume-Plausible Carriers** — §2 Round 4.2.
- **17.3 Live-Corpus Shaping** — §2 Round 4.3, answering T6 and T7.
- **17.4 Constraint Distribution** — §2 Round 4.4, answering T2.
- **17.5 Front Door Consistency** — the SPA + always-normal-443 pair.

---

## 4. Placement in `ROADMAP.md`

Phase 17 does not displace the existing order. It refines it:

- **17.1** is the correct, complete form of the P0 masquerade item. Do it there —
  a masquerade with divergent behavior is worse than none, because it advertises
  that something is hiding.
- **17.5** joins P0.
- **17.3** and **17.4** are the substance of P4 Adaptive Posture. `Evasion`
  posture without live-corpus shaping is theatre.
- **17.2** follows P4, once posture switching is real.

The ordering principle is unchanged: **do not claim evasion without a testbed
scenario that proves it (I3).**
