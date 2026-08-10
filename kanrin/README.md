# Kanrin

**The ship that crossed the silence.**

Kanrin is a resilient, transport-agnostic tunnel written in Rust. Its goal is not
raw speed — it is **survivability with no user-visible interruption**: the
connection stays alive while the transport, server, or network path underneath it
changes invisibly to the applications on top.

> New here? Start with **[`EXPLAIN-SIMPLE.md`](./EXPLAIN-SIMPLE.md)** — the whole
> design told as a plain-language story, no jargon.

---

## Documentation map

Each document has exactly one job. Nothing is duplicated across them.

| Document | What it owns | Read it when |
|----------|--------------|--------------|
| [`EXPLAIN-SIMPLE.md`](./EXPLAIN-SIMPLE.md) | The design as a plain-language story | You want the intuition first |
| [`ROADMAP.md`](./ROADMAP.md) | Priority, execution order, the North Star, and invariants I1-I3 | You want to know *what to build next and why* |
| [`DESIGN-EVASION.md`](./DESIGN-EVASION.md) | Threat model, why prior tools were caught, and the mechanism design (Phase 17 reasoning) | You are touching masquerade, stealth, or posture |
| [`STRUCTS.md`](./STRUCTS.md) | Reference of the major structs, enums, and traits | You need the exact data shapes |
| [`TASKS.md`](./TASKS.md) | Task inventory, phases 0-3 (foundation, protocol, transports) | You want the concrete work items |
| [`TASKS-2.md`](./TASKS-2.md) | Task inventory, phases 4-8 (TUN, stealth, routing, self-healing, client) | ″ |
| [`TASKS-3.md`](./TASKS-3.md) | Task inventory, phases 9-15 (server, admiral, fleet, testbed, launch) | ″ |
| [`TASKS-4.md`](./TASKS-4.md) | Task inventory, phases 16-17 (continuity, adaptation, single-path consistency, shaping) | ″ |

**The rule:** task checklists live *only* in the `TASKS*.md` files. `ROADMAP.md`
and `DESIGN-EVASION.md` explain the *reasoning* and point to those tasks; they
never restate them.

---

## The thesis in three lines

1. **The connection never drops.** Switching transport, server, or path is
   invisible to the apps running on top of it (invariant **I1**).
2. **Speed first when the network is clean.** Defensive posture costs latency and
   bandwidth; only pay for it under actual pressure.
3. **Be normal, not invisible.** Every prior tool that got caught was caught
   because it *imitated* something and the imitation diverged under inspection.
   Kanrin aims to *be* the thing, with a single behavior for every client
   (invariant **I2**).

The full reasoning behind these is in [`DESIGN-EVASION.md`](./DESIGN-EVASION.md);
the simple version is in [`EXPLAIN-SIMPLE.md`](./EXPLAIN-SIMPLE.md).

---

## Repository layout

```
kanrin/
├── README.md            ← you are here
├── EXPLAIN-SIMPLE.md    ← plain-language design story
├── ROADMAP.md           ← priorities and execution order
├── DESIGN-EVASION.md    ← threat model and mechanism design
├── STRUCTS.md           ← data structure reference
├── TASKS.md .. TASKS-4.md ← the task inventory
└── kanrin-core/         ← the Rust workspace (all crates)
    └── crates/
        ├── kanrin-protocol/   handshake, wire format, crypto, session
        ├── kanrin-transport/  QUIC, TLS/TCP, WebSocket
        ├── kanrin-tun/        TUN device, routing, NAT, kill switch
        ├── kanrin-engine/     detector, prober, scoreboard, switcher
        ├── kanrin-stealth/    shaping pipeline (rhythm, fragmentation)
        ├── kanrin-routing/    GeoIP, per-region presets, process rules
        ├── kanrin-client/     client library, pipeline, FFI, CLI
        └── kanrin-server/     server binary, listener, session, forwarder
```

---

## Status

End-to-end tunneling works today over the TLS/TCP transport (client on Windows,
server on Linux). The detailed build state, known issues, and what comes next are
tracked in [`ROADMAP.md`](./ROADMAP.md) § Current Build State.

---

## License

See the repository root.
