# Kanrin (咸臨) — Anti-Censorship Protocol

> *"The ship that crossed the silence"*

**Kanrin** is a novel censorship-circumvention protocol designed for heavily restricted networks. Named after the Kanrin Maru (咸臨丸) — the first Japanese warship to cross the Pacific after breaking the Sakoku isolation policy.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         KANRIN SYSTEM                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   SAKOKU     │    │   KANRIN     │    │    KANRIN            │  │
│  │   CLIENT     │◄──►│   FLEET     │◄──►│    HARBOR            │  │
│  │   (Rust)     │    │   (TS/CF)    │    │    (Go)              │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│         │                                          ▲                │
│         │            ┌──────────────┐              │                │
│         └───────────►│   KANRIN     │──────────────┘                │
│                      │   ADMIRAL    │                               │
│                      │   (Go)       │                               │
│                      └──────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Language | Purpose |
|-----------|----------|---------|
| `sakoku-client` | Rust | Connection core (library for Tauri app) |
| `kanrin-harbor` | Go | Exit server — receives tunneled traffic, forwards to internet |
| `kanrin-admiral` | Go | Orchestration — auto-deploys workers/harbors, distributes configs |
| `kanrin-fleet` | TypeScript | Cloudflare Workers — edge relay nodes |

## Transport Priority (fastest → most resilient)

| Priority | Transport | Latency | When |
|----------|-----------|---------|------|
| P1 | Direct QUIC (Chromium-native) | ~20ms | No UDP block |
| P2 | Direct TLS/TCP (Chromium-native) | ~40ms | UDP blocked |
| P3 | CF Worker WebSocket | ~60ms | Direct IP blocked |
| P4 | CDN HTTP/2 Multiplexed | ~100ms | WebSocket blocked |
| P5 | Domain Fronting | ~120ms | SNI inspection active |
| P6 | DNS Steganographic Tunnel | ~500ms | Total lockdown |

## Key Design Principles

1. **Indistinguishable** — Traffic looks like normal HTTPS/browser activity
2. **Self-healing** — Automatic transport switching without user intervention
3. **Ephemeral** — Workers/endpoints rotate automatically
4. **Lightweight** — Minimal client resources, no ML inference on device
5. **Resilient** — Works even under total internet lockdown (P6 DNS tunnel)

## Project Structure

```
kanrin/
├── kanrin-core/                ← Rust workspace (client library)
│   ├── crates/
│   │   ├── kanrin-protocol/   ← Wire format, crypto, session (SHARED)
│   │   ├── kanrin-transport/  ← Transport trait + P1-P6 implementations
│   │   ├── kanrin-stealth/    ← Anti-detection (rhythm, JA3, fragment)
│   │   ├── kanrin-routing/    ← Routing engine + Iran preset + GeoIP
│   │   ├── kanrin-tun/        ← TUN interface + kill switch + NAT
│   │   ├── kanrin-engine/     ← Self-healing, bootstrap, network detection
│   │   ├── kanrin-plugin/     ← WASM plugin runtime (wasmtime)
│   │   ├── kanrin-client/     ← Public API: start/stop/status + FFI
│   │   └── kanrin-cli/        ← CLI wrapper
│   └── tests/
├── kanrin-server/             ← Rust binary (exit server)
│   └── src/
│       ├── ingest/            ← Multi-transport listener
│       ├── masquerade/        ← Anti active-probe (fake website)
│       ├── proxy/             ← TCP/UDP/DNS outbound
│       └── users/             ← User management + traffic limits
├── kanrin-admiral/            ← JavaScript ESM (orchestration)
│   └── src/
│       ├── fleet/             ← CF Worker deployment automation
│       ├── harbor/            ← Server management
│       ├── triggers/          ← Auto-scaling triggers
│       ├── api/               ← REST API (config distribution, scores)
│       └── dashboard/         ← Admin web panel
├── kanrin-fleet/              ← JavaScript ESM (CF Workers)
│   └── src/
│       ├── worker.js          ← Worker relay code
│       ├── template.js        ← Parameterized code generator
│       └── deploy.js          ← CF API deployment
├── kanrin-testbed/            ← Docker (censorship simulator)
│   ├── dpi-simulator/
│   ├── network-conditions/
│   ├── active-prober/
│   └── scenarios/
├── PROTOCOL.md                ← Wire protocol specification
├── TASKS.md                   ← Phase 0-3 task breakdown
├── TASKS-2.md                 ← Phase 4-8 task breakdown
├── TASKS-3.md                 ← Phase 9-15 task breakdown
├── STRUCTS.md                 ← All data structures reference
└── README.md                  ← This file
```

## Tech Stack

| Component | Language | Key Dependencies |
|-----------|----------|-----------------|
| kanrin-core | Rust | tokio, quinn, rustls, wasmtime, wintun |
| kanrin-server | Rust | tokio, quinn, rustls, hyper |
| kanrin-admiral | JavaScript (ESM) | Node.js, Hono/Fastify, pg |
| kanrin-fleet | JavaScript (ESM) | Cloudflare Workers API |
| kanrin-testbed | Docker + Shell | iptables, tc, mitmproxy |

## License

TBD
