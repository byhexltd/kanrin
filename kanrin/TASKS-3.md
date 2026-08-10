# Kanrin — Task Breakdown (Phases 9-15)

---

## Phase 9: Server (`kanrin-server`)

### 9.1 — Server Core
- [ ] **9.1.1** Implement `KanrinServer::new(config)`
- [ ] **9.1.2** Implement `KanrinServer::run()` → start all listeners
- [ ] **9.1.3** Implement config file parsing (YAML)
- [ ] **9.1.4** Implement auto TLS certificate (ACME / Let's Encrypt)
- [ ] **9.1.5** Implement graceful shutdown (drain connections)
- [ ] **9.1.6** Implement config hot-reload (SIGHUP or file watch)
- [ ] **9.1.7** Implement structured JSON logging

### 9.2 — Ingest (Receiving Traffic)
- [ ] **9.2.1** Implement QUIC listener (Kanrin over QUIC)
- [ ] **9.2.2** Implement TLS/TCP listener (Kanrin over TLS)
- [ ] **9.2.3** Implement WebSocket listener (from CF Workers)
- [ ] **9.2.4** Implement HTTP/2 listener (from CDN)
- [ ] **9.2.5** Implement DNS tunnel listener (from DNS queries)
- [ ] **9.2.6** Implement unified handshake processing
- [ ] **9.2.7** Implement connection routing to user session
- [ ] **9.2.8** Implement concurrent handling (io_uring / epoll)

### 9.3 — Masquerade (Anti Active-Probe)
- [ ] **9.3.1** Implement active probe detection (non-Kanrin request → fake site)
- [ ] **9.3.2** Implement static file serving mode
- [ ] **9.3.3** Implement reverse proxy mode (proxy to real site)
- [ ] **9.3.4** Implement response timing normalization
- [ ] **9.3.5** Implement browser fingerprint checking
- [ ] **9.3.6** Implement proper HTTP headers (Server, Date, etc.)
- [ ] **9.3.7** Tests: probe sees normal website
- [ ] **9.3.8** Tests: real client connects successfully

### 9.4 — Outbound Proxy
- [ ] **9.4.1** Implement TCP proxy (connect+relay bidirectional)
- [ ] **9.4.2** Implement UDP proxy (datagram relay)
- [ ] **9.4.3** Implement DNS proxy (resolve for client)
- [ ] **9.4.4** Implement target ACL (blocked destinations)
- [ ] **9.4.5** Implement connection pooling (reuse TCP)
- [ ] **9.4.6** Implement timeout handling

### 9.5 — User Management
- [ ] **9.5.1** Implement user auth (constant-time password)
- [ ] **9.5.2** Implement traffic counting per user
- [ ] **9.5.3** Implement traffic limit enforcement
- [ ] **9.5.4** Implement speed limit (per-user throttle)
- [ ] **9.5.5** Implement connection limit (max concurrent)
- [ ] **9.5.6** Implement expiry checking
- [ ] **9.5.7** Implement online user tracking
- [ ] **9.5.8** Implement traffic reset (monthly/daily)

### 9.6 — Server API & Metrics
- [ ] **9.6.1** Implement `GET /api/stats` (admin)
- [ ] **9.6.2** Implement `GET /api/users` (list, traffic, status)
- [ ] **9.6.3** Implement `POST /api/users/{name}/reset`
- [ ] **9.6.4** Implement `POST /api/users/{name}/kick`
- [ ] **9.6.5** Implement Prometheus `/metrics` export
- [ ] **9.6.6** Implement connection count metrics
- [ ] **9.6.7** Implement bandwidth metrics
- [ ] **9.6.8** Implement uptime/health metrics

### 9.7 — Server CLI
- [ ] **9.7.1** Implement `kanrin-server run -c config.yml`
- [ ] **9.7.2** Implement `kanrin-server init` (generate config)
- [ ] **9.7.3** Implement `kanrin-server add-user <name> <pass> [--limit]`
- [ ] **9.7.4** Implement `kanrin-server remove-user <name>`
- [ ] **9.7.5** Implement `kanrin-server list-users`
- [ ] **9.7.6** Implement `kanrin-server check` (validate config)
- [ ] **9.7.7** Implement `kanrin-server version`
- [ ] **9.7.8** Implement `kanrin-server install-service` (systemd)

---

## Phase 10: Admiral (`kanrin-admiral`)

### 10.1 — Project Setup
- [ ] **10.1.1** Initialize Node.js with `"type": "module"`
- [ ] **10.1.2** Setup ESLint + Prettier
- [ ] **10.1.3** Setup database (PostgreSQL with `pg`)
- [ ] **10.1.4** Setup web framework (`Hono` or `Fastify`)
- [ ] **10.1.5** Setup `.env` management

### 10.2 — Database Schema & Migrations
- [ ] **10.2.1** Create workers table (id, name, url, status, harbor_id, health_score, etc.)
- [ ] **10.2.2** Create harbors table (id, host, ip, port, status, region, etc.)
- [ ] **10.2.3** Create users table (id, name, password_hash, limits, etc.)
- [ ] **10.2.4** Create score_reports table (endpoint_id, score, latency, region)
- [ ] **10.2.5** Create configs table (version, data, active)
- [ ] **10.2.6** Create deployments table (type, action, status, timestamps)
- [ ] **10.2.7** Implement migration runner
- [ ] **10.2.8** Implement seed data for dev

### 10.3 — Fleet Manager (Worker Deployment)
- [ ] **10.3.1** Implement Cloudflare API client (REST)
- [ ] **10.3.2** Implement worker code template (parameterized JS)
- [ ] **10.3.3** Implement `deployWorker(harborId)`:
  - Generate unique name
  - Generate auth key
  - Render code from template
  - Upload via CF API
  - Store in database
- [ ] **10.3.4** Implement `destroyWorker(workerId)`:
  - Delete via CF API
  - Remove from DB
  - Log history
- [ ] **10.3.5** Implement `rotateWorker(workerId)`:
  - Deploy new → mark old rotating → drain → destroy old
- [ ] **10.3.6** Implement batch deploy (N workers at once)
- [ ] **10.3.7** Implement name generator (random valid subdomains)
- [ ] **10.3.8** Implement key generator (Ed25519 per worker)

### 10.4 — Harbor Manager
- [ ] **10.4.1** Implement harbor registration (admin adds server)
- [ ] **10.4.2** Implement harbor health monitoring (periodic HTTP)
- [ ] **10.4.3** Implement harbor status tracking
- [ ] **10.4.4** Implement load balancing (assign workers to least-loaded)
- [ ] **10.4.5** Implement IP rotation notification
- [ ] **10.4.6** Implement auto-provisioning (optional: cloud API)

### 10.5 — Trigger Engine (Auto-Scaling)
- [ ] **10.5.1** Implement health check trigger (down → replace)
- [ ] **10.5.2** Implement rotation schedule (cron: "rotate 20% every 6h")
- [ ] **10.5.3** Implement client report trigger (score < 0.3 → blocked)
- [ ] **10.5.4** Implement capacity trigger (connections > threshold → more)
- [ ] **10.5.5** Implement cooldown logic
- [ ] **10.5.6** Implement trigger history logging
- [ ] **10.5.7** Implement manual trigger API

### 10.6 — Config Distribution API
- [ ] **10.6.1** Implement `GET /api/v1/config` → active endpoints for client
- [ ] **10.6.2** Implement config versioning (client sends version, diff if newer)
- [ ] **10.6.3** Implement config signing (Ed25519)
- [ ] **10.6.4** Implement per-user config
- [ ] **10.6.5** Implement rate limiting
- [ ] **10.6.6** Implement client auth for config fetch

### 10.7 — Collective ScoreBoard API
- [ ] **10.7.1** Implement `POST /api/v1/report` → receive anonymous score
- [ ] **10.7.2** Implement score aggregation (average)
- [ ] **10.7.3** Implement outlier detection (ignore fake)
- [ ] **10.7.4** Implement `GET /api/v1/scores` → aggregated to clients
- [ ] **10.7.5** Implement geographic grouping

### 10.8 — Admin Dashboard
- [ ] **10.8.1** Implement admin auth (JWT)
- [ ] **10.8.2** Dashboard home (overview)
- [ ] **10.8.3** Workers page (list, deploy, destroy)
- [ ] **10.8.4** Harbors page (list, status, load)
- [ ] **10.8.5** Users page (list, add, remove, traffic)
- [ ] **10.8.6** Deployments page (history, logs)
- [ ] **10.8.7** Real-time logs (WebSocket)
- [ ] **10.8.8** Settings page (schedules, thresholds)
- [ ] **10.8.9** Frontend: simple HTML+JS or React

### 10.9 — Admiral CLI
- [ ] **10.9.1** Implement `kanrin-admiral serve`
- [ ] **10.9.2** Implement `kanrin-admiral deploy-workers <count>`
- [ ] **10.9.3** Implement `kanrin-admiral destroy-worker <id>`
- [ ] **10.9.4** Implement `kanrin-admiral list-workers`
- [ ] **10.9.5** Implement `kanrin-admiral list-harbors`
- [ ] **10.9.6** Implement `kanrin-admiral add-user`
- [ ] **10.9.7** Implement `kanrin-admiral rotate-all`
- [ ] **10.9.8** Implement `kanrin-admiral init` (setup DB, keys)

---

## Phase 11: Fleet — CF Workers (`kanrin-fleet`)

### 11.1 — Worker Code
- [ ] **11.1.1** Implement WebSocket upgrade handling
- [ ] **11.1.2** Implement auth (validate client token)
- [ ] **11.1.3** Implement TCP connect to Harbor (`connect()` API)
- [ ] **11.1.4** Implement bidirectional relay (WS↔Harbor TCP)
- [ ] **11.1.5** Implement error handling (Harbor unreachable)
- [ ] **11.1.6** Implement health check endpoint (`GET /health`)
- [ ] **11.1.7** Implement request logging (minimal, privacy)
- [ ] **11.1.8** Implement rate limiting (per-IP)
- [ ] **11.1.9** Implement graceful connection close

### 11.2 — Worker Template System
- [ ] **11.2.1** Parameterized template (HARBOR_HOST, PORT, AUTH_KEY, WORKER_ID)
- [ ] **11.2.2** Code variation per deploy (slight obfuscation)
- [ ] **11.2.3** `wrangler.toml` template generation
- [ ] **11.2.4** Tests: generated code is valid JS

### 11.3 — Deployment Scripts
- [ ] **11.3.1** Implement `deploy(name, config)` → upload to CF
- [ ] **11.3.2** Implement `destroy(name)` → delete from CF
- [ ] **11.3.3** Implement `list()` → all deployed workers
- [ ] **11.3.4** Implement `healthCheck(url)` → verify running
- [ ] **11.3.5** Implement `batchDeploy(count, harborId)`
- [ ] **11.3.6** Implement `rotateAll(harborId)` → replace all

---

## Phase 12: Testbed (`kanrin-testbed`)

### 12.1 — DPI Simulator
- [ ] **12.1.1** Implement packet inspection (detect Kanrin protocol patterns)
- [ ] **12.1.2** Implement TLS fingerprint detection (block non-browser)
- [ ] **12.1.3** Implement SNI inspection (block specific domains)
- [ ] **12.1.4** Implement protocol detection rules (configurable)
- [ ] **12.1.5** Docker container with `mitmproxy` or custom Go proxy

### 12.2 — Network Conditions Simulator
- [ ] **12.2.1** Implement IP blocking (iptables drop specific IPs)
- [ ] **12.2.2** Implement UDP throttling (tc netem, limit bandwidth)
- [ ] **12.2.3** Implement UDP dropping (iptables drop all UDP)
- [ ] **12.2.4** Implement DNS poisoning (return wrong IPs)
- [ ] **12.2.5** Implement total shutdown (block all except DNS)
- [ ] **12.2.6** Implement latency injection (tc netem delay)

### 12.3 — Active Prober
- [ ] **12.3.1** Implement HTTP probe (connect like browser)
- [ ] **12.3.2** Implement TLS probe (send non-Kanrin data)
- [ ] **12.3.3** Implement replay probe (replay captured handshake)
- [ ] **12.3.4** Verify server returns masquerade, not protocol error

### 12.4 — Scenarios
- [ ] **12.4.1** Create `iran-normal.yml` (DPI + some IPs blocked + UDP slow)
- [ ] **12.4.2** Create `iran-protest.yml` (heavy blocking + throttling)
- [ ] **12.4.3** Create `iran-shutdown.yml` (only DNS + internal sites)
- [ ] **12.4.4** Create `china-gfw.yml` (active probing + deep inspection)
- [ ] **12.4.5** Implement `docker-compose.yml` (spin up full scenario)
- [ ] **12.4.6** Implement automated test runner (pass/fail per scenario)

---

## Phase 13: Integration Testing

### 13.1 — End-to-End Tests
- [ ] **13.1.1** Test: client connects to server via QUIC → browse web
- [ ] **13.1.2** Test: client connects via TLS → browse web
- [ ] **13.1.3** Test: client connects via CF Worker → browse web
- [ ] **13.1.4** Test: client connects via HTTP/2 CDN → browse web
- [ ] **13.1.5** Test: client connects via DNS tunnel → browse web
- [ ] **13.1.6** Test: self-healing switches transport when blocked
- [ ] **13.1.7** Test: kill switch blocks all traffic when tunnel drops
- [ ] **13.1.8** Test: no DNS leak (all DNS through tunnel)
- [ ] **13.1.9** Test: no WebRTC leak
- [ ] **13.1.10** Test: session migration on IP change
- [ ] **13.1.11** Test: traffic limits enforced
- [ ] **13.1.12** Test: concurrent 1000 connections
- [ ] **13.1.13** Test: Iranian traffic bypasses tunnel

### 13.2 — Performance Tests
- [ ] **13.2.1** Benchmark: throughput (Gbps) per transport
- [ ] **13.2.2** Benchmark: latency overhead per transport
- [ ] **13.2.3** Benchmark: CPU usage under load
- [ ] **13.2.4** Benchmark: memory usage (steady state + peak)
- [ ] **13.2.5** Benchmark: connection establishment time
- [ ] **13.2.6** Benchmark: packets-per-second (TUN processing)
- [ ] **13.2.7** Compare vs Hysteria2 (same hardware/network)
- [ ] **13.2.8** Compare vs sing-box (same hardware/network)

### 13.3 — Security Tests
- [ ] **13.3.1** Test: active probe returns masquerade
- [ ] **13.3.2** Test: replay attack rejected
- [ ] **13.3.3** Test: brute force auth rate-limited
- [ ] **13.3.4** Test: no timing side-channel in auth
- [ ] **13.3.5** Test: key material zeroed after use
- [ ] **13.3.6** Test: plugin sandbox prevents escape
- [ ] **13.3.7** Audit: cryptographic implementation review
- [ ] **13.3.8** Fuzz: all parsers (wire, packet, config)

---

## Phase 14: Build & Distribution

### 14.1 — Cross-Compilation
- [ ] **14.1.1** Setup CI (GitHub Actions)
- [ ] **14.1.2** Build matrix: linux-amd64, linux-arm64, windows-amd64, macos-amd64, macos-arm64
- [ ] **14.1.3** Android: build shared library (.so) via NDK
- [ ] **14.1.4** iOS: build static library (.a) via Xcode toolchain
- [ ] **14.1.5** Implement cross-compile script (using `cross-rs`)
- [ ] **14.1.6** Implement release automation (tag → build → publish)

### 14.2 — Packaging
- [ ] **14.2.1** Create Dockerfile for kanrin-server
- [ ] **14.2.2** Create Dockerfile for kanrin-admiral
- [ ] **14.2.3** Create install script (`curl | sh`)
- [ ] **14.2.4** Create systemd service file
- [ ] **14.2.5** Create Windows installer (optional)
- [ ] **14.2.6** Create Homebrew formula (macOS)
- [ ] **14.2.7** Publish kanrin-core to crates.io (optional)
- [ ] **14.2.8** Publish kanrin-admiral to npm (optional)

### 14.3 — Documentation
- [ ] **14.3.1** Write PROTOCOL.md (complete wire spec)
- [ ] **14.3.2** Write server setup guide (3-step)
- [ ] **14.3.3** Write client usage guide
- [ ] **14.3.4** Write plugin development guide
- [ ] **14.3.5** Write Admiral setup guide
- [ ] **14.3.6** Write architecture overview (for contributors)
- [ ] **14.3.7** API reference (auto-generated from code)
- [ ] **14.3.8** FAQ / Troubleshooting

---

## Phase 15: Polish & Launch

### 15.1 — UX Polish
- [ ] **15.1.1** Human-readable error messages (Persian + English)
- [ ] **15.1.2** Progress indicators during connection
- [ ] **15.1.3** Clear status messages ("Connected via QUIC, 12ms latency")
- [ ] **15.1.4** Auto-reconnect with exponential backoff
- [ ] **15.1.5** Battery optimization (reduce polling when on mobile)
- [ ] **15.1.6** Bandwidth-adaptive stealth (reduce padding on slow networks)

### 15.2 — Operator UX
- [ ] **15.2.1** One-command install script
- [ ] **15.2.2** Interactive config wizard (`kanrin-server init`)
- [ ] **15.2.3** Automatic SSL certificate (no manual certbot)
- [ ] **15.2.4** Default config works out of box (zero-knowledge needed)
- [ ] **15.2.5** Clear server logs ("User ali connected, 45GB remaining")
- [ ] **15.2.6** Telegram bot integration (optional, for user management)

### 15.3 — Security Hardening
- [ ] **15.3.1** Memory safety audit (unsafe blocks review)
- [ ] **15.3.2** Dependency audit (`cargo audit`)
- [ ] **15.3.3** Reproducible builds (verify binary matches source)
- [ ] **15.3.4** Binary signing (GPG / code signing)
- [ ] **15.3.5** Minimal binary (strip debug symbols, LTO)

---

## Summary: Total Task Count

| Phase | Name | Tasks |
|-------|------|-------|
| 0 | Foundation | 20 |
| 1 | Protocol | 47 |
| 2 | Plugin System | 17 |
| 3 | Transport Layer | 52 |
| 4 | TUN & Packet | 46 |
| 5 | Stealth | 23 |
| 6 | Routing | 21 |
| 7 | Self-Healing | 35 |
| 8 | Client Library | 37 |
| 9 | Server | 38 |
| 10 | Admiral | 47 |
| 11 | Fleet (CF Workers) | 16 |
| 12 | Testbed | 17 |
| 13 | Integration Testing | 21 |
| 14 | Build & Distribution | 18 |
| 15 | Polish & Launch | 14 |
| **Total** | | **~469 tasks** |

---

## Execution Order (Critical Path)

```
Phase 0 (Foundation)
    ↓
Phase 1 (Protocol) ← MUST be first, everything depends on this
    ↓
Phase 3.1-3.3 (Transport: QUIC + TLS + WS) ← minimum viable transports
    ↓
Phase 9.1-9.4 (Server: core + ingest + masquerade + proxy) ← need server to test client
    ↓
Phase 4 (TUN & Packet) ← this makes us leak-free
    ↓
Phase 8 (Client Library) ← wire everything together
    ↓
[MVP: Client ↔ Server works, one transport, no leaks]
    ↓
Phase 5 (Stealth) ← add anti-detection
Phase 6 (Routing) ← add Iran bypass
Phase 7 (Self-Healing) ← add auto-switch
    ↓
Phase 2 (Plugin) ← add extensibility
Phase 11 (Fleet) ← add CF workers
Phase 10 (Admiral) ← add automation
    ↓
Phase 12-15 (Testing, Build, Polish)
```
