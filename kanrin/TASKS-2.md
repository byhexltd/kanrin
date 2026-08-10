# Kanrin — Task Breakdown (Phases 4-8)

---

## Phase 4: TUN & Packet Engine (`kanrin-tun`)

### 4.1 — TUN Interface (Per-OS)
- [ ] **4.1.1** Implement TUN creation on Linux (`/dev/net/tun` ioctl)
- [ ] **4.1.2** Implement TUN creation on macOS (`utun` socket)
- [ ] **4.1.3** Implement TUN creation on Windows (Wintun driver)
- [ ] **4.1.4** Implement `TunDevice::read_packet() -> IpPacket`
- [ ] **4.1.5** Implement `TunDevice::write_packet(IpPacket)`
- [ ] **4.1.6** Implement MTU configuration
- [ ] **4.1.7** Implement IP address assignment to TUN
- [ ] **4.1.8** Implement DNS server assignment to TUN
- [ ] **4.1.9** Implement `TunDevice::close()` (cleanup on shutdown)
- [ ] **4.1.10** Tests: packet read/write roundtrip

### 4.2 — Packet Parser
- [ ] **4.2.1** Implement IPv4 header parser
- [ ] **4.2.2** Implement IPv6 header parser
- [ ] **4.2.3** Implement TCP segment parser
- [ ] **4.2.4** Implement UDP datagram parser
- [ ] **4.2.5** Implement ICMP packet parser
- [ ] **4.2.6** Implement DNS query parser (extract domain from UDP:53)
- [ ] **4.2.7** Implement packet reconstruction (modify + recalculate checksums)
- [ ] **4.2.8** Tests: parse real captured packets
- [ ] **4.2.9** Fuzz test: random bytes don't crash parser

### 4.3 — NAT Table
- [ ] **4.3.1** Implement `NatTable::new(timeout)`
- [ ] **4.3.2** Implement `NatTable::lookup_outgoing(packet)` → find/create entry
- [ ] **4.3.3** Implement `NatTable::lookup_incoming(packet)` → find return path
- [ ] **4.3.4** Implement `NatTable::cleanup()` → remove expired
- [ ] **4.3.5** Implement TCP state tracking (SYN/ESTABLISHED/FIN)
- [ ] **4.3.6** Implement UDP session tracking (timeout-based)
- [ ] **4.3.7** Tests: bidirectional NAT translation
- [ ] **4.3.8** Tests: expired entries cleaned

### 4.4 — DNS Interceptor
- [ ] **4.4.1** Implement DNS query interception (catch all UDP:53)
- [ ] **4.4.2** Implement DNS-over-tunnel forwarding
- [ ] **4.4.3** Implement DNS cache (LRU, TTL-aware)
- [ ] **4.4.4** Implement FakeIP mode (return fake IP, resolve later)
- [ ] **4.4.5** Implement DNS-over-HTTPS fallback (DoH)
- [ ] **4.4.6** Implement DNS leak prevention (block non-tunnel DNS)
- [ ] **4.4.7** Tests: all DNS goes through tunnel
- [ ] **4.4.8** Tests: FakeIP mapping bidirectional

### 4.5 — Kill Switch
- [ ] **4.5.1** Windows: WFP filter — block all outgoing
- [ ] **4.5.2** Windows: WFP filter — allow Kanrin server IP
- [ ] **4.5.3** Windows: WFP filter — allow LAN (optional)
- [ ] **4.5.4** Windows: cleanup filters on disable
- [ ] **4.5.5** Linux: nftables — block all OUTPUT
- [ ] **4.5.6** Linux: nftables — allow Kanrin server + TUN
- [ ] **4.5.7** Linux: cleanup on disable
- [ ] **4.5.8** macOS: pf rules — block all
- [ ] **4.5.9** macOS: pf rules — allow Kanrin + TUN
- [ ] **4.5.10** macOS: cleanup on disable
- [ ] **4.5.11** Implement `KillSwitch::activate(server_ips)`
- [ ] **4.5.12** Implement `KillSwitch::deactivate()`
- [ ] **4.5.13** Implement crash recovery (self-expiring rules or cleanup daemon)
- [ ] **4.5.14** Integration test: no traffic leaks when active

### 4.6 — Routing Table Manager
- [ ] **4.6.1** Save original default route before connecting
- [ ] **4.6.2** Set TUN as default gateway
- [ ] **4.6.3** Add specific route for server IP (bypass TUN)
- [ ] **4.6.4** Restore original routes on disconnect
- [ ] **4.6.5** Crash recovery (restore if process died)
- [ ] **4.6.6** Platform: Windows (`route add/delete`)
- [ ] **4.6.7** Platform: Linux (`ip route`)
- [ ] **4.6.8** Platform: macOS (`route`)

---

## Phase 5: Stealth Engine (`kanrin-stealth`)

### 5.1 — Stealth Trait & Pipeline
- [ ] **5.1.1** Define `StealthModule` trait (transform_outgoing/incoming, cover_traffic)
- [ ] **5.1.2** Define `StealthContext` (time, bytes, duration, transport)
- [ ] **5.1.3** Implement `StealthPipeline` (chain modules in order)
- [ ] **5.1.4** Implement `StealthPipeline::apply_outgoing(data)`
- [ ] **5.1.5** Implement `StealthPipeline::apply_incoming(data)`

### 5.2 — Rhythm Engine (Traffic Shaping)
- [ ] **5.2.1** Implement `TrafficPattern::VideoStreaming` (1-4MB chunks + pauses)
- [ ] **5.2.2** Implement `TrafficPattern::WebBrowsing` (burst→silence→burst)
- [ ] **5.2.3** Implement `TrafficPattern::FileDownload` (steady rate)
- [ ] **5.2.4** Implement `TrafficPattern::Messaging` (small, irregular)
- [ ] **5.2.5** Implement `TrafficPattern::Adaptive` (learn real pattern)
- [ ] **5.2.6** Implement packet delay injection (hold to match timing)
- [ ] **5.2.7** Implement padding injection (add volume to match pattern)
- [ ] **5.2.8** Implement cover traffic (send when idle)
- [ ] **5.2.9** Tests: output matches pattern distribution

### 5.3 — TLS Fingerprint Randomization
- [ ] **5.3.1** Implement JA3 fingerprint for Chrome (latest)
- [ ] **5.3.2** Implement JA3 fingerprint for Firefox (latest)
- [ ] **5.3.3** Implement JA3 fingerprint for Safari (latest)
- [ ] **5.3.4** Implement random valid fingerprint generation
- [ ] **5.3.5** Implement cipher suite ordering (match browser)
- [ ] **5.3.6** Implement TLS extension ordering (match browser)
- [ ] **5.3.7** Implement GREASE values (like real browsers)
- [ ] **5.3.8** Tests: ClientHello matches target JA3

### 5.4 — TLS Record Fragmentation
- [ ] **5.4.1** Implement ClientHello fragmentation (multiple TCP segments)
- [ ] **5.4.2** Implement SNI-aware splitting (cut in middle of SNI)
- [ ] **5.4.3** Implement random delay between fragments
- [ ] **5.4.4** Implement TLS record-layer fragmentation
- [ ] **5.4.5** Tests: fragmented ClientHello reassembles correctly

---

## Phase 6: Routing Engine (`kanrin-routing`)

### 6.1 — Routing Trait & Rules
- [ ] **6.1.1** Define `RoutingRule` trait (matches, decision, priority)
- [ ] **6.1.2** Define `RoutingContext` (src_ip, dst_ip, port, domain, process)
- [ ] **6.1.3** Implement `RoutingEngine::decide(ctx)` → evaluate rules
- [ ] **6.1.4** Implement `DomainRule` (match: `*.ir`, `*.google.com`)
- [ ] **6.1.5** Implement `IpRule` (match CIDR ranges)
- [ ] **6.1.6** Implement `GeoIpRule` (match country: `geoip:ir`)
- [ ] **6.1.7** Implement `PortRule` (match port)
- [ ] **6.1.8** Implement `ProcessRule` (match app name/path)
- [ ] **6.1.9** Implement `ProtocolRule` (match TCP/UDP/ICMP)
- [ ] **6.1.10** Implement `CompositeRule` (AND/OR)

### 6.2 — GeoIP Database
- [ ] **6.2.1** Integrate MaxMind GeoLite2 (or custom format)
- [ ] **6.2.2** Implement `GeoIpDatabase::lookup(ip) -> CountryCode`
- [ ] **6.2.3** Implement Iran IP range database (RIPE NCC)
- [ ] **6.2.4** Implement auto-update (periodic download)
- [ ] **6.2.5** Implement compact binary format (minimize memory)

### 6.3 — Iran Preset
- [ ] **6.3.1** Implement Iran domain list (`.ir`, known domains)
- [ ] **6.3.2** Implement Iran IP ranges (all Iranian ASNs)
- [ ] **6.3.3** Implement `IranPreset::default()` → bypass Iranian traffic
- [ ] **6.3.4** Implement auto-update for lists (from Admiral/GitHub)
- [ ] **6.3.5** Implement banking apps rule (bank domains → direct)
- [ ] **6.3.6** Tests: Iranian → direct, foreign → proxy

### 6.4 — Process Detection (Per-App)
- [ ] **6.4.1** Windows: `GetExtendedTcpTable` → process from socket
- [ ] **6.4.2** Linux: `/proc/net/tcp` + `/proc/pid` → process from socket
- [ ] **6.4.3** macOS: `proc_pidinfo` → process from socket
- [ ] **6.4.4** Implement process path resolution
- [ ] **6.4.5** Implement caching (don't re-lookup same connection)
- [ ] **6.4.6** Tests: correctly identifies calling process

---

## Phase 7: Self-Healing Engine (`kanrin-engine`)

### 7.1 — Prober
- [ ] **7.1.1** Implement `Prober::new(endpoints, interval)`
- [ ] **7.1.2** Implement background probing loop (async)
- [ ] **7.1.3** Implement per-transport probe (QUIC/TLS/WS)
- [ ] **7.1.4** Implement latency measurement (RTT)
- [ ] **7.1.5** Implement success rate (rolling window)
- [ ] **7.1.6** Implement scoring: `score = success_rate * (1/latency)`
- [ ] **7.1.7** Implement event on state change (up/down)
- [ ] **7.1.8** Tests: detects unreachable endpoint
- [ ] **7.1.9** Tests: scoring ranks fast+reliable higher

### 7.2 — ScoreBoard
- [ ] **7.2.1** Implement `ScoreBoard::update_local(endpoint, result)`
- [ ] **7.2.2** Implement `ScoreBoard::update_collective(from_admiral)`
- [ ] **7.2.3** Implement `ScoreBoard::best_endpoint()`
- [ ] **7.2.4** Implement `ScoreBoard::ranked_list()`
- [ ] **7.2.5** Implement score decay (old scores matter less)
- [ ] **7.2.6** Implement anonymous reporting (to Admiral)

### 7.3 — Switcher
- [ ] **7.3.1** Implement `Switcher::new(scoreboard, threshold, cooldown)`
- [ ] **7.3.2** Implement `Switcher::monitor_loop()` — watch health
- [ ] **7.3.3** Implement `Switcher::should_switch()` — decision logic
- [ ] **7.3.4** Implement `Switcher::perform_switch()` — seamless switch
- [ ] **7.3.5** Implement session migration during switch (no data loss)
- [ ] **7.3.6** Implement event emission ("Switching to faster route...")
- [ ] **7.3.7** Tests: switch on score drop
- [ ] **7.3.8** Tests: cooldown prevents rapid switching
- [ ] **7.3.9** Tests: data continuity across switch

### 7.4 — Bootstrap Engine
- [ ] **7.4.1** Define `BootstrapMethod` trait
- [ ] **7.4.2** Implement `HardcodedBootstrap` (static list)
- [ ] **7.4.3** Implement `TotpDnsBootstrap` (time-based subdomain)
- [ ] **7.4.4** Implement `AdmiralBootstrap` (fetch from Admiral API)
- [ ] **7.4.5** Implement `PeerBootstrap` (ask other clients)
- [ ] **7.4.6** Implement `BootstrapEngine::discover()` → try all, merge
- [ ] **7.4.7** Implement fallback chain
- [ ] **7.4.8** Tests: TOTP correct subdomain for time
- [ ] **7.4.9** Tests: fallback when primary fails

### 7.5 — Network Detection
- [ ] **7.5.1** Implement UDP reachability test
- [ ] **7.5.2** Implement TCP direct reachability test
- [ ] **7.5.3** Implement WebSocket upgrade test
- [ ] **7.5.4** Implement SNI filtering detection
- [ ] **7.5.5** Implement total shutdown detection
- [ ] **7.5.6** Implement national intranet detection
- [ ] **7.5.7** Implement `NetworkDetector::detect() -> NetworkState`
- [ ] **7.5.8** Implement transport recommendation based on state
- [ ] **7.5.9** Tests: each state correctly identified

---

## Phase 8: Client Library (`kanrin-client`)

### 8.1 — Public API
- [ ] **8.1.1** Implement `KanrinClient::new(config)`
- [ ] **8.1.2** Implement `KanrinClient::start()` (connect+TUN+killswitch)
- [ ] **8.1.3** Implement `KanrinClient::stop()` (disconnect+cleanup)
- [ ] **8.1.4** Implement `KanrinClient::status() -> ClientState`
- [ ] **8.1.5** Implement `KanrinClient::subscribe_events(callback)`
- [ ] **8.1.6** Implement `KanrinClient::get_stats() -> Stats`
- [ ] **8.1.7** Implement `KanrinClient::force_switch_transport(name)`
- [ ] **8.1.8** Implement `KanrinClient::update_config(new)` (hot reload)
- [ ] **8.1.9** Implement graceful shutdown (flush, close, restore)
- [ ] **8.1.10** Implement crash recovery (cleanup stale state)

### 8.2 — Pipeline Orchestrator
- [ ] **8.2.1** Implement main loop: TUN→parse→route→encrypt→shape→send
- [ ] **8.2.2** Implement reverse: recv→unshape→decrypt→NAT→TUN
- [ ] **8.2.3** Implement TCP proxying (full state machine through tunnel)
- [ ] **8.2.4** Implement UDP proxying (stateless through tunnel)
- [ ] **8.2.5** Implement DNS interception integration
- [ ] **8.2.6** Implement per-packet routing decision
- [ ] **8.2.7** Implement direct path (bypass for Iranian traffic)
- [ ] **8.2.8** Implement concurrent connection handling (thousands)
- [ ] **8.2.9** Implement buffer management (back-pressure)
- [ ] **8.2.10** Performance benchmark: packets-per-second

### 8.3 — FFI / C API
- [ ] **8.3.1** Implement C-compatible API (extern "C")
- [ ] **8.3.2** Implement JSON config parsing in FFI layer
- [ ] **8.3.3** Implement event callback (C function pointer)
- [ ] **8.3.4** Implement thread safety
- [ ] **8.3.5** Generate C header file (`kanrin.h`)
- [ ] **8.3.6** Build as shared library (.so/.dll/.dylib)
- [ ] **8.3.7** Build as static library (.a/.lib)
- [ ] **8.3.8** Smoke test from C program
- [ ] **8.3.9** Integration test from Tauri (direct crate dep)

### 8.4 — CLI Wrapper
- [ ] **8.4.1** Implement `kanrin connect -c config.yml`
- [ ] **8.4.2** Implement `kanrin disconnect`
- [ ] **8.4.3** Implement `kanrin status`
- [ ] **8.4.4** Implement `kanrin test` (connectivity tests)
- [ ] **8.4.5** Implement `kanrin generate-config` (interactive wizard)
- [ ] **8.4.6** Implement signal handling (SIGTERM → graceful)
- [ ] **8.4.7** Implement daemon mode (`--daemon`)
- [ ] **8.4.8** Implement log levels (`--log-level`)
