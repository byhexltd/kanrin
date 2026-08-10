# Kanrin — Task Breakdown (0 to 100)

> Every phase, every module, every struct, every function.
> Priority order: each phase depends on the previous one.

---

## Phase 0: Project Foundation

### 0.1 — Repository Structure
- [ ] **0.1.1** Create Rust workspace `Cargo.toml` with all crate members
- [ ] **0.1.2** Create each crate's `Cargo.toml` with proper dependencies
- [ ] **0.1.3** Create `kanrin-server/Cargo.toml` depending on `kanrin-protocol`
- [ ] **0.1.4** Create `kanrin-admiral/package.json` with `"type": "module"`
- [ ] **0.1.5** Create `kanrin-fleet/package.json` with `"type": "module"`
- [ ] **0.1.6** Create `.gitignore` (target/, node_modules/, .env, *.wasm)
- [ ] **0.1.7** Create `rust-toolchain.toml` (pin Rust version)
- [ ] **0.1.8** Create `.cargo/config.toml` (cross-compile targets)

### 0.2 — Protocol Specification (PROTOCOL.md)
- [ ] **0.2.1** Define chunk format (header + payload + MAC)
- [ ] **0.2.2** Define handshake sequence (ClientHello → ServerHello → keys)
- [ ] **0.2.3** Define authentication mechanism (constant-time, no timing leak)
- [ ] **0.2.4** Define session token format (for migration/reconnect)
- [ ] **0.2.5** Define TCP proxy request format
- [ ] **0.2.6** Define UDP proxy request format
- [ ] **0.2.7** Define DNS query format (encrypted DNS over tunnel)
- [ ] **0.2.8** Define control messages (ping, config-update, score-report)
- [ ] **0.2.9** Define error codes and their meanings
- [ ] **0.2.10** Define version negotiation (future-proof)
- [ ] **0.2.11** Define padding strategy (variable-length per chunk)
- [ ] **0.2.12** Define key rotation mechanism (forward secrecy)

---

## Phase 1: Core Protocol (`kanrin-protocol`)

### 1.1 — Cryptography Module
- [ ] **1.1.1** Implement `KeyDerivation::derive_session_keys()` using HKDF-SHA256
- [ ] **1.1.2** Implement `encrypt_chunk(key, nonce, plaintext, aad) -> ciphertext`
- [ ] **1.1.3** Implement `decrypt_chunk(key, nonce, ciphertext, aad) -> plaintext`
- [ ] **1.1.4** Implement X25519 key exchange (ephemeral-ephemeral)
- [ ] **1.1.5** Implement key rotation (new keys every N bytes or T seconds)
- [ ] **1.1.6** Implement constant-time comparison for auth tokens
- [ ] **1.1.7** Implement secure random generation (nonces, padding, IVs)
- [ ] **1.1.8** Implement zeroize on drop for all key material
- [ ] **1.1.9** Unit tests: encrypt/decrypt roundtrip
- [ ] **1.1.10** Unit tests: key derivation deterministic
- [ ] **1.1.11** Unit tests: nonce never repeats
- [ ] **1.1.12** Unit tests: tampered ciphertext fails

### 1.2 — Wire Format Module
- [ ] **1.2.1** Implement `Chunk::encode(&self) -> Vec<u8>`
- [ ] **1.2.2** Implement `Chunk::decode(bytes) -> Result<Chunk>`
- [ ] **1.2.3** Implement `ChunkHeader::encode/decode`
- [ ] **1.2.4** Implement `ControlMessage::encode/decode`
- [ ] **1.2.5** Implement `ProxyRequest::encode/decode`
- [ ] **1.2.6** Implement random padding generation (1-255 bytes)
- [ ] **1.2.7** Implement chunk framing over stream (length-prefix for TCP)
- [ ] **1.2.8** Implement chunk framing over datagram (QUIC/UDP)
- [ ] **1.2.9** Unit tests: roundtrip all chunk types
- [ ] **1.2.10** Unit tests: invalid bytes produce clear errors
- [ ] **1.2.11** Fuzz test: random bytes don't crash decoder

### 1.3 — Handshake Module
- [ ] **1.3.1** Implement `HandshakeState::new_client()` → generates ephemeral key
- [ ] **1.3.2** Implement `HandshakeState::new_server()`
- [ ] **1.3.3** Implement `client_hello()` → produces ClientHello bytes
- [ ] **1.3.4** Implement `server_process_hello()` → produces ServerHello
- [ ] **1.3.5** Implement `client_process_server_hello()` → derives shared key
- [ ] **1.3.6** Implement `client_finished(auth_token)` → encrypted auth
- [ ] **1.3.7** Implement `server_process_finished()` → validates auth (constant-time)
- [ ] **1.3.8** Implement `server_finished(status)` → response
- [ ] **1.3.9** Implement anti-replay: reject old timestamps (>30s drift)
- [ ] **1.3.10** Implement rate limiting state (per-IP)
- [ ] **1.3.11** Unit tests: successful handshake produces matching keys
- [ ] **1.3.12** Unit tests: tampered hello fails
- [ ] **1.3.13** Unit tests: replay attack detected
- [ ] **1.3.14** Unit tests: constant-time auth response

### 1.4 — Session Module
- [ ] **1.4.1** Implement `Session::new(keys, id)`
- [ ] **1.4.2** Implement `Session::encrypt_outgoing(data)` (incrementing nonce)
- [ ] **1.4.3** Implement `Session::decrypt_incoming(chunk)`
- [ ] **1.4.4** Implement `Session::generate_migration_token()`
- [ ] **1.4.5** Implement `Session::validate_migration_token(token)`
- [ ] **1.4.6** Implement `SessionManager::create/get/remove_session()`
- [ ] **1.4.7** Implement `SessionManager::cleanup_idle()`
- [ ] **1.4.8** Implement session byte counting (traffic limits)
- [ ] **1.4.9** Unit tests: nonce never reused
- [ ] **1.4.10** Unit tests: migration token works
- [ ] **1.4.11** Unit tests: idle sessions cleaned up

---

## Phase 2: Plugin System (`kanrin-plugin`)

### 2.1 — Plugin Interface
- [ ] **2.1.1** Define plugin ABI as WASM interface (wit-bindgen)
- [ ] **2.1.2** Define `TransportPlugin` WASM interface (connect, send, recv, close)
- [ ] **2.1.3** Define `StealthPlugin` WASM interface (transform_outgoing/incoming)
- [ ] **2.1.4** Define `RoutingPlugin` WASM interface (should_proxy, get_target)
- [ ] **2.1.5** Define `ObserverPlugin` WASM interface (on_event)
- [ ] **2.1.6** Define host functions (log, random, time, dns_resolve)
- [ ] **2.1.7** Create plugin manifest schema (TOML)

### 2.2 — Plugin Runtime
- [ ] **2.2.1** Integrate `wasmtime` crate
- [ ] **2.2.2** Implement `PluginRuntime::new()` with fuel metering
- [ ] **2.2.3** Implement `PluginRuntime::load_plugin(path)` → validate & load
- [ ] **2.2.4** Implement capability sandboxing
- [ ] **2.2.5** Implement host functions (log, random, time, dns_resolve)
- [ ] **2.2.6** Implement `PluginRegistry::discover()` → scan for .wasm files
- [ ] **2.2.7** Implement plugin hot-reload (watch + reload)
- [ ] **2.2.8** Unit tests: no-capability plugin can't access network
- [ ] **2.2.9** Unit tests: fuel limit terminates infinite loop
- [ ] **2.2.10** Unit tests: malformed .wasm produces clear error

---

## Phase 3: Transport Layer (`kanrin-transport`)

### 3.1 — Transport Trait
- [ ] **3.1.1** Define `Transport` trait (name, priority, probe, connect, latency, 0rtt)
- [ ] **3.1.2** Define `Connection` trait (send, recv, close, is_alive)
- [ ] **3.1.3** Define `Endpoint` struct (host, port, sni, fingerprint)
- [ ] **3.1.4** Define `TransportError` enum
- [ ] **3.1.5** Implement `TransportRegistry` (all available transports)
- [ ] **3.1.6** Implement `AutoSelect` (priority-based, first working)

### 3.2 — P1: Direct QUIC
- [ ] **3.2.1** Integrate `quinn` crate
- [ ] **3.2.2** Implement `QuicTransport::new/probe/connect`
- [ ] **3.2.3** Implement Chromium QUIC fingerprint mimicry
- [ ] **3.2.4** Implement `QuicConnection::send/recv`
- [ ] **3.2.5** Implement Brutal congestion control (fixed-rate, loss-ignoring)
- [ ] **3.2.6** Implement Adaptive congestion (BBR↔Brutal based on loss)
- [ ] **3.2.7** Implement 0-RTT reconnection
- [ ] **3.2.8** Implement connection migration (IP change)
- [ ] **3.2.9** Implement PMTU discovery
- [ ] **3.2.10** Tests: connect, data roundtrip, 0-RTT, migration

### 3.3 — P2: Direct TLS/TCP
- [ ] **3.3.1** Integrate `rustls` + `tokio-rustls`
- [ ] **3.3.2** Implement `TlsTcpTransport::new/probe/connect`
- [ ] **3.3.3** Implement Chrome/Firefox/Safari TLS fingerprints
- [ ] **3.3.4** Implement ECH (Encrypted Client Hello)
- [ ] **3.3.5** Implement ALPN negotiation
- [ ] **3.3.6** Implement `TlsConnection::send/recv` with chunk framing
- [ ] **3.3.7** Implement TCP keepalive
- [ ] **3.3.8** Tests: handshake, fingerprint, ECH

### 3.4 — P3: CF Worker WebSocket
- [ ] **3.4.1** Integrate `tokio-tungstenite`
- [ ] **3.4.2** Implement `CfWebSocketTransport::new/probe/connect`
- [ ] **3.4.3** Implement worker URL rotation (failover)
- [ ] **3.4.4** Implement browser-like upgrade headers
- [ ] **3.4.5** Implement `CfWsConnection::send/recv` (binary frames)
- [ ] **3.4.6** Implement ping/pong keepalive
- [ ] **3.4.7** Implement reconnect with session migration
- [ ] **3.4.8** Tests: connect, failover, data transfer

### 3.5 — P4: CDN HTTP/2 Multiplexed
- [ ] **3.5.1** Integrate `hyper` + `h2`
- [ ] **3.5.2** Implement `CdnHttp2Transport::new/probe/connect`
- [ ] **3.5.3** Implement client→server: POST with encrypted body
- [ ] **3.5.4** Implement server→client: long-poll GET or SSE
- [ ] **3.5.5** Implement path/header randomization
- [ ] **3.5.6** Implement multiplexed concurrent streams
- [ ] **3.5.7** Tests: data transfer over HTTP/2

### 3.6 — P5: Domain Fronting
- [ ] **3.6.1** Implement `DomainFrontTransport::new/probe/connect`
- [ ] **3.6.2** Implement TLS to front_domain + Host: real_host
- [ ] **3.6.3** Implement CDN-specific quirks (CF, Fastly, Azure)
- [ ] **3.6.4** Tests: SNI vs Host mismatch routing

### 3.7 — P6: DNS Steganographic Tunnel
- [ ] **3.7.1** Integrate `trust-dns-client`
- [ ] **3.7.2** Implement `DnsTunnelTransport::new/probe/connect`
- [ ] **3.7.3** Implement data encoding in subdomains (base32)
- [ ] **3.7.4** Implement data retrieval via TXT records
- [ ] **3.7.5** Implement chunking across multiple queries
- [ ] **3.7.6** Implement polling for server responses
- [ ] **3.7.7** Tests: encode/decode roundtrip, large data chunking

---

See `TASKS-2.md` for Phases 4-15.
