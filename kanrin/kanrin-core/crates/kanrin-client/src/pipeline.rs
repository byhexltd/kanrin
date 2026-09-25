use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};

use kanrin_engine::bootstrap::{BootstrapEngine, HardcodedBootstrap};
use kanrin_engine::detection::NetworkDetector;
use kanrin_engine::prober::Prober;
use kanrin_engine::scoreboard::{ScoreBoard, ScoreWeights};
use kanrin_engine::switcher::Switcher;
use kanrin_protocol::continuity::{ReceiveBuffer, Received, SendBuffer};
use kanrin_protocol::handshake::{AuthStatus, ClientHandshake, ServerFinished, ServerHello};
use kanrin_protocol::session::{Session, SessionId};
use kanrin_protocol::wire::{Chunk, ChunkType, ControlMessage};
use kanrin_routing::{RouteDecision, RoutingEngine};
use kanrin_routing::iran::load_iran_preset;
use kanrin_stealth::StealthPipeline;
use kanrin_transport::{Connection, Endpoint, TransportRegistry};
use kanrin_tun::device::{TunConfig, TunDevice};
use kanrin_tun::dns::DnsInterceptor;
use kanrin_tun::killswitch::{KillSwitch, KillSwitchConfig};
use kanrin_tun::nat::NatTable;
use kanrin_tun::packet::IpPacket;
use kanrin_tun::routing::RoutingManager;

use kanrin_protocol::crypto::SessionKeys;

use crate::config::KanrinConfig;
use crate::events::KanrinEvent;
use crate::posture::{Posture, PostureController, Signal};
use crate::switch::{self, LivenessMonitor, SwitchPolicy, SwitchReason, PROBE_INTERVAL};
use crate::{ClientError, ClientState};

/// Packets held between the TUN reader task and the encrypt/send loop.
///
/// Bounded on purpose: once the send buffer stops accepting work, this queue
/// fills, the reader's `send().await` parks, and the pressure reaches the TUN
/// device itself — which makes the guest TCP stacks slow down instead of us
/// buffering the whole world.
const TUN_QUEUE_DEPTH: usize = 256;

/// Acknowledge the server after this many data chunks, or after this long,
/// whichever comes first. Mirrors the server's policy: frequent enough that the
/// peer's send buffer keeps draining, rare enough not to double the frame count.
const ACK_EVERY_N_CHUNKS: usize = 32;
const ACK_MAX_DELAY: Duration = Duration::from_millis(200);

/// Move the session onto another transport without the tunnelled connections
/// noticing (16.2.2).
///
/// Make-before-break (16.2.4): the replacement is connected, resumed and has
/// carried the full replay *before* the active handle is replaced. If any of
/// that fails, the old transport is still in place and still owns the session,
/// so a failed switch costs nothing.
///
/// The old handle is not closed here. It is returned to the caller to be shut
/// down once the new one has actually carried traffic.
#[allow(clippy::too_many_arguments)]
async fn attempt_switch(
    reason: &SwitchReason,
    connection: &mut Box<dyn Connection>,
    active_transport: &mut String,
    transport_registry: &TransportRegistry,
    endpoint: &Endpoint,
    session_id: SessionId,
    keys: &SessionKeys,
    send_buffer: &mut SendBuffer,
    next_expected: u64,
    policy: &mut SwitchPolicy,
    monitor: &mut LivenessMonitor,
    event_tx: &mpsc::UnboundedSender<KanrinEvent>,
) -> Option<Box<dyn Connection>> {
    if !policy.allows(reason) {
        tracing::debug!(?reason, cooldown = ?policy.cooldown(), "switch suppressed by cooldown");
        return None;
    }

    let mut standby = match switch::prepare_standby(
        transport_registry,
        endpoint,
        active_transport,
        session_id,
        keys,
        next_expected,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "no standby transport could be prepared");
            return None;
        }
    };

    // The server told us what it already has; everything below that can go.
    send_buffer.apply_ack(standby.server_next_expected, &[]);

    let replayed = match switch::replay_onto(&mut standby.connection, send_buffer).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "replay onto standby failed — keeping current transport");
            let _ = standby.connection.close().await;
            return None;
        }
    };

    // Atomic swap: from here on, everything goes out over the new transport.
    let previous = std::mem::replace(connection, standby.connection);
    let from = std::mem::replace(active_transport, standby.transport);

    policy.record();
    monitor.reset();

    tracing::info!(from = %from, to = %active_transport, replayed, "transport switched");

    // 16.2.6 — a switch is normal operation, so it is reported as such. An
    // `Error` here would train users to distrust a feature that just saved
    // their connection.
    event_tx
        .send(KanrinEvent::TransportSwitched {
            from,
            to: active_transport.clone(),
            reason: reason.describe(),
        })
        .ok();

    Some(previous)
}

/// Main pipeline — orchestrates the full VPN lifecycle:
/// TUN Capture → Route → Encrypt → Shape → Transport → Network
pub async fn run_pipeline(
    config: Arc<RwLock<KanrinConfig>>,
    state: Arc<RwLock<ClientState>>,
    event_tx: mpsc::UnboundedSender<KanrinEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), ClientError> {
    let cfg = config.read().clone();

    // Install rustls CryptoProvider (ring)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // === Phase 1: Network Detection ===
    if cfg.engine.detect_censorship {
        let mut detector = NetworkDetector::new();
        // Test UDP against the actual server, not a hardcoded address
        detector.quic_test_endpoint = format!("{}:{}", cfg.server.address, cfg.server.port);
        detector.tls_test_endpoint = format!("{}:{}", cfg.server.address, cfg.server.port);
        let detection = detector.detect().await;
        event_tx.send(KanrinEvent::CensorshipDetected {
            state: format!("{:?}", detection.state),
            suggested_transports: detector
                .suggest_transport(detection.state)
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }).ok();
    }

    // === Phase 2: Bootstrap — Discover Endpoints ===
    let endpoint = Endpoint::new(&cfg.server.address, cfg.server.port);
    let endpoint = if let Some(ref sni) = cfg.server.sni {
        endpoint.with_sni(sni.clone())
    } else {
        endpoint
    };

    // === Phase 3: Build Transport Registry ===
    let mut transport_registry = TransportRegistry::new();

    {
        use kanrin_transport::quic::QuicTransport;
        transport_registry.register(Box::new(QuicTransport::with_defaults()));
    }

    {
        use kanrin_transport::tls_tcp::TlsTcpTransport;
        transport_registry.register(Box::new(TlsTcpTransport::with_defaults()));
    }

    {
        use kanrin_transport::websocket::WebSocketTransport;
        transport_registry.register(Box::new(WebSocketTransport::with_defaults()));
    }

    // === Phase 4: Connect ===
    let (mut connection, transport_name) = transport_registry
        .auto_connect(&endpoint)
        .await
        .map_err(|e| ClientError::ConnectionFailed(format!("{}", e)))?;

    tracing::info!(transport = transport_name, "connected to server");

    // === Phase 5: Handshake ===
    let mut handshake = ClientHandshake::new();
    let client_hello = handshake.client_hello()
        .map_err(|e| ClientError::ConnectionFailed(format!("handshake: {}", e)))?;

    // Send ClientHello
    let hello_data = client_hello.encode();
    let hello_chunk = Chunk::new_handshake(hello_data);
    // For handshake, use a temporary key (all zeros — first message is cleartext-wrapped)
    let temp_key = [0u8; 32];
    let temp_nonce = [0u8; 12];
    let encoded = hello_chunk.encode_encrypted(&temp_key, &temp_nonce)
        .map_err(|e| ClientError::ConnectionFailed(format!("encode hello: {}", e)))?;
    connection.send(&encoded).await
        .map_err(|e| ClientError::ConnectionFailed(format!("send hello: {}", e)))?;

    // Receive ServerHello
    let server_data = connection.recv().await
        .map_err(|e| ClientError::ConnectionFailed(format!("recv server hello: {}", e)))?;
    let server_chunk = Chunk::decode_encrypted(&server_data, &temp_key, &temp_nonce)
        .map_err(|e| ClientError::ConnectionFailed(format!("decode server hello: {}", e)))?;
    let server_hello = ServerHello::decode(&server_chunk.payload)
        .map_err(|e| ClientError::ConnectionFailed(format!("parse server hello: {}", e)))?;

    // Derive session keys
    let session_keys = handshake.process_server_hello(&server_hello)
        .map_err(|e| ClientError::ConnectionFailed(format!("process server hello: {}", e)))?;

    // Send ClientFinished (auth)
    let finished = handshake.client_finished(&cfg.server.password, &session_keys)
        .map_err(|e| ClientError::ConnectionFailed(format!("auth: {}", e)))?;
    let finished_chunk = Chunk::new_handshake(finished.encode());
    let encoded = finished_chunk.encode_encrypted(&session_keys.client_write_key, &[0u8; 12])
        .map_err(|e| ClientError::ConnectionFailed(format!("encode auth: {}", e)))?;
    connection.send(&encoded).await
        .map_err(|e| ClientError::ConnectionFailed(format!("send auth: {}", e)))?;

    // Receive ServerFinished (auth result)
    let finished_data = connection.recv().await
        .map_err(|e| ClientError::ConnectionFailed(format!("recv server finished: {}", e)))?;
    let finished_chunk = Chunk::decode_encrypted(&finished_data, &session_keys.server_write_key, &[0u8; 12])
        .map_err(|e| ClientError::ConnectionFailed(format!("decode server finished: {}", e)))?;
    let server_finished = ServerFinished::decode(&finished_chunk.payload)
        .map_err(|e| ClientError::ConnectionFailed(format!("parse server finished: {}", e)))?;

    if server_finished.status != AuthStatus::Ok {
        return Err(ClientError::ConnectionFailed(format!(
            "authentication failed: {:?}", server_finished.status
        )));
    }

    tracing::info!("authentication successful");

    // The server owns address assignment and returns the allocated tunnel IP in
    // the session token. Using anything else (such as a stale value from the
    // config file) makes the server unable to match reply packets back to this
    // client, so every response would be silently dropped.
    // Token layout: `tunnel_ip(4) || session_id(16)`. The id is the handle we
    // present to reattach to this session after a transport switch.
    let (assigned_ip, session_id) = match server_finished.session_token.as_deref() {
        Some(token) if token.len() >= 20 => (
            Some(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(&token[..4]).unwrap(),
            )),
            Some(SessionId::from_bytes(
                <[u8; 16]>::try_from(&token[4..20]).unwrap(),
            )),
        ),
        _ => (None, None),
    };

    let tun_address: std::net::IpAddr = match assigned_ip {
        Some(ip) => {
            tracing::info!(address = %ip, "server assigned tunnel address");
            ip.into()
        }
        None => {
            tracing::warn!("server did not assign an address — falling back to config");
            cfg.tun
                .address
                .parse()
                .unwrap_or_else(|_| "10.10.0.2".parse().unwrap())
        }
    };

    // Create session. Use the server's id so both sides agree on the handle
    // a resumption request names.
    let session_id = session_id.unwrap_or_else(SessionId::generate);
    let resumption_keys = session_keys.clone();
    let mut session = Session::new(session_id, session_keys);

    // === Phase 6: Setup TUN ===
    let tun_config = TunConfig {
        name: cfg.tun.name.clone(),
        address: tun_address,
        mtu: cfg.tun.mtu,
        ..TunConfig::default()
    };

    let tun_device = Arc::new(
        TunDevice::create(tun_config)
            .map_err(|e| ClientError::Internal(format!("TUN create: {}", e)))?,
    );

    // === Phase 6b: Activate System Routing (all traffic -> TUN) ===
    let server_ips: Vec<std::net::IpAddr> = match cfg.server.address.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host(format!("{}:{}", cfg.server.address, cfg.server.port))
            .await
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .unwrap_or_default(),
    };

    let mut routing_manager = RoutingManager::new(
        cfg.tun.name.clone(),
        tun_device.config().gateway.into(),
        server_ips,
    );

    if let Err(e) = routing_manager.activate() {
        tracing::warn!(error = %e, "failed to activate system routing");
    }

    // === Phase 7: Setup Kill Switch ===
    let mut kill_switch = if cfg.tun.kill_switch {
        let ks_config = KillSwitchConfig {
            allowed_ips: vec![cfg.server.address.parse().unwrap_or("0.0.0.0".parse().unwrap())],
            allow_lan: cfg.tun.allow_lan,
            allow_loopback: true,
        };
        let mut ks = KillSwitch::new(ks_config);
        let _ = ks.activate();
        event_tx.send(KanrinEvent::KillSwitchChanged { active: true }).ok();
        Some(ks)
    } else {
        None
    };

    // === Phase 8: Setup Routing ===
    let mut routing_engine = RoutingEngine::new(RouteDecision::Proxy);
    if cfg.routing.iran_preset {
        load_iran_preset(&mut routing_engine);
    }

    // === Phase 9: Setup DNS Interceptor ===
    let mut dns_interceptor = DnsInterceptor::new(cfg.tun.fake_ip);

    // === Phase 10: Setup NAT ===
    let mut nat_table = NatTable::new(
        Duration::from_secs(300),
        Duration::from_secs(60),
    );

    // === Connected! ===
    *state.write() = ClientState::Connected;
    event_tx.send(KanrinEvent::Connected {
        transport: transport_name.to_string(),
        endpoint: endpoint.addr_string(),
        latency_ms: 0,
    }).ok();

    tracing::info!("VPN connected — all traffic routed through tunnel");

    // === Main Loop: TUN read → encrypt → send ===
    let mut stats_interval = tokio::time::interval(Duration::from_secs(5));

    // Every data chunk is retained here until the server acknowledges it, so it
    // can be replayed onto a new transport (16.1.5). The bound is what keeps a
    // stalled or dead transport from growing this without limit.
    let mut send_buffer = SendBuffer::with_default_capacity();

    // The other direction: reorder and de-duplicate what the server sends, and
    // acknowledge it so the server can release its own retained chunks. Without
    // this an interrupted download could never be replayed.
    let mut recv_buffer = ReceiveBuffer::with_default_capacity();
    let mut unacked_chunks = 0usize;
    let mut last_ack = tokio::time::Instant::now();

    // Adaptive posture (16.4). Starts at the configured level and escalates
    // on evidence; the floor keeps a user in a hostile network from being
    // optimised back down during a quiet hour.
    let mut posture = PostureController::new(Posture::Balanced);
    let mut posture_tick = tokio::time::interval(Duration::from_secs(30));
    posture_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    macro_rules! observe_signal {
        ($signal:expr) => {{
            let before = posture.current();
            if let Some(after) = posture.observe($signal) {
                tracing::info!(from = before.as_str(), to = after.as_str(), "posture changed");
                event_tx
                    .send(KanrinEvent::PostureChanged {
                        from: before.as_str().to_string(),
                        to: after.as_str().to_string(),
                        reason: format!("{:?}", $signal),
                    })
                    .ok();
            }
        }};
    }

    // Transport switching state (16.2).
    let mut active_transport = transport_name.to_string();
    let mut policy = SwitchPolicy::new();
    let mut monitor = LivenessMonitor::new();
    let mut liveness_tick = tokio::time::interval(PROBE_INTERVAL);
    liveness_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // The transport we just switched away from, kept open until the new one
    // has actually delivered something (16.2.4). Closing it any earlier would
    // make a failed switch unrecoverable.
    let mut draining: Option<Box<dyn Connection>> = None;

    // Consecutive failed switch attempts; the tunnel is only abandoned once
    // nothing at all can be established.
    let mut failed_switches = 0u32;
    const MAX_FAILED_SWITCHES: u32 = 5;

    macro_rules! switch_or_give_up {
        ($reason:expr) => {{
            let reason = $reason;
            let next_expected = recv_buffer.next_expected();
            let previous = attempt_switch(
                &reason,
                &mut connection,
                &mut active_transport,
                &transport_registry,
                &endpoint,
                session_id,
                &resumption_keys,
                &mut send_buffer,
                next_expected,
                &mut policy,
                &mut monitor,
                &event_tx,
            )
            .await;

            match previous {
                Some(old) => {
                    failed_switches = 0;
                    if let Some(mut stale) = draining.replace(old) {
                        let _ = stale.close().await;
                    }
                }
                None => {
                    failed_switches += 1;
                    if failed_switches >= MAX_FAILED_SWITCHES {
                        tracing::error!(attempts = failed_switches, "no transport could carry the session");
                        break;
                    }
                }
            }
        }};
    }

    // TUN reads happen in a dedicated task. Awaiting them directly in the
    // `select!` below would abandon an in-flight blocking read whenever another
    // branch wins, silently dropping that packet. Channel receives are
    // cancel-safe, so the loop can poll them freely.
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(TUN_QUEUE_DEPTH);
    let reader_tun = tun_device.clone();
    let tun_reader = tokio::spawn(async move {
        loop {
            match reader_tun.read_packet().await {
                Ok(raw) => {
                    // Awaiting here is the back-pressure: while the queue is
                    // full this task stops reading the device.
                    if tun_tx.send(raw).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TUN read error");
                    break;
                }
            }
        }
    });

    loop {
        tokio::select! {
            // Read from TUN (outgoing traffic).
            //
            // Disabled while the send buffer is at its bound: unacknowledged
            // data must not be discarded (it may still need replaying), so the
            // only correct response to a full buffer is to stop producing.
            packet = tun_rx.recv(), if !send_buffer.is_full() => {
                let Some(raw) = packet else {
                    tracing::warn!("TUN reader stopped");
                    break;
                };

                if let Some(ip_packet) = IpPacket::parse(&raw) {
                    // DNS interception
                    if ip_packet.is_dns_query() {
                        if let Some(response) = dns_interceptor.intercept_query(&raw) {
                            let _ = tun_device.write_packet(&response).await;
                            continue;
                        }
                    }

                    // Encrypt and send through tunnel
                    let chunk = Chunk::new_data(raw);
                    let sequence = session.send_nonce_value();
                    match session.encrypt_outgoing(&chunk, true) {
                        Ok(encrypted) => {
                            let sent = connection.send(&encrypted).await;

                            // Retain regardless of the outcome: a chunk the
                            // transport failed on is exactly the one a replay
                            // has to resend.
                            if let Err(e) = send_buffer.push(sequence, encrypted) {
                                tracing::warn!(error = %e, "send buffer rejected chunk");
                            }

                            if let Err(e) = sent {
                                // Not fatal any more: the chunk is retained, so
                                // a switch replays it and the inner stream
                                // never learns the transport changed.
                                tracing::warn!(error = %e, "send failed — switching transport");
                                switch_or_give_up!(SwitchReason::TransportError(e.to_string()));
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "encrypt failed");
                            break;
                        }
                    }
                }
            }

            // Receive from server (incoming traffic)
            data = connection.recv() => {
                match data {
                    Ok(encrypted) => {
                        // Any inbound frame proves the transport is alive, and
                        // proves the switch that produced it worked — so the
                        // one it replaced can finally be shut down (16.2.4).
                        monitor.record_inbound();
                        if let Some(mut old) = draining.take() {
                            let _ = old.close().await;
                        }

                        match session.decrypt_incoming(&encrypted, true) {
                            Ok(chunk) => match chunk.header.chunk_type {
                                // An ack is what releases the send buffer, and
                                // so what lifts back-pressure off the TUN reader.
                                ChunkType::Control => {
                                    match ControlMessage::decode(&chunk.payload) {
                                        Ok(ControlMessage::Ack { next_expected, ranges }) => {
                                            send_buffer.apply_ack(next_expected, &ranges);
                                        }
                                        Ok(other) => tracing::debug!(?other, "control message"),
                                        Err(e) => tracing::warn!(error = %e, "bad control message"),
                                    }
                                }
                                ChunkType::Data => {
                                    let sequence = chunk.header.sequence;
                                    match recv_buffer.accept(sequence, chunk.payload) {
                                        Ok(Received::Duplicate) => {}
                                        Ok(_) => {
                                            for packet in recv_buffer.drain_ready() {
                                                let _ = tun_device.write_packet(&packet).await;
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "receive buffer full");
                                            continue;
                                        }
                                    }

                                    unacked_chunks += 1;
                                    let due = unacked_chunks >= ACK_EVERY_N_CHUNKS
                                        || last_ack.elapsed() >= ACK_MAX_DELAY;
                                    if due {
                                        unacked_chunks = 0;
                                        last_ack = tokio::time::Instant::now();
                                        let ack = Chunk::new_control(recv_buffer.build_ack().encode());
                                        match session.encrypt_outgoing(&ack, true) {
                                            // Acks are not retained: a lost one
                                            // is superseded by the next.
                                            Ok(bytes) => {
                                                if let Err(e) = connection.send(&bytes).await {
                                                    tracing::warn!(error = %e, "ack send failed");
                                                    switch_or_give_up!(
                                                        SwitchReason::TransportError(e.to_string())
                                                    );
                                                }
                                            }
                                            Err(e) => tracing::warn!(error = %e, "ack encrypt failed"),
                                        }
                                    }
                                }
                                _ => {}
                            },
                            Err(e) => {
                                tracing::warn!(error = %e, "decrypt failed");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "recv failed — switching transport");
                        observe_signal!(Signal::SuspiciousReset);
                        switch_or_give_up!(SwitchReason::TransportError(e.to_string()));
                    }
                }
            }

            // Liveness (16.2.3). A transport can fail without erroring — the
            // socket stays open and nothing ever arrives — which is exactly
            // what blocking looks like. Silence is therefore treated as death.
            _ = liveness_tick.tick() => {
                if monitor.is_dead() {
                    tracing::warn!(silent_for = ?monitor.silent_for(), "link went silent");
                    // A healthy path going abruptly silent is the signature of
                    // interference, not of congestion (16.4.5).
                    observe_signal!(Signal::SuddenPathLoss);
                    switch_or_give_up!(SwitchReason::LinkSilent);
                } else if monitor.should_probe() {
                    let ping = ControlMessage::Ping {
                        timestamp: kanrin_protocol::handshake::current_timestamp(),
                    };
                    if let Ok(bytes) = session.encrypt_outgoing(&Chunk::new_control(ping.encode()), true) {
                        let _ = connection.send(&bytes).await;
                    }
                }
            }

            // A period with no adverse signal is itself evidence (16.4.4).
            // Relaxation needs a run of these plus time at the posture, so a
            // single quiet moment inside an active block cannot trigger it.
            _ = posture_tick.tick() => {
                observe_signal!(Signal::CleanPeriod);
            }

            // Periodic stats
            _ = stats_interval.tick() => {
                event_tx.send(KanrinEvent::StatsUpdate {
                    bytes_sent: session.bytes_sent,
                    bytes_received: session.bytes_received,
                    uptime_secs: session.age().as_secs(),
                    latency_ms: 0,
                }).ok();

                // NAT cleanup
                nat_table.cleanup();
            }

            // Shutdown signal
            _ = shutdown_rx.changed() => {
                tracing::info!("shutdown signal received");
                break;
            }
        }
    }

    // === Cleanup ===
    let _ = connection.close().await;
    if let Some(ref mut ks) = kill_switch {
        let _ = ks.deactivate();
        event_tx.send(KanrinEvent::KillSwitchChanged { active: false }).ok();
    }
    let _ = routing_manager.deactivate();

    tun_reader.abort();
    if let Ok(tun) = Arc::try_unwrap(tun_device) {
        let _ = tun.close();
    }

    Ok(())
}
