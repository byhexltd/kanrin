use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::{mpsc, watch};

use kanrin_engine::bootstrap::{BootstrapEngine, HardcodedBootstrap};
use kanrin_engine::detection::NetworkDetector;
use kanrin_engine::prober::Prober;
use kanrin_engine::scoreboard::{ScoreBoard, ScoreWeights};
use kanrin_engine::switcher::Switcher;
use kanrin_protocol::handshake::{AuthStatus, ClientHandshake, ServerFinished, ServerHello};
use kanrin_protocol::session::{Session, SessionId};
use kanrin_protocol::wire::Chunk;
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

use crate::config::KanrinConfig;
use crate::events::KanrinEvent;
use crate::{ClientError, ClientState};

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
    let assigned_ip = server_finished
        .session_token
        .as_deref()
        .and_then(|token| <[u8; 4]>::try_from(token).ok())
        .map(std::net::Ipv4Addr::from);

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

    // Create session
    let mut session = Session::new(SessionId::generate(), session_keys);

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

    // TUN reads happen in a dedicated task. Awaiting them directly in the
    // `select!` below would abandon an in-flight blocking read whenever another
    // branch wins, silently dropping that packet. Channel receives are
    // cancel-safe, so the loop can poll them freely.
    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader_tun = tun_device.clone();
    let tun_reader = tokio::spawn(async move {
        loop {
            match reader_tun.read_packet().await {
                Ok(raw) => {
                    if tun_tx.send(raw).is_err() {
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
            // Read from TUN (outgoing traffic)
            packet = tun_rx.recv() => {
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
                    match session.encrypt_outgoing(&chunk, true) {
                        Ok(encrypted) => {
                            if let Err(e) = connection.send(&encrypted).await {
                                tracing::warn!(error = %e, "send failed");
                                break;
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
                        match session.decrypt_incoming(&encrypted, true) {
                            Ok(chunk) => {
                                // Write decrypted packet back to TUN
                                let _ = tun_device.write_packet(&chunk.payload).await;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "decrypt failed");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "recv failed — connection lost");
                        break;
                    }
                }
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
