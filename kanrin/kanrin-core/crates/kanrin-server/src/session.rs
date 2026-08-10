use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use kanrin_protocol::handshake::{
    AuthStatus, ClientFinished, ClientHello, ServerFinished, ServerHandshake,
};
use kanrin_protocol::session::{Session, SessionId};
use kanrin_protocol::wire::{Chunk, ChunkType};

use crate::config::ServerConfig;
use crate::forwarder::PacketForwarder;

/// Manages a single client connection from TLS accept to data forwarding.
pub struct ClientSession {
    stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    config: Arc<ServerConfig>,
    assigned_ip: Ipv4Addr,
}

/// Global IP allocator — hands out 10.10.0.x addresses to clients.
///
/// Addresses are returned to the pool when a session ends, otherwise every
/// reconnect would burn one and the /24 would be exhausted after 252 sessions.
pub struct IpAllocator {
    base: u32,
    state: parking_lot::Mutex<AllocatorState>,
}

struct AllocatorState {
    /// Lowest host octet never handed out yet. `.0` = network, `.1` = server.
    next: u32,
    /// Host octets freed by ended sessions, reused before `next` advances.
    freed: Vec<u32>,
}

impl IpAllocator {
    pub fn new(base_ip: Ipv4Addr) -> Self {
        Self {
            base: u32::from(base_ip) & 0xFFFFFF00,
            state: parking_lot::Mutex::new(AllocatorState {
                next: 2,
                freed: Vec::new(),
            }),
        }
    }

    pub fn allocate(&self) -> Option<Ipv4Addr> {
        let mut state = self.state.lock();

        let host = match state.freed.pop() {
            Some(h) => h,
            None => {
                if state.next >= 254 {
                    return None; // /24 exhausted
                }
                let h = state.next;
                state.next += 1;
                h
            }
        };

        Some(Ipv4Addr::from(self.base | host))
    }

    /// Return an address to the pool once its session has ended.
    pub fn release(&self, ip: Ipv4Addr) {
        let host = u32::from(ip) & 0xFF;
        if host < 2 || host >= 254 {
            return;
        }

        let mut state = self.state.lock();
        if !state.freed.contains(&host) {
            state.freed.push(host);
        }
    }
}

impl ClientSession {
    pub fn new(
        stream: TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        config: Arc<ServerConfig>,
        assigned_ip: Ipv4Addr,
    ) -> Self {
        Self {
            stream,
            peer_addr,
            config,
            assigned_ip,
        }
    }

    /// Run the full client lifecycle: handshake -> auth -> data forwarding.
    pub async fn run(mut self, forwarder: Arc<PacketForwarder>) -> anyhow::Result<()> {
        tracing::info!(
            peer = %self.peer_addr,
            assigned_ip = %self.assigned_ip,
            "client session starting"
        );

        // === Step 1: Kanrin Handshake ===
        let mut server_hs = ServerHandshake::new();

        // Receive ClientHello
        let client_hello_data = self.recv_frame().await?;
        let temp_key = [0u8; 32];
        let temp_nonce = [0u8; 12];
        let client_hello_chunk = Chunk::decode_encrypted(&client_hello_data, &temp_key, &temp_nonce)
            .map_err(|e| anyhow::anyhow!("decode client hello: {}", e))?;
        let client_hello = ClientHello::decode(&client_hello_chunk.payload)
            .map_err(|e| anyhow::anyhow!("parse client hello: {}", e))?;

        tracing::debug!(
            peer = %self.peer_addr,
            version = client_hello.protocol_version,
            "received ClientHello"
        );

        // Process ClientHello and generate ServerHello
        let (server_hello, session_keys) = server_hs
            .process_client_hello(&client_hello)
            .map_err(|e| anyhow::anyhow!("process client hello: {}", e))?;

        // Send ServerHello
        let hello_chunk = Chunk::new_handshake(server_hello.encode());
        let encoded = hello_chunk
            .encode_encrypted(&temp_key, &temp_nonce)
            .map_err(|e| anyhow::anyhow!("encode server hello: {}", e))?;
        self.send_frame(&encoded).await?;

        tracing::debug!(peer = %self.peer_addr, "sent ServerHello");

        // === Step 2: Receive ClientFinished (auth) ===
        let auth_data = self.recv_frame().await?;
        let auth_chunk = Chunk::decode_encrypted(&auth_data, &session_keys.client_write_key, &[0u8; 12])
            .map_err(|e| anyhow::anyhow!("decode auth: {}", e))?;
        let client_finished = ClientFinished::decode(&auth_chunk.payload)
            .map_err(|e| anyhow::anyhow!("parse auth: {}", e))?;

        let auth_status = server_hs
            .verify_auth(&client_finished, &session_keys, &self.config.password)
            .map_err(|e| anyhow::anyhow!("verify auth: {}", e))?;

        // Send ServerFinished
        let server_finished = ServerFinished {
            status: auth_status,
            session_token: if auth_status == AuthStatus::Ok {
                Some(self.assigned_ip.octets().to_vec())
            } else {
                None
            },
        };

        let finished_chunk = Chunk::new_handshake(server_finished.encode());
        let encoded = finished_chunk
            .encode_encrypted(&session_keys.server_write_key, &[0u8; 12])
            .map_err(|e| anyhow::anyhow!("encode server finished: {}", e))?;
        self.send_frame(&encoded).await?;

        if auth_status != AuthStatus::Ok {
            tracing::warn!(
                peer = %self.peer_addr,
                status = ?auth_status,
                "authentication failed"
            );
            return Ok(());
        }

        tracing::info!(
            peer = %self.peer_addr,
            assigned_ip = %self.assigned_ip,
            "client authenticated — entering data mode"
        );

        // === Step 3: Data forwarding ===
        let peer_addr = self.peer_addr;
        let assigned_ip = self.assigned_ip;

        let session = Arc::new(tokio::sync::Mutex::new(Session::new(
            SessionId::generate(),
            session_keys,
        )));

        // Subscribe to reply packets addressed to this client's tunnel IP.
        let mut reply_rx = forwarder.register_client(assigned_ip);

        // `read_exact` is not cancel-safe, so the read and write directions run
        // independently instead of racing inside a single `select!`.
        let (mut reader, mut writer) = tokio::io::split(self.stream);

        // Internet -> client
        let writer_session = session.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(packet) = reply_rx.recv().await {
                let chunk = Chunk::new_data(packet);
                let encrypted = {
                    let mut s = writer_session.lock().await;
                    s.encrypt_outgoing(&chunk, false)
                };

                match encrypted {
                    Ok(bytes) => {
                        if write_frame(&mut writer, &bytes).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "encrypt response failed");
                        break;
                    }
                }
            }
        });

        // Client -> internet
        loop {
            let data = match read_frame(&mut reader).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(peer = %peer_addr, error = %e, "client disconnected");
                    break;
                }
            };

            let chunk = {
                let mut s = session.lock().await;
                s.decrypt_incoming(&data, false)
            };

            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(peer = %peer_addr, error = %e, "decrypt failed");
                    break;
                }
            };

            match chunk.header.chunk_type {
                ChunkType::Data => {
                    forwarder.send_to_internet(&chunk.payload).await;
                }
                ChunkType::Control => {
                    tracing::debug!("received control chunk");
                }
                _ => {}
            }
        }

        forwarder.unregister_client(assigned_ip);
        writer_task.abort();

        let s = session.lock().await;
        tracing::info!(
            peer = %peer_addr,
            bytes_rx = s.bytes_received,
            bytes_tx = s.bytes_sent,
            "client session ended"
        );

        Ok(())
    }

    /// Read a length-prefixed frame from the TLS stream.
    async fn recv_frame(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let length = u32::from_be_bytes(len_buf) as usize;

        if length > 1024 * 1024 {
            anyhow::bail!("frame too large: {} bytes", length);
        }

        let mut buf = vec![0u8; length];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Write a length-prefixed frame to the TLS stream.
    async fn send_frame(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let len_bytes = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// Read a length-prefixed frame from a stream half.
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let length = u32::from_be_bytes(len_buf) as usize;

    if length > 1024 * 1024 {
        anyhow::bail!("frame too large: {} bytes", length);
    }

    let mut buf = vec![0u8; length];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed frame to a stream half.
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> anyhow::Result<()> {
    let len_bytes = (data.len() as u32).to_be_bytes();
    writer.write_all(&len_bytes).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}
