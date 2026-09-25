use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;

use kanrin_protocol::continuity::{Received, Replay};
use kanrin_protocol::handshake::{
    AuthStatus, ClientFinished, ClientHello, ServerFinished, ServerHandshake,
};
use kanrin_protocol::resume::{ResumeRequest, ResumeResponse, ResumeStatus};
use kanrin_protocol::session::SessionId;
use kanrin_protocol::wire::{Chunk, ChunkHeader, ChunkType, ControlMessage, HEADER_SIZE};

use kanrin_protocol::handshake::current_timestamp;

use crate::config::ServerConfig;
use crate::forwarder::PacketForwarder;
use crate::frontdoor::{Admission, Admitter, ResponseTimer};
use crate::http::{ParseError, RequestHead};
use crate::registry::{SessionEntry, SessionRegistry};

/// Acknowledge after this many data chunks. The client cannot release its send
/// buffer until it hears from us, so acking too rarely would throttle it; acking
/// every chunk would roughly double the frame count for no benefit.
const ACK_EVERY_N_CHUNKS: usize = 32;

/// Also acknowledge if this long has passed, so a slow flow does not sit below
/// the chunk threshold indefinitely.
///
/// Checked when a chunk arrives rather than on a timer: the read loop uses
/// `read_exact`, which is not cancel-safe, so racing it against an interval in
/// a `select!` would abandon partially-read frames.
const ACK_MAX_DELAY: Duration = Duration::from_millis(200);

/// Cap on a front-door request body, matching what a static origin accepts.
const MAX_REQUEST_BODY: usize = 1024 * 1024;

/// What became of the tunnel address the acceptor reserved for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// A new session took the address; it stays owned by the registry entry
    /// and is reclaimed only when that entry expires.
    AddressTaken,
    /// The connection attached to an existing session, so the reserved
    /// address was never used and goes straight back to the pool.
    AddressUnused,
}

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

    /// Serve one connection — the single code path of Phase 17.1.
    ///
    /// Every connection, without exception, is first served as HTTP by the
    /// same code in the same order with the same timing. Only *after* that
    /// response has been written is the request examined for a tunnel
    /// authenticator, and only then may the connection be upgraded.
    ///
    /// The ordering is the substance of the defence. Reality (**T3**) fell
    /// because authentication chose which stack answered, so the branches
    /// could be told apart without any key. Here authentication chooses
    /// nothing about the answer; it is a property discovered about a request
    /// that was going to be served identically either way.
    pub async fn run(
        mut self,
        forwarder: Arc<PacketForwarder>,
        registry: Arc<SessionRegistry>,
        admitter: Arc<Admitter>,
    ) -> anyhow::Result<ConnectionOutcome> {
        // 17.1.7 — started before any work, awaited just before the response,
        // so the floor absorbs the work instead of being added to it.
        let timer = ResponseTimer::start();

        let head = self.read_request_head().await?;
        let body = self.read_body(&head).await?;

        // 17.1.3/17.1.4/17.1.5 — one content path for everyone.
        let response = self.config.origin().respond(&head, &body).await;

        // 17.1.6 — decided here, but it changes nothing about `response`.
        let admission = admitter.admit(&head, current_timestamp());

        timer.wait().await;
        self.send_raw(&response).await?;

        if admission == Admission::Web {
            // An ordinary visitor. Keep serving requests for as long as they
            // want to make them, exactly as the origin would.
            return self.serve_web(admitter).await;
        }

        self.run_tunnel(forwarder, registry).await
    }

    /// The tunnel, entered only from an authenticated request.
    ///
    /// The first chunk decides which of two things this is. Its type is
    /// readable from the plaintext header, so the choice needs no key and no
    /// guessing between a `ClientHello` and a `ResumeRequest`:
    ///
    /// - `Handshake` — a new client. Full key exchange, new tunnel address,
    ///   new registry entry.
    /// - `Resume` — a transport switch. The client proves it owns a live
    ///   session and reattaches to it, keeping its address, sequence counters
    ///   and both continuity buffers.
    async fn run_tunnel(
        mut self,
        forwarder: Arc<PacketForwarder>,
        registry: Arc<SessionRegistry>,
    ) -> anyhow::Result<ConnectionOutcome> {
        let first = self.recv_frame().await?;
        if first.len() < HEADER_SIZE {
            anyhow::bail!("first frame is shorter than a chunk header");
        }
        let header = ChunkHeader::decode(&mut &first[..HEADER_SIZE])?;

        match header.chunk_type {
            ChunkType::Resume => {
                let entry = self.accept_resume(&first, &registry).await?;
                let peer_addr = self.peer_addr;
                Self::serve(self.stream, peer_addr, entry, forwarder).await;
                Ok(ConnectionOutcome::AddressUnused)
            }
            ChunkType::Handshake => {
                let entry = self.accept_new(first, &forwarder, &registry).await?;
                let Some(entry) = entry else {
                    // Authentication failed; the client was already told.
                    return Ok(ConnectionOutcome::AddressUnused);
                };
                let peer_addr = self.peer_addr;
                Self::serve(self.stream, peer_addr, entry, forwarder).await;
                Ok(ConnectionOutcome::AddressTaken)
            }
            other => anyhow::bail!("unexpected first chunk type: {:?}", other),
        }
    }

    /// Attach to an existing session (16.2.1/16.2.2).
    ///
    /// A request naming an unknown session, or carrying a proof that does not
    /// verify, simply drops the connection. Answering would turn the server
    /// into an oracle for which session ids are live; staying silent makes a
    /// failed resume indistinguishable from any other dead connection, and the
    /// client falls back to a full handshake anyway.
    async fn accept_resume(
        &mut self,
        first: &[u8],
        registry: &SessionRegistry,
    ) -> anyhow::Result<Arc<SessionEntry>> {
        let chunk = Chunk::decode_encrypted(first, &[0u8; 32], &[0u8; 12])
            .map_err(|e| anyhow::anyhow!("decode resume chunk: {}", e))?;
        let request = ResumeRequest::decode(&chunk.payload)
            .map_err(|e| anyhow::anyhow!("parse resume request: {}", e))?;

        let entry = registry
            .get(&request.session_id)
            .ok_or_else(|| anyhow::anyhow!("resume names an unknown session"))?;

        let status = request
            .verify(&entry.keys)
            .map_err(|e| anyhow::anyhow!("verify resume: {}", e))?;
        if status != ResumeStatus::Ok {
            anyhow::bail!("resume rejected: {:?}", status);
        }

        // The client told us how far it got, so everything below that can be
        // dropped and the rest replayed by `serve`.
        let released = entry
            .send_buffer
            .lock()
            .await
            .apply_ack(request.next_expected, &[]);

        // Our own position goes back, so the client can do the same.
        let next_expected = entry.recv_buffer.lock().await.next_expected();
        let response = ResumeResponse::new(ResumeStatus::Ok, next_expected, &request, &entry.keys)
            .map_err(|e| anyhow::anyhow!("sign resume response: {}", e))?;
        let encoded = Chunk::new_resume(response.encode())
            .encode_encrypted(&[0u8; 32], &[0u8; 12])
            .map_err(|e| anyhow::anyhow!("encode resume response: {}", e))?;
        self.send_frame(&encoded).await?;

        tracing::info!(
            peer = %self.peer_addr,
            tunnel_ip = %entry.assigned_ip,
            released,
            "session resumed on a new transport"
        );

        Ok(entry)
    }

    /// Full handshake for a client we have never seen.
    async fn accept_new(
        &mut self,
        client_hello_data: Vec<u8>,
        forwarder: &PacketForwarder,
        registry: &SessionRegistry,
    ) -> anyhow::Result<Option<Arc<SessionEntry>>> {
        tracing::info!(
            peer = %self.peer_addr,
            assigned_ip = %self.assigned_ip,
            "client session starting"
        );

        // === Step 1: Kanrin Handshake ===
        let mut server_hs = ServerHandshake::new();

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

        // Send ServerFinished.
        //
        // The token is `tunnel_ip(4) || session_id(16)`. The id has to reach
        // the client here: it is the handle the client presents when resuming
        // on a new transport, and there is no later opportunity to send it
        // that a switch could rely on.
        let session_id = SessionId::generate();
        let server_finished = ServerFinished {
            status: auth_status,
            session_token: if auth_status == AuthStatus::Ok {
                let mut token = self.assigned_ip.octets().to_vec();
                token.extend_from_slice(session_id.as_bytes());
                Some(token)
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
            return Ok(None);
        }

        tracing::info!(
            peer = %self.peer_addr,
            assigned_ip = %self.assigned_ip,
            "client authenticated — entering data mode"
        );

        // Subscribe to reply packets addressed to this client's tunnel IP.
        let reply_rx = forwarder.register_client(self.assigned_ip);

        Ok(Some(registry.insert(
            session_id,
            session_keys,
            self.assigned_ip,
            reply_rx,
        )))
    }

    /// Carry data for as long as this connection lives.
    ///
    /// All mutable state belongs to `entry`, not to the connection, which is
    /// what makes a switch invisible to the tunnelled traffic.
    async fn serve(
        stream: TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        entry: Arc<SessionEntry>,
        forwarder: Arc<PacketForwarder>,
    ) {
        // `read_exact` is not cancel-safe, so the read and write directions run
        // independently instead of racing inside a single `select!`.
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Acknowledgements are produced by the reader loop but have to leave
        // through the writer, which owns the write half. A channel keeps that
        // ownership intact; `recv` on both queues is cancel-safe, so the writer
        // can race them in a `select!`.
        let (ack_tx, mut ack_rx) = mpsc::unbounded_channel::<ControlMessage>();

        // 16.1.5 — anything the previous transport never got acknowledged for
        // goes out first, ahead of new traffic, so the client's byte stream
        // continues where it stopped. Empty for a fresh session.
        {
            let send_buffer = entry.send_buffer.lock().await;
            let mut replay = Replay::new();
            let mut replayed = 0usize;
            while let Some((sequence, data)) = replay.next_chunk(&send_buffer) {
                if write_frame(&mut writer, data).await.is_err() {
                    break;
                }
                replay.confirm_sent(sequence);
                replayed += 1;
            }
            if replayed > 0 {
                tracing::info!(peer = %peer_addr, replayed, "replayed unacknowledged chunks");
            }
        }

        // Internet -> client
        let writer_entry = entry.clone();
        let writer_task = tokio::spawn(async move {
            // Held for the lifetime of this connection. A later attachment
            // aborts this task, which releases the queue to its successor.
            let mut reply_rx = writer_entry.reply_rx.lock().await;

            loop {
                let chunk = tokio::select! {
                    packet = reply_rx.recv() => match packet {
                        Some(packet) => Chunk::new_data(packet),
                        None => break,
                    },
                    ack = ack_rx.recv() => match ack {
                        Some(ack) => Chunk::new_control(ack.encode()),
                        None => break,
                    },
                };

                let is_data = chunk.header.chunk_type == ChunkType::Data;
                let encrypted = {
                    let mut s = writer_entry.session.lock().await;
                    let sequence = s.send_nonce_value();
                    s.encrypt_outgoing(&chunk, false).map(|bytes| (sequence, bytes))
                };

                match encrypted {
                    Ok((sequence, bytes)) => {
                        // Only data is retained: a lost ack is superseded by
                        // the next one, so replaying it would be pure cost.
                        if is_data {
                            let mut send_buffer = writer_entry.send_buffer.lock().await;
                            if let Err(e) = send_buffer.push(sequence, bytes.clone()) {
                                tracing::warn!(error = %e, "server send buffer full");
                            }
                        }
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

        // Evict whatever connection held this session before us. Doing it here
        // rather than at attach time means the replay above has already been
        // written, so the client never sees a gap between the two transports.
        entry.attach(vec![writer_task.abort_handle()]);

        // Client -> internet.
        //
        // Chunks go through the continuity layer rather than straight to the
        // forwarder: it restores the original order if a transport switch
        // delivered them out of order, and silently drops the duplicates that
        // a replay (16.1.5) is expected to produce.
        let mut unacked_chunks = 0usize;
        let mut last_ack = Instant::now();

        loop {
            let data = match read_frame(&mut reader).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(peer = %peer_addr, error = %e, "client disconnected");
                    break;
                }
            };
            entry.touch();

            let chunk = {
                let mut s = entry.session.lock().await;
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
                    let sequence = chunk.header.sequence;
                    let ready = {
                        let mut recv_buffer = entry.recv_buffer.lock().await;
                        match recv_buffer.accept(sequence, chunk.payload) {
                            Ok(Received::Duplicate) => continue,
                            Ok(_) => recv_buffer.drain_ready(),
                            Err(e) => {
                                // The peer is running far ahead of a gap it
                                // never filled. Dropping the chunk keeps memory
                                // bounded; it stays unacknowledged, so it will
                                // be replayed.
                                tracing::warn!(peer = %peer_addr, error = %e, "receive buffer full");
                                continue;
                            }
                        }
                    };
                    for packet in ready {
                        forwarder.send_to_internet(&packet).await;
                    }

                    unacked_chunks += 1;
                    if unacked_chunks >= ACK_EVERY_N_CHUNKS || last_ack.elapsed() >= ACK_MAX_DELAY {
                        unacked_chunks = 0;
                        last_ack = Instant::now();
                        let ack = entry.recv_buffer.lock().await.build_ack();
                        if ack_tx.send(ack).is_err() {
                            break;
                        }
                    }
                }
                ChunkType::Control => match ControlMessage::decode(&chunk.payload) {
                    // The client's ack is what releases our retained chunks.
                    Ok(ControlMessage::Ack { next_expected, ranges }) => {
                        entry.send_buffer.lock().await.apply_ack(next_expected, &ranges);
                    }
                    // The client's liveness probe (16.2.3). Answering is what
                    // distinguishes a quiet link from a blocked one, so it
                    // must never be dropped on the floor.
                    Ok(ControlMessage::Ping { timestamp }) => {
                        if ack_tx.send(ControlMessage::Pong { timestamp }).is_err() {
                            break;
                        }
                    }
                    Ok(other) => tracing::debug!(?other, "control message"),
                    Err(e) => tracing::warn!(error = %e, "bad control message"),
                },
                _ => {}
            }
        }

        // The session deliberately outlives the connection: the client may be
        // switching transports and about to reattach. Its address is released
        // only when the registry reaps the entry.
        writer_task.abort();
        entry.touch();

        let s = entry.session.lock().await;
        tracing::info!(
            peer = %peer_addr,
            session = ?entry.id,
            bytes_rx = s.bytes_received,
            bytes_tx = s.bytes_sent,
            "connection ended"
        );
    }

    /// Read one HTTP request head, and nothing past it.
    ///
    /// Reads byte by byte to the blank line rather than filling a buffer:
    /// anything read beyond the head would belong to the body or to the first
    /// tunnel frame, and the two paths must not differ in how much they
    /// consume.
    async fn read_request_head(&mut self) -> anyhow::Result<RequestHead> {
        let mut buf = Vec::with_capacity(1024);
        let mut byte = [0u8; 1];

        loop {
            self.stream.read_exact(&mut byte).await?;
            buf.push(byte[0]);

            match RequestHead::parse(&buf) {
                Ok(head) => return Ok(head),
                Err(ParseError::Incomplete) => continue,
                // Malformed and oversized both end the connection, as any
                // server does — and identically to each other, so neither
                // reveals which rule was hit.
                Err(_) => anyhow::bail!("bad request"),
            }
        }
    }

    async fn read_body(&mut self, head: &RequestHead) -> anyhow::Result<Vec<u8>> {
        let length = head.content_length().unwrap_or(0);
        if length == 0 {
            return Ok(Vec::new());
        }
        if length > MAX_REQUEST_BODY {
            anyhow::bail!("bad request");
        }
        let mut body = vec![0u8; length];
        self.stream.read_exact(&mut body).await?;
        Ok(body)
    }

    async fn send_raw(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Keep-alive loop for an ordinary visitor (17.1.4).
    ///
    /// A front door that closed after one response, while the origin it
    /// claims to be keeps connections alive, would be distinguishable without
    /// reading a byte of content. So this is a real keep-alive loop, and a
    /// later request on the same connection can still carry an authenticator
    /// — a browser that gets a page and then upgrades is ordinary behaviour.
    async fn serve_web(
        mut self,
        admitter: Arc<Admitter>,
    ) -> anyhow::Result<ConnectionOutcome> {
        loop {
            let timer = ResponseTimer::start();

            let head = match self.read_request_head().await {
                Ok(h) => h,
                // The visitor went away. Normal, and not worth a log line at
                // any level an operator would notice.
                Err(_) => return Ok(ConnectionOutcome::AddressUnused),
            };
            let keep_alive = head.wants_keep_alive();
            let body = self.read_body(&head).await.unwrap_or_default();

            let response = self.config.origin().respond(&head, &body).await;
            let admission = admitter.admit(&head, current_timestamp());

            timer.wait().await;
            self.send_raw(&response).await?;

            if admission == Admission::Tunnel {
                break;
            }
            if !keep_alive {
                return Ok(ConnectionOutcome::AddressUnused);
            }
        }

        // Reached only via an authenticator, so this is unreachable for
        // anyone probing the port.
        anyhow::bail!("tunnel upgrade on a keep-alive connection is not yet wired")
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
