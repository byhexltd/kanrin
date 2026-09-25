//! Phase 16.2.7 / 16.2.8 — a transfer survives the transport under it.
//!
//! 16.1.8 tested the client→server direction. The case users actually notice
//! is the other one: a download in flight when the transport dies. That
//! direction has an extra hazard — the server keeps producing while the link
//! is gone, because a download is driven by the origin, not by the client — so
//! the retention and replay have to hold under a producer that never pauses.
//!
//! The model here is deliberately end-to-end over the real primitives: a
//! server-side `SendBuffer` and `Session`, a client-side `ReceiveBuffer` and
//! `Session`, real `Ack` encoding, and a real resumption handshake between the
//! two halves of every switch.

use kanrin_protocol::continuity::{ReceiveBuffer, Received, Replay, SendBuffer};
use kanrin_protocol::crypto::{self, SessionKeys};
use kanrin_protocol::resume::{ResumeRequest, ResumeResponse, ResumeStatus};
use kanrin_protocol::session::{Session, SessionId};
use kanrin_protocol::wire::{Chunk, ControlMessage};

/// 1400-byte bodies, the usual MTU-sized payload of a bulk transfer.
fn block(i: usize) -> Vec<u8> {
    let mut b = format!("block-{i:06}:").into_bytes();
    b.resize(1400, (i % 251) as u8);
    b
}

fn shared_keys() -> SessionKeys {
    crypto::derive_session_keys(&crypto::random_bytes::<32>(), b"download-test").unwrap()
}

/// A download in progress across an unreliable transport.
struct Transfer {
    keys: SessionKeys,
    session_id: SessionId,
    /// Server side.
    server: Session,
    send_buffer: SendBuffer,
    /// Client side.
    client: Session,
    recv_buffer: ReceiveBuffer,
    /// Frames currently on the wire.
    wire: Vec<Vec<u8>>,
    link_up: bool,
    /// Blocks handed to the application, in the order it saw them.
    received: Vec<Vec<u8>>,
    /// Resends the client recognised and discarded.
    duplicates: usize,
    switches: usize,
}

impl Transfer {
    fn new() -> Self {
        let keys = shared_keys();
        let session_id = SessionId::generate();
        Self {
            server: Session::new(session_id, keys.clone()),
            client: Session::new(session_id, keys.clone()),
            keys,
            session_id,
            send_buffer: SendBuffer::with_default_capacity(),
            recv_buffer: ReceiveBuffer::with_default_capacity(),
            wire: Vec::new(),
            link_up: true,
            received: Vec::new(),
            duplicates: 0,
            switches: 0,
        }
    }

    /// The origin produces another block. Retained whether or not the link is
    /// up — a download does not pause because the tunnel did.
    fn serve_block(&mut self, i: usize) {
        let sequence = self.server.send_nonce_value();
        let encoded = self
            .server
            .encrypt_outgoing(&Chunk::new_data(block(i)), false)
            .expect("encrypt");
        self.send_buffer.push(sequence, encoded.clone()).expect("retain");
        if self.link_up {
            self.wire.push(encoded);
        }
    }

    /// The client drains whatever actually arrived.
    fn client_reads(&mut self) {
        for frame in std::mem::take(&mut self.wire) {
            let chunk = self.client.decrypt_incoming(&frame, true).expect("decrypt");
            let accepted = self
                .recv_buffer
                .accept(chunk.header.sequence, chunk.payload)
                .expect("accept");
            match accepted {
                Received::Duplicate => self.duplicates += 1,
                _ => self.received.extend(self.recv_buffer.drain_ready()),
            }
        }
    }

    /// An ack gets back to the server (the reverse path is not under test).
    fn client_acks(&mut self) {
        let ControlMessage::Ack { next_expected, ranges } = self.recv_buffer.build_ack() else {
            panic!("expected Ack");
        };
        let encoded = ControlMessage::Ack { next_expected, ranges }.encode();
        let ControlMessage::Ack { next_expected, ranges } =
            ControlMessage::decode(&encoded).expect("ack must be wire-legal")
        else {
            panic!("expected Ack");
        };
        self.send_buffer.apply_ack(next_expected, &ranges);
    }

    fn kill_link(&mut self) {
        self.link_up = false;
        self.wire.clear();
    }

    /// A full switch: resume on a new transport, then replay.
    fn switch(&mut self) {
        self.link_up = true;
        self.switches += 1;

        // Client proves ownership and reports where it got to.
        let request =
            ResumeRequest::new(self.session_id, self.recv_buffer.next_expected(), &self.keys)
                .unwrap();
        let request = ResumeRequest::decode(&request.encode()).unwrap();
        assert_eq!(request.verify(&self.keys).unwrap(), ResumeStatus::Ok);

        // Server releases what landed and answers.
        self.send_buffer.apply_ack(request.next_expected, &[]);
        let response =
            ResumeResponse::new(ResumeStatus::Ok, 0, &request, &self.keys).unwrap();
        let response = ResumeResponse::decode(&response.encode()).unwrap();
        assert!(
            response.verify(&request, &self.keys).unwrap(),
            "client must reject a response it cannot verify"
        );

        // Server replays the rest onto the new transport.
        let mut replay = Replay::new();
        while let Some((sequence, data)) = replay.next_chunk(&self.send_buffer) {
            self.wire.push(data.to_vec());
            replay.confirm_sent(sequence);
        }
    }

    fn assert_complete(&self, blocks: usize) {
        let expected: Vec<Vec<u8>> = (0..blocks).map(block).collect();
        assert_eq!(
            self.received.len(),
            blocks,
            "download stalled at {} of {blocks} blocks",
            self.received.len()
        );
        assert_eq!(self.received, expected, "download was corrupted");
        assert_eq!(self.recv_buffer.next_expected(), blocks as u64);
    }
}

#[test]
fn download_interrupted_mid_transfer_still_completes() {
    const BLOCKS: usize = 500;
    let mut t = Transfer::new();

    for i in 0..BLOCKS {
        t.serve_block(i);

        // The transport dies a third of the way in and stays dead for a
        // while, so the origin keeps producing into a buffer with no link.
        if i == BLOCKS / 3 {
            t.kill_link();
        }
        if i == BLOCKS / 3 + 50 {
            t.client_reads();
            t.switch();
        }

        if i % 25 == 0 {
            t.client_reads();
            t.client_acks();
        }
    }

    t.client_reads();
    t.assert_complete(BLOCKS);
    assert_eq!(t.switches, 1);
}

#[test]
fn repeated_forced_switches_do_not_corrupt_the_stream() {
    const BLOCKS: usize = 600;
    let mut t = Transfer::new();

    for i in 0..BLOCKS {
        t.serve_block(i);

        // Force a switch every 30 blocks, never letting the link settle.
        if i % 30 == 29 {
            t.kill_link();
            t.client_reads();
            t.switch();
            t.client_reads();
        } else if i % 11 == 0 {
            t.client_reads();
            t.client_acks();
        }
    }

    t.client_reads();
    t.switch();
    t.client_reads();

    t.assert_complete(BLOCKS);
    assert!(t.switches >= 20, "expected many switches, saw {}", t.switches);
}

#[test]
fn the_resumption_position_alone_keeps_replay_precise() {
    // The client never sends a standalone ack here, so the only thing that
    // ever releases the server's buffer is the position carried by the
    // resumption handshake. That position is exact, so the replay should
    // resend only what was genuinely lost — de-duplication is the safety net,
    // not the mechanism.
    const BLOCKS: usize = 120;
    let mut t = Transfer::new();

    for i in 0..BLOCKS {
        t.serve_block(i);
        if i % 40 == 39 {
            t.kill_link();
            t.client_reads();
            t.switch();
            t.client_reads();
        }
    }

    t.client_reads();
    t.switch();
    t.client_reads();

    t.assert_complete(BLOCKS);
    assert_eq!(
        t.duplicates, 0,
        "an exact resumption position should make resends unnecessary"
    );
}

#[test]
fn a_stale_resumption_position_resends_but_never_double_delivers() {
    // The other half of that story: if the client switches before draining
    // what already arrived, the position it reports is behind reality and the
    // server resends blocks the client is about to read anyway. Those must be
    // absorbed, not delivered twice.
    const BLOCKS: usize = 60;
    let mut t = Transfer::new();

    for i in 0..BLOCKS {
        t.serve_block(i);
    }

    // Half the frames are already on the wire and unread when the client
    // switches, so its reported position is stale by that much.
    let inflight = std::mem::take(&mut t.wire);
    t.wire = inflight[..BLOCKS / 2].to_vec();

    t.switch();
    t.client_reads();

    t.assert_complete(BLOCKS);
    assert!(
        t.duplicates > 0,
        "a stale position must have caused resends, which is the case worth proving"
    );
}

#[test]
fn a_switch_during_a_gap_does_not_deliver_out_of_order() {
    // The client is missing a block in the middle when the transport dies.
    // The replay must restore order, not just completeness.
    const BLOCKS: usize = 40;
    let mut t = Transfer::new();

    for i in 0..BLOCKS {
        t.serve_block(i);
    }

    // Deliver everything except block 10, out of order.
    const GAP: usize = 10;
    let mut frames = std::mem::take(&mut t.wire);
    frames.remove(GAP);
    frames.reverse();
    t.wire = frames;
    t.client_reads();

    // The contiguous prefix below the gap is deliverable; everything above it
    // must be held, however much of it arrived.
    assert_eq!(t.received.len(), GAP, "only the prefix below the gap may be delivered");
    assert_eq!(t.recv_buffer.next_expected(), GAP as u64);
    assert_eq!(t.recv_buffer.pending_len(), BLOCKS - GAP - 1);

    t.kill_link();
    t.switch();
    t.client_reads();

    t.assert_complete(BLOCKS);
}
