//! Phase 16.1.8 — the transport dies mid-transfer, the byte stream does not.
//!
//! These exercise 16.1.1 through 16.1.7 together, because that is the only
//! level at which the property of interest is visible: each piece can be
//! correct on its own while the stream still breaks at the seams.
//!
//! The property under test is what keeps the *inner* TCP connections alive. A
//! tunnelled TCP stack resets when the byte stream underneath it loses a
//! segment, reorders one, or delivers one twice. So every test here asserts the
//! same thing about the application-visible stream: **exactly the payloads
//! sent, exactly once each, in the order they were sent** — regardless of how
//! violently the transport beneath it was interrupted.

use kanrin_protocol::continuity::{ReceiveBuffer, Received, Replay, SendBuffer};
use kanrin_protocol::crypto::{self, SessionKeys};
use kanrin_protocol::resume::{ResumeRequest, ResumeStatus};
use kanrin_protocol::session::{Session, SessionId};
use kanrin_protocol::wire::{Chunk, ControlMessage};

fn shared_keys() -> SessionKeys {
    let secret = crypto::random_bytes::<32>();
    crypto::derive_session_keys(&secret, b"kanrin-continuity-integration").unwrap()
}

/// Payloads of varying length, so a silent off-by-one in framing or ordering
/// cannot hide behind uniform chunks.
fn payload(i: usize) -> Vec<u8> {
    let mut p = format!("packet-{i:05}:").into_bytes();
    p.extend(std::iter::repeat_n(b'x', i % 97));
    p
}

/// One direction of a link that can be cut.
///
/// Cutting discards whatever has been handed over but not yet collected — the
/// same way bytes sitting in a socket buffer vanish when the connection dies.
#[derive(Default)]
struct Link {
    down: bool,
    inflight: Vec<Vec<u8>>,
}

impl Link {
    fn send(&mut self, bytes: Vec<u8>) {
        if !self.down {
            self.inflight.push(bytes);
        }
    }

    fn drain(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.inflight)
    }

    fn cut(&mut self) {
        self.down = true;
        self.inflight.clear();
    }

    fn restore(&mut self) {
        self.down = false;
    }
}

struct Sender {
    session: Session,
    buffer: SendBuffer,
}

impl Sender {
    fn new(keys: SessionKeys) -> Self {
        Self {
            session: Session::new(SessionId::generate(), keys),
            buffer: SendBuffer::with_default_capacity(),
        }
    }

    fn send(&mut self, payload: Vec<u8>, link: &mut Link) {
        let sequence = self.session.send_nonce_value();
        let encoded = self
            .session
            .encrypt_outgoing(&Chunk::new_data(payload), true)
            .expect("encrypt");
        self.buffer.push(sequence, encoded.clone()).expect("buffer");
        link.send(encoded);
    }
}

struct Receiver {
    session: Session,
    buffer: ReceiveBuffer,
    delivered: Vec<Vec<u8>>,
    duplicates: usize,
}

impl Receiver {
    fn new(keys: SessionKeys) -> Self {
        Self {
            session: Session::new(SessionId::generate(), keys),
            buffer: ReceiveBuffer::with_default_capacity(),
            delivered: Vec::new(),
            duplicates: 0,
        }
    }

    fn ingest(&mut self, link: &mut Link) {
        for frame in link.drain() {
            let chunk = self.session.decrypt_incoming(&frame, false).expect("decrypt");
            match self
                .buffer
                .accept(chunk.header.sequence, chunk.payload)
                .expect("accept")
            {
                Received::Duplicate => self.duplicates += 1,
                _ => self.delivered.extend(self.buffer.drain_ready()),
            }
        }
    }
}

/// Bring up a replacement transport: resume the session, tell the sender where
/// the receiver got to, and replay whatever is still outstanding.
fn switch_transport(tx: &mut Sender, rx: &Receiver, keys: &SessionKeys, link: &mut Link) {
    link.restore();

    // 16.1.6 — the client proves it owns the session and reports its position.
    let request = ResumeRequest::new(rx.session.id, rx.buffer.next_expected(), keys).unwrap();
    let request = ResumeRequest::decode(&request.encode()).unwrap();
    assert_eq!(request.verify(keys).unwrap(), ResumeStatus::Ok);

    // 16.1.3/16.1.4 — release what landed, including anything past the gap.
    let ControlMessage::Ack { ranges, .. } = rx.buffer.build_ack() else {
        panic!("expected Ack");
    };
    tx.buffer.apply_ack(request.next_expected, &ranges);

    // 16.1.5 — resend the rest, in order.
    let mut replay = Replay::new();
    while let Some((sequence, data)) = replay.next_chunk(&tx.buffer) {
        link.send(data.to_vec());
        replay.confirm_sent(sequence);
    }
}

/// The receiver acknowledges; the sender releases. Modelled as a direct call
/// because the ack travels on the reverse link, which these tests do not cut.
fn exchange_ack(tx: &mut Sender, rx: &Receiver) {
    let ControlMessage::Ack { next_expected, ranges } = rx.buffer.build_ack() else {
        panic!("expected Ack");
    };
    tx.buffer.apply_ack(next_expected, &ranges);
}

fn assert_stream_intact(rx: &Receiver, total: usize) {
    let expected: Vec<Vec<u8>> = (0..total).map(payload).collect();
    assert_eq!(
        rx.delivered.len(),
        total,
        "delivered {} of {total} payloads — a gap or a double delivery would reset the inner TCP",
        rx.delivered.len()
    );
    assert_eq!(rx.delivered, expected, "byte stream was reordered or corrupted");
    assert_eq!(rx.buffer.next_expected(), total as u64);
    assert_eq!(rx.buffer.pending_len(), 0, "chunks left stranded above a gap");
}

#[test]
fn transport_dropped_mid_transfer_keeps_the_byte_stream_intact() {
    const TOTAL: usize = 200;
    const CUT_AT: usize = 60;

    let keys = shared_keys();
    let mut tx = Sender::new(keys.clone());
    let mut rx = Receiver::new(keys.clone());
    let mut link = Link::default();

    for i in 0..CUT_AT {
        tx.send(payload(i), &mut link);
    }
    rx.ingest(&mut link);
    exchange_ack(&mut tx, &rx);

    // The transport dies. The next batch is written into a black hole — the
    // sender has no way to know yet, which is exactly the real failure mode.
    link.cut();
    for i in CUT_AT..CUT_AT + 40 {
        tx.send(payload(i), &mut link);
    }
    rx.ingest(&mut link);
    assert_eq!(rx.delivered.len(), CUT_AT, "lost chunks must not be delivered");

    switch_transport(&mut tx, &rx, &keys, &mut link);

    for i in CUT_AT + 40..TOTAL {
        tx.send(payload(i), &mut link);
    }
    rx.ingest(&mut link);

    assert_stream_intact(&rx, TOTAL);
}

#[test]
fn repeated_transport_failures_never_corrupt_the_stream() {
    const TOTAL: usize = 300;

    let keys = shared_keys();
    let mut tx = Sender::new(keys.clone());
    let mut rx = Receiver::new(keys.clone());
    let mut link = Link::default();

    // Cut the link every 40 packets, without ever letting it settle.
    for i in 0..TOTAL {
        tx.send(payload(i), &mut link);

        if i % 40 == 39 {
            link.cut();
            rx.ingest(&mut link);
            switch_transport(&mut tx, &rx, &keys, &mut link);
            rx.ingest(&mut link);
        } else if i % 7 == 0 {
            rx.ingest(&mut link);
            exchange_ack(&mut tx, &rx);
        }
    }

    rx.ingest(&mut link);
    switch_transport(&mut tx, &rx, &keys, &mut link);
    rx.ingest(&mut link);

    assert_stream_intact(&rx, TOTAL);
}

#[test]
fn a_lost_ack_causes_resends_that_are_absorbed_as_duplicates() {
    // The dangerous case: the data arrived but the ack did not, so the sender
    // replays chunks the receiver already handed to the application. Delivering
    // them twice would corrupt the inner stream just as badly as losing them.
    const TOTAL: usize = 50;

    let keys = shared_keys();
    let mut tx = Sender::new(keys.clone());
    let mut rx = Receiver::new(keys.clone());
    let mut link = Link::default();

    for i in 0..TOTAL {
        tx.send(payload(i), &mut link);
    }
    rx.ingest(&mut link);
    assert_eq!(rx.delivered.len(), TOTAL);

    // No ack reaches the sender before the switch, so its buffer still holds
    // everything and the replay resends the lot.
    link.cut();
    link.restore();
    let mut replay = Replay::new();
    while let Some((sequence, data)) = replay.next_chunk(&tx.buffer) {
        link.send(data.to_vec());
        replay.confirm_sent(sequence);
    }
    rx.ingest(&mut link);

    assert_eq!(rx.duplicates, TOTAL, "every resend should be recognised");
    assert_stream_intact(&rx, TOTAL);
}

#[test]
fn chunks_reordered_across_two_transports_are_delivered_in_order() {
    // During a make-before-break switch (16.2.4) both transports are briefly
    // live, so chunks can arrive interleaved. Order must be restored from the
    // sequence, not from arrival.
    const TOTAL: usize = 30;

    let keys = shared_keys();
    let mut tx = Sender::new(keys.clone());
    let mut rx = Receiver::new(keys.clone());
    let mut link = Link::default();

    for i in 0..TOTAL {
        tx.send(payload(i), &mut link);
    }

    // Deliver the second half first, then the first.
    let frames = link.drain();
    let (head, tail) = frames.split_at(TOTAL / 2);
    for frame in tail.iter().chain(head.iter()) {
        link.send(frame.clone());
    }
    rx.ingest(&mut link);

    assert_eq!(rx.duplicates, 0);
    assert_stream_intact(&rx, TOTAL);
}
