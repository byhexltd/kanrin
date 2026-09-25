//! Phase 16.1.9 — memory stays bounded when a transport stalls.
//!
//! A stalled transport is worse than a dead one: nothing errors, so the sender
//! keeps producing while acknowledgements never arrive. The retention that
//! makes 16.1.5 replay possible is exactly what turns that into unbounded
//! growth, so the bound is load-bearing rather than defensive.
//!
//! Two properties are asserted throughout:
//!
//! 1. **Memory is capped.** Held bytes never exceed the configured bound by
//!    more than the one oversized chunk that is always admitted.
//! 2. **Nothing is silently dropped.** A refused chunk is reported as
//!    `SendBufferFull`, never swallowed — the producer must slow down, because
//!    discarding unacknowledged data would tear the byte stream just as badly
//!    as losing it on the wire.

use kanrin_protocol::continuity::{ReceiveBuffer, Received, SendBuffer};
use kanrin_protocol::error::ProtocolError;
use kanrin_protocol::wire::ControlMessage;

const CHUNK: usize = 1024;
const BOUND: usize = 64 * CHUNK;

fn chunk(seq: u64) -> Vec<u8> {
    vec![seq as u8; CHUNK]
}

/// A producer that respects back-pressure, standing in for the gated TUN
/// reader of 16.1.7: it stops offering work the moment the buffer is full.
fn produce_until_blocked(buffer: &mut SendBuffer, next_seq: &mut u64, limit: usize) -> usize {
    let mut produced = 0;
    while produced < limit && !buffer.is_full() {
        buffer
            .push(*next_seq, chunk(*next_seq))
            .expect("a non-full buffer must accept a chunk");
        *next_seq += 1;
        produced += 1;
    }
    produced
}

#[test]
fn stalled_transport_caps_memory_instead_of_growing() {
    let mut buffer = SendBuffer::new(BOUND);
    let mut next_seq = 0u64;

    // The transport accepts nothing and reports nothing. Offer far more than
    // the bound could ever hold.
    let produced = produce_until_blocked(&mut buffer, &mut next_seq, 100_000);

    assert!(buffer.is_full());
    assert_eq!(produced, BOUND / CHUNK, "producer should stop exactly at the bound");
    assert!(
        buffer.buffered_bytes() <= BOUND,
        "held {} bytes over a {BOUND}-byte bound",
        buffer.buffered_bytes()
    );

    // And a producer that ignores back-pressure is refused, not silently
    // truncated — the error is what the TUN gate reacts to.
    let refused = buffer.push(next_seq, chunk(next_seq));
    assert!(matches!(refused, Err(ProtocolError::SendBufferFull { .. })));
    assert_eq!(buffer.len(), produced, "a refused chunk must not be retained");
}

#[test]
fn back_pressure_lifts_exactly_as_far_as_the_ack_reaches() {
    let mut buffer = SendBuffer::new(BOUND);
    let mut next_seq = 0u64;
    produce_until_blocked(&mut buffer, &mut next_seq, 100_000);
    assert!(buffer.is_full());

    // The transport recovers and the peer acknowledges the first quarter.
    let acked = (BOUND / CHUNK / 4) as u64;
    buffer.apply_ack(acked, &[]);

    assert!(!buffer.is_full(), "an ack must release back-pressure");
    let resumed = produce_until_blocked(&mut buffer, &mut next_seq, 100_000);
    assert_eq!(resumed as u64, acked, "exactly the freed space should be reusable");
    assert!(buffer.buffered_bytes() <= BOUND);
}

#[test]
fn a_stall_then_recovery_loses_nothing() {
    // The point of the bound is that it throttles rather than drops: after the
    // stall clears, the receiver must still see every chunk, in order.
    let mut send = SendBuffer::new(BOUND);
    let mut recv = ReceiveBuffer::with_default_capacity();
    let mut next_seq = 0u64;
    let mut delivered: Vec<Vec<u8>> = Vec::new();

    // Three stall/drain cycles, offering more than the bound each time.
    for _ in 0..3 {
        produce_until_blocked(&mut send, &mut next_seq, 100_000);

        // The stall clears: everything held is finally carried and received.
        for (sequence, data) in send.unacked().map(|(s, d)| (s, d.to_vec())).collect::<Vec<_>>() {
            if recv.accept(sequence, data).unwrap() != Received::Duplicate {
                delivered.extend(recv.drain_ready());
            }
        }

        let ControlMessage::Ack { next_expected, ranges } = recv.build_ack() else {
            panic!("expected Ack");
        };
        send.apply_ack(next_expected, &ranges);
        assert!(send.is_empty(), "a full ack must clear the buffer");
    }

    let expected: Vec<Vec<u8>> = (0..next_seq).map(chunk).collect();
    assert_eq!(delivered, expected, "throttling must not cost data");
    assert_eq!(recv.next_expected(), next_seq);
}

#[test]
fn oversized_chunk_is_admitted_once_but_still_blocks_the_next() {
    // A single chunk larger than the whole bound is admitted, otherwise a
    // large MTU with a small bound would wedge forever. The overshoot is
    // capped at that one chunk.
    let mut buffer = SendBuffer::new(CHUNK);
    let oversized = vec![0u8; CHUNK * 10];
    buffer.push(0, oversized.clone()).expect("first chunk always admitted");

    assert!(buffer.is_full());
    assert_eq!(buffer.buffered_bytes(), oversized.len());
    assert!(matches!(
        buffer.push(1, chunk(1)),
        Err(ProtocolError::SendBufferFull { .. })
    ));
}

#[test]
fn receive_side_is_bounded_when_a_gap_never_fills() {
    // The mirror hazard: a peer that keeps sending past a hole would otherwise
    // make the receiver hold everything forever.
    let mut recv = ReceiveBuffer::new(BOUND);

    // Sequence 0 never arrives, so nothing can ever be delivered.
    let mut held = 0u64;
    for seq in 1..10_000u64 {
        match recv.accept(seq, chunk(seq)) {
            Ok(_) => held += 1,
            Err(ProtocolError::ReceiveBufferFull { .. }) => break,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert!(recv.is_full());
    assert_eq!(held, (BOUND / CHUNK) as u64);
    assert!(recv.buffered_bytes() <= BOUND);
    assert_eq!(recv.next_expected(), 0, "nothing may be delivered past the gap");

    // The chunk that fills the gap is accepted even at the bound — refusing it
    // would deadlock reassembly permanently.
    assert_eq!(recv.accept(0, chunk(0)).unwrap(), Received::Ready);
    assert_eq!(recv.drain_ready().len(), held as usize + 1);
    assert_eq!(recv.buffered_bytes(), 0);
}
