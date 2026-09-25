//! Session continuity layer (Phase 16.1).
//!
//! A reliable, ordered, transport-agnostic pipe that outlives any individual
//! connection. The pieces build on the explicit per-chunk `sequence` added in
//! 16.1.1 (`wire::ChunkHeader.sequence`):
//!
//! - [`SendBuffer`] (16.1.2) retains the encoded bytes of every data chunk until
//!   the peer acknowledges it, so an unacknowledged chunk can be replayed onto a
//!   new transport (16.1.5) after a switch (16.2) without the application ever
//!   seeing a gap.
//! - [`SendBuffer::apply_ack`] (16.1.3) consumes the peer's
//!   `wire::ControlMessage::Ack` (cumulative `next_expected` + SACK ranges).
//! - [`Replay`] (16.1.5) walks the send buffer to push everything still
//!   unacknowledged onto a replacement transport, in order.
//! - [`ReceiveBuffer`] (16.1.4) is the mirror image: it restores the original
//!   order of chunks that arrived reordered (across a switch, or striped over
//!   several paths in 16.3), drops duplicates, and produces the `Ack` the
//!   sender needs to release its own buffer.
//!
//! The buffer stores the *encoded* chunk (the output of
//! `Session::encrypt_outgoing`), which is transport-independent: framing is added
//! by whichever transport carries it, so the same buffered bytes can be replayed
//! across TLS/TCP, QUIC, or WebSocket interchangeably.

use std::collections::BTreeMap;

use crate::error::ProtocolError;
use crate::wire::{ControlMessage, SackRange, MAX_SACK_RANGES};

/// Default cap on the bytes held unacknowledged before back-pressure applies.
/// Back-pressure wiring to the TUN reader is 16.1.7; this bound is enforced here.
pub const DEFAULT_MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// An outgoing chunk retained until acknowledged.
#[derive(Debug, Clone)]
struct BufferedChunk {
    /// The transport-independent encoded chunk bytes (already encrypted).
    data: Vec<u8>,
}

/// Retains unacknowledged outgoing chunks, keyed by their monotonic sequence.
///
/// A `BTreeMap` keeps the chunks ordered by sequence so that:
/// - cumulative acknowledgement is an O(log n) range split, and
/// - replay ([`SendBuffer::unacked`]) yields chunks in the exact order they were
///   originally sent, which is what preserves the inner byte stream.
#[derive(Debug)]
pub struct SendBuffer {
    chunks: BTreeMap<u64, BufferedChunk>,
    buffered_bytes: usize,
    max_bytes: usize,
}

impl SendBuffer {
    /// Create a send buffer bounded to `max_bytes` of unacknowledged data.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            chunks: BTreeMap::new(),
            buffered_bytes: 0,
            max_bytes,
        }
    }

    /// Create a send buffer with the default byte bound.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_MAX_BUFFER_BYTES)
    }

    /// Record an outgoing chunk's encoded bytes so it can be replayed until acked.
    ///
    /// Fails with [`ProtocolError::SendBufferFull`] if retaining this chunk would
    /// exceed the byte bound, unless the buffer is currently empty — a single
    /// chunk larger than the bound is always admitted so forward progress is
    /// never wedged.
    pub fn push(&mut self, sequence: u64, data: Vec<u8>) -> Result<(), ProtocolError> {
        if !self.chunks.is_empty() && self.buffered_bytes + data.len() > self.max_bytes {
            return Err(ProtocolError::SendBufferFull {
                buffered: self.buffered_bytes,
                max: self.max_bytes,
            });
        }

        // Sequences are unique and strictly increasing per direction, so a
        // collision means the same chunk was buffered twice. Adjust the byte
        // accounting for the replaced entry rather than double-counting.
        if let Some(old) = self.chunks.insert(sequence, BufferedChunk { data: data.clone() }) {
            self.buffered_bytes -= old.data.len();
        }
        self.buffered_bytes += data.len();
        Ok(())
    }

    /// Cumulative acknowledgement: drop every chunk with sequence `<= up_to`.
    /// Returns the number of chunks removed.
    pub fn ack_cumulative(&mut self, up_to: u64) -> usize {
        // Everything strictly greater than `up_to` is retained.
        let retained = match up_to.checked_add(1) {
            Some(boundary) => self.chunks.split_off(&boundary),
            // up_to == u64::MAX acknowledges the entire space.
            None => BTreeMap::new(),
        };

        let removed = std::mem::replace(&mut self.chunks, retained);
        let removed_bytes: usize = removed.values().map(|c| c.data.len()).sum();
        self.buffered_bytes -= removed_bytes;
        removed.len()
    }

    /// Selective acknowledgement: drop the specific `sequences`.
    /// Returns the number of chunks actually removed.
    pub fn ack_selective(&mut self, sequences: &[u64]) -> usize {
        let mut removed = 0;
        for seq in sequences {
            if let Some(chunk) = self.chunks.remove(seq) {
                self.buffered_bytes -= chunk.data.len();
                removed += 1;
            }
        }
        removed
    }

    /// Drop every chunk with sequence in the inclusive range `[start, end]`.
    /// Returns the number of chunks removed.
    pub fn ack_range(&mut self, start: u64, end: u64) -> usize {
        if start > end {
            return 0;
        }
        let seqs: Vec<u64> = self.chunks.range(start..=end).map(|(s, _)| *s).collect();
        self.ack_selective(&seqs)
    }

    /// Apply a peer's `ControlMessage::Ack` (16.1.3): release everything below
    /// `next_expected`, then every selectively acknowledged range.
    /// Returns the number of chunks removed.
    ///
    /// Idempotent: stale, duplicated, or reordered acks only ever release
    /// chunks, never re-add them.
    pub fn apply_ack(&mut self, next_expected: u64, ranges: &[SackRange]) -> usize {
        let cumulative = next_expected.checked_sub(1).map_or(0, |up_to| self.ack_cumulative(up_to));
        cumulative + ranges.iter().map(|r| self.ack_range(r.start, r.end)).sum::<usize>()
    }

    /// Iterate the unacknowledged chunks in ascending sequence order, yielding
    /// `(sequence, encoded_bytes)`. This is the replay source for 16.1.5.
    pub fn unacked(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.chunks.iter().map(|(seq, chunk)| (*seq, chunk.data.as_slice()))
    }

    /// Number of unacknowledged chunks currently held.
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the buffer holds no unacknowledged chunks.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Total bytes of unacknowledged chunk data currently held.
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// The configured byte bound.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Whether the buffer has reached its byte bound (16.1.7 back-pressure signal).
    pub fn is_full(&self) -> bool {
        self.buffered_bytes >= self.max_bytes
    }

    /// Lowest unacknowledged sequence, if any. Useful for diagnostics and for
    /// the resumption handshake (16.1.6).
    pub fn lowest_unacked(&self) -> Option<u64> {
        self.chunks.keys().next().copied()
    }
}

/// Progress marker for replaying unacknowledged chunks onto a new transport
/// after a switch (16.1.5).
///
/// Deliberately holds no copy of the chunks — it is just a cursor over the
/// live [`SendBuffer`]. That has two consequences that matter:
///
/// - Acks that arrive *during* the replay prune the buffer, so those chunks are
///   skipped instead of pointlessly resent.
/// - If the replacement transport also dies mid-replay, the cursor is simply
///   carried over to the next one; nothing needs unwinding.
///
/// Resending a chunk the peer already holds is harmless: the receiver drops it
/// as [`Received::Duplicate`] (16.1.4). Losing one is not — so the cursor only
/// advances on a send the caller has confirmed.
#[derive(Debug)]
pub struct Replay {
    /// Lowest sequence not yet replayed, or `None` once the cursor has run off
    /// the end of the sequence space. An `Option` rather than a saturating
    /// counter: saturating at `u64::MAX` would leave the cursor pointing at a
    /// chunk it had already sent, and the replay would never terminate.
    next: Option<u64>,
    replayed: usize,
}

impl Default for Replay {
    fn default() -> Self {
        Self { next: Some(0), replayed: 0 }
    }
}

impl Replay {
    /// Start a replay from the beginning of the unacknowledged range.
    pub fn new() -> Self {
        Self::default()
    }

    /// The next chunk to put on the wire: the lowest unacknowledged sequence at
    /// or above the cursor, or `None` when the replay is complete.
    ///
    /// Ascending order is what preserves the inner byte stream — the peer's
    /// reorder buffer would cope either way, but sending in order keeps it from
    /// holding chunks it could otherwise deliver straight through.
    pub fn next_chunk<'a>(&self, buffer: &'a SendBuffer) -> Option<(u64, &'a [u8])> {
        let from = self.next?;
        buffer.chunks.range(from..).next().map(|(seq, c)| (*seq, c.data.as_slice()))
    }

    /// Record that the chunk at `sequence` reached the new transport, moving
    /// the cursor past it. Call this only after the send actually succeeded.
    pub fn confirm_sent(&mut self, sequence: u64) {
        self.next = sequence.checked_add(1);
        self.replayed += 1;
    }

    /// Whether every unacknowledged chunk has been replayed.
    pub fn is_complete(&self, buffer: &SendBuffer) -> bool {
        self.next_chunk(buffer).is_none()
    }

    /// Number of chunks confirmed onto the new transport so far.
    pub fn replayed(&self) -> usize {
        self.replayed
    }
}

/// Outcome of offering a received chunk to the [`ReceiveBuffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// In order (or it filled the gap): payloads are ready to be delivered.
    Ready,
    /// Ahead of the gap; retained until the missing sequences arrive.
    Buffered,
    /// Already seen — discarded. Expected during hedging (16.3.3) and after a
    /// replay onto a new transport (16.1.5).
    Duplicate,
}

/// Reassembles the inner byte stream from chunks that may arrive out of order
/// or more than once, and tracks what to acknowledge.
///
/// Delivery is strictly in sequence order, so the state needed is small:
/// everything below `next_expected` has already been delivered, which makes
/// duplicate detection exact (not probabilistic) without retaining history.
#[derive(Debug)]
pub struct ReceiveBuffer {
    /// Lowest sequence not yet delivered — the cumulative ack point.
    next_expected: u64,
    /// Chunks received above the gap, keyed by sequence.
    pending: BTreeMap<u64, Vec<u8>>,
    /// Payloads ready for in-order delivery.
    ready: Vec<Vec<u8>>,
    buffered_bytes: usize,
    max_bytes: usize,
}

impl ReceiveBuffer {
    /// Create a receive buffer bounded to `max_bytes` of out-of-order data.
    pub fn new(max_bytes: usize) -> Self {
        Self {
            next_expected: 0,
            pending: BTreeMap::new(),
            ready: Vec::new(),
            buffered_bytes: 0,
            max_bytes,
        }
    }

    /// Create a receive buffer with the default byte bound.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_MAX_BUFFER_BYTES)
    }

    /// Offer a decrypted chunk payload received under `sequence`.
    ///
    /// Fails with [`ProtocolError::ReceiveBufferFull`] only for a chunk that
    /// must be *held* (out of order) when the bound is already reached. An
    /// in-order chunk is always accepted, since accepting it is what drains the
    /// buffer — refusing it would deadlock reassembly.
    pub fn accept(&mut self, sequence: u64, payload: Vec<u8>) -> Result<Received, ProtocolError> {
        if sequence < self.next_expected || self.pending.contains_key(&sequence) {
            return Ok(Received::Duplicate);
        }

        if sequence > self.next_expected {
            if self.buffered_bytes + payload.len() > self.max_bytes {
                return Err(ProtocolError::ReceiveBufferFull {
                    buffered: self.buffered_bytes,
                    max: self.max_bytes,
                });
            }
            self.buffered_bytes += payload.len();
            self.pending.insert(sequence, payload);
            return Ok(Received::Buffered);
        }

        // In order: deliver it, then any pending chunks it unblocked.
        self.ready.push(payload);
        self.next_expected += 1;
        while let Some(next) = self.pending.remove(&self.next_expected) {
            self.buffered_bytes -= next.len();
            self.ready.push(next);
            self.next_expected += 1;
        }
        Ok(Received::Ready)
    }

    /// Take the payloads that are ready, in their original order.
    pub fn drain_ready(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.ready)
    }

    /// Build the acknowledgement describing what has been received: the
    /// cumulative point plus coalesced ranges for the chunks held above it.
    ///
    /// Adjacent pending sequences are merged into one range, and at most
    /// [`MAX_SACK_RANGES`] (the lowest ones) are reported — those sit closest
    /// to the gap, so they are the ones the sender can release soonest.
    /// Anything omitted is simply acknowledged by a later ack.
    pub fn build_ack(&self) -> ControlMessage {
        let mut ranges: Vec<SackRange> = Vec::new();
        for &seq in self.pending.keys() {
            // Keys ascend, so the previous end is always below `seq` and
            // `end + 1` cannot overflow.
            let extends = ranges.last().is_some_and(|last| last.end + 1 == seq);
            if extends {
                ranges.last_mut().unwrap().end = seq;
            } else if ranges.len() == MAX_SACK_RANGES {
                break;
            } else {
                ranges.push(SackRange { start: seq, end: seq });
            }
        }
        ControlMessage::Ack {
            next_expected: self.next_expected,
            ranges,
        }
    }

    /// Lowest sequence not yet delivered. Reported by the resumption handshake
    /// (16.1.6) so the peer knows where to resume from.
    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Number of out-of-order chunks currently held.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Total bytes of out-of-order chunks currently held.
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Whether the out-of-order hold has reached its byte bound.
    pub fn is_full(&self) -> bool {
        self.buffered_bytes >= self.max_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(len: usize) -> Vec<u8> {
        vec![0xABu8; len]
    }

    #[test]
    fn test_push_and_accounting() {
        let mut buf = SendBuffer::new(1024);
        buf.push(0, chunk(100)).unwrap();
        buf.push(1, chunk(50)).unwrap();
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.buffered_bytes(), 150);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_cumulative_ack_removes_up_to_inclusive() {
        let mut buf = SendBuffer::new(1024);
        for seq in 0..5 {
            buf.push(seq, chunk(10)).unwrap();
        }
        // Ack through sequence 2 -> removes 0,1,2; keeps 3,4.
        let removed = buf.ack_cumulative(2);
        assert_eq!(removed, 3);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.buffered_bytes(), 20);
        assert_eq!(buf.lowest_unacked(), Some(3));
    }

    #[test]
    fn test_selective_ack() {
        let mut buf = SendBuffer::new(1024);
        for seq in 0..5 {
            buf.push(seq, chunk(10)).unwrap();
        }
        let removed = buf.ack_selective(&[1, 3, 99]); // 99 not present
        assert_eq!(removed, 2);
        assert_eq!(buf.len(), 3);
        let remaining: Vec<u64> = buf.unacked().map(|(s, _)| s).collect();
        assert_eq!(remaining, vec![0, 2, 4]);
    }

    #[test]
    fn test_unacked_yields_sequence_order() {
        let mut buf = SendBuffer::new(1024);
        // Insert out of order; iteration must still be ascending by sequence.
        buf.push(2, vec![2]).unwrap();
        buf.push(0, vec![0]).unwrap();
        buf.push(1, vec![1]).unwrap();
        let order: Vec<u64> = buf.unacked().map(|(s, _)| s).collect();
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn test_bound_enforced_but_first_chunk_always_admitted() {
        let mut buf = SendBuffer::new(100);
        // A single chunk larger than the bound is admitted (empty buffer).
        buf.push(0, chunk(500)).unwrap();
        assert!(buf.is_full());
        // But a second chunk that would exceed the bound is rejected.
        let err = buf.push(1, chunk(10));
        assert!(matches!(err, Err(ProtocolError::SendBufferFull { .. })));
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_ack_frees_space_for_new_chunks() {
        let mut buf = SendBuffer::new(100);
        buf.push(0, chunk(80)).unwrap();
        assert!(buf.push(1, chunk(80)).is_err());
        buf.ack_cumulative(0);
        assert_eq!(buf.buffered_bytes(), 0);
        // Space reclaimed — the previously rejected chunk now fits.
        buf.push(1, chunk(80)).unwrap();
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_ack_all_with_max_sequence() {
        let mut buf = SendBuffer::new(1024);
        buf.push(u64::MAX - 1, chunk(10)).unwrap();
        buf.push(u64::MAX, chunk(10)).unwrap();
        let removed = buf.ack_cumulative(u64::MAX);
        assert_eq!(removed, 2);
        assert!(buf.is_empty());
        assert_eq!(buf.buffered_bytes(), 0);
    }

    fn filled(n: u64) -> SendBuffer {
        let mut buf = SendBuffer::new(1 << 20);
        for seq in 0..n {
            buf.push(seq, chunk(10)).unwrap();
        }
        buf
    }

    fn remaining(buf: &SendBuffer) -> Vec<u64> {
        buf.unacked().map(|(s, _)| s).collect()
    }

    #[test]
    fn test_apply_ack_cumulative_and_selective() {
        let mut buf = filled(10);
        // Peer has 0..=2, then 5..=6 and 8; holes at 3,4,7,9.
        let removed = buf.apply_ack(
            3,
            &[SackRange { start: 5, end: 6 }, SackRange { start: 8, end: 8 }],
        );
        assert_eq!(removed, 6);
        assert_eq!(remaining(&buf), vec![3, 4, 7, 9]);
        assert_eq!(buf.buffered_bytes(), 40);
    }

    #[test]
    fn test_apply_ack_zero_releases_nothing_cumulatively() {
        let mut buf = filled(3);
        assert_eq!(buf.apply_ack(0, &[]), 0);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn test_apply_ack_is_idempotent_and_tolerates_stale_acks() {
        let mut buf = filled(10);
        let ranges = [SackRange { start: 7, end: 8 }];
        assert_eq!(buf.apply_ack(5, &ranges), 7);
        // Duplicate and older acks release nothing further and never re-add.
        assert_eq!(buf.apply_ack(5, &ranges), 0);
        assert_eq!(buf.apply_ack(2, &[]), 0);
        assert_eq!(remaining(&buf), vec![5, 6, 9]);
    }

    #[test]
    fn test_ack_range_bounds() {
        let mut buf = filled(5);
        assert_eq!(buf.ack_range(3, 1), 0); // inverted range is a no-op
        assert_eq!(buf.ack_range(1, 3), 3);
        assert_eq!(remaining(&buf), vec![0, 4]);
    }

    /// Drain a replay into `(sequence, first_byte)` pairs, as a transport that
    /// never fails would.
    fn run_replay(replay: &mut Replay, buf: &SendBuffer) -> Vec<(u64, u8)> {
        let mut sent = Vec::new();
        while let Some((seq, data)) = replay.next_chunk(buf) {
            sent.push((seq, data[0]));
            replay.confirm_sent(seq);
        }
        sent
    }

    #[test]
    fn test_replay_sends_all_unacked_in_order() {
        let mut buf = SendBuffer::new(1024);
        for seq in [0u64, 1, 2, 3] {
            buf.push(seq, vec![seq as u8; 4]).unwrap();
        }
        buf.ack_cumulative(1);

        let mut replay = Replay::new();
        assert_eq!(run_replay(&mut replay, &buf), vec![(2, 2), (3, 3)]);
        assert!(replay.is_complete(&buf));
        assert_eq!(replay.replayed(), 2);
        // Replay does not consume the buffer — those chunks stay until acked.
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn test_replay_resumes_after_second_transport_fails() {
        let buf = filled(5);
        let mut replay = Replay::new();

        // First replacement transport dies after two chunks.
        for _ in 0..2 {
            let (seq, _) = replay.next_chunk(&buf).unwrap();
            replay.confirm_sent(seq);
        }
        // The same cursor carries onto the next transport: no chunk is sent
        // twice, and none is skipped.
        assert_eq!(run_replay(&mut replay, &buf), vec![(2, 0xAB), (3, 0xAB), (4, 0xAB)]);
        assert_eq!(replay.replayed(), 5);
    }

    #[test]
    fn test_replay_skips_chunks_acked_while_in_flight() {
        let mut buf = filled(5);
        let mut replay = Replay::new();

        let (seq, _) = replay.next_chunk(&buf).unwrap();
        assert_eq!(seq, 0);
        replay.confirm_sent(seq);

        // An ack for 1..=3 lands over the old transport mid-replay.
        buf.apply_ack(4, &[]);
        assert_eq!(run_replay(&mut replay, &buf), vec![(4, 0xAB)]);
        assert_eq!(replay.replayed(), 2);
    }

    #[test]
    fn test_replay_of_empty_buffer_is_immediately_complete() {
        let buf = SendBuffer::new(1024);
        let mut replay = Replay::new();
        assert!(replay.is_complete(&buf));
        assert!(run_replay(&mut replay, &buf).is_empty());
    }

    #[test]
    fn test_replay_terminates_at_end_of_sequence_space() {
        // Confirming u64::MAX must complete the replay, not wrap the cursor.
        let mut buf = SendBuffer::new(1024);
        buf.push(u64::MAX, vec![7]).unwrap();
        let mut replay = Replay::new();
        assert_eq!(run_replay(&mut replay, &buf), vec![(u64::MAX, 7)]);
        assert!(replay.is_complete(&buf));
    }

    #[test]
    fn test_replayed_chunks_are_dropped_as_duplicates_by_receiver() {
        // End to end: a transport dies after the peer got 0 and 2 (1 was lost
        // in the switch). Replaying the unacked range must restore the stream
        // exactly once, in order.
        let mut tx = SendBuffer::new(1024);
        let mut rx = ReceiveBuffer::new(1024);
        for seq in 0..3u64 {
            tx.push(seq, vec![seq as u8]).unwrap();
        }
        assert_eq!(rx.accept(0, vec![0]).unwrap(), Received::Ready);
        assert_eq!(rx.accept(2, vec![2]).unwrap(), Received::Buffered);
        let ControlMessage::Ack { next_expected, ranges } = rx.build_ack() else {
            panic!("expected Ack");
        };
        tx.apply_ack(next_expected, &ranges);

        let mut replay = Replay::new();
        let mut outcomes = Vec::new();
        while let Some((seq, data)) = replay.next_chunk(&tx) {
            outcomes.push(rx.accept(seq, data.to_vec()).unwrap());
            replay.confirm_sent(seq);
        }

        // Only the genuinely missing chunk was resent, and it unblocked the run.
        assert_eq!(outcomes, vec![Received::Ready]);
        assert_eq!(rx.drain_ready(), vec![vec![0], vec![1], vec![2]]);
        assert_eq!(rx.next_expected(), 3);
    }

    fn ack_parts(buf: &ReceiveBuffer) -> (u64, Vec<(u64, u64)>) {
        match buf.build_ack() {
            ControlMessage::Ack { next_expected, ranges } => (
                next_expected,
                ranges.iter().map(|r| (r.start, r.end)).collect(),
            ),
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    #[test]
    fn test_receive_in_order_delivers_immediately() {
        let mut rx = ReceiveBuffer::new(1024);
        for seq in 0..3u64 {
            assert_eq!(rx.accept(seq, vec![seq as u8]).unwrap(), Received::Ready);
        }
        assert_eq!(rx.drain_ready(), vec![vec![0], vec![1], vec![2]]);
        assert_eq!(rx.next_expected(), 3);
        assert_eq!(rx.pending_len(), 0);
    }

    #[test]
    fn test_reorder_holds_until_gap_filled_then_delivers_in_order() {
        let mut rx = ReceiveBuffer::new(1024);
        assert_eq!(rx.accept(2, vec![2]).unwrap(), Received::Buffered);
        assert_eq!(rx.accept(1, vec![1]).unwrap(), Received::Buffered);
        // Nothing may be delivered while sequence 0 is missing.
        assert!(rx.drain_ready().is_empty());
        assert_eq!(rx.buffered_bytes(), 2);

        // The missing chunk releases the whole run, in original order.
        assert_eq!(rx.accept(0, vec![0]).unwrap(), Received::Ready);
        assert_eq!(rx.drain_ready(), vec![vec![0], vec![1], vec![2]]);
        assert_eq!(rx.next_expected(), 3);
        assert_eq!(rx.buffered_bytes(), 0);
    }

    #[test]
    fn test_duplicates_suppressed_delivered_and_pending() {
        let mut rx = ReceiveBuffer::new(1024);
        rx.accept(0, vec![0]).unwrap();
        rx.accept(2, vec![2]).unwrap();
        // Already delivered, and already held: both dropped, neither re-delivered.
        assert_eq!(rx.accept(0, vec![0xFF]).unwrap(), Received::Duplicate);
        assert_eq!(rx.accept(2, vec![0xFF]).unwrap(), Received::Duplicate);
        assert_eq!(rx.pending_len(), 1);
        assert_eq!(rx.buffered_bytes(), 1);
        assert_eq!(rx.drain_ready(), vec![vec![0]]);
    }

    #[test]
    fn test_build_ack_coalesces_and_matches_send_buffer() {
        let mut rx = ReceiveBuffer::new(1024);
        for seq in [0u64, 1, 3, 4, 5, 7] {
            rx.accept(seq, vec![seq as u8]).unwrap();
        }
        // Delivered 0,1; holes at 2 and 6; runs 3..=5 and 7 held.
        assert_eq!(ack_parts(&rx), (2, vec![(3, 5), (7, 7)]));

        // The ack must be wire-legal and must release exactly those from the
        // peer's send buffer, leaving only the genuinely missing chunks.
        let encoded = rx.build_ack().encode();
        let ControlMessage::Ack { next_expected, ranges } =
            ControlMessage::decode(&encoded).unwrap()
        else {
            panic!("expected Ack");
        };
        let mut tx = filled(8);
        tx.apply_ack(next_expected, &ranges);
        assert_eq!(remaining(&tx), vec![2, 6]);
    }

    #[test]
    fn test_build_ack_caps_ranges_at_protocol_limit() {
        let mut rx = ReceiveBuffer::new(1 << 20);
        // Every other sequence from 1 upward: one range per chunk, far more
        // than the wire allows.
        for i in 0..(MAX_SACK_RANGES as u64 + 10) {
            rx.accept(1 + i * 2, vec![0]).unwrap();
        }
        let (next_expected, ranges) = ack_parts(&rx);
        assert_eq!(next_expected, 0);
        assert_eq!(ranges.len(), MAX_SACK_RANGES);
        // The lowest holes are reported — those unblock the stream soonest.
        assert_eq!(ranges[0], (1, 1));
        assert!(ControlMessage::decode(&rx.build_ack().encode()).is_ok());
    }

    #[test]
    fn test_receive_bound_rejects_out_of_order_but_never_in_order() {
        let mut rx = ReceiveBuffer::new(10);
        rx.accept(5, vec![0; 10]).unwrap();
        assert!(rx.is_full());
        let err = rx.accept(6, vec![0; 1]);
        assert!(matches!(err, Err(ProtocolError::ReceiveBufferFull { .. })));

        // The chunk that actually drains the buffer is never refused.
        assert_eq!(rx.accept(0, vec![0; 100]).unwrap(), Received::Ready);
        assert_eq!(rx.next_expected(), 1);
    }

    #[test]
    fn test_duplicate_push_does_not_double_count() {
        let mut buf = SendBuffer::new(1024);
        buf.push(0, chunk(10)).unwrap();
        buf.push(0, chunk(10)).unwrap(); // same sequence again
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.buffered_bytes(), 10);
    }
}
