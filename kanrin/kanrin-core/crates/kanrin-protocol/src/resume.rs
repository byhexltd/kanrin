//! Resumption handshake (Phase 16.1.6).
//!
//! When a transport dies, the session itself is still alive: both sides hold
//! their keys, their `continuity::SendBuffer`, and their
//! `continuity::ReceiveBuffer`. All the new transport needs is proof that the
//! peer attaching to it is the same peer as before, plus each side's receive
//! position so the replay of 16.1.5 resends exactly what is missing.
//!
//! Two messages, no key exchange:
//!
//! ```text
//! client -> server   ResumeRequest  { session_id, timestamp, client_random, next_expected, proof }
//! server -> client   ResumeResponse { status, server_random, next_expected, proof }
//! ```
//!
//! Design points that matter:
//!
//! - **No bearer token on the wire.** Ownership is proved with an HMAC under a
//!   key derived from the session keys (`crypto::derive_resumption_key`), which
//!   only the two handshake participants can compute. Nothing replayable is
//!   ever transmitted, so capturing a resume message does not let an attacker
//!   resume the session later.
//! - **Freshness** comes from `timestamp` (bounded drift) plus a 32-byte
//!   `client_random`. The response's proof covers `client_random`, binding it to
//!   this exact request so an old response cannot be replayed at the client.
//! - **Fixed-width transcripts.** Every MAC input is fixed size, so plain
//!   concatenation is unambiguous and no field can be shifted into another.
//! - **Skipping the key exchange does not weaken the session:** the keys are
//!   the ones already agreed by X25519 during the original handshake. What is
//!   skipped is the round trip, not the secrecy.

use crate::crypto::{self, SessionKeys};
use crate::error::ProtocolError;
use crate::handshake::current_timestamp;
use crate::session::SessionId;

/// Maximum accepted clock drift on a resume request, in seconds. Bounds the
/// window in which a captured request could be replayed at the server.
pub const MAX_RESUME_DRIFT_SECS: u64 = 30;

/// Wire size of an encoded [`ResumeRequest`]: 16 + 8 + 32 + 8 + 32.
pub const RESUME_REQUEST_SIZE: usize = 96;

/// Wire size of an encoded [`ResumeResponse`]: 1 + 32 + 8 + 32.
pub const RESUME_RESPONSE_SIZE: usize = 73;

/// Outcome of a resumption attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResumeStatus {
    Ok = 0x00,
    /// No such session — expired, evicted, or never existed. Deliberately not
    /// distinguished from a bad proof in what the server reveals beyond this
    /// code, so it cannot be used to probe which session ids are live.
    UnknownSession = 0x01,
    /// The proof did not verify.
    ProofInvalid = 0x02,
    /// Timestamp outside the accepted drift window.
    Stale = 0x03,
    /// Session exists but is not in a resumable state (closed, for instance).
    NotResumable = 0x04,
}

impl ResumeStatus {
    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x00 => Ok(Self::Ok),
            0x01 => Ok(Self::UnknownSession),
            0x02 => Ok(Self::ProofInvalid),
            0x03 => Ok(Self::Stale),
            0x04 => Ok(Self::NotResumable),
            _ => Err(ProtocolError::HandshakeFailed(format!(
                "unknown resume status: 0x{:02x}",
                b
            ))),
        }
    }
}

/// Client's claim to an existing session, sent first on the new transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeRequest {
    pub session_id: SessionId,
    pub timestamp: u64,
    pub client_random: [u8; 32],
    /// The client's `ReceiveBuffer::next_expected()` — every sequence below it
    /// has been received, so the server may release those and must resend the
    /// rest.
    pub next_expected: u64,
    proof: [u8; 32],
}

impl ResumeRequest {
    /// Build and sign a resume request for `session_id`.
    pub fn new(
        session_id: SessionId,
        next_expected: u64,
        keys: &SessionKeys,
    ) -> Result<Self, ProtocolError> {
        let mut req = Self {
            session_id,
            timestamp: current_timestamp(),
            client_random: crypto::random_bytes(),
            next_expected,
            proof: [0u8; 32],
        };
        req.proof = req.compute_proof(&crypto::derive_resumption_key(keys)?);
        Ok(req)
    }

    fn compute_proof(&self, resumption_key: &[u8; 32]) -> [u8; 32] {
        crypto::mac_sha256(
            resumption_key,
            &[
                b"kanrin-resume-request",
                self.session_id.as_bytes(),
                &self.timestamp.to_be_bytes(),
                &self.client_random,
                &self.next_expected.to_be_bytes(),
            ],
        )
    }

    /// Verify freshness and ownership. Returns the status the server should
    /// report; `Ok` means the client proved it holds the session keys.
    pub fn verify(&self, keys: &SessionKeys) -> Result<ResumeStatus, ProtocolError> {
        let now = current_timestamp();
        if now.abs_diff(self.timestamp) > MAX_RESUME_DRIFT_SECS {
            return Ok(ResumeStatus::Stale);
        }

        let expected = self.compute_proof(&crypto::derive_resumption_key(keys)?);
        if crypto::constant_time_eq(&expected, &self.proof) {
            Ok(ResumeStatus::Ok)
        } else {
            Ok(ResumeStatus::ProofInvalid)
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RESUME_REQUEST_SIZE);
        buf.extend_from_slice(self.session_id.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.client_random);
        buf.extend_from_slice(&self.next_expected.to_be_bytes());
        buf.extend_from_slice(&self.proof);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < RESUME_REQUEST_SIZE {
            return Err(ProtocolError::BufferTooShort {
                need: RESUME_REQUEST_SIZE,
                got: data.len(),
            });
        }
        Ok(Self {
            session_id: SessionId::from_bytes(data[..16].try_into().unwrap()),
            timestamp: u64::from_be_bytes(data[16..24].try_into().unwrap()),
            client_random: data[24..56].try_into().unwrap(),
            next_expected: u64::from_be_bytes(data[56..64].try_into().unwrap()),
            proof: data[64..96].try_into().unwrap(),
        })
    }
}

/// Server's answer to a [`ResumeRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeResponse {
    pub status: ResumeStatus,
    pub server_random: [u8; 32],
    /// The server's own receive position, mirroring
    /// [`ResumeRequest::next_expected`]. Meaningful only when `status` is `Ok`.
    pub next_expected: u64,
    proof: [u8; 32],
}

impl ResumeResponse {
    /// Build and sign a response bound to `request`.
    pub fn new(
        status: ResumeStatus,
        next_expected: u64,
        request: &ResumeRequest,
        keys: &SessionKeys,
    ) -> Result<Self, ProtocolError> {
        let mut resp = Self {
            status,
            server_random: crypto::random_bytes(),
            next_expected,
            proof: [0u8; 32],
        };
        resp.proof = resp.compute_proof(&crypto::derive_resumption_key(keys)?, request);
        Ok(resp)
    }

    fn compute_proof(&self, resumption_key: &[u8; 32], request: &ResumeRequest) -> [u8; 32] {
        crypto::mac_sha256(
            resumption_key,
            &[
                b"kanrin-resume-response",
                // Binding the client's nonce is what stops a captured response
                // from being replayed against a later request.
                &request.client_random,
                &[self.status as u8],
                &self.server_random,
                &self.next_expected.to_be_bytes(),
            ],
        )
    }

    /// Verify that this response came from the session peer and answers
    /// `request`. The client must treat a `false` here as a failed resume.
    pub fn verify(&self, request: &ResumeRequest, keys: &SessionKeys) -> Result<bool, ProtocolError> {
        let expected = self.compute_proof(&crypto::derive_resumption_key(keys)?, request);
        Ok(crypto::constant_time_eq(&expected, &self.proof))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RESUME_RESPONSE_SIZE);
        buf.push(self.status as u8);
        buf.extend_from_slice(&self.server_random);
        buf.extend_from_slice(&self.next_expected.to_be_bytes());
        buf.extend_from_slice(&self.proof);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < RESUME_RESPONSE_SIZE {
            return Err(ProtocolError::BufferTooShort {
                need: RESUME_RESPONSE_SIZE,
                got: data.len(),
            });
        }
        Ok(Self {
            status: ResumeStatus::from_byte(data[0])?,
            server_random: data[1..33].try_into().unwrap(),
            next_expected: u64::from_be_bytes(data[33..41].try_into().unwrap()),
            proof: data[41..73].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuity::{ReceiveBuffer, SendBuffer};

    fn keys() -> SessionKeys {
        SessionKeys {
            client_write_key: crypto::random_bytes(),
            server_write_key: crypto::random_bytes(),
        }
    }

    #[test]
    fn test_resume_roundtrip_and_mutual_proof() {
        let k = keys();
        let id = SessionId::generate();

        let req = ResumeRequest::new(id, 42, &k).unwrap();
        let req = ResumeRequest::decode(&req.encode()).unwrap();
        assert_eq!(req.next_expected, 42);
        assert_eq!(req.verify(&k).unwrap(), ResumeStatus::Ok);

        let resp = ResumeResponse::new(ResumeStatus::Ok, 17, &req, &k).unwrap();
        let resp = ResumeResponse::decode(&resp.encode()).unwrap();
        assert_eq!(resp.next_expected, 17);
        assert!(resp.verify(&req, &k).unwrap());
    }

    #[test]
    fn test_encoded_sizes_are_fixed() {
        let k = keys();
        let req = ResumeRequest::new(SessionId::generate(), 0, &k).unwrap();
        assert_eq!(req.encode().len(), RESUME_REQUEST_SIZE);
        let resp = ResumeResponse::new(ResumeStatus::Ok, 0, &req, &k).unwrap();
        assert_eq!(resp.encode().len(), RESUME_RESPONSE_SIZE);
    }

    #[test]
    fn test_wrong_keys_cannot_claim_session() {
        // Knowing the session id is not enough — an attacker who saw it on the
        // wire still cannot produce a valid proof.
        let req = ResumeRequest::new(SessionId::generate(), 5, &keys()).unwrap();
        assert_eq!(req.verify(&keys()).unwrap(), ResumeStatus::ProofInvalid);
    }

    #[test]
    fn test_tampering_with_any_field_invalidates_the_proof() {
        let k = keys();
        let req = ResumeRequest::new(SessionId::generate(), 5, &k).unwrap();
        let encoded = req.encode();

        // Flip a bit in each covered field in turn: session id, timestamp,
        // random, next_expected. Rewriting next_expected in particular would
        // otherwise let an attacker force a huge pointless replay.
        //
        // Offset 23 is the *low* byte of the timestamp on purpose: a shift of
        // one second stays inside the drift window, so the failure proves the
        // proof caught it rather than the freshness check.
        for offset in [0usize, 23, 30, 60] {
            let mut tampered = encoded.clone();
            tampered[offset] ^= 0x01;
            let decoded = ResumeRequest::decode(&tampered).unwrap();
            assert_eq!(
                decoded.verify(&k).unwrap(),
                ResumeStatus::ProofInvalid,
                "tampering at offset {offset} was not detected"
            );
        }
    }

    #[test]
    fn test_stale_request_rejected() {
        let k = keys();
        let mut req = ResumeRequest::new(SessionId::generate(), 0, &k).unwrap();
        req.timestamp = current_timestamp() - MAX_RESUME_DRIFT_SECS - 1;
        // Re-sign so the only thing wrong is the age, not the proof.
        req.proof = req.compute_proof(&crypto::derive_resumption_key(&k).unwrap());
        assert_eq!(req.verify(&k).unwrap(), ResumeStatus::Stale);
    }

    #[test]
    fn test_response_cannot_be_replayed_against_another_request() {
        let k = keys();
        let id = SessionId::generate();
        let first = ResumeRequest::new(id, 0, &k).unwrap();
        let resp = ResumeResponse::new(ResumeStatus::Ok, 3, &first, &k).unwrap();
        assert!(resp.verify(&first, &k).unwrap());

        // A second attempt carries a fresh client_random, so the captured
        // response no longer verifies.
        let second = ResumeRequest::new(id, 0, &k).unwrap();
        assert_ne!(first.client_random, second.client_random);
        assert!(!resp.verify(&second, &k).unwrap());
    }

    #[test]
    fn test_reported_position_drives_replay_of_exactly_the_missing_chunks() {
        let k = keys();
        // Server sent 0..4; the client received 0,1 before the transport died.
        let mut tx = SendBuffer::new(1024);
        for seq in 0..5u64 {
            tx.push(seq, vec![seq as u8]).unwrap();
        }
        let mut rx = ReceiveBuffer::new(1024);
        rx.accept(0, vec![0]).unwrap();
        rx.accept(1, vec![1]).unwrap();

        // The client resumes, reporting its receive position.
        let req = ResumeRequest::new(SessionId::generate(), rx.next_expected(), &k).unwrap();
        let req = ResumeRequest::decode(&req.encode()).unwrap();
        assert_eq!(req.verify(&k).unwrap(), ResumeStatus::Ok);

        // Acting on it, the server releases what landed and keeps the rest.
        tx.apply_ack(req.next_expected, &[]);
        assert_eq!(tx.unacked().map(|(s, _)| s).collect::<Vec<_>>(), vec![2, 3, 4]);
    }

    #[test]
    fn test_decode_rejects_truncated_and_unknown_status() {
        let k = keys();
        let req = ResumeRequest::new(SessionId::generate(), 0, &k).unwrap();
        let encoded = req.encode();
        assert!(ResumeRequest::decode(&encoded[..RESUME_REQUEST_SIZE - 1]).is_err());

        let mut resp = ResumeResponse::new(ResumeStatus::Ok, 0, &req, &k).unwrap().encode();
        assert!(ResumeResponse::decode(&resp[..RESUME_RESPONSE_SIZE - 1]).is_err());
        resp[0] = 0xFF;
        assert!(ResumeResponse::decode(&resp).is_err());
    }
}
