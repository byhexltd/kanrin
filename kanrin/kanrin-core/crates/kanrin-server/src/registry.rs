//! Session state that outlives any single connection (Phase 16.2).
//!
//! Before this, a session *was* a TLS connection: keys, tunnel IP and buffers
//! all died with the socket, so a client reconnecting got a fresh identity and
//! a fresh address. That makes a transport switch visible to every tunnelled
//! TCP connection, which defeats the point of the continuity layer.
//!
//! Here the durable state is lifted into a [`SessionRegistry`]. A connection
//! becomes a temporary *attachment* to an entry, and a switch is a detach plus
//! an attach — the tunnel IP, the sequence counters and both continuity
//! buffers survive untouched.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::{mpsc, Mutex};
use tokio::task::AbortHandle;

use kanrin_protocol::continuity::{ReceiveBuffer, SendBuffer};
use kanrin_protocol::crypto::SessionKeys;
use kanrin_protocol::session::{Session, SessionId};

/// How long an unattached session is kept before its address is reclaimed.
///
/// Long enough to survive a switch over a slow or flapping network, short
/// enough that abandoned sessions do not hold addresses out of the /24.
pub const SESSION_LINGER: Duration = Duration::from_secs(120);

/// Durable per-client state, shared by every connection that attaches to it.
pub struct SessionEntry {
    pub id: SessionId,
    pub keys: SessionKeys,
    pub assigned_ip: Ipv4Addr,
    /// Crypto state: sequence counters and byte accounting.
    pub session: Mutex<Session>,
    /// Server → client chunks awaiting acknowledgement, for replay after a
    /// switch. This is what lets an in-flight download survive.
    pub send_buffer: Mutex<SendBuffer>,
    /// Client → server reassembly.
    pub recv_buffer: Mutex<ReceiveBuffer>,
    /// Reply packets from the forwarder. Held behind a lock rather than owned
    /// by a connection: the attached writer holds it for as long as it lives,
    /// and aborting that task drops the guard so the next writer can claim it.
    pub reply_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Tasks of the currently attached connection, so a new attachment can
    /// evict the old one (make-before-break, 16.2.4).
    attached: parking_lot::Mutex<Vec<AbortHandle>>,
    last_seen: parking_lot::Mutex<Instant>,
}

impl SessionEntry {
    /// Replace the attached connection's tasks, aborting whatever was there.
    ///
    /// Returns once the previous tasks have been signalled. Aborting is what
    /// releases [`Self::reply_rx`], so the incoming writer can proceed.
    pub fn attach(&self, tasks: Vec<AbortHandle>) {
        let previous = std::mem::replace(&mut *self.attached.lock(), tasks);
        for handle in previous {
            handle.abort();
        }
        self.touch();
    }

    /// Whether some connection currently claims this session.
    pub fn is_attached(&self) -> bool {
        self.attached.lock().iter().any(|h| !h.is_finished())
    }

    pub fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }

    pub fn idle_for(&self) -> Duration {
        self.last_seen.lock().elapsed()
    }
}

/// All live sessions, keyed by the identifier a client presents when resuming.
#[derive(Default)]
pub struct SessionRegistry {
    entries: RwLock<HashMap<SessionId, Arc<SessionEntry>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an entry for a freshly handshaked client.
    pub fn insert(
        &self,
        id: SessionId,
        keys: SessionKeys,
        assigned_ip: Ipv4Addr,
        reply_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Arc<SessionEntry> {
        let entry = Arc::new(SessionEntry {
            id,
            session: Mutex::new(Session::new(id, keys.clone())),
            keys,
            assigned_ip,
            send_buffer: Mutex::new(SendBuffer::with_default_capacity()),
            recv_buffer: Mutex::new(ReceiveBuffer::with_default_capacity()),
            reply_rx: Mutex::new(reply_rx),
            attached: parking_lot::Mutex::new(Vec::new()),
            last_seen: parking_lot::Mutex::new(Instant::now()),
        });
        self.entries.write().insert(id, entry.clone());
        entry
    }

    pub fn get(&self, id: &SessionId) -> Option<Arc<SessionEntry>> {
        self.entries.read().get(id).cloned()
    }

    pub fn remove(&self, id: &SessionId) -> Option<Arc<SessionEntry>> {
        self.entries.write().remove(id)
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Drop sessions that no connection has claimed for longer than
    /// [`SESSION_LINGER`], returning their addresses for reuse.
    ///
    /// An *attached* session is never reaped however quiet it is: idleness is
    /// a property of the client's traffic, not a reason to sever a live link.
    pub fn reap_expired(&self) -> Vec<Ipv4Addr> {
        let mut entries = self.entries.write();
        let mut reclaimed = Vec::new();
        entries.retain(|_, entry| {
            let expired = !entry.is_attached() && entry.idle_for() > SESSION_LINGER;
            if expired {
                reclaimed.push(entry.assigned_ip);
            }
            !expired
        });
        reclaimed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanrin_protocol::crypto;

    fn keys() -> SessionKeys {
        SessionKeys {
            client_write_key: crypto::random_bytes(),
            server_write_key: crypto::random_bytes(),
        }
    }

    fn registry_with_one() -> (SessionRegistry, SessionId, Arc<SessionEntry>) {
        let registry = SessionRegistry::new();
        let id = SessionId::generate();
        let (_tx, rx) = mpsc::unbounded_channel();
        let entry = registry.insert(id, keys(), Ipv4Addr::new(10, 10, 0, 2), rx);
        (registry, id, entry)
    }

    #[test]
    fn test_lookup_returns_the_same_durable_state() {
        let (registry, id, entry) = registry_with_one();
        let found = registry.get(&id).expect("session should be resumable");
        assert_eq!(found.assigned_ip, entry.assigned_ip);
        assert!(Arc::ptr_eq(&found, &entry), "resuming must not clone state");
    }

    #[test]
    fn test_unknown_session_is_not_resumable() {
        let (registry, _, _) = registry_with_one();
        assert!(registry.get(&SessionId::generate()).is_none());
    }

    #[tokio::test]
    async fn test_attach_evicts_the_previous_connection() {
        let (_registry, _, entry) = registry_with_one();

        // The first connection holds the reply queue for as long as it lives.
        let holder = entry.clone();
        let first = tokio::spawn(async move {
            let _guard = holder.reply_rx.lock().await;
            std::future::pending::<()>().await;
        });
        entry.attach(vec![first.abort_handle()]);
        tokio::task::yield_now().await;
        assert!(entry.reply_rx.try_lock().is_err(), "first connection holds it");

        // A second attachment evicts the first, which drops the guard.
        let second = tokio::spawn(std::future::pending::<()>());
        entry.attach(vec![second.abort_handle()]);
        tokio::time::timeout(Duration::from_secs(1), entry.reply_rx.lock())
            .await
            .expect("replacement must be able to claim the reply queue");
        assert!(first.await.unwrap_err().is_cancelled());
        second.abort();
    }

    #[test]
    fn test_attached_sessions_are_never_reaped() {
        let (registry, _, entry) = registry_with_one();
        *entry.last_seen.lock() = Instant::now() - SESSION_LINGER * 2;

        // No live tasks: the entry is stale and its address comes back.
        assert_eq!(registry.reap_expired(), vec![Ipv4Addr::new(10, 10, 0, 2)]);
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn test_reaper_spares_a_live_attachment() {
        let (registry, _, entry) = registry_with_one();
        let task = tokio::spawn(std::future::pending::<()>());
        entry.attach(vec![task.abort_handle()]);
        *entry.last_seen.lock() = Instant::now() - SESSION_LINGER * 2;

        // Idle traffic is not a reason to sever a live connection.
        assert!(registry.reap_expired().is_empty());
        assert_eq!(registry.len(), 1);
        task.abort();
    }
}
