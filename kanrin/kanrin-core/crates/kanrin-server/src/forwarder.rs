use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::mpsc;

use kanrin_tun::device::TunDevice;

/// Forwards IP packets between VPN clients and the real internet.
///
/// Rather than terminating TCP in userspace (which requires a full TCP stack),
/// packets are written into a TUN device and the kernel performs routing and
/// NAT (via `iptables MASQUERADE`). Reply packets are read back from the TUN
/// device and dispatched to the owning client by destination IP.
pub struct PacketForwarder {
    tun: Arc<TunDevice>,
    /// Per-client outbound queues keyed by the client's assigned tunnel IP.
    clients: RwLock<HashMap<Ipv4Addr, mpsc::UnboundedSender<Vec<u8>>>>,
}

impl PacketForwarder {
    pub fn new(tun: Arc<TunDevice>) -> Self {
        Self {
            tun,
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// Register a client and get the receiver for packets destined to it.
    pub fn register_client(&self, client_ip: Ipv4Addr) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.clients.write().insert(client_ip, tx);
        tracing::debug!(client_ip = %client_ip, "client registered with forwarder");
        rx
    }

    /// Remove a client's queue when its session ends.
    pub fn unregister_client(&self, client_ip: Ipv4Addr) {
        self.clients.write().remove(&client_ip);
        tracing::debug!(client_ip = %client_ip, "client unregistered from forwarder");
    }

    /// Write a client's IP packet into the TUN device so the kernel routes it.
    pub async fn send_to_internet(&self, ip_packet: &[u8]) {
        if ip_packet.len() < 20 {
            return;
        }

        // Only IPv4 is forwarded for now.
        if ip_packet[0] >> 4 != 4 {
            return;
        }

        if let Err(e) = self.tun.write_packet(ip_packet).await {
            tracing::debug!(error = %e, "TUN write failed");
        }
    }

    /// Background loop: read reply packets from TUN and dispatch to clients.
    pub fn spawn_dispatcher(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                let packet = match self.tun.read_packet().await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(error = %e, "TUN read failed â€” dispatcher stopping");
                        break;
                    }
                };

                if packet.len() < 20 || packet[0] >> 4 != 4 {
                    continue;
                }

                // Destination IP tells us which client this reply belongs to.
                let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                let sender = self.clients.read().get(&dst_ip).cloned();
                match sender {
                    Some(tx) => {
                        if tx.send(packet).is_err() {
                            self.clients.write().remove(&dst_ip);
                        }
                    }
                    None => {
                        tracing::trace!(dst = %dst_ip, "reply packet for unknown client, dropping");
                    }
                }
            }
        });
    }
}
