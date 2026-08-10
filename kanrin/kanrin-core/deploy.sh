#!/bin/bash
# Kanrin Server — Quick Deploy Script
# Run this on your VPS (Ubuntu/Debian)
#
# Usage:
#   curl -sSL <your-url>/deploy.sh | bash
#   OR
#   chmod +x deploy.sh && ./deploy.sh

set -e

echo "=== Kanrin Server Deployment ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (sudo)"
    exit 1
fi

# Install dependencies
echo "[*] Installing build dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential pkg-config libssl-dev curl git > /dev/null 2>&1

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "[*] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Create kanrin user
if ! id "kanrin" &>/dev/null; then
    useradd -r -s /bin/false -m -d /opt/kanrin kanrin
fi

# Clone and build
echo "[*] Building kanrin-server..."
WORK_DIR=$(mktemp -d)
cd "$WORK_DIR"

# Copy source (or clone from git)
# For now, assuming source is uploaded to /tmp/kanrin-source
if [ -d "/tmp/kanrin-source" ]; then
    cp -r /tmp/kanrin-source/* .
else
    echo "[!] Source code not found at /tmp/kanrin-source"
    echo "    Upload the kanrin-core directory to /tmp/kanrin-source first"
    echo ""
    echo "    From your Windows machine:"
    echo "    scp -r kanrin-core/ root@YOUR_VPS:/tmp/kanrin-source/"
    exit 1
fi

cd kanrin-core
cargo build --release -p kanrin-server

# Install binary
echo "[*] Installing binary..."
cp target/release/kanrin-server /usr/local/bin/
chmod +x /usr/local/bin/kanrin-server

# Setup directory
mkdir -p /etc/kanrin
cd /etc/kanrin

# Generate certificate
echo "[*] Generating TLS certificate..."
/usr/local/bin/kanrin-server --gen-cert

# Generate config
if [ ! -f /etc/kanrin/server.yml ]; then
    # Generate a random password
    PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 24)

    cat > /etc/kanrin/server.yml << EOF
# Kanrin Server Configuration
listen: "0.0.0.0:443"
password: "${PASSWORD}"
tls_cert: "/etc/kanrin/cert.pem"
tls_key: "/etc/kanrin/key.pem"
max_clients: 256
log_level: "info"
dns:
  - "1.1.1.1"
  - "8.8.8.8"
EOF

    # Move certs to /etc/kanrin
    mv cert.pem /etc/kanrin/ 2>/dev/null || true
    mv key.pem /etc/kanrin/ 2>/dev/null || true

    echo ""
    echo "============================================"
    echo "  YOUR PASSWORD: ${PASSWORD}"
    echo "  SAVE THIS! You need it for the client."
    echo "============================================"
    echo ""
fi

# Enable IP forwarding
echo "[*] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf 2>/dev/null || true

# Setup NAT (iptables)
# Each rule is checked with -C first so re-running this script does not append
# duplicate entries to the tables.
echo "[*] Setting up NAT..."
IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)

add_rule() {
    local table_args=()
    if [ "$1" = "-t" ]; then
        table_args=("$1" "$2")
        shift 2
    fi
    if ! iptables "${table_args[@]}" -C "$@" 2>/dev/null; then
        iptables "${table_args[@]}" -A "$@"
    fi
}

add_rule -t nat POSTROUTING -s 10.10.0.0/24 -o "$IFACE" -j MASQUERADE
add_rule FORWARD -s 10.10.0.0/24 -j ACCEPT
add_rule FORWARD -d 10.10.0.0/24 -j ACCEPT

# Save iptables
apt-get install -y -qq iptables-persistent > /dev/null 2>&1 || true
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

# Create systemd service
echo "[*] Creating systemd service..."
cat > /etc/systemd/system/kanrin-server.service << EOF
[Unit]
Description=Kanrin VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/kanrin
ExecStartPre=/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStart=/usr/local/bin/kanrin-server -c /etc/kanrin/server.yml
ExecStopPost=-/sbin/ip link delete kanrin0
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kanrin-server
systemctl start kanrin-server

# Cleanup
rm -rf "$WORK_DIR"

echo ""
echo "=== Kanrin Server Deployed ==="
echo ""
echo "Status: $(systemctl is-active kanrin-server)"
echo "Config: /etc/kanrin/server.yml"
echo "Logs:   journalctl -u kanrin-server -f"
echo ""
echo "--- Client Config ---"
echo "Server: $(curl -s ifconfig.me || hostname -I | awk '{print $1}')"
echo "Port:   443"
echo "Check server.yml for password"
echo ""
