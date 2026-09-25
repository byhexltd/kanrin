mod config;
mod forwarder;
mod frontdoor;
mod http;
mod listener;
mod origin;
mod registry;
mod session;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use kanrin_tun::device::{TunConfig, TunDevice};

use config::ServerConfig;
use forwarder::PacketForwarder;
use listener::KanrinListener;
use frontdoor::Admitter;
use registry::SessionRegistry;
use session::{ClientSession, ConnectionOutcome, IpAllocator};

#[derive(Parser)]
#[command(name = "kanrin-server")]
#[command(version)]
#[command(about = "Kanrin VPN Server — Harbor exit node")]
struct Cli {
    /// Path to config file (YAML)
    #[arg(short, long, default_value = "server.yml")]
    config: PathBuf,

    /// Generate a self-signed TLS certificate for testing
    #[arg(long)]
    gen_cert: bool,

    /// Generate a sample config file
    #[arg(long)]
    init: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.init {
        return cmd_init(&cli.config);
    }

    if cli.gen_cert {
        return cmd_gen_cert();
    }

    // Install rustls CryptoProvider (ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Load config
    let config = ServerConfig::from_file(&cli.config)?;

    // Setup logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level)),
        )
        .with_target(false)
        .init();

    tracing::info!(
        listen = %config.listen,
        max_clients = config.max_clients,
        "Kanrin server starting"
    );

    let config = Arc::new(config);

    // Create IP allocator
    let ip_allocator = Arc::new(IpAllocator::new(Ipv4Addr::new(10, 10, 0, 0)));

    // Create the server-side TUN device. Client packets are written here and
    // the kernel performs routing and NAT, so no userspace TCP stack is needed.
    let tun_config = TunConfig {
        name: "kanrin0".into(),
        address: Ipv4Addr::new(10, 10, 0, 1).into(),
        netmask: "255.255.255.0".parse().unwrap(),
        gateway: Ipv4Addr::new(10, 10, 0, 1).into(),
        dns: vec![],
        mtu: 1400,
    };

    let tun = Arc::new(TunDevice::create(tun_config)?);
    tracing::info!(tun = "kanrin0", address = "10.10.0.1/24", "TUN device ready");

    // Create packet forwarder and start dispatching reply packets
    let forwarder = Arc::new(PacketForwarder::new(tun));
    forwarder.clone().spawn_dispatcher();

    // Bind listener
    let listener = KanrinListener::bind(config.clone()).await?;

    // Sessions outlive the connections carrying them, so a client switching
    // transports keeps its tunnel address and continuity state (Phase 16.2).
    let registry = Arc::new(SessionRegistry::new());

    // Validates tunnel authenticators carried on ordinary requests (17.1.6).
    let admitter = Arc::new(Admitter::new(&config.password));

    // Addresses therefore belong to registry entries, not to connections:
    // only expiry returns one to the pool.
    {
        let registry = registry.clone();
        let ip_allocator = ip_allocator.clone();
        let forwarder = forwarder.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;
                for ip in registry.reap_expired() {
                    // Unregister before releasing: otherwise the forwarder
                    // would still hold a queue for an address about to be
                    // handed to a different client.
                    forwarder.unregister_client(ip);
                    ip_allocator.release(ip);
                    tracing::info!(tunnel_ip = %ip, "session expired, address reclaimed");
                }
            }
        });
    }

    // Accept loop
    let active_clients = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        let (tls_stream, peer_addr) = listener.accept().await?;

        let current = active_clients.load(std::sync::atomic::Ordering::Relaxed);
        if current >= config.max_clients {
            tracing::warn!(peer = %peer_addr, "max clients reached, rejecting");
            drop(tls_stream);
            continue;
        }

        let assigned_ip = match ip_allocator.allocate() {
            Some(ip) => ip,
            None => {
                tracing::error!("IP pool exhausted");
                continue;
            }
        };

        let config = config.clone();
        let forwarder = forwarder.clone();
        let active_clients = active_clients.clone();
        let ip_allocator = ip_allocator.clone();
        let registry = registry.clone();
        let admitter = admitter.clone();
        active_clients.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            let session = ClientSession::new(tls_stream, peer_addr, config, assigned_ip);
            match session.run(forwarder, registry, admitter).await {
                // A resuming connection never touched the address we reserved
                // for it, so it goes straight back.
                Ok(ConnectionOutcome::AddressUnused) => ip_allocator.release(assigned_ip),
                Ok(ConnectionOutcome::AddressTaken) => {}
                Err(e) => {
                    tracing::error!(peer = %peer_addr, error = %e, "session error");
                    ip_allocator.release(assigned_ip);
                }
            }
            active_clients.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}

fn cmd_init(config_path: &PathBuf) -> anyhow::Result<()> {
    if config_path.exists() {
        anyhow::bail!("file already exists: {:?}", config_path);
    }

    let template = r#"# Kanrin Server Configuration
# Harbor — exit node

# Listen address
listen: "0.0.0.0:443"

# Shared secret (change this!)
password: "change-me-to-a-strong-password"

# TLS certificate and key (PEM format)
# Generate with: kanrin-server --gen-cert
tls_cert: "cert.pem"
tls_key: "key.pem"

# Maximum concurrent clients
max_clients: 256

# Log level: trace, debug, info, warn, error
log_level: "info"

# DNS servers for forwarding
dns:
  - "1.1.1.1"
  - "8.8.8.8"
"#;

    std::fs::write(config_path, template)?;
    println!("[+] Config template created: {:?}", config_path);
    Ok(())
}

fn cmd_gen_cert() -> anyhow::Result<()> {
    use rcgen::{CertificateParams, KeyPair};

    println!("[*] Generating self-signed TLS certificate...");

    let mut params = CertificateParams::new(vec!["kanrin-server".to_string()])?;
    params.not_after = rcgen::date_time_ymd(2030, 1, 1);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    std::fs::write("cert.pem", &cert_pem)?;
    std::fs::write("key.pem", &key_pem)?;

    println!("[+] cert.pem created");
    println!("[+] key.pem created");
    println!();
    println!("[!] These are self-signed certificates for testing/personal use.");
    println!("    For production, use Let's Encrypt or a real CA.");

    Ok(())
}
