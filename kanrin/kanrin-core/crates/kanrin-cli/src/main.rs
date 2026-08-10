use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use kanrin_client::config::KanrinConfig;
use kanrin_client::{ClientState, KanrinClient};

#[derive(Parser)]
#[command(name = "kanrin")]
#[command(version)]
#[command(about = "Kanrin — The ship that crossed the silence")]
struct Cli {
    /// Path to config file (YAML)
    #[arg(short, long, default_value = "kanrin.yml")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to VPN server
    Connect,
    /// Run network detection and report censorship state
    Detect,
    /// Validate configuration file
    Validate,
    /// Generate a minimal config file template
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .with_target(false)
        .init();

    match cli.command {
        Commands::Connect => cmd_connect(&cli.config).await?,
        Commands::Detect => cmd_detect().await?,
        Commands::Validate => cmd_validate(&cli.config)?,
        Commands::Init => cmd_init(&cli.config)?,
    }

    Ok(())
}

async fn cmd_connect(config_path: &PathBuf) -> Result<()> {
    let config = KanrinConfig::from_file(config_path)
        .map_err(|e| anyhow::anyhow!("config error: {}", e))?;

    println!("[*] Kanrin — connecting to {}:{}", config.server.address, config.server.port);

    let mut client = KanrinClient::new(config);
    let mut events = client.take_events().unwrap();

    client.start().map_err(|e| anyhow::anyhow!("{}", e))?;

    // Wait for events until Ctrl+C
    let (ctrlc_tx, mut ctrlc_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = ctrlc_tx.send(());
    });

    loop {
        tokio::select! {
            Some(event) = events.recv() => {
                match event {
                    kanrin_client::events::KanrinEvent::StateChanged(state) => {
                        println!("[*] State: {:?}", state);
                    }
                    kanrin_client::events::KanrinEvent::Connected { transport, endpoint, latency_ms } => {
                        println!("[+] Connected via {} to {} ({}ms)", transport, endpoint, latency_ms);
                    }
                    kanrin_client::events::KanrinEvent::TransportSwitched { from, to, reason } => {
                        println!("[~] Transport switched: {} -> {} ({})", from, to, reason);
                    }
                    kanrin_client::events::KanrinEvent::CensorshipDetected { state, suggested_transports } => {
                        println!("[!] Censorship: {} — suggested: {:?}", state, suggested_transports);
                    }
                    kanrin_client::events::KanrinEvent::StatsUpdate { bytes_sent, bytes_received, uptime_secs, .. } => {
                        println!("    TX: {} KB | RX: {} KB | Uptime: {}s",
                            bytes_sent / 1024, bytes_received / 1024, uptime_secs);
                    }
                    kanrin_client::events::KanrinEvent::Error(e) => {
                        eprintln!("[!] Error: {}", e);
                    }
                    _ => {}
                }
            }
            _ = &mut ctrlc_rx => {
                println!("\n[*] Disconnecting...");
                break;
            }
        }
    }

    // `stop()` shuts down the client's own runtime, which blocks. Doing that
    // directly here would drop a runtime from inside an async context and panic,
    // so it runs on a blocking thread instead.
    tokio::task::spawn_blocking(move || client.stop())
        .await
        .map_err(|e| anyhow::anyhow!("join: {}", e))?
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("[*] Disconnected.");
    Ok(())
}

async fn cmd_detect() -> Result<()> {
    println!("[*] Running network detection...");

    let detector = kanrin_engine::detection::NetworkDetector::new();
    let result = detector.detect().await;

    println!("[*] Results:");
    println!("    State: {:?}", result.state);
    println!("    UDP:   {}", if result.udp_available { "available" } else { "BLOCKED" });
    println!("    TCP:   {}", if result.tcp_available { "available" } else { "BLOCKED" });
    println!("    DNS:   {}", if result.dns_clean { "clean" } else { "POISONED" });
    println!("    Suggested transports: {:?}", detector.suggest_transport(result.state));

    Ok(())
}

fn cmd_validate(config_path: &PathBuf) -> Result<()> {
    match KanrinConfig::from_file(config_path) {
        Ok(config) => {
            println!("[+] Config is valid!");
            println!("    Server: {}:{}", config.server.address, config.server.port);
            println!("    Kill switch: {}", config.tun.kill_switch);
            println!("    Iran preset: {}", config.routing.iran_preset);
            Ok(())
        }
        Err(e) => {
            eprintln!("[!] Config error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_init(config_path: &PathBuf) -> Result<()> {
    if config_path.exists() {
        eprintln!("[!] File already exists: {:?}", config_path);
        std::process::exit(1);
    }

    let template = r#"# Kanrin Configuration
# The ship that crossed the silence

server:
  address: "your-server.example.com"
  port: 443
  password: "your-secret-password"
  # sni: "cover-domain.com"  # Optional SNI override

# All options below have sensible defaults — you can omit them.

# transport:
#   preferred: ["quic", "tls-tcp", "websocket"]
#   auto_switch: true

# tun:
#   kill_switch: true
#   allow_lan: true

# routing:
#   iran_preset: true
#   default_action: "proxy"

# stealth:
#   traffic_pattern: "adaptive"
#   fragment: true
"#;

    std::fs::write(config_path, template)?;
    println!("[+] Config template created: {:?}", config_path);
    println!("    Edit the server section with your server details.");
    Ok(())
}
