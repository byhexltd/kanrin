# Kanrin — Key Data Structures

> Complete reference of all major structs, enums, and traits.

---

## `kanrin-protocol` (shared between client & server)

### Crypto
```rust
pub struct SessionKeys {
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
    pub client_write_nonce: u64,
    pub server_write_nonce: u64,
}

pub struct HandshakeKeys {
    pub ephemeral_private: x25519::StaticSecret,
    pub ephemeral_public: x25519::PublicKey,
    pub shared_secret: [u8; 32],
}

pub struct KeyDerivation {
    pub master_secret: [u8; 32],
    pub salt: [u8; 16],
}
```

### Wire Format
```rust
pub enum ChunkType {
    Handshake = 0x01,
    Data = 0x02,
    Control = 0x03,
    Padding = 0x04,
}

pub struct ChunkHeader {
    pub version: u8,
    pub chunk_type: ChunkType,
    pub payload_length: u16,
    pub padding_length: u8,
}

pub struct Chunk {
    pub header: ChunkHeader,
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
    pub tag: [u8; 16],
}

pub enum ControlMessage {
    Ping { timestamp: u64 },
    Pong { timestamp: u64 },
    ConfigUpdate { config_hash: [u8; 32], url: String },
    ScoreReport { node_id: String, score: f32 },
    SessionMigrate { new_session_token: Vec<u8> },
    Disconnect { reason: DisconnectReason },
}

pub enum ProxyRequest {
    TcpConnect { address: String, port: u16 },
    UdpDatagram { session_id: u32, address: String, port: u16, data: Vec<u8> },
    DnsQuery { id: u16, query: Vec<u8> },
}

pub enum DisconnectReason {
    ClientClose,
    ServerClose,
    AuthFailed,
    TrafficExceeded,
    Expired,
    Timeout,
}
```

### Handshake
```rust
pub struct ClientHello {
    pub protocol_version: u8,
    pub ephemeral_public: [u8; 32],
    pub timestamp: u64,
    pub random: [u8; 32],
}

pub struct ServerHello {
    pub ephemeral_public: [u8; 32],
    pub encrypted_session_token: Vec<u8>,
    pub server_random: [u8; 32],
}

pub struct ClientFinished {
    pub encrypted_auth: Vec<u8>,
}

pub struct ServerFinished {
    pub status: AuthStatus,
    pub config_hint: Option<Vec<u8>>,
}

pub enum AuthStatus { Ok, InvalidCredentials, RateLimited, ServerFull }

pub enum HandshakePhase { Initial, HelloSent, HelloReceived, Finished }

pub struct HandshakeState {
    phase: HandshakePhase,
    my_ephemeral: x25519::StaticSecret,
    peer_ephemeral: Option<x25519::PublicKey>,
    shared_secret: Option<[u8; 32]>,
}
```

### Session
```rust
pub struct SessionId([u8; 16]);

pub enum SessionState { Handshaking, Active, Migrating, Suspended, Closed }

pub struct Session {
    pub id: SessionId,
    pub keys: SessionKeys,
    pub state: SessionState,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub migration_token: Option<Vec<u8>>,
}

pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    max_sessions: usize,
    idle_timeout: Duration,
}
```

---

## `kanrin-transport`

```rust
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn priority(&self) -> u8;
    async fn probe(&self) -> ProbeResult;
    async fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn Connection>>;
    fn estimated_latency(&self) -> u32;
    fn supports_zero_rtt(&self) -> bool;
}

#[async_trait]
pub trait Connection: Send + Sync {
    async fn send(&mut self, data: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<Vec<u8>>;
    async fn close(&mut self) -> Result<()>;
    fn is_alive(&self) -> bool;
}

pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
}

pub enum ProbeResult {
    Available { latency_ms: u32 },
    Blocked { reason: String },
    Unknown,
}

pub enum CongestionAlgorithm { Brutal { bandwidth_mbps: u32 }, Bbr, Cubic, Adaptive }

pub enum TlsFingerprint { Chrome, Firefox, Safari, Random }
```

---

## `kanrin-tun`

```rust
pub struct TunDevice {
    name: String,
    mtu: u16,
    ip: IpAddr,
    gateway: IpAddr,
}

pub struct TunConfig {
    pub name: String,
    pub address: IpAddr,
    pub netmask: IpAddr,
    pub gateway: IpAddr,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
}

pub enum IpPacket { V4(Ipv4Packet), V6(Ipv6Packet) }

pub struct Ipv4Packet {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: IpProtocol,
    pub payload: TransportPacket,
    pub raw: Vec<u8>,
}

pub enum TransportPacket {
    Tcp(TcpSegment),
    Udp(UdpDatagram),
    Icmp(IcmpPacket),
    Other(Vec<u8>),
}

pub struct NatTable {
    tcp_entries: HashMap<(SocketAddr, SocketAddr), NatEntry>,
    udp_entries: HashMap<(SocketAddr, SocketAddr), NatEntry>,
    timeout: Duration,
}

pub struct NatEntry {
    pub local_addr: SocketAddr,
    pub mapped_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

pub struct DnsInterceptor {
    upstream: SocketAddr,
    cache: LruCache<String, DnsRecord>,
    fake_ip_pool: FakeIpPool,
}

pub struct KillSwitch {
    platform: PlatformFirewall,
    active: bool,
    allowed_ips: Vec<IpAddr>,
    allowed_lan: bool,
}
```

---

## `kanrin-stealth`

```rust
#[async_trait]
pub trait StealthModule: Send + Sync {
    fn name(&self) -> &str;
    async fn transform_outgoing(&self, data: &[u8], ctx: &StealthContext) -> Result<Vec<u8>>;
    async fn transform_incoming(&self, data: &[u8], ctx: &StealthContext) -> Result<Vec<u8>>;
    async fn generate_cover_traffic(&self, ctx: &StealthContext) -> Option<Vec<u8>>;
}

pub struct StealthContext {
    pub current_time: Instant,
    pub bytes_sent_total: u64,
    pub bytes_recv_total: u64,
    pub connection_duration: Duration,
    pub transport_name: String,
}

pub enum TrafficPattern { VideoStreaming, WebBrowsing, FileDownload, Messaging, Adaptive }

pub struct RhythmEngine {
    pattern: TrafficPattern,
    state: RhythmState,
}

pub struct FragmentConfig {
    pub min_fragment_size: usize,
    pub max_fragment_size: usize,
    pub delay_between_ms: Range<u64>,
    pub split_at_sni: bool,
}
```

---

## `kanrin-routing`

```rust
pub enum RouteDecision { Proxy, Direct, Block, CustomDns(IpAddr) }

pub trait RoutingRule: Send + Sync {
    fn matches(&self, ctx: &RoutingContext) -> bool;
    fn decision(&self) -> RouteDecision;
    fn priority(&self) -> u32;
}

pub struct RoutingContext {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub domain: Option<String>,
    pub protocol: IpProtocol,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

pub struct RoutingEngine {
    rules: Vec<Box<dyn RoutingRule>>,
    geoip: GeoIpDatabase,
    domain_lists: DomainListManager,
}
```

---

## `kanrin-engine`

```rust
pub struct Prober {
    interval: Duration,
    endpoints: Vec<Endpoint>,
    results: Arc<RwLock<HashMap<Endpoint, ProbeHistory>>>,
}

pub struct ProbeHistory {
    pub last_10_results: VecDeque<ProbeResult>,
    pub avg_latency_ms: f64,
    pub success_rate: f64,
    pub last_checked: Instant,
}

pub struct ScoreBoard {
    local_scores: HashMap<String, f64>,
    collective_scores: HashMap<String, f64>,
    weights: ScoreWeights,
}

pub struct Switcher {
    current_transport: Arc<RwLock<Box<dyn Transport>>>,
    current_endpoint: Arc<RwLock<Endpoint>>,
    scoreboard: Arc<ScoreBoard>,
    switch_threshold: f64,
    cooldown: Duration,
    last_switch: Instant,
}

pub enum NetworkState {
    Normal,
    UdpBlocked,
    DirectIpBlocked,
    WebSocketBlocked,
    SniFiltering,
    TotalShutdown,
    NationalIntranet,
}

pub trait BootstrapMethod: Send + Sync {
    fn name(&self) -> &str;
    async fn discover(&self) -> Result<Vec<Endpoint>>;
}
```

---

## `kanrin-client`

```rust
pub struct KanrinClient {
    engine: Engine,
    tun: TunDevice,
    kill_switch: KillSwitch,
    routing: RoutingEngine,
    state: Arc<RwLock<ClientState>>,
}

pub enum ClientState {
    Disconnected,
    Connecting { transport: String },
    Connected { transport: String, latency_ms: u32 },
    Reconnecting { reason: String },
    Error { message: String, recoverable: bool },
}

pub struct ClientConfig {
    pub server: String,
    pub password: String,
    pub mode: ConnectionMode,
    pub transport: Option<TransportConfig>,
    pub routing: Option<RoutingConfig>,
    pub stealth: Option<StealthConfig>,
    pub kill_switch: bool,
    pub dns: Option<DnsConfig>,
}

pub enum ConnectionMode { Auto, Manual }

pub enum KanrinEvent {
    StateChanged(ClientState),
    TransportSwitched { from: String, to: String, reason: String },
    SpeedUpdate { download_bps: u64, upload_bps: u64 },
    LatencyUpdate { ms: u32 },
    Error { message: String, severity: Severity },
    Log { level: LogLevel, module: String, message: String },
}
```

---

## `kanrin-server`

```rust
pub struct KanrinServer {
    config: ServerConfig,
    session_manager: SessionManager,
    ingest: IngestManager,
    masquerade: MasqueradeServer,
    user_manager: UserManager,
    metrics: MetricsCollector,
}

pub struct ServerConfig {
    pub listen: SocketAddr,
    pub domain: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub users: Vec<UserConfig>,
    pub masquerade: MasqueradeConfig,
}

pub struct UserConfig {
    pub name: String,
    pub password: String,
    pub traffic_limit: Option<u64>,
    pub speed_limit: Option<u64>,
    pub max_connections: Option<u32>,
    pub expiry: Option<DateTime<Utc>>,
}

pub enum MasqueradeMode {
    StaticFiles(PathBuf),
    ReverseProxy(Url),
    Mirror(String),
}
```

---

## `kanrin-plugin`

```rust
pub enum PluginType { Transport, Stealth, Routing, Observer }

pub enum Capability { NetworkAccess, FileRead, EventEmit, CryptoAccess }

pub struct PluginRuntime {
    engine: wasmtime::Engine,
    plugins: Vec<LoadedPlugin>,
}

pub struct LoadedPlugin {
    pub name: String,
    pub version: String,
    pub plugin_type: PluginType,
    pub instance: wasmtime::Instance,
}

pub struct PluginRegistry {
    search_paths: Vec<PathBuf>,
    loaded: HashMap<String, LoadedPlugin>,
}
```
