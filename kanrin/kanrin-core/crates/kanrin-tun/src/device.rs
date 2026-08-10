use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("failed to create TUN device: {0}")]
    CreateFailed(String),

    #[error("failed to configure TUN device: {0}")]
    ConfigFailed(String),

    #[error("read error: {0}")]
    ReadError(String),

    #[error("write error: {0}")]
    WriteError(String),

    #[error("device closed")]
    Closed,

    #[error("platform not supported")]
    Unsupported,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for creating a TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g. "kanrin0").
    pub name: String,
    /// IP address assigned to the TUN interface.
    pub address: IpAddr,
    /// Subnet mask.
    pub netmask: IpAddr,
    /// Gateway address (usually address + 1).
    pub gateway: IpAddr,
    /// DNS servers to assign.
    pub dns: Vec<IpAddr>,
    /// Maximum transmission unit.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "kanrin0".into(),
            address: "10.10.0.2".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            gateway: "10.10.0.1".parse().unwrap(),
            dns: vec!["10.10.0.1".parse().unwrap()],
            mtu: 1400,
        }
    }
}

/// Platform-agnostic TUN device handle.
pub struct TunDevice {
    #[cfg(windows)]
    inner: WindowsTun,
    #[cfg(target_os = "linux")]
    inner: LinuxTun,
    #[cfg(target_os = "macos")]
    inner: MacosTun,
    config: TunConfig,
}

impl TunDevice {
    /// Create and configure a new TUN device.
    pub fn create(config: TunConfig) -> Result<Self, TunError> {
        #[cfg(windows)]
        let inner = WindowsTun::create(&config)?;
        #[cfg(target_os = "linux")]
        let inner = LinuxTun::create(&config)?;
        #[cfg(target_os = "macos")]
        let inner = MacosTun::create(&config)?;
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        return Err(TunError::Unsupported);

        Ok(Self {
            inner,
            config,
        })
    }

    /// Read one IP packet from the TUN device.
    pub async fn read_packet(&self) -> Result<Vec<u8>, TunError> {
        self.inner.read_packet().await
    }

    /// Write one IP packet to the TUN device.
    pub async fn write_packet(&self, data: &[u8]) -> Result<(), TunError> {
        self.inner.write_packet(data).await
    }

    /// Get the device configuration.
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Close and destroy the TUN device.
    pub fn close(self) -> Result<(), TunError> {
        self.inner.close()
    }
}

// ============== Windows TUN (Wintun) ==============

#[cfg(windows)]
pub struct WindowsTun {
    session: std::sync::Arc<wintun::Session>,
    _adapter: std::sync::Arc<wintun::Adapter>,
}

#[cfg(windows)]
impl WindowsTun {
    fn create(config: &TunConfig) -> Result<Self, TunError> {
        let wintun_dll = unsafe { wintun::load() }
            .map_err(|e| TunError::CreateFailed(format!("failed to load wintun.dll: {}", e)))?;

        let adapter = wintun::Adapter::create(&wintun_dll, &config.name, "Kanrin", None)
            .map_err(|e| TunError::CreateFailed(format!("adapter create: {}", e)))?;

        // Set IP address via netsh (wintun doesn't do this itself)
        let ip_str = config.address.to_string();
        let mask_str = config.netmask.to_string();
        let output = std::process::Command::new("netsh")
            .args([
                "interface", "ip", "set", "address",
                &format!("name={}", config.name),
                "static", &ip_str, &mask_str, &config.gateway.to_string(),
            ])
            .output()
            .map_err(|e| TunError::ConfigFailed(format!("netsh: {}", e)))?;

        if !output.status.success() {
            tracing::warn!(
                "netsh set address may have failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Set DNS
        for dns in &config.dns {
            let _ = std::process::Command::new("netsh")
                .args([
                    "interface", "ip", "set", "dns",
                    &format!("name={}", config.name),
                    "static", &dns.to_string(),
                ])
                .output();
        }

        // Set MTU
        let _ = std::process::Command::new("netsh")
            .args([
                "interface", "ipv4", "set", "subinterface",
                &config.name, &format!("mtu={}", config.mtu),
            ])
            .output();

        let session = adapter.start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| TunError::CreateFailed(format!("start session: {}", e)))?;

        Ok(Self {
            session: std::sync::Arc::new(session),
            _adapter: adapter,
        })
    }

    async fn read_packet(&self) -> Result<Vec<u8>, TunError> {
        let session = self.session.clone();
        tokio::task::spawn_blocking(move || {
            match session.receive_blocking() {
                Ok(packet) => Ok(packet.bytes().to_vec()),
                Err(e) => Err(TunError::ReadError(format!("{}", e))),
            }
        })
        .await
        .map_err(|e| TunError::ReadError(format!("join: {}", e)))?
    }

    async fn write_packet(&self, data: &[u8]) -> Result<(), TunError> {
        let mut packet = self.session.allocate_send_packet(data.len() as u16)
            .map_err(|e| TunError::WriteError(format!("allocate: {}", e)))?;
        packet.bytes_mut().copy_from_slice(data);
        self.session.send_packet(packet);
        Ok(())
    }

    fn close(self) -> Result<(), TunError> {
        let _ = self.session.shutdown();
        Ok(())
    }
}

// ============== Linux TUN ==============

#[cfg(target_os = "linux")]
pub struct LinuxTun {
    fd: std::os::unix::io::RawFd,
    name: String,
}

#[cfg(target_os = "linux")]
impl LinuxTun {
    fn create(config: &TunConfig) -> Result<Self, TunError> {
        use std::os::unix::io::FromRawFd;

        // Open /dev/net/tun
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 {
            return Err(TunError::CreateFailed("failed to open /dev/net/tun".into()));
        }

        // Set up the interface with ioctl
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = config.name.as_bytes();
        let name_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                name_len,
            );
        }

        // IFF_TUN | IFF_NO_PI
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;

        let ret = unsafe { libc::ioctl(fd, 0x400454CA /* TUNSETIFF */, &ifr) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(TunError::CreateFailed("TUNSETIFF ioctl failed".into()));
        }

        // Configure IP address via ip command
        let _ = std::process::Command::new("ip")
            .args(["addr", "add", &format!("{}/24", config.address), "dev", &config.name])
            .output();

        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &config.name, "up"])
            .output();

        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &config.name, "mtu", &config.mtu.to_string()])
            .output();

        Ok(Self { fd, name: config.name.clone() })
    }

    async fn read_packet(&self) -> Result<Vec<u8>, TunError> {
        let fd = self.fd;
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 1500];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                Err(TunError::ReadError("read failed".into()))
            } else {
                buf.truncate(n as usize);
                Ok(buf)
            }
        })
        .await
        .map_err(|e| TunError::ReadError(format!("join: {}", e)))?
    }

    async fn write_packet(&self, data: &[u8]) -> Result<(), TunError> {
        let fd = self.fd;
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            let n = unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
            if n < 0 {
                Err(TunError::WriteError("write failed".into()))
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| TunError::WriteError(format!("join: {}", e)))?
    }

    fn close(self) -> Result<(), TunError> {
        unsafe { libc::close(self.fd) };
        Ok(())
    }
}

// ============== macOS TUN ==============

#[cfg(target_os = "macos")]
pub struct MacosTun {
    fd: std::os::unix::io::RawFd,
    name: String,
}

#[cfg(target_os = "macos")]
impl MacosTun {
    fn create(config: &TunConfig) -> Result<Self, TunError> {
        // macOS uses utun devices (utun0, utun1, etc.)
        // Open a utun socket
        let fd = unsafe {
            libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
        };
        if fd < 0 {
            return Err(TunError::CreateFailed("failed to create utun socket".into()));
        }

        // TODO: Full utun setup with connect() and CTLIOCGINFO
        // For now, use the simpler approach with the `tun` command

        let _ = std::process::Command::new("ifconfig")
            .args([&config.name, &config.address.to_string(), &config.gateway.to_string(), "up"])
            .output();

        Ok(Self { fd, name: config.name.clone() })
    }

    async fn read_packet(&self) -> Result<Vec<u8>, TunError> {
        let fd = self.fd;
        tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; 1500];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 4 {
                return Err(TunError::ReadError("short read".into()));
            }
            // macOS utun prepends 4-byte AF header
            buf.drain(..4);
            buf.truncate((n as usize) - 4);
            Ok(buf)
        })
        .await
        .map_err(|e| TunError::ReadError(format!("join: {}", e)))?
    }

    async fn write_packet(&self, data: &[u8]) -> Result<(), TunError> {
        let fd = self.fd;
        // Prepend AF header for macOS
        let mut buf = Vec::with_capacity(4 + data.len());
        let af: u32 = if data[0] >> 4 == 4 { 2 } else { 30 }; // AF_INET or AF_INET6
        buf.extend_from_slice(&af.to_be_bytes());
        buf.extend_from_slice(data);

        tokio::task::spawn_blocking(move || {
            let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
            if n < 0 {
                Err(TunError::WriteError("write failed".into()))
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|e| TunError::WriteError(format!("join: {}", e)))?
    }

    fn close(self) -> Result<(), TunError> {
        unsafe { libc::close(self.fd) };
        Ok(())
    }
}
