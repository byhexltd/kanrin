use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("failed to add route: {0}")]
    AddFailed(String),

    #[error("failed to remove route: {0}")]
    RemoveFailed(String),

    #[error("failed to get default gateway")]
    NoDefaultGateway,
}

/// Saved original routing state for restoration.
#[derive(Debug, Clone)]
pub struct SavedRoutes {
    pub default_gateway: Option<IpAddr>,
    pub default_interface: Option<String>,
}

/// Manages system routing table to direct traffic through TUN.
pub struct RoutingManager {
    tun_name: String,
    tun_gateway: IpAddr,
    server_ips: Vec<IpAddr>,
    saved: Option<SavedRoutes>,
}

impl RoutingManager {
    pub fn new(tun_name: String, tun_gateway: IpAddr, server_ips: Vec<IpAddr>) -> Self {
        Self {
            tun_name,
            tun_gateway,
            server_ips,
            saved: None,
        }
    }

    /// Save current routes and redirect all traffic through TUN.
    pub fn activate(&mut self) -> Result<(), RouteError> {
        // Save original default route
        let saved = self.get_current_default_route()?;
        self.saved = Some(saved.clone());

        // Add specific route for server IPs through original gateway (bypass TUN)
        if let Some(ref gw) = saved.default_gateway {
            for server_ip in &self.server_ips {
                self.add_host_route(*server_ip, *gw)?;
            }
        }

        // Set TUN as default gateway (all traffic → TUN)
        self.set_default_route(self.tun_gateway)?;

        tracing::info!(tun = %self.tun_name, "routing activated — all traffic through TUN");
        Ok(())
    }

    /// Restore original routing table.
    pub fn deactivate(&mut self) -> Result<(), RouteError> {
        if let Some(ref saved) = self.saved.clone() {
            // Windows never modifies the real default route, so undoing simply
            // means dropping the split routes that were layered on top of it.
            #[cfg(windows)]
            {
                let _ = saved;
                self.clear_split_routes();
            }

            #[cfg(not(windows))]
            if let Some(gw) = saved.default_gateway {
                let _ = self.set_default_route(gw);
            }

            // Remove server-specific routes
            for server_ip in &self.server_ips {
                let _ = self.remove_host_route(*server_ip);
            }

            self.saved = None;
            tracing::info!("routing deactivated — original routes restored");
        }
        Ok(())
    }

    #[cfg(windows)]
    fn get_current_default_route(&self) -> Result<SavedRoutes, RouteError> {
        // Only physical adapters qualify as the uplink. Restricting to them
        // avoids picking a default route belonging to this or another VPN's
        // virtual adapter, which would send the tunnel's own packets into a
        // tunnel instead of out to the network.
        let script = "\
            $physical = (Get-NetAdapter -Physical -ErrorAction SilentlyContinue \
                | Where-Object Status -eq 'Up').ifIndex; \
            $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
                | Where-Object { $physical -contains $_.InterfaceIndex } \
                | Sort-Object RouteMetric | Select-Object -First 1; \
            if ($r) { \"$($r.NextHop) $($r.InterfaceIndex)\" }";

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output()
            .map_err(|_| RouteError::NoDefaultGateway)?;

        let text = String::from_utf8_lossy(&output.stdout);
        let mut parts = text.split_whitespace();

        let gateway = parts.next().and_then(|s| s.parse::<IpAddr>().ok());
        let if_index = parts.next().and_then(|s| s.parse::<u32>().ok());

        if gateway.is_none() {
            return Err(RouteError::NoDefaultGateway);
        }

        Ok(SavedRoutes {
            default_gateway: gateway,
            default_interface: if_index.map(|i| i.to_string()),
        })
    }

    /// Interface index of the TUN adapter, needed to pin routes to it.
    #[cfg(windows)]
    fn tun_if_index(&self) -> Option<u32> {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).ifIndex",
                    self.tun_name
                ),
            ])
            .output()
            .ok()?;

        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    }

    #[cfg(windows)]
    fn run_route(args: &[&str]) -> Result<(), RouteError> {
        let output = std::process::Command::new("route")
            .args(args)
            .output()
            .map_err(|e| RouteError::AddFailed(e.to_string()))?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(RouteError::AddFailed(format!(
                "route {} failed: {}{}",
                args.join(" "),
                stdout,
                stderr
            )));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_current_default_route(&self) -> Result<SavedRoutes, RouteError> {
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| RouteError::NoDefaultGateway)?;

        let line = String::from_utf8_lossy(&output.stdout);
        // Parse "default via X.X.X.X dev ethX"
        let gateway = line.split_whitespace()
            .skip_while(|&w| w != "via")
            .nth(1)
            .and_then(|s| s.parse::<IpAddr>().ok());

        let iface = line.split_whitespace()
            .skip_while(|&w| w != "dev")
            .nth(1)
            .map(|s| s.to_string());

        Ok(SavedRoutes {
            default_gateway: gateway,
            default_interface: iface,
        })
    }

    #[cfg(target_os = "macos")]
    fn get_current_default_route(&self) -> Result<SavedRoutes, RouteError> {
        let output = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| RouteError::NoDefaultGateway)?;

        let text = String::from_utf8_lossy(&output.stdout);
        let gateway = text.lines()
            .find(|l| l.contains("gateway:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|s| s.trim().parse::<IpAddr>().ok());

        Ok(SavedRoutes {
            default_gateway: gateway,
            default_interface: None,
        })
    }

    /// Capture all traffic without touching the existing default route.
    ///
    /// `0.0.0.0/1` and `128.0.0.0/1` together cover the whole address space and
    /// have a longer prefix than `0.0.0.0/0`, so they win route selection while
    /// the physical default route stays available for the tunnel's own packets.
    #[cfg(windows)]
    fn set_default_route(&self, gateway: IpAddr) -> Result<(), RouteError> {
        let gw = gateway.to_string();
        let if_index = self.tun_if_index();

        for prefix in ["0.0.0.0", "128.0.0.0"] {
            let mut args = vec!["add", prefix, "mask", "128.0.0.0", &gw, "metric", "1"];

            let index_str;
            if let Some(idx) = if_index {
                index_str = idx.to_string();
                args.push("if");
                args.push(&index_str);
            }

            if let Err(e) = Self::run_route(&args) {
                // A leftover route from an earlier run is not fatal — replace it.
                tracing::debug!(error = %e, prefix, "split route add failed, retrying as change");
                let mut change = args.clone();
                change[0] = "change";
                Self::run_route(&change)?;
            }
        }

        Ok(())
    }

    /// Remove the split routes installed by [`Self::set_default_route`].
    #[cfg(windows)]
    fn clear_split_routes(&self) {
        for prefix in ["0.0.0.0", "128.0.0.0"] {
            let _ = std::process::Command::new("route")
                .args(["delete", prefix, "mask", "128.0.0.0"])
                .output();
        }
    }

    #[cfg(target_os = "linux")]
    fn set_default_route(&self, gateway: IpAddr) -> Result<(), RouteError> {
        let _ = std::process::Command::new("ip")
            .args(["route", "replace", "default", "via", &gateway.to_string()])
            .output();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn set_default_route(&self, gateway: IpAddr) -> Result<(), RouteError> {
        let _ = std::process::Command::new("route")
            .args(["change", "default", &gateway.to_string()])
            .output();
        Ok(())
    }

    #[cfg(windows)]
    fn add_host_route(&self, host: IpAddr, gateway: IpAddr) -> Result<(), RouteError> {
        let host_str = host.to_string();
        let gw = gateway.to_string();

        let mut args = vec![
            "add",
            &host_str,
            "mask",
            "255.255.255.255",
            &gw,
            "metric",
            "1",
        ];

        // Pin to the physical uplink so this route cannot be resolved through
        // the tunnel, which would loop the tunnel's own traffic back into itself.
        let index_str;
        if let Some(idx) = self
            .saved
            .as_ref()
            .and_then(|s| s.default_interface.as_ref())
        {
            index_str = idx.clone();
            args.push("if");
            args.push(&index_str);
        }

        if let Err(e) = Self::run_route(&args) {
            tracing::debug!(error = %e, host = %host, "host route add failed, retrying as change");
            let mut change = args.clone();
            change[0] = "change";
            Self::run_route(&change)?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn add_host_route(&self, host: IpAddr, gateway: IpAddr) -> Result<(), RouteError> {
        std::process::Command::new("ip")
            .args(["route", "add", &format!("{}/32", host), "via", &gateway.to_string()])
            .output()
            .map_err(|e| RouteError::AddFailed(e.to_string()))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn add_host_route(&self, host: IpAddr, gateway: IpAddr) -> Result<(), RouteError> {
        std::process::Command::new("route")
            .args(["add", "-host", &host.to_string(), &gateway.to_string()])
            .output()
            .map_err(|e| RouteError::AddFailed(e.to_string()))?;
        Ok(())
    }

    #[cfg(windows)]
    fn remove_host_route(&self, host: IpAddr) -> Result<(), RouteError> {
        std::process::Command::new("route")
            .args(["delete", &host.to_string()])
            .output()
            .map_err(|e| RouteError::RemoveFailed(e.to_string()))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_host_route(&self, host: IpAddr) -> Result<(), RouteError> {
        std::process::Command::new("ip")
            .args(["route", "delete", &format!("{}/32", host)])
            .output()
            .map_err(|e| RouteError::RemoveFailed(e.to_string()))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn remove_host_route(&self, host: IpAddr) -> Result<(), RouteError> {
        std::process::Command::new("route")
            .args(["delete", "-host", &host.to_string()])
            .output()
            .map_err(|e| RouteError::RemoveFailed(e.to_string()))?;
        Ok(())
    }
}

impl Drop for RoutingManager {
    fn drop(&mut self) {
        if self.saved.is_some() {
            tracing::warn!("routing still modified during drop — restoring");
            let _ = self.deactivate();
        }
    }
}
