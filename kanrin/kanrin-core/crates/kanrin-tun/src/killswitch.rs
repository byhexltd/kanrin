use std::net::IpAddr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KillSwitchError {
    #[error("failed to activate kill switch: {0}")]
    ActivateFailed(String),

    #[error("failed to deactivate kill switch: {0}")]
    DeactivateFailed(String),

    #[error("platform not supported")]
    Unsupported,
}

/// Kill switch configuration.
#[derive(Debug, Clone)]
pub struct KillSwitchConfig {
    /// IPs that must remain reachable (the Kanrin server).
    pub allowed_ips: Vec<IpAddr>,
    /// Allow LAN traffic when kill switch is active.
    pub allow_lan: bool,
    /// Allow loopback (127.0.0.1).
    pub allow_loopback: bool,
}

/// Kill switch that blocks all traffic if the tunnel drops.
pub struct KillSwitch {
    config: KillSwitchConfig,
    active: bool,
}

impl KillSwitch {
    pub fn new(config: KillSwitchConfig) -> Self {
        Self {
            config,
            active: false,
        }
    }

    /// Activate the kill switch (block all non-tunnel traffic).
    pub fn activate(&mut self) -> Result<(), KillSwitchError> {
        if self.active {
            return Ok(());
        }

        #[cfg(windows)]
        self.activate_windows()?;

        #[cfg(target_os = "linux")]
        self.activate_linux()?;

        #[cfg(target_os = "macos")]
        self.activate_macos()?;

        self.active = true;
        tracing::info!("kill switch activated");
        Ok(())
    }

    /// Deactivate the kill switch (restore normal networking).
    pub fn deactivate(&mut self) -> Result<(), KillSwitchError> {
        if !self.active {
            return Ok(());
        }

        #[cfg(windows)]
        self.deactivate_windows()?;

        #[cfg(target_os = "linux")]
        self.deactivate_linux()?;

        #[cfg(target_os = "macos")]
        self.deactivate_macos()?;

        self.active = false;
        tracing::info!("kill switch deactivated");
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    // ===== Windows (netsh/WFP) =====

    #[cfg(windows)]
    fn activate_windows(&self) -> Result<(), KillSwitchError> {
        // In Windows Firewall, explicit block rules take precedence over allow
        // rules. So instead of adding a "block all" rule (which would also kill
        // the tunnel itself), we change the default outbound policy to block and
        // then add explicit allow rules for the traffic we need.
        let rule_name = "KanrinKillSwitch";

        // Add allow rules BEFORE changing the default policy, so the tunnel is
        // never interrupted.
        for (i, ip) in self.config.allowed_ips.iter().enumerate() {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}_allow_{}", rule_name, i),
                    "dir=out", "action=allow",
                    &format!("remoteip={}", ip),
                    "enable=yes",
                ])
                .output();
        }

        // Allow all traffic leaving through the TUN interface
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}_tun", rule_name),
                "dir=out", "action=allow",
                "remoteip=any",
                "localip=10.10.0.0/24",
                "enable=yes",
            ])
            .output();

        // Allow loopback
        if self.config.allow_loopback {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}_loopback", rule_name),
                    "dir=out", "action=allow",
                    "remoteip=127.0.0.0/8",
                    "enable=yes",
                ])
                .output();
        }

        // Allow LAN
        if self.config.allow_lan {
            for range in &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
                let _ = std::process::Command::new("netsh")
                    .args([
                        "advfirewall", "firewall", "add", "rule",
                        &format!("name={}_lan", rule_name),
                        "dir=out", "action=allow",
                        &format!("remoteip={}", range),
                        "enable=yes",
                    ])
                    .output();
            }
        }

        // Allow DHCP and DNS so the machine keeps basic connectivity
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}_dhcp", rule_name),
                "dir=out", "action=allow",
                "protocol=udp", "remoteport=67,68",
                "enable=yes",
            ])
            .output();

        // Finally, switch the default outbound policy to block.
        let output = std::process::Command::new("netsh")
            .args([
                "advfirewall", "set", "allprofiles",
                "firewallpolicy", "blockinbound,blockoutbound",
            ])
            .output()
            .map_err(|e| KillSwitchError::ActivateFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(KillSwitchError::ActivateFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(windows)]
    fn deactivate_windows(&self) -> Result<(), KillSwitchError> {
        // Restore the default outbound policy FIRST so connectivity comes back
        // even if rule deletion fails.
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall", "set", "allprofiles",
                "firewallpolicy", "blockinbound,allowoutbound",
            ])
            .output();

        // Remove the allow rules we added
        for i in 0..self.config.allowed_ips.len() {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "delete", "rule",
                    &format!("name=KanrinKillSwitch_allow_{}", i),
                ])
                .output();
        }

        for suffix in &["_tun", "_loopback", "_lan", "_dhcp"] {
            let _ = std::process::Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "delete", "rule",
                    &format!("name=KanrinKillSwitch{}", suffix),
                ])
                .output();
        }

        Ok(())
    }

    // ===== Linux (nftables) =====

    #[cfg(target_os = "linux")]
    fn activate_linux(&self) -> Result<(), KillSwitchError> {
        // Add nftables rules
        let mut rules = String::from("#!/usr/sbin/nft -f\n");
        rules.push_str("add table inet kanrin_killswitch\n");
        rules.push_str("add chain inet kanrin_killswitch output { type filter hook output priority 0; policy drop; }\n");

        // Allow loopback
        if self.config.allow_loopback {
            rules.push_str("add rule inet kanrin_killswitch output oifname \"lo\" accept\n");
        }

        // Allow server IPs
        for ip in &self.config.allowed_ips {
            rules.push_str(&format!(
                "add rule inet kanrin_killswitch output ip daddr {} accept\n", ip
            ));
        }

        // Allow LAN
        if self.config.allow_lan {
            rules.push_str("add rule inet kanrin_killswitch output ip daddr 10.0.0.0/8 accept\n");
            rules.push_str("add rule inet kanrin_killswitch output ip daddr 172.16.0.0/12 accept\n");
            rules.push_str("add rule inet kanrin_killswitch output ip daddr 192.168.0.0/16 accept\n");
        }

        // Allow TUN interface
        rules.push_str("add rule inet kanrin_killswitch output oifname \"kanrin*\" accept\n");

        std::process::Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .output()
            .map_err(|e| KillSwitchError::ActivateFailed(e.to_string()))?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn deactivate_linux(&self) -> Result<(), KillSwitchError> {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "kanrin_killswitch"])
            .output();
        Ok(())
    }

    // ===== macOS (pf) =====

    #[cfg(target_os = "macos")]
    fn activate_macos(&self) -> Result<(), KillSwitchError> {
        // Write pf rules to temp file and load
        let mut rules = String::new();
        rules.push_str("# Kanrin Kill Switch\n");
        rules.push_str("block out all\n");

        if self.config.allow_loopback {
            rules.push_str("pass out on lo0 all\n");
        }

        for ip in &self.config.allowed_ips {
            rules.push_str(&format!("pass out to {} all\n", ip));
        }

        if self.config.allow_lan {
            rules.push_str("pass out to 10.0.0.0/8 all\n");
            rules.push_str("pass out to 172.16.0.0/12 all\n");
            rules.push_str("pass out to 192.168.0.0/16 all\n");
        }

        rules.push_str("pass out on utun* all\n");

        let rules_path = "/tmp/kanrin_killswitch.conf";
        std::fs::write(rules_path, &rules)
            .map_err(|e| KillSwitchError::ActivateFailed(e.to_string()))?;

        let _ = std::process::Command::new("pfctl")
            .args(["-f", rules_path, "-e"])
            .output();

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn deactivate_macos(&self) -> Result<(), KillSwitchError> {
        let _ = std::process::Command::new("pfctl")
            .args(["-d"])
            .output();
        let _ = std::fs::remove_file("/tmp/kanrin_killswitch.conf");
        Ok(())
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.active {
            tracing::warn!("kill switch still active during drop — deactivating");
            let _ = self.deactivate();
        }
    }
}
