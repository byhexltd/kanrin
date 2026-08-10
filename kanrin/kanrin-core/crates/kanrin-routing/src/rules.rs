use std::net::IpAddr;

/// Decision for a given packet/connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    /// Send through the tunnel (proxy).
    Proxy,
    /// Send directly (bypass tunnel).
    Direct,
    /// Drop the packet/connection.
    Block,
}

/// Context for routing decisions.
#[derive(Debug, Clone)]
pub struct RoutingContext {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub domain: Option<String>,
    pub protocol: Protocol,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

/// A routing rule that can match traffic and decide its path.
pub trait RoutingRule: Send + Sync {
    /// Check if this rule matches the given context.
    fn matches(&self, ctx: &RoutingContext) -> bool;

    /// The decision if this rule matches.
    fn decision(&self) -> RouteDecision;

    /// Priority (lower = evaluated first).
    fn priority(&self) -> u32;

    /// Human-readable rule name.
    fn name(&self) -> &str;
}

/// The routing engine evaluates rules in priority order.
pub struct RoutingEngine {
    rules: Vec<Box<dyn RoutingRule>>,
    /// Default decision when no rule matches.
    default_decision: RouteDecision,
}

impl RoutingEngine {
    pub fn new(default_decision: RouteDecision) -> Self {
        Self {
            rules: Vec::new(),
            default_decision,
        }
    }

    /// Add a rule (auto-sorts by priority).
    pub fn add_rule(&mut self, rule: Box<dyn RoutingRule>) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority());
    }

    /// Decide the route for a given context.
    pub fn decide(&self, ctx: &RoutingContext) -> RouteDecision {
        for rule in &self.rules {
            if rule.matches(ctx) {
                tracing::trace!(
                    rule = rule.name(),
                    decision = ?rule.decision(),
                    domain = ?ctx.domain,
                    dst = %ctx.dst_ip,
                    "routing decision"
                );
                return rule.decision();
            }
        }
        self.default_decision
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Rule: match by domain pattern (e.g. "*.ir", "*.google.com")
pub struct DomainRule {
    pub pattern: String,
    pub decision: RouteDecision,
    pub priority: u32,
}

impl RoutingRule for DomainRule {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        let domain = match &ctx.domain {
            Some(d) => d,
            None => return false,
        };

        if self.pattern.starts_with("*.") {
            let suffix = &self.pattern[1..]; // ".ir", ".google.com"
            domain.ends_with(suffix) || domain == &self.pattern[2..]
        } else {
            domain == &self.pattern
        }
    }

    fn decision(&self) -> RouteDecision {
        self.decision
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn name(&self) -> &str {
        &self.pattern
    }
}

/// Rule: match by IP CIDR range.
pub struct IpRule {
    pub network: IpAddr,
    pub prefix_len: u8,
    pub decision: RouteDecision,
    pub priority: u32,
    pub label: String,
}

impl RoutingRule for IpRule {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        ip_in_cidr(ctx.dst_ip, self.network, self.prefix_len)
    }

    fn decision(&self) -> RouteDecision {
        self.decision
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn name(&self) -> &str {
        &self.label
    }
}

/// Rule: match by destination port.
pub struct PortRule {
    pub ports: Vec<u16>,
    pub decision: RouteDecision,
    pub priority: u32,
    pub label: String,
}

impl RoutingRule for PortRule {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        self.ports.contains(&ctx.dst_port)
    }

    fn decision(&self) -> RouteDecision {
        self.decision
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn name(&self) -> &str {
        &self.label
    }
}

/// Rule: match by process name.
pub struct ProcessRule {
    pub process_names: Vec<String>,
    pub decision: RouteDecision,
    pub priority: u32,
    pub label: String,
}

impl RoutingRule for ProcessRule {
    fn matches(&self, ctx: &RoutingContext) -> bool {
        match &ctx.process_name {
            Some(name) => self.process_names.iter().any(|p| {
                name.eq_ignore_ascii_case(p)
            }),
            None => false,
        }
    }

    fn decision(&self) -> RouteDecision {
        self.decision
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn name(&self) -> &str {
        &self.label
    }
}

/// Check if an IP is within a CIDR range.
fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let ip_bits = u32::from(ip);
            let net_bits = u32::from(net);
            let mask = if prefix_len >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let ip_bits = u128::from(ip);
            let net_bits = u128::from(net);
            let mask = if prefix_len >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false, // IPv4 vs IPv6 mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_domain_rule_wildcard() {
        let rule = DomainRule {
            pattern: "*.ir".into(),
            decision: RouteDecision::Direct,
            priority: 1,
        };

        let ctx = RoutingContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_port: 443,
            domain: Some("bank.ir".into()),
            protocol: Protocol::Tcp,
            process_name: None,
            process_path: None,
        };

        assert!(rule.matches(&ctx));
    }

    #[test]
    fn test_domain_rule_no_match() {
        let rule = DomainRule {
            pattern: "*.ir".into(),
            decision: RouteDecision::Direct,
            priority: 1,
        };

        let ctx = RoutingContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_port: 443,
            domain: Some("google.com".into()),
            protocol: Protocol::Tcp,
            process_name: None,
            process_path: None,
        };

        assert!(!rule.matches(&ctx));
    }

    #[test]
    fn test_ip_cidr_match() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let network: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(ip_in_cidr(ip, network, 24));
        assert!(!ip_in_cidr(ip, "10.0.0.0".parse().unwrap(), 8));
    }

    #[test]
    fn test_routing_engine_priority() {
        let mut engine = RoutingEngine::new(RouteDecision::Proxy);

        engine.add_rule(Box::new(DomainRule {
            pattern: "*.ir".into(),
            decision: RouteDecision::Direct,
            priority: 10,
        }));

        let ctx = RoutingContext {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)),
            dst_port: 443,
            domain: Some("test.ir".into()),
            protocol: Protocol::Tcp,
            process_name: None,
            process_path: None,
        };

        assert_eq!(engine.decide(&ctx), RouteDecision::Direct);
    }
}
