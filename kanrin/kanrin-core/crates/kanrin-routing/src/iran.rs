use crate::rules::{DomainRule, RouteDecision, RoutingEngine};

/// Load the default Iran routing preset.
/// Bypasses all Iranian traffic (domains + IPs) to go direct.
pub fn load_iran_preset(engine: &mut RoutingEngine) {
    // Iranian TLD
    engine.add_rule(Box::new(DomainRule {
        pattern: "*.ir".into(),
        decision: RouteDecision::Direct,
        priority: 100,
    }));

    // Common Iranian domains that should bypass
    let iran_domains = [
        "*.digikala.com",
        "*.divar.ir",
        "*.snapp.ir",
        "*.shaparak.ir",
        "*.bmi.ir",
        "*.mellat.ir",
        "*.parsian-bank.ir",
        "*.bpi.ir",
        "*.bankmelli-iran.com",
        "*.irancell.ir",
        "*.mci.ir",
        "*.aparat.com",
        "*.filimo.com",
        "*.namava.ir",
        "*.telewebion.com",
        "*.varzesh3.com",
        "*.zoomit.ir",
        "*.cafebazaar.ir",
        "*.myket.ir",
    ];

    for (i, domain) in iran_domains.iter().enumerate() {
        engine.add_rule(Box::new(DomainRule {
            pattern: domain.to_string(),
            decision: RouteDecision::Direct,
            priority: 101 + i as u32,
        }));
    }

    // Private/LAN ranges should always be direct
    let private_ranges = [
        ("*.local", 200),
        ("*.localhost", 201),
        ("*.lan", 202),
    ];

    for (pattern, priority) in private_ranges {
        engine.add_rule(Box::new(DomainRule {
            pattern: pattern.into(),
            decision: RouteDecision::Direct,
            priority,
        }));
    }
}

/// List of known Iranian ASN IP ranges (sample — full list loaded from file).
/// In production, this would be loaded from an updatable binary file.
pub fn iran_ip_ranges() -> Vec<(u32, u8)> {
    // Format: (network_as_u32, prefix_length)
    // These are sample ranges — real implementation loads from data file.
    vec![
        // 2.144.0.0/14 - Irancell
        (0x02900000, 14),
        // 5.22.0.0/17 - Shatel
        (0x05160000, 17),
        // 5.52.0.0/15 - MCI
        (0x05340000, 15),
        // 31.56.0.0/14 - MCI
        (0x1F380000, 14),
        // 37.32.0.0/14 - Pars Online
        (0x25200000, 14),
        // 46.209.0.0/16 - Irancell
        (0x2ED10000, 16),
        // 77.81.128.0/18 - Rightel
        (0x4D518000, 18),
        // 91.92.192.0/18 - AFRANET
        (0x5B5CC000, 18),
        // 185.4.0.0/22 - Asiatech
        (0xB9040000, 22),
        // 217.218.0.0/15 - DCI
        (0xD9DA0000, 15),
    ]
}
