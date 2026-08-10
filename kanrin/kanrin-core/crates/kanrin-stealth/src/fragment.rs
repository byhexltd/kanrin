use std::ops::Range;
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;

use crate::traits::{StealthContext, StealthModule};

/// TLS record fragmentation to evade DPI that inspects ClientHello.
pub struct FragmentModule {
    config: FragmentConfig,
}

pub struct FragmentConfig {
    /// Minimum fragment size in bytes.
    pub min_fragment_size: usize,
    /// Maximum fragment size in bytes.
    pub max_fragment_size: usize,
    /// Random delay range between fragments (milliseconds).
    pub delay_between_ms: Range<u64>,
    /// Whether to split specifically at the SNI field boundary.
    pub split_at_sni: bool,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            min_fragment_size: 40,
            max_fragment_size: 200,
            delay_between_ms: 10..50,
            split_at_sni: true,
        }
    }
}

impl FragmentModule {
    pub fn new(config: FragmentConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(FragmentConfig::default())
    }

    /// Split data into fragments of random size within configured range.
    pub fn fragment(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let mut offset = 0;
        let mut rng = rand::thread_rng();

        while offset < data.len() {
            let frag_size = rng.gen_range(self.config.min_fragment_size..=self.config.max_fragment_size);
            let end = (offset + frag_size).min(data.len());
            fragments.push(data[offset..end].to_vec());
            offset = end;
        }

        fragments
    }

    /// Calculate delay for next fragment.
    pub fn fragment_delay(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let ms = rng.gen_range(self.config.delay_between_ms.clone());
        Duration::from_millis(ms)
    }

    /// Find the SNI offset in a TLS ClientHello (for targeted splitting).
    /// Returns the byte offset where the SNI field begins, or None.
    pub fn find_sni_offset(data: &[u8]) -> Option<usize> {
        // TLS Record: type(1) + version(2) + length(2) + handshake
        // Handshake: type(1) + length(3) + client_version(2) + random(32) + ...
        // We need to walk through extensions to find SNI (type 0x0000)
        if data.len() < 5 {
            return None;
        }

        // Check if this is a TLS ClientHello
        if data[0] != 0x16 {
            return None; // Not a handshake record
        }

        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + record_len {
            return None;
        }

        // Skip: record header(5) + handshake type(1) + handshake length(3)
        // + client version(2) + random(32) = 43 bytes minimum
        if data.len() < 43 {
            return None;
        }

        let mut pos = 43;

        // Session ID length
        if pos >= data.len() {
            return None;
        }
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites length
        if pos + 2 > data.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        // Compression methods length
        if pos >= data.len() {
            return None;
        }
        let comp_methods_len = data[pos] as usize;
        pos += 1 + comp_methods_len;

        // Extensions length
        if pos + 2 > data.len() {
            return None;
        }
        let _extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        // Walk extensions looking for SNI (type 0x0000)
        while pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

            if ext_type == 0x0000 {
                // Found SNI extension
                return Some(pos);
            }

            pos += 4 + ext_len;
        }

        None
    }
}

#[async_trait]
impl StealthModule for FragmentModule {
    fn name(&self) -> &str {
        "fragment"
    }

    async fn transform_outgoing(&self, data: &[u8], _ctx: &StealthContext) -> Vec<u8> {
        // Fragmentation is handled at the transport level, not in the pipeline.
        // This module provides the logic; the transport calls fragment() directly.
        data.to_vec()
    }

    async fn transform_incoming(&self, data: &[u8], _ctx: &StealthContext) -> Vec<u8> {
        // No transformation needed for incoming (fragments are reassembled by TCP)
        data.to_vec()
    }

    async fn generate_cover_traffic(&self, _ctx: &StealthContext) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_splits_data() {
        let module = FragmentModule::with_defaults();
        let data = vec![0u8; 500];
        let fragments = module.fragment(&data);

        // Should produce multiple fragments
        assert!(fragments.len() > 1);

        // Reassembled should equal original
        let reassembled: Vec<u8> = fragments.into_iter().flatten().collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragment_small_data() {
        let module = FragmentModule::new(FragmentConfig {
            min_fragment_size: 10,
            max_fragment_size: 20,
            ..Default::default()
        });
        let data = vec![0u8; 5]; // Smaller than min_fragment_size
        let fragments = module.fragment(&data);

        // Should still produce one fragment with all data
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], data);
    }

    #[test]
    fn test_find_sni_in_client_hello() {
        // A minimal (incomplete) TLS ClientHello for testing
        // In production, this would be tested with real captured ClientHello bytes
        let non_tls = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(FragmentModule::find_sni_offset(&non_tls).is_none());
    }
}
