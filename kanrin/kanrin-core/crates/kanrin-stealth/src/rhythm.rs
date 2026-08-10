use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::traits::{StealthContext, StealthModule};

/// Traffic patterns that mimic real user behavior.
#[derive(Debug, Clone, Copy)]
pub enum TrafficPattern {
    /// Mimic video streaming (large chunks with periodic pauses).
    VideoStreaming,
    /// Mimic web browsing (bursts followed by silence).
    WebBrowsing,
    /// Mimic file download (steady high throughput).
    FileDownload,
    /// Mimic messaging (small packets, irregular timing).
    Messaging,
    /// Analyze and adapt to real traffic pattern.
    Adaptive,
}

/// Rhythm engine shapes traffic to match a target pattern.
pub struct RhythmEngine {
    pattern: TrafficPattern,
    last_send: Instant,
    bytes_in_window: u64,
    window_start: Instant,
}

impl RhythmEngine {
    pub fn new(pattern: TrafficPattern) -> Self {
        let now = Instant::now();
        Self {
            pattern,
            last_send: now,
            bytes_in_window: 0,
            window_start: now,
        }
    }

    /// Calculate delay before sending next packet (to match pattern).
    pub fn next_delay(&self) -> Duration {
        match self.pattern {
            TrafficPattern::VideoStreaming => {
                // Large bursts every 2-4 seconds (buffer fill)
                let since_last = self.last_send.elapsed();
                if since_last < Duration::from_millis(50) {
                    Duration::from_millis(0) // Still in burst
                } else {
                    Duration::from_millis(2000 + (rand::random::<u64>() % 2000))
                }
            }
            TrafficPattern::WebBrowsing => {
                // Quick burst then 1-5s silence
                let since_last = self.last_send.elapsed();
                if since_last < Duration::from_millis(100) {
                    Duration::from_millis(5 + (rand::random::<u64>() % 20))
                } else {
                    Duration::from_millis(1000 + (rand::random::<u64>() % 4000))
                }
            }
            TrafficPattern::FileDownload => {
                // Steady with minimal gaps
                Duration::from_millis(1 + (rand::random::<u64>() % 5))
            }
            TrafficPattern::Messaging => {
                // Irregular gaps between small messages
                Duration::from_millis(500 + (rand::random::<u64>() % 5000))
            }
            TrafficPattern::Adaptive => {
                // No modification — pass through
                Duration::from_millis(0)
            }
        }
    }

    /// Suggested padding size for current pattern.
    pub fn suggested_padding(&self, payload_size: usize) -> usize {
        match self.pattern {
            TrafficPattern::VideoStreaming => {
                // Pad to multiples of 1400 (MTU-like)
                let target = ((payload_size / 1400) + 1) * 1400;
                target - payload_size
            }
            TrafficPattern::WebBrowsing => {
                // Pad to powers of 2 (common web object sizes)
                let next_pow2 = payload_size.next_power_of_two();
                next_pow2 - payload_size
            }
            TrafficPattern::FileDownload => {
                // Minimal padding
                rand::random::<usize>() % 16
            }
            TrafficPattern::Messaging => {
                // Pad all messages to 256 bytes
                if payload_size < 256 {
                    256 - payload_size
                } else {
                    rand::random::<usize>() % 32
                }
            }
            TrafficPattern::Adaptive => 0,
        }
    }
}

#[async_trait]
impl StealthModule for RhythmEngine {
    fn name(&self) -> &str {
        "rhythm"
    }

    async fn transform_outgoing(&self, data: &[u8], _ctx: &StealthContext) -> Vec<u8> {
        // For now, pass through. Delay injection is handled by the pipeline scheduler.
        data.to_vec()
    }

    async fn transform_incoming(&self, data: &[u8], _ctx: &StealthContext) -> Vec<u8> {
        data.to_vec()
    }

    async fn generate_cover_traffic(&self, ctx: &StealthContext) -> Option<Vec<u8>> {
        // Generate cover traffic if connection has been idle for too long
        let idle_threshold = match self.pattern {
            TrafficPattern::VideoStreaming => Duration::from_secs(5),
            TrafficPattern::WebBrowsing => Duration::from_secs(10),
            TrafficPattern::FileDownload => Duration::from_secs(2),
            TrafficPattern::Messaging => Duration::from_secs(30),
            TrafficPattern::Adaptive => return None,
        };

        if ctx.connection_duration > idle_threshold {
            // Generate random cover traffic (will be sent as Padding chunk)
            let size = match self.pattern {
                TrafficPattern::VideoStreaming => 1400,
                TrafficPattern::WebBrowsing => 256,
                TrafficPattern::FileDownload => 1400,
                TrafficPattern::Messaging => 64,
                TrafficPattern::Adaptive => return None,
            };
            Some(vec![0u8; size]) // Content doesn't matter — it's encrypted
        } else {
            None
        }
    }
}
