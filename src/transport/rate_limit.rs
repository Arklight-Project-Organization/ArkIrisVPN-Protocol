//! Token-bucket bandwidth limiter.

use crate::constants::RATE_LIMIT_DEFAULT_BURST_SECONDS;
use std::time::Instant;

#[derive(Clone)]
pub struct RateLimiter {
    limit_bytes_per_sec: f64,
    burst_bytes: f64,
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(limit_mbps: f64) -> Self {
        Self::new_with_burst(limit_mbps, RATE_LIMIT_DEFAULT_BURST_SECONDS)
    }

    pub fn new_with_burst(limit_mbps: f64, burst_seconds: f64) -> Self {
        let bps = if limit_mbps > 0.0 {
            limit_mbps * 1024.0 * 1024.0 / 8.0
        } else {
            0.0
        };
        let burst = burst_seconds.max(0.01);
        let burst_bytes = if bps > 0.0 { bps * burst } else { 0.0 };
        Self {
            limit_bytes_per_sec: bps,
            burst_bytes,
            tokens: burst_bytes,
            last_update: Instant::now(),
        }
    }

    pub fn allow(&mut self, bytes: usize) -> bool {
        if self.limit_bytes_per_sec == 0.0 {
            return true;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.tokens = (self.tokens + elapsed * self.limit_bytes_per_sec).min(self.burst_bytes);
        let required = bytes as f64;
        if self.tokens >= required {
            self.tokens -= required;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_limiter_allows_any_packet() {
        let mut limiter = RateLimiter::new(0.0);
        assert!(limiter.allow(usize::MAX));
    }

    #[test]
    fn burst_is_bounded() {
        let limiter = RateLimiter::new_with_burst(10.0, 2.0);
        assert!(limiter.burst_bytes >= limiter.limit_bytes_per_sec * 1.9);
        assert!(limiter.burst_bytes <= limiter.limit_bytes_per_sec * 2.1);
    }
}
