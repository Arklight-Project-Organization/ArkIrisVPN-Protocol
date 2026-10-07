//! Byte-time pacing for the outbound data plane.
//!
//! Pacing is deliberately time based rather than sleep-per-packet. The
//! scheduler can therefore batch packets when the deadline is already due,
//! while LDT packets are allowed a small bounded bypass to avoid adding a
//! queueing delay to interactive traffic.

use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Pacer {
    rate_bytes_per_sec: f64,
    next_deadline: Instant,
    min_interval: Duration,
}

impl Pacer {
    pub fn new(rate_mbps: f64) -> Self {
        let rate = if rate_mbps.is_finite() && rate_mbps > 0.0 {
            rate_mbps * 1024.0 * 1024.0 / 8.0
        } else { 0.0 };
        Self { rate_bytes_per_sec: rate, next_deadline: Instant::now(), min_interval: Duration::from_micros(80) }
    }

    pub fn enabled(&self) -> bool { self.rate_bytes_per_sec > 0.0 }

    pub fn deadline_for(&mut self, bytes: usize, ldt: bool, now: Instant) -> Instant {
        if self.rate_bytes_per_sec <= 0.0 { return now; }
        let due = self.next_deadline.max(now);
        let interval = Duration::from_secs_f64((bytes.max(1) as f64 / self.rate_bytes_per_sec).max(self.min_interval.as_secs_f64()));
        self.next_deadline = due + interval;
        if ldt { due.min(now + Duration::from_micros(250)) } else { due }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacing_deadline_moves_forward() {
        let mut p = Pacer::new(1000.0);
        let now = Instant::now();
        let a = p.deadline_for(1200, false, now);
        let b = p.deadline_for(1200, false, now);
        assert!(b >= a);
    }
}
