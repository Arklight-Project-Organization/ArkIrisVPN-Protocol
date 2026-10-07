//! CUBIC 拥塞控制（备用算法）。

use crate::constants::{MAX_RTO, MIN_RTO};

#[derive(Clone)]
pub struct CubicState {
    cwnd: f64,
    ssthresh: u32,
    rtt_srtt: f64,
    rtt_rttvar: f64,
    rtt_initialized: bool,
}

impl CubicState {
    pub fn new() -> Self {
        Self {
            cwnd: 10.0,
            ssthresh: 64,
            rtt_srtt: 0.0,
            rtt_rttvar: 0.0,
            rtt_initialized: false,
        }
    }

    pub fn on_ack(&mut self, rtt_ms: f64) {
        if !self.rtt_initialized {
            self.rtt_srtt = rtt_ms;
            self.rtt_rttvar = rtt_ms / 2.0;
            self.rtt_initialized = true;
        } else {
            self.rtt_rttvar = 0.75 * self.rtt_rttvar + 0.25 * (self.rtt_srtt - rtt_ms).abs();
            self.rtt_srtt = 0.875 * self.rtt_srtt + 0.125 * rtt_ms;
        }
        if self.cwnd < self.ssthresh as f64 {
            self.cwnd += 1.0;
        } else {
            self.cwnd += 1.0 / self.cwnd;
        }
    }

    pub fn on_ecn(&mut self) {
        self.cwnd = (self.cwnd * 0.85).max(2.0);
    }

    pub fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2.0) as u32;
        self.ssthresh = self.ssthresh.max(2);
        self.cwnd = 2.0;
    }

    pub fn cwnd(&self) -> f64 {
        self.cwnd
    }

    pub fn rto(&self) -> f64 {
        if self.rtt_initialized {
            (self.rtt_srtt + 4.0 * self.rtt_rttvar)
                .max(MIN_RTO.as_secs_f64() * 1000.0)
                .min(MAX_RTO.as_secs_f64() * 1000.0)
        } else {
            1000.0
        }
    }
}
