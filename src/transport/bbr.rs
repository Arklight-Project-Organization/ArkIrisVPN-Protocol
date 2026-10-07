//! BBR 拥塞控制状态机。

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub(crate) enum BbrState {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

#[derive(Clone)]
pub struct Bbr {
    state: BbrState,
    btl_bw: f64,
    rt_prop: Duration,
    min_rtt: Duration,
    cwnd_gain: f64,
    cwnd: f64,
    mtu: f64,
    inflight: f64,
    rtt_samples: VecDeque<Duration>,
    rtt_sum: Duration,
    rtt_count: usize,
    probe_rtt_done: bool,
    probe_rtt_start: Option<Instant>,
    last_delivered: u64,
    last_delivered_time: Instant,
    delivered_bytes: u64,
    min_rtt_stamp: Instant,
}

impl Bbr {
    pub fn new(mtu: u16) -> Self {
        Self {
            state: BbrState::Startup,
            btl_bw: 1.0,
            rt_prop: Duration::from_secs(1),
            min_rtt: Duration::from_secs(1),
            cwnd_gain: 2.0,
            cwnd: (mtu as f64) * 10.0,
            mtu: mtu as f64,
            inflight: 0.0,
            rtt_samples: VecDeque::with_capacity(10),
            rtt_sum: Duration::from_secs(0),
            rtt_count: 0,
            probe_rtt_done: false,
            probe_rtt_start: None,
            last_delivered: 0,
            last_delivered_time: Instant::now(),
            delivered_bytes: 0,
            min_rtt_stamp: Instant::now(),
        }
    }

    fn update_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push_back(rtt);
        self.rtt_sum += rtt;
        self.rtt_count += 1;
        if self.rtt_samples.len() > 10 {
            if let Some(old) = self.rtt_samples.pop_front() {
                self.rtt_sum -= old;
                self.rtt_count -= 1;
            }
        }
        let avg_rtt = if self.rtt_count > 0 {
            self.rtt_sum / self.rtt_count as u32
        } else {
            rtt
        };
        if avg_rtt < self.min_rtt || self.min_rtt == Duration::from_secs(1) {
            self.min_rtt = avg_rtt;
            self.rt_prop = avg_rtt;
            self.min_rtt_stamp = Instant::now();
        }
    }

    fn update_bw(&mut self, delivered: u64, interval: Duration) {
        if interval.as_secs_f64() > 0.0 {
            let bw = delivered as f64 / interval.as_secs_f64();
            self.btl_bw = self.btl_bw * 0.9 + bw * 0.1;
        }
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu as f64;
        self.cwnd = self.cwnd.max(self.mtu * 2.0);
    }

    pub fn on_send(&mut self, bytes: usize) {
        self.inflight = (self.inflight + bytes as f64).min(4_294_967_296.0);
    }

    pub fn on_ack(&mut self, acked_bytes: u64, rtt_sample: Option<Duration>) {
        if let Some(rtt) = rtt_sample {
            self.update_rtt(rtt);
        }
        self.inflight = (self.inflight - acked_bytes as f64).max(0.0);
        self.delivered_bytes += acked_bytes;

        // Update bandwidth estimate periodically
        let elapsed = self.last_delivered_time.elapsed();
        if elapsed.as_secs_f64() > 0.5 {
            let delivered = self.delivered_bytes - self.last_delivered;
            self.update_bw(delivered, elapsed);
            self.last_delivered = self.delivered_bytes;
            self.last_delivered_time = Instant::now();
        }

        match self.state {
            BbrState::Startup => {
                let estimate = (self.btl_bw * self.rt_prop.as_secs_f64() * 2.0).ceil();
                self.cwnd = self.cwnd.max(estimate);
                if self.inflight > self.cwnd * 0.75 {
                    self.state = BbrState::Drain;
                }
            }
            BbrState::Drain => {
                let target = self.btl_bw * self.rt_prop.as_secs_f64();
                if self.inflight <= target {
                    self.state = BbrState::ProbeBw;
                    self.cwnd_gain = 2.0;
                }
            }
            BbrState::ProbeBw => {
                // Re-sample the path minimum RTT periodically. The previous
                // implementation compared min_rtt against rt_prop, but rt_prop
                // was itself always lowered to min_rtt, making ProbeRtt unreachable.
                if self.min_rtt_stamp.elapsed() > Duration::from_secs(10) {
                    self.state = BbrState::ProbeRtt;
                    self.probe_rtt_done = false;
                    self.probe_rtt_start = Some(Instant::now());
                }
                self.cwnd = self.btl_bw * self.rt_prop.as_secs_f64() * self.cwnd_gain;
                self.cwnd = self.cwnd.max(self.mtu * 2.0);
            }
            BbrState::ProbeRtt => {
                if !self.probe_rtt_done {
                    self.cwnd = self.mtu * 4.0;
                    if self.probe_rtt_start.map(|t| t.elapsed() >= Duration::from_millis(200)).unwrap_or(false) {
                        self.probe_rtt_done = true;
                        self.min_rtt_stamp = Instant::now();
                    }
                } else {
                    self.cwnd = self.btl_bw * self.rt_prop.as_secs_f64() * self.cwnd_gain;
                    self.cwnd = self.cwnd.max(self.mtu * 2.0);
                    self.state = BbrState::ProbeBw;
                    self.probe_rtt_start = None;
                }
            }
        }
        self.cwnd = self.cwnd.min(64.0 * 1024.0 * 1024.0);
    }

    /// ECN-CE is an explicit congestion signal. It is less destructive than
    /// treating CE as packet loss, so reduce the pacing/cwnd target without
    /// entering a full loss recovery episode.
    pub fn on_ecn(&mut self) {
        self.btl_bw *= 0.90;
        self.cwnd = (self.cwnd * 0.85).max(self.mtu * 4.0);
    }

    pub fn on_timeout(&mut self) {
        self.btl_bw *= 0.7;
        self.cwnd = self.cwnd * 0.7;
        if self.cwnd < self.mtu * 2.0 {
            self.cwnd = self.mtu * 2.0;
        }
        self.state = BbrState::ProbeRtt;
        self.probe_rtt_done = false;
        self.probe_rtt_start = Some(Instant::now());
    }

    pub fn cwnd(&self) -> f64 {
        self.cwnd
    }

    pub fn rt_prop(&self) -> Duration {
        self.rt_prop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_cwnd_is_positive_and_bounded() {
        let mut bbr = Bbr::new(1420);
        for _ in 0..100 {
            bbr.on_ack(1400, Some(Duration::from_millis(10)));
        }
        assert!(bbr.cwnd() >= 2.0);
        assert!(bbr.cwnd() <= 65535.0);
        assert!(bbr.rt_prop() <= Duration::from_millis(20));
    }

    #[test]
    fn timeout_never_collapses_cwnd_to_zero() {
        let mut bbr = Bbr::new(1420);
        bbr.on_timeout();
        assert!(bbr.cwnd() >= 2.0);
    }
}
