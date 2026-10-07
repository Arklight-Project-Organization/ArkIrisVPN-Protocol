//! Reliable transmit path and FEC parity generation.

use crate::constants::{FEC_DEFAULT_GROUP_SIZE, MAX_RTO, MIN_RTO};
use crate::protocol::{SackBlock, TunnelHeader};
use super::{Bbr, CubicState};
use std::{
    collections::VecDeque,
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct TxEntry {
    pub data: Vec<u8>,
    pub seq: u32,
    pub flags: u8,
    pub sent: Instant,
    pub retries: u32,
}

pub struct ReliableTx {
    buf: VecDeque<TxEntry>,
    pub next_seq: u32,
    cubic: CubicState,
    bbr: Option<Bbr>,
    ssthresh: u32,
    in_fast_recovery: bool,
    recover: u32,
    duplicate_acks: u32,
    last_ack: u32,
    flight_size: u32,
    mtu: u16,
    max_retries: u32,
    fec_enabled: bool,
    fec_group_size: usize,
    fec_group: VecDeque<TxEntry>,
    fec_group_id: u32,
    tx_bytes: Arc<AtomicU64>,
    rtt_samples: VecDeque<Duration>,
    rtt_avg: Duration,
}

impl ReliableTx {
    pub fn new(
        mtu: u16,
        max_retries: u32,
        cc_type: &str,
        fec_size: usize,
        tx_bytes: Arc<AtomicU64>,
    ) -> Self {
        let bbr = if cc_type == "bbr" {
            Some(Bbr::new(mtu))
        } else {
            None
        };
        let fec_group_size = if fec_size > 1 { fec_size } else { FEC_DEFAULT_GROUP_SIZE };
        Self {
            buf: VecDeque::new(),
            next_seq: 1,
            cubic: CubicState::new(),
            bbr,
            ssthresh: 64,
            in_fast_recovery: false,
            recover: 0,
            duplicate_acks: 0,
            last_ack: 0,
            flight_size: 0,
            mtu,
            max_retries,
            fec_enabled: fec_size > 1,
            fec_group_size,
            fec_group: VecDeque::new(),
            fec_group_id: 0,
            tx_bytes,
            rtt_samples: VecDeque::with_capacity(20),
            rtt_avg: Duration::from_millis(100),
        }
    }

    pub fn update_mtu(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        if let Some(bbr) = &mut self.bbr {
            bbr.set_mtu(new_mtu);
        }
    }

    pub fn can_send(&self) -> bool {
        let inflight = self.flight_size;
        if let Some(bbr) = &self.bbr {
            return bbr.cwnd() > inflight as f64;
        }
        (self.cubic.cwnd() * self.mtu as f64) > inflight as f64
    }

    pub fn push(&mut self, data: Vec<u8>, flags: u8) -> (u32, Vec<u8>) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.flight_size = self.flight_size.saturating_add(data.len() as u32);
        if let Some(bbr) = &mut self.bbr {
            bbr.on_send(data.len());
        }
        let entry = TxEntry {
            data,
            seq,
            flags,
            sent: Instant::now(),
            retries: 0,
        };
        let entry_data = entry.data.clone();
        self.tx_bytes.fetch_add(entry_data.len() as u64, Ordering::Relaxed);
        // Keep one authoritative retransmission copy. FEC only clones the small
        // descriptor/data buffer when a group is actually enabled.
        self.buf.push_back(entry.clone());
        if self.fec_enabled {
            self.fec_group.push_back(entry);
        }
        (seq, entry_data)
    }

    pub fn ack(&mut self, ack_seq: u32, sack_blocks: &[SackBlock], now: Instant) {
        let mut rtt_sample: Option<Duration> = None;
        let mut acked_bytes = 0u32;

        while let Some(entry) = self.buf.front() {
            if TunnelHeader::is_before(entry.seq, ack_seq) {
                let entry = self.buf.pop_front().unwrap();
                acked_bytes += entry.data.len() as u32;
                if rtt_sample.is_none() {
                    rtt_sample = Some(now.duration_since(entry.sent));
                }
            } else {
                break;
            }
        }

        self.buf.retain(|entry| {
            let sacked = sack_blocks.iter().any(|block| {
                !TunnelHeader::is_before(entry.seq, block.start)
                    && !TunnelHeader::is_before(block.end, entry.seq)
            });
            if sacked {
                acked_bytes += entry.data.len() as u32;
                false
            } else {
                true
            }
        });
        self.flight_size = self.flight_size.saturating_sub(acked_bytes);

        if let Some(rtt) = rtt_sample {
            self.rtt_samples.push_back(rtt);
            if self.rtt_samples.len() > 20 {
                self.rtt_samples.pop_front();
            }
            let sum: Duration = self.rtt_samples.iter().sum();
            self.rtt_avg = sum / self.rtt_samples.len() as u32;

            if let Some(bbr) = &mut self.bbr {
                bbr.on_ack(acked_bytes as u64, Some(rtt));
            } else {
                self.cubic.on_ack(rtt.as_secs_f64() * 1000.0);
            }
        }

        if ack_seq == self.last_ack && !TunnelHeader::is_before(ack_seq, self.last_ack) {
            self.duplicate_acks += 1;
            if self.duplicate_acks == 3 && !self.in_fast_recovery {
                self.in_fast_recovery = true;
                if self.bbr.is_none() {
                    self.ssthresh = (self.cubic.cwnd() / 2.0) as u32;
                    self.ssthresh = self.ssthresh.max(2);
                    self.cubic.on_loss();
                }
                self.recover = self.next_seq.wrapping_sub(1);
                if let Some(entry) = self.buf.front_mut() {
                    entry.retries += 1;
                    entry.sent = now;
                }
            }
        } else {
            self.duplicate_acks = 0;
            if self.in_fast_recovery && !TunnelHeader::is_before(ack_seq, self.recover) {
                self.in_fast_recovery = false;
            }
            self.last_ack = ack_seq;
        }
    }

    pub fn flags_for_seq(&self, seq: u32) -> u8 {
        self.buf.iter().find(|e| e.seq == seq).map(|e| e.flags).unwrap_or(crate::constants::FLAG_RELIABLE)
    }

    pub fn on_ecn(&mut self) {
        if let Some(bbr) = &mut self.bbr { bbr.on_ecn(); } else { self.cubic.on_ecn(); }
    }

    pub fn retransmit(&mut self, now: Instant) -> Vec<(Vec<u8>, u32)> {
        let mut out = Vec::new();
        let rto = if let Some(bbr) = &self.bbr {
            let candidate = bbr.rt_prop() * 4;
            candidate.clamp(MIN_RTO, MAX_RTO)
        } else {
            Duration::from_millis(self.cubic.rto().max(MIN_RTO.as_millis() as f64).min(MAX_RTO.as_millis() as f64) as u64)
        };

        for entry in self.buf.iter_mut() {
            let multiplier = 1u32 << entry.retries.min(6);
            let timeout = rto.checked_mul(multiplier).unwrap_or(MAX_RTO).min(MAX_RTO);
            if now.duration_since(entry.sent) > timeout {
                entry.retries += 1;
                if entry.retries <= self.max_retries {
                    out.push((entry.data.clone(), entry.seq));
                    entry.sent = now;
                    if let Some(bbr) = &mut self.bbr {
                        bbr.on_timeout();
                    } else {
                        self.cubic.on_loss();
                    }
                }
            }
        }
        out
    }

    pub fn get_fec_parity(&mut self) -> Option<(Vec<u8>, u32, Vec<u32>, Vec<u16>)> {
        if !self.fec_enabled || self.fec_group.len() < self.fec_group_size {
            return None;
        }
        let group: Vec<TxEntry> = self.fec_group.drain(..).collect();
        self.fec_group_id = self.fec_group_id.wrapping_add(1);
        let group_id = self.fec_group_id;
        let base_len = group.iter().map(|e| e.data.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; base_len];
        let mut seqs = Vec::new();
        let mut lengths = Vec::with_capacity(group.len());
        for entry in &group {
            seqs.push(entry.seq);
            lengths.push(u16::try_from(entry.data.len()).ok()?);
            for i in 0..entry.data.len() {
                parity[i] ^= entry.data[i];
            }
        }
        Some((parity, group_id, seqs, lengths))
    }

    pub fn rtt_estimate(&self) -> Duration {
        self.rtt_avg
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

