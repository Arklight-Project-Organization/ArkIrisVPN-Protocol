//! Reliable receive path, SACK generation and single-loss XOR FEC recovery.

use crate::constants::{ACK_DELAY_MAX_MS, ACK_DELAY_MIN_MS, MAX_FEC_GROUP_SIZE, MAX_ACTIVE_FEC_GROUPS, MAX_RX_AHEAD, MAX_SACK_BLOCKS};
use crate::protocol::SackBlock;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::{Duration, Instant},
};

// ==================== 可靠接收 (含 FEC 恢复) ====================
struct FecGroup {
    group_size: usize,
    seqs: Vec<u32>,
    lengths: Vec<usize>,
    packets: HashMap<u32, Vec<u8>>,
    parity: Option<Vec<u8>>,
    created: Instant,
}

pub struct ReliableRx {
    buf: BTreeMap<u32, Vec<u8>>,
    pub base: u32,
    max_size: usize,
    last_ack_sent: Instant,
    last_ack_base: u32,
    rtt_hint: Duration,
    fec_groups: HashMap<u32, FecGroup>,
    rx_bytes: Arc<AtomicU64>,
}

impl ReliableRx {
    pub fn new(max_size: usize, rx_bytes: Arc<AtomicU64>) -> Self {
        Self {
            buf: BTreeMap::new(),
            // Sender sequence numbers start at 1. Starting the receive cursor at 0
            // would permanently stall delivery of the first packet.
            base: 1,
            max_size,
            last_ack_sent: Instant::now(),
            last_ack_base: 1,
            rtt_hint: Duration::from_millis(50),
            fec_groups: HashMap::new(),
            rx_bytes,
        }
    }

    pub fn set_rtt_hint(&mut self, rtt: Duration) {
        self.rtt_hint = rtt.clamp(Duration::from_millis(1), Duration::from_secs(5));
    }

    pub fn should_send_ack(&mut self, now: Instant) -> bool {
        if self.base != self.last_ack_base {
            self.last_ack_base = self.base;
            self.last_ack_sent = now;
            return true;
        }
        if self.buf.len() >= 4 {
            self.last_ack_sent = now;
            return true;
        }
        let delay = if self.rtt_hint <= Duration::from_millis(20) {
            ACK_DELAY_MIN_MS
        } else if self.rtt_hint >= Duration::from_millis(100) {
            ACK_DELAY_MAX_MS
        } else {
            ACK_DELAY_MIN_MS + ((self.rtt_hint.as_millis().saturating_sub(20) * (ACK_DELAY_MAX_MS - ACK_DELAY_MIN_MS) as u128) / 80) as u64
        };
        if now.duration_since(self.last_ack_sent) > Duration::from_millis(delay) {
            self.last_ack_sent = now;
            return true;
        }
        false
    }

    pub fn insert(
        &mut self,
        seq: u32,
        data: Vec<u8>,
        is_fec: bool,
        group_id: Option<u32>,
        group_size: Option<usize>,
        group_seqs: Option<Vec<u32>>,
        group_lengths: Option<Vec<usize>>,
    ) {
        self.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        if is_fec {
            let (Some(gid), Some(gs), Some(seqs), Some(lengths)) = (group_id, group_size, group_seqs, group_lengths) else { return; };
            if !(2..=MAX_FEC_GROUP_SIZE).contains(&gs) || seqs.len() != gs || lengths.len() != gs || seqs.iter().any(|s| *s == 0) || lengths.iter().any(|len| *len == 0) {
                return;
            }
            let mut unique = seqs.clone();
            unique.sort_unstable();
            unique.dedup();
            if unique.len() != gs || data.is_empty() {
                return;
            }
            let buffered: Vec<(u32, Vec<u8>)> = seqs
                .iter()
                .filter_map(|member_seq| self.buf.get(member_seq).map(|member| (*member_seq, member.clone())))
                .collect();
            let group = self.fec_groups.entry(gid).or_insert_with(|| FecGroup {
                group_size: gs,
                seqs: seqs.clone(),
                lengths: lengths.clone(),
                packets: HashMap::new(),
                parity: None,
                created: Instant::now(),
            });
            if group.seqs != seqs || group.lengths != lengths || group.group_size != gs {
                self.fec_groups.remove(&gid);
                return;
            }
            group.parity = Some(data);
            // The data packets do not carry FEC metadata. Associate any members
            // already buffered, and future data packets will be associated below.
            for (member_seq, member) in buffered {
                group.packets.entry(member_seq).or_insert(member);
            }
            self.try_recover();
            return;
        }

        let distance = seq.wrapping_sub(self.base);
        // Reject packets behind the delivery cursor and packets implausibly far
        // ahead. This prevents an attacker from forcing unbounded BTreeMap growth.
        if distance > MAX_RX_AHEAD {
            return;
        }
        if self.buf.len() >= self.max_size && !self.buf.contains_key(&seq) {
            return;
        }
        if self.buf.contains_key(&seq) {
            return;
        }
        self.buf.insert(seq, data.clone());

        // Attach this packet to any already-known FEC group that names its seq.
        for group in self.fec_groups.values_mut() {
            if group.seqs.iter().any(|member| *member == seq) {
                group.packets.insert(seq, data.clone());
            }
        }
        self.try_recover();
    }

    fn try_recover(&mut self) {
        let now = Instant::now();
        self.fec_groups.retain(|_, group| now.duration_since(group.created) <= Duration::from_secs(2));
        if self.fec_groups.len() > MAX_ACTIVE_FEC_GROUPS {
            let mut oldest: Vec<(u32, Instant)> = self.fec_groups.iter().map(|(id, group)| (*id, group.created)).collect();
            oldest.sort_unstable_by_key(|(_, created)| *created);
            for (id, _) in oldest.into_iter().take(self.fec_groups.len() - MAX_ACTIVE_FEC_GROUPS) {
                self.fec_groups.remove(&id);
            }
        }
        let mut recovered = Vec::new();
        let gids: Vec<u32> = self.fec_groups.keys().copied().collect();

        for gid in gids {
            let Some(group) = self.fec_groups.get(&gid) else { continue; };
            let Some(parity) = &group.parity else { continue; };
            if group.packets.len() != group.group_size.saturating_sub(1) { continue; }
            if group.seqs.len() != group.group_size || group.seqs.is_empty() { continue; }
            if group.packets.keys().any(|seq| !group.seqs.contains(seq)) { continue; }

            let Some((missing_index, &missing_seq)) = group.seqs.iter().enumerate().find(|(_, seq)| !group.packets.contains_key(seq)) else {
                continue;
            };
            let mut recovered_data = parity.clone();
            for data in group.packets.values() {
                for (dst, src) in recovered_data.iter_mut().zip(data.iter()) {
                    *dst ^= *src;
                }
            }
            let missing_len = group.lengths[missing_index];
            if missing_len > recovered_data.len() { continue; }
            recovered_data.truncate(missing_len);
            recovered.push((missing_seq, recovered_data));
        }

        for (seq, data) in recovered {
            let distance = seq.wrapping_sub(self.base);
            if distance <= MAX_RX_AHEAD
                && self.buf.len() < self.max_size
                && !self.buf.contains_key(&seq)
            {
                self.buf.insert(seq, data);
            }
            self.fec_groups.retain(|_, group| !group.seqs.contains(&seq));
        }
    }

    pub fn deliver(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            if let Some(data) = self.buf.remove(&self.base) {
                out.push(data);
                self.base = self.base.wrapping_add(1);
            } else {
                self.try_recover();
                if !self.buf.contains_key(&self.base) {
                    break;
                }
            }
        }
        out
    }

    pub fn sack_blocks(&self) -> Vec<SackBlock> {
        let mut blocks = Vec::new();
        let mut in_block = false;
        let mut block_start: u32 = 0;
        let mut prev_seq: u32 = 0;
        for (&seq, _) in self.buf.iter() {
            if !in_block {
                block_start = seq;
                in_block = true;
            } else if seq != prev_seq.wrapping_add(1) {
                blocks.push(SackBlock {
                    start: block_start,
                    end: prev_seq,
                });
                block_start = seq;
            }
            prev_seq = seq;
        }
        if in_block {
            blocks.push(SackBlock {
                start: block_start,
                end: prev_seq,
            });
        }
        blocks.truncate(MAX_SACK_BLOCKS);
        blocks
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::{AtomicU64, Ordering}, Arc};

    #[test]
    fn receive_window_rejects_far_future_packets() {
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let mut rx = ReliableRx::new(256, rx_bytes);
        rx.insert(MAX_RX_AHEAD + 2, vec![1], false, None, None, None, None);
        assert!(rx.deliver().is_empty());
        assert_eq!(rx.base, 1);
    }

    #[test]
    fn fec_recovers_missing_variable_length_packet() {
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let mut rx = ReliableRx::new(256, rx_bytes);
        let a = b"abc".to_vec();
        let missing = b"12345".to_vec();
        let c = b"xy".to_vec();
        let mut parity = vec![0u8; 5];
        for data in [&a, &missing, &c] {
            for (dst, src) in parity.iter_mut().zip(data.iter()) { *dst ^= *src; }
        }
        rx.insert(1, a.clone(), false, None, None, None, None);
        rx.insert(3, c.clone(), false, None, None, None, None);
        rx.insert(99, parity, true, Some(7), Some(3), Some(vec![1, 2, 3]), Some(vec![3, 5, 2]));
        assert_eq!(rx.deliver(), vec![a, missing, c]);
    }

}
