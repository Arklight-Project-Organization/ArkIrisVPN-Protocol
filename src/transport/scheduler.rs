//! Low-latency outbound scheduler.
//!
//! LDT (Lightweight Data Transfer) is a local scheduling class for small,
//! latency-sensitive datagrams. It does not change the wire protocol by
//! itself. Small packets use a bounded high-priority lane, while normal bulk
//! traffic is distributed across per-connection lanes for fairness.

use std::{collections::VecDeque, net::SocketAddr, sync::{Arc, Mutex}};
use tokio::sync::Notify;

pub const LDT_MAX_PACKET: usize = 512;
pub const LDT_LANES: usize = 8;
pub const NORMAL_QUEUE_LIMIT: usize = 4096;
pub const LDT_QUEUE_LIMIT: usize = 512;
pub const BULK_BATCH_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficClass { Ldt, Bulk }

pub type OutboundItem = (Vec<u8>, Option<SocketAddr>);

#[derive(Default)]
struct Lane {
    ldt: VecDeque<OutboundItem>,
    bulk: VecDeque<OutboundItem>,
}

struct Inner {
    lanes: [Mutex<Lane>; LDT_LANES],
    notify: Notify,
}

#[derive(Clone)]
pub struct OutboundTx { inner: Arc<Inner> }

pub struct OutboundRx {
    inner: Arc<Inner>,
    cursor: usize,
    ldt_streak: usize,
}

pub fn channel() -> (OutboundTx, OutboundRx) {
    let inner = Arc::new(Inner {
        lanes: std::array::from_fn(|_| Mutex::new(Lane::default())),
        notify: Notify::new(),
    });
    (OutboundTx { inner: inner.clone() }, OutboundRx { inner, cursor: 0, ldt_streak: 0 })
}

impl OutboundTx {
    fn is_ldt_packet(data: &[u8]) -> bool {
        if data.len() <= LDT_MAX_PACKET { return true; }
        // Privacy framing moves the authenticated tunnel header by 6 bytes.
        let flags = if data.len() >= 8 && data[0] == crate::constants::PRIVACY_MAGIC[0] && data[1] == crate::constants::PRIVACY_MAGIC[1] {
            data.get(7).copied().unwrap_or(0)
        } else {
            data.get(1).copied().unwrap_or(0)
        };
        flags & crate::constants::FLAG_LDT != 0
    }

    fn lane_for(dest: Option<SocketAddr>) -> usize {
        match dest {
            None => 0,
            Some(addr) => {
                let mut x = match addr {
                    SocketAddr::V4(v) => u64::from(u32::from_be_bytes(v.ip().octets())),
                    SocketAddr::V6(v) => v.ip().segments().iter().fold(0u64, |a, s| a.rotate_left(7) ^ *s as u64),
                } ^ addr.port() as u64;
                x ^= x >> 33;
                x = x.wrapping_mul(0xff51afd7ed558ccdu64);
                x ^= x >> 33;
                (x as usize) % LDT_LANES
            }
        }
    }

    pub async fn send(&self, item: OutboundItem) -> Result<(), OutboundItem> {
        let lane_idx = Self::lane_for(item.1);
        let is_ldt = Self::is_ldt_packet(&item.0);
        let mut lane = self.inner.lanes[lane_idx].lock().unwrap_or_else(|p| p.into_inner());
        let queue = if is_ldt { &mut lane.ldt } else { &mut lane.bulk };
        let limit = if is_ldt { LDT_QUEUE_LIMIT } else { NORMAL_QUEUE_LIMIT };
        if queue.len() >= limit {
            return Err(item);
        }
        queue.push_back(item);
        drop(lane);
        self.inner.notify.notify_one();
        Ok(())
    }
}

impl OutboundRx {
    fn pop_one(&mut self, class: TrafficClass) -> Option<OutboundItem> {
        // Round-robin across connection lanes. LDT gets one scheduling pass
        // before bulk traffic so a large transfer cannot bury a small packet.
        for offset in 0..LDT_LANES {
            let idx = (self.cursor + offset) % LDT_LANES;
            let mut lane = self.inner.lanes[idx].lock().unwrap_or_else(|p| p.into_inner());
            let item = match class {
                TrafficClass::Ldt => lane.ldt.pop_front(),
                TrafficClass::Bulk => lane.bulk.pop_front(),
            };
            if item.is_some() {
                self.cursor = (idx + 1) % LDT_LANES;
                return item;
            }
        }
        None
    }

    pub async fn recv(&mut self) -> Option<OutboundItem> {
        loop {
            if let Some(item) = self.try_recv() { return Some(item); }
            self.inner.notify.notified().await;
        }
    }

    pub fn try_recv(&mut self) -> Option<OutboundItem> {
        // Weighted priority: up to 16 LDT packets, then one bulk packet.
        // This prevents a flood of tiny interactive packets from starving a
        // large transfer forever.
        if self.ldt_streak < 16 {
            if let Some(item) = self.pop_one(TrafficClass::Ldt) {
                self.ldt_streak += 1;
                return Some(item);
            }
        }
        if let Some(item) = self.pop_one(TrafficClass::Bulk) {
            self.ldt_streak = 0;
            return Some(item);
        }
        if let Some(item) = self.pop_one(TrafficClass::Ldt) {
            self.ldt_streak = self.ldt_streak.saturating_add(1);
            return Some(item);
        }
        None
    }

    pub fn try_recv_batch(&mut self, out: &mut Vec<OutboundItem>, max: usize) {
        while out.len() < max {
            let Some(item) = self.try_recv() else { break; };
            out.push(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_framed_ldt_keeps_priority() {
        let mut frame = vec![0u8; 700];
        frame[0] = crate::constants::PRIVACY_MAGIC[0];
        frame[1] = crate::constants::PRIVACY_MAGIC[1];
        frame[7] = crate::constants::FLAG_LDT;
        assert!(OutboundTx::is_ldt_packet(&frame));
    }

    #[tokio::test]
    async fn ldt_is_served_before_bulk() {
        let (tx, mut rx) = channel();
        tx.send((vec![0; 1000], None)).await.unwrap();
        tx.send((vec![0; 32], None)).await.unwrap();
        assert_eq!(rx.recv().await.unwrap().0.len(), 32);
        assert_eq!(rx.recv().await.unwrap().0.len(), 1000);
    }
}
