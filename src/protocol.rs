//! 隧道协议定义：包类型、包头、SACK 与 ACK 编解码。

use crate::constants::{MAX_FEC_GROUP_SIZE, MAX_PACKET, MAX_SACK_BLOCKS};

// ==================== 协议定义 ====================
#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum PktType {
    HandshakeInit = 0,
    HandshakeResp = 1,
    Data = 2,
    Ack = 3,
    DhcpReq = 4,
    DhcpAck = 5,
    KeepAlive = 6,
    KeepAliveResp = 7,
    PmtudProbe = 8,
    Fec = 9,
}

#[derive(Debug, Clone)]
pub struct TunnelHeader {
    pub pkt_type: u8,
    pub flags: u8,
    pub seq: u32,
    pub ack_seq: u32,
    pub conn_id: u64,
}

impl TunnelHeader {
    pub fn encode(&self) -> [u8; 18] {
        let mut buf = [0u8; 18];
        buf[0] = self.pkt_type;
        buf[1] = self.flags;
        buf[2..6].copy_from_slice(&self.seq.to_be_bytes());
        buf[6..10].copy_from_slice(&self.ack_seq.to_be_bytes());
        buf[10..18].copy_from_slice(&self.conn_id.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 18 || data[0] > PktType::Fec as u8 {
            return None;
        }
        Some(Self {
            pkt_type: data[0],
            flags: data[1],
            seq: u32::from_be_bytes(data[2..6].try_into().ok()?),
            ack_seq: u32::from_be_bytes(data[6..10].try_into().ok()?),
            conn_id: u64::from_be_bytes(data[10..18].try_into().ok()?),
        })
    }

    pub fn is_before(a: u32, b: u32) -> bool {
        a.wrapping_sub(b) > u32::MAX / 2
    }
}

#[derive(Clone, Debug)]
pub struct SackBlock {
    pub start: u32,
    pub end: u32,
}

pub fn encode_ack_payload(ack_seq: u32, blocks: &[SackBlock]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 + blocks.len() * 8);
    buf.extend_from_slice(&ack_seq.to_be_bytes());
    buf.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
    for b in blocks {
        buf.extend_from_slice(&b.start.to_be_bytes());
        buf.extend_from_slice(&b.end.to_be_bytes());
    }
    buf
}

pub fn decode_ack_payload(data: &[u8]) -> Option<(u32, Vec<SackBlock>)> {
    if data.len() < 6 {
        return None;
    }
    let ack_seq = u32::from_be_bytes(data[0..4].try_into().ok()?);
    let num = u16::from_be_bytes(data[4..6].try_into().ok()?) as usize;
    if num > MAX_SACK_BLOCKS || 6usize.saturating_add(num.saturating_mul(8)) != data.len() {
        return None;
    }
    let mut blocks = Vec::with_capacity(num);
    let mut offset = 6;
    for _ in 0..num {
        if offset + 8 > data.len() {
            return None;
        }
        let start = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?);
        let end = u32::from_be_bytes(data[offset + 4..offset + 8].try_into().ok()?);
        if TunnelHeader::is_before(end, start) { return None; }
        blocks.push(SackBlock { start, end });
        offset += 8;
    }
    Some((ack_seq, blocks))
}

#[derive(Clone, Debug)]
pub struct FecPayload {
    pub group_id: u32,
    pub group_size: usize,
    pub seqs: Vec<u32>,
    pub lengths: Vec<usize>,
    pub parity: Vec<u8>,
}

pub fn encode_fec_payload(group_id: u32, seqs: &[u32], lengths: &[u16], parity: &[u8]) -> Option<Vec<u8>> {
    if !(2..=MAX_FEC_GROUP_SIZE).contains(&seqs.len())
        || seqs.len() != lengths.len()
        || seqs.iter().any(|seq| *seq == 0)
        || lengths.iter().any(|len| *len == 0)
        || parity.is_empty()
        || parity.len() > MAX_PACKET
    {
        return None;
    }
    let max_len = lengths.iter().map(|v| *v as usize).max().unwrap_or(0);
    if max_len == 0 || max_len > parity.len() {
        return None;
    }
    let mut unique = seqs.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != seqs.len() {
        return None;
    }
    let mut out = Vec::with_capacity(8 + seqs.len() * 6 + parity.len());
    out.extend_from_slice(&group_id.to_be_bytes());
    out.extend_from_slice(&(seqs.len() as u16).to_be_bytes());
    out.extend_from_slice(&(seqs.len() as u16).to_be_bytes());
    for seq in seqs {
        out.extend_from_slice(&seq.to_be_bytes());
    }
    for len in lengths {
        if *len == 0 { return None; }
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(parity);
    Some(out)
}

pub fn decode_fec_payload(data: &[u8]) -> Option<FecPayload> {
    if data.len() < 8 { return None; }
    let group_id = u32::from_be_bytes(data[0..4].try_into().ok()?);
    let group_size = u16::from_be_bytes(data[4..6].try_into().ok()?) as usize;
    let seq_count = u16::from_be_bytes(data[6..8].try_into().ok()?) as usize;
    if !(2..=MAX_FEC_GROUP_SIZE).contains(&group_size) || seq_count != group_size { return None; }
    let seq_bytes = seq_count.checked_mul(4)?;
    let len_bytes = seq_count.checked_mul(2)?;
    let meta_len = 8usize.checked_add(seq_bytes)?.checked_add(len_bytes)?;
    if data.len() <= meta_len { return None; }
    let mut seqs = Vec::with_capacity(seq_count);
    for i in 0..seq_count {
        let off = 8 + i * 4;
        seqs.push(u32::from_be_bytes(data[off..off + 4].try_into().ok()?));
    }
    let mut unique = seqs.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != seqs.len() || seqs.iter().any(|seq| *seq == 0) { return None; }
    let mut lengths = Vec::with_capacity(seq_count);
    for i in 0..seq_count {
        let off = 8 + seq_bytes + i * 2;
        let len = u16::from_be_bytes(data[off..off + 2].try_into().ok()?) as usize;
        if len == 0 { return None; }
        lengths.push(len);
    }
    let parity = &data[meta_len..];
    let max_len = lengths.iter().copied().max().unwrap_or(0);
    if parity.is_empty() || parity.len() < max_len || parity.len() > MAX_PACKET {
        return None;
    }
    Some(FecPayload {
        group_id,
        group_size,
        seqs,
        lengths,
        parity: parity.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn fec_roundtrip_preserves_lengths() {
        let seqs = [1u32, 2, 3, 4];
        let lengths = [10u16, 20, 30, 40];
        let parity = vec![7u8; 64];
        let encoded = encode_fec_payload(9, &seqs, &lengths, &parity).unwrap();
        let decoded = decode_fec_payload(&encoded).unwrap();
        assert_eq!(decoded.group_id, 9);
        assert_eq!(decoded.group_size, 4);
        assert_eq!(decoded.seqs, seqs);
        assert_eq!(decoded.lengths, lengths.iter().map(|v| *v as usize).collect::<Vec<_>>());
        assert_eq!(decoded.parity, parity);
    }

    #[test]
    fn malformed_fec_is_rejected() {
        assert!(decode_fec_payload(&[0; 8]).is_none());
        let encoded = encode_fec_payload(1, &[1, 1], &[4, 4], &[0; 4]);
        assert!(encoded.is_none());
    }

    #[test]
    fn fec_parity_must_cover_declared_member_length() {
        assert!(encode_fec_payload(1, &[1, 2], &[8, 4], &[0; 4]).is_none());
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        let mut rng = rand::thread_rng();
        for len in 0..=256usize {
            let mut data = vec![0u8; len];
            rng.fill_bytes(&mut data);
            let _ = TunnelHeader::decode(&data);
            let _ = decode_ack_payload(&data);
            let _ = decode_fec_payload(&data);
        }
    }
}
