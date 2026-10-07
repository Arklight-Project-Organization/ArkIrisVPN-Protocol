//! Length-hiding privacy framing for ArkIris datagrams.
//!
//! This module deliberately does not pretend to be a real TLS implementation.
//! The inner tunnel packet is already AEAD protected; this outer layer only
//! hides exact application packet lengths by adding bounded random padding.
//! It is a privacy feature, not a protocol impersonation layer.

use rand::RngCore;

use crate::constants::{MAX_PACKET, PRIVACY_FRAME_HEADER, PRIVACY_MAGIC, PRIVACY_VERSION};

/// Wrap an encrypted tunnel datagram in a bounded, length-hiding privacy frame.
///
/// `bucket` should normally be 64, 128, 256, or 512. A zero bucket disables
/// padding while retaining the framing header.
pub fn wrap_privacy_record(payload: &[u8], bucket: usize) -> Vec<u8> {
    let bucket = bucket.max(1);
    let max_payload = MAX_PACKET.saturating_sub(PRIVACY_FRAME_HEADER);
    if payload.len() > max_payload {
        return payload.to_vec();
    }

    let target = if bucket == 1 {
        payload.len()
    } else {
        ((payload.len() + bucket - 1) / bucket) * bucket
    };
    let target = target.min(max_payload).max(payload.len());
    let padding_len = target - payload.len();

    let mut out = Vec::with_capacity(PRIVACY_FRAME_HEADER + target);
    out.extend_from_slice(&[PRIVACY_MAGIC[0], PRIVACY_MAGIC[1], PRIVACY_VERSION, 0]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    if padding_len > 0 {
        let old_len = out.len();
        out.resize(old_len + padding_len, 0);
        rand::thread_rng().fill_bytes(&mut out[old_len..]);
    }
    out
}

/// Remove privacy framing. Returns `None` for malformed frames.
pub fn unwrap_privacy_record(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < PRIVACY_FRAME_HEADER
        || frame[0] != PRIVACY_MAGIC[0]
        || frame[1] != PRIVACY_MAGIC[1]
        || frame[2] != PRIVACY_VERSION
    {
        return None;
    }
    let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    let available = frame.len() - PRIVACY_FRAME_HEADER;
    if payload_len > available {
        return None;
    }
    Some(&frame[PRIVACY_FRAME_HEADER..PRIVACY_FRAME_HEADER + payload_len])
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_roundtrip_preserves_payload() {
        let payload = b"arkiris encrypted payload";
        let framed = wrap_privacy_record(payload, 64);
        assert!(framed.len() >= PRIVACY_FRAME_HEADER + payload.len());
        assert_eq!(unwrap_privacy_record(&framed), Some(payload.as_slice()));
    }

    #[test]
    fn malformed_privacy_frame_is_rejected() {
        assert!(unwrap_privacy_record(&[
            PRIVACY_MAGIC[0], PRIVACY_MAGIC[1], PRIVACY_VERSION, 0, 0, 9, 1
        ]).is_none());
        assert!(unwrap_privacy_record(&[0; PRIVACY_FRAME_HEADER]).is_none());
    }
}
