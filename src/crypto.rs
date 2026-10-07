//! 加密工作池、密钥交换与握手消息。

use chacha20poly1305::{
    aead::AeadInPlace,
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use x25519_dalek::PublicKey;

use crate::constants::{
    HANDSHAKE_REPLAY_WINDOW, HANDSHAKE_RESP_MAC_SIZE, MAX_HANDSHAKE_REPLAY_ENTRIES, NONCE_SIZE,
    PQ_CIPHERTEXT_SIZE, PQ_PUBLIC_KEY_SIZE, TAG_SIZE,
};

// ==================== 加密热路径 ====================
// 当前隧道包最大只有几 KiB，ChaCha20-Poly1305 的单次调用成本远低于
// Tokio channel + worker + oneshot 的调度成本，因此数据面直接同步执行。
pub struct CryptoEngine;

/// Compatibility alias for older internal call sites.
pub type CryptoPool = CryptoEngine;

impl CryptoEngine {
    pub fn new(_workers: usize) -> Self {
        Self
    }

    pub async fn encrypt(
        &self,
        cipher: Arc<ChaCha20Poly1305>,
        aad: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        Self::encrypt_sync(&cipher, &aad, &plaintext)
    }

    pub async fn decrypt(
        &self,
        cipher: Arc<ChaCha20Poly1305>,
        aad: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        Self::decrypt_sync(&cipher, &aad, &ciphertext)
    }

    fn pad_payload(plaintext: &[u8]) -> Vec<u8> {
        // AEAD 保留精确的明文长度，不再额外发送 2-byte 长度前缀。
        plaintext.to_vec()
    }

    fn encrypt_sync(
        cipher: &ChaCha20Poly1305,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let padded = Self::pad_payload(plaintext);
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut encrypted = padded;
        let tag = cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut encrypted)?;
        let mut out = Vec::with_capacity(NONCE_SIZE + encrypted.len() + TAG_SIZE);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&encrypted);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn decrypt_sync(
        cipher: &ChaCha20Poly1305,
        aad: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(chacha20poly1305::Error);
        }
        let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
        let encrypted = &data[NONCE_SIZE..data.len() - TAG_SIZE];
        let tag = &data[data.len() - TAG_SIZE..];
        let mut decrypted = encrypted.to_vec();
        cipher.decrypt_in_place_detached(nonce, aad, &mut decrypted, tag.into())?;
        Ok(decrypted)
    }
}

// ==================== 密钥交换 ====================
pub fn derive_session_keys(
    eph_dh: &[u8; 32],
    static_dh: &[u8; 32],
    pq_shared: &[u8; 32],
    psk: &[u8],
    is_server: bool,
) -> (Key, Key) {
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(eph_dh);
    combined.extend_from_slice(static_dh);
    combined.extend_from_slice(pq_shared);
    let hkdf = Hkdf::<Sha256>::new(Some(psk), &combined);
    let mut okm = [0u8; 64];
    hkdf.expand(b"ArkIris-v1-hybrid-mlkem768-initiator-to-responder", &mut okm[..32]).expect("HKDF failed");
    hkdf.expand(b"ArkIris-v1-hybrid-mlkem768-responder-to-initiator", &mut okm[32..]).expect("HKDF failed");
    let k1 = Key::from_slice(&okm[..32]);
    let k2 = Key::from_slice(&okm[32..]);
    if is_server { (*k2, *k1) } else { (*k1, *k2) }
}

fn compute_psk_mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    mac.update(b"ArkIris-v1-handshake-init");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn compute_server_psk_mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    mac.update(b"ArkIris-v1-handshake-response");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn build_handshake_init(
    psk: &[u8],
    eph_public: &PublicKey,
    static_public: &PublicKey,
    pq_public: &[u8],
    challenge: u64,
    conn_id: u64,
) -> Vec<u8> {
    debug_assert_eq!(pq_public.len(), PQ_PUBLIC_KEY_SIZE);
    let mut msg = Vec::with_capacity(3 + 32 + 32 + PQ_PUBLIC_KEY_SIZE + 24 + 32);
    msg.extend_from_slice(b"AIR");
    msg.extend_from_slice(eph_public.as_bytes());
    msg.extend_from_slice(static_public.as_bytes());
    msg.extend_from_slice(pq_public);
    msg.extend_from_slice(&challenge.to_be_bytes());
    msg.extend_from_slice(&conn_id.to_be_bytes());
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    msg.extend_from_slice(&ts.to_be_bytes());
    let mac = compute_psk_mac(psk, &msg);
    msg.extend_from_slice(&mac);
    msg
}

pub struct HandshakeReplayCache {
    seen: Mutex<(HashMap<(u64, u64), Instant>, VecDeque<(u64, u64)>)>,
}

impl Default for HandshakeReplayCache {
    fn default() -> Self {
        Self { seen: Mutex::new((HashMap::new(), VecDeque::new())) }
    }
}

impl HandshakeReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically accepts a challenge only once during the replay window.
    pub fn accept_once(&self, challenge: u64, conn_id: u64, now: Instant) -> bool {
        let mut guard = self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (seen, order) = &mut *guard;
        while let Some(oldest) = order.front().copied() {
            let expired = seen.get(&oldest).map(|ts| now.duration_since(*ts) > HANDSHAKE_REPLAY_WINDOW).unwrap_or(true);
            if !expired { break; }
            order.pop_front();
            seen.remove(&oldest);
        }
        let key = (challenge, conn_id);
        if seen.contains_key(&key) {
            return false;
        }
        while seen.len() >= MAX_HANDSHAKE_REPLAY_ENTRIES {
            if let Some(oldest) = order.pop_front() {
                seen.remove(&oldest);
            } else {
                break;
            }
        }
        seen.insert(key, now);
        order.push_back(key);
        true
    }
}

pub fn verify_handshake_init(
    psk: &[u8],
    data: &[u8],
    allowed_static_pubs: &[[u8; 32]],
    replay_cache: &HandshakeReplayCache,
) -> Option<([u8; 32], [u8; 32], Vec<u8>, u64, u64)> {
    let expected = 3 + 32 + 32 + PQ_PUBLIC_KEY_SIZE + 8 + 8 + 8 + 32;
    if data.len() != expected || &data[..3] != b"AIR" { return None; }
    let eph_off = 3;
    let static_off = eph_off + 32;
    let pq_off = static_off + 32;
    let challenge_off = pq_off + PQ_PUBLIC_KEY_SIZE;
    let conn_off = challenge_off + 8;
    let ts_off = conn_off + 8;
    let mac_off = ts_off + 8;
    let eph_bytes: [u8; 32] = data[eph_off..static_off].try_into().ok()?;
    let static_bytes: [u8; 32] = data[static_off..pq_off].try_into().ok()?;
    if !allowed_static_pubs.contains(&static_bytes) { return None; }
    let pq_public = data[pq_off..challenge_off].to_vec();
    let challenge = u64::from_be_bytes(data[challenge_off..conn_off].try_into().ok()?);
    let conn_id = u64::from_be_bytes(data[conn_off..ts_off].try_into().ok()?);
    if conn_id == 0 || challenge == 0 { return None; }
    let ts = u64::from_be_bytes(data[ts_off..mac_off].try_into().ok()?);
    let expected_mac = compute_psk_mac(psk, &data[..mac_off]);
    if !constant_time_eq(&data[mac_off..], &expected_mac) { return None; }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let delta = if ts >= now { ts - now } else { now - ts };
    if delta > HANDSHAKE_REPLAY_WINDOW.as_secs() { return None; }
    if !replay_cache.accept_once(challenge, conn_id, Instant::now()) { return None; }
    Some((eph_bytes, static_bytes, pq_public, challenge, conn_id))
}

pub async fn build_handshake_resp(
    crypto_pool: &CryptoPool,
    cipher: Arc<ChaCha20Poly1305>,
    psk: &[u8],
    server_eph_public: &PublicKey,
    static_public: &PublicKey,
    challenge: u64,
    conn_id: u64,
    pq_ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    debug_assert_eq!(pq_ciphertext.len(), PQ_CIPHERTEXT_SIZE);
    let mut prefix = Vec::with_capacity(32 + 32 + PQ_CIPHERTEXT_SIZE + 16);
    prefix.extend_from_slice(server_eph_public.as_bytes());
    prefix.extend_from_slice(static_public.as_bytes());
    prefix.extend_from_slice(pq_ciphertext);
    prefix.extend_from_slice(&challenge.to_be_bytes());
    prefix.extend_from_slice(&conn_id.to_be_bytes());
    let encrypted_ok = crypto_pool.encrypt(cipher, prefix.clone(), b"OK".to_vec()).await?;
    prefix.extend_from_slice(&encrypted_ok);
    let mac = compute_server_psk_mac(psk, &prefix);
    prefix.extend_from_slice(&mac);
    Ok(prefix)
}

pub async fn verify_handshake_resp(
    crypto_pool: &CryptoPool,
    cipher: Arc<ChaCha20Poly1305>,
    psk: &[u8],
    data: &[u8],
    expected_challenge: u64,
    expected_static_pub: &[u8; 32],
    expected_conn_id: u64,
) -> bool {
    let prefix_len = 32 + 32 + PQ_CIPHERTEXT_SIZE + 8 + 8;
    let encrypted_len = NONCE_SIZE + TAG_SIZE + 2;
    if data.len() != prefix_len + encrypted_len + HANDSHAKE_RESP_MAC_SIZE {
        return false;
    }
    if !constant_time_eq(&data[32..64], expected_static_pub) { return false; }
    let challenge_off = 64 + PQ_CIPHERTEXT_SIZE;
    let challenge = match data[challenge_off..challenge_off + 8].try_into() {
        Ok(v) => u64::from_be_bytes(v),
        Err(_) => return false,
    };
    if challenge != expected_challenge { return false; }
    let conn_off = challenge_off + 8;
    let conn_id = match data[conn_off..conn_off + 8].try_into() {
        Ok(v) => u64::from_be_bytes(v),
        Err(_) => return false,
    };
    if conn_id != expected_conn_id { return false; }
    let mac_off = data.len() - HANDSHAKE_RESP_MAC_SIZE;
    let expected_mac = compute_server_psk_mac(psk, &data[..mac_off]);
    if !constant_time_eq(&data[mac_off..], &expected_mac) { return false; }
    crypto_pool.decrypt(
        cipher,
        data[..prefix_len].to_vec(),
        data[prefix_len..mac_off].to_vec(),
    ).await.map(|v| v == b"OK").unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_replay_cache_is_single_use() {
        let cache = HandshakeReplayCache::new();
        let now = Instant::now();
        assert!(cache.accept_once(10, 20, now));
        assert!(!cache.accept_once(10, 20, now));
        assert!(cache.accept_once(10, 21, now));
    }
}
