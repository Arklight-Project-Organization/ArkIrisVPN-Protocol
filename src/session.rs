//! 会话管理、DHCP 与持久化状态、分片映射。

use chacha20poly1305::ChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use ipnetwork::IpNetwork;
use std::{
    collections::HashMap,
    fs,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::AtomicU64,
        Arc, RwLock,
    },
    time::Instant,
};
use tokio::sync::Mutex as TokioMutex;
use x25519_dalek::ReusableSecret;
use pqcrypto_mlkem::mlkem768;

use crate::constants::{
    CONNECTION_MIGRATION_TIMEOUT, DHCP_MAGIC, INITIAL_MTU_V4, SHARD_COUNT,
};
use crate::transport::{AntiReplay, RateLimiter, ReliableRx, ReliableTx};

// ==================== 持久化状态 ====================
#[derive(Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub allocated_ips: HashMap<String, String>,
    pub ip_to_pubkey: HashMap<String, String>,
    pub conn_id_map: HashMap<String, u64>,
    pub client_conn_ids: HashMap<String, u64>, // SocketAddr -> ConnID
}

impl PersistedState {
    pub fn load(path: &str) -> Self {
        if let Ok(content) = fs::read_to_string(path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }
    pub fn save(&self, path: &str) {
        let Ok(json) = serde_json::to_string_pretty(self) else {
            log::error!("状态序列化失败");
            return;
        };
        let tmp = format!("{}.tmp", path);
        match fs::OpenOptions::new().create(true).truncate(true).write(true).open(&tmp) {
            Ok(mut file) => {
                use std::io::Write;
                if let Err(e) = file.write_all(json.as_bytes()).and_then(|_| file.sync_all()) {
                    log::warn!("状态临时文件写入失败 {}: {}", tmp, e);
                    let _ = fs::remove_file(&tmp);
                    return;
                }
            }
            Err(e) => {
                log::warn!("状态临时文件创建失败 {}: {}", tmp, e);
                return;
            }
        }
        if let Err(e) = fs::rename(&tmp, path) {
            // Windows 不允许直接覆盖已有目标文件，退化为 remove + rename。
            if fs::remove_file(path).is_ok() && fs::rename(&tmp, path).is_ok() {
                return;
            }
            log::warn!("状态文件替换失败 {}: {}", path, e);
            let _ = fs::remove_file(&tmp);
        }
    }
}

// ==================== 分片映射 ====================
pub struct ShardedMap<K: Hash + Eq + Clone, V> {
    shards: Vec<RwLock<HashMap<K, V>>>,
}

impl<K: Hash + Eq + Clone, V> ShardedMap<K, V> {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(RwLock::new(HashMap::new()));
        }
        Self { shards }
    }

    fn get_shard_index<Q: ?Sized + Hash>(&self, key: &Q) -> usize
    where
        K: std::borrow::Borrow<Q>,
    {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % SHARD_COUNT
    }

    pub fn insert(&self, key: K, value: V) {
        let idx = self.get_shard_index(&key);
        self.shards[idx].write().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(key, value);
    }

    /// Returns a cloned value. Prefer `Arc<T>` values for large session objects so this
    /// operation only clones the reference count; storing large owned buffers here is
    /// intentionally discouraged.
    pub fn get<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        V: Clone,
    {
        let idx = self.get_shard_index(key);
        self.shards[idx].read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(key).cloned()
    }

    pub fn snapshot(&self) -> Vec<(K, V)>
    where
        V: Clone,
    {
        let mut out = Vec::new();
        for shard in &self.shards {
            let guard = shard.read().unwrap_or_else(|poisoned| poisoned.into_inner());
            for (k, v) in guard.iter() {
                out.push((k.clone(), v.clone()));
            }
        }
        out
    }

    pub fn remove<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
    {
        let idx = self.get_shard_index(key);
        self.shards[idx].write().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(key)
    }

    pub fn iter<F>(&self, mut f: F)
    where
        F: FnMut(&K, &V),
    {
        for shard in &self.shards {
            let guard = shard.read().unwrap_or_else(|poisoned| poisoned.into_inner());
            for (k, v) in guard.iter() {
                f(k, v);
            }
        }
    }

    pub fn contains_key<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
    {
        let idx = self.get_shard_index(key);
        self.shards[idx].read().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(key)
    }

    pub fn len(&self) -> usize {
        let mut total = 0;
        for shard in &self.shards {
            total += shard.read().unwrap_or_else(|poisoned| poisoned.into_inner()).len();
        }
        total
    }
}

// ==================== 会话管理 ====================
pub struct ClientSession {
    socket_addr: RwLock<SocketAddr>,
    pub static_public: [u8; 32],
    pub conn_id: u64,
    pub last_seen: RwLock<Instant>,
    pub assigned_ip4: RwLock<Option<Ipv4Addr>>,
    pub assigned_ip6: RwLock<Option<Ipv6Addr>>,
    pub cipher_send: Arc<ChaCha20Poly1305>,
    pub cipher_recv: Arc<ChaCha20Poly1305>,
    pub reliable_tx: TokioMutex<ReliableTx>,
    pub reliable_rx: TokioMutex<ReliableRx>,
    pub anti_replay: TokioMutex<AntiReplay>,
    pub tx_limiter: TokioMutex<RateLimiter>,
    pub rx_limiter: TokioMutex<RateLimiter>,
    pub tx_bytes: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
    migration_old_addr: RwLock<Option<SocketAddr>>,
    migration_time: RwLock<Instant>,
}

impl ClientSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_addr: SocketAddr,
        static_public: [u8; 32],
        conn_id: u64,
        cipher_send: Arc<ChaCha20Poly1305>,
        cipher_recv: Arc<ChaCha20Poly1305>,
        cc_type: &str,
        fec_size: usize,
        rate_limit_mbps: f64,
        rate_burst_seconds: f64,
        tx_bytes: Arc<AtomicU64>,
        rx_bytes: Arc<AtomicU64>,
    ) -> Self {
        Self {
            socket_addr: RwLock::new(socket_addr),
            static_public,
            conn_id,
            last_seen: RwLock::new(Instant::now()),
            assigned_ip4: RwLock::new(None),
            assigned_ip6: RwLock::new(None),
            cipher_send: cipher_send.clone(),
            cipher_recv: cipher_recv.clone(),
            reliable_tx: TokioMutex::new(ReliableTx::new(
                INITIAL_MTU_V4,
                8,
                cc_type,
                fec_size,
                tx_bytes.clone(),
            )),
            reliable_rx: TokioMutex::new(ReliableRx::new(256, rx_bytes.clone())),
            anti_replay: TokioMutex::new(AntiReplay::new()),
            tx_limiter: TokioMutex::new(RateLimiter::new_with_burst(rate_limit_mbps, rate_burst_seconds)),
            rx_limiter: TokioMutex::new(RateLimiter::new_with_burst(rate_limit_mbps, rate_burst_seconds)),
            tx_bytes,
            rx_bytes,
            migration_old_addr: RwLock::new(None),
            migration_time: RwLock::new(Instant::now()),
        }
    }

    pub fn socket_addr(&self) -> SocketAddr {
        *self.socket_addr.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn update_addr(&self, new_addr: SocketAddr) {
        let old = *self.socket_addr.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        *self.migration_old_addr.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(old);
        *self.socket_addr.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = new_addr;
        *self.migration_time.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
        log::info!("ConnID {} 从 {} 迁移到 {}", self.conn_id, old, new_addr);
    }

    pub fn is_migration_cooldown(&self) -> bool {
        if let Some(old_addr) = *self.migration_old_addr.read().unwrap_or_else(|poisoned| poisoned.into_inner()) {
            if *self.socket_addr.read().unwrap_or_else(|poisoned| poisoned.into_inner()) != old_addr {
                return Instant::now().duration_since(*self.migration_time.read().unwrap_or_else(|poisoned| poisoned.into_inner()))
                    < CONNECTION_MIGRATION_TIMEOUT;
            }
        }
        false
    }
}

pub struct ClientHandshakeContext {
    pub eph_secret: ReusableSecret,
    pub pq_secret: mlkem768::SecretKey,
    pub challenge: u64,
    pub peer_static_pub: [u8; 32],
    pub conn_id: u64,
}

pub struct ClientOwnState {
    pub cipher_send: Arc<ChaCha20Poly1305>,
    pub cipher_recv: Arc<ChaCha20Poly1305>,
    pub reliable_tx: Arc<TokioMutex<ReliableTx>>,
    pub reliable_rx: Arc<TokioMutex<ReliableRx>>,
    pub anti_replay: Arc<TokioMutex<AntiReplay>>,
    pub assigned_ip4: Option<Ipv4Addr>,
    pub assigned_ip6: Option<Ipv6Addr>,
    pub tx_limiter: Arc<TokioMutex<RateLimiter>>,
    pub last_ka_resp: Instant,
    pub conn_id: u64,
}

// ==================== DHCP ====================
pub struct DhcpRequest {
    pub client_id: [u8; 16],
    pub requested_ip: Option<Ipv4Addr>,
}

pub struct DhcpReply {
    pub ip4: Option<Ipv4Addr>,
    pub subnet_mask4: Ipv4Addr,
    pub ip6: Option<Ipv6Addr>,
    pub prefix_len6: u8,
    pub mtu: u16,
    pub dns: Vec<IpAddr>,
    pub routes: Vec<(String, String)>,
}

pub fn encode_dhcp_request(req: &DhcpRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    buf.extend_from_slice(DHCP_MAGIC);
    buf.extend_from_slice(&req.client_id);
    if let Some(ip) = req.requested_ip {
        buf.push(1);
        buf.extend_from_slice(&ip.octets());
    } else {
        buf.push(0);
    }
    buf
}

pub fn decode_dhcp_request(data: &[u8]) -> Option<DhcpRequest> {
    if data.len() < 20 || &data[..4] != DHCP_MAGIC {
        return None;
    }
    let mut client_id = [0u8; 16];
    client_id.copy_from_slice(&data[4..20]);
    let mut requested_ip = None;
    if data.len() >= 25 && data[20] == 1 {
        requested_ip = Some(Ipv4Addr::new(data[21], data[22], data[23], data[24]));
    }
    Some(DhcpRequest {
        client_id,
        requested_ip,
    })
}

pub fn encode_dhcp_reply(reply: &DhcpReply) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(1);
    if let Some(ip4) = reply.ip4 {
        buf.push(4);
        buf.extend_from_slice(&ip4.octets());
        buf.extend_from_slice(&reply.subnet_mask4.octets());
    } else {
        buf.push(0);
    }
    if let Some(ip6) = reply.ip6 {
        buf.push(6);
        buf.extend_from_slice(&ip6.octets());
        buf.push(reply.prefix_len6);
    } else {
        buf.push(0);
    }
    buf.extend_from_slice(&reply.mtu.to_be_bytes());
    buf.push(reply.dns.len() as u8);
    for addr in &reply.dns {
        match addr {
            IpAddr::V4(ip) => {
                buf.push(4);
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(6);
                buf.extend_from_slice(&ip.octets());
            }
        }
    }
    buf.push(reply.routes.len() as u8);
    for (dest, gw) in &reply.routes {
        let dest_bytes = dest.as_bytes();
        buf.push(dest_bytes.len() as u8);
        buf.extend_from_slice(dest_bytes);
        let gw_bytes = gw.as_bytes();
        buf.push(gw_bytes.len() as u8);
        buf.extend_from_slice(gw_bytes);
    }
    buf
}

pub fn decode_dhcp_reply(data: &[u8]) -> Option<DhcpReply> {
    if data.len() < 1 { return None; }
    let mut off = 1usize;
    let ip4 = match *data.get(off)? {
        4 => {
            let end = off.checked_add(9)?;
            if end > data.len() { return None; }
            let ip = Ipv4Addr::new(data[off + 1], data[off + 2], data[off + 3], data[off + 4]);
            let mask = Ipv4Addr::new(data[off + 5], data[off + 6], data[off + 7], data[off + 8]);
            off = end;
            Some((ip, mask))
        }
        0 => { off += 1; None }
        _ => return None,
    };
    let ip6 = match *data.get(off)? {
        6 => {
            let end = off.checked_add(18)?;
            if end > data.len() { return None; }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[off + 1..off + 17]);
            let prefix_len = data[off + 17];
            if prefix_len > 128 { return None; }
            off = end;
            Some((Ipv6Addr::from(octets), prefix_len))
        }
        0 => { off += 1; None }
        _ => return None,
    };
    if off.checked_add(3)? > data.len() { return None; }
    let mtu = u16::from_be_bytes(data[off..off + 2].try_into().ok()?);
    if !(576..=9000).contains(&mtu) { return None; }
    off += 2;
    let dns_count = *data.get(off)? as usize;
    off += 1;
    let mut dns = Vec::with_capacity(dns_count);
    for _ in 0..dns_count {
        match *data.get(off)? {
            4 => {
                let end = off.checked_add(5)?;
                if end > data.len() { return None; }
                dns.push(IpAddr::V4(Ipv4Addr::new(data[off + 1], data[off + 2], data[off + 3], data[off + 4])));
                off = end;
            }
            6 => {
                let end = off.checked_add(17)?;
                if end > data.len() { return None; }
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&data[off + 1..off + 17]);
                dns.push(IpAddr::V6(Ipv6Addr::from(oct)));
                off = end;
            }
            _ => return None,
        }
    }
    let route_count = *data.get(off)? as usize;
    off += 1;
    let mut routes = Vec::with_capacity(route_count);
    for _ in 0..route_count {
        let dest_len = *data.get(off)? as usize;
        off += 1;
        let dest_end = off.checked_add(dest_len)?;
        if dest_end > data.len() { return None; }
        let dest = std::str::from_utf8(&data[off..dest_end]).ok()?.to_string();
        off = dest_end;
        let gw_len = *data.get(off)? as usize;
        off += 1;
        let gw_end = off.checked_add(gw_len)?;
        if gw_end > data.len() { return None; }
        let gw = std::str::from_utf8(&data[off..gw_end]).ok()?.to_string();
        off = gw_end;
        // Validate before allowing a peer-controlled DHCP reply to reach routing code.
        dest.parse::<IpNetwork>().ok()?;
        gw.parse::<IpAddr>().ok()?;
        routes.push((dest, gw));
    }
    if off != data.len() { return None; }
    Some(DhcpReply {
        ip4: ip4.map(|(ip, _)| ip),
        subnet_mask4: ip4.map(|(_, m)| m).unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
        ip6: ip6.map(|(ip, _)| ip),
        prefix_len6: ip6.map(|(_, p)| p).unwrap_or(64),
        mtu,
        dns,
        routes,
    })
}
