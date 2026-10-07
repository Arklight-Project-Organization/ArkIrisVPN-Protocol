//! 运行时服务：PMTU 探测、监控接口、客户端会话初始化与基准测试。

use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};
use rand::rngs::OsRng;
use rand::RngCore;
use std::{
    convert::TryInto,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
    sync::Mutex as TokioMutex,
    time::interval,
};
use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret, StaticSecret};
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SharedSecret as PqSharedSecret};
use zeroize::Zeroizing;

use crate::cli::Args;
use crate::constants::{
    BENCHMARK_INTERVAL, BENCHMARK_PACKET_SIZE, INITIAL_MTU_V4, MAX_PACKET, PMTU_PROBE_INTERVAL, NONCE_SIZE, TAG_SIZE, PQ_CIPHERTEXT_SIZE,
};
use crate::crypto::{build_handshake_init, derive_session_keys, CryptoPool};
use crate::net::privacy::wrap_privacy_record;
use crate::protocol::{decode_ack_payload, PktType, TunnelHeader};
use crate::session::{ClientHandshakeContext, ClientSession, ShardedMap};
use crate::transport::{AntiReplay, RateLimiter, ReliableRx, ReliableTx};

// ==================== PMTU 独立探测 ====================
pub async fn pmtu_probe_loop(
    socket: Arc<UdpSocket>,
    conn_id: u64,
    crypto_pool: Arc<CryptoPool>,
    cipher_send: Arc<ChaCha20Poly1305>,
    reliable_tx: Arc<TokioMutex<ReliableTx>>,
    stealth_enabled: bool,
    privacy_bucket: usize,
) {
    let mut interval = interval(PMTU_PROBE_INTERVAL);
    let mut probing = false;
    let mut probe_start = Instant::now();

    loop {
        interval.tick().await;
        let current_mtu = reliable_tx.lock().await.mtu();
        if !probing {
            probing = true;
            probe_start = Instant::now();
            let probe_seq = rand::random::<u32>();
            let probe_size = if current_mtu > 100 { current_mtu - 50 } else { 1000 };

            let probe_hdr = TunnelHeader {
                pkt_type: PktType::PmtudProbe as u8,
                flags: 0,
                seq: probe_seq,
                ack_seq: 0,
                conn_id,
            };
            let probe_aad = probe_hdr.encode().to_vec();
            let payload = vec![0u8; (probe_size as usize).min(1500)];
            if let Ok(enc) = crypto_pool
                .encrypt(cipher_send.clone(), probe_aad, payload)
                .await
            {
                let mut pkt = Vec::with_capacity(18 + enc.len());
                pkt.extend_from_slice(&probe_hdr.encode());
                pkt.extend_from_slice(&enc);
                let final_pkt = if stealth_enabled {
                    wrap_privacy_record(&pkt, privacy_bucket)
                } else {
                    pkt
                };
                let _ = socket.send(&final_pkt).await;
            }
        } else if Instant::now().duration_since(probe_start) > Duration::from_secs(5) {
            probing = false;
            if current_mtu > 1280 {
                let new_mtu = (current_mtu as u32 * 9 / 10) as u16;
                reliable_tx.lock().await.update_mtu(new_mtu);
                log::debug!("PMTU 探测超时，减小 MTU 到 {}", new_mtu);
            }
        }
    }
}

// ==================== 监控接口 ====================
pub async fn run_monitor(
    port: u16,
    start_time: Instant,
    clients_by_connid: Arc<ShardedMap<u64, Arc<ClientSession>>>,
) {
    let addr = format!("0.0.0.0:{}", port);
    if let Ok(listener) = TcpListener::bind(&addr).await {
        log::info!("监控接口已启动：http://{}", addr);
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut stats = Vec::new();
                clients_by_connid.iter(|_conn_id, sess| {
                    let tx = sess.tx_bytes.load(Ordering::Relaxed);
                    let rx = sess.rx_bytes.load(Ordering::Relaxed);
                    let rtt_ms = sess
                        .reliable_tx
                        .try_lock()
                        .map(|tx| tx.rtt_estimate().as_millis())
                        .unwrap_or(0);
                    let ip = sess
                        .assigned_ip4
                        .read()
                        .unwrap()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    stats.push(format!(
                        "{{\"ip\":\"{}\",\"conn_id\":{},\"rtt_ms\":{},\"tx_bytes\":{},\"rx_bytes\":{},\"last_seen\":{},\"addr\":\"{}\"}}",
                        ip,
                        sess.conn_id,
                        rtt_ms,
                        tx,
                        rx,
                        sess.last_seen.read().unwrap_or_else(|poisoned| poisoned.into_inner()).elapsed().as_secs(),
                        sess.socket_addr()
                    ));
                });
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"uptime_seconds\": {}, \"total_clients\": {}, \"clients\": [{}]}}",
                    start_time.elapsed().as_secs(),
                    clients_by_connid.len(),
                    stats.join(",")
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    }
}

// ==================== 客户端会话初始化 ====================
pub async fn run_client_session_init(
    args: &Args,
    psk: &Arc<Zeroizing<Vec<u8>>>,
    _static_secret: &Option<StaticSecret>,
    static_public: &Option<PublicKey>,
    peer_static_public_bytes: &Option<[u8; 32]>,
    handshake_ctx: &Arc<TokioMutex<Option<ClientHandshakeContext>>>,
    socket: &Arc<UdpSocket>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let peer_addr: SocketAddr = args.peer.as_deref().ok_or("客户端缺少 --peer")?.parse()?;
    socket.connect(peer_addr).await?;
    log::info!("已连接至服务端 {}", peer_addr);
    let eph_secret = ReusableSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let (pq_public, pq_secret) = mlkem768::keypair();
    let static_pub = static_public.as_ref().ok_or("客户端缺少静态公钥")?;
    let challenge: u64 = rand::random();
    let conn_id: u64 = rand::random();
    let init_msg = build_handshake_init(
        &psk,
        &eph_public,
        static_pub,
        pq_public.as_bytes(),
        challenge,
        conn_id,
    );
    let header = TunnelHeader {
        pkt_type: PktType::HandshakeInit as u8,
        flags: 0,
        seq: 0,
        ack_seq: 0,
        conn_id,
    };
    let mut pkt = Vec::with_capacity(18 + init_msg.len());
    pkt.extend_from_slice(&header.encode());
    pkt.extend_from_slice(&init_msg);
    socket.send(&pkt).await?;

    *handshake_ctx.lock().await = Some(ClientHandshakeContext {
        eph_secret,
        pq_secret,
        challenge,
        peer_static_pub: peer_static_public_bytes.ok_or("客户端缺少对方静态公钥")?,
        conn_id,
    });
    Ok(())
}

// ==================== 基准测试 ====================
pub async fn run_bench(
    server: SocketAddr,
    psk_hex: &str,
    duration: u64,
    clients: usize,
    cc: &str,
    fec: usize,
    rate_limit_mbps: f64,
) {
    if clients == 0 || duration == 0 {
        log::error!("基准测试的 clients 和 duration 必须大于 0");
        return;
    }
    println!(
        "🚀 开始基准测试: {} 个客户端, 时长 {}s, CC={}, FEC={}",
        clients, duration, cc, fec
    );
    let psk = match hex::decode(psk_hex) {
        Ok(v) if v.len() >= 32 => v,
        Ok(_) => { log::error!("PSK 必须至少为 32 字节"); return; }
        Err(e) => { log::error!("PSK 解码失败: {}", e); return; }
    };
    let psk = Arc::new(Zeroizing::new(psk));
    let start_time = Instant::now();
    let total_bytes = Arc::new(AtomicU64::new(0));
    let total_packets = Arc::new(AtomicU64::new(0));
    let total_rtt_sum = Arc::new(AtomicU64::new(0));
    let total_rtt_count = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();

    for i in 0..clients {
        let psk = psk.clone();
        let server = server;
        let duration = duration;
        let cc = cc.to_string();
        let fec = fec;
        let total_bytes = total_bytes.clone();
        let total_packets = total_packets.clone();
        let _total_rtt_sum = total_rtt_sum.clone();
        let _total_rtt_count = total_rtt_count.clone();
        let rate_limit = rate_limit_mbps / clients as f64;

        handles.push(tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("客户端 {} 绑定失败: {}", i, e);
                    return;
                }
            };
            if let Err(e) = socket.connect(server).await {
                log::error!("客户端 {} 连接失败: {}", i, e);
                return;
            }

            // 握手
            let eph_secret = EphemeralSecret::random_from_rng(OsRng);
            let eph_public = PublicKey::from(&eph_secret);
            let static_secret = StaticSecret::random_from_rng(OsRng);
            let static_public = PublicKey::from(&static_secret);
            let challenge: u64 = rand::random();
            let conn_id: u64 = rand::random();
            let (pq_public, pq_secret) = mlkem768::keypair();

            let init_msg = build_handshake_init(
                &psk, &eph_public, &static_public, pq_public.as_bytes(), challenge, conn_id
            );
            let header = TunnelHeader {
                pkt_type: PktType::HandshakeInit as u8,
                flags: 0,
                seq: 0,
                ack_seq: 0,
                conn_id,
            };
            let mut pkt = Vec::with_capacity(18 + init_msg.len());
            pkt.extend_from_slice(&header.encode());
            pkt.extend_from_slice(&init_msg);
            let _ = socket.send(&pkt).await;

            // 等待握手响应
            let mut resp_buf = vec![0u8; MAX_PACKET];
            let mut cipher_send: Option<Arc<ChaCha20Poly1305>> = None;
            let mut cipher_recv: Option<Arc<ChaCha20Poly1305>> = None;

            if let Ok((n, _)) = socket.recv_from(&mut resp_buf).await {
                if n >= 18 {
                    if let Some(resp_hdr) = TunnelHeader::decode(&resp_buf[..18]) {
                        if resp_hdr.pkt_type == PktType::HandshakeResp as u8 {
                            let resp_body = &resp_buf[18..n];
                            if resp_body.len() >= 32 {
                                let prefix_len = 32 + 32 + PQ_CIPHERTEXT_SIZE + 8 + 8;
                                if resp_body.len() < prefix_len + NONCE_SIZE + TAG_SIZE { return; }
                                let server_eph_bytes: [u8; 32] = match resp_body[0..32].try_into() {
                                    Ok(b) => b,
                                    Err(_) => return,
                                };
                                let server_public = PublicKey::from(server_eph_bytes);
                                let eph_dh = eph_secret.diffie_hellman(&server_public);
                                let server_static_bytes: [u8; 32] = match resp_body[32..64].try_into() {
                                    Ok(b) => b,
                                    Err(_) => return,
                                };
                                let static_dh = static_secret.diffie_hellman(&PublicKey::from(server_static_bytes));
                                let pq_ct = match mlkem768::Ciphertext::from_bytes(&resp_body[64..64 + PQ_CIPHERTEXT_SIZE]) {
                                    Ok(ct) => ct,
                                    Err(_) => return,
                                };
                                let pq_shared = mlkem768::decapsulate(&pq_ct, &pq_secret);
                                let pq_bytes: [u8; 32] = match pq_shared.as_bytes().try_into() {
                                    Ok(v) => v,
                                    Err(_) => return,
                                };
                                let (key_send, key_recv) = derive_session_keys(
                                    eph_dh.as_bytes(),
                                    static_dh.as_bytes(),
                                    &pq_bytes,
                                    &psk,
                                    false,
                                );
                                cipher_send = Some(Arc::new(ChaCha20Poly1305::new(&key_send)));
                                cipher_recv = Some(Arc::new(ChaCha20Poly1305::new(&key_recv)));
                            }
                        }
                    }
                }
            }

            let cipher_send = match cipher_send {
                Some(c) => c,
                None => return,
            };
            let cipher_recv = match cipher_recv {
                Some(c) => c,
                None => return,
            };

            let crypto_pool = CryptoPool::new(2);
            let mut rng = OsRng;
            let mut data = vec![0u8; BENCHMARK_PACKET_SIZE];
            rng.fill_bytes(&mut data);
            let tx_bytes = Arc::new(AtomicU64::new(0));
            let rx_bytes = Arc::new(AtomicU64::new(0));
            let mut reliable_tx = ReliableTx::new(INITIAL_MTU_V4, 8, &cc, fec, tx_bytes.clone());
            let _reliable_rx = ReliableRx::new(256, rx_bytes.clone());
            let _anti_replay = AntiReplay::new();
            let mut tx_limiter = RateLimiter::new(rate_limit);
            let _rx_limiter = RateLimiter::new(rate_limit);

            let end_time = Instant::now() + Duration::from_secs(duration);
            let mut sent = 0u64;
            let mut interval = tokio::time::interval(BENCHMARK_INTERVAL);

            while Instant::now() < end_time {
                interval.tick().await;
                if !reliable_tx.can_send() || !tx_limiter.allow(data.len()) {
                    continue;
                }

                let seq = reliable_tx.next_seq;
                let data_hdr = TunnelHeader {
                    pkt_type: PktType::Data as u8,
                    flags: 0x02,
                    seq,
                    ack_seq: 0,
                    conn_id,
                };
                let aad = data_hdr.encode().to_vec();
                if let Ok(enc) = crypto_pool
                    .encrypt(cipher_send.clone(), aad.clone(), data.clone())
                    .await
                {
                    let (actual_seq, stored) = reliable_tx.push(enc.clone(), data_hdr.flags);
                    let mut data_hdr = data_hdr;
                    data_hdr.seq = actual_seq;
                    let mut pkt = Vec::with_capacity(18 + stored.len());
                    pkt.extend_from_slice(&data_hdr.encode());
                    pkt.extend_from_slice(&stored);
                    if let Err(e) = socket.send(&pkt).await {
                        log::debug!("发送失败: {}", e);
                        break;
                    }
                    sent += 1;
                    total_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                    total_packets.fetch_add(1, Ordering::Relaxed);
                }

                // 尝试接收ACK
                if let Ok((n, _)) = socket.recv_from(&mut resp_buf).await {
                    if n >= 18 {
                        if let Some(hdr) = TunnelHeader::decode(&resp_buf[..18]) {
                            if hdr.pkt_type == PktType::Ack as u8 {
                                let body = &resp_buf[18..n];
                                if let Ok(dec) = crypto_pool
                                    .decrypt(cipher_recv.clone(), hdr.encode().to_vec(), body.to_vec())
                                    .await
                                {
                                    if let Some((ack_seq, sack_blocks)) = decode_ack_payload(&dec) {
                                        reliable_tx.ack(ack_seq, &sack_blocks, Instant::now());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            log::debug!("客户端 {} 发送 {} 包", i, sent);
        }));
    }

    // 等待所有客户端完成
    for h in handles {
        let _ = h.await;
    }

    let elapsed = start_time.elapsed();
    let total = total_bytes.load(Ordering::Relaxed);
    let packets = total_packets.load(Ordering::Relaxed);
    let mbps = (total as f64 * 8.0) / (elapsed.as_secs_f64() * 1024.0 * 1024.0);
    let avg_rtt_ms = if total_rtt_count.load(Ordering::Relaxed) > 0 {
        total_rtt_sum.load(Ordering::Relaxed) as f64 / total_rtt_count.load(Ordering::Relaxed) as f64
    } else {
        0.0
    };
    println!(
        "✅ 基准测试完成: 总传输 {} bytes ({} packets), 耗时 {:.2}s, 吞吐量 {:.2} Mbps, 平均RTT {:.2}ms",
        total, packets, elapsed.as_secs_f64(), mbps, avg_rtt_ms
    );
}
