// ============================================================================
// ArkIris v1 - high performance hybrid post-quantum tunnel
// 包含: ConnID, 连接迁移, BBR状态机, FEC恢复, 长度隐藏隐私封装, ACL,
//       Jitter, IPv6-MTU适配, 监控统计, 基准测试, 后台运行, PMTU独立探测
// 作者：Arklight Project
// Copyright © Arklight Project™
// ============================================================================

mod cli;
mod constants;
mod crypto;
mod net;
mod protocol;
mod service;
mod session;
mod transport;
mod tui;

use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};
use clap::Parser;
use ipnetwork::IpNetwork;
use rand::rngs::OsRng;
use std::{
    convert::TryInto,
    env,
    fs::File,
    io::IsTerminal,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    net::UdpSocket,
    sync::{mpsc, Mutex as TokioMutex},
    time::{interval, sleep, sleep_until},
};
use tun::Configuration;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SharedSecret as PqSharedSecret};
use zeroize::Zeroizing;

use crate::cli::*;
use crate::constants::*;
use crate::crypto::*;
use crate::net::*;
use crate::net::batch_udp;
use crate::protocol::*;
use crate::service::*;
use crate::session::*;
use crate::transport::*;
use crate::tui::{Metrics, TuiConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 日志初始化
    let args = Args::parse();

    // 设置日志级别
    let log_level = match args.log_level.as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };

    let mut logger = env_logger::Builder::new();
    logger.filter_level(log_level).format_timestamp_millis();
    if let Some(log_file) = &args.log_file {
        let file = File::create(log_file)?;
        logger.target(env_logger::Target::Pipe(Box::new(file)));
    }
    let _ = logger.try_init();

    // 处理子命令
    if let Some(Commands::Bench {
        server,
        psk,
        duration,
        clients,
        cc,
        fec,
        rate_limit_mbps,
    }) = args.command.clone()
    {
        run_bench(server, &psk, duration, clients, &cc, fec, rate_limit_mbps).await;
        return Ok(());
    }

    if args.mode != "client" && args.mode != "server" {
        return Err("--mode 只能是 client 或 server".into());
    }
    if !(576..=1500).contains(&args.mtu) {
        return Err("--mtu 必须在 576..=1500 之间".into());
    }
    if !args.rate_limit_mbps.is_finite() || args.rate_limit_mbps < 0.0 {
        return Err("--rate-limit-mbps 必须是非负有限数字".into());
    }
    if !args.rate_burst_seconds.is_finite() || !(0.01..=10.0).contains(&args.rate_burst_seconds) {
        return Err("--rate-burst-seconds 必须在 0.01..=10.0 之间".into());
    }
    if !args.pacing_mbps.is_finite() || args.pacing_mbps < 0.0 {
        return Err("--pacing-mbps 必须是非负有限数字".into());
    }
    if !(64..=LDT_MAX_PACKET).contains(&args.ldt_max_packet) {
        return Err(format!("--ldt-max-packet 必须在 64..={} 之间", LDT_MAX_PACKET).into());
    }
    if args.fec > 32 {
        return Err("--fec 最大为 32".into());
    }
    if args.cc != "bbr" && args.cc != "cubic" {
        return Err("--cc 只能是 bbr 或 cubic".into());
    }

    // 兼容 hide-vpn
    let privacy_enabled = args.privacy || args.stealth_vpn || args.hide_vpn;
    if args.privacy_bucket != 0 && !args.privacy_bucket.is_power_of_two() {
        return Err("--privacy-bucket 必须为 0 或 2 的幂".into());
    }
    if args.privacy_bucket > 512 {
        return Err("--privacy-bucket 最大为 512".into());
    }
    let jitter_ms = args.jitter;
    let privacy_bucket = args.privacy_bucket;
    let fec_size = args.fec;
    let cc_type = args.cc.clone();
        let acl_rules = if let Some(ref acl_str) = args.acl {
        parse_acl(acl_str)
    } else {
        Vec::new()
    };

    // 后台运行
    if args.daemonize {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let exe = env::current_exe()?;
            let args: Vec<String> = env::args().skip(1).collect();
            let mut cmd = Command::new(exe);
            cmd.args(args);
            cmd.creation_flags(0x00000008);
            cmd.spawn()?;
            std::process::exit(0);
        }
        #[cfg(not(target_os = "windows"))]
        {
            unsafe {
                if libc::fork() > 0 {
                    std::process::exit(0);
                }
                libc::setsid();
            }
        }
    }

    // 加载密钥
    let psk_bytes = Zeroizing::new(
        hex::decode(&args.psk).map_err(|e| format!("PSK 解码失败：{}", e))?,
    );
    if psk_bytes.len() < 32 {
        return Err("PSK 必须至少为 32 字节".into());
    }

    fn decode_32(value: &str, label: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let bytes = hex::decode(value).map_err(|e| format!("{} Hex 解码失败: {}", label, e))?;
        bytes.as_slice().try_into().map_err(|_| format!("{} 必须恰好 32 字节", label).into())
    }
    let static_secret_bytes = match args.static_secret.as_deref() {
        Some(v) => Some(decode_32(v, "静态私钥")?),
        None => None,
    };
    let peer_static_public_bytes = match args.peer_static_public.as_deref() {
        Some(v) => Some(decode_32(v, "对方静态公钥")?),
        None => None,
    };
    let mut allowed_static_pubs = Vec::with_capacity(args.allowed_clients.len());
    for value in &args.allowed_clients {
        allowed_static_pubs.push(decode_32(value, "允许客户端公钥")?);
    }

    if args.mode == "server" && (static_secret_bytes.is_none() || allowed_static_pubs.is_empty()) {
        return Err("服务端必须提供 --static-secret 和 --allowed-clients".into());
    }
    if args.mode == "client"
        && (static_secret_bytes.is_none() || peer_static_public_bytes.is_none())
    {
        return Err("客户端必须提供 --static-secret 和 --peer-static-public".into());
    }

    let static_secret = static_secret_bytes.map(StaticSecret::from);
    let static_public = static_secret.as_ref().map(|s| PublicKey::from(s));
    let subnet4: IpNetwork = args.subnet4.parse()?;
    let subnet6: IpNetwork = args.subnet6.parse()?;
    let mtu = args.mtu;

    let (server_ip4, server_ip6) = {
        let mut iter4 = subnet4.iter();
        iter4.next();
        let srv4 = iter4.next().ok_or("subnet4 太小")?;
        let mut iter6 = subnet6.iter();
        iter6.next();
        let srv6 = iter6.next().ok_or("subnet6 太小")?;
        (srv4, srv6)
    };

    let persisted_state = PersistedState::load(&args.state_file);

    // TUN 设备
    let mut tun_config = Configuration::default();
    tun_config
        .name("arkiris0")
        .address("10.255.255.254")
        .netmask("255.255.255.0")
        .mtu(mtu as i32)
        .up();
    let tun = Arc::new(TokioMutex::new(tun::create_as_async(&tun_config)?));
    log::info!("TUN 接口 arkiris0 已创建");

    let socket = UdpSocket::bind(&args.bind).await?;
    // Larger kernel queues prevent burst loss from becoming application-level
    // retransmissions on fast links.  The OS may clamp these values.
    let std_socket = socket2::Socket::from(socket.into_std()?);
    let _ = std_socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = std_socket.set_send_buffer_size(4 * 1024 * 1024);
    std_socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(std_socket.into())?;
    if let Err(e) = batch_udp::enable_ecn(&socket) { log::debug!("ECN socket setup unavailable: {}", e); }
    log::info!("UDP 监听于 {}", args.bind);
    let socket = Arc::new(socket);
    let psk = Arc::new(psk_bytes.clone());

    let (to_udp_tx, mut to_udp_rx) = transport::channel();
    let (to_tun_tx, to_tun_rx) = mpsc::channel::<Vec<u8>>(1024);

    // 映射
    let clients_by_ip: Arc<ShardedMap<IpAddr, Arc<ClientSession>>> = Arc::new(ShardedMap::new());
    let clients_by_addr: Arc<ShardedMap<SocketAddr, IpAddr>> = Arc::new(ShardedMap::new());
    let clients_by_connid: Arc<ShardedMap<u64, Arc<ClientSession>>> = Arc::new(ShardedMap::new());
    let pending_sessions: Arc<ShardedMap<SocketAddr, (Arc<ClientSession>, Instant)>> =
        Arc::new(ShardedMap::new());
    // HandshakeInit challenges are single-use for the replay window.
    let handshake_replay_cache = Arc::new(HandshakeReplayCache::new());

    // IP 池
    let ip_pool = Arc::new(TokioMutex::new(IpPool::new(subnet4, &persisted_state)));
    let ip_pool_v6 = Arc::new(TokioMutex::new(IpPoolV6::new(subnet6, &persisted_state)));
    let state_file = args.state_file.clone();
    let client_state: Arc<TokioMutex<Option<ClientOwnState>>> = Arc::new(TokioMutex::new(None));
    let handshake_ctx: Arc<TokioMutex<Option<ClientHandshakeContext>>> =
        Arc::new(TokioMutex::new(None));
    let crypto_pool = Arc::new(CryptoPool::new(CRYPTO_WORKERS));
    let active_clients_count = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();
    let metrics = Metrics::new();

    // 监控
    if let Some(port) = args.monitor_port {
        tokio::spawn(run_monitor(
            port,
            start_time,
            clients_by_connid.clone(),
        ));
    }

    let tui_stop = if !args.daemonize && !args.no_tui && std::io::stdout().is_terminal() {
        Some(tui::spawn(TuiConfig {
            theme: tui::Theme::parse(&args.tui_theme),
            refresh_ms: args.tui_refresh_ms,
            mode: args.mode.clone(),
            bind: args.bind.clone(),
            peer: args.peer.clone(),
            cc: cc_type.clone(),
            fec: fec_size,
            mtu,
            privacy: privacy_enabled,
            pq: true,
            ldt: args.ldt,
            pacing_mbps: args.pacing_mbps,
            tun_backend: format!("{} / {}", tun_platform_name(), tun_fast::offload_capability()),
        }, metrics.clone(), start_time))
    } else { None };

    // --- 客户端逻辑 ---
    if args.mode == "client" {
        let args_clone = args.clone();
        let psk_clone = psk.clone();
        let static_secret_clone = static_secret.clone();
        let static_public_clone = static_public.clone();
        let peer_static_public_bytes_clone = peer_static_public_bytes.clone();
        let handshake_ctx_clone = handshake_ctx.clone();
        let socket_clone = socket.clone();
        let client_state_clone = client_state.clone();
        let crypto_pool_clone = crypto_pool.clone();
        let privacy_enabled_clone = privacy_enabled;
        let jitter_ms_clone = jitter_ms;
        let privacy_bucket_clone = privacy_bucket;
        let _cc_type_clone = cc_type.clone();
        let _fec_size_clone = fec_size;
        let _tx_bytes = Arc::new(AtomicU64::new(0));
        let _rx_bytes = Arc::new(AtomicU64::new(0));

        tokio::spawn(async move {
            let mut retry_delay = Duration::from_secs(2);
            loop {
                log::info!("正在尝试连接服务端...");
                *client_state_clone.lock().await = None;
                *handshake_ctx_clone.lock().await = None;
                match run_client_session_init(
                    &args_clone,
                    &psk_clone,
                    &static_secret_clone,
                    &static_public_clone,
                    &peer_static_public_bytes_clone,
                    &handshake_ctx_clone,
                    &socket_clone,
                )
                .await
                {
                    Ok(_) => {
                        // 等待握手完成（使用 HANDSHAKE_TIMEOUT 作为超时上限）
                        let success = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                            loop {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                if client_state_clone.lock().await.is_some() {
                                    break true;
                                }
                            }
                        })
                        .await
                        .unwrap_or(false);
                        if success {
                            log::info!("客户端初始化成功，进入数据转发模式");
                            retry_delay = Duration::from_secs(2);
                            let mut last_dhcp_send = Instant::now();
                            let mut dhcp_sent = false;

                            // 启动 PMTU 探测
                            let pmtu_socket = socket_clone.clone();
                            let pmtu_conn_id = {
                                let state = client_state_clone.lock().await;
                                if let Some(s) = state.as_ref() {
                                    s.conn_id
                                } else {
                                    0
                                }
                            };
                            if pmtu_conn_id != 0 {
                                let (pmtu_cipher, pmtu_tx) = {
                                    let state = client_state_clone.lock().await;
                                    match state.as_ref() {
                                        Some(s) => {
                                            (Some(s.cipher_send.clone()), Some(s.reliable_tx.clone()))
                                        }
                                        None => (None, None),
                                    }
                                };
                                if let (Some(cipher), Some(reliable_tx)) = (pmtu_cipher, pmtu_tx) {
                                    tokio::spawn(pmtu_probe_loop(
                                        pmtu_socket,
                                        pmtu_conn_id,
                                        crypto_pool_clone.clone(),
                                        cipher,
                                        reliable_tx,
                                        privacy_enabled_clone,
                                        privacy_bucket_clone,
                                    ));
                                }
                            }

                            loop {
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                let state_guard = client_state_clone.lock().await;
                                if let Some(s) = state_guard.as_ref() {
                                    if Instant::now().duration_since(s.last_ka_resp) > KA_TIMEOUT {
                                        log::warn!("服务端心跳超时，准备重连");
                                        break;
                                    }
                                    // KeepAlive
                                    let ka_header = TunnelHeader {
                                        pkt_type: PktType::KeepAlive as u8,
                                        flags: 0,
                                        seq: 0,
                                        ack_seq: 0,
                                        conn_id: s.conn_id,
                                    };
                                    let ka_aad = ka_header.encode().to_vec();
                                    if let Ok(enc) = crypto_pool_clone
                                        .encrypt(s.cipher_send.clone(), ka_aad, vec![])
                                        .await
                                    {
                                        let mut hdr_pkt = Vec::with_capacity(18 + enc.len());
                                        hdr_pkt.extend_from_slice(&ka_header.encode());
                                        hdr_pkt.extend_from_slice(&enc);
                                        let final_pkt = if privacy_enabled_clone {
                                            wrap_privacy_record(&hdr_pkt, privacy_bucket_clone)
                                        } else {
                                            hdr_pkt
                                        };
                                        if jitter_ms_clone > 0 {
                                            let delay = rand::random::<u64>() % jitter_ms_clone;
                                            sleep(Duration::from_millis(delay)).await;
                                        }
                                        let _ = socket_clone.send(&final_pkt).await;
                                    }
                                    // DHCP
                                    if !dhcp_sent
                                        || Instant::now().duration_since(last_dhcp_send)
                                            > DHCP_RETRY_INTERVAL
                                    {
                                        if s.assigned_ip4.is_none() {
                                            let mut cid = [0u8; 16];
                                            let client_static_pub =
                                                static_public_clone.as_ref().unwrap();
                                            cid.copy_from_slice(&client_static_pub.as_bytes()[..16]);
                                            let requested_ip = s.assigned_ip4;
                                            let dhcp_req = DhcpRequest {
                                                client_id: cid,
                                                requested_ip,
                                            };
                                            let req_data = encode_dhcp_request(&dhcp_req);
                                            let dhcp_hdr = TunnelHeader {
                                                pkt_type: PktType::DhcpReq as u8,
                                                flags: 0,
                                                seq: 0,
                                                ack_seq: 0,
                                                conn_id: s.conn_id,
                                            };
                                            let dhcp_aad = dhcp_hdr.encode().to_vec();
                                            if let Ok(enc) = crypto_pool_clone
                                                .encrypt(s.cipher_send.clone(), dhcp_aad, req_data)
                                                .await
                                            {
                                                let mut hdr_pkt =
                                                    Vec::with_capacity(18 + enc.len());
                                                hdr_pkt.extend_from_slice(&dhcp_hdr.encode());
                                                hdr_pkt.extend_from_slice(&enc);
                                                let final_pkt = if privacy_enabled_clone {
                                                    wrap_privacy_record(&hdr_pkt, privacy_bucket_clone)
                                                } else {
                                                    hdr_pkt
                                                };
                                                if jitter_ms_clone > 0 {
                                                    let delay = rand::random::<u64>()
                                                        % jitter_ms_clone;
                                                    sleep(Duration::from_millis(delay)).await;
                                                }
                                                let _ = socket_clone.send(&final_pkt).await;
                                                last_dhcp_send = Instant::now();
                                                dhcp_sent = true;
                                            }
                                        }
                                    }
                                } else {
                                    break;
                                }
                            }
                        } else {
                            log::error!("握手超时");
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "客户端会话失败：{}, {} 秒后重试...",
                            e,
                            retry_delay.as_secs()
                        );
                        tokio::time::sleep(retry_delay).await;
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(60));
                    }
                }
            }
        });
    }

    // --- UDP 接收循环 ---
    let _udp_recv = {
        let socket = socket.clone();
        let to_tun_tx = to_tun_tx.clone();
        let clients_by_ip = clients_by_ip.clone();
        let clients_by_addr = clients_by_addr.clone();
        let clients_by_connid = clients_by_connid.clone();
        let pending_sessions = pending_sessions.clone();
        let handshake_replay_cache = handshake_replay_cache.clone();
        let psk = psk.clone();
        let ip_pool = ip_pool.clone();
        let ip_pool_v6 = ip_pool_v6.clone();
        let allowed_static_pubs = allowed_static_pubs.clone();
        let server_static_secret = static_secret.clone();
        let server_static_public = static_public.clone();
        let dns4 = args.dns4.clone();
        let dns6 = args.dns6.clone();
        let crypto_pool = crypto_pool.clone();
        let state_file = state_file.clone();
        let active_clients = active_clients_count.clone();
        let mode = args.mode.clone();
        let client_state = client_state.clone();
        let handshake_ctx = handshake_ctx.clone();
        let server_ip4_str = server_ip4.to_string();
        let server_ip6 = server_ip6;
        let static_secret_client = static_secret.clone();
        let static_public_client = static_public.clone();
        let privacy_enabled = privacy_enabled;
        let jitter_ms = jitter_ms;
        let privacy_bucket = privacy_bucket;
        let acl_rules = acl_rules.clone();
        let cc_type = cc_type.clone();
        let fec_size = fec_size;
        let tx_bytes = Arc::new(AtomicU64::new(0));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let metrics = metrics.clone();

        tokio::spawn(async move {
            loop {
                let batch = match batch_udp::recv_batch(&socket, crate::constants::UDP_BATCH_SIZE).await {
                    Ok(batch) => batch,
                    Err(e) => {
                        log::error!("UDP 批量接收错误：{}", e);
                        continue;
                    }
                };
                for datagram in batch {
                    let src = match datagram.addr { Some(addr) => addr, None => continue };
                    if datagram.ecn == Some(3) { metrics.ecn_ce.fetch_add(1, Ordering::Relaxed); }
                    let n = datagram.data.len();
                    metrics.udp_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    metrics.packets_rx.fetch_add(1, Ordering::Relaxed);
                    let mut payload = datagram.data.as_slice();
                if privacy_enabled {
                    if let Some(unwrapped) = unwrap_privacy_record(payload) {
                        payload = unwrapped;
                    } else if payload.len() >= PRIVACY_FRAME_HEADER
                        && payload[0] == PRIVACY_MAGIC[0]
                        && payload[1] == PRIVACY_MAGIC[1]
                    {
                        // Looks like an ArkIris privacy frame but failed validation.
                        continue;
                    }
                }

                if payload.len() < 18 {
                    continue;
                }

                let hdr = match TunnelHeader::decode(&payload[..18]) {
                    Some(h) => h,
                    None => continue,
                };
                if hdr.flags & FLAG_LDT != 0 { metrics.ldt_rx_packets.fetch_add(1, Ordering::Relaxed); }
                if hdr.flags & FLAG_ECN_CE != 0 { metrics.ecn_ce.fetch_add(1, Ordering::Relaxed); }
                let body = &payload[18..];
                let aad = hdr.encode().to_vec();

                if mode == "client" {
                    if hdr.pkt_type == PktType::HandshakeResp as u8 {
                        let ctx_guard = handshake_ctx.lock().await;
                        if let Some(ctx) = ctx_guard.as_ref() {
                            let resp = body;
                            let prefix_len = 32 + 32 + PQ_CIPHERTEXT_SIZE + 8 + 8;
                            if resp.len() < prefix_len + NONCE_SIZE + TAG_SIZE {
                                continue;
                            }
                            let server_eph_bytes: [u8; 32] = match resp[0..32].try_into().ok() {
                                Some(b) => b,
                                None => continue,
                            };
                            let server_static_bytes: [u8; 32] = match resp[32..64].try_into().ok() {
                                Some(b) => b,
                                None => continue,
                            };
                            if server_static_bytes != ctx.peer_static_pub {
                                continue;
                            }
                            let server_public = PublicKey::from(server_eph_bytes);
                            let eph_dh = ctx.eph_secret.diffie_hellman(&server_public);
                            let static_sec = static_secret_client.as_ref().unwrap();
                            let static_dh = static_sec.diffie_hellman(&PublicKey::from(ctx.peer_static_pub));
                            let pq_ct = match mlkem768::Ciphertext::from_bytes(&resp[64..64 + PQ_CIPHERTEXT_SIZE]) {
                                Ok(ct) => ct,
                                Err(_) => continue,
                            };
                            let pq_shared = mlkem768::decapsulate(&pq_ct, &ctx.pq_secret);
                            let pq_bytes: [u8; 32] = match pq_shared.as_bytes().try_into() {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            let (key_send, key_recv) = derive_session_keys(
                                eph_dh.as_bytes(),
                                static_dh.as_bytes(),
                                &pq_bytes,
                                &psk,
                                false,
                            );
                            let cipher_send = Arc::new(ChaCha20Poly1305::new(&key_send));
                            let cipher_recv = Arc::new(ChaCha20Poly1305::new(&key_recv));
                            if verify_handshake_resp(
                                &crypto_pool,
                                cipher_recv.clone(),
                                &psk,
                                resp,
                                ctx.challenge,
                                &ctx.peer_static_pub,
                                ctx.conn_id,
                            )
                            .await
                            {
                                log::info!("客户端握手成功, ConnID={}", ctx.conn_id);
                                *client_state.lock().await = Some(ClientOwnState {
                                    cipher_send: cipher_send.clone(),
                                    cipher_recv: cipher_recv.clone(),
                                    reliable_tx: Arc::new(TokioMutex::new(ReliableTx::new(
                                        INITIAL_MTU_V4,
                                        8,
                                        &cc_type,
                                        fec_size,
                                        tx_bytes.clone(),
                                    ))),
                                    reliable_rx: Arc::new(TokioMutex::new(ReliableRx::new(
                                        256,
                                        rx_bytes.clone(),
                                    ))),
                                    anti_replay: Arc::new(TokioMutex::new(AntiReplay::new())),
                                    assigned_ip4: None,
                                    assigned_ip6: None,
                                    tx_limiter: Arc::new(TokioMutex::new(RateLimiter::new_with_burst(
                                        args.rate_limit_mbps,
                                        args.rate_burst_seconds,
                                    ))),
                                    last_ka_resp: Instant::now(),
                                    conn_id: ctx.conn_id,
                                });
                                *handshake_ctx.lock().await = None;

                                // DHCP 请求
                                let mut cid = [0u8; 16];
                                let client_static_pub = static_public_client.as_ref().unwrap();
                                cid.copy_from_slice(&client_static_pub.as_bytes()[..16]);
                                let dhcp_req = DhcpRequest {
                                    client_id: cid,
                                    requested_ip: None,
                                };
                                let req_data = encode_dhcp_request(&dhcp_req);
                                let dhcp_hdr = TunnelHeader {
                                    pkt_type: PktType::DhcpReq as u8,
                                    flags: 0,
                                    seq: 0,
                                    ack_seq: 0,
                                    conn_id: ctx.conn_id,
                                };
                                let dhcp_aad = dhcp_hdr.encode().to_vec();
                                if let Ok(enc) = crypto_pool
                                    .encrypt(cipher_send, dhcp_aad, req_data)
                                    .await
                                {
                                    let mut hdr_pkt = Vec::with_capacity(18 + enc.len());
                                    hdr_pkt.extend_from_slice(&dhcp_hdr.encode());
                                    hdr_pkt.extend_from_slice(&enc);
                                    let final_pkt = if privacy_enabled {
                                        wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                    } else {
                                        hdr_pkt
                                    };
                                    if jitter_ms > 0 {
                                        let delay = rand::random::<u64>() % jitter_ms;
                                        sleep(Duration::from_millis(delay)).await;
                                    }
                                    let _ = socket.send_to(&final_pkt, src).await;
                                }
                            }
                        }
                    } else {
                        let cipher_recv = {
                            let state_guard = client_state.lock().await;
                            if let Some(s) = state_guard.as_ref() {
                                s.cipher_recv.clone()
                            } else {
                                continue;
                            }
                        };
                        match hdr.pkt_type {
                            x if x == PktType::DhcpAck as u8 => {
                                if let Ok(decrypted) = crypto_pool
                                    .decrypt(cipher_recv, aad, body.to_vec())
                                    .await
                                {
                                    if let Some(reply) = decode_dhcp_reply(&decrypted) {
                                        if let Some(ip4) = reply.ip4 {
                                            if let Err(e) = RouteManager::configure_interface(
                                                "arkiris0",
                                                &format!("{}/{}", ip4, 24),
                                                reply.mtu as u32,
                                            ) {
                                                log::error!("配置 arkiris0 失败: {}", e);
                                                continue;
                                            }
                                            for (dest, gw) in &reply.routes {
                                                if dest.contains(':') {
                                                    if let Err(e) = RouteManager::add_route_v6(dest, gw, "arkiris0") {
                                                        log::warn!("添加 IPv6 路由 {} via {} 失败: {}", dest, gw, e);
                                                    }
                                                } else {
                                                    if let Err(e) = RouteManager::add_route(dest, gw, "arkiris0") {
                                                        log::warn!("添加 IPv4 路由 {} via {} 失败: {}", dest, gw, e);
                                                    }
                                                }
                                            }
                                        }
                                        let mut state_guard = client_state.lock().await;
                                        if let Some(state) = state_guard.as_mut() {
                                            state.assigned_ip4 = reply.ip4;
                                            state.assigned_ip6 = reply.ip6;
                                            state
                                                .reliable_tx
                                                .lock()
                                                .await
                                                .update_mtu(reply.mtu);
                                        }
                                        log::info!("客户端获取 IP: {:?} / {:?}", reply.ip4, reply.ip6);
                                    }
                                }
                            }
                            x if x == PktType::Data as u8 || x == PktType::Fec as u8 => {
                                let is_fec = hdr.pkt_type == PktType::Fec as u8;
                                if let Ok(dec) = crypto_pool
                                    .decrypt(cipher_recv, aad.clone(), body.to_vec())
                                    .await
                                {
                                    if hdr.flags & FLAG_ECN_CE != 0 {
                                        let state_guard = client_state.lock().await;
                                        if let Some(s) = state_guard.as_ref() { s.reliable_tx.lock().await.on_ecn(); }
                                    }
                                    let replay_id = ((hdr.seq as u64) << 1) | if is_fec { 1 } else { 0 };
                                    let anti_replay_ok = {
                                        let state_guard = client_state.lock().await;
                                        if let Some(s) = state_guard.as_ref() {
                                            s.anti_replay.lock().await.check(replay_id)
                                        } else {
                                            false
                                        }
                                    };
                                    if !anti_replay_ok {
                                        log::debug!("客户端丢弃重放包：seq={}", hdr.seq);
                                        continue;
                                    }
                                    let (fec_group_id, fec_group_size, fec_group_seqs, fec_group_lengths, rx_payload) = if is_fec {
                                        match decode_fec_payload(&dec) {
                                            Some(fec) => (Some(fec.group_id), Some(fec.group_size), Some(fec.seqs), Some(fec.lengths), fec.parity),
                                            None => continue,
                                        }
                                    } else {
                                        (None, None, None, None, dec)
                                    };

                                    let rx = {
                                        let state_guard = client_state.lock().await;
                                        if let Some(s) = state_guard.as_ref() {
                                            s.reliable_rx.clone()
                                        } else {
                                            continue;
                                        }
                                    };
                                    let mut rx = rx.lock().await;
                                    rx.insert(
                                        hdr.seq,
                                        rx_payload,
                                        is_fec,
                                        fec_group_id,
                                        fec_group_size,
                                        fec_group_seqs,
                                        fec_group_lengths,
                                    );
                                    for pkt in rx.deliver() {
                                        let _ = to_tun_tx.send(pkt).await;
                                    }
                                    if rx.should_send_ack(Instant::now()) {
                                        let sack_blocks = rx.sack_blocks();
                                        let ack_payload =
                                            encode_ack_payload(rx.base, &sack_blocks);
                                        let ack_hdr = TunnelHeader {
                                            pkt_type: PktType::Ack as u8,
                                            flags: 0,
                                            seq: 0,
                                            ack_seq: 0,
                                            conn_id: hdr.conn_id,
                                        };
                                        let ack_aad = ack_hdr.encode().to_vec();
                                        let cipher_send = {
                                            let state_guard = client_state.lock().await;
                                            if let Some(s) = state_guard.as_ref() {
                                                s.cipher_send.clone()
                                            } else {
                                                continue;
                                            }
                                        };
                                        if let Ok(enc_ack) = crypto_pool
                                            .encrypt(cipher_send, ack_aad, ack_payload)
                                            .await
                                        {
                                            let mut hdr_pkt = Vec::with_capacity(18 + enc_ack.len());
                                            hdr_pkt.extend_from_slice(&ack_hdr.encode());
                                            hdr_pkt.extend_from_slice(&enc_ack);
                                            let final_pkt = if privacy_enabled {
                                                wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                            } else {
                                                hdr_pkt
                                            };
                                            if jitter_ms > 0 {
                                                let delay = rand::random::<u64>() % jitter_ms;
                                                sleep(Duration::from_millis(delay)).await;
                                            }
                                            let _ = socket.send_to(&final_pkt, src).await;
                                        }
                                    }
                                }
                            }
                            x if x == PktType::Ack as u8 => {
                                if let Ok(dec) = crypto_pool
                                    .decrypt(cipher_recv, aad, body.to_vec())
                                    .await
                                {
                                    if let Some((ack_seq, sack_blocks)) = decode_ack_payload(&dec) {
                                        let state_guard = client_state.lock().await;
                                        if let Some(s) = state_guard.as_ref() {
                                            let rtt = {
                                                let mut tx = s.reliable_tx.lock().await;
                                                tx.ack(ack_seq, &sack_blocks, Instant::now());
                                                tx.rtt_estimate()
                                            };
                                            s.reliable_rx.lock().await.set_rtt_hint(rtt);
                                        }
                                    }
                                }
                            }
                            x if x == PktType::KeepAliveResp as u8 => {
                                let mut state_guard = client_state.lock().await;
                                if let Some(s) = state_guard.as_mut() {
                                    s.last_ka_resp = Instant::now();
                                }
                            }
                            x if x == PktType::PmtudProbe as u8 => {
                                // 响应 PMTU 探测
                                let resp_hdr = TunnelHeader {
                                    pkt_type: PktType::Ack as u8,
                                    flags: 0,
                                    seq: 0,
                                    ack_seq: hdr.seq,
                                    conn_id: hdr.conn_id,
                                };
                                let resp_aad = resp_hdr.encode().to_vec();
                                let cipher_send = {
                                    let state_guard = client_state.lock().await;
                                    if let Some(s) = state_guard.as_ref() {
                                        s.cipher_send.clone()
                                    } else {
                                        continue;
                                    }
                                };
                                if let Ok(enc) = crypto_pool
                                    .encrypt(cipher_send, resp_aad, vec![])
                                    .await
                                {
                                    let mut pkt = Vec::with_capacity(18 + enc.len());
                                    pkt.extend_from_slice(&resp_hdr.encode());
                                    pkt.extend_from_slice(&enc);
                                    let _ = socket.send_to(&pkt, src).await;
                                }
                            }
                            _ => {}
                        }
                    }
                } else {
                    // Server Mode
                    match hdr.pkt_type {
                        x if x == PktType::HandshakeInit as u8 => {
                            if let Some(old_ip) = clients_by_addr.remove(&src) {
                                clients_by_ip.remove(&old_ip);
                            }
                            pending_sessions.remove(&src);
                            if let Some((eph_bytes, static_bytes, pq_public_bytes, challenge, conn_id)) =
                                verify_handshake_init(&psk, body, &allowed_static_pubs, &handshake_replay_cache)
                            {
                                let pq_public = match mlkem768::PublicKey::from_bytes(&pq_public_bytes) {
                                    Ok(pk) => pk,
                                    Err(_) => continue,
                                };
                                let (pq_shared, pq_ct) = mlkem768::encapsulate(&pq_public);
                                let pq_bytes: [u8; 32] = match pq_shared.as_bytes().try_into() {
                                    Ok(v) => v,
                                    Err(_) => continue,
                                };
                                let server_secret = EphemeralSecret::random_from_rng(OsRng);
                                let server_pub = PublicKey::from(&server_secret);
                                let eph_dh = server_secret.diffie_hellman(&PublicKey::from(eph_bytes));
                                let static_dh = server_static_secret
                                    .as_ref()
                                    .unwrap()
                                    .diffie_hellman(&PublicKey::from(static_bytes));
                                let (key_send, key_recv) = derive_session_keys(
                                    eph_dh.as_bytes(),
                                    static_dh.as_bytes(),
                                    &pq_bytes,
                                    &psk,
                                    true,
                                );
                                let cipher_send = Arc::new(ChaCha20Poly1305::new(&key_send));
                                let cipher_recv = Arc::new(ChaCha20Poly1305::new(&key_recv));
                                let tx_bytes = Arc::new(AtomicU64::new(0));
                                let rx_bytes = Arc::new(AtomicU64::new(0));
                                let session = Arc::new(ClientSession::new(
                                    src,
                                    static_bytes,
                                    conn_id,
                                    cipher_send.clone(),
                                    cipher_recv.clone(),
                                    &cc_type,
                                    fec_size,
                                    args.rate_limit_mbps,
                                    args.rate_burst_seconds,
                                    tx_bytes,
                                    rx_bytes,
                                ));
                                pending_sessions.insert(src, (session.clone(), Instant::now()));

                                if let Ok(resp) = build_handshake_resp(
                                    &crypto_pool,
                                    cipher_send,
                                    &psk,
                                    &server_pub,
                                    server_static_public.as_ref().unwrap(),
                                    challenge,
                                    conn_id,
                                    pq_ct.as_bytes(),
                                )
                                .await
                                {
                                    let mut hdr_pkt = Vec::with_capacity(18 + resp.len());
                                    let resp_hdr = TunnelHeader {
                                        pkt_type: PktType::HandshakeResp as u8,
                                        flags: 0,
                                        seq: 0,
                                        ack_seq: 0,
                                        conn_id,
                                    };
                                    hdr_pkt.extend_from_slice(&resp_hdr.encode());
                                    hdr_pkt.extend_from_slice(&resp);
                                    let final_pkt = if privacy_enabled {
                                        wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                    } else {
                                        hdr_pkt
                                    };
                                    let _ = socket.send_to(&final_pkt, src).await;
                                }
                            }
                        }
                        x if x == PktType::DhcpReq as u8 => {
                            if let Some((session, _)) = pending_sessions.remove(&src) {
                                if let Ok(dec) = crypto_pool
                                    .decrypt(session.cipher_recv.clone(), aad.clone(), body.to_vec())
                                    .await
                                {
                                    if let Some(req) = decode_dhcp_request(&dec) {
                                        let mut pool = ip_pool.lock().await;
                                        let mut pool_v6 = ip_pool_v6.lock().await;
                                        let ip4 = pool.allocate_ip4(req.requested_ip);
                                        let ip6 = pool_v6.allocate_ip6();
                                        let mut dns = Vec::new();
                                        for ip in &dns4 {
                                            dns.push(IpAddr::V4(*ip));
                                        }
                                        for ip in &dns6 {
                                            dns.push(IpAddr::V6(*ip));
                                        }
                                        let mut routes = Vec::new();
                                        routes.push(("0.0.0.0/0".to_string(), server_ip4_str.clone()));
                                        routes.push(("::/0".to_string(), server_ip6.to_string()));
                                        let reply = DhcpReply {
                                            ip4,
                                            subnet_mask4: Ipv4Addr::new(255, 255, 255, 0),
                                            ip6,
                                            prefix_len6: 64,
                                            mtu: INITIAL_MTU_V4,
                                            dns,
                                            routes,
                                        };
                                        if reply.ip4.is_none() && reply.ip6.is_none() {
                                            log::warn!("地址池耗尽，无法为 {} 分配地址", src);
                                            continue;
                                        }
                                        let data = encode_dhcp_reply(&reply);
                                        if let Ok(enc) = crypto_pool
                                            .encrypt(session.cipher_send.clone(), aad.clone(), data)
                                            .await
                                        {
                                            let mut hdr_pkt = Vec::with_capacity(18 + enc.len());
                                            let ack_hdr = TunnelHeader {
                                                pkt_type: PktType::DhcpAck as u8,
                                                flags: 0,
                                                seq: 0,
                                                ack_seq: 0,
                                                conn_id: session.conn_id,
                                            };
                                            hdr_pkt.extend_from_slice(&ack_hdr.encode());
                                            hdr_pkt.extend_from_slice(&enc);
                                            let final_pkt = if privacy_enabled {
                                                wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                            } else {
                                                hdr_pkt
                                            };
                                            let _ = socket.send_to(&final_pkt, src).await;

                                            let key = ip4
                                                .map(IpAddr::V4)
                                                .unwrap_or(IpAddr::V6(ip6.unwrap()));
                                            *session.assigned_ip4.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = ip4;
                                            *session.assigned_ip6.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = ip6;
                                            clients_by_addr.insert(src, key);
                                            clients_by_ip.insert(key, session.clone());
                                            clients_by_connid.insert(session.conn_id, session.clone());
                                            let mut persisted =
                                                PersistedState::load(&state_file);
                                            persisted
                                                .allocated_ips
                                                .insert(key.to_string(), src.to_string());
                                            persisted.ip_to_pubkey.insert(
                                                key.to_string(),
                                                hex::encode(session.static_public),
                                            );
                                            persisted
                                                .conn_id_map
                                                .insert(key.to_string(), session.conn_id);
                                            persisted
                                                .client_conn_ids
                                                .insert(src.to_string(), session.conn_id);
                                            persisted.save(&state_file);
                                            active_clients.fetch_add(1, Ordering::Relaxed);
                                        metrics.sessions.store(active_clients.load(Ordering::Relaxed), Ordering::Relaxed);
                                            log::info!(
                                                "客户端 {} 分配地址：{:?} / {:?} ConnID={}",
                                                src,
                                                ip4,
                                                ip6,
                                                session.conn_id
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        x if x == PktType::Data as u8 || x == PktType::Fec as u8 => {
                            let is_fec = hdr.pkt_type == PktType::Fec as u8;
                            let session_opt = clients_by_connid.get(&hdr.conn_id);
                            if let Some(sess) = session_opt {
                                // 连接迁移检测（带冷却期，避免频繁迁移抖动）
                                if sess.socket_addr() != src
                                    && !sess.is_migration_cooldown()
                                    && !clients_by_addr.contains_key(&src)
                                {
                                    if let Some(old_addr) = clients_by_addr.remove(&sess.socket_addr())
                                    {
                                        clients_by_addr.insert(src, old_addr);
                                    }
                                    sess.update_addr(src);
                                }
                                if !allowed_static_pubs.contains(&sess.static_public) {
                                    log::warn!("拒绝未授权客户端数据：{}", src);
                                    continue;
                                }
                                let allow_rx = {
                                    let mut limiter = sess.rx_limiter.lock().await;
                                    limiter.allow(body.len())
                                };
                                if !allow_rx {
                                    continue;
                                }
                                if let Ok(dec) = crypto_pool
                                    .decrypt(sess.cipher_recv.clone(), aad.clone(), body.to_vec())
                                    .await
                                {
                                    if hdr.flags & FLAG_ECN_CE != 0 { sess.reliable_tx.lock().await.on_ecn(); }
                                    let replay_id = ((hdr.seq as u64) << 1) | if is_fec { 1 } else { 0 };
                                    if !sess.anti_replay.lock().await.check(replay_id) {
                                        log::debug!("服务端丢弃重放包：seq={}, client={}", hdr.seq, src);
                                        continue;
                                    }
                                    let (fec_group_id, fec_group_size, fec_group_seqs, fec_group_lengths, rx_payload) = if is_fec {
                                        match decode_fec_payload(&dec) {
                                            Some(fec) => (Some(fec.group_id), Some(fec.group_size), Some(fec.seqs), Some(fec.lengths), fec.parity),
                                            None => continue,
                                        }
                                    } else {
                                        (None, None, None, None, dec)
                                    };

                                    let mut rx = sess.reliable_rx.lock().await;
                                    rx.insert(
                                        hdr.seq,
                                        rx_payload,
                                        is_fec,
                                        fec_group_id,
                                        fec_group_size,
                                        fec_group_seqs,
                                        fec_group_lengths,
                                    );
                                    for pkt in rx.deliver() {
                                        if let Some(dest_ip) = parse_dest_ip(&pkt) {
                                            if !acl_rules.is_empty() && !acl_check(&acl_rules, dest_ip)
                                            {
                                                log::warn!("ACL 拒绝: {} -> {}", src, dest_ip);
                                                continue;
                                            }
                                        }
                                        let _ = to_tun_tx.send(pkt).await;
                                    }
                                    if rx.should_send_ack(Instant::now()) {
                                        let sack_blocks = rx.sack_blocks();
                                        let ack_payload =
                                            encode_ack_payload(rx.base, &sack_blocks);
                                        let ack_hdr = TunnelHeader {
                                            pkt_type: PktType::Ack as u8,
                                            flags: 0,
                                            seq: 0,
                                            ack_seq: 0,
                                            conn_id: hdr.conn_id,
                                        };
                                        let ack_aad = ack_hdr.encode().to_vec();
                                        if let Ok(enc_ack) = crypto_pool
                                            .encrypt(sess.cipher_send.clone(), ack_aad, ack_payload)
                                            .await
                                        {
                                            let mut hdr_pkt = Vec::with_capacity(18 + enc_ack.len());
                                            hdr_pkt.extend_from_slice(&ack_hdr.encode());
                                            hdr_pkt.extend_from_slice(&enc_ack);
                                            let final_pkt = if privacy_enabled {
                                                wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                            } else {
                                                hdr_pkt
                                            };
                                            if jitter_ms > 0 {
                                                let delay = rand::random::<u64>() % jitter_ms;
                                                sleep(Duration::from_millis(delay)).await;
                                            }
                                            let _ = socket.send_to(&final_pkt, src).await;
                                        }
                                    }
                                    *sess.last_seen.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                                }
                            } else {
                                log::warn!("未知 ConnID: {} from {}", hdr.conn_id, src);
                            }
                        }
                        x if x == PktType::Ack as u8 => {
                            if let Some(sess) = clients_by_connid.get(&hdr.conn_id) {
                                if let Ok(dec) = crypto_pool
                                    .decrypt(sess.cipher_recv.clone(), aad, body.to_vec())
                                    .await
                                {
                                    if let Some((ack_seq, sack_blocks)) = decode_ack_payload(&dec) {
                                        let rtt = {
                                            let mut tx = sess.reliable_tx.lock().await;
                                            tx.ack(ack_seq, &sack_blocks, Instant::now());
                                            tx.rtt_estimate()
                                        };
                                        sess.reliable_rx.lock().await.set_rtt_hint(rtt);
                                    }
                                }
                            }
                        }
                        x if x == PktType::KeepAlive as u8 => {
                            if let Some(sess) = clients_by_connid.get(&hdr.conn_id) {
                                let ka_resp_hdr = TunnelHeader {
                                    pkt_type: PktType::KeepAliveResp as u8,
                                    flags: 0,
                                    seq: 0,
                                    ack_seq: 0,
                                    conn_id: hdr.conn_id,
                                };
                                let ka_resp_aad = ka_resp_hdr.encode().to_vec();
                                if let Ok(enc) = crypto_pool
                                    .encrypt(sess.cipher_send.clone(), ka_resp_aad, vec![])
                                    .await
                                {
                                    let mut hdr_pkt = Vec::with_capacity(18 + enc.len());
                                    hdr_pkt.extend_from_slice(&ka_resp_hdr.encode());
                                    hdr_pkt.extend_from_slice(&enc);
                                    let final_pkt = if privacy_enabled {
                                        wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                    } else {
                                        hdr_pkt
                                    };
                                    let _ = socket.send_to(&final_pkt, src).await;
                                }
                                *sess.last_seen.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Instant::now();
                            }
                        }
                        x if x == PktType::PmtudProbe as u8 => {
                            if let Some(sess) = clients_by_connid.get(&hdr.conn_id) {
                                let resp_hdr = TunnelHeader {
                                    pkt_type: PktType::Ack as u8,
                                    flags: 0,
                                    seq: 0,
                                    ack_seq: hdr.seq,
                                    conn_id: hdr.conn_id,
                                };
                                let resp_aad = resp_hdr.encode().to_vec();
                                if let Ok(enc) = crypto_pool
                                    .encrypt(sess.cipher_send.clone(), resp_aad, vec![])
                                    .await
                                {
                                    let mut pkt = Vec::with_capacity(18 + enc.len());
                                    pkt.extend_from_slice(&resp_hdr.encode());
                                    pkt.extend_from_slice(&enc);
                                    let _ = socket.send_to(&pkt, src).await;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                }
            }
        })
    };

    // 清理待处理会话
    {
        let pending_sessions = pending_sessions.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut to_remove = Vec::new();
                pending_sessions.iter(|addr, (_, created_at)| {
                    if now.duration_since(*created_at) > PENDING_SESSION_TIMEOUT {
                        to_remove.push(*addr);
                    }
                });
                for addr in to_remove {
                    pending_sessions.remove(&addr);
                    log::warn!("Pending session for {} timed out", addr);
                }
            }
        });
    }

    // TUN -> UDP 转发
    let _tun_to_udp = {
        let tun = tun.clone();
        let ldt_enabled = args.ldt;
        let ldt_max_packet = args.ldt_max_packet.min(LDT_MAX_PACKET);
        let to_udp_tx = to_udp_tx.clone();
        let client_state = client_state.clone();
        let clients_by_ip = clients_by_ip.clone();
        let _clients_by_connid = clients_by_connid.clone();
        let mode = args.mode.clone();
        let crypto_pool = crypto_pool.clone();
        let _max_mss = args.mtu - 40;
        let privacy_enabled = privacy_enabled;
        let jitter_ms = jitter_ms;
        let privacy_bucket = privacy_bucket;
        let acl_rules = acl_rules.clone();
        let _fec_size = fec_size;
        let _tx_bytes = Arc::new(AtomicU64::new(0));
        let _rx_bytes = Arc::new(AtomicU64::new(0));
        let metrics = metrics.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            
            loop {
                let n = {
                    let mut tun = tun.lock().await;
                    tun.read(&mut buf).await.ok().filter(|&n| n > 0)
                };
                if let Some(n) = n {
                    metrics.tun_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    let mut ip_pkt = buf[..n].to_vec();
                    let is_v6 = is_ipv6_packet(&ip_pkt);
                    // 客户端使用会话 MTU（随 PMTU 探测结果动态调整）；服务端按协议取初始值
                    let mtu = if mode == "client" {
                        let state = client_state.lock().await;
                        state
                            .as_ref()
                            .and_then(|s| s.reliable_tx.try_lock().ok().map(|tx| tx.mtu()))
                            .unwrap_or(if is_v6 { INITIAL_MTU_V6 } else { INITIAL_MTU_V4 })
                    } else if is_v6 {
                        INITIAL_MTU_V6
                    } else {
                        INITIAL_MTU_V4
                    };
                    clamp_tcp_mss(&mut ip_pkt, mtu - 40);

                    if let Some(dest_ip) = parse_dest_ip(&ip_pkt) {
                        if !acl_rules.is_empty() && !acl_check(&acl_rules, dest_ip) {
                            log::warn!("ACL 出站拒绝: {}", dest_ip);
                            continue;
                        }
                    }

                    if mode == "client" {
                        let state = client_state.lock().await;
                        if let Some(s) = state.as_ref() {
                            let mut tx = s.reliable_tx.lock().await;
                            if tx.can_send() {
                                if s.tx_limiter.lock().await.allow(ip_pkt.len()) {
                                    let seq = tx.next_seq;
                                    let data_flags = FLAG_RELIABLE | if ldt_enabled && ip_pkt.len() <= ldt_max_packet { FLAG_LDT } else { 0 } | ecn_flags_for(&ip_pkt);
                                    let data_hdr = TunnelHeader {
                                        pkt_type: PktType::Data as u8,
                                        flags: data_flags,
                                        seq,
                                        ack_seq: 0,
                                        conn_id: s.conn_id,
                                    };
                                    let aad = data_hdr.encode().to_vec();
                                    if let Ok(enc) = crypto_pool
                                        .encrypt(s.cipher_send.clone(), aad, ip_pkt.clone())
                                        .await
                                    {
                                        let (actual_seq, entry_data) = tx.push(enc, data_hdr.flags);
                                        let mut final_hdr = data_hdr;
                                        final_hdr.seq = actual_seq;
                                        let mut hdr_pkt = Vec::with_capacity(18 + entry_data.len());
                                        hdr_pkt.extend_from_slice(&final_hdr.encode());
                                        hdr_pkt.extend_from_slice(&entry_data);

                                        // FEC 冗余包
                                        if let Some((fec_data, fec_group_id, fec_seqs, fec_lengths)) = tx.get_fec_parity() {
                                            let full_fec_data = match encode_fec_payload(fec_group_id, &fec_seqs, &fec_lengths, &fec_data) {
                                                Some(v) => v,
                                                None => continue,
                                            };

                                            let fec_hdr = TunnelHeader {
                                                pkt_type: PktType::Fec as u8,
                                                flags: 0x02,
                                                seq: fec_group_id,
                                                ack_seq: 0,
                                                conn_id: s.conn_id,
                                            };
                                            let fec_aad = fec_hdr.encode().to_vec();
                                            if let Ok(fec_enc) = crypto_pool
                                                .encrypt(s.cipher_send.clone(), fec_aad, full_fec_data)
                                                .await
                                            {
                                                let mut fec_pkt =
                                                    Vec::with_capacity(18 + fec_enc.len());
                                                fec_pkt.extend_from_slice(&fec_hdr.encode());
                                                fec_pkt.extend_from_slice(&fec_enc);
                                                let final_fec = if privacy_enabled {
                                                    wrap_privacy_record(&fec_pkt, privacy_bucket)
                                                } else {
                                                    fec_pkt
                                                };
                                                if jitter_ms > 0 {
                                                    let delay = rand::random::<u64>() % jitter_ms;
                                                    sleep(Duration::from_millis(delay)).await;
                                                }
                                                if to_udp_tx.send((final_fec, None)).await.is_err() { metrics.dropped.fetch_add(1, Ordering::Relaxed); }
                                            }
                                        }

                                        let final_pkt = if privacy_enabled {
                                            wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                        } else {
                                            hdr_pkt
                                        };
                                        if jitter_ms > 0 {
                                            let delay = rand::random::<u64>() % jitter_ms;
                                            sleep(Duration::from_millis(delay)).await;
                                        }
                                        if to_udp_tx.send((final_pkt, None)).await.is_err() { metrics.dropped.fetch_add(1, Ordering::Relaxed); }
                                    }
                                }
                            }
                        }
                    } else {
                        if let Some(dest_ip) = parse_dest_ip(&ip_pkt) {
                            if is_multicast_or_broadcast(&dest_ip) {
                                for (_ip, sess) in clients_by_ip.snapshot() {
                                    let mut tx = sess.reliable_tx.lock().await;
                                    if tx.can_send() && sess.tx_limiter.lock().await.allow(ip_pkt.len()) {
                                        let seq = tx.next_seq;
                                        let data_flags = FLAG_RELIABLE | if ldt_enabled && ip_pkt.len() <= ldt_max_packet { FLAG_LDT } else { 0 } | ecn_flags_for(&ip_pkt);
                                        let data_hdr = TunnelHeader {
                                            pkt_type: PktType::Data as u8,
                                            flags: data_flags,
                                            seq,
                                            ack_seq: 0,
                                            conn_id: sess.conn_id,
                                        };
                                        let aad = data_hdr.encode().to_vec();
                                        if let Ok(enc) = crypto_pool
                                            .encrypt(sess.cipher_send.clone(), aad, ip_pkt.clone())
                                            .await
                                        {
                                            let (actual_seq, entry_data) = tx.push(enc, data_hdr.flags);
                                            let mut final_hdr = data_hdr;
                                            final_hdr.seq = actual_seq;
                                            let mut hdr_pkt =
                                                Vec::with_capacity(18 + entry_data.len());
                                            hdr_pkt.extend_from_slice(&final_hdr.encode());
                                            hdr_pkt.extend_from_slice(&entry_data);
                                            let final_pkt = if privacy_enabled {
                                                wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                            } else {
                                                hdr_pkt
                                            };
                                            if jitter_ms > 0 {
                                                let delay = rand::random::<u64>() % jitter_ms;
                                                sleep(Duration::from_millis(delay)).await;
                                            }
                                            if to_udp_tx
                                                .send((final_pkt, Some(sess.socket_addr())))
                                                .await.is_err() { metrics.dropped.fetch_add(1, Ordering::Relaxed); }
                                        }
                                    }
                                }
                            } else if let Some(sess) = clients_by_ip.get(&dest_ip) {
                                let mut tx = sess.reliable_tx.lock().await;
                                if tx.can_send() && sess.tx_limiter.lock().await.allow(ip_pkt.len()) {
                                    let seq = tx.next_seq;
                                    let data_flags = FLAG_RELIABLE | if ldt_enabled && ip_pkt.len() <= ldt_max_packet { FLAG_LDT } else { 0 } | ecn_flags_for(&ip_pkt);
                                    let data_hdr = TunnelHeader {
                                        pkt_type: PktType::Data as u8,
                                        flags: data_flags,
                                        seq,
                                        ack_seq: 0,
                                        conn_id: sess.conn_id,
                                    };
                                    let aad = data_hdr.encode().to_vec();
                                    if let Ok(enc) = crypto_pool
                                        .encrypt(sess.cipher_send.clone(), aad, ip_pkt)
                                        .await
                                    {
                                        let (actual_seq, entry_data) = tx.push(enc, data_hdr.flags);
                                        let mut final_hdr = data_hdr;
                                        final_hdr.seq = actual_seq;
                                        let mut hdr_pkt = Vec::with_capacity(18 + entry_data.len());
                                        hdr_pkt.extend_from_slice(&final_hdr.encode());
                                        hdr_pkt.extend_from_slice(&entry_data);

                                        // FEC
                                        if let Some((fec_data, fec_group_id, fec_seqs, fec_lengths)) = tx.get_fec_parity() {
                                            let full_fec_data = match encode_fec_payload(fec_group_id, &fec_seqs, &fec_lengths, &fec_data) {
                                                Some(v) => v,
                                                None => continue,
                                            };

                                            let fec_hdr = TunnelHeader {
                                                pkt_type: PktType::Fec as u8,
                                                flags: 0x02,
                                                seq: fec_group_id,
                                                ack_seq: 0,
                                                conn_id: sess.conn_id,
                                            };
                                            let fec_aad = fec_hdr.encode().to_vec();
                                            if let Ok(fec_enc) = crypto_pool
                                                .encrypt(sess.cipher_send.clone(), fec_aad, full_fec_data)
                                                .await
                                            {
                                                let mut fec_pkt =
                                                    Vec::with_capacity(18 + fec_enc.len());
                                                fec_pkt.extend_from_slice(&fec_hdr.encode());
                                                fec_pkt.extend_from_slice(&fec_enc);
                                                let final_fec = if privacy_enabled {
                                                    wrap_privacy_record(&fec_pkt, privacy_bucket)
                                                } else {
                                                    fec_pkt
                                                };
                                                if jitter_ms > 0 {
                                                    let delay = rand::random::<u64>() % jitter_ms;
                                                    sleep(Duration::from_millis(delay)).await;
                                                }
                                                if to_udp_tx
                                                    .send((final_fec, Some(sess.socket_addr())))
                                                    .await.is_err() { metrics.dropped.fetch_add(1, Ordering::Relaxed); }
                                            }
                                        }

                                        let final_pkt = if privacy_enabled {
                                            wrap_privacy_record(&hdr_pkt, privacy_bucket)
                                        } else {
                                            hdr_pkt
                                        };
                                        if jitter_ms > 0 {
                                            let delay = rand::random::<u64>() % jitter_ms;
                                            sleep(Duration::from_millis(delay)).await;
                                        }
                                        if to_udp_tx
                                            .send((final_pkt, Some(sess.socket_addr())))
                                            .await.is_err() { metrics.dropped.fetch_add(1, Ordering::Relaxed); }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        })
    };

    // UDP 发送器: LDT 优先 + 连接级多队列 + batch I/O + byte-time pacing。
    let _udp_send = {
        let socket = socket.clone();
        let mode = args.mode.clone();
        let client_state = client_state.clone();
        let clients_by_ip = clients_by_ip.clone();
        let metrics = metrics.clone();
        let pacing_mbps = if args.pacing_mbps > 0.0 { args.pacing_mbps } else { args.rate_limit_mbps };

        tokio::spawn(async move {
            let mut retrans_timer = interval(Duration::from_millis(20));
            let mut pacer = Pacer::new(pacing_mbps);
            let mut batch = Vec::with_capacity(crate::constants::UDP_BATCH_SIZE);
            loop {
                tokio::select! {
                    Some(first) = to_udp_rx.recv() => {
                        batch.clear();
                        batch.push(first);
                        to_udp_rx.try_recv_batch(&mut batch, crate::constants::UDP_BATCH_SIZE);
                        let mut ldt = Vec::with_capacity(batch.len());
                        let mut bulk = Vec::with_capacity(BULK_BATCH_SIZE);
                        for item in batch.drain(..) {
                            if item.0.len() <= LDT_MAX_PACKET { ldt.push(item); }
                            else if bulk.len() < BULK_BATCH_SIZE { bulk.push(item); }
                            else { let _ = to_udp_tx.send(item).await; }
                        }
                        if !ldt.is_empty() {
                            let before = ldt.len();
                            let mut ldt_datagrams = ldt.into_iter().map(|(data, addr)| batch_udp::Datagram { data, addr, ecn: None }).collect::<Vec<_>>();
                            if let Err(e) = batch_udp::send_batch(&socket, &mut ldt_datagrams).await { log::error!("LDT UDP batch send error: {}", e); }
                            let sent = before.saturating_sub(ldt_datagrams.len());
                            if sent > 0 {
                                metrics.ldt_tx_packets.fetch_add(sent as u64, Ordering::Relaxed);
                                metrics.packets_tx.fetch_add(sent as u64, Ordering::Relaxed);
                            }
                        }
                        if !bulk.is_empty() {
                            if pacer.enabled() {
                                let bytes: usize = bulk.iter().map(|x| x.0.len()).sum();
                                let due = pacer.deadline_for(bytes, false, Instant::now());
                                if due > Instant::now() { sleep_until(tokio::time::Instant::from_std(due)).await; }
                            }
                            let before = bulk.len();
                            let mut bulk_datagrams = bulk.into_iter().map(|(data, addr)| batch_udp::Datagram { data, addr, ecn: None }).collect::<Vec<_>>();
                            if let Err(e) = batch_udp::send_batch(&socket, &mut bulk_datagrams).await { log::error!("UDP batch send error: {}", e); }
                            let sent = before.saturating_sub(bulk_datagrams.len());
                            if sent > 0 { metrics.packets_tx.fetch_add(sent as u64, Ordering::Relaxed); }
                        }
                    }
                    _ = retrans_timer.tick() => {
                        let now = Instant::now();
                        if mode == "client" {
                            let state = client_state.lock().await;
                            if let Some(s) = state.as_ref() {
                                let mut tx = s.reliable_tx.lock().await;
                                for (raw, seq) in tx.retransmit(now) {
                                    let flags = tx.flags_for_seq(seq);
                                    let hdr = TunnelHeader { pkt_type: PktType::Data as u8, flags, seq, ack_seq: 0, conn_id: s.conn_id };
                                    let mut pkt = Vec::with_capacity(18 + raw.len()); pkt.extend_from_slice(&hdr.encode()); pkt.extend_from_slice(&raw);
                                    let mut one = vec![batch_udp::Datagram { data: pkt, addr: None, ecn: None }]; let _ = batch_udp::send_batch(&socket, &mut one).await;
                                }
                            }
                        } else {
                            for (_ip, sess) in clients_by_ip.snapshot() {
                                let mut tx = sess.reliable_tx.lock().await;
                                for (raw, seq) in tx.retransmit(now) {
                                    let flags = tx.flags_for_seq(seq);
                                    let hdr = TunnelHeader { pkt_type: PktType::Data as u8, flags, seq, ack_seq: 0, conn_id: sess.conn_id };
                                    let mut pkt = Vec::with_capacity(18 + raw.len()); pkt.extend_from_slice(&hdr.encode()); pkt.extend_from_slice(&raw);
                                    let mut one = vec![batch_udp::Datagram { data: pkt, addr: Some(sess.socket_addr()), ecn: None }]; let _ = batch_udp::send_batch(&socket, &mut one).await;
                                }
                            }
                        }
                    }
                }
            }
        })
    };

    // TUN 写入器
    let _tun_write = {
        let tun = tun.clone();
        let mut to_tun_rx = to_tun_rx;
        let metrics = metrics.clone();

        tokio::spawn(async move {
            let mut pending: Vec<Vec<u8>> = Vec::with_capacity(TUN_BATCH_SIZE);
            loop {
                let Some(first) = to_tun_rx.recv().await else { break; };
                pending.push(first);
                while pending.len() < TUN_BATCH_SIZE {
                    match to_tun_rx.try_recv() {
                        Ok(pkt) => pending.push(pkt),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                let mut tun = tun.lock().await;
                let bytes: usize = pending.iter().map(Vec::len).sum();
                if let Err(e) = tun_fast::write_burst(&mut *tun, &mut pending).await {
                    log::error!("TUN burst write error ({}): {}", tun_fast::platform_name(), e);
                } else {
                    metrics.tun_tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                }
            }
        })
    };

    // 超时清理 (服务端)
    if args.mode == "server" {
        let clients_by_ip = clients_by_ip.clone();
        let clients_by_addr = clients_by_addr.clone();
        let clients_by_connid = clients_by_connid.clone();
        let ip_pool = ip_pool.clone();
        let ip_pool_v6 = ip_pool_v6.clone();
        let active_clients = active_clients_count.clone();
        let state_file = state_file.clone();
        let metrics = metrics.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let mut to_remove = Vec::new();
                clients_by_ip.iter(|ip, sess| {
                    if sess.last_seen.read().unwrap_or_else(|poisoned| poisoned.into_inner()).elapsed().as_secs() > 120 {
                        to_remove.push(*ip);
                    }
                });
                for ip in to_remove {
                    if let Some(sess) = clients_by_ip.remove(&ip) {
                        clients_by_addr.remove(&sess.socket_addr());
                        clients_by_connid.remove(&sess.conn_id);
                        ip_pool.lock().await.release(ip);
                        ip_pool_v6.lock().await.release(ip);
                        let mut persisted = PersistedState::load(&state_file);
                        persisted.allocated_ips.remove(&ip.to_string());
                        persisted.ip_to_pubkey.remove(&ip.to_string());
                        persisted.conn_id_map.remove(&ip.to_string());
                        persisted.client_conn_ids.remove(&sess.socket_addr().to_string());
                        persisted.save(&state_file);
                        active_clients.fetch_sub(1, Ordering::Relaxed);
                        metrics.sessions.store(active_clients.load(Ordering::Relaxed), Ordering::Relaxed);
                        log::info!("客户端 {} 超时已断开", ip);
                    }
                }
            }
        });
    }

    log::info!("ArkIris v1 已启动 | mode={} | cc={} | fec={} | jitter={}ms | privacy={} | tui={}",
        args.mode.to_uppercase(), cc_type, if fec_size > 0 { fec_size.to_string() } else { "disabled".into() }, jitter_ms, privacy_enabled, tui_stop.is_some());
    if !acl_rules.is_empty() {
        log::info!("ACL 已启用: {} 条规则", acl_rules.len());
    }

    tokio::signal::ctrl_c().await?;
    if let Some(stop) = tui_stop { stop.store(true, Ordering::Relaxed); }
    log::info!("正在关闭 ArkIris...");
    Ok(())
}