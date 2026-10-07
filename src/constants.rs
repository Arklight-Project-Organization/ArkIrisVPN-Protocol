//! 全局常量。

use std::time::Duration;

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
// ML-KEM-768 sizes from FIPS 203.
pub const PQ_PUBLIC_KEY_SIZE: usize = 1184;
pub const PQ_CIPHERTEXT_SIZE: usize = 1088;
pub const MAX_PACKET: usize = 4096;
pub const PRIVACY_MAGIC: [u8; 2] = [0xA7, 0x49];
pub const PRIVACY_VERSION: u8 = 1;
pub const PRIVACY_FRAME_HEADER: usize = 6;
pub const MAX_SACK_BLOCKS: usize = 32;
pub const MAX_FEC_GROUP_SIZE: usize = 32;
pub const MAX_ACTIVE_FEC_GROUPS: usize = 64;
pub const MIN_RTO: Duration = Duration::from_millis(80);
pub const MAX_RTO: Duration = Duration::from_secs(10);
pub const INITIAL_MTU_V4: u16 = 1420;
pub const INITIAL_MTU_V6: u16 = 1280;
pub const SHARD_COUNT: usize = 64;
pub const CRYPTO_WORKERS: usize = 4;
pub const ANTI_REPLAY_WINDOW_BITS: usize = 2048;
pub const MAX_RX_AHEAD: u32 = 4096;
pub const HANDSHAKE_REPLAY_WINDOW: Duration = Duration::from_secs(10);
pub const HANDSHAKE_RESP_MAC_SIZE: usize = 32;
pub const MAX_HANDSHAKE_REPLAY_ENTRIES: usize = 8192;
pub const RATE_LIMIT_DEFAULT_BURST_SECONDS: f64 = 1.0;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const PENDING_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
pub const DHCP_RETRY_INTERVAL: Duration = Duration::from_secs(5);
pub const KA_TIMEOUT: Duration = Duration::from_secs(30);
pub const FEC_DEFAULT_GROUP_SIZE: usize = 4;
pub const ACK_DELAY_MIN_MS: u64 = 4;
pub const ACK_DELAY_MAX_MS: u64 = 12;
pub const PMTU_PROBE_INTERVAL: Duration = Duration::from_secs(30);
pub const CONNECTION_MIGRATION_TIMEOUT: Duration = Duration::from_secs(10);
pub const BENCHMARK_PACKET_SIZE: usize = 1400;
pub const BENCHMARK_INTERVAL: Duration = Duration::from_millis(10);
pub const DHCP_MAGIC: &[u8; 4] = b"DHCP";

// Data-plane scheduling / ECN
pub const FLAG_RELIABLE: u8 = 0x02;
pub const FLAG_LDT: u8 = 0x04;
pub const FLAG_ECT0: u8 = 0x08;
pub const FLAG_ECN_CE: u8 = 0x10;
pub const UDP_BATCH_SIZE: usize = 32;
