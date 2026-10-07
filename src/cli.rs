//! 命令行参数定义。

use clap::{Parser, Subcommand};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Parser, Clone)]
#[command(author, version, about = "ArkIris v1 - high performance hybrid post-quantum tunnel")]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(long, default_value = "client")]
    pub mode: String,
    #[arg(long, default_value = "0.0.0.0:13250")]
    pub bind: String,
    #[arg(long)]
    pub peer: Option<String>,
    #[arg(long, default_value = "10.9.0.0/24")]
    pub subnet4: String,
    #[arg(long, default_value = "fd00:9::/64")]
    pub subnet6: String,
    #[arg(long, env = "ARKIRIS_PSK")]
    pub psk: String,
    #[arg(long, default_value = "1420")]
    pub mtu: u16,
    #[arg(long, value_delimiter = ',')]
    pub dns4: Vec<Ipv4Addr>,
    #[arg(long, value_delimiter = ',')]
    pub dns6: Vec<Ipv6Addr>,
    #[arg(long)]
    pub static_secret: Option<String>,
    #[arg(long)]
    pub peer_static_public: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub allowed_clients: Vec<String>,
    #[arg(long, default_value_t = 0.0)]
    pub rate_limit_mbps: f64,
    /// Token-bucket burst capacity in seconds of configured bandwidth.
    #[arg(long, default_value_t = 1.0)]
    pub rate_burst_seconds: f64,
    #[arg(long)]
    pub monitor_port: Option<u16>,
    #[arg(long, default_value = "arkiris_state.json")]
    pub state_file: String,

    // Runtime and compatibility options.
    /// Enable bounded length-hiding privacy framing. This does not emulate another protocol.
    #[arg(long)]
    pub privacy: bool,
    /// Legacy alias for --privacy.
    #[arg(long)]
    pub stealth_vpn: bool,
    #[arg(long)]
    pub hide_vpn: bool,
    /// Length-hiding bucket in bytes. 0 disables padding while retaining framing.
    #[arg(long, default_value_t = 64)]
    pub privacy_bucket: usize,
    /// Fixed byte-time pacing rate in Mbps. 0 disables a fixed cap; when a rate
    /// limiter is configured, pacing follows that rate automatically.
    #[arg(long, default_value_t = 0.0)]
    pub pacing_mbps: f64,
    /// Enable Lightweight Data Transfer scheduling for small packets.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub ldt: bool,
    #[arg(long, default_value_t = 512)]
    pub ldt_max_packet: usize,
    #[arg(long, default_value = "bbr")]
    pub cc: String,
    #[arg(long, default_value = "0")]
    pub fec: usize,
    #[arg(long, default_value = "0")]
    pub jitter: u64,
    #[arg(long)]
    pub acl: Option<String>,
    #[arg(long)]
    pub log_file: Option<String>,
    #[arg(long)]
    pub daemonize: bool,
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Interactive TUI color theme: neon, ocean, amber, mono.
    #[arg(long, default_value = "neon", env = "ARKIRIS_TUI_THEME")]
    pub tui_theme: String,
    /// TUI refresh interval in milliseconds.
    #[arg(long, default_value_t = 250, env = "ARKIRIS_TUI_REFRESH_MS")]
    pub tui_refresh_ms: u64,
    /// Disable the interactive terminal UI (useful for services/CI).
    #[arg(long, default_value_t = false)]
    pub no_tui: bool,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// 运行基准测试
    Bench {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        psk: String,
        #[arg(long, default_value = "60")]
        duration: u64,
        #[arg(long, default_value = "4")]
        clients: usize,
        #[arg(long, default_value = "bbr")]
        cc: String,
        #[arg(long, default_value = "0")]
        fec: usize,
        #[arg(long, default_value_t = 0.0)]
        rate_limit_mbps: f64,
    },
}
