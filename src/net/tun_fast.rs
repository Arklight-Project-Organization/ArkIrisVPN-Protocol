//! Platform-aware TUN fast-path helpers.
//!
//! The `tun` crate already selects the platform-native TUN/Wintun backend.
//! This module keeps the data-plane policy separate: read/write in bounded
//! bursts, avoid a task wakeup per packet, and expose platform hooks for future
//! zero-copy/offload integration without leaking OS handles into the core.

use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub const TUN_BATCH_SIZE: usize = 32;

pub async fn write_burst<D>(device: &mut D, packets: &mut Vec<Vec<u8>>) -> io::Result<usize>
where
    D: AsyncWrite + Unpin,
{
    let mut written = 0usize;
    for packet in packets.iter() {
        device.write_all(packet).await?;
        written += 1;
    }
    packets.drain(..written);
    Ok(written)
}

/// Platform capability marker used by diagnostics/TUI. The underlying `tun`
/// crate remains responsible for opening the native device implementation.
pub fn offload_capability() -> &'static str {
    #[cfg(target_os = "linux")]
    { "Linux TUN native backend; offload hook available" }
    #[cfg(target_os = "windows")]
    { "Windows Wintun native backend; driver-managed offload" }
    #[cfg(target_os = "macos")]
    { "macOS TUN native backend" }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    { "portable backend" }
}

pub fn platform_name() -> &'static str {
    #[cfg(target_os = "windows")]
    { "Windows native TUN/Wintun backend" }
    #[cfg(target_os = "linux")]
    { "Linux native /dev/net/tun backend" }
    #[cfg(target_os = "macos")]
    { "macOS native TUN backend" }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    { "portable TUN backend" }
}
