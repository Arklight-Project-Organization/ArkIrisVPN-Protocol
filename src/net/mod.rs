//! 网络层：路由管理、IP 池与报文辅助函数。

pub mod batch_udp;

pub mod acl;
pub mod privacy;
pub mod ecn;
pub mod tun_fast;

use crate::session::PersistedState;
use ipnetwork::IpNetwork;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
};

pub use acl::{acl_check, parse_acl};
pub use ecn::flags_for as ecn_flags_for;
pub use tun_fast::{platform_name as tun_platform_name, TUN_BATCH_SIZE};
pub use privacy::{unwrap_privacy_record, wrap_privacy_record};

// ==================== 路由管理器 (Windows) ====================
pub struct RouteManager;

impl RouteManager {
    #[cfg(target_os = "windows")]
    fn run_netsh(args: &[String]) -> std::io::Result<()> {
        let output = Command::new("netsh").args(args).output()?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("netsh 失败 ({}): {}{}", output.status, stdout.trim(), if stderr.trim().is_empty() { "".to_string() } else { format!(" / {}", stderr.trim()) }),
        ))
    }

    fn validate_iface(iface: &str) -> std::io::Result<()> {
        if iface.is_empty() || iface.len() > 255 || iface.chars().any(|c| c == '\0' || c.is_control()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "非法网络接口名称"));
        }
        Ok(())
    }

    fn validate_route(dest: &str, gateway: &str) -> std::io::Result<()> {
        dest.parse::<IpNetwork>().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("非法路由目标 {}: {}", dest, e)))?;
        gateway.parse::<IpAddr>().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("非法网关 {}: {}", gateway, e)))?;
        Ok(())
    }
    pub fn configure_interface(iface: &str, ip: &str, mtu: u32) -> std::io::Result<()> {
        Self::validate_iface(iface)?;
        if !(576..=9000).contains(&mtu) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "MTU 超出允许范围"));
        }
        let network: IpNetwork = ip.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("非法接口地址 {}: {}", ip, e)))?;
        let IpNetwork::V4(v4) = network else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "当前 Windows IPv4 接口配置要求 IPv4 地址"));
        };
        let ip_addr = v4.ip().to_string();
        let prefix_len = v4.prefix();
        let mask = if prefix_len == 0 {
            "0.0.0.0".to_string()
        } else if prefix_len >= 32 {
            "255.255.255.255".to_string()
        } else {
            let mask_u32 = u32::MAX << (32 - prefix_len);
            format!("{}.{}.{}.{}", (mask_u32 >> 24) & 0xFF, (mask_u32 >> 16) & 0xFF, (mask_u32 >> 8) & 0xFF, mask_u32 & 0xFF)
        };

        #[cfg(target_os = "windows")]
        {
            Self::run_netsh(&[
                "interface".into(), "ipv4".into(), "set".into(), "subinterface".into(),
                iface.into(), format!("mtu={}", mtu), "store=active".into(),
            ])?;
            Self::run_netsh(&[
                "interface".into(), "ipv4".into(), "set".into(), "address".into(),
                format!("name={}", iface), "source=static".into(), format!("address={}", ip_addr),
                format!("mask={}", mask), "gateway=none".into(),
            ])?;
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (iface, ip_addr, mask, mtu);
        }
        Ok(())
    }

    pub fn add_route(dest: &str, gateway: &str, iface: &str) -> std::io::Result<()> {
        Self::validate_iface(iface)?;
        Self::validate_route(dest, gateway)?;
        #[cfg(target_os = "windows")]
        {
            Self::run_netsh(&[
                "interface".into(), "ipv4".into(), "add".into(), "route".into(),
                dest.into(), format!("interface={}", iface), gateway.into(), "store=active".into(),
            ])?;
        }
        Ok(())
    }

    pub fn add_route_v6(dest: &str, gateway: &str, iface: &str) -> std::io::Result<()> {
        Self::validate_iface(iface)?;
        Self::validate_route(dest, gateway)?;
        #[cfg(target_os = "windows")]
        {
            Self::run_netsh(&[
                "interface".into(), "ipv6".into(), "add".into(), "route".into(),
                dest.into(), format!("interface={}", iface), gateway.into(), "store=active".into(),
            ])?;
        }
        Ok(())
    }
}

// ==================== IP 池 ====================
pub struct IpPool {
    subnet4: IpNetwork,
    next_ip4: Ipv4Addr,
    used: HashMap<IpAddr, bool>,
}

impl IpPool {
    pub fn new(subnet4: IpNetwork, persisted: &PersistedState) -> Self {
        let mut iter = subnet4.iter();
        iter.next();
        iter.next();
        let mut start = iter.next().unwrap_or(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)));
        let mut used = HashMap::new();
        for (ip_str, _) in &persisted.allocated_ips {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                used.insert(ip, true);
                if let IpAddr::V4(v4) = ip {
                    if v4 > start {
                        start = IpAddr::V4(v4);
                    }
                }
            }
        }
        if let IpAddr::V4(v4) = start {
            start = IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(v4.octets()).saturating_add(1)));
        }
        Self {
            subnet4,
            next_ip4: match start {
                IpAddr::V4(ip) => ip,
                _ => Ipv4Addr::new(10, 9, 0, 3),
            },
            used,
        }
    }

    pub fn allocate_ip4(&mut self, requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(req) = requested {
            if self.subnet4.contains(IpAddr::V4(req)) && !self.used.contains_key(&IpAddr::V4(req))
            {
                self.used.insert(IpAddr::V4(req), true);
                return Some(req);
            }
        }
        let start = self.next_ip4;
        let mut current = start;
        loop {
            if !self.used.contains_key(&IpAddr::V4(current))
                && self.subnet4.contains(IpAddr::V4(current))
            {
                self.used.insert(IpAddr::V4(current), true);
                self.next_ip4 = Ipv4Addr::from(u32::from_be_bytes(current.octets()).saturating_add(1));
                return Some(current);
            }
            let next = u32::from_be_bytes(current.octets()).checked_add(1);
            let Some(next) = next else { break; };
            current = Ipv4Addr::from(next);
            if !self.subnet4.contains(IpAddr::V4(current)) {
                break;
            }
        }
        None
    }

    pub fn release(&mut self, ip: IpAddr) {
        self.used.remove(&ip);
    }
}

pub struct IpPoolV6 {
    subnet6: IpNetwork,
    next_suffix: u16,
    used: HashMap<IpAddr, bool>,
}

impl IpPoolV6 {
    pub fn new(subnet6: IpNetwork, persisted: &PersistedState) -> Self {
        let mut used = HashMap::new();
        let mut max_suffix = 0u16;
        for (ip_str, _) in &persisted.allocated_ips {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                used.insert(ip, true);
                if let IpAddr::V6(v6) = ip {
                    let octets = v6.octets();
                    let suffix = u16::from_be_bytes([octets[14], octets[15]]);
                    if suffix > max_suffix {
                        max_suffix = suffix;
                    }
                }
            }
        }
        Self {
            subnet6,
            next_suffix: max_suffix.saturating_add(1),
            used,
        }
    }

    pub fn allocate_ip6(&mut self) -> Option<Ipv6Addr> {
        let start_suffix = self.next_suffix;
        let mut current_suffix = start_suffix;
        let mut base_octets = match self.subnet6.network() {
            IpAddr::V6(v6) => v6.octets(),
            _ => [0u8; 16],
        };
        loop {
            base_octets[14] = (current_suffix >> 8) as u8;
            base_octets[15] = (current_suffix & 0xFF) as u8;
            let ip = IpAddr::V6(Ipv6Addr::from(base_octets));
            if self.subnet6.contains(ip) && !self.used.contains_key(&ip) {
                self.used.insert(ip, true);
                self.next_suffix = current_suffix.saturating_add(1);
                return Some(Ipv6Addr::from(base_octets));
            }
            current_suffix = current_suffix.saturating_add(1);
            if current_suffix == start_suffix {
                break;
            }
        }
        None
    }

    pub fn release(&mut self, ip: IpAddr) {
        self.used.remove(&ip);
    }
}

// ==================== 辅助函数 ====================
pub fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) {
    if packet.is_empty() {
        return;
    }
    let ip_version = packet[0] >> 4;
    if ip_version == 4 {
        if packet.len() < 40 || packet[9] != 6 {
            return;
        }
        let ihl = (packet[0] & 0x0F) as usize * 4;
        let tcp_hdr_len = ((packet[ihl + 12] >> 4) as usize) * 4;
        if tcp_hdr_len < 20 || (packet[ihl + 13] & 0x02) == 0 {
            return;
        }
        let mut opt_offset = ihl + 20;
        let tcp_end = ihl + tcp_hdr_len;
        while opt_offset + 1 < tcp_end {
            let kind = packet[opt_offset];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                opt_offset += 1;
                continue;
            }
            if kind == 2 && opt_offset + 3 < tcp_end {
                packet[opt_offset + 2] = (max_mss >> 8) as u8;
                packet[opt_offset + 3] = (max_mss & 0xFF) as u8;
                return;
            }
            if opt_offset + 1 < tcp_end {
                let len = packet[opt_offset + 1] as usize;
                if len < 2 {
                    break;
                }
                opt_offset += len;
            } else {
                break;
            }
        }
    } else if ip_version == 6 {
        if packet.len() < 60 || packet[6] != 6 {
            return;
        }
        let tcp_hdr_len = ((packet[40 + 12] >> 4) as usize) * 4;
        if tcp_hdr_len < 20 || (packet[40 + 13] & 0x02) == 0 {
            return;
        }
        let mut opt_offset = 40 + 20;
        let tcp_end = 40 + tcp_hdr_len;
        while opt_offset + 1 < tcp_end {
            let kind = packet[opt_offset];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                opt_offset += 1;
                continue;
            }
            if kind == 2 && opt_offset + 3 < tcp_end {
                packet[opt_offset + 2] = (max_mss >> 8) as u8;
                packet[opt_offset + 3] = (max_mss & 0xFF) as u8;
                return;
            }
            if opt_offset + 1 < tcp_end {
                let len = packet[opt_offset + 1] as usize;
                if len < 2 {
                    break;
                }
                opt_offset += len;
            } else {
                break;
            }
        }
    }
}

pub fn is_multicast_or_broadcast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.octets()[0] >= 224,
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

pub fn parse_dest_ip(data: &[u8]) -> Option<IpAddr> {
    if data.is_empty() {
        return None;
    }
    match data[0] >> 4 {
        4 => {
            if data.len() >= 20 {
                Some(IpAddr::V4(Ipv4Addr::new(
                    data[16], data[17], data[18], data[19],
                )))
            } else {
                None
            }
        }
        6 => {
            if data.len() >= 40 {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&data[24..40]);
                Some(IpAddr::V6(Ipv6Addr::from(oct)))
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn is_ipv6_packet(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    (data[0] >> 4) == 6
}
