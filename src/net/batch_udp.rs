//! UDP micro-batching abstraction.
//!
//! On every platform the public API drains multiple datagrams per readiness
//! wakeup. On Linux the implementation additionally uses recvmmsg/sendmmsg
//! when available, reducing syscall pressure on high packet-rate links.

use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

pub const UDP_BATCH_SIZE: usize = 32;
const MAX_DATAGRAM: usize = 4096;

#[derive(Clone, Debug)]
pub struct Datagram {
    pub data: Vec<u8>,
    pub addr: Option<SocketAddr>,
    pub ecn: Option<u8>,
}

pub fn enable_ecn(socket: &UdpSocket) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let mut any_ok = false;
        let mut last_err = None;
        let tos: libc::c_int = 0x02; // ECT(0)
        let rc4 = unsafe { libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_TOS, &tos as *const _ as *const libc::c_void, std::mem::size_of_val(&tos) as libc::socklen_t) };
        if rc4 == 0 { any_ok = true; } else { last_err = Some(io::Error::last_os_error()); }
        let tclass: libc::c_int = 0x02;
        let rc6 = unsafe { libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tclass as *const _ as *const libc::c_void, std::mem::size_of_val(&tclass) as libc::socklen_t) };
        if rc6 == 0 { any_ok = true; } else if last_err.is_none() { last_err = Some(io::Error::last_os_error()); }
        let one: libc::c_int = 1;
        let _ = unsafe { libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, &one as *const _ as *const libc::c_void, std::mem::size_of_val(&one) as libc::socklen_t) };
        let _ = unsafe { libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, &one as *const _ as *const libc::c_void, std::mem::size_of_val(&one) as libc::socklen_t) };
        if any_ok { Ok(()) } else { Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "ECN unavailable"))) }
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = socket; Ok(()) }
}

pub async fn recv_batch(socket: &UdpSocket, max: usize) -> io::Result<Vec<Datagram>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(batch) = recv_batch_linux(socket, max.min(UDP_BATCH_SIZE)) {
            if !batch.is_empty() { return Ok(batch); }
        }
    }

    socket.readable().await?;
    let mut out = Vec::with_capacity(max.min(UDP_BATCH_SIZE));
    for _ in 0..max.min(UDP_BATCH_SIZE) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        match socket.try_recv_from(&mut buf) {
            Ok((n, addr)) => { buf.truncate(n); out.push(Datagram { data: buf, addr: Some(addr), ecn: None }); }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

pub async fn send_batch(socket: &UdpSocket, batch: &mut Vec<Datagram>) -> io::Result<usize> {
    let mut sent_total = 0usize;
    while !batch.is_empty() {
        #[cfg(target_os = "linux")]
        {
            match send_batch_linux(socket, batch) {
                Ok(n) if n > 0 => { batch.drain(..n); sent_total += n; continue; }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }

        // Portable fallback and EAGAIN path. We wait for writability and then
        // drain as many datagrams as the kernel accepts.
        socket.writable().await?;
        let mut progressed = false;
        while !batch.is_empty() {
            let item = &batch[0];
            let result = match item.addr {
                Some(addr) => socket.try_send_to(&item.data, addr),
                None => socket.try_send(&item.data),
            };
            match result {
                Ok(_) => { batch.remove(0); sent_total += 1; progressed = true; }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        if !progressed && !batch.is_empty() {
            // The readiness notification can race with another writer. Yield
            // instead of spinning in user space.
            tokio::task::yield_now().await;
        }
    }
    Ok(sent_total)
}

#[cfg(target_os = "linux")]
fn recv_batch_linux(socket: &UdpSocket, max: usize) -> io::Result<Vec<Datagram>> {
    use std::{mem, os::fd::AsRawFd, ptr};
    use libc::{c_int, iovec, mmsghdr, msghdr, sockaddr_storage};

    let max = max.min(UDP_BATCH_SIZE);
    let fd = socket.as_raw_fd();
    let mut bufs = (0..max).map(|_| vec![0u8; MAX_DATAGRAM]).collect::<Vec<_>>();
    let mut addrs = vec![unsafe { mem::zeroed::<sockaddr_storage>() }; max];
    let mut ctrls = vec![[0u8; 128]; max];
    let mut hdrs = (0..max).map(|i| {
        let mut h: mmsghdr = unsafe { mem::zeroed() };
        h.msg_hdr = msghdr {
            msg_name: &mut addrs[i] as *mut _ as *mut _,
            msg_namelen: mem::size_of::<sockaddr_storage>() as u32,
            msg_iov: Box::into_raw(Box::new(iovec { iov_base: bufs[i].as_mut_ptr() as *mut _, iov_len: MAX_DATAGRAM })) as *mut iovec,
            msg_iovlen: 1,
            msg_control: ctrls[i].as_mut_ptr() as *mut _,
            msg_controllen: ctrls[i].len(),
            ..unsafe { mem::zeroed() }
        };
        h
    }).collect::<Vec<_>>();

    let rc = unsafe { libc::recvmmsg(fd, hdrs.as_mut_ptr(), max as c_int, libc::MSG_DONTWAIT, ptr::null_mut()) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        for h in &mut hdrs { if !h.msg_hdr.msg_iov.is_null() { unsafe { drop(Box::from_raw(h.msg_hdr.msg_iov)); } } }
        return Err(e);
    }
    let mut out = Vec::with_capacity(rc as usize);
    for i in 0..rc as usize {
        let n = hdrs[i].msg_len as usize;
        bufs[i].truncate(n);
        let addr = sockaddr_to_std(&addrs[i], hdrs[i].msg_hdr.msg_namelen as usize);
        let ecn = parse_ecn_control(&ctrls[i][..hdrs[i].msg_hdr.msg_controllen]);
        out.push(Datagram { data: std::mem::take(&mut bufs[i]), addr, ecn });
    }
    for h in &mut hdrs { if !h.msg_hdr.msg_iov.is_null() { unsafe { drop(Box::from_raw(h.msg_hdr.msg_iov)); } } }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn send_batch_linux(socket: &UdpSocket, batch: &[Datagram]) -> io::Result<usize> {
    use std::{mem, net::{Ipv4Addr, Ipv6Addr}, os::fd::AsRawFd, ptr};
    use libc::{iovec, mmsghdr, msghdr, sockaddr, sockaddr_in, sockaddr_in6};

    let max = batch.len().min(UDP_BATCH_SIZE);
    let fd = socket.as_raw_fd();
    let mut names = Vec::<Vec<u8>>::with_capacity(max);
    let mut iovs = Vec::<iovec>::with_capacity(max);
    let mut hdrs = Vec::<mmsghdr>::with_capacity(max);

    for item in &batch[..max] {
        let name = match item.addr {
            None => Vec::new(),
            Some(SocketAddr::V4(v4)) => {
                let sin = sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) },
                    sin_zero: [0; 8],
                };
                unsafe { std::slice::from_raw_parts((&sin as *const _) as *const u8, mem::size_of::<sockaddr_in>()) }.to_vec()
            }
            Some(SocketAddr::V6(v6)) => {
                let sin6 = sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as u16,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                    sin6_scope_id: v6.scope_id(),
                };
                unsafe { std::slice::from_raw_parts((&sin6 as *const _) as *const u8, mem::size_of::<sockaddr_in6>()) }.to_vec()
            }
        };
        names.push(name);
        let item_ref = &batch[iovs.len()];
        iovs.push(iovec { iov_base: item_ref.data.as_ptr() as *mut _, iov_len: item_ref.data.len() });
        let name_ref = names.last().unwrap();
        hdrs.push(mmsghdr { msg_hdr: msghdr {
            msg_name: if name_ref.is_empty() { ptr::null_mut() } else { name_ref.as_ptr() as *mut _ },
            msg_namelen: name_ref.len() as u32,
            msg_iov: &mut iovs[iovs.len()-1], msg_iovlen: 1, ..unsafe { mem::zeroed() }
        }, msg_len: 0 });
    }

    let rc = unsafe { libc::sendmmsg(fd, hdrs.as_mut_ptr(), max as u32, libc::MSG_DONTWAIT) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    Ok(rc as usize)
}

#[cfg(target_os = "linux")]
fn parse_ecn_control(control: &[u8]) -> Option<u8> {
    // Parse a small set of Linux IP_TOS/IPV6_TCLASS ancillary messages.
    // The low two bits are the ECN codepoint; CE (3) is the congestion signal.
    let mut offset = 0usize;
    while offset + std::mem::size_of::<libc::cmsghdr>() <= control.len() {
        let cmsg = unsafe { &*(control[offset..].as_ptr() as *const libc::cmsghdr) };
        if cmsg.cmsg_len < std::mem::size_of::<libc::cmsghdr>() { break; }
        let len = cmsg.cmsg_len as usize;
        if offset + len > control.len() { break; }
        let data_offset = offset + ((std::mem::size_of::<libc::cmsghdr>() + std::mem::align_of::<libc::cmsghdr>() - 1) / std::mem::align_of::<libc::cmsghdr>()) * std::mem::align_of::<libc::cmsghdr>();
        if data_offset < offset + len {
            let proto = cmsg.cmsg_level;
            let typ = cmsg.cmsg_type;
            if (proto == libc::IPPROTO_IP && typ == libc::IP_TOS) || (proto == libc::IPPROTO_IPV6 && typ == libc::IPV6_TCLASS) {
                return control.get(data_offset).map(|v| *v & 0x03);
            }
        }
        let aligned = (len + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1);
        offset = offset.saturating_add(aligned);
    }
    None
}

#[cfg(target_os = "linux")]
fn sockaddr_to_std(storage: &libc::sockaddr_storage, len: usize) -> Option<SocketAddr> {
    use std::mem;
    if len < mem::size_of::<libc::sa_family_t>() { return None; }
    unsafe {
        match storage.ss_family as i32 {
            libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
                let sin = &*(storage as *const _ as *const libc::sockaddr_in);
                Some(SocketAddr::from((std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)), u16::from_be(sin.sin_port))))
            }
            libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
                let sin6 = &*(storage as *const _ as *const libc::sockaddr_in6);
                Some(SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)), u16::from_be(sin6.sin6_port)))
            }
            _ => None,
        }
    }
}
