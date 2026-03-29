use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc;
use nix::net::if_::if_nametoindex;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tracing::warn;

use crate::error::MapEError;
use crate::map::rule::MapRule;

use super::parser::parse_mape_option;

// BPF filter: IPv6 UDP dst port 546 or src port 547
// Index 0: ldh [12]              load EtherType
// Index 1: jeq #0x86dd jt=0 jf=7  IPv6? (no → reject at index 9)
// Index 2: ldb [20]              load IPv6 Next Header
// Index 3: jeq #0x11  jt=0 jf=5   UDP? (no → reject)
// Index 4: ldh [56]              load UDP dst port
// Index 5: jeq #0x222 jt=2 jf=0   dst port 546? (yes → accept at index 8)
// Index 6: ldh [54]              load UDP src port
// Index 7: jeq #0x223 jt=0 jf=1   src port 547? (yes → accept, no → reject)
// Index 8: ret #65535            accept
// Index 9: ret #0                reject
static BPF_FILTER: [libc::sock_filter; 10] = [
    libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 12 },       // ldh [12]
    libc::sock_filter { code: 0x15, jt: 0, jf: 7, k: 0x86dd },   // jeq #0x86dd jt=0 jf=7
    libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 20 },       // ldb [20]
    libc::sock_filter { code: 0x15, jt: 0, jf: 5, k: 0x11 },     // jeq #0x11 jt=0 jf=5
    libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 56 },       // ldh [56]
    libc::sock_filter { code: 0x15, jt: 2, jf: 0, k: 0x222 },    // jeq #0x222 jt=2 jf=0
    libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 54 },       // ldh [54]
    libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 0x223 },    // jeq #0x223 jt=0 jf=1
    libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },    // ret #65535
    libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },        // ret #0
];

/// Create a raw AF_PACKET socket bound to the given interface with a BPF filter
/// for DHCPv6 packets (UDP dst port 546 or src port 547).
fn create_packet_socket(ifindex: u32) -> Result<OwnedFd, MapEError> {
    let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        return Err(MapEError::NetlinkError(format!(
            "socket() failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Attach BPF filter
    let prog = libc::sock_fprog {
        len: BPF_FILTER.len() as u16,
        filter: BPF_FILTER.as_ptr() as *mut libc::sock_filter,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(MapEError::NetlinkError(format!(
            "setsockopt SO_ATTACH_FILTER failed: {err}"
        )));
    }

    // Bind to the specific interface
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = ifindex as i32;

    let ret = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(MapEError::NetlinkError(format!(
            "bind() failed: {err}"
        )));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Extract DHCPv6 payload from a raw Ethernet frame.
/// Frame layout:
///   0..13:  Ethernet header (14 bytes)
///   14..53: IPv6 header (40 bytes)
///   54..61: UDP header (8 bytes)
///   62..:   DHCPv6 payload
fn extract_dhcpv6_payload(frame: &[u8]) -> Option<&[u8]> {
    // Check minimum frame length (14 Eth + 40 IPv6 + 8 UDP = 62 bytes)
    if frame.len() < 62 {
        return None;
    }

    // Check EtherType = 0x86DD (IPv6)
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x86DD {
        return None;
    }

    // Check IPv6 Next Header = 17 (UDP)
    if frame[20] != 17 {
        return None;
    }

    // UDP length is at offset 58 (Eth:14 + IPv6:40 + UDP length field offset:4)
    let udp_total_len = u16::from_be_bytes([frame[58], frame[59]]) as usize;
    if udp_total_len < 8 {
        return None;
    }
    let udp_payload_len = udp_total_len - 8;

    let dhcpv6_start = 62;
    if frame.len() < dhcpv6_start + udp_payload_len {
        return None;
    }

    Some(&frame[dhcpv6_start..dhcpv6_start + udp_payload_len])
}

/// Capture DHCPv6 packets on the given interface and send parsed MAP rules via `tx`.
pub async fn run_capture(
    ifname: &str,
    tx: mpsc::Sender<Vec<MapRule>>,
) -> Result<(), MapEError> {
    let ifindex = if_nametoindex(ifname).map_err(|e| {
        MapEError::NetlinkError(format!("if_nametoindex({ifname}): {e}"))
    })?;

    let owned_fd = create_packet_socket(ifindex)?;
    let async_fd = AsyncFd::new(owned_fd).map_err(|e| {
        MapEError::NetlinkError(format!("AsyncFd::new failed: {e}"))
    })?;

    let mut buf = vec![0u8; 65535];

    loop {
        let mut guard = async_fd.readable().await.map_err(|e| {
            MapEError::NetlinkError(format!("readable() failed: {e}"))
        })?;

        let result = guard.try_io(|fd| {
            let n = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });

        match result {
            Ok(Ok(n)) => {
                if let Some(dhcpv6_payload) = extract_dhcpv6_payload(&buf[..n]) {
                    match parse_mape_option(dhcpv6_payload) {
                        Ok(Some(rules)) => {
                            if tx.send(rules).await.is_err() {
                                // Receiver dropped, exit gracefully
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("DHCPv6 parse error: {e}");
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("recv error: {e}");
            }
            Err(_would_block) => {
                // WouldBlock: guard not ready yet, continue
                continue;
            }
        }
    }

    Ok(())
}
