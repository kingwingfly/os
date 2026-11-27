//! Guest POSIX/WASI helpers for `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`) and L3 IPv4/ICMP/UDP
//! packet construction & parsing (`Phase 10b #87`).

#[cfg(target_os = "wasi")]
use crate::os_error;
use crate::{OsCallError, value_call};
use abi::Errno;
use abi::overlay::{
    TunGetIffResp, TunInfo, TunSetIffReq, TunSetIffResp, TunSetMtuReq, TunStats, build_ipv4_packet,
    internet_checksum, tun_ioctl,
};
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "wasi")]
use std::os::wasi::io::AsRawFd;

/// Open `/dev/net/tun` descriptor with single-packet L3 I/O and `ioctl` helpers.
pub struct TunDevice {
    file: File,
}

impl TunDevice {
    /// Open a fresh `/dev/net/tun` clone descriptor (`O_RDWR`).
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        Ok(Self { file })
    }

    pub fn raw_fd(&self) -> u32 {
        self.file.as_raw_fd() as u32
    }

    /// Attach this clone descriptor to a TUN interface (`IFF_TUN | IFF_NO_PI`).
    pub fn set_iff(
        &self,
        name: &str,
        mtu: Option<u16>,
        network: Option<&str>,
    ) -> io::Result<TunSetIffResp> {
        let req = TunSetIffReq {
            name: name.to_string(),
            flags: tun_ioctl::IFF_REQUIRED,
            mtu,
            network: network.map(str::to_string),
            static_ip: None,
        };
        let val = value_call(abi::Call::Ioctl {
            fd: self.raw_fd().into(),
            request: tun_ioctl::TUNSETIFF,
            arg: serde_json::to_value(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        })?;
        serde_json::from_value(val).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Attach using a raw 40-byte Linux `struct ifreq` buffer.
    pub fn set_iff_raw_ifreq(&self, ifreq: &[u8; 40]) -> io::Result<TunSetIffResp> {
        let arr: Vec<u8> = ifreq.to_vec();
        let val = value_call(abi::Call::Ioctl {
            fd: self.raw_fd().into(),
            request: tun_ioctl::TUNSETIFF,
            arg: json!(arr),
        })?;
        serde_json::from_value(val).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Query bound `{ name, flags }` via `TUNGETIFF`.
    pub fn get_iff(&self) -> io::Result<TunGetIffResp> {
        let val = value_call(abi::Call::Ioctl {
            fd: self.raw_fd().into(),
            request: tun_ioctl::TUNGETIFF,
            arg: serde_json::Value::Null,
        })?;
        serde_json::from_value(val).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Query supported features bitmask via `TUNGETFEATURES`.
    pub fn features(&self) -> io::Result<u32> {
        let val = value_call(abi::Call::Ioctl {
            fd: self.raw_fd().into(),
            request: tun_ioctl::TUNGETFEATURES,
            arg: serde_json::Value::Null,
        })?;
        val.as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad TUNGETFEATURES reply"))
    }

    /// Query full interface state, IP, CIDR, gateway, MTU, and queue occupancy via `TUN_IOC_INFO`.
    pub fn info(&self) -> io::Result<TunInfo> {
        let val = value_call(abi::Call::Ioctl {
            fd: self.raw_fd().into(),
            request: tun_ioctl::TUN_IOC_INFO,
            arg: serde_json::Value::Null,
        })?;
        serde_json::from_value(val).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Query packet & firewall drop statistics via `TUN_IOC_STATS`.
    pub fn stats(&self) -> io::Result<TunStats> {
        let val = value_call(abi::Call::Ioctl {
            fd: self.raw_fd().into(),
            request: tun_ioctl::TUN_IOC_STATS,
            arg: serde_json::Value::Null,
        })?;
        serde_json::from_value(val).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Update interface MTU within negotiated ceiling via `TUN_IOC_SET_MTU`.
    pub fn set_mtu(&self, mtu: u16) -> io::Result<TunInfo> {
        let val = value_call(abi::Call::Ioctl {
            fd: self.raw_fd().into(),
            request: tun_ioctl::TUN_IOC_SET_MTU,
            arg: serde_json::to_value(TunSetMtuReq { mtu })
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        })?;
        serde_json::from_value(val).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Toggle `O_NONBLOCK` on this TUN descriptor.
    pub fn set_nonblocking(&self, nonblock: bool) -> io::Result<()> {
        #[cfg(target_os = "wasi")]
        {
            #[link(wasm_import_module = "wasi_snapshot_preview1")]
            unsafe extern "C" {
                fn fd_fdstat_set_flags(fd: u32, flags: u16) -> u16;
            }
            const WASI_FDFLAG_NONBLOCK: u16 = 0x0004;
            let flags = if nonblock { WASI_FDFLAG_NONBLOCK } else { 0 };
            let rc = unsafe { fd_fdstat_set_flags(self.raw_fd(), flags) };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            Ok(())
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let _ = nonblock;
            Ok(())
        }
    }

    /// Read a single L3 packet from `/dev/net/tun`.
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.file).read(buf)
    }

    /// Write a single L3 packet to `/dev/net/tun`.
    pub fn write_packet(&self, pkt: &[u8]) -> io::Result<usize> {
        (&self.file).write(pkt)
    }

    /// Wait up to `timeout_ms` milliseconds for a packet to become readable using WASI `poll_oneoff`.
    pub fn poll_readable(&self, timeout_ms: u64) -> io::Result<bool> {
        #[cfg(target_os = "wasi")]
        {
            #[link(wasm_import_module = "wasi_snapshot_preview1")]
            unsafe extern "C" {
                fn poll_oneoff(
                    in_ptr: *const u8,
                    out_ptr: *mut u8,
                    nsubscriptions: usize,
                    nevents: *mut usize,
                ) -> u16;
            }
            // Two 48-byte WASI subscriptions: [0] FD_READ on tun fd, [1] relative monotonic CLOCK.
            let mut subs = [0u8; 96];
            // Subscription 0: userdata = 1, type = 1 (FD_READ), fd = raw_fd
            subs[0..8].copy_from_slice(&1u64.to_le_bytes());
            subs[8] = 1;
            subs[16..20].copy_from_slice(&self.raw_fd().to_le_bytes());
            // Subscription 1: userdata = 2, type = 0 (CLOCK), clock_id = 1 (MONOTONIC), timeout_ns
            subs[48..56].copy_from_slice(&2u64.to_le_bytes());
            subs[56] = 0;
            subs[64..68].copy_from_slice(&1u32.to_le_bytes());
            let timeout_ns = timeout_ms.saturating_mul(1_000_000);
            subs[72..80].copy_from_slice(&timeout_ns.to_le_bytes());
            subs[80..88].copy_from_slice(&1_000_000u64.to_le_bytes());
            subs[88..90].copy_from_slice(&0u16.to_le_bytes()); // relative

            let mut events = [0u8; 64];
            let mut nevents: usize = 0;
            let rc = unsafe { poll_oneoff(subs.as_ptr(), events.as_mut_ptr(), 2, &mut nevents) };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            for i in 0..nevents.min(2) {
                let off = i * 32;
                let userdata = u64::from_le_bytes(events[off..off + 8].try_into().unwrap());
                let err = u16::from_le_bytes(events[off + 8..off + 10].try_into().unwrap());
                let flags = u16::from_le_bytes(events[off + 24..off + 26].try_into().unwrap());
                if userdata == 1 {
                    if err != 0 {
                        return Err(io::Error::from_raw_os_error(err as i32));
                    }
                    if (flags & 1) != 0 {
                        return Err(os_error(abi::Error::new(Errno::ENOTCONN)));
                    }
                    return Ok(true);
                }
            }
            Ok(false)
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let _ = timeout_ms;
            Ok(true)
        }
    }
}

/// Build an IPv4 ICMP Echo Request (`type = 8, code = 0`) packet with valid IPv4 & ICMP checksums.
pub fn build_icmp_echo_request(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_icmp_echo(src, dst, 8, id, seq, payload)
}

/// Build an IPv4 ICMP Echo Reply (`type = 0, code = 0`) packet with valid IPv4 & ICMP checksums.
pub fn build_icmp_echo_reply(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_icmp_echo(src, dst, 0, id, seq, payload)
}

fn build_icmp_echo(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    icmp_type: u8,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(icmp_type);
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let csum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());
    build_ipv4_packet(src, dst, 1, 64, &icmp)
}

/// Parsed IPv4 ICMP Echo message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpEcho {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub icmp_type: u8,
    pub id: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
}

/// Parse an IPv4 ICMP Echo Request (`type == 8`) or Echo Reply (`type == 0`).
pub fn parse_icmp_echo(pkt: &[u8]) -> Option<IcmpEcho> {
    if pkt.len() < 28 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl + 8 > pkt.len() || pkt[9] != 1 {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len != pkt.len() {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let icmp = &pkt[ihl..];
    let icmp_type = icmp[0];
    if (icmp_type != 8 && icmp_type != 0) || icmp[1] != 0 {
        return None;
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    Some(IcmpEcho {
        src,
        dst,
        icmp_type,
        id,
        seq,
        payload: icmp[8..].to_vec(),
    })
}

/// Build an IPv4 UDP packet with valid IPv4 & UDP checksums.
pub fn build_udp_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);

    // UDP pseudo-header + UDP segment checksum.
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let mut csum = internet_checksum(&pseudo);
    if csum == 0 {
        csum = 0xffff;
    }
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    build_ipv4_packet(src, dst, 17, 64, &udp)
}

/// Parsed IPv4 UDP datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpIpv4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

/// Parse an IPv4 UDP datagram.
pub fn parse_udp_ipv4_packet(pkt: &[u8]) -> Option<UdpIpv4> {
    if pkt.len() < 28 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl + 8 > pkt.len() || pkt[9] != 17 {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len != pkt.len() {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let udp = &pkt[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    Some(UdpIpv4 {
        src,
        dst,
        src_port,
        dst_port,
        payload: udp[8..udp_len].to_vec(),
    })
}

/// Convenience helper extracting `abi::Errno` from `io::Error` if present.
pub fn tun_errno(err: &io::Error) -> Option<Errno> {
    crate::errno_of(err).or_else(|| {
        err.get_ref()
            .and_then(|e| e.downcast_ref::<OsCallError>())
            .map(|o| o.0.errno)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_and_udp_builders_round_trip() {
        let a = Ipv4Addr::new(10, 64, 1, 2);
        let b = Ipv4Addr::new(10, 64, 1, 3);
        let req = build_icmp_echo_request(a, b, 0x1234, 7, b"ping-payload");
        let parsed = parse_icmp_echo(&req).expect("valid icmp");
        assert_eq!(parsed.src, a);
        assert_eq!(parsed.dst, b);
        assert_eq!(parsed.icmp_type, 8);
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.seq, 7);
        assert_eq!(parsed.payload, b"ping-payload");

        let udp = build_udp_ipv4_packet(a, b, 4000, 5000, b"hello-udp");
        let up = parse_udp_ipv4_packet(&udp).expect("valid udp");
        assert_eq!(up.src, a);
        assert_eq!(up.dst, b);
        assert_eq!(up.src_port, 4000);
        assert_eq!(up.dst_port, 5000);
        assert_eq!(up.payload, b"hello-udp");
    }
}
