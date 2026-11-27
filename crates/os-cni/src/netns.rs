//! Network namespace interface drivers: `UserspaceNetnsDriver` + optional `LinuxTunNetnsDriver`.

use crate::spec::{
    CNI_ERR_INTERNAL, CNI_ERR_INVALID_CONFIG, CNI_ERR_IO_FAILURE, CniAttachmentDescriptor,
    CniError, DriverMode, load_cni_attachment, remove_cni_attachment, save_cni_attachment,
    validate_no_symlinks_on_existing_path,
};
use std::net::Ipv4Addr;
use std::path::Path;

pub trait NetnsDriver: Send + Sync {
    fn driver_name(&self) -> &'static str;

    fn setup_interface(
        &self,
        state_dir: &Path,
        desc: &CniAttachmentDescriptor,
    ) -> Result<String, CniError>;

    fn check_interface(
        &self,
        state_dir: &Path,
        desc: &CniAttachmentDescriptor,
    ) -> Result<(), CniError>;

    fn delete_interface(
        &self,
        state_dir: &Path,
        container_id: &str,
        netns: &str,
        ifname: &str,
    ) -> Result<(), CniError>;
}

/// Portable userspace CNI driver: persists atomic `0600` attachment descriptors consumed by
/// `containerd-shim-os` and `os-native` when wiring pods to `NativeOverlaySwitch`.
#[derive(Clone, Debug, Default)]
pub struct UserspaceNetnsDriver;

impl NetnsDriver for UserspaceNetnsDriver {
    fn driver_name(&self) -> &'static str {
        "userspace"
    }

    fn setup_interface(
        &self,
        state_dir: &Path,
        desc: &CniAttachmentDescriptor,
    ) -> Result<String, CniError> {
        let mut stored = desc.clone();
        stored.driver = "userspace".to_string();
        save_cni_attachment(state_dir, &stored)?;
        Ok("userspace".to_string())
    }

    fn check_interface(
        &self,
        state_dir: &Path,
        desc: &CniAttachmentDescriptor,
    ) -> Result<(), CniError> {
        let Some(existing) = load_cni_attachment(state_dir, &desc.container_id)? else {
            return Err(CniError::new(
                CNI_ERR_INTERNAL,
                "userspace CNI attachment missing",
                format!("no attachment descriptor for '{}'", desc.container_id),
            ));
        };
        if existing.ifname != desc.ifname
            || existing.ip != desc.ip
            || existing.lease_id != desc.lease_id
            || existing.netns != desc.netns
        {
            return Err(CniError::new(
                CNI_ERR_INTERNAL,
                "userspace CNI attachment mismatch",
                format!("attachment drift for '{}'", desc.container_id),
            ));
        }
        Ok(())
    }

    fn delete_interface(
        &self,
        state_dir: &Path,
        container_id: &str,
        _netns: &str,
        _ifname: &str,
    ) -> Result<(), CniError> {
        remove_cni_attachment(state_dir, container_id)
    }
}

/// Optional Linux kernel `/dev/net/tun` + `setns(CLONE_NEWNET)` driver for privileged hosts
/// with `CAP_NET_ADMIN`, with clean fallback to [`UserspaceNetnsDriver`] in `Auto` mode.
#[derive(Clone, Debug)]
pub struct LinuxTunNetnsDriver {
    pub mode: DriverMode,
}

impl Default for LinuxTunNetnsDriver {
    fn default() -> Self {
        Self {
            mode: DriverMode::Auto,
        }
    }
}

impl NetnsDriver for LinuxTunNetnsDriver {
    fn driver_name(&self) -> &'static str {
        match self.mode {
            DriverMode::Userspace => "userspace",
            DriverMode::Linux => "linux-tun",
            DriverMode::Auto => "auto",
        }
    }

    fn setup_interface(
        &self,
        state_dir: &Path,
        desc: &CniAttachmentDescriptor,
    ) -> Result<String, CniError> {
        if self.mode == DriverMode::Userspace {
            return UserspaceNetnsDriver.setup_interface(state_dir, desc);
        }
        #[cfg(target_os = "linux")]
        {
            match setup_linux_tun_in_netns(desc) {
                Ok(()) => {
                    let mut stored = desc.clone();
                    stored.driver = "linux-tun".to_string();
                    save_cni_attachment(state_dir, &stored)?;
                    Ok("linux-tun".to_string())
                }
                Err(e) if self.mode == DriverMode::Auto => {
                    // Cleanly fall back to userspace driver when unprivileged or non-Linux netns.
                    let _ = e;
                    UserspaceNetnsDriver.setup_interface(state_dir, desc)
                }
                Err(e) => Err(e),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            if self.mode == DriverMode::Linux {
                return Err(CniError::new(
                    CNI_ERR_IO_FAILURE,
                    "linux-tun driver unavailable",
                    "linux-tun requires Linux with CAP_NET_ADMIN",
                ));
            }
            UserspaceNetnsDriver.setup_interface(state_dir, desc)
        }
    }

    fn check_interface(
        &self,
        state_dir: &Path,
        desc: &CniAttachmentDescriptor,
    ) -> Result<(), CniError> {
        UserspaceNetnsDriver.check_interface(state_dir, desc)?;
        #[cfg(target_os = "linux")]
        if self.mode != DriverMode::Userspace
            && desc.driver == "linux-tun"
            && !desc.netns.is_empty()
        {
            check_linux_tun_in_netns(desc)?;
        }
        Ok(())
    }

    fn delete_interface(
        &self,
        state_dir: &Path,
        container_id: &str,
        netns: &str,
        ifname: &str,
    ) -> Result<(), CniError> {
        #[cfg(target_os = "linux")]
        if self.mode != DriverMode::Userspace && !netns.is_empty() && !ifname.is_empty() {
            // Best-effort teardown inside netns; ignore ENOENT / EPERM so DEL stays idempotent.
            let _ = teardown_linux_tun_in_netns(netns, ifname);
        }
        UserspaceNetnsDriver.delete_interface(state_dir, container_id, netns, ifname)
    }
}

#[cfg(target_os = "linux")]
fn setup_linux_tun_in_netns(desc: &CniAttachmentDescriptor) -> Result<(), CniError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let netns_path = Path::new(&desc.netns);
    validate_no_symlinks_on_existing_path(netns_path, "CNI_NETNS")?;
    let c_netns = CString::new(netns_path.as_os_str().as_bytes())
        .map_err(|_| CniError::new(CNI_ERR_IO_FAILURE, "invalid CNI_NETNS path", "NUL in path"))?;
    let ip: Ipv4Addr = desc
        .ip
        .parse()
        .map_err(|_| CniError::new(CNI_ERR_INTERNAL, "invalid IPv4", desc.ip.clone()))?;
    let prefix_len = desc.prefix_len;
    if !(1..=32).contains(&prefix_len) {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            "invalid IPv4 prefix length",
            format!("prefix_len {prefix_len} outside 1..=32"),
        ));
    }
    let ifname = desc.ifname.clone();
    let mtu = desc.mtu;

    // Run `setns(CLONE_NEWNET)` on a short-lived dedicated thread so the caller thread's netns
    // is never mutated.
    let handle = std::thread::spawn(move || -> Result<(), CniError> {
        // SAFETY: `c_netns` is NUL-terminated.
        let ns_fd = unsafe {
            libc::open(
                c_netns.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if ns_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "failed to open CNI_NETNS",
                err.to_string(),
            ));
        }
        // SAFETY: `ns_fd` is a valid fd opened above.
        let rc = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
        unsafe { libc::close(ns_fd) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "setns(CLONE_NEWNET) failed",
                err.to_string(),
            ));
        }

        let dev_tun = CString::new("/dev/net/tun").unwrap();
        let tun_fd = unsafe { libc::open(dev_tun.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if tun_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "open /dev/net/tun failed",
                err.to_string(),
            ));
        }

        let mut ifr = [0u8; 40];
        let name_bytes = ifname.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        let flags: u16 = 0x1001; // IFF_TUN | IFF_NO_PI
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());

        // TUNSETIFF = 0x400454ca, TUNSETPERSIST = 0x400454cb
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
        let rc = unsafe { libc::ioctl(tun_fd, TUNSETIFF as _, ifr.as_mut_ptr()) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(tun_fd) };
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "ioctl(TUNSETIFF) failed",
                err.to_string(),
            ));
        }
        if unsafe { libc::ioctl(tun_fd, TUNSETPERSIST as _, 1 as libc::c_int) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(tun_fd) };
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "ioctl(TUNSETPERSIST) failed",
                err.to_string(),
            ));
        }

        // Configure IPv4 address, netmask, MTU, and IFF_UP via AF_INET control socket.
        // Keep `tun_fd` open until all configuration ioctls succeed so we can atomically
        // rollback `TUNSETPERSIST = 0` on any failure.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if sock < 0 {
            let err = std::io::Error::last_os_error();
            let _ = unsafe { libc::ioctl(tun_fd, TUNSETPERSIST as _, 0 as libc::c_int) };
            unsafe { libc::close(tun_fd) };
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "AF_INET control socket failed",
                err.to_string(),
            ));
        }

        let res = (|| -> Result<(), CniError> {
            // SIOCSIFADDR
            let mut req = make_ifreq(&ifname);
            write_sockaddr_in(&mut req[16..32], ip);
            if unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as _, req.as_mut_ptr()) } < 0 {
                return Err(CniError::new(
                    CNI_ERR_IO_FAILURE,
                    "SIOCSIFADDR failed",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            // SIOCSIFNETMASK
            let mask_u32 = !0u32 << (32 - u32::from(prefix_len));
            let mut req = make_ifreq(&ifname);
            write_sockaddr_in(&mut req[16..32], Ipv4Addr::from(mask_u32));
            if unsafe { libc::ioctl(sock, libc::SIOCSIFNETMASK as _, req.as_mut_ptr()) } < 0 {
                return Err(CniError::new(
                    CNI_ERR_IO_FAILURE,
                    "SIOCSIFNETMASK failed",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            // SIOCSIFMTU
            let mut req = make_ifreq(&ifname);
            req[16..20].copy_from_slice(&(mtu as i32).to_ne_bytes());
            if unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, req.as_mut_ptr()) } < 0 {
                return Err(CniError::new(
                    CNI_ERR_IO_FAILURE,
                    "SIOCSIFMTU failed",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            // SIOCGIFFLAGS + SIOCSIFFLAGS (preserve existing flags, OR in IFF_UP | IFF_RUNNING)
            let mut req = make_ifreq(&ifname);
            if unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, req.as_mut_ptr()) } < 0 {
                return Err(CniError::new(
                    CNI_ERR_IO_FAILURE,
                    "SIOCGIFFLAGS failed",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            let cur_flags = i16::from_ne_bytes([req[16], req[17]]);
            let up_flags = cur_flags | (libc::IFF_UP | libc::IFF_RUNNING) as i16;
            req[16..18].copy_from_slice(&up_flags.to_ne_bytes());
            if unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, req.as_mut_ptr()) } < 0 {
                return Err(CniError::new(
                    CNI_ERR_IO_FAILURE,
                    "SIOCSIFFLAGS failed",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            Ok(())
        })();
        unsafe { libc::close(sock) };
        if res.is_err() {
            let _ = unsafe { libc::ioctl(tun_fd, TUNSETPERSIST as _, 0 as libc::c_int) };
        }
        unsafe { libc::close(tun_fd) };
        res
    });

    handle
        .join()
        .map_err(|_| CniError::new(CNI_ERR_INTERNAL, "netns worker panicked", ""))?
}

#[cfg(target_os = "linux")]
fn check_linux_tun_in_netns(desc: &CniAttachmentDescriptor) -> Result<(), CniError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let netns_path = Path::new(&desc.netns);
    validate_no_symlinks_on_existing_path(netns_path, "CNI_NETNS")?;
    let c_netns = CString::new(netns_path.as_os_str().as_bytes())
        .map_err(|_| CniError::new(CNI_ERR_IO_FAILURE, "invalid CNI_NETNS path", "NUL in path"))?;
    let ifname = desc.ifname.clone();

    let handle = std::thread::spawn(move || -> Result<(), CniError> {
        let ns_fd = unsafe {
            libc::open(
                c_netns.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if ns_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "failed to open CNI_NETNS during CHECK",
                err.to_string(),
            ));
        }
        let rc = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
        unsafe { libc::close(ns_fd) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "setns(CLONE_NEWNET) failed during CHECK",
                err.to_string(),
            ));
        }
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if sock < 0 {
            let err = std::io::Error::last_os_error();
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "AF_INET control socket failed during CHECK",
                err.to_string(),
            ));
        }
        let mut req = make_ifreq(&ifname);
        let rc = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, req.as_mut_ptr()) };
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        if rc < 0 {
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "TUN interface missing in netns",
                format!("{ifname}: {err}"),
            ));
        }
        let cur_flags = i16::from_ne_bytes([req[16], req[17]]);
        if (cur_flags & (libc::IFF_UP as i16)) == 0 {
            return Err(CniError::new(
                CNI_ERR_IO_FAILURE,
                "TUN interface is down in netns",
                format!("{ifname} lacks IFF_UP"),
            ));
        }
        Ok(())
    });

    handle
        .join()
        .map_err(|_| CniError::new(CNI_ERR_INTERNAL, "netns check worker panicked", ""))?
}

#[cfg(target_os = "linux")]
fn teardown_linux_tun_in_netns(netns: &str, ifname: &str) -> Result<(), CniError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let netns_path = Path::new(netns);
    if validate_no_symlinks_on_existing_path(netns_path, "CNI_NETNS").is_err() {
        return Ok(());
    }
    let Ok(c_netns) = CString::new(netns_path.as_os_str().as_bytes()) else {
        return Ok(());
    };
    let ifname = ifname.to_string();
    let _ = std::thread::spawn(move || {
        let ns_fd = unsafe {
            libc::open(
                c_netns.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if ns_fd < 0 {
            return;
        }
        let rc = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
        unsafe { libc::close(ns_fd) };
        if rc != 0 {
            return;
        }
        let dev_tun = CString::new("/dev/net/tun").unwrap();
        let tun_fd = unsafe { libc::open(dev_tun.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if tun_fd < 0 {
            return;
        }
        let mut ifr = make_ifreq(&ifname);
        let flags: u16 = 0x1001;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
        if unsafe { libc::ioctl(tun_fd, TUNSETIFF as _, ifr.as_mut_ptr()) } >= 0 {
            let _ = unsafe { libc::ioctl(tun_fd, TUNSETPERSIST as _, 0 as libc::c_int) };
        }
        unsafe { libc::close(tun_fd) };
    })
    .join();
    Ok(())
}

#[cfg(target_os = "linux")]
fn make_ifreq(ifname: &str) -> [u8; 40] {
    let mut ifr = [0u8; 40];
    let bytes = ifname.as_bytes();
    let len = bytes.len().min(15);
    ifr[..len].copy_from_slice(&bytes[..len]);
    ifr
}

#[cfg(target_os = "linux")]
fn write_sockaddr_in(dst: &mut [u8], ip: Ipv4Addr) {
    dst.fill(0);
    let family = libc::AF_INET as u16;
    dst[0..2].copy_from_slice(&family.to_ne_bytes());
    dst[4..8].copy_from_slice(&ip.octets());
}
