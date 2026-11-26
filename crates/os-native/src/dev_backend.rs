//! OS CSPRNG (`libc::getrandom`) and native `/dev` character device backend stack.

use abi::Errno;
use std::rc::Rc;
use vfs::devfs::DeviceBackend;
use vfs::guidev::{GuiDeviceBackend, GuiDeviceRegistry};
use vfs::loopdev::{LoopDeviceBackend, LoopRegistry};
use vfs::vblk::{VblkDeviceBackend, VblkRegistry};

/// Fill `buf` from the Linux kernel CSPRNG (`getrandom(2)`).
pub fn fill_os_random(buf: &mut [u8]) -> Result<(), Errno> {
    let mut off = 0usize;
    while off < buf.len() {
        let slice = &mut buf[off..];
        let rc = unsafe { libc::getrandom(slice.as_mut_ptr().cast(), slice.len(), 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(crate::errno::io_err_to_abi(&err));
        }
        if rc == 0 {
            return Err(Errno::EIO);
        }
        off += rc as usize;
    }
    Ok(())
}

/// Generate `n_bytes` of OS CSPRNG entropy encoded as lowercase hex (`2 * n_bytes` chars).
pub fn random_hex(n_bytes: usize) -> String {
    let mut raw = vec![0u8; n_bytes];
    if fill_os_random(&mut raw).is_err() {
        // Should never fail on Linux; fall back to nanos xor pid only if getrandom unavailable.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1);
        for (i, b) in raw.iter_mut().enumerate() {
            *b = ((now >> ((i % 16) * 4)) as u8).wrapping_add(i as u8);
        }
    }
    os_image::hex(&raw)
}

/// Generate a RFC-4122 v4 UUID using OS CSPRNG.
pub fn new_uuid_v4() -> String {
    let mut b = [0u8; 16];
    let _ = fill_os_random(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = os_image::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Base `DeviceBackend` using Linux `getrandom(2)` for `/dev/urandom` & `/dev/random`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeRandomBackend;

impl DeviceBackend for NativeRandomBackend {
    fn fill_random(&self, buf: &mut [u8]) -> vfs::Result<()> {
        fill_os_random(buf)
    }
}

/// Complete stacked `/dev` backend for `os-native` (ZERO remote devices at boot):
/// `GuiDeviceBackend` -> `LoopDeviceBackend` -> `VblkDeviceBackend` -> `NativeRandomBackend`.
pub type NativeDevBackend =
    GuiDeviceBackend<LoopDeviceBackend<VblkDeviceBackend<NativeRandomBackend>>>;

pub fn build_native_dev_backend(
    loop_reg: LoopRegistry,
    gui_reg: GuiDeviceRegistry,
) -> NativeDevBackend {
    let vblk = VblkDeviceBackend::new(NativeRandomBackend);
    let loop_b = LoopDeviceBackend::new(loop_reg, vblk);
    GuiDeviceBackend::new(loop_b, gui_reg)
}

pub fn build_native_dev_backend_with_vblk(
    loop_reg: LoopRegistry,
    gui_reg: GuiDeviceRegistry,
    vblk_reg: Rc<VblkRegistry>,
) -> NativeDevBackend {
    let vblk = VblkDeviceBackend::with_registry(NativeRandomBackend, vblk_reg);
    let loop_b = LoopDeviceBackend::new(loop_reg, vblk);
    GuiDeviceBackend::new(loop_b, gui_reg)
}
