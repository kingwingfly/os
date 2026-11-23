use abi::Errno;
use os_services::exportd::{ExportDaemon, current_uid};
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn exportd_signal(sig: u32) {
    if matches!(sig, 1 | 2 | 15) {
        STOP.store(true, Ordering::Release);
    }
}

fn run() -> Result<(), Errno> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("Usage: exportd [--user [uid]]");
        return Ok(());
    }
    os_posix::init_preopens().map_err(|_| Errno::EIO)?;
    let user = match args.as_slice() {
        [] => None,
        [u] if u == "--user" => Some(current_uid()?),
        [u, id] if u == "--user" => Some(id.parse().map_err(|_| Errno::EINVAL)?),
        _ => return Err(Errno::EINVAL),
    };
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasix_32v1")]
        unsafe extern "C" {
            fn callback_signal(name: *const u8, len: usize);
        }
        #[link(wasm_import_module = "os")]
        unsafe extern "C" {
            fn sigaction(sig: u32, kind: u32, mask: u32, flags: u32) -> i32;
        }
        let name = b"exportd_signal";
        // SAFETY: static exported callback, scalar WASIX signal dispositions.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            for sig in [1, 2, 15] {
                if sigaction(sig, 2, 0, 0) < 0 {
                    return Err(Errno::EIO);
                }
            }
        }
    }
    ExportDaemon::bind(user)?.run(|| STOP.load(Ordering::Acquire))
}
fn main() {
    if let Err(e) = run() {
        eprintln!("exportd: {e:?} ({})", e.text());
        std::process::exit(1);
    }
}
