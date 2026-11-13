//! Optional loopback host helper. It never executes a workload. Linux's
//! openat2 enforces the granted root, including concurrent symlink substitution.
#[cfg(target_os = "linux")]
mod linux;

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = linux::run() {
        eprintln!("os-local-helper: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "os-local-helper currently requires Linux with openat2; use Chrome or Edge for direct host-folder mounts, or use browser storage"
        );
        std::process::exit(1);
    }
}
