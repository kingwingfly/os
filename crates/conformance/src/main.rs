//! Linux/WASI measurement probe; other workspace hosts keep an explicit stub.
#[cfg(any(target_os = "wasi", test))]
mod abi_audit;
#[cfg(any(target_os = "linux", target_os = "wasi"))]
mod platform;
#[cfg(any(target_os = "linux", target_os = "wasi"))]
mod probe;

fn main() {
    #[cfg(any(target_os = "linux", target_os = "wasi"))]
    probe::run();
    #[cfg(not(any(target_os = "linux", target_os = "wasi")))]
    {
        eprintln!("os-conformance requires Linux for the reference run or WASI for the OS probe");
        std::process::exit(1);
    }
}
