//! The boot reaper is user space. Its proof cannot open files, spawn or signal other tasks.
#[cfg(target_os = "wasi")]
mod reaper {
    use std::sync::atomic::{AtomicBool, Ordering};
    static REAP: AtomicBool = AtomicBool::new(true);

    #[unsafe(no_mangle)]
    pub extern "C" fn __os_init_signal(signal: u32) {
        if signal == 17 {
            REAP.store(true, Ordering::SeqCst);
        }
    }

    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        fn callback_signal(name: *const u8, len: usize);
        fn proc_id(pid: *mut u32) -> u32;
    }
    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        fn sigaction(signal: u32, kind: u32, mask: u32, flags: u32) -> i32;
        fn waitpid2(pid: i32, status: *mut u32, options: u32) -> i32;
    }

    pub fn run() -> Result<(), String> {
        let mut pid = 0;
        // SAFETY: scalar imports and valid, live pointers to the callback name and PID.
        unsafe {
            if proc_id(&mut pid) != 0 || pid != 1 {
                return Err("requires the Machine boot capability".into());
            }
            let name = b"__os_init_signal";
            callback_signal(name.as_ptr(), name.len());
            if sigaction(17, 2, 0, 0x10000000) < 0 {
                return Err("cannot install SIGCHLD handler".into());
            }
        }
        loop {
            if REAP.swap(false, Ordering::SeqCst) {
                loop {
                    let mut status = 0;
                    // SAFETY: status points to a live u32; -1/WNOHANG select ended children.
                    let pid = unsafe { waitpid2(-1, &mut status, 1) };
                    match pid {
                        1.. => (),
                        0 | -12 => break, // No ended child, or ECHILD.
                        -27 => continue,  // EINTR.
                        _ => return Err(format!("waitpid failed: {}", -pid)),
                    }
                }
            }
            // Signals are delivered at runtime safe points; sleeping locally sends no I/O.
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

fn main() {
    #[cfg(target_os = "wasi")]
    let result = reaper::run();
    #[cfg(not(target_os = "wasi"))]
    let result: Result<(), String> = Err("requires the OS WASI runtime".into());
    if let Err(error) = result {
        eprintln!("init: {error}");
        std::process::exit(1);
    }
}
