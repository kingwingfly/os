//! `losetup` utility for `/dev/loop-control` and `/dev/loop0..7` read-only `.cowpack` archive
//! and image loop devices (`docs/architecture/contract.md` §2.16, §5; Blueprint §3.1 `C-07`/`C-08`).

use abi::Errno;
use abi::contract::loop_ioctl;
use abi::volume::LoopStatus64;
use std::io;

const USAGE: &str = "Usage:\n\
  losetup -f [--show] [-r] [FILE]     Find first free loop device (and optionally bind FILE)\n\
  losetup [-r] [--show] LOOPDEV FILE  Bind FILE to LOOPDEV\n\
  losetup -d LOOPDEV                  Detach LOOPDEV (fails EBUSY while mounted)\n\
  losetup [-a] [-J|--json] [LOOPDEV]  Show bound loop device(s)\n";

const LOOP_COUNT: usize = 8;

pub(crate) trait LosetupBackend {
    fn uid(&self) -> io::Result<u32>;
    fn get_free(&self) -> io::Result<u32>;
    fn attach(
        &mut self,
        dev_path: &str,
        file_path: &str,
        read_only: bool,
    ) -> io::Result<LoopStatus64>;
    fn detach(&mut self, dev_path: &str) -> io::Result<()>;
    fn status(&self, dev_path: &str) -> io::Result<LoopStatus64>;
}

fn errno_io(errno: Errno, detail: &str) -> io::Error {
    let kind = match errno {
        Errno::EPERM | Errno::EACCES => io::ErrorKind::PermissionDenied,
        Errno::ENOENT => io::ErrorKind::NotFound,
        Errno::EINVAL => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        os_posix::OsCallError(abi::Error::because(errno, detail)),
    )
}

fn call_one(call: abi::Call) -> io::Result<serde_json::Value> {
    let mut reply = os_posix::batch(&[call])?;
    reply
        .results
        .remove(0)
        .into_result()
        .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))
}

fn open_fd(path: &str, flags: u32) -> io::Result<u32> {
    let val = call_one(abi::Call::Open {
        path: path.to_string(),
        flags,
        mode: 0,
        size: None,
        sha256: None,
        version: None,
    })?;
    val["fd"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| errno_io(Errno::EIO, "open returned invalid descriptor"))
}

fn close_fd(fd: u32) {
    let _ = os_posix::batch(&[abi::Call::Close { fd: fd.into() }]);
}

struct OsLosetupBackend;

impl LosetupBackend for OsLosetupBackend {
    fn uid(&self) -> io::Result<u32> {
        let val = call_one(abi::Call::Getcreds)?;
        let creds: abi::Creds =
            serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))?;
        Ok(creds.uid)
    }

    fn get_free(&self) -> io::Result<u32> {
        let ctl_fd = open_fd("/dev/loop-control", abi::O_RDONLY)?;
        let res = call_one(abi::Call::Ioctl {
            fd: ctl_fd.into(),
            request: loop_ioctl::LOOP_CTL_GET_FREE,
            arg: serde_json::Value::Null,
        });
        close_fd(ctl_fd);
        let val = res?;
        val.as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| errno_io(Errno::EIO, "invalid LOOP_CTL_GET_FREE reply"))
    }

    fn attach(
        &mut self,
        dev_path: &str,
        file_path: &str,
        read_only: bool,
    ) -> io::Result<LoopStatus64> {
        let file_fd = if read_only {
            open_fd(file_path, abi::O_RDONLY)?
        } else {
            match open_fd(file_path, abi::O_RDWR) {
                Ok(fd) => fd,
                Err(e)
                    if matches!(
                        os_posix::errno_of(&e),
                        Some(Errno::EROFS | Errno::EACCES | Errno::EISDIR)
                    ) =>
                {
                    open_fd(file_path, abi::O_RDONLY)?
                }
                Err(e) => return Err(e),
            }
        };
        let dev_fd = match open_fd(dev_path, abi::O_RDONLY) {
            Ok(fd) => fd,
            Err(e) => {
                close_fd(file_fd);
                return Err(e);
            }
        };
        let res = call_one(abi::Call::Ioctl {
            fd: dev_fd.into(),
            request: loop_ioctl::LOOP_SET_FD,
            arg: serde_json::json!(file_fd),
        });
        close_fd(dev_fd);
        close_fd(file_fd);
        let val = res?;
        serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
    }

    fn detach(&mut self, dev_path: &str) -> io::Result<()> {
        let dev_fd = open_fd(dev_path, abi::O_RDONLY)?;
        let res = call_one(abi::Call::Ioctl {
            fd: dev_fd.into(),
            request: loop_ioctl::LOOP_CLR_FD,
            arg: serde_json::Value::Null,
        });
        close_fd(dev_fd);
        res.map(|_| ())
    }

    fn status(&self, dev_path: &str) -> io::Result<LoopStatus64> {
        let dev_fd = open_fd(dev_path, abi::O_RDONLY)?;
        let res = call_one(abi::Call::Ioctl {
            fd: dev_fd.into(),
            request: loop_ioctl::LOOP_GET_STATUS64,
            arg: serde_json::Value::Null,
        });
        close_fd(dev_fd);
        let val = res?;
        serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
    }
}

#[derive(Default)]
struct ParsedArgs {
    help: bool,
    find: bool,
    show: bool,
    read_only: bool,
    all: bool,
    json: bool,
    detach: Option<String>,
    positional: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    let mut parsed = ParsedArgs::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                parsed.help = true;
                return Ok(parsed);
            }
            "-f" | "--find" => parsed.find = true,
            "--show" => parsed.show = true,
            "-r" | "--read-only" => parsed.read_only = true,
            "-a" | "--all" => parsed.all = true,
            "-J" | "--json" => parsed.json = true,
            "-d" | "--detach" => {
                let dev = iter
                    .next()
                    .ok_or_else(|| "losetup: -d requires a loop device path".to_string())?;
                parsed.detach = Some(dev.clone());
            }
            s if s.starts_with('-') && s.len() > 2 && !s.starts_with("--") => {
                // Support combined short flags like `-rf` or `-aJ`.
                for ch in s[1..].chars() {
                    match ch {
                        'f' => parsed.find = true,
                        'r' => parsed.read_only = true,
                        'a' => parsed.all = true,
                        'J' => parsed.json = true,
                        other => return Err(format!("losetup: unsupported option '-{other}'")),
                    }
                }
            }
            s if s.starts_with('-') => {
                return Err(format!("losetup: unsupported option '{s}'"));
            }
            v => parsed.positional.push(v.to_string()),
        }
    }
    Ok(parsed)
}

fn format_err(target: &str, err: &io::Error) -> String {
    if let Some(errno) = os_posix::errno_of(err) {
        format!("losetup: {target}: {errno:?}: {err}")
    } else {
        format!("losetup: {target}: {err}")
    }
}

fn format_status_line(st: &LoopStatus64) -> String {
    let ro_flag = if st.read_only { "ro" } else { "rw" };
    let mnt_flag = if st.mounted { ",mounted" } else { "" };
    format!(
        "/dev/{}: [{}]:{} ({}) [{} {}{}]\n",
        st.device,
        st.backing_dev,
        st.backing_ino,
        st.file_name,
        st.archive_format,
        ro_flag,
        mnt_flag
    )
}

pub(crate) fn run_with(
    args: &[String],
    backend: &mut impl LosetupBackend,
) -> (String, Vec<String>, i32) {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => return (String::new(), vec![msg], 2),
    };
    if parsed.help {
        return (USAGE.to_string(), Vec::new(), 0);
    }

    // 1. Detach (`losetup -d /dev/loopN`).
    if let Some(dev) = parsed.detach {
        match backend.uid() {
            Ok(0) => {}
            Ok(_) => {
                let err = errno_io(Errno::EPERM, "Operation not permitted");
                return (String::new(), vec![format_err(&dev, &err)], 1);
            }
            Err(err) => return (String::new(), vec![format_err(&dev, &err)], 1),
        }
        return match backend.detach(&dev) {
            Ok(()) => (String::new(), Vec::new(), 0),
            Err(err) => (String::new(), vec![format_err(&dev, &err)], 1),
        };
    }

    // 2. Find free (`losetup -f [--show] [-r] [FILE]`).
    if parsed.find {
        match backend.uid() {
            Ok(0) => {}
            Ok(_) => {
                let err = errno_io(Errno::EPERM, "Operation not permitted");
                return (
                    String::new(),
                    vec![format_err("/dev/loop-control", &err)],
                    1,
                );
            }
            Err(err) => {
                return (
                    String::new(),
                    vec![format_err("/dev/loop-control", &err)],
                    1,
                );
            }
        }
        let idx = match backend.get_free() {
            Ok(i) => i,
            Err(err) => {
                return (
                    String::new(),
                    vec![format_err("/dev/loop-control", &err)],
                    1,
                );
            }
        };
        let dev = format!("/dev/loop{idx}");
        if parsed.positional.is_empty() {
            return (format!("{dev}\n"), Vec::new(), 0);
        }
        if parsed.positional.len() > 1 {
            return (
                String::new(),
                vec!["losetup: -f accepts at most one FILE operand".to_string()],
                2,
            );
        }
        let file = &parsed.positional[0];
        let st = match backend.attach(&dev, file, parsed.read_only) {
            Ok(s) => s,
            Err(err) => return (String::new(), vec![format_err(file, &err)], 1),
        };
        if parsed.json {
            let out = serde_json::to_string_pretty(&st).unwrap_or_else(|_| "{}".into()) + "\n";
            return (out, Vec::new(), 0);
        }
        if parsed.show {
            return (format!("{dev}\n"), Vec::new(), 0);
        }
        return (String::new(), Vec::new(), 0);
    }

    // 3. Explicit bind (`losetup [-r] [--show] /dev/loopN FILE`).
    if parsed.positional.len() == 2 {
        let dev = &parsed.positional[0];
        let file = &parsed.positional[1];
        match backend.uid() {
            Ok(0) => {}
            Ok(_) => {
                let err = errno_io(Errno::EPERM, "Operation not permitted");
                return (String::new(), vec![format_err(dev, &err)], 1);
            }
            Err(err) => return (String::new(), vec![format_err(dev, &err)], 1),
        }
        let st = match backend.attach(dev, file, parsed.read_only) {
            Ok(s) => s,
            Err(err) => return (String::new(), vec![format_err(dev, &err)], 1),
        };
        if parsed.json {
            let out = serde_json::to_string_pretty(&st).unwrap_or_else(|_| "{}".into()) + "\n";
            return (out, Vec::new(), 0);
        }
        if parsed.show {
            return (format!("{dev}\n"), Vec::new(), 0);
        }
        return (String::new(), Vec::new(), 0);
    }

    // 4. Single-device query (`losetup [-J] /dev/loopN`).
    if parsed.positional.len() == 1 && !parsed.all {
        let dev = &parsed.positional[0];
        let st = match backend.status(dev) {
            Ok(s) => s,
            Err(err) => return (String::new(), vec![format_err(dev, &err)], 1),
        };
        if parsed.json {
            let out = serde_json::to_string_pretty(&st).unwrap_or_else(|_| "{}".into()) + "\n";
            return (out, Vec::new(), 0);
        }
        return (format_status_line(&st), Vec::new(), 0);
    }

    if parsed.positional.len() > 2 {
        return (
            String::new(),
            vec!["losetup: too many positional operands".to_string()],
            2,
        );
    }

    // 5. List all bound loop devices (`losetup` or `losetup -a [-J]`).
    let mut bound = Vec::new();
    for idx in 0..LOOP_COUNT {
        let dev = format!("/dev/loop{idx}");
        match backend.status(&dev) {
            Ok(st) => bound.push(st),
            Err(e)
                if matches!(
                    os_posix::errno_of(&e),
                    Some(Errno::ENXIO | Errno::ENOENT | Errno::ENODEV)
                ) => {}
            Err(e) => return (String::new(), vec![format_err(&dev, &e)], 1),
        }
    }
    if parsed.json {
        let val = serde_json::json!({ "loopdevices": bound });
        let out = serde_json::to_string_pretty(&val).unwrap_or_else(|_| "{}".into()) + "\n";
        return (out, Vec::new(), 0);
    }
    let mut out = String::new();
    for st in &bound {
        out.push_str(&format_status_line(st));
    }
    (out, Vec::new(), 0)
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsLosetupBackend;
    let (out, errs, code) = run_with(args, &mut backend);
    if !out.is_empty() {
        print!("{out}");
    }
    for err in errs {
        eprintln!("{err}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MockLosetup {
        uid: u32,
        slots: BTreeMap<usize, LoopStatus64>,
    }

    impl MockLosetup {
        fn new(uid: u32) -> Self {
            Self {
                uid,
                slots: BTreeMap::new(),
            }
        }
    }

    impl LosetupBackend for MockLosetup {
        fn uid(&self) -> io::Result<u32> {
            Ok(self.uid)
        }

        fn get_free(&self) -> io::Result<u32> {
            for i in 0..LOOP_COUNT {
                if !self.slots.contains_key(&i) {
                    return Ok(i as u32);
                }
            }
            Err(errno_io(Errno::ENODEV, "no free loop device"))
        }

        fn attach(
            &mut self,
            dev_path: &str,
            file_path: &str,
            read_only: bool,
        ) -> io::Result<LoopStatus64> {
            let idx: usize = dev_path
                .strip_prefix("/dev/loop")
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| errno_io(Errno::EINVAL, "bad loop path"))?;
            if self.slots.contains_key(&idx) {
                return Err(errno_io(Errno::EBUSY, "already bound"));
            }
            let is_cowpack = file_path.ends_with(".cowpack");
            let st = LoopStatus64 {
                device: format!("loop{idx}"),
                bound: true,
                read_only: read_only || is_cowpack,
                mounted: false,
                backing_dev: 1,
                backing_ino: 42,
                backing_size: 4096,
                offset: 0,
                sizelimit: 4096,
                archive_format: if is_cowpack {
                    "cowpack-v1".into()
                } else {
                    "raw".into()
                },
                root_digest: is_cowpack.then(|| "a".repeat(64)),
                file_name: file_path.to_string(),
            };
            self.slots.insert(idx, st.clone());
            Ok(st)
        }

        fn detach(&mut self, dev_path: &str) -> io::Result<()> {
            let idx: usize = dev_path
                .strip_prefix("/dev/loop")
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| errno_io(Errno::EINVAL, "bad loop path"))?;
            let Some(st) = self.slots.get(&idx) else {
                return Err(errno_io(Errno::ENXIO, "not bound"));
            };
            if st.mounted {
                return Err(errno_io(Errno::EBUSY, "mounted"));
            }
            self.slots.remove(&idx);
            Ok(())
        }

        fn status(&self, dev_path: &str) -> io::Result<LoopStatus64> {
            let idx: usize = dev_path
                .strip_prefix("/dev/loop")
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| errno_io(Errno::EINVAL, "bad loop path"))?;
            self.slots
                .get(&idx)
                .cloned()
                .ok_or_else(|| errno_io(Errno::ENXIO, "not bound"))
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn losetup_find_attach_list_detach_and_non_root_eperm() {
        let mut non_root = MockLosetup::new(1000);
        let (_, errs, code) = run_with(&s(&["-f"]), &mut non_root);
        assert_eq!(code, 1);
        assert!(errs[0].contains("EPERM"));

        let mut root = MockLosetup::new(0);
        let (out, errs, code) = run_with(&s(&["-f", "--show", "/tmp/pkg.cowpack"]), &mut root);
        assert_eq!(code, 0, "errs={errs:?}");
        assert_eq!(out.trim(), "/dev/loop0");

        let (list_json, _, code) = run_with(&s(&["-a", "-J"]), &mut root);
        assert_eq!(code, 0);
        let v: serde_json::Value = serde_json::from_str(&list_json).unwrap();
        assert_eq!(v["loopdevices"].as_array().unwrap().len(), 1);
        assert_eq!(v["loopdevices"][0]["archive_format"], "cowpack-v1");
        assert_eq!(v["loopdevices"][0]["read_only"], true);

        // Mounted loop refuses detach with EBUSY.
        root.slots.get_mut(&0).unwrap().mounted = true;
        let (_, errs, code) = run_with(&s(&["-d", "/dev/loop0"]), &mut root);
        assert_eq!(code, 1);
        assert!(errs[0].contains("EBUSY"));

        // After unmount, detach succeeds cleanly.
        root.slots.get_mut(&0).unwrap().mounted = false;
        let (_, errs, code) = run_with(&s(&["-d", "/dev/loop0"]), &mut root);
        assert_eq!(code, 0, "errs={errs:?}");
        assert!(root.slots.is_empty());
    }
}
