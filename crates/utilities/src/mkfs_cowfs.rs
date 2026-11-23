//! `mkfs.cowfs` utility: format a managed `/dev/vdN` or `volume:<uuid>` target as `os-cowfs`
//! (`docs/architecture/contract.md` §2.7, §2.16, §4; Blueprint §3.1 `C-02`).
//!
//! Strictly refuses:
//! - non-root callers (`EPERM`)
//! - mounted or leased targets (`EBUSY`)
//! - already-formatted volumes without `-f`/`--force` (`EEXIST`)
//! - any directory, regular file, symlink, `hostfs:`, `opfs:`, `helperfs:`, `sharefs:`, or
//!   non-block tree (`ENOTBLK`)
//! - read-only `/dev/loopN` archive devices (`EROFS` / `ENOTBLK`)

use abi::Errno;
use abi::contract::cowfs_ioctl;
use abi::volume::{CowfsInfoResp, CowfsMkfsReq};
use std::io;

const USAGE: &str = "Usage: mkfs.cowfs [-f|--force] [-L|--label LABEL] [--json] TARGET\n\n\
Format a managed os-cowfs volume device (/dev/vdN or volume:<uuid>).\n\
Requires root (uid 0). Refuses directories, files, symlinks, and non-block trees (ENOTBLK).\n";

const MAX_VBLK_SCAN: u32 = 16;

pub(crate) trait MkfsBackend {
    fn uid(&self) -> io::Result<u32>;
    fn mkfs(&mut self, target: &str, req: &CowfsMkfsReq) -> io::Result<CowfsInfoResp>;
}

fn errno_io(errno: Errno, detail: &str) -> io::Error {
    let kind = match errno {
        Errno::EPERM | Errno::EACCES => io::ErrorKind::PermissionDenied,
        Errno::ENOENT => io::ErrorKind::NotFound,
        Errno::EEXIST => io::ErrorKind::AlreadyExists,
        Errno::EINVAL => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        os_posix::OsCallError(abi::Error::because(errno, detail)),
    )
}

type Batch<'a> = dyn Fn(&[abi::Call]) -> io::Result<abi::Results> + 'a;

struct OsMkfsBackend<'a> {
    batch: &'a Batch<'a>,
}

impl OsMkfsBackend<'_> {
    fn open_device(&self, path: &str, allow_loop: bool) -> io::Result<u32> {
        let mut reply = (self.batch)(&[abi::Call::Open {
            path: path.to_string(),
            flags: abi::O_RDONLY | abi::O_NOFOLLOW,
            mode: 0,
            size: None,
            sha256: None,
            version: None,
        }])?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| match e.errno {
                Errno::ELOOP => errno_io(Errno::ENOTBLK, "symlink target"),
                Errno::ENOENT if !path.starts_with("/dev/vd") => {
                    errno_io(Errno::ENOTBLK, "not a volume device")
                }
                errno => errno_io(errno, e.detail.as_deref().unwrap_or("")),
            })?;
        let fd = val["fd"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| errno_io(Errno::EIO, "invalid descriptor"))?;
        let stat = serde_json::from_value::<abi::Stat>(val["stat"].clone());
        if !stat.is_ok_and(|st| {
            st.is_device()
                && st
                    .rdev
                    .as_deref()
                    .is_some_and(|r| r.starts_with("vblk:") || allow_loop && r.starts_with("loop:"))
        }) {
            self.close_fd(fd);
            return Err(errno_io(Errno::ENOTBLK, "not a managed volume device"));
        }
        Ok(fd)
    }

    fn close_fd(&self, fd: u32) {
        let _ = (self.batch)(&[abi::Call::Close { fd: fd.into() }]);
    }

    fn send_mkfs_ioctl(&self, fd: u32, req: &CowfsMkfsReq) -> io::Result<CowfsInfoResp> {
        let arg = serde_json::to_value(req).map_err(|e| errno_io(Errno::EINVAL, &e.to_string()))?;
        let res = (self.batch)(&[abi::Call::Ioctl {
            fd: fd.into(),
            request: cowfs_ioctl::COWFS_IOC_MKFS,
            arg,
        }]);
        self.close_fd(fd);
        let mut reply = res?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
    }

    fn find_any_vblk(&self) -> Option<u32> {
        (0..MAX_VBLK_SCAN).find_map(|i| self.open_device(&format!("/dev/vd{i}"), false).ok())
    }
}

impl MkfsBackend for OsMkfsBackend<'_> {
    fn uid(&self) -> io::Result<u32> {
        let mut reply = (self.batch)(&[abi::Call::Getcreds])?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        let creds: abi::Creds =
            serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))?;
        Ok(creds.uid)
    }

    fn mkfs(&mut self, target: &str, req: &CowfsMkfsReq) -> io::Result<CowfsInfoResp> {
        if target.is_empty() {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a managed /dev/vdN volume device",
            ));
        }
        if let Some(vol) = target.strip_prefix("volume:") {
            if vol.is_empty() || vol.contains(['/', '\0']) {
                return Err(errno_io(Errno::EINVAL, "invalid volume identifier"));
            }
            let fd = self
                .find_any_vblk()
                .ok_or_else(|| errno_io(Errno::ENODEV, "no /dev/vdN device available in store"))?;
            let mut vol_req = req.clone();
            vol_req.volume = Some(vol.to_string());
            return self.send_mkfs_ioctl(fd, &vol_req);
        }

        // Refuse explicit non-block tree prefixes (`hostfs:`, `opfs:`, `helperfs:`, `sharefs:`,
        // `cloud:`, `snapshot:`) and trailing slashes (`ENOTBLK`, contract §2.7 & §4).
        if (target.contains(':') && !target.starts_with('/')) || target.ends_with('/') {
            return Err(errno_io(
                Errno::ENOTBLK,
                "refusing to format non-block tree target",
            ));
        }

        let fd = self.open_device(target, true)?;
        self.send_mkfs_ioctl(fd, req)
    }
}

#[derive(Default)]
struct ParsedArgs {
    help: bool,
    force: bool,
    json: bool,
    label: Option<String>,
    target: Option<String>,
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
            "-f" | "--force" => parsed.force = true,
            "--json" => parsed.json = true,
            "-L" | "--label" => {
                let lbl = iter
                    .next()
                    .ok_or_else(|| "mkfs.cowfs: --label requires an argument".to_string())?;
                if lbl.contains('\0') || lbl.len() > 64 {
                    return Err("mkfs.cowfs: invalid label (max 64 bytes, no NUL)".to_string());
                }
                parsed.label = Some(lbl.clone());
            }
            s if s.starts_with("--label=") => {
                let lbl = &s["--label=".len()..];
                if lbl.contains('\0') || lbl.len() > 64 {
                    return Err("mkfs.cowfs: invalid label (max 64 bytes, no NUL)".to_string());
                }
                parsed.label = Some(lbl.to_string());
            }
            s if s.starts_with('-') => {
                return Err(format!("mkfs.cowfs: unsupported option '{s}'"));
            }
            target => {
                if parsed.target.is_some() {
                    return Err("mkfs.cowfs: expected a single TARGET operand".to_string());
                }
                parsed.target = Some(target.to_string());
            }
        }
    }
    if !parsed.help && parsed.target.is_none() {
        return Err("mkfs.cowfs: missing TARGET (/dev/vdN or volume:<uuid>)".to_string());
    }
    Ok(parsed)
}

fn format_err(target: &str, err: &io::Error) -> String {
    if let Some(errno) = os_posix::errno_of(err) {
        format!("mkfs.cowfs: {target}: {errno:?}: {err}")
    } else {
        format!("mkfs.cowfs: {target}: {err}")
    }
}

pub(crate) fn run_with(
    args: &[String],
    backend: &mut impl MkfsBackend,
) -> (String, Vec<String>, i32) {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => return (String::new(), vec![msg], 2),
    };
    if parsed.help {
        return (USAGE.to_string(), Vec::new(), 0);
    }
    let target = parsed.target.unwrap();

    match backend.uid() {
        Ok(0) => {}
        Ok(_) => {
            let err = errno_io(Errno::EPERM, "Operation not permitted (root required)");
            return (String::new(), vec![format_err(&target, &err)], 1);
        }
        Err(err) => return (String::new(), vec![format_err(&target, &err)], 1),
    }

    let req = CowfsMkfsReq {
        force: parsed.force,
        label: parsed.label,
        volume: None,
    };
    let info = match backend.mkfs(&target, &req) {
        Ok(info) => info,
        Err(err) => return (String::new(), vec![format_err(&target, &err)], 1),
    };

    if parsed.json {
        let out = serde_json::to_string_pretty(&info).unwrap_or_else(|_| "{}".into()) + "\n";
        return (out, Vec::new(), 0);
    }
    let short_root = &info.root[..info.root.len().min(12)];
    let out = format!(
        "mkfs.cowfs: formatted volume {} on {} (format v{}, incarnation {}, root {})\n",
        info.volume, target, info.format_version, info.incarnation, short_root
    );
    (out, Vec::new(), 0)
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsMkfsBackend {
        batch: &os_posix::batch,
    };
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
    use abi::contract::{COWFS_FORMAT_VERSION, Durability, WriterModel};

    struct MockMkfs {
        uid: u32,
        result: io::Result<CowfsInfoResp>,
        seen: Vec<(String, CowfsMkfsReq)>,
    }

    impl MockMkfs {
        fn ok(uid: u32) -> Self {
            Self {
                uid,
                result: Ok(CowfsInfoResp {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: "scratch-vd1".into(),
                    root: "a".repeat(64),
                    incarnation: 1,
                    fence: 1,
                    epoch: 0,
                    writer_model: WriterModel::Local,
                    durability: Durability::TreeCommit,
                    read_only: false,
                    parent_volume: None,
                }),
                seen: Vec::new(),
            }
        }
    }

    impl MkfsBackend for MockMkfs {
        fn uid(&self) -> io::Result<u32> {
            Ok(self.uid)
        }

        fn mkfs(&mut self, target: &str, req: &CowfsMkfsReq) -> io::Result<CowfsInfoResp> {
            self.seen.push((target.to_string(), req.clone()));
            match &self.result {
                Ok(info) => Ok(info.clone()),
                Err(e) => Err(errno_io(
                    os_posix::errno_of(e).unwrap_or(Errno::EIO),
                    "mock error",
                )),
            }
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn mkfs_uses_the_open_device_after_its_path_is_replaced() {
        let path_replaced = std::cell::Cell::new(false);
        let formatted = std::cell::Cell::new(false);
        let batch = |calls: &[abi::Call]| {
            let response = match calls {
                [abi::Call::Open { path, flags, .. }] => {
                    assert_eq!(path, "/dev/vd1");
                    assert_ne!(flags & abi::O_NOFOLLOW, 0);
                    assert!(!path_replaced.replace(true), "reopened redirected path");
                    let stat = abi::Stat {
                        mode: abi::S_IFCHR | 0o600,
                        rdev: Some("vblk:vd1".into()),
                        ..Default::default()
                    };
                    serde_json::json!({ "fd": 37, "stat": stat })
                }
                [
                    abi::Call::Ioctl {
                        fd: abi::FdRef::Fd(37),
                        request,
                        ..
                    },
                ] => {
                    assert!(path_replaced.get());
                    assert_eq!(*request, cowfs_ioctl::COWFS_IOC_MKFS);
                    formatted.set(true);
                    serde_json::to_value(MockMkfs::ok(0).result.unwrap()).unwrap()
                }
                [
                    abi::Call::Close {
                        fd: abi::FdRef::Fd(37),
                    },
                ] => serde_json::Value::Null,
                _ => panic!("unexpected pathname or descriptor operation: {calls:?}"),
            };
            Ok(abi::Results {
                results: vec![abi::Return::Ok(response)],
            })
        };
        let mut mkfs = OsMkfsBackend { batch: &batch };
        let request = CowfsMkfsReq {
            force: true,
            label: None,
            volume: None,
        };
        mkfs.mkfs("/dev/vd1", &request).unwrap();
        assert!(formatted.get());
    }

    #[test]
    fn mkfs_refuses_non_root_with_eperm() {
        let mut mock = MockMkfs::ok(1000);
        let (_, errs, code) = run_with(&s(&["/dev/vd1"]), &mut mock);
        assert_eq!(code, 1);
        assert!(errs[0].contains("EPERM"));
        assert!(mock.seen.is_empty());
    }

    #[test]
    fn mkfs_passes_force_label_and_emits_json() {
        let mut mock = MockMkfs::ok(0);
        let (out, errs, code) = run_with(
            &s(&["-f", "--label", "data-vol", "--json", "/dev/vd1"]),
            &mut mock,
        );
        assert_eq!(code, 0, "errs={errs:?}");
        assert_eq!(mock.seen.len(), 1);
        assert_eq!(mock.seen[0].0, "/dev/vd1");
        assert!(mock.seen[0].1.force);
        assert_eq!(mock.seen[0].1.label.as_deref(), Some("data-vol"));
        let info: CowfsInfoResp = serde_json::from_str(&out).unwrap();
        assert_eq!(info.volume, "scratch-vd1");
    }

    #[test]
    fn mkfs_surfaces_enotblk_eexist_ebusy_and_usage_errors() {
        let mut mock = MockMkfs::ok(0);
        mock.result = Err(errno_io(Errno::ENOTBLK, "not a block device"));
        let (_, errs, code) = run_with(&s(&["/tmp"]), &mut mock);
        assert_eq!(code, 1);
        assert!(errs[0].contains("ENOTBLK"));

        let (_, _, usage_code) = run_with(&s(&[]), &mut mock);
        assert_eq!(usage_code, 2);
    }
}
