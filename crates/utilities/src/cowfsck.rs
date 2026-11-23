//! `cowfsck` utility: pre-mount & online `os-cowfs` integrity checker and snapshot rollback helper
//! (`docs/architecture/contract.md` §2.12, §2.15; Blueprint §2.2, §3.2 `B-06`/`B-07`).
//!
//! Exit codes (matching Linux `fsck` conventions):
//! - `0`: volume format version and Merkle B+tree / extent / pack integrity verified clean
//! - `4`: integrity errors detected (left uncorrected; use `--rollback <snapshot>` or recovery)
//! - `8`: operational error (`EPROTONOSUPPORT` format mismatch, `ENOTBLK`, `ENOENT`, `EPERM`)
//! - `16`: usage / syntax error

use abi::Errno;
use abi::contract::{COWFS_FORMAT_VERSION, cowfs_ioctl};
use abi::volume::{CowfsForkReq, CowfsForkResp, CowfsFsckReq, CowfsFsckResp, CowfsInfoResp};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

const USAGE: &str = "Usage: cowfsck [--json] [-q|--quiet] [--snapshot SNAP] [--archive] [--rollback SNAP] TARGET\n\n\
Verify os-cowfs volume, named snapshot, /dev/loopN, or .cowpack archive integrity without mutating user data.\n\
TARGET may be /dev/vdN, /dev/loopN, volume:<uuid>, a mounted cowfs directory, or a .cowpack file with --archive.\n";

#[allow(dead_code)]
pub const COWFSCK_REPORT_PATH: &str = "/run/os/cowfsck.json";

/// Maximum number of `/dev/vdN` device slots scanned when resolving `volume:<uuid>`.
const MAX_VBLK_SCAN: u32 = 16;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsckSummary {
    pub ok: bool,
    pub volume: String,
    pub format_version: u32,
    pub epoch: u64,
    #[serde(default)]
    pub subvols_checked: usize,
    #[serde(default)]
    pub nodes_verified: usize,
    #[serde(default)]
    pub extents_verified: usize,
    #[serde(default)]
    pub packs_verified: usize,
    #[serde(default)]
    pub orphan_inodes: usize,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolled_back_to: Option<String>,
}

pub(crate) trait CowfsckBackend {
    /// Run authoritative Merkle verification (`COWFS_IOC_FSCK`) against `target`
    /// (`/dev/vdN`, `/dev/loopN`, `volume:<uuid>`, mounted cowfs dir, or `--archive FILE`).
    fn verify_merkle(&self, target: &str) -> io::Result<CowfsFsckResp>;
    fn verify_merkle_opts(
        &self,
        target: &str,
        _snapshot: Option<&str>,
        _archive: bool,
    ) -> io::Result<CowfsFsckResp> {
        self.verify_merkle(target)
    }
    fn fork_snapshot(&mut self, target: &str, req: &CowfsForkReq) -> io::Result<CowfsForkResp>;
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

struct OsCowfsckBackend;

impl OsCowfsckBackend {
    fn open_device_fd(path: &str) -> io::Result<u32> {
        let mut reply = os_posix::batch(&[abi::Call::Open {
            path: path.to_string(),
            flags: abi::O_RDONLY,
            mode: 0,
            size: None,
            sha256: None,
            version: None,
        }])?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        val["fd"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| errno_io(Errno::EIO, "open returned invalid descriptor"))
    }

    fn close_fd(fd: u32) {
        let _ = os_posix::batch(&[abi::Call::Close { fd: fd.into() }]);
    }

    fn validate_vblk_path(path: &str) -> io::Result<()> {
        if (path.contains(':') && !path.starts_with('/')) || path.ends_with('/') {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a cowfs volume or block device",
            ));
        }
        let st = os_posix::stat(Path::new(path), false)?;
        if !st.is_device() || !st.rdev.as_deref().is_some_and(|r| r.starts_with("vblk:")) {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a managed /dev/vdN volume device",
            ));
        }
        Ok(())
    }

    fn query_device_info(path: &str) -> io::Result<CowfsInfoResp> {
        let fd = Self::open_device_fd(path)?;
        let res = os_posix::batch(&[abi::Call::Ioctl {
            fd: fd.into(),
            request: cowfs_ioctl::COWFS_IOC_INFO,
            arg: serde_json::Value::Null,
        }]);
        Self::close_fd(fd);
        let mut reply = res?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
    }

    fn send_fsck_ioctl(path: &str, req: &CowfsFsckReq) -> io::Result<CowfsFsckResp> {
        let fd = Self::open_device_fd(path)?;
        let arg = serde_json::to_value(req).map_err(|e| errno_io(Errno::EINVAL, &e.to_string()))?;
        let res = os_posix::batch(&[abi::Call::Ioctl {
            fd: fd.into(),
            request: cowfs_ioctl::COWFS_IOC_FSCK,
            arg,
        }]);
        Self::close_fd(fd);
        let mut reply = res?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
    }

    /// Scan `/dev/vd0`..`/dev/vd15` via `COWFS_IOC_INFO` to locate a device attached to `uuid`,
    /// also remembering the first accessible `/dev/vdN` device so unmounted volumes in the same
    /// store can still be verified via `COWFS_IOC_FSCK { volume: Some(uuid) }`.
    fn find_vblk_for_volume(uuid: &str) -> io::Result<(Option<String>, Option<String>)> {
        let mut first_dev: Option<String> = None;
        for idx in 0..MAX_VBLK_SCAN {
            let path = format!("/dev/vd{idx}");
            let Ok(st) = os_posix::stat(Path::new(&path), false) else {
                continue;
            };
            if !st.is_device() || !st.rdev.as_deref().is_some_and(|r| r.starts_with("vblk:")) {
                continue;
            }
            if first_dev.is_none() {
                first_dev = Some(path.clone());
            }
            match Self::query_device_info(&path) {
                Ok(info) => {
                    if info.volume == uuid {
                        return Ok((Some(path), first_dev));
                    }
                }
                Err(err) if os_posix::errno_of(&err) == Some(Errno::EPROTONOSUPPORT) => {
                    return Err(err);
                }
                Err(_) => continue,
            }
        }
        Ok((None, first_dev))
    }
}

impl CowfsckBackend for OsCowfsckBackend {
    fn verify_merkle(&self, target: &str) -> io::Result<CowfsFsckResp> {
        self.verify_merkle_opts(target, None, false)
    }

    fn verify_merkle_opts(
        &self,
        target: &str,
        snapshot: Option<&str>,
        archive: bool,
    ) -> io::Result<CowfsFsckResp> {
        if archive {
            let st = os_posix::stat(Path::new(target), true)?;
            if (st.mode & abi::S_IFMT) != abi::S_IFREG {
                return Err(errno_io(
                    Errno::EINVAL,
                    "--archive target must be a regular .cowpack file",
                ));
            }
            let req = CowfsFsckReq {
                volume: None,
                snapshot: None,
                archive: true,
            };
            return Self::send_fsck_ioctl(target, &req);
        }

        if let Some(vol) = target.strip_prefix("volume:") {
            if vol.is_empty() || vol.contains(['/', '\0']) {
                return Err(errno_io(Errno::EINVAL, "invalid volume identifier"));
            }
            let (matched, first_dev) = Self::find_vblk_for_volume(vol)?;
            let dev_path = matched.or(first_dev).ok_or_else(|| {
                errno_io(Errno::ENOENT, "no /dev/vdN device available for volume")
            })?;
            let req = CowfsFsckReq {
                volume: Some(vol.to_string()),
                snapshot: snapshot.map(str::to_owned),
                archive: false,
            };
            let resp = Self::send_fsck_ioctl(&dev_path, &req)?;
            if resp.volume != vol {
                return Err(errno_io(
                    Errno::ENOENT,
                    &format!(
                        "volume mismatch: requested '{vol}', device reported '{}'",
                        resp.volume
                    ),
                ));
            }
            return Ok(resp);
        }

        if target.contains(':') && !target.starts_with('/') {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a cowfs volume or block device",
            ));
        }
        let st = os_posix::stat(Path::new(target), false)?;
        let is_vblk = st.is_device() && st.rdev.as_deref().is_some_and(|r| r.starts_with("vblk:"));
        let is_loop = st.is_device() && st.rdev.as_deref().is_some_and(|r| r.starts_with("loop:"));
        let is_dir = (st.mode & abi::S_IFMT) == abi::S_IFDIR;
        if !is_vblk && !is_loop && !is_dir {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a managed /dev/vdN, /dev/loopN, or mounted cowfs directory",
            ));
        }
        if is_vblk && target.ends_with('/') {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a managed /dev/vdN volume device",
            ));
        }
        Self::send_fsck_ioctl(
            target,
            &CowfsFsckReq {
                volume: None,
                snapshot: snapshot.map(str::to_owned),
                archive: false,
            },
        )
    }

    fn fork_snapshot(&mut self, target: &str, req: &CowfsForkReq) -> io::Result<CowfsForkResp> {
        let dev_path = if let Some(vol) = target.strip_prefix("volume:") {
            if vol.is_empty() || vol.contains(['/', '\0']) {
                return Err(errno_io(Errno::EINVAL, "invalid volume identifier"));
            }
            let (matched, _) = Self::find_vblk_for_volume(vol)?;
            matched.ok_or_else(|| {
                errno_io(
                    Errno::ENODEV,
                    &format!("volume '{vol}' is not attached to any /dev/vdN device"),
                )
            })?
        } else {
            Self::validate_vblk_path(target)?;
            target.to_string()
        };

        let fd = Self::open_device_fd(&dev_path)?;
        let arg = serde_json::to_value(req).map_err(|e| errno_io(Errno::EINVAL, &e.to_string()))?;
        let res = os_posix::batch(&[abi::Call::Ioctl {
            fd: fd.into(),
            request: cowfs_ioctl::COWFS_IOC_FORK,
            arg,
        }]);
        Self::close_fd(fd);
        let mut reply = res?;
        let val = reply
            .results
            .remove(0)
            .into_result()
            .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))?;
        serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
    }
}

fn is_valid_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Default)]
struct ParsedArgs {
    help: bool,
    json: bool,
    quiet: bool,
    archive: bool,
    snapshot: Option<String>,
    rollback: Option<String>,
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
            "--json" => parsed.json = true,
            "-q" | "--quiet" => parsed.quiet = true,
            "--archive" => parsed.archive = true,
            "--snapshot" => {
                let snap = iter
                    .next()
                    .ok_or_else(|| "cowfsck: --snapshot requires a snapshot name".to_string())?;
                if snap.is_empty() || snap.contains(['/', '\0']) {
                    return Err(format!("cowfsck: invalid snapshot name '{snap}'"));
                }
                parsed.snapshot = Some(snap.clone());
            }
            s if s.starts_with("--snapshot=") => {
                let snap = &s["--snapshot=".len()..];
                if snap.is_empty() || snap.contains(['/', '\0']) {
                    return Err(format!("cowfsck: invalid snapshot name '{snap}'"));
                }
                parsed.snapshot = Some(snap.to_string());
            }
            "--rollback" => {
                let snap = iter
                    .next()
                    .ok_or_else(|| "cowfsck: --rollback requires a snapshot name".to_string())?;
                if snap.is_empty() || snap.contains(['/', '\0']) {
                    return Err(format!("cowfsck: invalid snapshot name '{snap}'"));
                }
                parsed.rollback = Some(snap.clone());
            }
            s if s.starts_with("--rollback=") => {
                let snap = &s["--rollback=".len()..];
                if snap.is_empty() || snap.contains(['/', '\0']) {
                    return Err(format!("cowfsck: invalid snapshot name '{snap}'"));
                }
                parsed.rollback = Some(snap.to_string());
            }
            s if s.starts_with('-') => {
                return Err(format!("cowfsck: unsupported option '{s}'"));
            }
            target => {
                if parsed.target.is_some() {
                    return Err("cowfsck: expected a single TARGET operand".to_string());
                }
                parsed.target = Some(target.to_string());
            }
        }
    }
    if parsed.archive && (parsed.snapshot.is_some() || parsed.rollback.is_some()) {
        return Err("cowfsck: --archive cannot be combined with --snapshot or --rollback".into());
    }
    if !parsed.help && parsed.target.is_none() {
        return Err(
            "cowfsck: missing TARGET (/dev/vdN, /dev/loopN, volume:<uuid>, or --archive FILE)"
                .to_string(),
        );
    }
    Ok(parsed)
}

fn summary_from_resp(resp: CowfsFsckResp, rolled_back_to: Option<String>) -> FsckSummary {
    let mut errors = resp.errors;
    let mut ok = resp.ok && errors.is_empty();
    if !is_valid_hex64(&resp.root) {
        ok = false;
        errors.push(format!("invalid root digest encoding: {}", resp.root));
    }
    if ok && resp.nodes_verified == 0 {
        ok = false;
        errors.push("no Merkle nodes verified for volume".to_string());
    }
    FsckSummary {
        ok,
        volume: resp.volume,
        format_version: resp.format_version,
        epoch: resp.epoch,
        subvols_checked: resp.subvols_checked,
        nodes_verified: resp.nodes_verified,
        extents_verified: resp.extents_verified,
        packs_verified: resp.packs_verified,
        orphan_inodes: resp.orphan_inodes,
        errors,
        rolled_back_to,
    }
}

pub(crate) fn run_with(
    args: &[String],
    backend: &mut impl CowfsckBackend,
) -> (String, Vec<String>, i32) {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => return (String::new(), vec![msg], 16),
    };
    if parsed.help {
        return (USAGE.to_string(), Vec::new(), 0);
    }
    let target = parsed.target.unwrap();
    let expected_volume = target.strip_prefix("volume:");
    if let Some(vol) = expected_volume
        && (vol.is_empty() || vol.contains(['/', '\0']))
    {
        return (
            String::new(),
            vec![format!("cowfsck: {target}: invalid volume identifier")],
            8,
        );
    }

    // Step 1: Run authoritative Merkle verification via `COWFS_IOC_FSCK`.
    // NEVER infer health from `info.root` formatting or a missing/stale stored report file!
    let resp = match backend.verify_merkle_opts(&target, parsed.snapshot.as_deref(), parsed.archive)
    {
        Ok(resp) => resp,
        Err(err) => {
            if os_posix::errno_of(&err) == Some(Errno::EPROTONOSUPPORT) {
                return (
                    String::new(),
                    vec![format!(
                        "cowfsck: {target}: EPROTONOSUPPORT: incompatible os-cowfs format version (volume preserved untouched; refusing to format)"
                    )],
                    8,
                );
            }
            return (String::new(), vec![format!("cowfsck: {target}: {err}")], 8);
        }
    };

    if resp.format_version != COWFS_FORMAT_VERSION {
        return (
            String::new(),
            vec![format!(
                "cowfsck: {target}: EPROTONOSUPPORT: format version {} != expected {} (volume preserved untouched; refusing to format)",
                resp.format_version, COWFS_FORMAT_VERSION
            )],
            8,
        );
    }

    if resp.volume.is_empty() {
        return (
            String::new(),
            vec![format!(
                "cowfsck: {target}: kernel returned empty volume identifier"
            )],
            8,
        );
    }
    if let Some(expected_vol) = expected_volume
        && resp.volume != expected_vol
    {
        return (
            String::new(),
            vec![format!(
                "cowfsck: {target}: volume mismatch: expected '{expected_vol}', got '{}'",
                resp.volume
            )],
            8,
        );
    }

    let mut summary = summary_from_resp(resp, None);

    // Optional snapshot rollback (creates a fork from `snap` without destroying the original head,
    // then ALWAYS runs real Merkle verification on the newly created rollback fork before reporting
    // clean).
    if let Some(snap) = parsed.rollback {
        let req = CowfsForkReq {
            snapshot: Some(snap.clone()),
            new_volume: format!("{}-rollback-{snap}", summary.volume),
            ephemeral_if_unmodified: false,
        };
        let forked = match backend.fork_snapshot(&target, &req) {
            Ok(forked) => forked,
            Err(err) => {
                return (
                    String::new(),
                    vec![format!(
                        "cowfsck: rollback to snapshot '{snap}' failed: {err}"
                    )],
                    8,
                );
            }
        };
        let rollback_target = format!("volume:{}", forked.volume);
        let rb_resp = match backend.verify_merkle(&rollback_target) {
            Ok(r) => r,
            Err(err) => {
                if os_posix::errno_of(&err) == Some(Errno::EPROTONOSUPPORT) {
                    return (
                        String::new(),
                        vec![format!(
                            "cowfsck: rollback volume {}: EPROTONOSUPPORT: incompatible os-cowfs format version",
                            forked.volume
                        )],
                        8,
                    );
                }
                return (
                    String::new(),
                    vec![format!(
                        "cowfsck: rollback verification failed for volume {}: {err}",
                        forked.volume
                    )],
                    8,
                );
            }
        };
        if rb_resp.format_version != COWFS_FORMAT_VERSION {
            return (
                String::new(),
                vec![format!(
                    "cowfsck: rollback volume {}: EPROTONOSUPPORT: format version {} != expected {}",
                    forked.volume, rb_resp.format_version, COWFS_FORMAT_VERSION
                )],
                8,
            );
        }
        if rb_resp.volume != forked.volume {
            return (
                String::new(),
                vec![format!(
                    "cowfsck: rollback verification volume mismatch: expected '{}', got '{}'",
                    forked.volume, rb_resp.volume
                )],
                8,
            );
        }
        summary = summary_from_resp(rb_resp, Some(forked.volume));
    }

    let exit_code = if summary.ok { 0 } else { 4 };
    if parsed.json {
        let out = serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".into()) + "\n";
        return (out, Vec::new(), exit_code);
    }
    if parsed.quiet {
        return (String::new(), Vec::new(), exit_code);
    }
    if summary.ok {
        let mut msg = format!(
            "cowfsck: volume {} (format v{}, epoch {}): clean ({} nodes, {} extents, {} packs verified)\n",
            summary.volume,
            summary.format_version,
            summary.epoch,
            summary.nodes_verified,
            summary.extents_verified,
            summary.packs_verified
        );
        if let Some(vol) = &summary.rolled_back_to {
            msg.push_str(&format!("cowfsck: rolled back to new volume {vol}\n"));
        }
        (msg, Vec::new(), 0)
    } else {
        let mut errs = vec![format!(
            "cowfsck: volume {} (epoch {}): CORRUPTION DETECTED ({} error(s)):",
            summary.volume,
            summary.epoch,
            summary.errors.len()
        )];
        for e in &summary.errors {
            errs.push(format!("  - {e}"));
        }
        errs.push(
            "cowfsck: refusing to auto-format; use --rollback <snapshot> or recovery shell".into(),
        );
        (String::new(), errs, 4)
    }
}

pub fn run(args: &[String]) -> i32 {
    let mut backend = OsCowfsckBackend;
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
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn clone_io_err(e: &io::Error) -> io::Error {
        io::Error::new(
            e.kind(),
            os_posix::OsCallError(abi::Error::new(os_posix::errno_of(e).unwrap_or(Errno::EIO))),
        )
    }

    fn clean_resp(volume: &str, epoch: u64) -> CowfsFsckResp {
        CowfsFsckResp {
            ok: true,
            volume: volume.to_string(),
            format_version: COWFS_FORMAT_VERSION,
            epoch,
            root: "a".repeat(64),
            subvols_checked: 1,
            nodes_verified: 12,
            extents_verified: 4,
            packs_verified: 1,
            orphan_inodes: 0,
            errors: Vec::new(),
        }
    }

    struct MockCowfsck {
        responses: HashMap<String, io::Result<CowfsFsckResp>>,
        verified_targets: RefCell<Vec<String>>,
        fork_resp: Option<CowfsForkResp>,
        fork_requests: Vec<CowfsForkReq>,
    }

    impl MockCowfsck {
        fn clean() -> Self {
            let mut responses = HashMap::new();
            responses.insert("/dev/vd0".to_string(), Ok(clean_resp("vol-root-1", 3)));
            responses.insert(
                "volume:vol-root-1".to_string(),
                Ok(clean_resp("vol-root-1", 3)),
            );
            responses.insert(
                "volume:vol-root-1-rollback-good".to_string(),
                Ok(clean_resp("vol-root-1-rollback-good", 0)),
            );
            Self {
                responses,
                verified_targets: RefCell::new(Vec::new()),
                fork_resp: Some(CowfsForkResp {
                    volume: "vol-root-1-rollback-good".into(),
                    parent_volume: "vol-root-1".into(),
                    root: "b".repeat(64),
                    epoch: 0,
                }),
                fork_requests: Vec::new(),
            }
        }
    }

    impl CowfsckBackend for MockCowfsck {
        fn verify_merkle(&self, target: &str) -> io::Result<CowfsFsckResp> {
            self.verified_targets.borrow_mut().push(target.to_string());
            match self.responses.get(target) {
                Some(Ok(resp)) => Ok(resp.clone()),
                Some(Err(e)) => Err(clone_io_err(e)),
                None => Err(errno_io(Errno::ENOENT, "volume not found")),
            }
        }

        fn verify_merkle_opts(
            &self,
            target: &str,
            snapshot: Option<&str>,
            archive: bool,
        ) -> io::Result<CowfsFsckResp> {
            let key = if archive {
                format!("archive:{target}")
            } else if let Some(s) = snapshot {
                format!("{target}@{s}")
            } else {
                target.to_string()
            };
            if self.responses.contains_key(&key) {
                return self.verify_merkle(&key);
            }
            self.verify_merkle(target)
        }

        fn fork_snapshot(
            &mut self,
            _target: &str,
            req: &CowfsForkReq,
        ) -> io::Result<CowfsForkResp> {
            self.fork_requests.push(req.clone());
            self.fork_resp
                .clone()
                .ok_or_else(|| errno_io(Errno::ENOENT, "snapshot not found"))
        }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn cowfsck_passes_clean_volume_and_emits_json() {
        let mut mock = MockCowfsck::clean();
        let (out, errs, code) = run_with(&s(&["--json", "/dev/vd0"]), &mut mock);
        assert_eq!(code, 0, "errs={errs:?}");
        let parsed: FsckSummary = serde_json::from_str(&out).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.volume, "vol-root-1");
        assert_eq!(parsed.nodes_verified, 12);
    }

    #[test]
    fn cowfsck_refuses_incompatible_format_version_with_eprotonosupport() {
        let mut mock = MockCowfsck::clean();
        mock.responses
            .get_mut("/dev/vd0")
            .unwrap()
            .as_mut()
            .unwrap()
            .format_version = 99;
        let (_, errs, code) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code, 8);
        assert!(errs[0].contains("EPROTONOSUPPORT"));
        assert!(errs[0].contains("refusing to format"));

        mock.responses.insert(
            "/dev/vd0".to_string(),
            Err(errno_io(Errno::EPROTONOSUPPORT, "incompatible")),
        );
        let (_, errs2, code2) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code2, 8);
        assert!(errs2[0].contains("EPROTONOSUPPORT"));
    }

    #[test]
    fn cowfsck_rejects_missing_or_mismatched_volume_uuid() {
        let mut mock = MockCowfsck::clean();
        // Missing UUID must fail with exit 8 (never fall back to /dev/vd0).
        let (_, errs, code) = run_with(&s(&["volume:does-not-exist"]), &mut mock);
        assert_eq!(code, 8);
        assert!(errs[0].contains("does-not-exist"));

        // Backend returning a different volume UUID must fail with exit 8!
        mock.responses.insert(
            "volume:vol-other".to_string(),
            Ok(clean_resp("vol-root-1", 3)),
        );
        let (_, errs2, code2) = run_with(&s(&["volume:vol-other"]), &mut mock);
        assert_eq!(code2, 8);
        assert!(
            errs2[0].contains("volume mismatch"),
            "expected mismatch error, got {errs2:?}"
        );
    }

    #[test]
    fn cowfsck_fails_exit_4_on_corrupt_volume_without_stored_report() {
        // Even with valid 64-hex root digest and NO stored `/run/os/cowfsck.json` report,
        // Merkle verification errors MUST fail with exit 4 (and 0-node fake ok also fails exit 4).
        let mut mock = MockCowfsck::clean();
        let mut corrupt = clean_resp("vol-root-1", 3);
        corrupt.ok = false;
        corrupt.errors = vec!["subvol @: block digest mismatch in pack p1".to_string()];
        mock.responses.insert("/dev/vd0".to_string(), Ok(corrupt));

        let (_, errs, code) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code, 4);
        assert!(errs.iter().any(|l| l.contains("CORRUPTION DETECTED")));
        assert!(errs.iter().any(|l| l.contains("block digest mismatch")));

        // Zero verified nodes with ok=true must NEVER exit 0.
        let mut unverified = clean_resp("vol-root-1", 3);
        unverified.nodes_verified = 0;
        mock.responses
            .insert("/dev/vd0".to_string(), Ok(unverified));
        let (_, errs_zero, code_zero) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code_zero, 4);
        assert!(errs_zero.iter().any(|l| l.contains("no Merkle nodes")));
    }

    #[test]
    fn cowfsck_reports_corruption_and_verifies_rollback_fork() {
        let mut mock = MockCowfsck::clean();
        let mut corrupt = clean_resp("vol-root-1", 3);
        corrupt.ok = false;
        corrupt.errors = vec!["subvol @: block digest mismatch in pack p1".to_string()];
        mock.responses.insert("/dev/vd0".to_string(), Ok(corrupt));

        let (_, errs, code) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code, 4);
        assert!(errs.iter().any(|l| l.contains("CORRUPTION DETECTED")));
        assert!(errs.iter().any(|l| l.contains("block digest mismatch")));

        // Clean rollback fork: verifies `volume:<forked.volume>` and exits 0.
        mock.verified_targets.borrow_mut().clear();
        let (out, errs, rb_code) = run_with(&s(&["--rollback", "good", "/dev/vd0"]), &mut mock);
        assert_eq!(rb_code, 0, "errs={errs:?}");
        assert!(out.contains("vol-root-1-rollback-good"));
        assert_eq!(mock.fork_requests.len(), 1);
        assert_eq!(mock.fork_requests[0].snapshot.as_deref(), Some("good"));
        assert_eq!(
            *mock.verified_targets.borrow(),
            vec![
                "/dev/vd0".to_string(),
                "volume:vol-root-1-rollback-good".to_string()
            ]
        );

        // Corrupt rollback fork: MUST fail with exit 4 and report its errors (never exit 0)!
        let mut corrupt_fork = clean_resp("vol-root-1-rollback-good", 0);
        corrupt_fork.ok = false;
        corrupt_fork.errors = vec!["subvol @: pack trailer verification failed".to_string()];
        mock.responses.insert(
            "volume:vol-root-1-rollback-good".to_string(),
            Ok(corrupt_fork),
        );
        let (_, rb_errs, rb_bad_code) =
            run_with(&s(&["--rollback", "good", "/dev/vd0"]), &mut mock);
        assert_eq!(rb_bad_code, 4, "corrupt rollback fork must fail exit 4");
        assert!(rb_errs.iter().any(|l| l.contains("CORRUPTION DETECTED")));
        assert!(
            rb_errs
                .iter()
                .any(|l| l.contains("pack trailer verification failed"))
        );
    }

    #[test]
    fn cowfsck_supports_snapshot_and_archive_flags() {
        let mut mock = MockCowfsck::clean();
        mock.responses
            .insert("/dev/vd0@s1".to_string(), Ok(clean_resp("vol-root-1", 1)));
        mock.responses.insert(
            "archive:/tmp/pkg.cowpack".to_string(),
            Ok(clean_resp("/tmp/pkg.cowpack", 0)),
        );

        let (out_s, errs_s, code_s) = run_with(&s(&["--snapshot", "s1", "/dev/vd0"]), &mut mock);
        assert_eq!(code_s, 0, "errs={errs_s:?}");
        assert!(out_s.contains("clean"));

        let (out_a, errs_a, code_a) =
            run_with(&s(&["--archive", "--json", "/tmp/pkg.cowpack"]), &mut mock);
        assert_eq!(code_a, 0, "errs={errs_a:?}");
        let sum: FsckSummary = serde_json::from_str(&out_a).unwrap();
        assert!(sum.ok);

        // Corrupt archive exits 4.
        let mut bad_arch = clean_resp("/tmp/bad.cowpack", 0);
        bad_arch.ok = false;
        bad_arch.errors = vec!["archive header/footer/index verification failed".into()];
        mock.responses
            .insert("archive:/tmp/bad.cowpack".to_string(), Ok(bad_arch));
        let (_, errs_bad, code_bad) = run_with(&s(&["--archive", "/tmp/bad.cowpack"]), &mut mock);
        assert_eq!(code_bad, 4);
        assert!(errs_bad.iter().any(|l| l.contains("CORRUPTION DETECTED")));

        // Incompatible `--archive --snapshot` exits 16.
        let (_, _, code_usage) = run_with(
            &s(&["--archive", "--snapshot", "s1", "/tmp/pkg.cowpack"]),
            &mut mock,
        );
        assert_eq!(code_usage, 16);
    }
}
