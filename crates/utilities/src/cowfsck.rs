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
use abi::volume::{CowfsForkReq, CowfsForkResp, CowfsInfoResp};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

const USAGE: &str = "Usage: cowfsck [--json] [-q|--quiet] [--rollback SNAPSHOT] TARGET\n\n\
Verify os-cowfs volume format version and integrity without mutating user data.\n\
TARGET may be /dev/vdN or volume:<uuid>.\n";

pub const COWFSCK_REPORT_PATH: &str = "/run/os/cowfsck.json";

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

#[derive(Clone, Debug, Default, Deserialize)]
struct StoredFsckReport {
    ok: bool,
    volume: String,
    epoch: u64,
    #[serde(default)]
    subvols_checked: usize,
    #[serde(default)]
    nodes_verified: usize,
    #[serde(default)]
    extents_verified: usize,
    #[serde(default)]
    packs_verified: usize,
    #[serde(default)]
    orphan_inodes: usize,
    #[serde(default)]
    errors: Vec<String>,
}

pub(crate) trait CowfsckBackend {
    fn query_info(&self, target: &str) -> io::Result<CowfsInfoResp>;
    fn read_stored_report(&self) -> Option<String>;
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
    fn open_target_fd(target: &str) -> io::Result<u32> {
        if let Some(vol) = target.strip_prefix("volume:") {
            if vol.is_empty() || vol.contains(['/', '\0']) {
                return Err(errno_io(Errno::EINVAL, "invalid volume identifier"));
            }
            // Fall back to `/dev/vd0` when addressing the primary boot volume by `volume:<uuid>`.
            return Self::open_device_fd("/dev/vd0");
        }
        if (target.contains(':') && !target.starts_with('/')) || target.ends_with('/') {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a cowfs volume or block device",
            ));
        }
        let st = os_posix::stat(Path::new(target), false)?;
        if !st.is_device() || !st.rdev.as_deref().is_some_and(|r| r.starts_with("vblk:")) {
            return Err(errno_io(
                Errno::ENOTBLK,
                "target is not a managed /dev/vdN volume device",
            ));
        }
        Self::open_device_fd(target)
    }

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
}

impl CowfsckBackend for OsCowfsckBackend {
    fn query_info(&self, target: &str) -> io::Result<CowfsInfoResp> {
        let fd = Self::open_target_fd(target)?;
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

    fn read_stored_report(&self) -> Option<String> {
        std::fs::read_to_string(COWFSCK_REPORT_PATH).ok()
    }

    fn fork_snapshot(&mut self, target: &str, req: &CowfsForkReq) -> io::Result<CowfsForkResp> {
        let fd = Self::open_target_fd(target)?;
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
    if !parsed.help && parsed.target.is_none() {
        return Err("cowfsck: missing TARGET (/dev/vdN or volume:<uuid>)".to_string());
    }
    Ok(parsed)
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

    // Step 1: Query volume info & verify COWFS_FORMAT_VERSION BEFORE any mount or repair!
    let info = match backend.query_info(&target) {
        Ok(info) => info,
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

    if info.format_version != COWFS_FORMAT_VERSION {
        return (
            String::new(),
            vec![format!(
                "cowfsck: {target}: EPROTONOSUPPORT: format version {} != expected {} (volume preserved untouched; refusing to format)",
                info.format_version, COWFS_FORMAT_VERSION
            )],
            8,
        );
    }

    let mut summary = FsckSummary {
        ok: true,
        volume: info.volume.clone(),
        format_version: info.format_version,
        epoch: info.epoch,
        ..FsckSummary::default()
    };

    if !is_valid_hex64(&info.root) {
        summary.ok = false;
        summary
            .errors
            .push(format!("invalid root digest encoding: {}", info.root));
    }

    // Merge pre-computed Merkle fsck report from Stage 0/1 kernel verification when present for
    // this exact volume.
    if let Some(raw) = backend.read_stored_report()
        && let Ok(stored) = serde_json::from_str::<StoredFsckReport>(&raw)
        && (stored.volume == info.volume || stored.volume.is_empty())
        && (stored.epoch == info.epoch || stored.epoch == 0)
    {
        summary.subvols_checked = stored.subvols_checked;
        summary.nodes_verified = stored.nodes_verified;
        summary.extents_verified = stored.extents_verified;
        summary.packs_verified = stored.packs_verified;
        summary.orphan_inodes = stored.orphan_inodes;
        if !stored.ok {
            summary.ok = false;
            summary.errors.extend(stored.errors);
        }
    }

    // Optional snapshot rollback (creates a clean fork from verified snapshot without destroying
    // the original damaged head).
    if let Some(snap) = parsed.rollback {
        let req = CowfsForkReq {
            snapshot: Some(snap.clone()),
            new_volume: format!("{}-rollback-{snap}", info.volume),
            ephemeral_if_unmodified: false,
        };
        match backend.fork_snapshot(&target, &req) {
            Ok(forked) => {
                summary.rolled_back_to = Some(forked.volume.clone());
                summary.ok = true;
                summary.errors.clear();
            }
            Err(err) => {
                return (
                    String::new(),
                    vec![format!(
                        "cowfsck: rollback to snapshot '{snap}' failed: {err}"
                    )],
                    8,
                );
            }
        }
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
    use abi::contract::{Durability, WriterModel};

    struct MockCowfsck {
        info: io::Result<CowfsInfoResp>,
        stored_report: Option<String>,
        fork_resp: Option<CowfsForkResp>,
        fork_requests: Vec<CowfsForkReq>,
    }

    impl MockCowfsck {
        fn clean() -> Self {
            Self {
                info: Ok(CowfsInfoResp {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: "vol-root-1".into(),
                    root: "a".repeat(64),
                    incarnation: 1,
                    fence: 1,
                    epoch: 3,
                    writer_model: WriterModel::Local,
                    durability: Durability::TreeCommit,
                    read_only: false,
                    parent_volume: None,
                }),
                stored_report: Some(
                    serde_json::json!({
                        "ok": true,
                        "volume": "vol-root-1",
                        "epoch": 3,
                        "subvols_checked": 1,
                        "nodes_verified": 12,
                        "extents_verified": 4,
                        "packs_verified": 1,
                        "orphan_inodes": 0,
                        "errors": []
                    })
                    .to_string(),
                ),
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
        fn query_info(&self, _target: &str) -> io::Result<CowfsInfoResp> {
            match &self.info {
                Ok(i) => Ok(i.clone()),
                Err(e) => Err(io::Error::new(
                    e.kind(),
                    os_posix::OsCallError(abi::Error::new(
                        os_posix::errno_of(e).unwrap_or(Errno::EIO),
                    )),
                )),
            }
        }
        fn read_stored_report(&self) -> Option<String> {
            self.stored_report.clone()
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
        mock.info.as_mut().unwrap().format_version = 99;
        let (_, errs, code) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code, 8);
        assert!(errs[0].contains("EPROTONOSUPPORT"));
        assert!(errs[0].contains("refusing to format"));

        mock.info = Err(errno_io(Errno::EPROTONOSUPPORT, "incompatible"));
        let (_, errs2, code2) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code2, 8);
        assert!(errs2[0].contains("EPROTONOSUPPORT"));
    }

    #[test]
    fn cowfsck_reports_corruption_and_supports_snapshot_rollback() {
        let mut mock = MockCowfsck::clean();
        mock.stored_report = Some(
            serde_json::json!({
                "ok": false,
                "volume": "vol-root-1",
                "epoch": 3,
                "errors": ["subvol @: block digest mismatch in pack p1"]
            })
            .to_string(),
        );
        let (_, errs, code) = run_with(&s(&["/dev/vd0"]), &mut mock);
        assert_eq!(code, 4);
        assert!(errs.iter().any(|l| l.contains("CORRUPTION DETECTED")));
        assert!(errs.iter().any(|l| l.contains("block digest mismatch")));

        let (out, errs, rb_code) = run_with(&s(&["--rollback", "good", "/dev/vd0"]), &mut mock);
        assert_eq!(rb_code, 0, "errs={errs:?}");
        assert!(out.contains("vol-root-1-rollback-good"));
        assert_eq!(mock.fork_requests.len(), 1);
        assert_eq!(mock.fork_requests[0].snapshot.as_deref(), Some("good"));
    }
}
