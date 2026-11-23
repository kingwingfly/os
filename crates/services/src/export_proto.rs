//! One osfs v2 stream session. Socket owners feed complete frames, dispatch
//! ready calls and tick the lease even if the client sends no more bytes.
use abi::Errno;
use abi::export_ctl::*;
pub use abi::export_ctl::{decode_frame, encode_frame};
use abi::fs::{Access, Entry, Handle, OpenRef};
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

type Result<T> = std::result::Result<T, Errno>;

/// Each instance owns one admitted identity and one pinned directory. Both
/// operands of a two-directory operation must resolve from that pin. Methods
/// operate under the scoped credential; no call accepts a UID from the wire.
pub trait ExportFsOps {
    fn root(&self) -> Handle;
    fn at(&mut self, base: &Handle, call: AtOp) -> Result<OsfsResponse>;
    /// Revalidate the retained inode beneath the pin and its live ACL as part
    /// of the operation. Release is unconditional, including after expiry.
    fn on_open(&mut self, open: &OpenRef, call: FdOp) -> Result<OsfsResponse>;
}

pub struct ExportCore<F: ExportFsOps> {
    fs: F,
    rule: ExportRule,
    expires_at: u64,
    revoked: Rc<Cell<bool>>,
    closed: Option<Errno>,
    last_request: Option<u64>,
    pending: VecDeque<(u64, OsfsRequest)>,
    handles: BTreeMap<u64, OpenRef>,
}

impl<F: ExportFsOps> ExportCore<F> {
    pub fn new(fs: F, rule: ExportRule, expires_at: u64, revoked: Rc<Cell<bool>>) -> Self {
        Self {
            fs,
            rule,
            expires_at,
            revoked,
            closed: None,
            last_request: None,
            pending: VecDeque::new(),
            handles: BTreeMap::new(),
        }
    }
    pub fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Called on EOF, daemon shutdown, revocation, malformed input or timeout.
    pub fn close(&mut self, errno: Errno) -> OsfsFrame {
        let errno = *self.closed.get_or_insert(errno);
        self.pending.clear();
        for (_, open) in std::mem::take(&mut self.handles) {
            let _ = self.fs.on_open(&open, FdOp::Release {});
        }
        OsfsFrame::Closed { errno }
    }
    pub fn tick(&mut self, now: u64) -> Option<OsfsFrame> {
        if let Some(errno) = self.closed {
            return Some(OsfsFrame::Closed { errno });
        }
        if self.revoked.get() {
            return Some(self.close(Errno::EACCES));
        }
        if now >= self.expires_at {
            return Some(self.close(Errno::ESTALE));
        }
        None
    }
    pub fn receive(&mut self, frame: OsfsFrame, now: u64) -> Vec<OsfsFrame> {
        if let Some(end) = self.tick(now) {
            return vec![end];
        }
        let OsfsFrame::Request {
            request_id,
            request,
        } = frame
        else {
            return vec![self.close(Errno::EIO)];
        };
        if self.last_request.is_some_and(|last| request_id <= last) {
            return vec![self.close(Errno::EIO)];
        }
        self.last_request = Some(request_id);
        if let OsfsRequest::Cancel { target_id } = request {
            if let Some(idx) = self.pending.iter().position(|(id, _)| *id == target_id) {
                self.pending.remove(idx);
                return vec![
                    reply(target_id, Err(Errno::ECANCELED)),
                    reply(request_id, Ok(OsfsResponse::Unit)),
                ];
            }
            return vec![reply(request_id, Err(Errno::ENOENT))];
        }
        if self.pending.len() == OSFS_MAX_INFLIGHT {
            return vec![reply(request_id, Err(Errno::EAGAIN))];
        }
        self.pending.push_back((request_id, request));
        Vec::new()
    }
    /// Visit each queued call once. A contended blocking lock stays cancellable
    /// while unrelated calls (including unlock) continue on this connection.
    pub fn dispatch(&mut self, now: u64) -> Vec<OsfsFrame> {
        if let Some(end) = self.tick(now) {
            return vec![end];
        }
        let mut replies = Vec::new();
        for _ in 0..self.pending.len() {
            let (id, req) = self.pending.pop_front().expect("queued request");
            let waits = matches!(
                req,
                OsfsRequest::Fd {
                    call: FdOp::Lock { wait: true, .. },
                    ..
                }
            );
            let result = self.execute(id, &req);
            if waits && result == Err(Errno::EAGAIN) {
                self.pending.push_back((id, req));
            } else {
                replies.push(reply(id, result));
            }
        }
        replies
    }
    fn execute(&mut self, id: u64, req: &OsfsRequest) -> Result<OsfsResponse> {
        if !self.rule.writable && req.is_mutation() {
            return Err(Errno::EROFS);
        }
        let mut response = match req {
            OsfsRequest::Root {} => {
                let base = self.fs.root();
                self.fs.at(
                    &base,
                    AtOp::Access {
                        mask: abi::R_OK | abi::X_OK,
                    },
                )?;
                let OsfsResponse::Metadata(metadata) = self.fs.at(&base, AtOp::Metadata {})? else {
                    return Err(Errno::EIO);
                };
                OsfsResponse::Root {
                    entry: Entry {
                        handle: base,
                        metadata,
                    },
                    rule: self.rule,
                }
            }
            OsfsRequest::At { base, call } => {
                relative_path(&base.proof)?;
                validate_at(call)?;
                match call {
                    AtOp::Open { options } | AtOp::Create { options, .. } => {
                        let access = options.access()?;
                        if access == Access::Exec && !self.rule.execute {
                            return Err(Errno::EACCES);
                        }
                        if access.writes() && !self.rule.writable {
                            return Err(Errno::EROFS);
                        }
                        if self.handles.len() >= OSFS_MAX_HANDLES {
                            return Err(Errno::EMFILE);
                        }
                    }
                    AtOp::Access { mask } if mask & abi::W_OK != 0 && !self.rule.writable => {
                        return Err(Errno::EROFS);
                    }
                    AtOp::Access { mask } if mask & abi::X_OK != 0 && !self.rule.execute => {
                        if let OsfsResponse::Metadata(meta) = self.fs.at(base, AtOp::Metadata {})?
                            && meta.is_file()
                        {
                            return Err(Errno::EACCES);
                        }
                    }
                    _ => {}
                }
                self.fs.at(base, call.clone())?
            }
            OsfsRequest::Fd { handle, call } => {
                let open = self.handles.get(handle).ok_or(Errno::EBADF)?;
                match call {
                    FdOp::Read { count, .. } if *count > OSFS_CHUNK => return Err(Errno::E2BIG),
                    FdOp::Write { data, .. } if data.0.len() > OSFS_CHUNK => {
                        return Err(Errno::E2BIG);
                    }
                    _ => {}
                }
                let result = self.fs.on_open(open, call.clone());
                if matches!(call, FdOp::Release {}) {
                    self.handles.remove(handle);
                } else if matches!(result, Err(Errno::EACCES | Errno::ESTALE)) {
                    let _ = self.fs.on_open(open, FdOp::Release {});
                    self.handles.remove(handle);
                }
                result?
            }
            OsfsRequest::Cancel { .. } => return Err(Errno::EINVAL),
        };
        match &mut response {
            OsfsResponse::Opened { entry, open } => {
                self.handles.insert(id, open.clone());
                open.id = id;
                self.rule.mask(&mut entry.metadata);
            }
            OsfsResponse::Root { entry, .. }
            | OsfsResponse::Entry(entry)
            | OsfsResponse::Parent(Some((entry, _))) => self.rule.mask(&mut entry.metadata),
            OsfsResponse::Walked(walked) => {
                for entry in &mut walked.entries {
                    self.rule.mask(&mut entry.metadata);
                }
            }
            OsfsResponse::Metadata(meta) => self.rule.mask(meta),
            OsfsResponse::Link(target) => relative_path(target).map_err(|_| Errno::ELOOP)?,
            _ => {}
        }
        Ok(response)
    }
}
impl<F: ExportFsOps> Drop for ExportCore<F> {
    fn drop(&mut self) {
        self.close(Errno::ENOTCONN);
    }
}
fn reply(request_id: u64, result: Result<OsfsResponse>) -> OsfsFrame {
    OsfsFrame::Reply { request_id, result }
}
fn validate_at(op: &AtOp) -> Result<()> {
    match op {
        AtOp::Lookup { name }
        | AtOp::Create { name, .. }
        | AtOp::Mkdir { name, .. }
        | AtOp::Mknod { name, .. }
        | AtOp::Rmdir { name }
        | AtOp::Unlink { name }
        | AtOp::UnlinkIf { name, .. } => component(name),
        AtOp::Walk { names } => names.iter().try_for_each(|name| component(name)),
        AtOp::Symlink { name, target } => {
            component(name)?;
            relative_path(target)
        }
        AtOp::Link { name, target } => {
            component(name)?;
            relative_path(&target.proof)
        }
        AtOp::Rename {
            name, to_dir, to, ..
        } => {
            component(name)?;
            component(to)?;
            relative_path(&to_dir.proof)
        }
        AtOp::Access { mask } if mask & !7 != 0 => Err(Errno::EINVAL),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::fs::{FsId, NodeId};

    struct NoFs;
    impl ExportFsOps for NoFs {
        fn root(&self) -> Handle {
            Handle {
                fs: FsId("tree".into()),
                node: NodeId {
                    ino: 2,
                    generation: 1,
                },
                proof: String::new(),
            }
        }
        fn at(&mut self, _: &Handle, _: AtOp) -> Result<OsfsResponse> {
            Err(Errno::ENOENT)
        }
        fn on_open(&mut self, _: &OpenRef, _: FdOp) -> Result<OsfsResponse> {
            Err(Errno::EBADF)
        }
    }
    fn session() -> ExportCore<NoFs> {
        ExportCore::new(NoFs, ExportRule::default(), 100, Rc::new(Cell::new(false)))
    }
    fn request(id: u64, op: OsfsRequest) -> OsfsFrame {
        OsfsFrame::Request {
            request_id: id,
            request: op,
        }
    }

    #[test]
    fn window_full_cancel_before_execution_and_monotonicity() {
        let mut s = session();
        for id in 1..=4 {
            assert!(s.receive(request(id, OsfsRequest::Root {}), 1).is_empty());
        }
        assert_eq!(
            s.receive(request(5, OsfsRequest::Root {}), 1),
            [reply(5, Err(Errno::EAGAIN))]
        );
        assert_eq!(
            s.receive(request(6, OsfsRequest::Cancel { target_id: 2 }), 1),
            [
                reply(2, Err(Errno::ECANCELED)),
                reply(6, Ok(OsfsResponse::Unit))
            ]
        );
        assert!(s.receive(request(7, OsfsRequest::Root {}), 1).is_empty());
        assert_eq!(
            s.dispatch(1),
            [1, 3, 4, 7].map(|id| reply(id, Err(Errno::ENOENT)))
        );
        assert_eq!(
            s.receive(request(7, OsfsRequest::Root {}), 1),
            [OsfsFrame::Closed { errno: Errno::EIO }]
        );
        assert!(s.is_closed());
    }
    #[test]
    fn lease_and_revocation_precede_queued_work() {
        for (expire, errno) in [(true, Errno::ESTALE), (false, Errno::EACCES)] {
            let mut s = session();
            s.receive(request(1, OsfsRequest::Root {}), 99);
            s.revoked.set(!expire);
            assert_eq!(
                s.dispatch(if expire { 100 } else { 99 }),
                [OsfsFrame::Closed { errno }]
            );
            assert!(s.pending.is_empty());
        }
    }
    #[test]
    fn fragmented_and_coalesced_frames_exact_limit() {
        let a = request(1, OsfsRequest::Root {});
        let b = request(u64::MAX, OsfsRequest::Cancel { target_id: 1 });
        let bytes = [encode_frame(&a).unwrap(), encode_frame(&b).unwrap()].concat();
        for n in [1, 2, 3, 4, 23, bytes.len()] {
            let mut reader = FrameReader::default();
            let mut out: Vec<OsfsFrame> = vec![];
            for chunk in bytes.chunks(n) {
                reader
                    .feed(chunk, |f| {
                        out.push(f);
                        Ok(())
                    })
                    .unwrap();
            }
            assert_eq!(out, [a.clone(), b.clone()]);
        }
        let content = "x".repeat(OSFS_MAX_FRAME_BYTES - 2);
        let frame = encode_frame(&content).unwrap();
        assert_eq!(frame.len(), OSFS_MAX_FRAME_BYTES + 4);
        assert_eq!(decode_frame::<String>(&frame).unwrap(), content);
        assert_eq!(encode_frame(&(content + "x")), Err(Errno::E2BIG));
        assert_eq!(
            FrameReader::default().feed::<OsfsFrame>(&u32::MAX.to_be_bytes(), |_| Ok(())),
            Err(Errno::E2BIG)
        );
    }
    #[test]
    fn both_operands_and_symlink_targets_are_confined() {
        let mut s = session();
        for (i, name) in ["a/b", "/outside", "..", "a\0b", "a\\b"]
            .into_iter()
            .enumerate()
        {
            let req = OsfsRequest::At {
                base: s.fs.root(),
                call: AtOp::Lookup { name: name.into() },
            };
            s.receive(request(i as u64, req), 1);
            assert_eq!(s.dispatch(1), [reply(i as u64, Err(Errno::EACCES))]);
        }
        let mut other = s.fs.root();
        other.proof = "dir/../private".into();
        assert_eq!(
            validate_at(&AtOp::Rename {
                name: "a".into(),
                to_dir: other,
                to: "b".into(),
                flags: abi::fs::RenameFlags::empty()
            }),
            Err(Errno::EACCES)
        );
        assert_eq!(
            validate_at(&AtOp::Symlink {
                name: "link".into(),
                target: "/secret".into()
            }),
            Err(Errno::EACCES)
        );
    }
}
