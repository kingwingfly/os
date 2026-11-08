//! Remote execution lifetime and resource grants, independent of an accelerator's CLI or
//! operation parser. Registered drivers select work; executors receive bounded grants and
//! a credential snapshot. A placement label or task ID is never an I/O capability.
use crate::db::Db;
use crate::db::Job;
use abi::{Call, Errno, Error};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use terminal_worker_core::permissions::{Identity, Store};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WriteGrant {
    /// Directory which was authorized at submission.
    pub directory: String,
    pub inode: u64,
    /// A single output basename, or the directory's descendants for a tree operation.
    pub name: Option<String>,
}
impl WriteGrant {
    fn contains(&self, db: &Db, path: &str) -> bool {
        if !db
            .node(&self.directory)
            .is_some_and(|n| n.directory && n.ino == self.inode)
        {
            return false;
        }
        let root = self.directory.trim_end_matches('/');
        match &self.name {
            Some(name) => path == format!("{root}/{name}"),
            None => path == self.directory || path.starts_with(&format!("{root}/")),
        }
    }
}

/// Validate both lexical and physically resolved names before the same transaction performs
/// a call. Existing symlinks cannot expand a directory grant beyond its authorized subtree.
pub fn authorize(db: &Db, credential: &crate::creds::Credential, call: &Call) -> Result<(), Error> {
    let Some(id) = credential.job() else {
        return Ok(());
    };
    let task = db.device_task(&id).ok_or(Errno::EPERM)?;
    let grants: Vec<WriteGrant> = serde_json::from_str(&task.grants).map_err(|_| Errno::EIO)?;
    let check = |path: &str, follow: bool| -> Result<(), Error> {
        let real = kernel::namei(db, &credential.identity(), path, follow)?.path;
        if !grants
            .iter()
            .any(|grant| grant.contains(db, path) && grant.contains(db, &real))
        {
            return Err(Errno::EACCES.into());
        }
        Ok(())
    };
    match call {
        Call::Open { path, flags, .. } if flags & abi::O_ACCMODE != abi::O_RDONLY => {
            check(path, true)
        }
        Call::Lstat { path } | Call::Mkdir { path, .. } | Call::Unlink { path } => {
            check(path, false)
        }
        Call::Chmod { path, .. } => check(path, true),
        Call::Symlink { path, .. } => check(path, false),
        Call::Link { from, to, follow } => {
            check(from, *follow)?;
            check(to, false)
        }
        Call::Rename { from, to, .. } => {
            check(from, false)?;
            check(to, false)
        }
        Call::Fchmod { fd, .. } => {
            let found = db
                .fd(&credential.session(), fd.number())
                .ok_or(Errno::EBADF)?;
            if !found.writes() {
                return Err(Errno::EBADF.into());
            }
            check(&found.path, true)
        }
        Call::Readlink { path }
            if path
                .strip_prefix("/proc/self/fd/")
                .is_some_and(|n| n.parse::<u32>().is_ok()) =>
        {
            Ok(())
        }
        Call::Close { .. } | Call::Discard { .. } | Call::Pwrite { .. } => Ok(()),
        _ => Err(Errno::EPERM.into()),
    }
}

/// End a job: let go of the files it read, revoke its credentials, which closes what it had
/// open, and keep what it says.
pub fn finish(db: &mut Db, job: &str, state: &str) {
    if matches!(state, "cancelled" | "failed") {
        // Failure revokes writers without committing partial files, including when the
        // executor died before it could send its normal discard request.
        let owner = crate::creds::job_owner(job);
        let process = kernel::Process {
            cred: Identity::root(),
            umask: 0o022,
        };
        for fd in db.fds_of(&owner) {
            if fd.writes() {
                let _ = crate::fds::call(
                    db,
                    Some(&owner),
                    &process,
                    Some(&owner),
                    abi::Call::Discard { fd: fd.fd.into() },
                );
            }
        }
    }
    db.set_job(job, crate::db::JobColumn::State, Some(state));
    db.set_job(job, crate::db::JobColumn::Question, None);
    db.unpin(job);
    db.revoke_job(job);
    db.clear_expiry("job", job);
}

/// The process calls (owner's design, 2026-10-29): a job is a process of the account signed in
/// (`owner`), run as `process` (root under sudo).
pub fn call(
    db: &mut Db,
    owner: u32,
    process: &kernel::Process,
    call: abi::Call,
) -> std::result::Result<Value, abi::Error> {
    use crate::db::JobColumn;
    use abi::{Call, Errno, Error};
    // Its owner's, or root's, to see and signal.
    let theirs = |db: &Db, pid: &str| -> std::result::Result<Job, Error> {
        let job = db.job(pid).ok_or(Errno::ESRCH)?;
        if job.owner != owner && process.cred.id != 0 {
            return Err(Errno::EPERM.into());
        }
        Ok(job)
    };
    match call {
        Call::Kill { pid, .. } => {
            let job = theirs(db, &pid)?;
            if !job.finished() {
                db.set_job(&pid, JobColumn::State, Some("cancelling"));
            }
            Ok(json!({ "pid": pid, "state": db.job(&pid).map(|job| job.state) }))
        }
        Call::Wait { pid, .. } => {
            let job = theirs(db, &pid)?;
            if !job.finished() {
                return Err(Errno::EAGAIN.into());
            }
            Ok(
                json!({"pid": pid, "state": "zombie", "status": if job.state == "done" && serde_json::from_str::<Value>(&job.progress).ok().and_then(|p| p["errors"].as_u64()).unwrap_or(0) == 0 { 0 } else { 256 }}),
            )
        }
        _ => Err(Errno::ENOSYS.into()),
    }
}
