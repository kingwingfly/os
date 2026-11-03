//! /dev, after Linux (owner's design, 2026-10-29): a device is a character device, a node of
//! its own (`Node::rdev` names its driver), owned by the account that made it (mknod), with
//! the mode a file gets (less the umask) and the ACL its maker gives it (setfacl). Who may read
//! it (follow a presentation, hear a sound) or write it (turn the slides, speak) is its mode's
//! and ACL's to say, as for any file; its owner or root changes them (chmod, setfacl) and
//! removes it (rm), which hangs it up. What a device does is its driver's, as Linux's
//! `file_operations` are: /dev/present's (`present`), slides others follow and speak in;
//! /dev/snd's (`snd`), a live sound others hear (Cloudflare Realtime, `realtime`).
//!
//! Each browser is a session (auth::sid); signed out, all are guest, and told apart by their
//! sessions. As Linux passes an open file to another process, a presenter lets a guest speak
//! by passing a descriptor that writes the presentation to the guest's session (present.rs);
//! an account, by an ACL entry.
pub mod present;
pub mod realtime;
pub mod snd;

use crate::auth;
use crate::db::{Db, Device, Told};
use abi::{Errno, Error, Opened};
use kernel::Process;
use serde_json::{Value, json};
use terminal_worker_core::devices::device_path;
pub use terminal_worker_core::devices::{PRESENT, SOUND};
use terminal_worker_core::{parent, permissions::*};

type Result<T> = std::result::Result<T, Error>;

/// How long a presentation lasts after its last turn, in seconds, unless stopped before.
pub const PRESENT_TTL: u64 = 12 * 60 * 60;
/// How long a live sound lasts unkept by the descriptor that sends it (sound.mjs keeps it
/// every half minute), or unsent once made.
pub const SOUND_IDLE: u64 = 2 * 60;
/// How many live sounds an account may send at once: each is a Realtime session.
pub const SOUNDS_MAX: usize = 3;

/// The driver of the devices of the directory `directory`.
pub fn driver(directory: &str) -> Option<&'static str> {
    match directory {
        PRESENT => Some("present"),
        SOUND => Some("snd"),
        _ => None,
    }
}

/// Make /dev and its directories, root's, where they are not: they are there from the start
/// (store.rs), and made again if removed.
pub fn ensure(db: &mut Db) {
    for directory in ["/dev", PRESENT, SOUND] {
        if db.node(directory).is_none() {
            db.set_node(directory, &Node::directory(0, 0, 0o755));
        }
    }
}

/// mknod(2) of a character device of the driver `rdev` at `path`, as `process`: in the
/// driver's directory, by an account signed in, as the name is free or the caller's (whose
/// device of that name is replaced, its followers following the new one). It is the caller's,
/// with `mode` less the umask, as a file is made.
pub fn mknod(db: &mut Db, process: &Process, path: &str, mode: u16, rdev: &str) -> Result<()> {
    let who = &process.cred;
    let directory = parent(path);
    if driver(directory) != Some(rdev) {
        return Err(Error::because(
            Errno::EPERM,
            format!("{path}: {rdev} devices are made in their driver's directory"),
        ));
    }
    let name = path.rsplit('/').next().unwrap_or_default();
    if device_path(directory, name).ok().as_deref() != Some(path) {
        return Err(Error::because(
            Errno::EINVAL,
            format!("{path}: Invalid device name"),
        ));
    }
    if who.id == GUEST {
        return Err(Error::because(
            Errno::EPERM,
            if rdev == "present" {
                "Permission denied: sign in to present; guest is everyone signed out, who could all turn your slides"
            } else {
                "Permission denied: sign in to send live sound; guest is everyone signed out"
            },
        ));
    }
    match (db.device(path), db.node(path)) {
        (Some(other), _)
            if other.owner != who.id && who.id != 0 && db.user_by_id(other.owner).is_some() =>
        {
            return Err(Error::because(
                Errno::EBUSY,
                format!(
                    "{path}: Device or resource busy: it is another account's; name yours with -n"
                ),
            ));
        }
        (None, Some(_)) => return Err(Errno::EEXIST.into()),
        _ => {}
    }
    if rdev == "snd"
        && db
            .sounds_of(who.id)
            .into_iter()
            .filter(|other| other != path)
            .count()
            >= SOUNDS_MAX
    {
        return Err(Error::because(
            Errno::EBUSY,
            format!("an account sends at most {SOUNDS_MAX} live sounds at once; stop one first"),
        ));
    }
    // One of the account's of that name is replaced: its followers follow the new one.
    if db.device(path).is_some() {
        db.replaced_device(path);
        hangup(db, path, false);
    }
    ensure(db);
    let dir = db.node(directory).ok_or(Errno::ENOENT)?;
    let mut node = created(who, &dir, mode & 0o777, false, process.umask);
    node.rdev = Some(rdev.to_string());
    db.set_node(path, &node);
    db.set_device(
        &Device {
            name: path.to_string(),
            owner: who.id,
            path: String::new(),
            media: None,
        },
        auth::now(),
    );
    let lasts = if rdev == "snd" {
        SOUND_IDLE
    } else {
        PRESENT_TTL
    };
    db.set_expiry("device", path, auth::now() + lasts);
    Ok(())
}

/// open(2) of the device at `path`, whose node `kernel::open` found the caller may read or
/// write, as `flags` ask: a descriptor of the session `sid`.
pub fn open(db: &mut Db, sid: &str, path: &str, flags: u32) -> Result<Opened> {
    if db.device(path).is_none() {
        return Err(Errno::ENXIO.into());
    }
    let now = auth::now();
    let fd = db.add_device_fd(sid, path, flags, now);
    db.set_expiry("fd", &crate::db::fd_key(sid, fd), now + crate::fds::IDLE);
    Ok(Opened {
        fd,
        ..Opened::default()
    })
}

/// What a descriptor of the device `device` ending (closed, or its session gone) ends: the
/// sound it sends, or the voice it speaks with.
pub fn closed(db: &mut Db, sid: &str, fd: u32, device: &str) {
    match db.node(device).and_then(|node| node.rdev) {
        Some(rdev) if rdev == "snd" => snd::closed(db, sid, fd, device),
        Some(_) => present::closed(db, sid, fd, device),
        None => {}
    }
}

/// A descriptor of the device `device` is kept: what it sends lasts.
pub fn leased(db: &mut Db, sid: &str, fd: u32, device: &str) {
    for voice in db.devices_in(SOUND) {
        if sent_by(&voice, sid, fd)
            || (voice.name == device && writer(db, device) == Some((sid.to_string(), fd)))
        {
            db.set_expiry("device", &voice.name, auth::now() + SOUND_IDLE);
        }
    }
}

/// Whether the sound `device` was sent through the descriptor `fd` of `sid`.
pub fn sent_by(device: &Device, sid: &str, fd: u32) -> bool {
    let media: Value = device
        .media
        .as_deref()
        .and_then(|media| serde_json::from_str(media).ok())
        .unwrap_or_default();
    media["sid"] == sid && media["fd"] == fd
}

/// The descriptor that sends the sound `device`, if one does.
pub fn writer(db: &Db, device: &str) -> Option<(String, u32)> {
    let media: Value = db
        .device(device)?
        .media
        .as_deref()
        .and_then(|media| serde_json::from_str(media).ok())?;
    Some((
        media["sid"].as_str()?.to_string(),
        media["fd"].as_u64()? as u32,
    ))
}

/// What unlinking the device at `path` does: as its account or root, it hangs it up; another
/// may not (EACCES, or EPERM for an account signed in). None for no device.
pub fn unlink(db: &mut Db, who: &Identity, path: &str) -> Option<Result<()>> {
    driver(parent(path))?;
    let device = db.device(path)?;
    if device.owner != who.id && who.id != 0 {
        return Some(Err(Error::because(
            if who.id == GUEST {
                Errno::EACCES
            } else {
                Errno::EPERM
            },
            "Permission denied: it is another account's",
        )));
    }
    hangup(db, path, true);
    Some(Ok(()))
}

/// Hang up the device `name`: its driver lets go of what it keeps, its node and its
/// descriptors go, and its followers, and its account's pages, hear so (`told`).
pub fn hangup(db: &mut Db, name: &str, told: bool) {
    let rdev = db.node(name).and_then(|node| node.rdev);
    match rdev.as_deref() {
        Some("snd") => snd::hangup(db, name),
        Some(_) => present::hangup(db, name),
        None => {}
    }
    if told {
        db.delete_device(name);
    } else {
        db.forget_device(name);
    }
    if db.node(name).is_some_and(|node| node.is_device()) {
        db.delete_node(name);
    }
    db.revoke_device(name);
    db.clear_expiry("device", name);
}

/// The device `name`, if `who` may follow or hear it: it is there, a device, and `who` may
/// search its directory and read it.
pub fn followed(db: &Db, who: &Identity, name: &str) -> std::result::Result<Device, String> {
    let missing = || format!("{name}: No such device; it does not exist");
    let device = db.device(name).ok_or_else(missing)?;
    let node = db.node(name).filter(Node::is_device).ok_or_else(missing)?;
    kernel::namei(db, who, name, false).map_err(|error| format!("{name}: {error}"))?;
    if !kernel::permission(who, &node, READ) {
        return Err(format!("{name}: Permission denied"));
    }
    Ok(device)
}

/// What a device is, as an opaque word that changes exactly when it is replaced: its account,
/// the file it shows, its sound. A page compares the one it followed with the one it is told on
/// following again, to know whether what it shows is still that device's.
pub fn version(device: &Device) -> String {
    use sha2::{Digest, Sha256};
    let what = format!(
        "{}\n{}\n{}",
        device.owner,
        device.path,
        device.media.as_deref().unwrap_or_default()
    );
    Sha256::digest(what.as_bytes())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What reading the device at `path` tells `who` of session `sid`, who may read it: its
/// driver's state, as the page takes it, and cat shows it.
pub fn read(db: &Db, who: &Identity, sid: Option<&str>, path: &str) -> Option<Value> {
    let device = db.device(path)?;
    let node = db.node(path)?;
    Some(match node.rdev.as_deref()? {
        "snd" => snd::read(db, &device),
        _ => present::read(db, who, sid, &device, &node),
    })
}

/// The name a session goes by to a presenter: its account's, `guest` for one signed out.
pub fn name_of(db: &Db, who: &Identity) -> String {
    db.username(who.id)
}

/// Have the pages of the account `uid` hear `message`.
pub fn tell_account(db: &mut Db, uid: u32, message: Value) {
    db.tell(Told::Account(uid), message);
}

/// Have the pages of the session `sid` hear `message`.
pub fn tell_session(db: &mut Db, sid: &str, message: Value) {
    db.tell(Told::Session(sid.to_string()), message);
}

/// A request a driver does not take.
pub fn not_for(request: u32) -> Error {
    Error::because(
        Errno::ENOTTY,
        format!("request {request:#x} is not this device's"),
    )
}

/// What a request `ioctl` on `fd` asks of a device, and which: the device and the descriptor.
pub struct Request {
    pub device: Device,
    pub node: Node,
    pub sid: String,
    pub fd: u32,
    pub flags: u32,
}
impl Request {
    pub fn writes(&self) -> bool {
        self.flags & abi::O_ACCMODE != abi::O_RDONLY
    }
}

/// The device the descriptor `fd` of `sid` opens, still there.
pub fn request(db: &Db, sid: &str, fd: u32) -> Result<Option<Request>> {
    let Some(found) = db.fd(sid, fd) else {
        return Err(Errno::EBADF.into());
    };
    let Some(name) = found.device else {
        if found.file.is_none() && found.path.starts_with("/dev/") {
            return Err(Error::because(Errno::EBADF, "the device was hung up"));
        }
        return Ok(None);
    };
    let device = db.device(&name).ok_or(Errno::ENXIO)?;
    let node = db.node(&name).ok_or(Errno::ENXIO)?;
    Ok(Some(Request {
        device,
        node,
        sid: sid.to_string(),
        fd,
        flags: found.flags,
    }))
}

/// A driver's request that needs no network: answered within one transaction.
pub fn ioctl(
    db: &mut Db,
    process: &Process,
    request: Request,
    op: u32,
    arg: Value,
) -> Result<Value> {
    match request.node.rdev.as_deref() {
        Some("present") => present::ioctl(db, process, request, op, arg),
        _ => Err(not_for(op)),
    }
}

/// Whether `op` is a request that asks Realtime, outside a transaction (sys.rs).
pub fn networked(op: u32) -> bool {
    matches!(
        op,
        abi::PRESENT_SPEAK | abi::SND_PUBLISH | abi::SND_LISTEN | abi::SND_ANSWER
    )
}

/// What a device says when there is nothing more to it.
pub fn ok() -> Value {
    json!({})
}
