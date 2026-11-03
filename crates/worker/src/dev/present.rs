//! /dev/present's driver: a presentation, slides others follow. Its maker shows a file in it
//! (`PRESENT_SHOW`); whoever may read it follows, turned as its account turns the file (the
//! places store.rs relays), and whoever may write it turns it too. A listener asks to speak
//! (`PRESENT_ASK`, on a descriptor that reads it); its owner answers (`PRESENT_ANSWER`):
//! allowed, an account gets an ACL entry that lets it write the presentation, and a guest's
//! session, as each browser signed out is, gets a descriptor that writes it, passed to it as
//! Linux passes open files. Through such a descriptor the listener speaks (`PRESENT_SPEAK`): a
//! voice, /dev/snd/NAME-SPEAKER, its presenter's, which whoever follows the presentation hears,
//! until the descriptor closes or its presenter removes the voice, which takes the leave to
//! speak back.
use super::{
    Request, SOUND, SOUND_IDLE, ok, realtime, sent_by, tell_account, tell_session, version,
};
use crate::auth;
use crate::db::{Ask, Db, Device};
use abi::{Errno, Error, O_WRONLY};
use kernel::Process;
use serde_json::{Value, json};
use terminal_worker_core::acl::{self, Perms, Spec, Tag};
use terminal_worker_core::devices::device_path;
use terminal_worker_core::{kind, permissions::*};

type Result<T> = std::result::Result<T, Error>;

/// How many listeners may speak in a presentation at once.
pub const VOICES_MAX: usize = 2;

/// What reading a presentation tells `who`: the file it shows, of what kind, whose it is,
/// whether `who` turns it too (may write it), where it is, its sound and the voices of the
/// listeners speaking in it (those `who` may hear); to its owner, who asks to speak; to the
/// session `sid`, its own ask.
pub fn read(db: &Db, who: &Identity, sid: Option<&str>, device: &Device, node: &Node) -> Value {
    let voices: Vec<Value> = db
        .voices_for(&device.name)
        .iter()
        .filter(|voice| super::followed(db, who, &voice.name).is_ok())
        .filter_map(voice)
        .collect();
    let owner = who.id == device.owner || who.id == 0;
    let asks: Vec<Value> = db
        .asks(&device.name)
        .into_iter()
        .filter(|_| owner)
        .map(|ask| json!({ "presentation": device.name, "id": ask.id, "name": ask.name }))
        .collect();
    let asking = sid.and_then(|sid| {
        db.asks(&device.name)
            .into_iter()
            .find(|ask| ask.sid == sid)
            .map(|ask| ask.id)
    });
    json!({
        "device": device.name, "path": device.path, "kind": kind(&device.path),
        "owner": db.username(device.owner), "controller": turns(who, device, node),
        "place": db.place(device.owner, &device.path), "sound": sound(db, who, device),
        "voices": voices, "asks": asks, "asking": asking, "version": version(device),
    })
}

/// Whether `who` turns the presentation `device`: its account, and whoever its mode or ACL let
/// write it. Root may write any device, but turns only what it presents or is let turn: one
/// following another's talk turns nothing of it by being root.
pub fn turns(who: &Identity, device: &Device, node: &Node) -> bool {
    who.id == device.owner || who.id != 0 && who.allows(node, WRITE)
}

/// What a voice is said to be, to whoever hears of it: who speaks, in which presentation.
pub fn voice(device: &Device) -> Option<Value> {
    let media: Value = serde_json::from_str(device.media.as_deref()?).ok()?;
    let presentation = media["for"].as_str()?;
    Some(json!({
        "device": device.name, "presentation": presentation, "speaker": media["speaker"],
        "ask": media["ask"], "version": version(device),
    }))
}

/// The live sound the listeners of the presentation hear with it, of those `who` may hear: its
/// presenter's of the same name, or else the latest it started (owner's choice, 2026-10-28).
pub fn sound(db: &Db, who: &Identity, presentation: &Device) -> Option<String> {
    let base = presentation.name.rsplit('/').next().unwrap_or_default();
    let same = format!("{SOUND}/{base}");
    let mut sounds = db.sounds_by(presentation.owner);
    sounds.sort_by_key(|sound| sound.name != same);
    sounds
        .into_iter()
        .find(|sound| super::followed(db, who, &sound.name).is_ok())
        .map(|sound| sound.name)
}

pub fn ioctl(
    db: &mut Db,
    process: &Process,
    request: Request,
    op: u32,
    arg: Value,
) -> Result<Value> {
    let who = &process.cred;
    match op {
        abi::PRESENT_SHOW => show(db, who, &request, arg["path"].as_str().unwrap_or_default()),
        abi::PRESENT_ASK if arg["withdraw"] == true => {
            withdraw(db, &request.device.name, &request.sid);
            Ok(ok())
        }
        abi::PRESENT_ASK => ask(db, who, &request),
        abi::PRESENT_ANSWER => answer(
            db,
            who,
            &request,
            arg["id"].as_str().unwrap_or_default(),
            arg["allow"] == true,
        ),
        _ => Err(super::not_for(op)),
    }
}

/// Show the file at `path` in the presentation, as its account (or root), through a descriptor
/// that writes it: a deck, Markdown or a PDF the account may read. From where the account showed
/// it last, or its start; its followers follow it again if it showed another.
fn show(db: &mut Db, who: &Identity, request: &Request, path: &str) -> Result<Value> {
    if !request.writes() {
        return Err(Errno::EBADF.into());
    }
    let mut device = request.device.clone();
    if device.owner != who.id && who.id != 0 {
        return Err(Error::because(
            Errno::EPERM,
            "only the presentation's account shows a file in it",
        ));
    }
    if !matches!(kind(path), "slides" | "markdown" | "pdf") {
        return Err(Error::because(
            Errno::EINVAL,
            format!("{path}: present shows slides (*.slides.md or Markdown) and PDFs"),
        ));
    }
    let name = kernel::namei(db, who, path, true)?;
    let node = name.node.ok_or(Errno::ENOENT)?;
    if node.directory {
        return Err(Errno::EISDIR.into());
    }
    if !kernel::permission(who, &node, READ) {
        return Err(Errno::EACCES.into());
    }
    // Followers of what it showed before, or of the one it replaced, follow it again.
    if device.path != path {
        db.replaced_device(&device.name);
    }
    device.path = path.to_string();
    db.set_device(&device, auth::now());
    let place = db.place(device.owner, path).unwrap_or((0, 0));
    db.set_place(device.owner, path, place);
    Ok(json!({ "device": device.name, "place": place, "version": version(&device) }))
}

/// A listener asks to speak, through a descriptor that reads the presentation: its owner's pages
/// hear so, until it is answered, withdrawn, or its session's pages go (store.rs).
fn ask(db: &mut Db, who: &Identity, request: &Request) -> Result<Value> {
    let device = &request.device;
    if device.owner == who.id && who.id != GUEST {
        return Err(Error::because(Errno::EINVAL, "you present it"));
    }
    withdraw(db, &device.name, &request.sid);
    let id = auth::random_token()[..16].to_string();
    let name = super::name_of(db, who);
    db.set_ask(&Ask {
        device: device.name.clone(),
        sid: request.sid.clone(),
        id: id.clone(),
        uid: who.id,
        name: name.clone(),
    });
    tell_account(
        db,
        device.owner,
        json!({ "asking": { "presentation": device.name, "id": id, "name": name } }),
    );
    Ok(json!({ "presentation": device.name, "id": id }))
}

/// The session `sid` asks to speak in the presentation `device` no longer.
pub fn withdraw(db: &mut Db, device: &str, sid: &str) {
    let Some(asked) = db.asks(device).into_iter().find(|ask| ask.sid == sid) else {
        return;
    };
    db.delete_ask(device, sid);
    if let Some(presentation) = db.device(device) {
        tell_account(
            db,
            presentation.owner,
            json!({ "asking": { "id": asked.id, "gone": true } }),
        );
    }
}

/// The presentation's owner (or root) answers the ask `id`: allowed, the listener may write the
/// presentation, and so speak in it: an account by an ACL entry, a guest's session by a
/// descriptor passed to it. Either way its pages hear the answer.
fn answer(db: &mut Db, who: &Identity, request: &Request, id: &str, allow: bool) -> Result<Value> {
    let device = &request.device;
    if device.owner != who.id && who.id != 0 {
        return Err(Error::because(
            Errno::EPERM,
            "Permission denied: it is another account's",
        ));
    }
    let Some(asked) = db.asks(&device.name).into_iter().find(|ask| ask.id == id) else {
        return Err(Error::because(Errno::ENOENT, "the ask was withdrawn"));
    };
    db.delete_ask(&device.name, &asked.sid);
    tell_account(
        db,
        device.owner,
        json!({ "asking": { "id": id, "gone": true, "allowed": allow } }),
    );
    if !allow {
        tell_session(
            db,
            &asked.sid,
            json!({ "denied": { "presentation": device.name, "id": id } }),
        );
        return Ok(ok());
    }
    let mut granted = json!({ "presentation": device.name, "id": id });
    if asked.uid == GUEST {
        let fd = db.add_device_fd(&asked.sid, &device.name, O_WRONLY, auth::now());
        db.set_expiry(
            "fd",
            &crate::db::fd_key(&asked.sid, fd),
            auth::now() + crate::fds::IDLE,
        );
        granted["fd"] = json!(fd);
    } else {
        let mut node = request.node.clone();
        let mut entries = node.entries();
        let spec = Spec {
            default: false,
            tag: Tag::User(Some(asked.uid)),
            perms: Some(Perms {
                bits: READ | WRITE,
                conditional_exec: false,
            }),
        };
        acl::modify(&mut entries, &[&spec], false, false);
        node.set_entries(&entries);
        db.set_node(&device.name, &node);
    }
    tell_session(db, &asked.sid, json!({ "granted": granted }));
    Ok(ok())
}

/// The descriptor `fd` of `sid` closed: the voice it spoke with ends.
pub fn closed(db: &mut Db, sid: &str, fd: u32, device: &str) {
    for voice in db.voices_for(device) {
        if sent_by(&voice, sid, fd) {
            super::hangup(db, &voice.name, true);
        }
    }
}

/// A presentation hung up: its voices end, and its asks go.
pub fn hangup(db: &mut Db, name: &str) {
    for voice in db.voices_for(name) {
        super::hangup(db, &voice.name, true);
    }
    db.delete_asks_of(name);
}

/// A voice of the presentation `presentation` ended, the speaker its media names: they may
/// speak no more without asking again; an account loses its ACL entry, a guest's session the
/// descriptors passed to it.
pub fn silenced(db: &mut Db, presentation: &str, media: &Value) {
    let Some(sid) = media["sid"].as_str() else {
        return;
    };
    let uid = media["uid"].as_u64().map(|uid| uid as u32);
    if uid == Some(GUEST) {
        for fd in db.fds_of(sid) {
            if fd.device.as_deref() == Some(presentation) && fd.writes() {
                db.close_fd(sid, fd.fd);
            }
        }
        return;
    }
    let (Some(uid), Some(mut node)) = (uid, db.node(presentation)) else {
        return;
    };
    let mut entries = node.entries();
    let spec = Spec {
        default: false,
        tag: Tag::User(Some(uid)),
        perms: None,
    };
    if acl::remove(&mut entries, &[&spec], false).is_ok() {
        node.set_entries(&entries);
        db.set_node(presentation, &node);
    }
}

/// The voice a listener speaking through `request` sends: /dev/snd/PRESENTATION-SPEAKER,
/// numbered if taken; if they may.
pub fn voice_name(db: &Db, who: &Identity, request: &Request) -> Result<String> {
    if !request.writes() {
        return Err(Error::because(
            Errno::EBADF,
            "Not allowed to speak, or no longer: ask again",
        ));
    }
    if request.device.path.is_empty() {
        return Err(Error::because(
            Errno::ENODATA,
            "the presentation shows nothing yet",
        ));
    }
    if db.voices_for(&request.device.name).len() >= VOICES_MAX {
        return Err(Error::because(
            Errno::EBUSY,
            format!("at most {VOICES_MAX} listeners speak at once; wait for one to finish"),
        ));
    }
    let base = request.device.name.rsplit('/').next().unwrap_or_default();
    let stem = format!("{base}-{}", super::name_of(db, who));
    let mut name = device_path(SOUND, &stem).map_err(|e| Error::because(Errno::EINVAL, e))?;
    let mut number = 2;
    while db.device(&name).is_some() || db.node(&name).is_some() {
        name = device_path(SOUND, &format!("{stem}-{number}"))
            .map_err(|e| Error::because(Errno::EINVAL, e))?;
        number += 1;
    }
    Ok(name)
}

/// The voice `name` made, as Realtime's `session` carries it, for the ask `ask` the speaker was
/// let speak by (which tells its presenter's page whose voice it allowed): its presenter's, with the
/// presentation's mode and ACL, so that whoever follows the presentation hears it; it lasts
/// while the descriptor it was sent through is kept.
pub fn spoken(
    db: &mut Db,
    who: &Identity,
    request: &Request,
    name: &str,
    session: &str,
    ask: Option<&str>,
) -> Result<Value> {
    let presentation = db.device(&request.device.name).ok_or(Errno::ENXIO)?;
    let shown = db.node(&presentation.name).ok_or(Errno::ENXIO)?;
    if voice_name(db, who, request)? != name {
        return Err(Errno::EBUSY.into());
    }
    let mut node = Node::device(presentation.owner, shown.group, shown.mode, "snd");
    node.acl = shown.acl.clone();
    super::ensure(db);
    db.set_node(name, &node);
    let media = json!({
        "session": session, "track": realtime::TRACK, "for": presentation.name,
        "speaker": super::name_of(db, who), "uid": who.id, "sid": request.sid, "fd": request.fd,
        "ask": ask,
    });
    let made = Device {
        name: name.to_string(),
        owner: presentation.owner,
        path: presentation.path.clone(),
        media: Some(media.to_string()),
    };
    db.set_device(&made, auth::now());
    db.set_expiry("device", name, auth::now() + SOUND_IDLE);
    db.started_sound(name);
    Ok(json!({ "device": name, "version": version(&made) }))
}
