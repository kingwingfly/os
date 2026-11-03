//! /dev/snd's driver: a live sound. Its maker writes it, sending its microphone through
//! Realtime (`SND_PUBLISH`, on a descriptor that writes it), for as long as that descriptor is
//! kept (`lease`) and open: closed, the sound ends. Whoever may read it hears it (`SND_LISTEN`,
//! then `SND_ANSWER`). A voice, a listener's speaking in a presentation (present.rs), is one
//! too, its presenter's, made by the driver of the presentation.
use super::{Request, SOUND_IDLE, realtime, version};
use crate::auth;
use crate::db::{Db, Device};
use abi::{Errno, Error};
use serde_json::{Value, json};
use terminal_worker_core::permissions::Store;

type Result<T> = std::result::Result<T, Error>;

/// What reading a sound tells: whose it is, whether it is live, and, a voice, whose and in
/// which presentation.
pub fn read(db: &Db, device: &Device) -> Value {
    let media: Value = device
        .media
        .as_deref()
        .and_then(|media| serde_json::from_str(media).ok())
        .unwrap_or_default();
    json!({
        "device": device.name, "owner": db.username(device.owner), "live": device.media.is_some(),
        "presentation": media["for"], "speaker": media["speaker"], "version": version(device),
    })
}

/// The descriptor `fd` of `sid` closed: if it sends the sound `device`, or would have, being
/// one that writes it before any sends it, the sound ends.
pub fn closed(db: &mut Db, sid: &str, fd: u32, device: &str) {
    let unsent = db
        .device(device)
        .is_some_and(|device| device.media.is_none())
        && db.fd(sid, fd).is_some_and(|found| found.writes());
    if unsent || super::writer(db, device) == Some((sid.to_string(), fd)) {
        super::hangup(db, device, true);
    }
}

/// A sound hung up keeps nothing beyond its row; a voice hung up takes its speaker's leave to
/// speak back (present::silenced).
pub fn hangup(db: &mut Db, name: &str) {
    let Some(device) = db.device(name) else {
        return;
    };
    let media: Value = device
        .media
        .as_deref()
        .and_then(|media| serde_json::from_str(media).ok())
        .unwrap_or_default();
    if let Some(presentation) = media["for"].as_str() {
        super::present::silenced(db, presentation, &media);
    }
}

/// Whether `request` may send the sound: a descriptor that writes it, which no other sends.
pub fn may_publish(request: &Request) -> Result<()> {
    if !request.writes() {
        return Err(Errno::EBADF.into());
    }
    if request.device.media.is_some() {
        return Err(Error::because(Errno::EBUSY, "the sound is sent already"));
    }
    Ok(())
}

/// The sound sent, as Realtime's `session` carries it, through `request`'s descriptor: it lasts
/// while that one is kept.
pub fn published(db: &mut Db, request: &Request, session: &str) -> Result<Value> {
    let mut device = db.device(&request.device.name).ok_or(Errno::ENXIO)?;
    if device.media.is_some() {
        return Err(Error::because(Errno::EBUSY, "the sound is sent already"));
    }
    device.media = Some(
        json!({ "session": session, "track": realtime::TRACK, "sid": request.sid, "fd": request.fd })
            .to_string(),
    );
    db.set_device(&device, auth::now());
    db.set_expiry("device", &device.name, auth::now() + SOUND_IDLE);
    db.started_sound(&device.name);
    Ok(json!({ "device": device.name, "version": version(&device) }))
}

/// What a listener pulls of the sound `device`: Realtime's session and track.
pub fn heard(device: &Device) -> Result<(String, String)> {
    let media: Value = device
        .media
        .as_deref()
        .and_then(|media| serde_json::from_str(media).ok())
        .ok_or_else(|| Error::because(Errno::ENODATA, format!("{}: not live yet", device.name)))?;
    let session = media["session"].as_str().unwrap_or_default().to_string();
    let track = media["track"]
        .as_str()
        .unwrap_or(realtime::TRACK)
        .to_string();
    Ok((session, track))
}
