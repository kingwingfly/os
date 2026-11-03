use crate::db::{self, transact};
use crate::{api, auth, dev, jobs};
use std::cell::Cell;
use std::collections::BTreeSet;
use terminal_worker_core::devices::PRESENT;
use terminal_worker_core::permissions::{EXEC, GUEST, GUEST_HOME, Node, READ, Store, User};
use worker::*;

/// The R2 object that marks the bucket as managed by an authority, so that a lost authority is
/// noticed instead of silently starting over with an empty filesystem.
const MARKER: &str = "system/terminal-authority-v2";

/// The one authority over accounts, sessions and the filesystem tree. Every decision is a
/// synchronous SQLite transaction, so requests never wait on each other's network I/O; file
/// bytes go to and from R2 in the Worker, never through here.
#[durable_object]
pub struct TerminalAuthority {
    state: State,
    env: Env,
    ready: Cell<bool>,
}
impl DurableObject for TerminalAuthority {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ready: Cell::new(false),
        }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.ready().await?;
        if req.path() == "/api/events" {
            return self.listen(&req);
        }
        let reply = api::handle(&mut req, &self.env, &self.state).await?;
        self.schedule().await?;
        self.broadcast();
        reply.response()
    }
    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // Pings are answered without waking this object; what else a page says is about the
        // decks it shows.
        if let WebSocketIncomingMessage::String(text) = message {
            self.ready().await?;
            self.heard(&ws, &text);
            self.schedule().await?;
        }
        Ok(())
    }
    async fn websocket_close(&self, ws: WebSocket, _: usize, _: String, _: bool) -> Result<()> {
        // A session whose last page goes asks to speak no more (dev/present.rs).
        if let Some(sid) = Line::of(&ws).sid {
            let others = self
                .state
                .get_websockets()
                .iter()
                .filter(|other| other.as_ref() != ws.as_ref())
                .any(|other| Line::of(other).sid.as_deref() == Some(sid.as_str()));
            if !others {
                self.ready().await?;
                let _ = transact(&self.state, move |db| {
                    for ask in db.asks_of(&sid) {
                        dev::present::withdraw(db, &ask.device, &sid);
                    }
                    ((), true)
                });
                self.broadcast();
            }
        }
        let _ = ws.close(Some(1000), Some("closed"));
        Ok(())
    }
    async fn websocket_error(&self, _: WebSocket, _: Error) -> Result<()> {
        Ok(())
    }
    async fn alarm(&self) -> Result<Response> {
        self.ready().await?;
        let now = auth::now();
        transact(&self.state, move |db| {
            for (kind, id) in db.due(now) {
                match (kind.as_str(), db.file(&id), db.job(&id)) {
                    ("upload", Some(file), _) if file.recording() => {
                        api::finish_recording(db, &file)
                    }
                    // A file whose writer went is what it wrote, as one a process that died
                    // was writing.
                    ("upload", Some(file), _) if file.growing() => db.finish_file(&file.id),
                    ("upload", Some(file), _) => api::cancel(db, &file),
                    ("job", _, Some(job)) if !job.finished() => {
                        let why = if job.state == "question" {
                            "Cancelled: its question went unanswered for an hour"
                        } else {
                            "Cancelled after waiting a week"
                        };
                        db.add_lines(&id, &[(true, why.into())]);
                        jobs::finish(db, &id, "cancelled");
                    }
                    // A session not heard from for long watches nothing any more, and once it
                    // keeps no descriptor, its numbers start again.
                    ("watches", _, _) => {
                        db.drop_watches(&id);
                        db.forget_fd_numbers(&id);
                    }
                    // A descriptor not kept for long is closed; what it wrote waits, unfinished,
                    // for a writer to go on with it.
                    ("fd", _, _) => {
                        if let Some((sid, fd)) = id.rsplit_once(' ')
                            && let Ok(fd) = fd.parse()
                        {
                            crate::fds::release(db, sid, fd);
                        }
                        db.clear_expiry(&kind, &id);
                    }
                    // A session ends when it expires, and the pages holding it hear so.
                    ("session", _, _) => {
                        db.delete_session(&id);
                        db.clear_expiry(&kind, &id);
                    }
                    // So does a device: a presentation unturned for long, a sound unkept; its
                    // followers hear so.
                    ("device", _, _) => dev::hangup(db, &id, true),
                    _ => db.clear_expiry(&kind, &id),
                }
            }
            ((), true)
        })?;
        let bucket = self.env.bucket("FILES")?;
        loop {
            let mut keys = transact(&self.state, |db| (db.garbage(1000), false))?;
            if keys.is_empty() {
                break;
            }
            // A prefix is forgotten once nothing is listed under it.
            let (prefixes, objects): (Vec<String>, Vec<String>) =
                keys.iter().cloned().partition(|key| key.ends_with('/'));
            let mut doomed = objects;
            for prefix in prefixes {
                let listed = bucket.list().prefix(&prefix).limit(1000).execute().await?;
                if listed.truncated() {
                    keys.retain(|key| *key != prefix);
                }
                doomed.extend(listed.objects().iter().map(|o| o.key()));
            }
            if !doomed.is_empty() {
                bucket.delete_multiple(doomed).await?;
            }
            transact(&self.state, move |db| {
                db.forget_garbage(&keys);
                ((), true)
            })?;
        }
        // Uploads it let expire leave their directories.
        self.broadcast();
        db::take_alarm();
        if let Some(due) = transact(&self.state, |db| (db.next_due(), false))? {
            let delay = (due.saturating_sub(auth::now()) * 1000).max(1000);
            self.state
                .storage()
                .set_alarm(delay.min(i64::MAX as u64) as i64)
                .await?;
        }
        Response::ok("")
    }
}
impl TerminalAuthority {
    /// A page that listens for changes: a WebSocket, which keeps the session that opened it, so
    /// that it hears only of directories its account may list. Hibernation keeps idle ones free.
    fn listen(&self, req: &Request) -> Result<Response> {
        if !req
            .headers()
            .get("Upgrade")?
            .is_some_and(|upgrade| upgrade.eq_ignore_ascii_case("websocket"))
        {
            return Response::error("Expected a WebSocket", 426);
        }
        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        // A cookie whose session is gone is a guest's, which has nothing to end; each browser
        // signed out is a session all the same (auth::sid), which a driver's news may be for.
        let key = auth::token_key(req);
        let guest = auth::guest_key(req);
        let (uid, sid) = transact(&self.state, {
            let key = key.clone();
            move |db| {
                let id = auth::identity(db, key.as_deref()).id;
                let sid = auth::sid(db, key.as_deref(), guest.as_deref());
                ((Some(id).filter(|id| *id != GUEST), sid), false)
            }
        })?;
        pair.server.serialize_attachment(Line {
            session: key.filter(|_| uid.is_some()),
            uid,
            sid,
            follows: Vec::new(),
        })?;
        if self.state.get_websocket_auto_response().is_none()
            && let Ok(ping) = worker::worker_sys::WebSocketRequestResponsePair::new("ping", "pong")
        {
            self.state.set_websocket_auto_response(&ping);
        }
        Response::from_websocket(pair.client)
    }
    /// Tell the listening pages what changed in the directories their sessions watch (inotify),
    /// those their accounts may still list, so that they show what others did as it happens; those whose session ended (signed
    /// out elsewhere, a password changed, the account locked or removed, expired) that it did,
    /// once, as their account is a guest's from then on; those following a device that ended,
    /// or its account's, that it did; and those following a presentation whose account started
    /// a live sound, or let a listener speak, that it did, to hear it.
    fn broadcast(&self) {
        let changed = db::take_changes();
        let ended = db::take_ended();
        let removed = db::take_removed();
        let started = db::take_started();
        let told = db::take_told();
        if changed.is_empty()
            && !ended
            && removed.is_empty()
            && started.is_empty()
            && told.is_empty()
        {
            return;
        }
        let sockets = self.state.get_websockets();
        if sockets.is_empty() {
            return;
        }
        self.tell(&sockets, told);
        let lines: Vec<Line> = sockets.iter().map(Line::of).collect();
        let asked: Vec<(Option<String>, Option<String>, Vec<String>)> = lines
            .iter()
            .map(|line| (line.session.clone(), line.sid.clone(), line.follows.clone()))
            .collect();
        let visible = transact(&self.state, move |db| {
            // What each sound started is, if it is still there: whose, and, a voice, of which
            // presentation.
            let sounds: Vec<(db::Device, Option<serde_json::Value>)> = started
                .iter()
                .filter_map(|name| db.device(name))
                .map(|device| {
                    let voice = dev::present::voice(&device);
                    (device, voice)
                })
                .collect();
            let visible: Vec<(bool, Vec<serde_json::Value>, Vec<serde_json::Value>)> = asked
                .iter()
                .map(|(key, sid, follows)| {
                    let who = auth::identity(db, key.as_deref());
                    let gone = ended && key.is_some() && who.id == GUEST;
                    // What changed in the directories its session watches, those its account
                    // may still list; a watch of one it may not, or that went, is told so.
                    let watches = sid
                        .as_deref()
                        .map(|sid| db.watches_of(sid))
                        .unwrap_or_default();
                    let dirs = watches
                        .into_iter()
                        .filter(|(_, path)| changed.contains(path))
                        .map(|(wd, path)| {
                            let mask = if db.access(&who, &path, READ | EXEC).is_ok() {
                                abi::IN_MODIFY
                            } else {
                                abi::IN_IGNORED
                            };
                            serde_json::json!({ "wd": wd, "mask": mask })
                        })
                        .collect();
                    let presentations: Vec<db::Device> = follows
                        .iter()
                        .filter(|name| terminal_worker_core::parent(name) == PRESENT)
                        .filter_map(|name| db.device(name))
                        .collect();
                    let heard = sounds
                        .iter()
                        .filter(|(sound, _)| !follows.contains(&sound.name))
                        .filter_map(|(sound, voice)| {
                            let presentation = presentations.iter().find(|presentation| {
                                presentation.owner == sound.owner
                                    && voice.as_ref().is_none_or(|voice| {
                                        voice["presentation"] == presentation.name.as_str()
                                    })
                            });
                            let mine = voice.is_some() && who.id == sound.owner;
                            if presentation.is_none() && !mine {
                                return None;
                            }
                            dev::followed(db, &who, &sound.name).ok()?;
                            Some(match voice {
                                Some(voice) => serde_json::json!({ "sound": voice }),
                                None => serde_json::json!({ "sound": {
                                    "device": sound.name, "presentation": presentation?.name,
                                    "version": dev::version(sound),
                                } }),
                            })
                        })
                        .collect();
                    (gone, dirs, heard)
                })
                .collect();
            (visible, false)
        });
        let Ok(visible) = visible else {
            return;
        };
        for ((ws, mut line), (gone, dirs, heard)) in sockets.iter().zip(lines).zip(visible) {
            if gone {
                line.session = None;
                line.uid = None;
                line.keep(ws);
                let _ = ws.send_with_str(serde_json::json!({ "session": "ended" }).to_string());
            }
            // Ended: no longer followed. Replaced by one that shows something else: still
            // followed, by name, so that a page attending it again hears of the next replacement
            // too; what it relays is checked against each follower as it goes. Its account's
            // pages hear of its end too, followed or not: the bar of one presenting it, or the
            // page sending it.
            let told: Vec<&db::Removed> = removed
                .iter()
                .filter(|device| {
                    line.follows.contains(&device.name)
                        || (!device.replaced && line.uid == Some(device.owner))
                })
                .collect();
            let following = line.follows.len();
            line.follows.retain(|device| {
                !told
                    .iter()
                    .any(|removed| removed.name == *device && !removed.replaced)
            });
            if line.follows.len() != following {
                line.keep(ws);
            }
            for device in told {
                let mut said =
                    serde_json::json!({ "name": device.name, "version": device.version });
                said[if device.replaced { "replaced" } else { "ended" }] = true.into();
                let _ = ws.send_with_str(serde_json::json!({ "device": said }).to_string());
            }
            for sound in heard {
                let _ = ws.send_with_str(sound.to_string());
            }
            if !dirs.is_empty() {
                let _ = ws.send_with_str(serde_json::json!({ "inotify": dirs }).to_string());
            }
        }
    }
    /// Send the drivers' news to the pages it is for: an account's, those still signed in as
    /// it (a presenter's, of an ask to speak), or a session's (a listener's, of its answer).
    fn tell(&self, sockets: &[WebSocket], told: Vec<(db::Told, serde_json::Value)>) {
        if told.is_empty() {
            return;
        }
        let lines: Vec<Line> = sockets.iter().map(Line::of).collect();
        let keys: Vec<Option<String>> = lines.iter().map(|line| line.session.clone()).collect();
        let uids = transact(&self.state, move |db| {
            let uids: Vec<Option<u32>> = keys
                .iter()
                .map(|key| {
                    key.as_ref()
                        .map(|key| auth::identity(db, Some(key)).id)
                        .filter(|id| *id != GUEST)
                })
                .collect();
            (uids, false)
        })
        .unwrap_or_default();
        for (whom, message) in told {
            for ((ws, line), uid) in sockets.iter().zip(&lines).zip(&uids) {
                let theirs = match &whom {
                    db::Told::Account(owner) => line.uid == Some(*owner) && *uid == Some(*owner),
                    db::Told::Session(sid) => line.sid.as_deref() == Some(sid.as_str()),
                };
                if theirs {
                    let _ = ws.send_with_str(message.to_string());
                }
            }
        }
    }
    /// What a page says on its line, about the deck or the presented PDF it shows:
    ///
    /// - `{"present": {"path", "at": [column, row]}}`: it shows that place (a PDF's page and 0).
    ///   Kept as where its account last showed that file, it goes to the account's pages signed
    ///   in elsewhere, in other browsers (this browser's other windows hear it from the page),
    ///   and to whoever follows a presentation of that file by the account (devices.rs), guests
    ///   included. Guests, who are anyone signed out, say nothing to anyone.
    /// - `{"where": path}`: where its account last showed that file, which it opens at.
    /// - `{"follow": [name...]}`: it follows these devices, a presentation /dev/present/NAME and
    ///   sounds /dev/snd/NAME, and no others; it is told what each shows (`followed`) and where
    ///   a presentation is, and hears when one ends or is replaced.
    ///
    /// Asking to speak, and answering, are a presentation's driver's (dev/present.rs).
    fn heard(&self, from: &WebSocket, text: &str) {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Said {
            Present(Place),
            Where(String),
            Follow(Vec<String>),
        }
        #[derive(serde::Deserialize, serde::Serialize)]
        struct Place {
            path: String,
            at: [u32; 2],
        }
        let reply = |ws: &WebSocket, message: serde_json::Value| {
            let _ = ws.send_with_str(message.to_string());
        };
        if text.len() > 8192 {
            return;
        }
        let Ok(said) = serde_json::from_str::<Said>(text) else {
            return;
        };
        let mut line = Line::of(from);
        match said {
            Said::Present(place) => {
                let Some(key) = line.session else {
                    return;
                };
                if terminal_worker_core::resolve("/", &place.path)
                    .ok()
                    .as_ref()
                    != Some(&place.path)
                {
                    return;
                }
                let sockets = self.state.get_websockets();
                let lines: Vec<Line> = sockets.iter().map(Line::of).collect();
                let path = place.path.clone();
                let at = (place.at[0], place.at[1]);
                let told = transact(&self.state, move |db| {
                    let who = auth::identity(db, Some(&key));
                    // Only a file the account may read is kept as shown, or said to anyone.
                    let readable = db
                        .physical(&who, &path, true)
                        .and_then(|real| db.access(&who, &real, READ));
                    if who.id == GUEST || readable.is_err() {
                        return (Vec::new(), false);
                    }
                    db.set_place(who.id, &path, at);
                    // The presentations of the file it may write (turn): its account's, and
                    // another's that lets it, which its turn turns too.
                    let writable: Vec<db::Device> = db
                        .presentations_of(&path)
                        .into_iter()
                        .filter(|device| {
                            db.node(&device.name)
                                .is_some_and(|node| dev::present::turns(&who, device, &node))
                        })
                        .collect();
                    let mut presented = Vec::new();
                    for device in writable {
                        if device.owner != who.id {
                            db.set_place(device.owner, &path, at);
                        }
                        presented.push(device.name);
                    }
                    for device in &presented {
                        db.set_expiry("device", device, auth::now() + dev::PRESENT_TTL);
                    }
                    // Whether each account may follow each device, asked once per turn: an
                    // audience of guests is one account.
                    let mut may = std::collections::BTreeMap::<(u32, &str), bool>::new();
                    let told = lines
                        .iter()
                        .map(|line| {
                            // Another session of the presenter's account, as the line was opened
                            // with (whose session is checked to be so still), or a follower: no
                            // other line is looked up.
                            let elsewhere = line.uid == Some(who.id)
                                && line.session.as_deref().is_some_and(|other| other != key);
                            let watching: Vec<&String> = line
                                .follows
                                .iter()
                                .filter(|device| presented.contains(device))
                                .collect();
                            if !elsewhere && watching.is_empty() {
                                return false;
                            }
                            let reader = auth::identity(db, line.session.as_deref());
                            (elsewhere && reader.id == who.id)
                                || watching.into_iter().any(|device| {
                                    *may.entry((reader.id, device.as_str())).or_insert_with(|| {
                                        dev::followed(db, &reader, device).is_ok()
                                    })
                                })
                        })
                        .collect();
                    (told, true)
                });
                let message = serde_json::json!({ "present": place });
                for (ws, told) in sockets.iter().zip(told.unwrap_or_default()) {
                    if told {
                        reply(ws, message.clone());
                    }
                }
            }
            Said::Where(path) => {
                let Some(key) = line.session else {
                    return;
                };
                let asked = path.clone();
                let place = transact(&self.state, move |db| {
                    let who = auth::identity(db, Some(&key));
                    let place = (who.id != GUEST)
                        .then(|| db.place(who.id, &asked))
                        .flatten();
                    (place, false)
                });
                if let Ok(Some((column, row))) = place {
                    reply(
                        from,
                        serde_json::json!({ "present": { "path": path, "at": [column, row] } }),
                    );
                }
            }
            Said::Follow(names) => {
                let key = line.session.clone();
                let asked: Vec<String> = names.into_iter().take(FOLLOWS_MAX).collect();
                let followed = transact(&self.state, move |db| {
                    let who = auth::identity(db, key.as_deref());
                    let followed: Vec<_> = asked
                        .into_iter()
                        .map(|name| {
                            let device = dev::followed(db, &who, &name).map(|device| {
                                let version = dev::version(&device);
                                (db.place(device.owner, &device.path), device.path, version)
                            });
                            (name, device)
                        })
                        .collect();
                    (followed, false)
                });
                let Ok(followed) = followed else {
                    return;
                };
                line.follows.clear();
                for (name, device) in followed {
                    match device {
                        Ok((place, path, version)) => {
                            // What it is now, which a page whose line was down when it was
                            // replaced did not hear of.
                            reply(
                                from,
                                serde_json::json!({ "followed": { "name": name, "version": version } }),
                            );
                            line.follows.push(name);
                            if let Some((column, row)) = place {
                                reply(
                                    from,
                                    serde_json::json!({ "present": { "path": path, "at": [column, row] } }),
                                );
                            }
                        }
                        Err(error) => reply(
                            from,
                            serde_json::json!({ "device": { "name": name, "error": error } }),
                        ),
                    }
                }
                line.keep(from);
            }
        }
    }
    /// Run the alarm soon if a transaction left garbage or a deadline; it reschedules itself.
    async fn schedule(&self) -> Result<()> {
        if db::take_alarm() {
            self.state.storage().set_alarm(1000).await?;
        }
        Ok(())
    }
    async fn ready(&self) -> Result<()> {
        if self.ready.get() {
            return Ok(());
        }
        db::create(&self.state.storage().sql())?;
        if transact(&self.state, |db| (db.is_empty(), false))? {
            self.initialize().await?;
        }
        // /dev is there from the start, for storage made before it was too.
        transact(&self.state, |db| {
            dev::ensure(db);
            crate::sys::ensure(db);
            ((), true)
        })?;
        // /usr is the build's: its binaries' sizes, as its manifest says.
        let sizes = self.manifest().await;
        let size = |content: &str| {
            crate::usr::asset(content)
                .and_then(|asset| sizes[asset].as_u64())
                .unwrap_or(0)
        };
        crate::usr::mount(size(crate::usr::COREUTILS), size(crate::usr::TERMINAL));
        self.ready.set(true);
        Ok(())
    }
    /// What the build says of /usr's binaries (scripts/build.mjs, `/usr/manifest.json`): each
    /// one's size, by its asset's path; nothing if it says nothing.
    async fn manifest(&self) -> serde_json::Value {
        let fetched = async {
            let request = Request::new(
                &format!("https://assets{}", crate::usr::MANIFEST),
                Method::Get,
            )?;
            let mut response = self.env.assets("ASSETS")?.fetch_request(request).await?;
            response.json::<serde_json::Value>().await
        };
        fetched.await.unwrap_or_default()
    }
    /// Create root, the system groups and the top directories, the first time only.
    async fn initialize(&self) -> Result<()> {
        let bucket = self.env.bucket("FILES")?;
        if bucket.head(MARKER).await?.is_some() {
            return Err(Error::RustError("Permission catalog is missing for an initialized bucket; restore Durable Object storage instead of starting over".into()));
        }
        let password = self.env.secret("ADMIN_PASSWORD")?.to_string();
        let salt = auth::random_token();
        let hash = auth::hash(&password, &salt, &self.env).await?;
        transact(&self.state, move |db| {
            if !db.is_empty() {
                return ((), false);
            }
            db.set_user(
                "root",
                &User {
                    id: 0,
                    group: 0,
                    groups: BTreeSet::from([0]),
                    home: "/root".into(),
                    locked: false,
                    salt,
                    hash,
                },
            );
            // Who is signed out is guest, a real account that cannot sign in, as nobody is on
            // Linux; the accounts guests make are in its group, with homes in /guest, which
            // is shared, sticky as /tmp is.
            db.set_user(
                "guest",
                &User {
                    id: GUEST,
                    group: GUEST,
                    groups: BTreeSet::new(),
                    home: GUEST_HOME.into(),
                    locked: true,
                    salt: String::new(),
                    hash: String::new(),
                },
            );
            for (name, id) in [("root", 0), ("wheel", 27), ("guest", GUEST)] {
                db.set_group(name, id);
            }
            for (path, group, mode) in [
                ("/", 0, 0o755),
                ("/home", 0, 0o755),
                ("/root", 0, 0o750),
                (GUEST_HOME, GUEST, 0o1777),
            ] {
                db.set_node(path, &Node::directory(0, group, mode));
            }
            db.set_meta("schema", db::SCHEMA_VERSION);
            ((), true)
        })?;
        bucket
            .put(
                MARKER,
                "v2: the filesystem's metadata is managed by AUTHORITY; restore its storage if missing"
                    .to_string(),
            )
            .execute()
            .await?;
        Ok(())
    }
}

/// The most devices a page follows: a presentation, its sound and voices.
const FOLLOWS_MAX: usize = 8;

/// What a page's line keeps: the session it was opened with (none for a guest's, or once that
/// session ended), its account then, its session as descriptors are kept (auth::sid, a guest's
/// browser too), and the devices it follows: a presentation, sounds.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Line {
    session: Option<String>,
    /// The account the session was, as the line was opened.
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    follows: Vec<String>,
}
impl Line {
    fn of(ws: &WebSocket) -> Self {
        ws.deserialize_attachment::<Line>()
            .ok()
            .flatten()
            // A line opened before lines kept more than their session.
            .or_else(|| {
                let session = ws.deserialize_attachment::<Option<String>>().ok()??;
                Some(Line {
                    session,
                    ..Line::default()
                })
            })
            .unwrap_or_default()
    }
    fn keep(&self, ws: &WebSocket) {
        let _ = ws.serialize_attachment(self);
    }
}
