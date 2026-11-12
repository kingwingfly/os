//! The Machine persists coordination separately from cookie and process credentials.
use crate::{
    auth,
    db::{Db, int, text},
};
use abi::{Errno, Error, LoginAction};
use kernel::login::Session;
use kernel::startup::{Profile, Startup};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::SqlStorage;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Context {
    pub binding: String,
    pub uid: u32,
    pub expires: u64,
}
#[derive(Deserialize)]
struct Row {
    binding: String,
    state: String,
}
const SESSIONS_MAX: usize = 32;

pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    crate::seat_policy::create(sql)?;
    sql.exec("CREATE TABLE IF NOT EXISTS login_sessions(binding TEXT PRIMARY KEY, ns TEXT NOT NULL, id TEXT NOT NULL UNIQUE, deadline INTEGER NOT NULL, state TEXT NOT NULL)", None)?;
    sql.exec("CREATE TABLE IF NOT EXISTS login_profiles(ns TEXT NOT NULL, uid INTEGER NOT NULL, profile TEXT NOT NULL, PRIMARY KEY(ns, uid))", None)?;
    Ok(())
}
fn invalid() -> Error {
    Errno::ESTALE.into()
}
fn hash(proof: &str) -> Result<String, Error> {
    if proof.len() != 64 || !proof.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Errno::EINVAL.into());
    }
    Ok(auth::token_hash(proof))
}
impl Db {
    fn new_login(&mut self, ns: &str, context: &Context, now: u64) -> Result<Session, Error> {
        let rows = self.rows::<Row>(
            "SELECT binding, state FROM login_sessions WHERE ns = ? ORDER BY rowid",
            vec![text(ns)],
        );
        if rows.len() >= SESSIONS_MAX {
            let idle = rows.into_iter().find(|row| {
                serde_json::from_str::<Session>(&row.state).is_ok_and(|mut session| {
                    self.refresh_managed(ns, &mut session);
                    session.expire(now);
                    session.idle()
                        && !self
                            .processes(ns)
                            .iter()
                            .any(|p| p.login_scope.as_deref() == Some(&session.id) && !p.zombie())
                })
            });
            let Some(idle) = idle else {
                return Err(Errno::ENOSPC.into());
            };
            self.run(
                "DELETE FROM login_sessions WHERE binding = ?",
                vec![text(&idle.binding)],
            );
        }
        let mut session = Session::new(auth::random_token(), context.uid, context.expires, now);
        session.startup = self.login_profile(ns, context.uid)?.map(Startup::new);
        Ok(session)
    }
    /// Capture login membership before awaiting image authorization. Exec cannot cross
    /// explicit shutdown/restart, even if the same account's cookie is still valid.
    pub(crate) fn admit_login(
        &mut self,
        ns: &str,
        context: &Context,
        now: u64,
    ) -> Result<String, Error> {
        self.ensure_namespace(ns, now);
        self.admit_boot(ns)?;
        let row = self
            .rows::<Row>(
                "SELECT binding, state FROM login_sessions WHERE ns = ? AND binding = ?",
                vec![text(ns), text(&context.binding)],
            )
            .pop();
        let mut session = match row {
            Some(row) => {
                serde_json::from_str::<Session>(&row.state).map_err(|_| Error::from(Errno::EIO))?
            }
            None => self.new_login(ns, context, now)?,
        };
        session.expire(now);
        if session.uid != context.uid || context.expires <= now {
            return Err(Errno::ESTALE.into());
        }
        if session.shutdown.is_some() {
            return Err(Error::because(
                Errno::EBUSY,
                "this login session is ending or ended; start a new session from the greeter",
            ));
        }
        self.save_login(ns, &context.binding, &session);
        Ok(session.id)
    }
    pub(crate) fn check_login_admission(
        &self,
        ns: &str,
        scope: Option<&str>,
        context: Option<&Context>,
    ) -> Result<(), Error> {
        self.admit_boot(ns)?;
        let context = context.ok_or(Error::from(Errno::EACCES))?;
        let row = self
            .rows::<Row>(
                "SELECT binding, state FROM login_sessions WHERE ns = ? AND binding = ?",
                vec![text(ns), text(&context.binding)],
            )
            .pop()
            .ok_or(Errno::ESTALE)?;
        let session: Session =
            serde_json::from_str(&row.state).map_err(|_| Error::from(Errno::EIO))?;
        if scope != Some(session.id.as_str()) || session.uid != context.uid {
            return Err(Errno::ESTALE.into());
        }
        if session.shutdown.is_some() {
            return Err(Error::because(
                Errno::EBUSY,
                "this login session is ending or ended; start a new session from the greeter",
            ));
        }
        Ok(())
    }
    fn advance_login_shutdown(&mut self, ns: &str, session: &mut Session, now: u64) {
        if let Some(shutdown) = &mut session.shutdown
            && !shutdown.complete
        {
            shutdown.complete = self.drain_scope(ns, Some(&session.id), shutdown.due(now), now);
        }
    }
    fn login_profile(&self, ns: &str, uid: u32) -> Result<Option<Profile>, Error> {
        #[derive(Deserialize)]
        struct Stored {
            profile: String,
        }
        self.rows::<Stored>(
            "SELECT profile FROM login_profiles WHERE ns = ? AND uid = ?",
            vec![text(ns), int(uid)],
        )
        .pop()
        .map(|row| serde_json::from_str(&row.profile).map_err(|_| Errno::EIO.into()))
        .transpose()
    }
    fn configure_login(
        &mut self,
        ns: &str,
        session: &mut Session,
        file: Option<&str>,
    ) -> Result<(), Error> {
        if let Some(file) = file {
            if session.managed.is_some() {
                return Err(Errno::EBUSY.into());
            }
            if self.login_profile(ns, session.uid)?.is_none() {
                #[derive(Deserialize)]
                struct Count {
                    n: u32,
                }
                let n = self.rows::<Count>(
                    "SELECT COUNT(*) AS n FROM login_profiles WHERE ns = ?",
                    vec![text(ns)],
                )[0]
                .n;
                if n >= 32 {
                    return Err(Errno::ENOSPC.into());
                }
            }
            let profile = Profile::new(auth::random_token(), file.into())?;
            self.run("INSERT INTO login_profiles(ns, uid, profile) VALUES(?, ?, ?) ON CONFLICT(ns, uid) DO UPDATE SET profile = excluded.profile",
                vec![text(ns), int(session.uid), text(&serde_json::to_string(&profile).unwrap())]);
            session.startup = Some(Startup::new(profile));
        } else {
            self.run(
                "DELETE FROM login_profiles WHERE ns = ? AND uid = ?",
                vec![text(ns), int(session.uid)],
            );
            if let Some(startup) = &mut session.startup {
                startup.disable();
            }
        }
        Ok(())
    }
    fn refresh_managed(&self, ns: &str, session: &mut Session) {
        if session
            .managed
            .as_ref()
            .is_some_and(|managed| self.process(ns, managed.pid).is_none_or(|row| row.zombie()))
        {
            if let Some(startup) = &mut session.startup
                && session
                    .managed
                    .as_ref()
                    .is_some_and(|m| Some(m.pid) == startup.pid)
            {
                startup.observed_exit();
            }
            session.managed = None;
        }
    }
    fn save_login(&mut self, ns: &str, binding: &str, session: &Session) {
        self.run("INSERT INTO login_sessions(binding, ns, id, deadline, state) VALUES(?, ?, ?, ?, ?) ON CONFLICT(binding) DO UPDATE SET id = excluded.id, deadline = excluded.deadline, state = excluded.state",
            vec![text(binding), text(ns), text(&session.id), int(session.deadline()), text(&serde_json::to_string(session).unwrap())]);
    }
    pub fn expire_logins(&mut self, now: u64) {
        #[derive(Deserialize)]
        struct Expired {
            ns: String,
            binding: String,
            state: String,
        }
        for row in self.rows::<Expired>(
            "SELECT ns, binding, state FROM login_sessions WHERE deadline <= ?",
            vec![int(now)],
        ) {
            let Ok(mut session) = serde_json::from_str::<Session>(&row.state) else {
                continue;
            };
            self.refresh_managed(&row.ns, &mut session);
            session.expire(now);
            self.advance_login_shutdown(&row.ns, &mut session, now);
            if session.expires <= now && session.shutdown.as_ref().is_none_or(|s| s.complete) {
                self.run(
                    "DELETE FROM login_sessions WHERE binding = ?",
                    vec![text(&row.binding)],
                );
            } else {
                self.save_login(&row.ns, &row.binding, &session);
            }
        }
    }
    pub fn login_deadline(&self) -> Option<u64> {
        #[derive(Deserialize)]
        struct Deadline {
            deadline: Option<u64>,
        }
        self.rows::<Deadline>(
            "SELECT MIN(deadline) AS deadline FROM login_sessions",
            vec![],
        )
        .first()
        .and_then(|row| row.deadline)
    }
    pub fn login_session(
        &mut self,
        ns: &str,
        context: Option<&Context>,
        action: LoginAction,
        now: u64,
    ) -> Result<Value, Error> {
        // Leave and Finish are narrow capabilities: after logout they may remove their
        // own membership or report an ended run, never refresh a lease or act as the account.
        let retired = match &action {
            LoginAction::Leave { member } => Some(member.session.clone()),
            LoginAction::Finish { session, .. } => Some(session.clone()),
            _ => None,
        };
        let row = if let Some(id) = &retired {
            self.rows::<Row>(
                "SELECT binding, state FROM login_sessions WHERE ns = ? AND id = ?",
                vec![text(ns), text(id)],
            )
            .pop()
        } else {
            let context = context.ok_or(Error::from(Errno::EACCES))?;
            self.rows::<Row>(
                "SELECT binding, state FROM login_sessions WHERE ns = ? AND binding = ?",
                vec![text(ns), text(&context.binding)],
            )
            .pop()
        };
        let (binding, mut session) = match row {
            Some(row) => (
                row.binding,
                serde_json::from_str::<Session>(&row.state).map_err(|_| Error::from(Errno::EIO))?,
            ),
            None if matches!(action, LoginAction::Inspect) => return Ok(Value::Null),
            None if matches!(action, LoginAction::Join { .. }) => {
                let context = context.ok_or(Error::from(Errno::EACCES))?;
                let session = self.new_login(ns, context, now)?;
                (context.binding.clone(), session)
            }
            None => return Err(invalid()),
        };
        if retired.is_none() {
            let context = context.ok_or(Error::from(Errno::EACCES))?;
            if context.uid != session.uid {
                return Err(Errno::EACCES.into());
            }
            session.expires = context.expires;
        }
        session.expire(now);
        self.refresh_managed(ns, &mut session);
        self.advance_login_shutdown(ns, &mut session, now);
        match &action {
            LoginAction::Inspect => (),
            LoginAction::SeatPolicy {
                session: expected_session,
                expected,
                sharing,
            } => {
                if expected_session != &session.id {
                    return Err(Errno::ESTALE.into());
                }
                self.set_seat_policy(ns, session.uid, *expected, *sharing)?;
            }
            LoginAction::End { session: expected } => {
                if session.end(expected)? {
                    self.stop_scope(ns, Some(&session.id), now);
                }
                self.advance_login_shutdown(ns, &mut session, now);
            }
            LoginAction::Restart { session: expected } => {
                if expected != &session.id {
                    return Err(Errno::ESTALE.into());
                }
                if !session.shutdown.as_ref().is_some_and(|s| s.complete) {
                    return Err(Errno::EBUSY.into());
                }
                self.admit_boot(ns)?;
                let context = context.ok_or(Error::from(Errno::EACCES))?;
                session = Session::new(auth::random_token(), context.uid, context.expires, now);
                session.startup = self.login_profile(ns, context.uid)?.map(Startup::new);
            }
            LoginAction::Join { host, proof } => session.join(host, &hash(proof)?)?,
            LoginAction::Finish {
                launch,
                status,
                error,
                ..
            } => {
                let startup = session.startup.as_mut().ok_or(Error::from(Errno::ESTALE))?;
                let proof_hash = hash(&launch.proof)?;
                startup.authorize_finish(&launch.revision, &proof_hash)?;
                if startup
                    .pid
                    .is_some_and(|pid| self.process(ns, pid).is_some_and(|row| !row.zombie()))
                {
                    return Err(Errno::EBUSY.into());
                }
                startup.finish(&launch.revision, &proof_hash, *status, error.clone())?;
            }
            LoginAction::Keep { member }
            | LoginAction::Claim { member, .. }
            | LoginAction::Renew { member, .. }
            | LoginAction::Attach { member, .. }
            | LoginAction::Configure { member, .. }
            | LoginAction::Begin { member, .. }
            | LoginAction::Signal { member, .. }
            | LoginAction::Leave { member } => {
                if member.session != session.id {
                    return Err(invalid());
                }
                let hash = hash(&member.proof)?;
                match &action {
                    LoginAction::Keep { .. } => session.keep(&member.host, &hash)?,
                    LoginAction::Claim { generation, .. } => {
                        session.claim(&member.host, &hash, *generation)?
                    }
                    LoginAction::Renew { generation, .. } => {
                        session.renew(&member.host, &hash, *generation)?
                    }
                    LoginAction::Leave { .. } => session.leave(&member.host, &hash)?,
                    LoginAction::Configure {
                        generation, file, ..
                    } => {
                        session.authorize(&member.host, &hash, *generation)?;
                        self.configure_login(ns, &mut session, file.as_deref())?;
                    }
                    LoginAction::Begin {
                        generation, launch, ..
                    } => {
                        session.authorize(&member.host, &hash, *generation)?;
                        if session.managed.is_some() {
                            return Err(Errno::EBUSY.into());
                        }
                        let proof_hash = crate::login::hash(&launch.proof)?;
                        session
                            .startup
                            .as_mut()
                            .ok_or(Error::from(Errno::ESTALE))?
                            .begin(&member.host, *generation, &launch.revision, &proof_hash)?;
                    }
                    LoginAction::Attach {
                        generation,
                        process,
                        launch,
                        ..
                    } => {
                        session.authorize(&member.host, &hash, *generation)?;
                        let row = self
                            .process_token(&process.token, Some(process.pid), ns)
                            .ok_or(Error::from(Errno::EPERM))?;
                        // This is an explicit grant of one same-account session leader,
                        // never authority derived from a public PID or coordinator name.
                        if row.uid != session.uid
                            || row.pid == 1
                            || row.ppid != 1
                            || row.sid != row.pid
                            || row.pgid != row.pid
                        {
                            return Err(Errno::EPERM.into());
                        }
                        for other in self.rows::<Row>("SELECT binding, state FROM login_sessions WHERE ns = ? AND binding != ?", vec![text(ns), text(&binding)]) {
                            if serde_json::from_str::<Session>(&other.state).is_ok_and(|s| s.managed.is_some_and(|m| m.pid == row.pid)) {
                                return Err(Errno::EBUSY.into());
                            }
                        }
                        if row.login_scope.as_deref() != Some(session.id.as_str()) {
                            return Err(Error::because(
                                Errno::EPERM,
                                "the process belongs to another login scope",
                            ));
                        }
                        if let Some(launch) = launch {
                            session.attach_startup(
                                &member.host,
                                &hash,
                                *generation,
                                row.pid,
                                &launch.revision,
                                &crate::login::hash(&launch.proof)?,
                            )?;
                        } else {
                            session.attach(&member.host, &hash, *generation, row.pid)?;
                        }
                    }
                    LoginAction::Signal {
                        generation,
                        pid,
                        signal,
                        ..
                    } => {
                        session.signal(&member.host, &hash, *generation, *pid)?;
                        let row = self.process(ns, *pid).ok_or(Errno::ESRCH)?;
                        if row.uid != session.uid {
                            return Err(Errno::EPERM.into());
                        }
                        self.kill(ns, &row.identity(), *pid, *signal, now)?;
                        if matches!(*signal, 1 | 2 | 15) {
                            self.kill(ns, &row.identity(), *pid, abi::SIGCONT, now)?;
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
        self.save_login(ns, &binding, &session);
        // A departed host receives no metadata from an earlier login.
        Ok(if retired.is_some() {
            Value::Null
        } else {
            let mut view = session.view();
            view["seat_policy"] =
                serde_json::to_value(self.seat_policy(ns, session.uid)?).map_err(|_| Errno::EIO)?;
            view
        })
    }
}
