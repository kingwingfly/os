//! Accounts' and groups' names, as libc's getpwnam and getgrnam find them: in /etc/passwd and
//! /etc/group, which the kernel keeps for its accounts, as /proc's files are kept.
use crate::sys::Sys;

#[derive(Clone, Debug, Default)]
pub struct Names {
    users: Vec<(String, u32)>,
    groups: Vec<(String, u32)>,
    /// Each account's login group.
    logins: Vec<(u32, u32)>,
}
impl Names {
    /// The names, as /etc/passwd and /etc/group say now; none if they cannot be read.
    pub async fn read(sys: &impl Sys) -> Self {
        let table = |bytes: Result<Vec<u8>, ()>| -> Vec<(String, u32)> {
            String::from_utf8(bytes.unwrap_or_default())
                .unwrap_or_default()
                .lines()
                .filter_map(|line| {
                    let mut fields = line.split(':');
                    let name = fields.next()?.to_string();
                    let id = fields.nth(1)?.parse().ok()?;
                    Some((name, id))
                })
                .collect()
        };
        let passwd = String::from_utf8(sys.read("/etc/passwd").await.unwrap_or_default())
            .unwrap_or_default();
        let logins = passwd
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                Some((fields.get(2)?.parse().ok()?, fields.get(3)?.parse().ok()?))
            })
            .collect();
        Self {
            users: table(Ok::<_, ()>(passwd.into_bytes())),
            groups: table(sys.read("/etc/group").await.map_err(|_| ())),
            logins,
        }
    }
    /// The login group of the account `uid`.
    pub fn login_group(&self, uid: u32) -> Option<u32> {
        self.logins
            .iter()
            .find(|(user, _)| *user == uid)
            .map(|(_, gid)| *gid)
    }
    /// The account `name` names: its uid, or the number given.
    pub fn uid(&self, name: &str) -> Option<u32> {
        lookup(&self.users, name)
    }
    pub fn gid(&self, name: &str) -> Option<u32> {
        lookup(&self.groups, name)
    }
    /// The name of the account `uid`, or its number, as ls shows one it does not know.
    pub fn user(&self, uid: u32) -> String {
        name(&self.users, uid)
    }
    pub fn group(&self, gid: u32) -> String {
        name(&self.groups, gid)
    }
}

fn lookup(table: &[(String, u32)], name: &str) -> Option<u32> {
    table
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, id)| *id)
        .or_else(|| name.parse().ok())
}

fn name(table: &[(String, u32)], id: u32) -> String {
    table
        .iter()
        .find(|(_, i)| *i == id)
        .map_or_else(|| id.to_string(), |(n, _)| n.clone())
}
