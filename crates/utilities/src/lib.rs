//! Portable `wasm32-wasip1`-compatible local account and Service Manager v2 CLI applets
//! (`#57` `L3d`, Contract v2 §2.4, §2.8).
//!
//! Exported as a library target so all 6 applets compile, lint, and unit-test cleanly in Wave 4A
//! without conflicting with Wave 4A Track 2 edits to `src/main.rs` or `crates/core/src/bin.rs`.
//! Wave 4B wires each `::run(&args[1..])` directly into the `utilities` multicall dispatcher.

pub mod login;
pub mod newgrp;
pub mod passwd;
pub mod service;
pub mod su;
pub mod sudo;

/// Parsed record from local `/etc/passwd` shared by `su`, `login`, and `newgrp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalPasswdRecord {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// Parsed record from local `/etc/group` shared by `newgrp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalGroupRecord {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

pub(crate) fn parse_passwd_line(line: &str) -> Option<LocalPasswdRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = trimmed.split(':').collect();
    if fields.len() != 7 || fields[0].is_empty() {
        return None;
    }
    Some(LocalPasswdRecord {
        name: fields[0].to_owned(),
        uid: fields[2].parse().ok()?,
        gid: fields[3].parse().ok()?,
        home: fields[5].to_owned(),
        shell: fields[6].to_owned(),
    })
}

pub(crate) fn parse_group_line(line: &str) -> Option<LocalGroupRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields: Vec<&str> = trimmed.split(':').collect();
    if fields.len() != 4 || fields[0].is_empty() {
        return None;
    }
    let members = fields[3]
        .split(',')
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
        .collect();
    Some(LocalGroupRecord {
        name: fields[0].to_owned(),
        gid: fields[2].parse().ok()?,
        members,
    })
}
