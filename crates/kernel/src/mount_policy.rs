//! Metadata for host-backed mounts. Content stays in the provider; permissions
//! use precisely the same VFS and POSIX ACL implementation as the system tree.
use std::collections::BTreeMap;

use abi::{Call, Errno, Error};
use os_core::permissions::{Identity, MemStore, Node, Store, created};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub struct Request {
    pub identity: Identity,
    #[serde(default)]
    pub nodes: BTreeMap<String, Node>,
    pub call: Option<Call>,
    pub create: Option<Creation>,
}

#[derive(Deserialize)]
pub struct Creation {
    pub parent: Option<Node>,
    pub directory: bool,
    pub mode: u16,
}

pub fn evaluate(request: Request) -> Result<Value, Error> {
    if let Some(create) = request.create {
        let parent = create
            .parent
            .unwrap_or_else(|| Node::directory(request.identity.id, request.identity.group, 0o700));
        return Ok(json!(created(
            &request.identity,
            &parent,
            create.mode,
            create.directory,
            0
        )));
    }
    let mut store = MemStore::default();
    for (path, mut node) in request.nodes {
        node.ino = 0;
        store.set_node(&path, &node);
    }
    let call = request.call.ok_or(Errno::EINVAL)?;
    // No file data or account operations. Namespace calls validate changes on
    // the temporary metadata tree before the host provider performs them.
    if !matches!(
        call,
        Call::Access { .. }
            | Call::Unlink { .. }
            | Call::Rmdir { .. }
            | Call::Rename { .. }
            | Call::Stat { .. }
            | Call::Lstat { .. }
            | Call::Chmod { .. }
            | Call::Chown { .. }
            | Call::Getxattr { .. }
            | Call::Setxattr { .. }
            | Call::Listxattr { .. }
            | Call::Removexattr { .. }
    ) {
        return Err(Errno::EOPNOTSUPP.into());
    }
    // ACLs are inode metadata. Other xattrs need a durable provider store, which
    // this metadata overlay intentionally does not pretend to provide.
    if let Call::Getxattr { name, .. }
    | Call::Setxattr { name, .. }
    | Call::Removexattr { name, .. } = &call
        && !matches!(name.as_str(), abi::ACL_ACCESS | abi::ACL_DEFAULT)
    {
        return Err(Errno::EOPNOTSUPP.into());
    }
    let value = crate::call(
        &mut store,
        &crate::Process {
            cred: request.identity,
            umask: 0,
        },
        call,
    )?;
    let nodes: BTreeMap<_, _> = store
        .names
        .keys()
        .map(|path| (path.clone(), store.at(path)))
        .collect();
    Ok(json!({ "value": value, "nodes": nodes }))
}

pub fn json_request(input: &str) -> String {
    let result = serde_json::from_str(input)
        .map_err(|_| Error::from(Errno::EINVAL))
        .and_then(evaluate);
    match result {
        Ok(value) => json!({ "ok": value }),
        Err(error) => json!({ "err": error }),
    }
    .to_string()
}
