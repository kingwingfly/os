use crate::{Entry, Error, Image, Kind, Node, Result, parent, protected, require, valid_path};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Composition {
    pub entries: BTreeMap<String, Entry>,
}
impl Composition {
    pub fn new(base: &Image, extensions: &[Image]) -> Result<Self> {
        require(base.kind == Kind::Base, "composition needs a base image")?;
        let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
        for image in std::iter::once(base).chain(extensions) {
            image.validate()?;
            require(
                matches!(image.kind, Kind::Base | Kind::Sysext | Kind::Confext),
                "unsupported composition image kind",
            )?;
            if !std::ptr::eq(image, base) {
                require(image.kind != Kind::Base, "only one base is permitted")?;
            }
            for entry in &image.entries {
                if let Some(existing) = entries.get(&entry.path) {
                    require(
                        matches!(existing.node, Node::Directory) && existing == entry,
                        "image collision or inconsistent shared-directory metadata",
                    )?;
                } else {
                    entries.insert(entry.path.clone(), entry.clone());
                }
            }
        }
        // Every ancestor must be an explicit directory, never a symlink. This closes
        // /usr/link/file and cross-image aliases rather than relying on lexical checks.
        for entry in entries.values() {
            if entry.path != "/" {
                require(
                    entries
                        .get(parent(&entry.path))
                        .is_some_and(|p| matches!(p.node, Node::Directory)),
                    "missing/non-directory image parent",
                )?;
            }
        }
        let composition = Self { entries };
        for image in std::iter::once(base).chain(extensions) {
            for entry in &image.entries {
                if matches!(entry.node, Node::Symlink { .. }) {
                    let physical = composition.resolve(&entry.path)?;
                    require(
                        !protected(&physical) && image.allows(&physical, false),
                        "image symlink escapes its roots",
                    )?;
                }
            }
        }
        Ok(composition)
    }
    pub fn resolve(&self, path: &str) -> Result<String> {
        require(valid_path(path), "invalid lookup path")?;
        let mut todo: std::collections::VecDeque<String> = path
            .split('/')
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect();
        let mut parts: Vec<String> = Vec::new();
        let mut links = 0;
        while let Some(part) = todo.pop_front() {
            match part.as_str() {
                "." | "" => continue,
                ".." => {
                    require(parts.pop().is_some(), "symlink escapes filesystem root")?;
                    continue;
                }
                _ => {}
            }
            parts.push(part);
            let path = format!("/{}", parts.join("/"));
            let entry = self
                .entries
                .get(&path)
                .ok_or_else(|| Error("dangling image symlink".into()))?;
            if let Node::Symlink { target } = &entry.node {
                links += 1;
                require(links <= 40, "image symlink loop")?;
                parts.pop();
                if target.starts_with('/') {
                    parts.clear();
                }
                for part in target.split('/').rev() {
                    todo.push_front(part.into());
                }
            } else if !todo.is_empty() {
                require(
                    matches!(entry.node, Node::Directory),
                    "symlink traverses non-directory",
                )?;
            }
        }
        Ok(format!("/{}", parts.join("/")))
    }
}
