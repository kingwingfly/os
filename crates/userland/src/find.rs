//! fd: what is below its roots, a level a batch, matched as core's `find` says. Running a
//! command on each (-x, -X) is the terminal's, on what this finds.
use crate::files::shown_path;
use crate::io::Io;
use crate::sys::Sys;
use crate::walk;

/// The most results fd gives.
const FD_MAX: usize = 50_000;

pub async fn fd(sys: &impl Sys, io: &mut Io<'_>) -> i32 {
    let find = match terminal_worker_core::find::parse(io.rest()) {
        Ok(find) => find,
        Err(error) => {
            io.fail(error);
            return 1;
        }
    };
    let cwd = shown_path(&io.cwd);
    let roots: Vec<(Option<String>, String)> = if find.roots.is_empty() {
        vec![(None, cwd.clone())]
    } else {
        find.roots
            .iter()
            .map(|typed| (Some(typed.clone()), shown_path(&io.path(typed))))
            .collect()
    };
    let mut found = Vec::new();
    let mut hidden = 0;
    let mut status = 0;
    for (typed, root) in roots {
        if let Err(error) = crate::sys::getdents(sys, &root).await {
            io.fail(format!("fd: {}: {error}", typed.as_deref().unwrap_or(".")));
            status = 1;
            continue;
        }
        let tree = walk::below(sys, &root, find.max_depth, io.cancelled).await;
        hidden += tree.unread.len();
        for entry in tree.found {
            let Some(stat) = entry.stat else { continue };
            if find.matches(
                &root,
                &entry.abs,
                stat.is_dir(),
                stat.is_link(),
                stat.perm(),
            ) {
                found.push(find.display(typed.as_deref(), &root, &cwd, &entry.abs));
            }
        }
        if found.len() > FD_MAX {
            io.fail(format!("fd: more than {FD_MAX} results; narrow the search"));
            return 1;
        }
    }
    if hidden > 0 {
        io.fail(format!(
            "fd: {hidden} director{} could not be read, so {} not searched",
            if hidden == 1 { "y" } else { "ies" },
            if hidden == 1 { "it was" } else { "they were" }
        ));
    }
    let separator = if find.null { '\0' } else { '\n' };
    io.out = found
        .iter()
        .map(|path| format!("{path}{separator}"))
        .collect();
    io.found = found;
    status
}
