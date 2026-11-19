//! `findmnt` utility and shared `/proc/self/mountinfo` parser.
use os_core::cli::{parse, system::Findmnt};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MountRecord {
    pub id: u64,
    pub parent_id: u64,
    pub maj_min: String,
    pub root: String,
    pub target: String,
    pub mount_opts: String,
    pub optional_fields: Vec<String>,
    pub fstype: String,
    pub source: String,
    pub super_opts: String,
}

impl MountRecord {
    pub(crate) fn combined_options(&self) -> String {
        let mut out: Vec<&str> = Vec::new();
        for opt in self
            .mount_opts
            .split(',')
            .chain(self.super_opts.split(','))
            .filter(|s| !s.is_empty())
        {
            if !out.contains(&opt) {
                out.push(opt);
            }
        }
        out.join(",")
    }

    pub(crate) fn propagation(&self) -> String {
        let mut tags = Vec::new();
        for field in &self.optional_fields {
            if field == "shared" || field.starts_with("shared:") {
                if !tags.contains(&"shared") {
                    tags.push("shared");
                }
            } else if field == "master" || field.starts_with("master:") {
                if !tags.contains(&"slave") {
                    tags.push("slave");
                }
            } else if (field == "unbindable" || field.starts_with("unbindable:"))
                && !tags.contains(&"unbindable")
            {
                tags.push("unbindable");
            }
        }
        if tags.is_empty() {
            "private".to_string()
        } else {
            tags.join(",")
        }
    }

    pub(crate) fn display_source(&self) -> &str {
        if self.source.is_empty() {
            "none"
        } else {
            &self.source
        }
    }
}

/// Decode Linux `/proc/self/mountinfo` octal escapes (`\040`, `\011`, `\012`, `\134`, etc.).
pub(crate) fn unescape_mountinfo(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && (b'0'..=b'7').contains(&bytes[i + 1])
            && (b'0'..=b'7').contains(&bytes[i + 2])
            && (b'0'..=b'7').contains(&bytes[i + 3])
        {
            let val =
                ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(val);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_mountinfo(text: &str) -> Vec<MountRecord> {
    let mut records = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(sep) = tokens.iter().position(|tok| *tok == "-") else {
            continue;
        };
        if sep < 6 || sep + 2 >= tokens.len() {
            continue;
        }
        let Ok(id) = tokens[0].parse::<u64>() else {
            continue;
        };
        let Ok(parent_id) = tokens[1].parse::<u64>() else {
            continue;
        };
        let optional_fields = tokens[6..sep].iter().map(|s| (*s).to_string()).collect();
        let super_opts = tokens.get(sep + 3).copied().unwrap_or("").to_string();
        records.push(MountRecord {
            id,
            parent_id,
            maj_min: tokens[2].to_string(),
            root: unescape_mountinfo(tokens[3]),
            target: unescape_mountinfo(tokens[4]),
            mount_opts: unescape_mountinfo(tokens[5]),
            optional_fields,
            fstype: unescape_mountinfo(tokens[sep + 1]),
            source: unescape_mountinfo(tokens[sep + 2]),
            super_opts: unescape_mountinfo(&super_opts),
        });
    }
    records
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    Target,
    Source,
    Fstype,
    Options,
    Id,
    Parent,
    MajMin,
    Propagation,
    VfsOptions,
    FsOptions,
    Fsroot,
}

impl Column {
    fn parse_list(spec: Option<&str>) -> Result<Vec<Self>, String> {
        let Some(spec) = spec else {
            return Ok(vec![
                Self::Target,
                Self::Source,
                Self::Fstype,
                Self::Options,
            ]);
        };
        let mut cols = Vec::new();
        for raw in spec.split(',') {
            let name = raw.trim();
            if name.is_empty() {
                continue;
            }
            let col = match name.to_ascii_uppercase().as_str() {
                "TARGET" => Self::Target,
                "SOURCE" => Self::Source,
                "FSTYPE" => Self::Fstype,
                "OPTIONS" => Self::Options,
                "ID" => Self::Id,
                "PARENT" => Self::Parent,
                "MAJ:MIN" | "MAJ_MIN" => Self::MajMin,
                "PROPAGATION" => Self::Propagation,
                "VFS-OPTIONS" | "VFS_OPTIONS" => Self::VfsOptions,
                "FS-OPTIONS" | "FS_OPTIONS" => Self::FsOptions,
                "FSROOT" => Self::Fsroot,
                _ => return Err(format!("findmnt: unknown column: {name}")),
            };
            cols.push(col);
        }
        if cols.is_empty() {
            return Err("findmnt: empty column list".to_string());
        }
        Ok(cols)
    }

    fn header(self) -> &'static str {
        match self {
            Self::Target => "TARGET",
            Self::Source => "SOURCE",
            Self::Fstype => "FSTYPE",
            Self::Options => "OPTIONS",
            Self::Id => "ID",
            Self::Parent => "PARENT",
            Self::MajMin => "MAJ:MIN",
            Self::Propagation => "PROPAGATION",
            Self::VfsOptions => "VFS-OPTIONS",
            Self::FsOptions => "FS-OPTIONS",
            Self::Fsroot => "FSROOT",
        }
    }

    fn json_key(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Source => "source",
            Self::Fstype => "fstype",
            Self::Options => "options",
            Self::Id => "id",
            Self::Parent => "parent",
            Self::MajMin => "maj:min",
            Self::Propagation => "propagation",
            Self::VfsOptions => "vfs-options",
            Self::FsOptions => "fs-options",
            Self::Fsroot => "fsroot",
        }
    }

    fn value(self, rec: &MountRecord) -> String {
        match self {
            Self::Target => rec.target.clone(),
            Self::Source => rec.display_source().to_string(),
            Self::Fstype => rec.fstype.clone(),
            Self::Options => rec.combined_options(),
            Self::Id => rec.id.to_string(),
            Self::Parent => rec.parent_id.to_string(),
            Self::MajMin => rec.maj_min.clone(),
            Self::Propagation => rec.propagation(),
            Self::VfsOptions => rec.mount_opts.clone(),
            Self::FsOptions => rec.super_opts.clone(),
            Self::Fsroot => rec.root.clone(),
        }
    }

    fn json_value(self, rec: &MountRecord) -> Value {
        match self {
            Self::Id => json!(rec.id),
            Self::Parent => json!(rec.parent_id),
            other => json!(other.value(rec)),
        }
    }
}

fn check_unsupported_flags(args: &[String]) -> Result<(), String> {
    for arg in args {
        if arg == "--" {
            break;
        }
        for bad in [
            "--fstab", "--kernel", "--mtab", "--poll", "--df", "--task", "-s", "-k", "-m", "-p",
            "-D", "-N",
        ] {
            if arg == bad
                || (bad.starts_with("--") && arg.starts_with(&format!("{bad}=")))
                || (bad.len() == 2
                    && arg.starts_with('-')
                    && !arg.starts_with("--")
                    && arg[1..].starts_with(&bad[1..]))
            {
                return Err(format!("findmnt: unsupported option '{arg}'"));
            }
        }
    }
    Ok(())
}

fn normalize_path(raw: &str, cwd: Option<&str>) -> String {
    let joined = if raw.starts_with('/') {
        raw.to_string()
    } else if let Some(base) = cwd.filter(|c| !c.is_empty()) {
        if base == "/" {
            format!("/{raw}")
        } else {
            format!("{}/{raw}", base.trim_end_matches('/'))
        }
    } else {
        raw.to_string()
    };
    if !joined.starts_with('/') {
        let trimmed = joined.trim_end_matches('/');
        return if trimmed.is_empty() {
            ".".to_string()
        } else {
            trimmed.to_string()
        };
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn matches_fstype_filter(fstype: &str, filter: &str) -> bool {
    let mut positive = Vec::new();
    let mut negative = Vec::new();
    for item in filter.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(neg) = item.strip_prefix("no")
            && !neg.is_empty()
        {
            negative.push(neg);
        } else {
            positive.push(item);
        }
    }
    if negative.contains(&fstype) {
        return false;
    }
    positive.is_empty() || positive.contains(&fstype)
}

fn find_containing_mount(records: &[MountRecord], path: &str) -> Option<u64> {
    // Visible mounts: later entries at the same mountpoint shadow earlier ones.
    let mut visible: Vec<&MountRecord> = Vec::new();
    for rec in records {
        if let Some(slot) = visible.iter_mut().find(|r| r.target == rec.target) {
            *slot = rec;
        } else {
            visible.push(rec);
        }
    }
    visible
        .into_iter()
        .filter(|rec| {
            if rec.target == "/" {
                path.starts_with('/')
            } else {
                path == rec.target
                    || path
                        .strip_prefix(&rec.target)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
        })
        .max_by_key(|rec| rec.target.len())
        .map(|rec| rec.id)
}

fn expand_submounts(all: &[MountRecord], seeds: &BTreeSet<u64>) -> BTreeSet<u64> {
    let mut keep = seeds.clone();
    loop {
        let mut added = false;
        for rec in all {
            if rec.id != rec.parent_id && keep.contains(&rec.parent_id) && keep.insert(rec.id) {
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    keep
}

pub(crate) fn execute_with_mountinfo(
    args: &[String],
    mountinfo: &str,
    cwd: Option<&str>,
    canonicalize: impl Fn(&str) -> Option<String>,
) -> Result<(String, i32), (String, i32)> {
    if let Err(msg) = check_unsupported_flags(args) {
        return Err((msg, 2));
    }
    let opts = parse::<Findmnt>(args).map_err(|msg| (msg, 2))?;
    let cols = Column::parse_list(opts.output.as_deref()).map_err(|msg| (msg, 2))?;
    let all_records = parse_mountinfo(mountinfo);

    let has_filter = opts.types.is_some()
        || opts.mountpoint.is_some()
        || opts.target.is_some()
        || opts.positional_target.is_some();

    let mut matched_ids: Option<BTreeSet<u64>> = None;

    if let Some(mp) = &opts.mountpoint {
        let norm = canonicalize(mp).unwrap_or_else(|| normalize_path(mp, cwd));
        // When stacked mounts exist at `norm`, pick the topmost visible mount (or all if submounts).
        let ids: BTreeSet<u64> = all_records
            .iter()
            .rev()
            .find(|r| r.target == norm)
            .map(|r| r.id)
            .into_iter()
            .collect();
        matched_ids = Some(ids);
    }

    if let Some(tgt) = &opts.target {
        let resolved = canonicalize(tgt).unwrap_or_else(|| normalize_path(tgt, cwd));
        let id_set: BTreeSet<u64> = find_containing_mount(&all_records, &resolved)
            .into_iter()
            .collect();
        matched_ids = Some(match matched_ids {
            Some(prev) => prev.intersection(&id_set).copied().collect(),
            None => id_set,
        });
    }

    if opts.mountpoint.is_none()
        && opts.target.is_none()
        && let Some(pos) = &opts.positional_target
    {
        let norm = if pos.starts_with('/') || pos.starts_with('.') {
            canonicalize(pos).unwrap_or_else(|| normalize_path(pos, cwd))
        } else {
            pos.clone()
        };
        let mut ids: BTreeSet<u64> = all_records
            .iter()
            .filter(|r| r.target == norm || r.source == *pos || r.display_source() == pos)
            .map(|r| r.id)
            .collect();
        // If positional path is inside a mount rather than an exact mountpoint, match containing mount
        // when `pos` looks like a path and exists.
        if ids.is_empty()
            && (pos.starts_with('/') || pos.starts_with('.'))
            && let Some(canon) = canonicalize(pos)
            && let Some(id) = find_containing_mount(&all_records, &canon)
        {
            ids.insert(id);
        }
        matched_ids = Some(ids);
    }

    if opts.submounts
        && let Some(seeds) = &matched_ids
    {
        matched_ids = Some(expand_submounts(&all_records, seeds));
    }

    let selected: Vec<&MountRecord> = all_records
        .iter()
        .filter(|rec| matched_ids.as_ref().is_none_or(|ids| ids.contains(&rec.id)))
        .filter(|rec| {
            opts.types
                .as_deref()
                .is_none_or(|t| matches_fstype_filter(&rec.fstype, t))
        })
        .collect();

    if selected.is_empty() {
        if has_filter {
            return Ok((String::new(), 1));
        }
        if opts.json {
            return Ok((
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&json!({"filesystems": []})).unwrap()
                ),
                0,
            ));
        }
        return Ok((String::new(), 0));
    }

    let tree_mode = !opts.list && !opts.raw;
    if opts.json {
        let out = render_json(&selected, &cols, tree_mode);
        return Ok((format!("{out}\n"), 0));
    }

    let rows = if tree_mode {
        build_tree_rows(&selected, &cols)
    } else {
        selected
            .iter()
            .map(|rec| cols.iter().map(|c| c.value(rec)).collect::<Vec<_>>())
            .collect()
    };

    let mut out = String::new();
    if opts.raw {
        if !opts.noheadings {
            out.push_str(
                &cols
                    .iter()
                    .map(|c| c.header())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            out.push('\n');
        }
        for row in rows {
            let escaped: Vec<String> = row.iter().map(|cell| escape_raw_cell(cell)).collect();
            out.push_str(&escaped.join(" "));
            out.push('\n');
        }
    } else {
        let mut all_rows = Vec::new();
        if !opts.noheadings {
            all_rows.push(
                cols.iter()
                    .map(|c| c.header().to_string())
                    .collect::<Vec<_>>(),
            );
        }
        all_rows.extend(rows);
        let widths: Vec<usize> = (0..cols.len())
            .map(|i| {
                all_rows
                    .iter()
                    .map(|r| r[i].chars().count())
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        for row in all_rows {
            let mut line = String::new();
            for (idx, cell) in row.iter().enumerate() {
                if idx + 1 == cols.len() {
                    line.push_str(cell);
                } else {
                    let pad = widths[idx].saturating_sub(cell.chars().count()) + 1;
                    line.push_str(cell);
                    for _ in 0..pad {
                        line.push(' ');
                    }
                }
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
    }

    Ok((out, 0))
}

fn escape_raw_cell(cell: &str) -> String {
    let mut out = String::with_capacity(cell.len());
    for ch in cell.chars() {
        match ch {
            ' ' => out.push_str("\\x20"),
            '\t' => out.push_str("\\x09"),
            '\n' => out.push_str("\\x0a"),
            '\\' => out.push_str("\\x5c"),
            other => out.push(other),
        }
    }
    out
}

fn tree_structure<'a>(
    selected: &[&'a MountRecord],
) -> (Vec<&'a MountRecord>, BTreeMap<u64, Vec<&'a MountRecord>>) {
    let present: BTreeSet<u64> = selected.iter().map(|r| r.id).collect();
    let mut roots = Vec::new();
    let mut children: BTreeMap<u64, Vec<&'a MountRecord>> = BTreeMap::new();
    for &rec in selected {
        if rec.parent_id != rec.id && present.contains(&rec.parent_id) {
            children.entry(rec.parent_id).or_default().push(rec);
        } else {
            roots.push(rec);
        }
    }
    (roots, children)
}

fn build_tree_rows(selected: &[&MountRecord], cols: &[Column]) -> Vec<Vec<String>> {
    let (roots, children) = tree_structure(selected);
    let mut rows = Vec::new();
    fn visit(
        rec: &MountRecord,
        prefix: &str,
        connector: &str,
        is_root: bool,
        children: &BTreeMap<u64, Vec<&MountRecord>>,
        cols: &[Column],
        rows: &mut Vec<Vec<String>>,
    ) {
        let row: Vec<String> = cols
            .iter()
            .map(|&col| {
                let val = col.value(rec);
                if col == Column::Target && !is_root {
                    format!("{prefix}{connector}{val}")
                } else {
                    val
                }
            })
            .collect();
        rows.push(row);
        if let Some(kids) = children.get(&rec.id) {
            for (idx, &kid) in kids.iter().enumerate() {
                let last = idx + 1 == kids.len();
                let next_conn = if last { "└─" } else { "├─" };
                let next_prefix = if is_root {
                    String::new()
                } else if connector == "├─" {
                    format!("{prefix}│ ")
                } else {
                    format!("{prefix}  ")
                };
                visit(kid, &next_prefix, next_conn, false, children, cols, rows);
            }
        }
    }
    for root in roots {
        visit(root, "", "", true, &children, cols, &mut rows);
    }
    rows
}

fn render_json(selected: &[&MountRecord], cols: &[Column], tree_mode: bool) -> String {
    fn node_obj(
        rec: &MountRecord,
        cols: &[Column],
        children: Option<&BTreeMap<u64, Vec<&MountRecord>>>,
    ) -> Value {
        let mut map = Map::new();
        for &col in cols {
            map.insert(col.json_key().to_string(), col.json_value(rec));
        }
        if let Some(tree) = children
            && let Some(kids) = tree.get(&rec.id)
            && !kids.is_empty()
        {
            let arr: Vec<Value> = kids
                .iter()
                .map(|&kid| node_obj(kid, cols, Some(tree)))
                .collect();
            map.insert("children".to_string(), Value::Array(arr));
        }
        Value::Object(map)
    }

    let filesystems: Vec<Value> = if tree_mode {
        let (roots, children) = tree_structure(selected);
        roots
            .into_iter()
            .map(|r| node_obj(r, cols, Some(&children)))
            .collect()
    } else {
        selected.iter().map(|&r| node_obj(r, cols, None)).collect()
    };

    let mut top = Map::new();
    top.insert("filesystems".to_string(), Value::Array(filesystems));
    serde_json::to_string_pretty(&Value::Object(top))
        .unwrap_or_else(|_| "{\"filesystems\":[]}".into())
}

pub fn run(args: &[String]) -> i32 {
    if let Err(msg) = check_unsupported_flags(args) {
        eprintln!("{msg}");
        return 2;
    }
    let mountinfo = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(text) => text,
        Err(err) => {
            eprintln!("findmnt: cannot read /proc/self/mountinfo: {err}");
            return 1;
        }
    };
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let canon = |p: &str| {
        Path::new(p)
            .canonicalize()
            .ok()
            .map(|c| c.to_string_lossy().into_owned())
    };
    match execute_with_mountinfo(args, &mountinfo, cwd.as_deref(), canon) {
        Ok((out, code)) => {
            if !out.is_empty() && io::stdout().write_all(out.as_bytes()).is_err() {
                return 1;
            }
            code
        }
        Err((msg, code)) => {
            eprintln!("{msg}");
            code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MOUNTINFO: &str = "\
1 1 0:1 / / rw,relatime shared:1 - r2 r2 rw
2 1 0:2 / /proc rw,nosuid,nodev,noexec - proc proc rw
3 1 0:3 / /mnt/work\\040dir rw,nodev - tmpfs scratch rw,size=65536k
4 3 0:4 /sub\\134path /mnt/work\\040dir/nested ro master:2 - overlay lower\\011tab ro
";

    fn s(list: &[&str]) -> Vec<String> {
        list.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn parses_mountinfo_octal_escapes_propagation_and_combined_options() {
        let recs = parse_mountinfo(SAMPLE_MOUNTINFO);
        assert_eq!(recs.len(), 4);
        assert_eq!(recs[0].propagation(), "shared");
        assert_eq!(recs[1].propagation(), "private");
        assert_eq!(recs[2].target, "/mnt/work dir");
        assert_eq!(recs[2].combined_options(), "rw,nodev,size=65536k");
        assert_eq!(recs[3].root, "/sub\\path");
        assert_eq!(recs[3].source, "lower\ttab");
        assert_eq!(recs[3].propagation(), "slave");
    }

    #[test]
    fn renders_tree_list_raw_and_json_modes() {
        let (tree, code) =
            execute_with_mountinfo(&[], SAMPLE_MOUNTINFO, Some("/"), |_| None).expect("tree");
        assert_eq!(code, 0);
        assert!(tree.contains("TARGET"), "tree={tree}");
        assert!(tree.contains("├─/proc"), "tree={tree}");
        assert!(tree.contains("└─/mnt/work dir"), "tree={tree}");
        assert!(tree.contains("  └─/mnt/work dir/nested"), "tree={tree}");

        let (json_out, code) = execute_with_mountinfo(
            &s(&["-J", "-o", "TARGET,FSTYPE,ID,PROPAGATION"]),
            SAMPLE_MOUNTINFO,
            Some("/"),
            |_| None,
        )
        .expect("json tree");
        assert_eq!(code, 0);
        let parsed: Value = serde_json::from_str(&json_out).expect("valid json");
        let root = &parsed["filesystems"][0];
        assert_eq!(root["target"], "/");
        assert_eq!(root["id"], 1);
        assert_eq!(root["propagation"], "shared");
        assert_eq!(root["children"].as_array().unwrap().len(), 2);

        let (raw_out, code) = execute_with_mountinfo(
            &s(&["-r", "-n", "-t", "tmpfs", "-o", "TARGET,SOURCE"]),
            SAMPLE_MOUNTINFO,
            Some("/"),
            |_| None,
        )
        .expect("raw");
        assert_eq!(code, 0);
        assert_eq!(raw_out, "/mnt/work\\x20dir scratch\n");
    }

    #[test]
    fn filters_mountpoint_target_submounts_and_rejects_unsupported_flags() {
        let (_, miss_code) = execute_with_mountinfo(
            &s(&["-M", "/mnt/work dir/not-a-mount"]),
            SAMPLE_MOUNTINFO,
            Some("/"),
            |_| None,
        )
        .expect("missing mountpoint");
        assert_eq!(miss_code, 1);

        let (target_out, hit_code) = execute_with_mountinfo(
            &s(&["-l", "-n", "-T", "/mnt/work dir/file.txt", "-o", "TARGET"]),
            SAMPLE_MOUNTINFO,
            Some("/"),
            |_| None,
        )
        .expect("containing mount");
        assert_eq!(hit_code, 0);
        assert_eq!(target_out, "/mnt/work dir\n");

        let (sub_out, sub_code) = execute_with_mountinfo(
            &s(&["-l", "-n", "-M", "/mnt/work dir", "-R", "-o", "TARGET"]),
            SAMPLE_MOUNTINFO,
            Some("/"),
            |_| None,
        )
        .expect("submounts");
        assert_eq!(sub_code, 0);
        assert_eq!(sub_out, "/mnt/work dir\n/mnt/work dir/nested\n");

        let (err_msg, err_code) =
            execute_with_mountinfo(&s(&["--fstab"]), SAMPLE_MOUNTINFO, Some("/"), |_| None)
                .expect_err("fstab rejected");
        assert_eq!(err_code, 2);
        assert!(err_msg.contains("unsupported option"));
    }
}
