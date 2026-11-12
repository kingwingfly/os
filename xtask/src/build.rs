use crate::{Result, package};
use os_image::digest;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, fs, path::Path, process::Command};

const RECORD: &str = "build-provenance.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: String,
    version: u32,
    inputs: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
}

// Hash exact output bytes. Retained releases are separate build products; the record
// itself cannot hash itself. Symlinks/special files are never accepted as build output.
fn files(root: &Path, output: bool) -> Result<BTreeMap<String, String>> {
    fn walk(
        root: &Path,
        path: &Path,
        output: bool,
        result: &mut BTreeMap<String, String>,
    ) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            let name = path.strip_prefix(root)?.to_str().ok_or("non-UTF8 output")?;
            if output && matches!(name, RECORD | "boot") {
                continue;
            }
            let kind = fs::symlink_metadata(&path)?.file_type();
            if kind.is_dir() {
                walk(root, &path, output, result)?;
            } else if kind.is_file() {
                result.insert(name.into(), digest(&fs::read(path)?));
            } else {
                return Err("build output must contain regular files/directories".into());
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, output, &mut result)?;
    Ok(result)
}

pub fn run(args: Vec<String>) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace root missing")?;
    let caller = env::current_dir()?;
    let mut out = root.join("dist");
    let mut content = None;
    let mut web_only = false;
    let mut options = args.iter();
    while let Some(option) = options.next() {
        match option.as_str() {
            "--out-dir" => out = caller.join(options.next().ok_or("missing output directory")?),
            "--content" => {
                content = Some(caller.join(options.next().ok_or("missing content file")?))
            }
            "--web-only" => web_only = true,
            _ => return Err(format!("unknown build option {option}").into()),
        }
    }
    let inputs = || -> Result<BTreeMap<String, String>> {
        let mut inputs = package::provenance()?;
        inputs.insert("build.web-only".into(), web_only.to_string());
        // Record compiler flags without capturing unrelated (possibly secret) environment.
        for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CFLAGS", "AR"] {
            if let Ok(value) = env::var(name) {
                inputs.insert(format!("env.{name}"), value);
            }
        }
        if let Some(path) = &content {
            let bytes = fs::read(path)?;
            let config: serde_json::Value = serde_json::from_slice(&bytes)?;
            inputs.insert("content.config.sha256".into(), digest(&bytes));
            if let Some(assets) = config["assets"].as_str() {
                let tree = path.parent().ok_or("missing content parent")?.join(assets);
                inputs.insert(
                    "content.assets.sha256".into(),
                    digest(&serde_json::to_vec(&files(&tree, false)?)?),
                );
            }
        }
        Ok(inputs)
    };
    let before = inputs()?;
    // Invalidate an earlier success before building into the same output directory.
    if out.join(RECORD).exists() {
        fs::remove_file(out.join(RECORD))?;
    }
    let status = Command::new("node")
        .arg(root.join("scripts/build.mjs"))
        .args(args)
        .status()?;
    if !status.success() {
        return Err("asset build failed".into());
    }
    if inputs()? != before {
        return Err("build inputs changed during assembly; rebuild before packaging".into());
    }
    let record = Record {
        format: "os.build".into(),
        version: 1,
        inputs: before,
        files: files(&out, true)?,
    };
    package::replace(&out.join(RECORD), &serde_json::to_vec(&record)?)
}

pub fn verify(assets: &Path) -> Result<BTreeMap<String, String>> {
    let bytes = fs::read(assets.join(RECORD))
        .map_err(|_| "missing build provenance; run cargo xtask build")?;
    let record: Record = serde_json::from_slice(&bytes)?;
    if record.format != "os.build" || record.version != 1 || record.inputs.is_empty() {
        return Err("invalid build provenance".into());
    }
    if files(assets, true)? != record.files {
        return Err("assets differ from the recorded build; rebuild before packaging".into());
    }
    let mut inputs = record.inputs;
    inputs.insert("build.record.sha256".into(), digest(&bytes));
    Ok(inputs)
}
