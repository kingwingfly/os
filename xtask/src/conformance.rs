use crate::Result;
use std::{path::Path, process::Command};

pub fn run(args: Vec<String>) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let status = Command::new("node")
        .arg(root.join("scripts/conformance/run.mjs"))
        .args(args)
        .current_dir(root)
        .status()?;
    if !status.success() {
        return Err(format!("conformance runner exited with {status}").into());
    }
    Ok(())
}
