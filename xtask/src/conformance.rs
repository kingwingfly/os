use crate::Result;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

pub fn run(args: Vec<String>) -> Result<()> {
    let args = resolve_out(args, &std::env::current_dir()?)?;
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

fn resolve_out(mut args: Vec<String>, cwd: &Path) -> Result<Vec<String>> {
    let absolute = |value: &str| -> Result<String> {
        if value.is_empty() {
            return Err("--out needs a directory".into());
        }
        let path = PathBuf::from(value);
        Ok(if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        }
        .to_string_lossy()
        .into_owned())
    };
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--out" {
            i += 1;
            let value = args.get_mut(i).ok_or("--out needs a directory")?;
            if value.starts_with("--") {
                return Err("--out needs a directory".into());
            }
            *value = absolute(value)?;
        } else if let Some(value) = args[i].strip_prefix("--out=") {
            args[i] = format!("--out={}", absolute(value)?);
        }
        i += 1;
    }
    Ok(args)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_is_relative_to_caller() {
        let cwd = Path::new("/repo/subdir");
        for (input, expected) in [
            (
                vec!["--out", "results"],
                vec!["--out", "/repo/subdir/results"],
            ),
            (vec!["--out=results"], vec!["--out=/repo/subdir/results"]),
            (vec!["--out", "/tmp/results"], vec!["--out", "/tmp/results"]),
            (vec!["--target", "linux"], vec!["--target", "linux"]),
        ] {
            assert_eq!(
                resolve_out(input.into_iter().map(str::to_owned).collect(), cwd).unwrap(),
                expected
            );
        }
        for args in [vec!["--out"], vec!["--out="], vec!["--out", "--check"]] {
            assert!(resolve_out(args.into_iter().map(str::to_owned).collect(), cwd).is_err());
        }
    }
}
