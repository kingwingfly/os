mod build;
mod package;
use ed25519_dalek::{Signer, SigningKey};
use os_image::{Detached, Image, Kind, Release, Trust, digest, hex, signing_message, unhex};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const HELP: &str = "cargo xtask build [build.mjs options]\n\
cargo xtask image --root TREE --kind base|sysext|confext|workload --out PACKAGE [--name NAME] [--revision REV]\n\
cargo xtask boot --assets DIST --out BUNDLE [--name NAME] [--sysext PACKAGE] [--confext PACKAGE]\n\
cargo xtask verify --bundle BUNDLE --trust PUBLIC_TRUST_JSON\n\
cargo xtask verify --bundle BUNDLE --unsigned-development\n\
cargo xtask sign --bundle BUNDLE --key-file PRIVATE_SEED_FILE\n\
Signing is explicit. The key file contains a 32-byte Ed25519 seed (or 64 lowercase hex digits).\n\
Build/assembly do not deploy, create keys, or modify production data.";

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        println!("{HELP}");
        return Ok(());
    };
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if command == "build" {
        return build::run(args.collect());
    }
    let mut options: BTreeMap<String, Vec<String>> = BTreeMap::new();
    while let Some(key) = args.next() {
        if key == "--unsigned-development" {
            options.entry(key).or_default().push("true".into());
            continue;
        }
        if !key.starts_with("--") {
            return Err(format!("unexpected argument {key}").into());
        }
        options.entry(key.clone()).or_default().push(
            args.next()
                .ok_or_else(|| format!("missing value for {key}"))?,
        );
    }
    let allowed: &[&str] = match command.as_str() {
        "image" => &["--root", "--kind", "--out", "--name", "--revision"],
        "boot" => &["--assets", "--out", "--name", "--sysext", "--confext"],
        "verify" => &["--bundle", "--trust", "--unsigned-development"],
        "sign" => &["--bundle", "--key-file"],
        _ => return Err(format!("unknown command {command}\n{HELP}").into()),
    };
    for (key, values) in &options {
        if !allowed.contains(&key.as_str())
            || (values.len() != 1 && !matches!(key.as_str(), "--sysext" | "--confext"))
        {
            return Err(format!("unknown/duplicate option {key}").into());
        }
    }
    let get = |key: &str| options.get(key).and_then(|v| v.first()).map(String::as_str);
    let required = |key: &str| get(key).ok_or_else(|| format!("missing {key}"));
    match command.as_str() {
        "image" => {
            let kind = match required("--kind")? {
                "base" => Kind::Base,
                "sysext" => Kind::Sysext,
                "confext" => Kind::Confext,
                "workload" => Kind::Workload,
                _ => return Err("invalid image kind".into()),
            };
            let image = package::tree(
                Path::new(required("--root")?),
                kind,
                get("--name").unwrap_or("local"),
                get("--revision").unwrap_or("1"),
                Path::new(required("--out")?),
            )?;
            println!("{}", image);
        }
        "boot" => {
            let paths = |key: &str| {
                options
                    .get(key)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            };
            let id = package::boot(
                Path::new(required("--assets")?),
                Path::new(required("--out")?),
                get("--name").unwrap_or("local"),
                &paths("--sysext"),
                &paths("--confext"),
            )?;
            println!("{id}");
        }
        "verify" => {
            if get("--trust").is_some() == get("--unsigned-development").is_some() {
                return Err("choose --trust or explicit --unsigned-development".into());
            }
            let trust: Option<Trust> = get("--trust")
                .map(|path| {
                    fs::read(path)
                        .map_err(Box::<dyn std::error::Error>::from)
                        .and_then(|b| Ok(os_image::parse(&b)?))
                })
                .transpose()?;
            let id = package::verify(Path::new(required("--bundle")?), trust.as_ref())?;
            println!(
                "verified {id} ({})",
                if trust.is_some() {
                    "signed"
                } else {
                    "unsigned development; not approved for shared activation"
                }
            );
        }
        "sign" => {
            let bundle = Path::new(required("--bundle")?);
            let id = package::verify(bundle, None)?;
            let mut bytes = fs::read(required("--key-file")?)?;
            let mut seed: [u8; 32] = if bytes.len() == 32 {
                bytes.as_slice().try_into()?
            } else {
                unhex(std::str::from_utf8(&bytes)?.trim())?
            };
            let key = SigningKey::from_bytes(&seed);
            seed.fill(0);
            bytes.fill(0);
            let release_bytes = fs::read(bundle.join("release.json"))?;
            let release = Release::parse(&release_bytes)?;
            let sign = |domain: &str, data: &[u8]| -> Result<Vec<u8>> {
                Ok(serde_json::to_vec(&Detached {
                    format: "os.signature".into(),
                    version: 1,
                    key: digest(key.verifying_key().as_bytes()),
                    signature: hex(&key.sign(&signing_message(domain, data)?).to_bytes()),
                })?)
            };
            for image in release.images() {
                let data = fs::read(bundle.join(format!("images/{image}.json")))?;
                Image::parse(&data)?;
                package::replace(
                    &bundle.join(format!("images/{image}.sig")),
                    &sign("os.image.v1", &data)?,
                )?;
            }
            package::replace(
                &bundle.join(format!("releases/{id}/signature.json")),
                &sign("os.release.v1", &release_bytes)?,
            )?;
            let mut trust = Trust::default();
            trust.keys.insert(
                digest(key.verifying_key().as_bytes()),
                hex(key.verifying_key().as_bytes()),
            );
            package::replace(&bundle.join("publisher.json"), &serde_json::to_vec(&trust)?)?;
            package::verify(bundle, Some(&trust))?;
            println!("signed {id}; publisher.json contains public key material only");
        }
        _ => unreachable!(),
    }
    Ok(())
}
