use ed25519_dalek::{Signer, SigningKey};
use os_image::*;
use std::collections::BTreeMap;

fn entry(path: &str, node: Node) -> Entry {
    Entry {
        path: path.into(),
        uid: 0,
        gid: 0,
        mode: 0o755,
        node,
    }
}
fn dir(path: &str) -> Entry {
    entry(path, Node::Directory)
}
fn file(path: &str) -> Entry {
    entry(
        path,
        Node::File {
            sha256: digest(b"test"),
            size: 4,
        },
    )
}
fn link(path: &str, target: &str) -> Entry {
    entry(
        path,
        Node::Symlink {
            target: target.into(),
        },
    )
}
fn image(kind: Kind, mut entries: Vec<Entry>) -> Image {
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Image {
        format: "os.image".into(),
        version: 1,
        kind,
        name: "test".into(),
        revision: "1".into(),
        abi: ABI,
        features: vec![],
        level: LEVEL,
        provenance: BTreeMap::new(),
        entries,
    }
}
fn base() -> Image {
    image(
        Kind::Base,
        vec![
            dir("/"),
            dir("/usr"),
            dir("/usr/bin"),
            file("/usr/bin/echo"),
            link("/bin", "usr/bin"),
            dir("/etc"),
            dir("/opt"),
        ],
    )
}
fn signed(bytes: &[u8], domain: &str, key: &SigningKey) -> Vec<u8> {
    serde_json::to_vec(&Detached {
        format: "os.signature".into(),
        version: 1,
        key: digest(key.verifying_key().as_bytes()),
        signature: hex(&key
            .sign(&signing_message(domain, bytes).unwrap())
            .to_bytes()),
    })
    .unwrap()
}

#[test]
fn private_composition_preserves_validation_without_a_system_base() {
    let extension = image(
        Kind::Sysext,
        vec![dir("/"), dir("/opt"), file("/opt/probe")],
    );
    let config = image(
        Kind::Confext,
        vec![dir("/"), dir("/etc"), file("/etc/probe")],
    );
    let view = Composition::private(&[extension.clone(), config]).unwrap();
    assert!(view.entries.contains_key("/opt/probe"));
    assert!(view.entries.contains_key("/etc/probe"));
    assert!(Composition::private(&[]).is_err());
    assert!(Composition::private(&[base()]).is_err());
    assert!(Composition::private(&[extension.clone(), extension.clone()]).is_err());
    let mut privileged = extension.clone();
    privileged.entries.last_mut().unwrap().mode = 0o4755;
    assert!(Composition::private(&[privileged]).is_err());
    let escaping = image(
        Kind::Sysext,
        vec![dir("/"), dir("/opt"), link("/opt/link", "../../outside")],
    );
    assert!(Composition::private(&[escaping]).is_err());
    assert!(Composition::private(&vec![extension; 17]).is_err());
}

#[test]
fn duplicate_keys_are_rejected_at_all_depths_before_typed_parsing() {
    for bytes in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":[{"x":1,"\u0078":2}]}"#,
        br#"{"a":null} trailing"#,
    ] {
        assert!(parse::<serde_json::Value>(bytes).is_err());
    }
    assert!(parse::<serde_json::Value>(&vec![b' '; MANIFEST_MAX + 1]).is_err());
    assert!(parse::<serde_json::Value>(&[vec![b'['; 130], vec![b']'; 130]].concat()).is_err());
}
#[test]
fn metadata_and_versions_fail_closed() {
    let mut v = serde_json::to_value(base()).unwrap();
    for (field, value) in [
        ("acl", serde_json::json!([])),
        ("version", serde_json::json!(2)),
        ("features", serde_json::json!(["unknown"])),
    ] {
        let mut v = v.clone();
        v[field] = value;
        assert!(Image::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    v["entries"][0]["xattrs"] = serde_json::json!({"security.capability":"x"});
    assert!(Image::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    let mut b = base();
    b.entries[0].mode = 0o4755;
    assert!(b.validate().is_err());
    b = base();
    b.entries.reverse();
    assert!(b.validate().is_err());
    b = base();
    b.entries.push(b.entries.last().unwrap().clone());
    assert!(b.validate().is_err());
}
#[test]
fn paths_are_normalized_and_unicode_is_preserved() {
    for path in [
        "usr/a",
        "/usr/../etc",
        "/usr//a",
        "/usr/./a",
        "/usr/a/",
        "/usr/a\0b",
    ] {
        assert!(!valid_path(path));
    }
    let b = image(Kind::Base, vec![dir("/"), dir("/usr"), file("/usr/你好")]);
    assert!(Composition::new(&b, &[]).is_ok());
    assert_eq!(Image::parse(&serde_json::to_vec(&b).unwrap()).unwrap(), b);
}
#[test]
fn collision_and_directory_metadata_are_checked_across_layers() {
    let good = image(
        Kind::Sysext,
        vec![dir("/usr"), dir("/usr/bin"), file("/usr/bin/new")],
    );
    assert!(Composition::new(&base(), std::slice::from_ref(&good)).is_ok());
    let conflict = image(Kind::Sysext, vec![file("/usr/bin/echo")]);
    assert!(Composition::new(&base(), &[conflict]).is_err());
    let mut bad = good;
    bad.entries[0].gid = 123;
    assert!(Composition::new(&base(), &[bad]).is_err());
    let bad = image(Kind::Sysext, vec![file("/usr/bin")]);
    assert!(Composition::new(&base(), &[bad]).is_err());
}
#[test]
fn physical_resolution_prevents_alias_and_symlink_escapes() {
    assert_eq!(
        Composition::new(&base(), &[])
            .unwrap()
            .resolve("/bin/echo")
            .unwrap(),
        "/usr/bin/echo"
    );
    for entries in [
        vec![link("/usr/leak", "../../etc/passwd")],
        vec![link("/usr/leak", "/etc")],
        vec![link("/usr/a", "b"), link("/usr/b", "a")],
        vec![link("/usr/a", "bin"), file("/usr/a/hidden")],
        vec![file("/usr/missing/child")],
        vec![link("/usr/a", "bin/echo/../echo")],
    ] {
        assert!(Composition::new(&base(), &[image(Kind::Sysext, entries)]).is_err());
    }
    let good = image(Kind::Sysext, vec![link("/usr/a", "../usr/bin/echo")]);
    assert!(Composition::new(&base(), &[good]).is_ok());
}
#[test]
fn configuration_cannot_replace_identity_or_escape_managed_etc() {
    for path in [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers.d/admin",
        "/usr/bin/x",
    ] {
        assert!(image(Kind::Confext, vec![file(path)]).validate().is_err());
    }
    let config = image(
        Kind::Confext,
        vec![dir("/etc/example"), file("/etc/example/service.json")],
    );
    let composed = Composition::new(&base(), &[config]).unwrap();
    assert!(composed.entries.contains_key("/etc/example/service.json"));
    assert!(!composed.entries.contains_key("/etc/passwd"));
}
#[test]
fn signature_binds_exact_bytes_domain_and_operator_trust() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let id = digest(key.verifying_key().as_bytes());
    let mut trust = Trust::default();
    trust
        .keys
        .insert(id.clone(), hex(key.verifying_key().as_bytes()));
    let bytes = serde_json::to_vec(&base()).unwrap();
    let signature = signed(&bytes, "os.image.v1", &key);
    assert_eq!(trust.verify("os.image.v1", &bytes, &signature).unwrap(), id);
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(trust.verify("os.image.v1", &changed, &signature).is_err());
    assert!(trust.verify("os.release.v1", &bytes, &signature).is_err());
    assert!(
        Trust::default()
            .verify("os.image.v1", &bytes, &signature)
            .is_err()
    );
    trust.revoked.insert(id);
    assert!(trust.verify("os.image.v1", &bytes, &signature).is_err());
}
#[test]
fn rotation_preserves_allowed_old_publishers_and_revocation_wins() {
    let old = SigningKey::from_bytes(&[1; 32]);
    let new = SigningKey::from_bytes(&[2; 32]);
    let mut trust = Trust::default();
    for key in [&old, &new] {
        trust.keys.insert(
            digest(key.verifying_key().as_bytes()),
            hex(key.verifying_key().as_bytes()),
        );
    }
    for key in [&old, &new] {
        assert!(
            trust
                .verify("os.image.v1", b"{}", &signed(b"{}", "os.image.v1", key))
                .is_ok()
        );
    }
    trust.revoked.insert(digest(old.verifying_key().as_bytes()));
    assert!(
        trust
            .verify("os.image.v1", b"{}", &signed(b"{}", "os.image.v1", &old))
            .is_err()
    );
    assert!(
        trust
            .verify("os.image.v1", b"{}", &signed(b"{}", "os.image.v1", &new))
            .is_ok()
    );
}
#[test]
fn release_compatibility_rejects_rollback_into_incompatible_state() {
    let mut r = Release {
        format: "os.release".into(),
        version: 1,
        name: "test".into(),
        boot: digest(b"boot"),
        base: digest(b"base"),
        sysext: vec![],
        confext: vec![],
        protocol: Range { min: 1, max: 1 },
        schema: Range { min: 7, max: 7 },
        provenance: BTreeMap::new(),
    };
    assert!(r.validate().is_ok());
    r.schema.max = 6;
    assert!(r.validate().is_err());
    r.schema.max = 7;
    r.protocol.min = 2;
    assert!(r.validate().is_err());
    r.protocol.min = 1;
    r.sysext.push(r.base.clone());
    assert!(r.validate().is_err());
}
