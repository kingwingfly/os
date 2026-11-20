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
fn file_bytes(path: &str, bytes: &[u8]) -> Entry {
    entry(
        path,
        Node::File {
            sha256: digest(bytes),
            size: bytes.len() as u64,
            chunk_size: CHUNK_SIZE_DEFAULT,
            chunks: chunk_digests(bytes, CHUNK_SIZE_DEFAULT).unwrap(),
        },
    )
}
fn file(path: &str) -> Entry {
    file_bytes(path, b"test")
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
        version: IMAGE_VERSION,
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
fn initramfs() -> Image {
    image(
        Kind::Initramfs,
        vec![
            dir("/"),
            dir("/bin"),
            dir("/dev"),
            dir("/proc"),
            dir("/run"),
            dir("/sysroot"),
            dir("/tmp"),
            dir("/usr"),
            file_bytes("/init", b"\0asm\x01\0\0\0init"),
            file_bytes("/bin/utilities", b"\0asm\x01\0\0\0util"),
            file_bytes("/bin/dash", b"\0asm\x01\0\0\0dash"),
            link("/bin/mount", "utilities"),
            link("/bin/switch_root", "utilities"),
            link("/bin/cowfsck", "utilities"),
            link("/bin/sh", "dash"),
        ],
    )
}
fn root_template() -> Image {
    image(
        Kind::RootTemplate,
        vec![
            dir("/"),
            dir("/etc"),
            dir("/var"),
            dir("/root"),
            dir("/home"),
            file_bytes("/etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n"),
            file_bytes("/etc/group", b"root:x:0:\nwheel:x:10:root\n"),
        ],
    )
}
fn boot_image() -> Image {
    image(
        Kind::Boot,
        vec![
            dir("/"),
            file_bytes("/index.html", b"<!doctype html>"),
            file_bytes("/client-kernel.js", b"// kernel"),
            file_bytes("/client_kernel_bg.wasm", b"\0asm\x01\0\0\0"),
        ],
    )
}
fn release_v2() -> ReleaseV2 {
    ReleaseV2 {
        format: "os.release".into(),
        version: RELEASE_VERSION,
        name: "test".into(),
        loader: LoaderMeta {
            entry: "/index.html".into(),
            client_kernel_js: "/client-kernel.js".into(),
            client_kernel_wasm: "/client_kernel_bg.wasm".into(),
            client_kernel_sha256: digest(b"\0asm\x01\0\0\0"),
            host_adapter: Range {
                min: HOST_ADAPTER,
                max: HOST_ADAPTER,
            },
        },
        boot: digest(b"boot"),
        initramfs: digest(b"initramfs"),
        root_template: digest(b"root-template"),
        base: digest(b"base"),
        sysext: vec![],
        confext: vec![],
        protocol: Range {
            min: PROTOCOL,
            max: PROTOCOL,
        },
        schema: Range {
            min: SCHEMA,
            max: SCHEMA,
        },
        provenance: BTreeMap::new(),
    }
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
fn metadata_versions_and_chunk_digests_fail_closed() {
    let mut v = serde_json::to_value(base()).unwrap();
    for (field, value) in [
        ("acl", serde_json::json!([])),
        ("version", serde_json::json!(1)),
        ("version", serde_json::json!(3)),
        ("features", serde_json::json!(["unknown"])),
    ] {
        let mut v = v.clone();
        v[field] = value;
        assert!(Image::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    v["entries"][0]["xattrs"] = serde_json::json!({"security.capability":"x"});
    assert!(Image::parse(&serde_json::to_vec(&v).unwrap()).is_err());

    // Multi-chunk digest validation + edge cases (empty file, invalid chunk_size, wrong count, single-chunk mismatch).
    let payload = vec![0x5au8; CHUNK_SIZE_MIN as usize * 2 + 123];
    let multi = Entry {
        path: "/usr/large.bin".into(),
        uid: 0,
        gid: 0,
        mode: 0o644,
        node: Node::File {
            sha256: digest(&payload),
            size: payload.len() as u64,
            chunk_size: CHUNK_SIZE_MIN,
            chunks: chunk_digests(&payload, CHUNK_SIZE_MIN).unwrap(),
        },
    };
    let empty = file_bytes("/usr/empty", b"");
    assert!(
        image(
            Kind::Base,
            vec![dir("/"), dir("/usr"), empty, multi.clone()]
        )
        .validate()
        .is_ok()
    );

    // Non-power-of-two or out-of-range chunk_size rejected.
    for bad_cs in [0, 32 * 1024, 96 * 1024, 2 * 1024 * 1024] {
        let bad = Entry {
            node: Node::File {
                sha256: digest(b"x"),
                size: 1,
                chunk_size: bad_cs,
                chunks: vec![digest(b"x")],
            },
            ..file("/usr/bad")
        };
        assert!(
            image(Kind::Base, vec![dir("/"), dir("/usr"), bad])
                .validate()
                .is_err()
        );
    }
    // Wrong chunk count or single-chunk mismatch rejected.
    let mut wrong_count = multi.clone();
    if let Node::File { chunks, .. } = &mut wrong_count.node {
        chunks.pop();
    }
    assert!(
        image(Kind::Base, vec![dir("/"), dir("/usr"), wrong_count])
            .validate()
            .is_err()
    );
    let wrong_single = Entry {
        node: Node::File {
            sha256: digest(b"a"),
            size: 1,
            chunk_size: CHUNK_SIZE_DEFAULT,
            chunks: vec![digest(b"b")],
        },
        ..file("/usr/bad")
    };
    assert!(
        image(Kind::Base, vec![dir("/"), dir("/usr"), wrong_single])
            .validate()
            .is_err()
    );

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
fn initramfs_and_root_template_validation_enforce_stage1_invariants() {
    assert!(initramfs().validate().is_ok());
    assert!(root_template().validate().is_ok());

    // Dropping any required Stage 1 binary fails validation.
    for required in ReleaseV2::REQUIRED_INITRAMFS_BINS {
        let mut missing = initramfs();
        missing.entries.retain(|e| e.path != *required);
        assert!(
            missing.validate().is_err(),
            "expected failure without {required}"
        );
    }

    // Non-executable /init fails validation.
    let mut non_exec = initramfs();
    non_exec
        .entries
        .iter_mut()
        .find(|e| e.path == "/init")
        .unwrap()
        .mode = 0o644;
    assert!(non_exec.validate().is_err());

    // Initramfs cannot include /etc/passwd.
    let mut bad_initramfs = initramfs();
    bad_initramfs.entries.push(dir("/etc"));
    bad_initramfs.entries.push(file("/etc/passwd"));
    bad_initramfs.entries.sort_by(|a, b| a.path.cmp(&b.path));
    assert!(bad_initramfs.validate().is_err());

    // RootTemplate requires /etc, /var, /root, /etc/passwd, /etc/group and forbids /etc/os-trust.
    for required in ["/etc/passwd", "/etc/group", "/var", "/root"] {
        let mut missing = root_template();
        missing.entries.retain(|e| e.path != required);
        assert!(
            missing.validate().is_err(),
            "expected failure without {required}"
        );
    }
    let mut bad_trust = root_template();
    bad_trust.entries.push(file("/etc/os-trust"));
    bad_trust.entries.sort_by(|a, b| a.path.cmp(&b.path));
    assert!(bad_trust.validate().is_err());
}

#[test]
fn signature_binds_exact_bytes_v2_domain_and_operator_trust() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let id = digest(key.verifying_key().as_bytes());
    let mut trust = Trust::default();
    trust
        .keys
        .insert(id.clone(), hex(key.verifying_key().as_bytes()));
    let bytes = serde_json::to_vec(&base()).unwrap();
    let signature = signed(&bytes, SIGNING_DOMAIN_IMAGE_V2, &key);
    assert_eq!(
        trust
            .verify(SIGNING_DOMAIN_IMAGE_V2, &bytes, &signature)
            .unwrap(),
        id
    );
    // v1 domains are rejected cleanly (Contract §2.12).
    assert!(signing_message("os.image.v1", &bytes).is_err());
    assert!(signing_message("os.release.v1", &bytes).is_err());

    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(
        trust
            .verify(SIGNING_DOMAIN_IMAGE_V2, &changed, &signature)
            .is_err()
    );
    assert!(
        trust
            .verify(SIGNING_DOMAIN_RELEASE_V2, &bytes, &signature)
            .is_err()
    );
    assert!(
        Trust::default()
            .verify(SIGNING_DOMAIN_IMAGE_V2, &bytes, &signature)
            .is_err()
    );
    trust.revoked.insert(id);
    assert!(
        trust
            .verify(SIGNING_DOMAIN_IMAGE_V2, &bytes, &signature)
            .is_err()
    );
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
                .verify(
                    SIGNING_DOMAIN_IMAGE_V2,
                    b"{}",
                    &signed(b"{}", SIGNING_DOMAIN_IMAGE_V2, key)
                )
                .is_ok()
        );
    }
    trust.revoked.insert(digest(old.verifying_key().as_bytes()));
    assert!(
        trust
            .verify(
                SIGNING_DOMAIN_IMAGE_V2,
                b"{}",
                &signed(b"{}", SIGNING_DOMAIN_IMAGE_V2, &old)
            )
            .is_err()
    );
    assert!(
        trust
            .verify(
                SIGNING_DOMAIN_IMAGE_V2,
                b"{}",
                &signed(b"{}", SIGNING_DOMAIN_IMAGE_V2, &new)
            )
            .is_ok()
    );
}

#[test]
fn release_v2_compatibility_and_loader_binding_fail_closed() {
    let mut r = release_v2();
    assert!(r.validate().is_ok());
    assert!(r.verify_boot_loader(&boot_image()).is_ok());
    assert_eq!(
        r.images().collect::<Vec<_>>(),
        vec![
            r.boot.as_str(),
            r.initramfs.as_str(),
            r.root_template.as_str(),
            r.base.as_str(),
        ]
    );

    // v1 release manifests are refused.
    r.version = 1;
    assert!(r.validate().is_err());
    r.version = RELEASE_VERSION;

    // Incompatible schema, protocol, or host_adapter ranges fail closed.
    r.schema.max = 6;
    assert!(r.validate().is_err());
    r.schema.max = SCHEMA;
    r.protocol.max = 1;
    assert!(r.validate().is_err());
    r.protocol = Range {
        min: PROTOCOL,
        max: PROTOCOL,
    };
    r.loader.host_adapter = Range { min: 1, max: 1 };
    assert!(r.validate().is_err());
    r.loader.host_adapter = Range {
        min: HOST_ADAPTER,
        max: HOST_ADAPTER,
    };

    // Duplicate image digests refused.
    r.sysext.push(r.base.clone());
    assert!(r.validate().is_err());
    r.sysext.clear();

    // Tampered loader sha256 fails verify_boot_loader.
    r.loader.client_kernel_sha256 = digest(b"wrong");
    assert!(r.verify_boot_loader(&boot_image()).is_err());
}
