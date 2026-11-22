//! Exhaustive tests for 100% local `/etc/{passwd,group,shadow,sudoers}` accounts engine (`#57` `L3d`).
use abi::Errno;
use os_core::permissions::Identity;
use os_kernel::accounts::{
    AccountFs, GROUP_MODE, GROUP_PATH, LocalAccountStore, MemoryAccountFs, PASSWD_MODE,
    PASSWD_PATH, PBKDF2_ITERATIONS, SHADOW_MODE, SHADOW_PATH, SUDO_TIMESTAMP_TTL_SECS,
    SUDOERS_MODE, SUDOERS_PATH, SudoCheck, UseraddReq, UsermodReq, constant_time_eq, hash_password,
    pbkdf2_hmac_sha256, verify_password,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn pbkdf2_hmac_sha256_matches_standard_rfc_test_vectors() {
    let mut dk = [0u8; 32];
    pbkdf2_hmac_sha256(b"password", b"salt", 1, &mut dk);
    assert_eq!(
        hex(&dk),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );

    pbkdf2_hmac_sha256(b"password", b"salt", 2, &mut dk);
    assert_eq!(
        hex(&dk),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );

    pbkdf2_hmac_sha256(b"password", b"salt", 4096, &mut dk);
    assert_eq!(
        hex(&dk),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
}

#[test]
fn password_hashing_and_constant_time_verification_handle_locked_and_malformed() {
    let salt = [0x42u8; 16];
    let encoded = hash_password("correct horse battery staple", salt);
    assert!(encoded.starts_with(&format!("$pbkdf2-sha256$i={PBKDF2_ITERATIONS}$")));
    assert!(verify_password("correct horse battery staple", &encoded));
    assert!(!verify_password("wrong horse battery staple", &encoded));
    assert!(!verify_password("", &encoded));

    // Locked accounts ("!", "*", or "!<hash>") can NEVER password-authenticate.
    assert!(!verify_password("correct horse battery staple", "!"));
    assert!(!verify_password("correct horse battery staple", "*"));
    assert!(!verify_password(
        "correct horse battery staple",
        &format!("!{encoded}")
    ));
    assert!(!verify_password("anything", ""));
    assert!(!verify_password("anything", "$pbkdf2-sha256$i=0$AAAA$BBBB"));
    assert!(!verify_password(
        "anything",
        "$pbkdf2-sha256$i=99999999$AAAA$BBBB"
    ));
    assert!(!verify_password("anything", "$bcrypt$not-supported"));

    assert!(constant_time_eq(b"abcdef", b"abcdef"));
    assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
}

#[test]
fn default_seed_supports_auto_login_wheel_nopasswd_and_exact_file_modes() {
    let fs = MemoryAccountFs::seeded();
    let mut store = LocalAccountStore::new();

    // Verify exact Contract v2 modes on seeded /etc files.
    assert_eq!(fs.files[PASSWD_PATH].mode, PASSWD_MODE);
    assert_eq!(fs.files[GROUP_PATH].mode, GROUP_MODE);
    assert_eq!(fs.files[SHADOW_PATH].mode, SHADOW_MODE);
    assert_eq!(fs.files[SUDOERS_PATH].mode, SUDOERS_MODE);
    assert_eq!(fs.files[SHADOW_PATH].uid, 0);
    assert_eq!(fs.files[SHADOW_PATH].gid, 0);

    // Zero OS-level issuer or principals files exist.
    assert!(!fs.exists("/etc/os/principals"));

    // Default local `user` resolves cleanly (uid 1000, gid 1000, wheel gid 10).
    let user = store.resolve_user(&fs, "user").unwrap();
    assert_eq!(user.id, 1000);
    assert_eq!(user.group, 1000);
    assert!(user.groups.contains(&1000));
    assert!(user.groups.contains(&10));

    // Locked shadow hash "!" cannot password-authenticate...
    assert_eq!(
        store.authenticate(&fs, "user", "").unwrap_err().errno,
        Errno::EACCES
    );
    assert_eq!(
        store
            .authenticate(&fs, "user", "anything")
            .unwrap_err()
            .errno,
        Errno::EACCES
    );

    // ...yet auto-login + `%wheel ALL=(ALL:ALL) NOPASSWD: ALL` sudo works out of the box!
    let gids: Vec<u32> = user.groups.iter().copied().collect();
    assert_eq!(
        store.check_sudo(&fs, user.id, &gids, 1, 1000).unwrap(),
        SudoCheck::AllowedNoPassword
    );
    store
        .sudo_authenticate(&fs, &user, 1, None, 1000)
        .expect("wheel NOPASSWD works while shadow is '!'");

    // `build_creds` produces local creds with zero network RPCs.
    let creds = store.build_creds(&fs, 1000, 1, 1000).unwrap();
    assert_eq!(creds.user, "user");
    assert_eq!(creds.uid, 1000);
    assert_eq!(creds.home, "/home/user");
    assert!(creds.can_sudo);
    assert!(creds.sudo_active);

    // Non-wheel user (`nobody`) is denied sudo.
    let nobody = store.resolve_user(&fs, "nobody").unwrap();
    assert_eq!(
        store
            .sudo_authenticate(&fs, &nobody, 1, None, 1000)
            .unwrap_err()
            .errno,
        Errno::EPERM
    );

    // Root is always allowed.
    let root = Identity::root();
    store.sudo_authenticate(&fs, &root, 1, None, 1000).unwrap();

    // Ensure default seed files are writable/readable cleanly.
    assert!(fs.read_file(PASSWD_PATH).is_ok());
}

#[test]
fn sudo_password_mode_enforces_5_minute_sid_timestamp_and_revocation() {
    let mut fs = MemoryAccountFs::seeded();
    let mut store = LocalAccountStore::new();
    let root = Identity::root();

    // Switch `/etc/sudoers` to password-required wheel rule.
    fs.write_file(
        SUDOERS_PATH,
        b"root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\n",
        SUDOERS_MODE,
        0,
        0,
    )
    .unwrap();

    // Locked `user` CANNOT password-authenticate for sudo!
    let user = store.resolve_user(&fs, "user").unwrap();
    assert_eq!(
        store.check_sudo(&fs, 1000, &[1000, 10], 42, 5000).unwrap(),
        SudoCheck::RequiresPassword
    );
    assert_eq!(
        store
            .sudo_authenticate(&fs, &user, 42, Some("anything"), 5000)
            .unwrap_err()
            .errno,
        Errno::EACCES
    );

    // Root sets a password for `user`.
    store
        .passwd(
            &mut fs,
            &root,
            Some("user"),
            None,
            "super-secret-passphrase",
            false,
            [0x11; 16],
        )
        .unwrap();

    // Missing or wrong password fails.
    assert_eq!(
        store
            .sudo_authenticate(&fs, &user, 42, None, 5000)
            .unwrap_err()
            .errno,
        Errno::EACCES
    );
    assert_eq!(
        store
            .sudo_authenticate(&fs, &user, 42, Some("wrong-password"), 5000)
            .unwrap_err()
            .errno,
        Errno::EACCES
    );

    // Correct password succeeds and caches timestamp for `(uid=1000, sid=42)` for 300s.
    store
        .sudo_authenticate(&fs, &user, 42, Some("super-secret-passphrase"), 5000)
        .unwrap();

    // Within 5-minute window on same sid: AllowedNoPassword.
    assert_eq!(
        store
            .check_sudo(
                &fs,
                1000,
                &[1000, 10],
                42,
                5000 + SUDO_TIMESTAMP_TTL_SECS - 1
            )
            .unwrap(),
        SudoCheck::AllowedNoPassword
    );

    // Different session (`sid=99`) does NOT inherit sid=42's sudo timestamp!
    assert_eq!(
        store.check_sudo(&fs, 1000, &[1000, 10], 99, 5001).unwrap(),
        SudoCheck::RequiresPassword
    );

    // Exactly at expiry (`5000 + 300`): requires password again.
    assert_eq!(
        store
            .check_sudo(&fs, 1000, &[1000, 10], 42, 5000 + SUDO_TIMESTAMP_TTL_SECS)
            .unwrap(),
        SudoCheck::RequiresPassword
    );

    // Re-authenticate, use sliding grace-window without password, then `sudo_revoke` (`sudo -k`) invalidates immediately.
    store
        .sudo_authenticate(&fs, &user, 42, Some("super-secret-passphrase"), 6000)
        .unwrap();
    store.sudo_authenticate(&fs, &user, 42, None, 6010).unwrap();
    assert_eq!(
        store.check_sudo(&fs, 1000, &[1000, 10], 42, 6011).unwrap(),
        SudoCheck::AllowedNoPassword
    );
    store.sudo_revoke(1000, 42);
    assert_eq!(
        store.check_sudo(&fs, 1000, &[1000, 10], 42, 6012).unwrap(),
        SudoCheck::RequiresPassword
    );
}

#[test]
fn full_local_user_and_group_crud_lifecycle_and_permissions() {
    let mut fs = MemoryAccountFs::seeded();
    let mut store = LocalAccountStore::new();
    let root = Identity::root();
    let regular = store.resolve_user(&fs, "user").unwrap();

    // Non-root cannot mutate accounts or groups.
    assert_eq!(
        store.groupadd(&mut fs, &regular, "devs").unwrap_err().errno,
        Errno::EPERM
    );
    assert_eq!(
        store
            .useradd(
                &mut fs,
                &regular,
                UseraddReq {
                    name: "alice".into(),
                    ..Default::default()
                },
                [1; 16],
            )
            .unwrap_err()
            .errno,
        Errno::EPERM
    );

    // Root creates group `devs`, then adds `alice` with home + supplementary group `devs`.
    let devs = store.groupadd(&mut fs, &root, "devs").unwrap();
    assert_eq!(devs.name, "devs");
    assert!(devs.gid >= 1000);

    let alice = store
        .useradd(
            &mut fs,
            &root,
            UseraddReq {
                name: "alice".into(),
                groups: vec!["devs".into()],
                create_home: true,
                password: Some("alice-strong-passphrase".into()),
                ..Default::default()
            },
            [0x22; 16],
        )
        .unwrap();
    assert_eq!(alice.name, "alice");
    assert_eq!(alice.home, "/home/alice");
    assert!(fs.exists("/home/alice"));

    // Authenticate alice locally (zero network!).
    let alice_id = store
        .authenticate(&fs, "alice", "alice-strong-passphrase")
        .unwrap();
    assert_eq!(alice_id.id, alice.uid);
    assert!(alice_id.groups.contains(&devs.gid));

    // Alice changes her own password (requires old password).
    assert_eq!(
        store
            .passwd(
                &mut fs,
                &alice_id,
                None,
                Some("wrong-old-pass"),
                "alice-newer-passphrase",
                false,
                [0x33; 16],
            )
            .unwrap_err()
            .errno,
        Errno::EACCES
    );
    // Non-root cannot change someone else's password.
    assert_eq!(
        store
            .passwd(
                &mut fs,
                &alice_id,
                Some("user"),
                Some("alice-strong-passphrase"),
                "hijack-passphrase-123",
                false,
                [0x33; 16],
            )
            .unwrap_err()
            .errno,
        Errno::EPERM
    );
    store
        .passwd(
            &mut fs,
            &alice_id,
            None,
            Some("alice-strong-passphrase"),
            "alice-newer-passphrase",
            false,
            [0x33; 16],
        )
        .unwrap();
    assert!(
        store
            .authenticate(&fs, "alice", "alice-strong-passphrase")
            .is_err()
    );
    assert!(
        store
            .authenticate(&fs, "alice", "alice-newer-passphrase")
            .is_ok()
    );

    // Lock alice -> password auth rejected; unlock -> password auth works again!
    store
        .usermod(
            &mut fs,
            &root,
            UsermodReq {
                name: "alice".into(),
                lock: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        store
            .authenticate(&fs, "alice", "alice-newer-passphrase")
            .unwrap_err()
            .errno,
        Errno::EACCES
    );
    store
        .usermod(
            &mut fs,
            &root,
            UsermodReq {
                name: "alice".into(),
                unlock: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        store
            .authenticate(&fs, "alice", "alice-newer-passphrase")
            .is_ok()
    );

    // Rename alice -> alicia, append `wheel`, move home `/home/alice` -> `/home/alicia`.
    let renamed = store
        .usermod(
            &mut fs,
            &root,
            UsermodReq {
                name: "alice".into(),
                rename: Some("alicia".into()),
                groups: Some(vec!["wheel".into()]),
                append: true,
                home: Some("/home/alicia".into()),
                move_home: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(renamed.name, "alicia");
    assert_eq!(renamed.uid, alice.uid);
    assert_eq!(renamed.home, "/home/alicia");
    assert!(!fs.exists("/home/alice"));
    assert!(fs.exists("/home/alicia"));
    let alicia_id = store
        .authenticate(&fs, "alicia", "alice-newer-passphrase")
        .unwrap();
    assert!(alicia_id.groups.contains(&devs.gid));
    assert!(alicia_id.groups.contains(&10)); // wheel

    // Rename group `devs` -> `engineers`.
    let renamed_grp = store.groupmod(&mut fs, &root, "devs", "engineers").unwrap();
    assert_eq!(renamed_grp.gid, devs.gid);
    assert_eq!(renamed_grp.name, "engineers");

    // Cannot delete a group that is still a user's primary group (`alice` private group).
    assert_eq!(
        store.groupdel(&mut fs, &root, "alice").unwrap_err().errno,
        Errno::EBUSY
    );
    // Cannot delete reserved system groups or root user.
    assert_eq!(
        store.groupdel(&mut fs, &root, "wheel").unwrap_err().errno,
        Errno::EPERM
    );
    assert_eq!(
        store
            .userdel(&mut fs, &root, "root", false)
            .unwrap_err()
            .errno,
        Errno::EPERM
    );

    // Delete alicia with `remove_home = true`.
    store.userdel(&mut fs, &root, "alicia", true).unwrap();
    assert!(!fs.exists("/home/alicia"));
    assert_eq!(
        store.resolve_user(&fs, "alicia").unwrap_err().errno,
        Errno::ENOENT
    );
    // Now deleting `alice` and `engineers` groups succeeds.
    store.groupdel(&mut fs, &root, "alice").unwrap();
    store.groupdel(&mut fs, &root, "engineers").unwrap();
}

#[test]
fn atomic_temp_file_writes_preserve_modes_and_survive_crash_injection() {
    let mut fs = MemoryAccountFs::seeded();
    let mut store = LocalAccountStore::new();
    let root = Identity::root();

    let original_shadow = fs.read_file(SHADOW_PATH).unwrap();
    let original_passwd = fs.read_file(PASSWD_PATH).unwrap();

    // Inject a crash right on `rename()` during `passwd`.
    fs.fail_next_rename = true;
    let err = store
        .passwd(
            &mut fs,
            &root,
            Some("user"),
            None,
            "new-strong-password-123",
            false,
            [0x55; 16],
        )
        .unwrap_err();
    assert_eq!(err.errno, Errno::EIO);

    // `/etc/shadow` is 100% intact and no `.tmp.*` file leaked!
    assert_eq!(fs.read_file(SHADOW_PATH).unwrap(), original_shadow);
    assert!(
        !fs.files.keys().any(|k| k.contains(".tmp.")),
        "temp files leaked after failed rename: {:?}",
        fs.files.keys().collect::<Vec<_>>()
    );

    // Now succeed and verify temp-file write used exact mode 0600 + owner 0:0 before rename!
    fs.write_log.clear();
    fs.rename_log.clear();
    store
        .passwd(
            &mut fs,
            &root,
            Some("user"),
            None,
            "new-strong-password-123",
            false,
            [0x55; 16],
        )
        .unwrap();
    assert_eq!(fs.write_log.len(), 1);
    let (tmp_path, mode, uid, gid) = &fs.write_log[0];
    assert!(tmp_path.starts_with("/etc/shadow.tmp."));
    assert_eq!((*mode, *uid, *gid), (SHADOW_MODE, 0, 0));
    assert_eq!(fs.rename_log, vec![(tmp_path.clone(), SHADOW_PATH.into())]);
    assert_eq!(fs.files[SHADOW_PATH].mode, SHADOW_MODE);
    assert_eq!(fs.read_file(PASSWD_PATH).unwrap(), original_passwd);
}

#[test]
fn input_validation_rejects_injection_delimiters_and_duplicates() {
    let mut fs = MemoryAccountFs::seeded();
    let store = LocalAccountStore::new();
    let root = Identity::root();

    // Reject colons, newlines, NULs in username, gecos, home, shell.
    for bad_name in [
        "bad:name",
        "bad\nname",
        "bad\0name",
        "BadUpper",
        "1numeric",
        "guest",
        "guest-abc",
        "",
    ] {
        assert_eq!(
            store
                .useradd(
                    &mut fs,
                    &root,
                    UseraddReq {
                        name: bad_name.into(),
                        ..Default::default()
                    },
                    [0; 16],
                )
                .unwrap_err()
                .errno,
            Errno::EINVAL,
            "expected EINVAL for username {bad_name:?}"
        );
    }

    for bad_gecos in ["a:b", "line1\nline2", "has\0nul", "cr\rhere"] {
        assert_eq!(
            store
                .useradd(
                    &mut fs,
                    &root,
                    UseraddReq {
                        name: "bob".into(),
                        gecos: Some(bad_gecos.into()),
                        ..Default::default()
                    },
                    [0; 16],
                )
                .unwrap_err()
                .errno,
            Errno::EINVAL
        );
    }

    for bad_home in ["relative/home", "/home/a:b", "/home/../etc", "/home/bob/"] {
        assert_eq!(
            store
                .useradd(
                    &mut fs,
                    &root,
                    UseraddReq {
                        name: "bob".into(),
                        home: Some(bad_home.into()),
                        ..Default::default()
                    },
                    [0; 16],
                )
                .unwrap_err()
                .errno,
            Errno::EINVAL,
            "expected EINVAL for home {bad_home:?}"
        );
    }

    // Duplicate username and duplicate explicit UID rejected with EEXIST.
    assert_eq!(
        store
            .useradd(
                &mut fs,
                &root,
                UseraddReq {
                    name: "user".into(),
                    ..Default::default()
                },
                [0; 16],
            )
            .unwrap_err()
            .errno,
        Errno::EEXIST
    );
    assert_eq!(
        store
            .useradd(
                &mut fs,
                &root,
                UseraddReq {
                    name: "bob".into(),
                    uid: Some(1000),
                    ..Default::default()
                },
                [0; 16],
            )
            .unwrap_err()
            .errno,
        Errno::EEXIST
    );

    // Short password rejected without `short_password` flag, accepted with flag; empty always rejected.
    assert_eq!(
        store
            .useradd(
                &mut fs,
                &root,
                UseraddReq {
                    name: "bob".into(),
                    password: Some("short".into()),
                    short_password: false,
                    ..Default::default()
                },
                [0; 16],
            )
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );
    assert_eq!(
        store
            .useradd(
                &mut fs,
                &root,
                UseraddReq {
                    name: "bob".into(),
                    password: Some(String::new()),
                    short_password: true,
                    ..Default::default()
                },
                [0; 16],
            )
            .unwrap_err()
            .errno,
        Errno::EINVAL
    );
    store
        .useradd(
            &mut fs,
            &root,
            UseraddReq {
                name: "bob".into(),
                password: Some("short".into()),
                short_password: true,
                ..Default::default()
            },
            [0x77; 16],
        )
        .unwrap();
    assert!(store.authenticate(&fs, "bob", "short").is_ok());
}

#[test]
fn sudoers_rejects_non_root_runas_and_restricted_command_rules() {
    let mut fs = MemoryAccountFs::seeded();
    let store = LocalAccountStore::new();
    let root = Identity::root();

    let alice = store
        .useradd(
            &mut fs,
            &root,
            UseraddReq {
                name: "alice".into(),
                ..Default::default()
            },
            [0xaa; 16],
        )
        .unwrap();

    // Non-root RunAs targets and command-restricted rules MUST NOT grant local root (`uid 0`) sudo.
    for denied_sudoers in [
        "root ALL=(ALL:ALL) ALL\nalice ALL=(nobody) ALL\n",
        "root ALL=(ALL:ALL) ALL\nalice ALL=(bob:bob) NOPASSWD: ALL\n",
        "root ALL=(ALL:ALL) ALL\nalice ALL=(ALL:ALL) /bin/ls\n",
        "root ALL=(ALL:ALL) ALL\nalice ALL=(ALL:ALL) NOPASSWD: /bin/ls\n",
        "root ALL=(ALL:ALL) ALL\nalice ALL=(ALL:ALL) /bin/ls, ALL\n",
    ] {
        fs.write_file(SUDOERS_PATH, denied_sudoers.as_bytes(), SUDOERS_MODE, 0, 0)
            .unwrap();
        assert_eq!(
            store
                .check_sudo(&fs, alice.uid, &[alice.gid], 1, 1000)
                .unwrap(),
            SudoCheck::Denied,
            "expected Denied for sudoers rule: {denied_sudoers:?}"
        );
    }

    // Explicit root RunAs rules are accepted accurately.
    fs.write_file(
        SUDOERS_PATH,
        b"root ALL=(ALL:ALL) ALL\nalice ALL=(root:root) ALL\n",
        SUDOERS_MODE,
        0,
        0,
    )
    .unwrap();
    assert_eq!(
        store
            .check_sudo(&fs, alice.uid, &[alice.gid], 1, 1000)
            .unwrap(),
        SudoCheck::RequiresPassword
    );
}
