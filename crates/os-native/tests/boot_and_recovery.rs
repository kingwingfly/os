//! NAT-01, NAT-02, NAT-04: Stage 0 signature fail-closed, offline boot, clean restart,
//! real `SIGKILL` crash recovery, and `format_version` mismatch protection without data loss.

mod common;

use common::{TempDir, boot_host, exec_sh, test_bundle_dir};
use os_native::{NativeBootConfig, NativeOsHost};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("mkdir dst");
    for entry in std::fs::read_dir(src).expect("read_dir src") {
        let entry = entry.expect("dir entry");
        let ty = entry.file_type().expect("file_type");
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path);
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dst_path).expect("copy file");
        }
    }
}

#[test]
#[ignore = "requires signed Release v2 bundle; run with OS_NATIVE_TEST_BUNDLE=<dir> cargo test -p os-native -- --ignored --test-threads=1"]
fn nat01_signature_fail_closed_and_full_offline_boot() {
    let bundle = test_bundle_dir();

    // 1. Missing `publisher.json` must fail closed (unless `--allow-unsigned-dev` is explicit).
    {
        let unsigned_bundle = TempDir::new("nat01-no-pub");
        copy_dir_recursive(&bundle, unsigned_bundle.path());
        std::fs::remove_file(unsigned_bundle.path().join("publisher.json"))
            .expect("remove publisher.json");
        let state = TempDir::new("nat01-no-pub-state");
        let cfg = NativeBootConfig::new(
            unsigned_bundle.path().to_path_buf(),
            state.path().to_path_buf(),
        );
        let err = NativeOsHost::boot(cfg)
            .err()
            .expect("boot without publisher.json must fail closed");
        assert!(
            err.contains("publisher") || err.contains("trust"),
            "unexpected error for missing publisher.json: {err}"
        );
    }

    // 2. Tampered release signature must fail closed.
    {
        let bad_sig_bundle = TempDir::new("nat01-bad-rel-sig");
        copy_dir_recursive(&bundle, bad_sig_bundle.path());
        let release_bytes = std::fs::read(bad_sig_bundle.path().join("release.json")).unwrap();
        let release_id = os_image::digest(&release_bytes);
        let sig_path = bad_sig_bundle
            .path()
            .join(format!("releases/{release_id}/signature.json"));
        let mut sig = std::fs::read_to_string(&sig_path).unwrap();
        // Flip a hex/base64 character inside the signature payload.
        sig = sig.replacen('a', "b", 1);
        if sig == std::fs::read_to_string(&sig_path).unwrap() {
            sig = sig.replacen('0', "1", 1);
        }
        std::fs::write(&sig_path, sig).unwrap();

        let state = TempDir::new("nat01-bad-rel-sig-state");
        let cfg = NativeBootConfig::new(
            bad_sig_bundle.path().to_path_buf(),
            state.path().to_path_buf(),
        );
        let err = NativeOsHost::boot(cfg)
            .err()
            .expect("boot with tampered release signature must fail closed");
        assert!(
            err.contains("signature") || err.contains("invalid") || err.contains("verify"),
            "unexpected error for tampered release signature: {err}"
        );
    }

    // 3. Tampered image signature must fail closed.
    {
        let bad_img_bundle = TempDir::new("nat01-bad-img-sig");
        copy_dir_recursive(&bundle, bad_img_bundle.path());
        let sig_entry = std::fs::read_dir(bad_img_bundle.path().join("images"))
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.path().extension().and_then(|s| s.to_str()) == Some("sig"))
            .expect("at least one .sig in images/");
        let mut raw = std::fs::read(sig_entry.path()).unwrap();
        let flip_idx = raw.len().saturating_sub(4);
        raw[flip_idx] ^= 0x01;
        std::fs::write(sig_entry.path(), raw).unwrap();

        let state = TempDir::new("nat01-bad-img-sig-state");
        let cfg = NativeBootConfig::new(
            bad_img_bundle.path().to_path_buf(),
            state.path().to_path_buf(),
        );
        let err = NativeOsHost::boot(cfg)
            .err()
            .expect("boot with tampered image signature must fail closed");
        assert!(
            err.contains("signature") || err.contains("invalid") || err.contains("verify"),
            "unexpected error for tampered image signature: {err}"
        );
    }

    // 4. Full offline verified Stage 0 -> Stage 1 -> Stage 2 boot.
    let state = TempDir::new("nat01-boot-state");
    let host = boot_host(state.path(), false);

    let info = host.inspect_blocking();
    assert_eq!(
        info.stage, "stage2",
        "expected Stage 2 after switch_root: {info:?}"
    );
    assert!(info.boot_healthy, "expected /run/os/boot-healthy: {info:?}");
    assert!(
        info.root_volume.is_some(),
        "expected mounted CowFs root volume"
    );

    // Verify /run/os/boot-healthy, /run/os/root, /proc/self/mountinfo, absence of remote devices,
    // and seeded account file modes.
    let out = exec_sh(
        &host,
        0,
        "set -e
test -f /run/os/boot-healthy
test -f /run/os/root
cat /proc/self/mountinfo
echo '---DEVS---'
for d in /dev/archive /dev/media /dev/present /dev/snd; do
  if [ -e \"$d\" ]; then
    echo \"UNEXPECTED_DEV:$d\"
    exit 1
  fi
done
echo 'NO_REMOTE_DEVS'
test -f /etc/passwd
test -f /etc/group
test -f /etc/shadow
test -f /etc/sudoers
stat -c '%a %n' /etc/shadow /etc/sudoers
",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.exit_code, 0,
        "NAT-01 inspection script failed (exit={}): stdout={stdout}\nstderr={stderr}",
        out.exit_code
    );
    assert!(
        stdout.contains("cowfs"),
        "mountinfo missing cowfs: {stdout}"
    );
    assert!(
        stdout.contains("image"),
        "mountinfo missing image /usr: {stdout}"
    );
    assert!(
        stdout.contains("tmpfs"),
        "mountinfo missing tmpfs /tmp: {stdout}"
    );
    assert!(stdout.contains("proc"), "mountinfo missing proc: {stdout}");
    assert!(
        stdout.contains("devtmpfs"),
        "mountinfo missing devtmpfs: {stdout}"
    );
    assert!(
        stdout.contains("devpts"),
        "mountinfo missing devpts: {stdout}"
    );
    assert!(
        stdout.contains("NO_REMOTE_DEVS"),
        "unexpected remote devices: {stdout}"
    );
    assert!(
        stdout.contains("600 /etc/shadow"),
        "shadow mode mismatch: {stdout}"
    );
    assert!(
        stdout.contains("440 /etc/sudoers"),
        "sudoers mode mismatch: {stdout}"
    );

    assert!(
        host.shutdown_blocking().expect("clean shutdown"),
        "expected clean CowFs shutdown"
    );
}

#[test]
#[ignore = "requires signed Release v2 bundle; run with OS_NATIVE_TEST_BUNDLE=<dir> cargo test -p os-native -- --ignored --test-threads=1"]
fn nat02_clean_restart_and_sigkill_crash_recovery() {
    let state = TempDir::new("nat02-state");

    // Phase 1: Initial boot, write user + system files, clean shutdown.
    let vol_uuid = {
        let host = boot_host(state.path(), false);
        let vol = host
            .inspect_blocking()
            .root_volume
            .expect("root volume uuid");
        let out = exec_sh(
            &host,
            0,
            "set -e
mkdir -p /home/user
printf 'persisted-across-clean-restart\\n' > /home/user/clean.txt
chown 1000:1000 /home/user/clean.txt
printf 'native-host-config=1\\n' > /etc/native-test.conf
",
        );
        assert_eq!(
            out.exit_code,
            0,
            "phase 1 write failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(host.shutdown_blocking().expect("clean shutdown 1"));
        vol
    };

    // Phase 2: Clean reboot on the same `$STATE` verifies persistence & same root volume.
    {
        let host = boot_host(state.path(), false);
        let info = host.inspect_blocking();
        assert_eq!(info.root_volume.as_deref(), Some(vol_uuid.as_str()));
        let out = exec_sh(
            &host,
            1000,
            "set -e
cat /home/user/clean.txt
cat /etc/native-test.conf
",
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.exit_code,
            0,
            "phase 2 read failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("persisted-across-clean-restart"));
        assert!(stdout.contains("native-host-config=1"));
        assert!(host.shutdown_blocking().expect("clean shutdown 2"));
    }

    // Phase 3: Real `SIGKILL` (`kill -9`) on a spawned `os-native run` process.
    let bin = env!("CARGO_BIN_EXE_os-native");
    let ready_file = state.path().join("ready.json");
    let token_file = state.path().join("bootstrap.tok");
    let seat_sock = state.path().join("seat.sock");

    let mut child = Command::new(bin)
        .args([
            "run",
            "--bundle",
            test_bundle_dir().to_str().unwrap(),
            "--state",
            state.path().to_str().unwrap(),
            "--no-console-shell",
            "--ready-file",
            ready_file.to_str().unwrap(),
            "--bootstrap-token-file",
            token_file.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn os-native run");

    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready_file.is_file() {
        if let Some(status) = child.try_wait().expect("try_wait child") {
            let output = child.wait_with_output().unwrap();
            panic!(
                "os-native exited early ({status}): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for ready.json"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Record current root_epoch before writing, write `/home/user/crash.txt`, wait for the
    // automatic 5-second Contract §2.15 dirty-commit deadline to advance `root_epoch` durably
    // on SQLite WAL + packs, then send real `SIGKILL` (`kill -9`) with zero graceful shutdown!
    let epoch_before: u64 = {
        let out = Command::new(bin)
            .args([
                "inspect",
                "--state",
                state.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("inspect before write");
        assert!(out.status.success());
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["root_epoch"].as_u64().unwrap()
    };

    let exec_out = Command::new(bin)
        .args([
            "exec",
            "--target",
            &format!("unix://{}", seat_sock.display()),
            "--token-file",
            token_file.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "printf 'survived-real-sigkill\\n' > /home/user/crash.txt",
        ])
        .output()
        .expect("run os-native exec");
    if !exec_out.status.success() {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "os-native exec failed: stdout={} stderr={}",
            String::from_utf8_lossy(&exec_out.stdout),
            String::from_utf8_lossy(&exec_out.stderr)
        );
    }

    let commit_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = Command::new(bin)
            .args([
                "inspect",
                "--state",
                state.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("inspect after write");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let epoch_now = v["root_epoch"].as_u64().unwrap_or(0);
        if epoch_now > epoch_before {
            break;
        }
        if Instant::now() >= commit_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "timed out waiting for CowFs dirty-commit deadline to advance epoch past {epoch_before}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Send real SIGKILL (`kill -9`) — no graceful shutdown, dirty mount marker remains on SQLite.
    child.kill().expect("SIGKILL os-native child");
    let kill_status = child.wait().expect("wait killed child");
    assert!(
        !kill_status.success(),
        "expected non-zero exit after SIGKILL"
    );

    // Phase 4: Reboot directly on the crashed `$STATE` — Stage 1 runs `cowfsck` recovery and boots cleanly!
    {
        let host = boot_host(state.path(), false);
        let info = host.inspect_blocking();
        assert!(info.boot_healthy, "recovery boot must reach boot-healthy");
        assert_eq!(info.root_volume.as_deref(), Some(vol_uuid.as_str()));

        let out = exec_sh(
            &host,
            0,
            "set -e
cat /home/user/clean.txt
cat /home/user/crash.txt
/bin/cowfs info /
",
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.exit_code, 0,
            "post-SIGKILL check failed: stdout={stdout}\nstderr={stderr}"
        );
        assert!(stdout.contains("persisted-across-clean-restart"));
        assert!(stdout.contains("survived-real-sigkill"));
        assert!(host.shutdown_blocking().expect("clean shutdown 4"));
    }
}

#[test]
#[ignore = "requires signed Release v2 bundle; run with OS_NATIVE_TEST_BUNDLE=<dir> cargo test -p os-native -- --ignored --test-threads=1"]
fn nat04_format_version_mismatch_fails_without_data_loss() {
    let state = TempDir::new("nat04-state");

    // 1. Boot cleanly and store precious user data.
    {
        let host = boot_host(state.path(), false);
        let out = exec_sh(
            &host,
            0,
            "set -e
mkdir -p /home/user
printf 'precious-user-data-v1\\n' > /home/user/precious.txt
chown 1000:1000 /home/user/precious.txt
",
        );
        assert_eq!(
            out.exit_code,
            0,
            "write precious.txt failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(host.shutdown_blocking().expect("clean shutdown"));
    }

    // 2. Simulate an incompatible future format_version (`99`) in `$STATE/cowfs.sqlite3`.
    {
        let store = os_cowfs::native_sqlite::NativeSqliteHeadStore::open(state.path())
            .expect("open NativeSqliteHeadStore");
        store
            .set_stored_format_version(99)
            .expect("bump format_version to 99");
    }

    // 3. Booting with an unsupported format_version MUST fail without wiping or reformatting.
    {
        let mut cfg = NativeBootConfig::new(test_bundle_dir(), state.path().to_path_buf());
        cfg.spawn_console_shell = false;
        cfg.boot_timeout = Duration::from_secs(15);
        let err = NativeOsHost::boot(cfg)
            .err()
            .expect("boot with unsupported format_version=99 must fail");
        assert!(
            err.to_lowercase().contains("format")
                || err.to_lowercase().contains("version")
                || err.to_lowercase().contains("incompatible")
                || err.contains("99"),
            "unexpected format_version mismatch error: {err}"
        );
    }

    // 4. Restore format_version = 1 and confirm user data is 100% intact.
    {
        let store = os_cowfs::native_sqlite::NativeSqliteHeadStore::open(state.path())
            .expect("re-open NativeSqliteHeadStore");
        store
            .set_stored_format_version(1)
            .expect("restore format_version to 1");
    }

    {
        let host = boot_host(state.path(), false);
        let out = exec_sh(&host, 1000, "cat /home/user/precious.txt");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.exit_code,
            0,
            "read precious.txt after restore failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(stdout.trim(), "precious-user-data-v1");
        assert!(host.shutdown_blocking().expect("clean shutdown 2"));
    }
}
