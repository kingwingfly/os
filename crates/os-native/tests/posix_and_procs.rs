//! NAT-03: POSIX & process fidelity inside `os-native` (`dash` fork/pipelines/signals,
//! coreutils, utilities, `cowfs` snapshot/fork/reflink, `AF_UNIX`/`SO_PEERCRED` via `service`,
//! local `/etc/{passwd,shadow}` accounts & permissions, `chroot` containment, and cgroups).

mod common;

use common::{TempDir, boot_host, exec_sh};

#[test]
#[ignore = "requires signed Release v2 bundle; run with OS_NATIVE_TEST_BUNDLE=<dir> cargo test -p os-native -- --ignored --test-threads=1"]
fn nat03_dash_fork_pipelines_signals_and_coreutils() {
    let state = TempDir::new("nat03-posix");
    let host = boot_host(state.path(), false);

    // 1. Pipelines, subshells, fork/wait, redirections, coreutils.
    let res = exec_sh(
        &host,
        0,
        r#"
set -e
printf 'cherry\napple\nbanana\napple\n' | sort | uniq > /tmp/sorted.txt
cat /tmp/sorted.txt
wc -l < /tmp/sorted.txt
(echo "subshell-ok")
mkdir -p /tmp/dirA/nested
ln -s /tmp/sorted.txt /tmp/dirA/link
readlink /tmp/dirA/link
chmod 0640 /tmp/sorted.txt
"#,
    );
    let stdout = String::from_utf8_lossy(&res.stdout);
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert_eq!(res.exit_code, 0, "stderr={stderr}\nstdout={stdout}");
    assert!(
        stdout.contains("apple\nbanana\ncherry\n"),
        "stdout={stdout}"
    );
    assert!(stdout.contains("subshell-ok"), "stdout={stdout}");
    assert!(stdout.contains("/tmp/sorted.txt"), "stdout={stdout}");

    // 2. Exit code propagation across subshell & fork.
    let res_exit = exec_sh(&host, 0, "sh -c 'exit 42'");
    assert_eq!(res_exit.exit_code, 42);

    // 3. Signal trap & delivery inside dash (`kill -USR1 $$`).
    let res_sig = exec_sh(
        &host,
        0,
        "trap 'echo CAUGHT_USR1' USR1; kill -USR1 $$; echo AFTER_TRAP",
    );
    let sig_out = String::from_utf8_lossy(&res_sig.stdout);
    let sig_err = String::from_utf8_lossy(&res_sig.stderr);
    assert_eq!(res_sig.exit_code, 0, "stderr={sig_err}\nstdout={sig_out}");
    assert!(sig_out.contains("CAUGHT_USR1"), "sig_out={sig_out}");
    assert!(sig_out.contains("AFTER_TRAP"), "sig_out={sig_out}");

    assert!(host.shutdown_blocking().expect("clean shutdown"));
}

#[test]
#[ignore = "requires signed Release v2 bundle; run with OS_NATIVE_TEST_BUNDLE=<dir> cargo test -p os-native -- --ignored --test-threads=1"]
fn nat03_cowfs_snapshots_forks_service_accounts_and_chroot() {
    let state = TempDir::new("nat03-os");
    let host = boot_host(state.path(), false);

    // 1. `cowfs` info, snapshot create/list, mount snapshot RO, and O(1) fork.
    let vol = host
        .inspect_blocking()
        .root_volume
        .expect("mounted root volume uuid");
    let cow_script = format!(
        r#"
set -e
echo "before-snap-v1" > /root/snap-data.txt
cowfs info --json /
cowfs snapshot create / snap1
echo "after-snap-v2" > /root/snap-data.txt
cowfs snapshot list --json /
mkdir -p /mnt/snap1
mount -t cowfs -o ro "snapshot:{vol}@snap1" /mnt/snap1
echo "SNAP=$(cat /mnt/snap1/root/snap-data.txt)"
echo "LIVE=$(cat /root/snap-data.txt)"
umount /mnt/snap1
cowfs fork --snapshot snap1 / fork-nat03
"#
    );
    let res_cow = exec_sh(&host, 0, &cow_script);
    let out = String::from_utf8_lossy(&res_cow.stdout);
    let err = String::from_utf8_lossy(&res_cow.stderr);
    assert_eq!(
        res_cow.exit_code, 0,
        "cowfs test failed:\nstderr={err}\nstdout={out}"
    );
    assert!(out.contains("snap1"), "out={out}");
    assert!(out.contains("SNAP=before-snap-v1"), "out={out}");
    assert!(out.contains("LIVE=after-snap-v2"), "out={out}");

    // 2. PID 1 `init` service manager over `AF_UNIX` + `SO_PEERCRED` (`/run/init/control.sock`).
    let res_svc = exec_sh(&host, 0, "service list");
    let svc_out = String::from_utf8_lossy(&res_svc.stdout);
    let svc_err = String::from_utf8_lossy(&res_svc.stderr);
    assert_eq!(
        res_svc.exit_code, 0,
        "service list failed:\nstderr={svc_err}\nstdout={svc_out}"
    );
    assert!(
        svc_out.contains("multi-user.target") || svc_out.contains("mountd.service"),
        "svc_out={svc_out}"
    );

    // 3. Local offline account permissions: uid 1000 cannot read `/etc/shadow` (`EACCES`).
    let res_shadow_user = exec_sh(&host, 1000, "cat /etc/shadow");
    assert_ne!(
        res_shadow_user.exit_code, 0,
        "non-root uid=1000 MUST NOT read /etc/shadow"
    );
    let res_passwd_user = exec_sh(&host, 1000, "id -u && cat /etc/passwd");
    assert_eq!(res_passwd_user.exit_code, 0);
    assert!(String::from_utf8_lossy(&res_passwd_user.stdout).contains("1000"));

    // 4. `useradd` creates a real local account offline & persists to `/etc/passwd`.
    let res_ua = exec_sh(&host, 0, "useradd -m alice && grep '^alice:' /etc/passwd");
    let ua_out = String::from_utf8_lossy(&res_ua.stdout);
    let ua_err = String::from_utf8_lossy(&res_ua.stderr);
    assert_eq!(
        res_ua.exit_code, 0,
        "useradd failed:\nstderr={ua_err}\nstdout={ua_out}"
    );
    assert!(ua_out.contains("alice:"));

    // 5. `chroot` containment: process inside `/tmp/jail` cannot escape via `../../etc/shadow`
    //    nor open host PTY nodes `/dev/ptmx` or `/dev/pts/0` outside the jail.
    let res_chroot = exec_sh(
        &host,
        0,
        r#"
set -e
mkdir -p /tmp/jail/bin /tmp/jail/etc
echo "JAILED_SENTINEL" > /tmp/jail/etc/sentinel
cp /usr/bin/coreutils /tmp/jail/bin/cat
chmod 0755 /tmp/jail/bin/cat
chroot /tmp/jail /bin/cat /etc/sentinel
if chroot /tmp/jail /bin/cat /../../etc/shadow 2>/dev/null; then
    echo "ESCAPED_SHADOW"
    exit 99
fi
if chroot /tmp/jail /bin/cat /dev/ptmx 2>/dev/null; then
    echo "ESCAPED_PTMX"
    exit 98
fi
if chroot /tmp/jail /bin/cat /dev/pts/0 2>/dev/null; then
    echo "ESCAPED_PTS0"
    exit 97
fi
echo "CONTAINED_OK"
"#,
    );
    let ch_out = String::from_utf8_lossy(&res_chroot.stdout);
    let ch_err = String::from_utf8_lossy(&res_chroot.stderr);
    assert_eq!(
        res_chroot.exit_code, 0,
        "chroot failed:\nstderr={ch_err}\nstdout={ch_out}"
    );
    assert!(ch_out.contains("JAILED_SENTINEL"), "ch_out={ch_out}");
    assert!(ch_out.contains("CONTAINED_OK"), "ch_out={ch_out}");
    assert!(!ch_out.contains("ESCAPED"));

    // 6. Security regressions:
    //    (a) Cross-UID PTY DAC: console `/dev/pts/0` is owned by default_user `user` (uid=1000, 0620),
    //        so a different non-root user (`alice`, uid=1001) MUST get EACCES opening `/dev/pts/0`.
    let res_pts_stat = exec_sh(&host, 0, "stat -c '%u %a' /dev/pts/0");
    assert_eq!(res_pts_stat.exit_code, 0);
    assert_eq!(
        String::from_utf8_lossy(&res_pts_stat.stdout).trim(),
        "1000 620",
        "expected /dev/pts/0 to be owned by uid 1000 with mode 0620"
    );
    let res_pts_dac = exec_sh(&host, 1001, "cat /dev/pts/0");
    assert_ne!(
        res_pts_dac.exit_code, 0,
        "cross-UID user (uid=1001) MUST NOT open uid=1000 /dev/pts/0"
    );

    //    (b) CowFs ioctl must NOT fall back to root CowFs on a non-CowFs mount (`/tmp` tmpfs -> ENOTTY).
    let res_tmp_ioctl = exec_sh(&host, 0, "cowfs info /tmp");
    assert_ne!(
        res_tmp_ioctl.exit_code, 0,
        "cowfs info /tmp (tmpfs) must fail with ENOTTY, not fall back to root CowFs"
    );

    assert!(host.shutdown_blocking().expect("clean shutdown"));
}
