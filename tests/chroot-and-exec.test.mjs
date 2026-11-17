import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { accessSync, constants as fsConstants, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

// --- Compile & load real `os-client-kernel` Wasm module for Node.js ---
const repoRoot = fileURLToPath(new URL('..', import.meta.url));
function resolveCargoTargetDir() {
  if (process.env.CARGO_TARGET_DIR) return process.env.CARGO_TARGET_DIR;
  try {
    const dir = JSON.parse(
      execFileSync('cargo', ['metadata', '--no-deps', '--format-version=1'], {
        cwd: repoRoot,
        encoding: 'utf8',
      }),
    ).target_directory;
    mkdirSync(dir, { recursive: true });
    accessSync(dir, fsConstants.W_OK);
    return dir;
  } catch {
    return join(tmpdir(), 'os-client-kernel-target');
  }
}

const targetDir = resolveCargoTargetDir();
const wasmOutDir = mkdtempSync(join(tmpdir(), 'os-l2-chroot-wasm-'));
process.on('exit', () => {
  try {
    rmSync(wasmOutDir, { recursive: true, force: true });
  } catch {}
});

execFileSync(
  'cargo',
  ['build', '--quiet', '--locked', '-p', 'os-client-kernel', '--target', 'wasm32-unknown-unknown', '--target-dir', targetDir],
  {
    cwd: repoRoot,
    stdio: 'inherit',
    env: { ...process.env, CARGO_PROFILE_DEV_DEBUG: process.env.CARGO_PROFILE_DEV_DEBUG ?? '0' },
  },
);
execFileSync(
  'wasm-bindgen',
  [
    '--target',
    'nodejs',
    '--no-typescript',
    '--out-dir',
    wasmOutDir,
    '--out-name',
    'client_kernel',
    join(targetDir, 'wasm32-unknown-unknown/debug/os_client_kernel.wasm'),
  ],
  { cwd: repoRoot, stdio: 'inherit' },
);
const require = createRequire(import.meta.url);
const wasm = require(join(wasmOutDir, 'client_kernel.js'));
globalThis.wasm_bindgen = wasm;

// --- Constants ---
const OS_FD_ROOT = 0x7ffffffd;
const OS_FD_CWD = 0x7ffffffe;

const O_RDONLY = 0;
const O_RDWR = 2;
const O_CREAT = 0o100;
const O_TRUNC = 0o1000;
const O_DIRECTORY = 0o200000;

const MS_NOEXEC = 8n;
const MS_BIND = 4096n;

const CLONE_FS = 0x00000200;
const CLONE_FILES = 0x00000400;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const WASM_BIN = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

function createHarness(t) {
  const k = new wasm.Kernel(`inst-${crypto.randomUUID()}`, `k-${crypto.randomUUID()}`);
  const pids = new Set();
  const sessions = new Set();

  t.after(async () => {
    for (const pid of [...pids]) {
      await k.proc_exit(pid).catch(() => {});
    }
    for (const sid of [...sessions]) {
      await k.session_end(sid).catch(() => {});
    }
  });

  return {
    k,
    async spawn(opts) {
      const res = await k.proc_spawn_init(JSON.stringify(opts));
      pids.add(opts.pid);
      return res;
    },
    fork(parentPid, childPid, cloneFlags = 0, token = null, cloudAccess = true) {
      const res = k.proc_fork(parentPid, childPid, cloneFlags, token, cloudAccess);
      pids.add(childPid);
      return res;
    },
    async mkdirAll(pid, path, mode = 0o755) {
      const parts = path.split('/').filter(Boolean);
      let cur = '';
      for (const seg of parts) {
        cur += '/' + seg;
        await k.proc_mkdirat(pid, OS_FD_ROOT, cur, mode).catch(err => {
          if (err?.errno !== 'EEXIST') throw err;
        });
      }
    },
    async writeBytes(pid, path, data, mode = 0o644, dirfd = OS_FD_ROOT) {
      const bytes = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
      const prevUmask = k.proc_set_umask(pid, 0);
      let opened;
      try {
        opened = await k.proc_openat(pid, dirfd, path, O_RDWR | O_CREAT | O_TRUNC, mode, false);
        await k.kfd_write(pid, opened.kfd, bytes);
      } finally {
        k.proc_set_umask(pid, prevUmask);
        if (opened) await k.kfd_close(pid, opened.kfd);
      }
    },
    async readText(pid, path, dirfd = OS_FD_ROOT) {
      const opened = await k.proc_openat(pid, dirfd, path, O_RDONLY, 0, false);
      try {
        const buf = await k.kfd_pread(pid, opened.kfd, 16384, 0n);
        return decoder.decode(buf);
      } finally {
        await k.kfd_close(pid, opened.kfd);
      }
    },
  };
}

// ============================================================================
// Tests
// ============================================================================

test('OS_FD_ROOT/OS_FD_CWD component walk preserves link-dotdot, cwd-rename, and cwd-remove semantics', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.spawn({ pid: 10, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await h.spawn({ pid: 11, ppid: 1, uid: 0, gid: 0, groups: [0] });

  // 1. link-dotdot: symlink must be resolved BEFORE following '..'
  await h.mkdirAll(10, '/tmp/real/a/b');
  await h.mkdirAll(10, '/tmp/real/sibling');
  await h.writeBytes(10, '/tmp/real/a/from-real-parent.txt', 'physical-parent');
  await k.proc_symlinkat(10, '/tmp/real/a/b', OS_FD_ROOT, '/tmp/real/sibling/jump');
  // Lexical collapse of '/tmp/real/sibling/jump/../from-real-parent.txt' would wrongly look in /tmp/real/sibling!
  assert.equal(await h.readText(10, '/tmp/real/sibling/jump/../from-real-parent.txt'), 'physical-parent');

  // 2. cwd-rename: handle-backed cwd tracks directory across renames
  await h.mkdirAll(10, '/tmp/dir-before');
  await k.sys_chdir(10, '/tmp/dir-before');
  assert.equal(await k.sys_getcwd(10), '/tmp/dir-before');
  await k.proc_renameat(11, OS_FD_ROOT, '/tmp/dir-before', OS_FD_ROOT, '/tmp/dir-after', 0);
  assert.equal(await k.sys_getcwd(10), '/tmp/dir-after');

  // 3. cwd-remove: unlinked cwd fails getcwd with ENOENT while stat(".") on OS_FD_CWD still succeeds
  await h.mkdirAll(10, '/tmp/ephemeral');
  await k.sys_chdir(10, '/tmp/ephemeral');
  await k.proc_unlinkat(11, OS_FD_ROOT, '/tmp/ephemeral', true);
  await assert.rejects(k.sys_getcwd(10), { errno: 'ENOENT' });
  const dotStat = await k.proc_statat(10, OS_FD_CWD, '.', true);
  assert.equal((dotStat.mode & 0o170000) === 0o040000, true);
});

test('chroot enforces EPERM/ENOENT/ENOTDIR, clamps .., rebases absolute symlinks, and keeps outside cwd & retained dirfds working', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.spawn({ pid: 20, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await h.spawn({ pid: 21, ppid: 1, uid: 0, gid: 0, groups: [0] }); // sibling root stays at /
  await h.spawn({ pid: 22, ppid: 1, uid: 1001, gid: 1001, groups: [1001] });

  await h.mkdirAll(20, '/tmp/jail/sub');
  await h.mkdirAll(20, '/tmp/outside-cwd');
  await h.mkdirAll(20, '/tmp/outside-dirfd');
  await h.writeBytes(20, '/tmp/plain-file.txt', 'not-a-dir');
  await h.writeBytes(20, '/tmp/jail/marker.txt', 'inside-jail');
  await h.writeBytes(20, '/tmp/jail/sub/nested.txt', 'nested-target');
  await k.proc_symlinkat(20, '/sub/nested.txt', OS_FD_ROOT, '/tmp/jail/abs-sym');
  await h.writeBytes(20, '/tmp/outside-cwd/rel.txt', 'from-outside-cwd');
  await h.writeBytes(20, '/tmp/outside-dirfd/held.txt', 'from-retained-dirfd');

  // Denial & error checks
  await assert.rejects(k.sys_chroot(22, '/tmp/jail'), { errno: 'EPERM' });
  await assert.rejects(k.sys_chroot(20, '/tmp/no-such-jail'), { errno: 'ENOENT' });
  await assert.rejects(k.sys_chroot(20, '/tmp/plain-file.txt'), { errno: 'ENOTDIR' });

  // Position cwd outside jail and open a retained directory fd + file fd outside jail BEFORE chroot
  await k.sys_chdir(20, '/tmp/outside-cwd');
  const heldDir = await k.proc_openat(20, OS_FD_ROOT, '/tmp/outside-dirfd', O_RDONLY | O_DIRECTORY, 0, false);
  const heldFile = await k.proc_openat(20, OS_FD_ROOT, '/tmp/plain-file.txt', O_RDONLY, 0, false);

  // chroot does NOT change cwd or close descriptors (not a sandbox!)
  await k.sys_chroot(20, '/tmp/jail');

  // Outside cwd: getcwd -> ENOENT, while relative open via OS_FD_CWD still works!
  await assert.rejects(k.sys_getcwd(20), { errno: 'ENOENT' });
  assert.equal(await h.readText(20, 'rel.txt', OS_FD_CWD), 'from-outside-cwd');

  // Meanwhile OS_FD_ROOT resolves inside /tmp/jail, clamps ../../.., and rebases absolute symlinks
  assert.equal(await h.readText(20, '/marker.txt', OS_FD_ROOT), 'inside-jail');
  assert.equal(await h.readText(20, '/../../../../marker.txt', OS_FD_ROOT), 'inside-jail');
  assert.equal(await h.readText(20, '/abs-sym', OS_FD_ROOT), 'nested-target');
  await assert.rejects(k.proc_statat(20, OS_FD_ROOT, '/tmp/plain-file.txt', true), { errno: 'ENOENT' });

  // Retained dirfd openat and retained file fd pread continue working outside chroot
  assert.equal(await h.readText(20, 'held.txt', heldDir.fd), 'from-retained-dirfd');
  assert.equal(decoder.decode(await k.kfd_pread(20, heldFile.kfd, 32, 0n)), 'not-a-dir');

  // chdir("/sub") inside jail gives jail-relative getcwd "/sub", then fchdir(heldDir) moves cwd back outside jail!
  await k.sys_chdir(20, '/sub');
  assert.equal(await k.sys_getcwd(20), '/sub');
  await k.sys_fchdir(20, heldDir.kfd);
  await assert.rejects(k.sys_getcwd(20), { errno: 'ENOENT' });
  assert.equal(await h.readText(20, 'held.txt', OS_FD_CWD), 'from-retained-dirfd');

  // Sibling process 21's root is completely unaffected
  assert.equal(await h.readText(21, '/tmp/plain-file.txt', OS_FD_ROOT), 'not-a-dir');

  await k.kfd_close(20, heldDir.kfd);
  await k.kfd_close(20, heldFile.kfd);
});

test('fork, exec, CLONE_FS, and CLONE_FILES preserve/share/split root, cwd, and descriptors accurately', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.spawn({ pid: 30, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await h.mkdirAll(30, '/tmp/forkjail/work');
  await h.mkdirAll(30, '/tmp/forkjail/other');
  await h.writeBytes(30, '/tmp/forkjail/note.txt', 'fork-inherited');

  await k.sys_chroot(30, '/tmp/forkjail');
  await k.sys_chdir(30, '/work');
  const keepFd = await k.proc_openat(30, OS_FD_ROOT, '/note.txt', O_RDONLY, 0, false);
  const cloexecFd = await k.proc_openat(30, OS_FD_ROOT, '/note.txt', O_RDONLY, 0, true);

  // 1. Ordinary fork copies FsContext & FdTable; exec_preserve keeps root/cwd/keepFd and closes FD_CLOEXEC
  h.fork(30, 31, 0);
  assert.equal(await k.sys_getcwd(31), '/work');
  assert.equal(await h.readText(31, '/note.txt'), 'fork-inherited');
  await k.sys_chdir(31, '/other');
  assert.equal(await k.sys_getcwd(30), '/work');
  assert.equal(await k.sys_getcwd(31), '/other');

  await k.proc_exec_preserve(31);
  assert.equal(await k.sys_getcwd(31), '/other');
  assert.equal(await h.readText(31, '/note.txt'), 'fork-inherited');
  assert.equal((await k.kfd_fstat(31, keepFd.kfd)).size, 14);
  await assert.rejects(k.kfd_fstat(31, cloexecFd.kfd), { errno: 'EBADF' });
  // Parent's cloexecFd is still open
  assert.equal((await k.kfd_fstat(30, cloexecFd.kfd)).size, 14);

  // 2. CLONE_FS shares root & cwd across processes until unshare(CLONE_FS) or exec_preserve
  await h.spawn({ pid: 32, ppid: 1, uid: 0, gid: 0, groups: [0] });
  h.fork(32, 33, CLONE_FS);
  await k.sys_chdir(33, '/tmp');
  assert.equal(await k.sys_getcwd(32), '/tmp');
  await k.sys_chroot(33, '/tmp/forkjail');
  await k.sys_chdir(33, '/work');
  assert.equal(await k.sys_getcwd(32), '/work');
  assert.equal(await h.readText(32, '/note.txt'), 'fork-inherited');

  await k.sys_unshare(33, CLONE_FS);
  await k.sys_chdir(33, '/other');
  assert.equal(await k.sys_getcwd(32), '/work');
  assert.equal(await k.sys_getcwd(33), '/other');

  // 3. CLONE_FILES shares descriptor table until unshare(CLONE_FILES)
  h.fork(32, 34, CLONE_FILES);
  const sharedOpen = await k.proc_openat(34, OS_FD_ROOT, '/note.txt', O_RDONLY, 0, false);
  assert.equal((await k.kfd_fstat(32, sharedOpen.kfd)).size, 14);

  await k.sys_unshare(34, CLONE_FILES);
  await k.kfd_close(34, sharedOpen.kfd);
  await assert.rejects(k.kfd_fstat(34, sharedOpen.kfd), { errno: 'EBADF' });
  assert.equal((await k.kfd_fstat(32, sharedOpen.kfd)).size, 14);
  await k.kfd_close(32, sharedOpen.kfd);
});

test('#! shebang resolution (single opt-arg, depth 4 + 5th -> ELOOP), MS_NOEXEC -> EACCES, and zero outside-root /usr fallback', async t => {
  const h = createHarness(t);
  const { k } = h;

  await h.spawn({ pid: 50, ppid: 1, uid: 0, gid: 0, groups: [0] });
  await h.mkdirAll(50, '/tmp/exec-suite/bin');
  await h.writeBytes(50, '/tmp/exec-suite/bin/interp.wasm', WASM_BIN, 0o755);
  await h.writeBytes(50, '/tmp/exec-suite/bin/nonexec.wasm', WASM_BIN, 0o644);

  // Non-executable 0o644 file fails with EACCES even for uid 0
  await assert.rejects(
    k.proc_resolve_exec(50, '/tmp/exec-suite/bin/nonexec.wasm', JSON.stringify(['nonexec']), '/usr/bin', false),
    { errno: 'EACCES' },
  );

  // Single optional argument rule (whitespace-trimmed remainder before '\n')
  await h.writeBytes(
    50,
    '/tmp/exec-suite/bin/s1',
    '#!  /tmp/exec-suite/bin/interp.wasm   -O   --flag value  \nbody\n',
    0o755,
  );
  const s1 = await k.proc_resolve_exec(50, '/tmp/exec-suite/bin/s1', JSON.stringify(['s1', 'argA']), '/usr/bin', false);
  assert.equal(s1.path, '/tmp/exec-suite/bin/interp.wasm');
  assert.deepEqual(s1.argv, ['/tmp/exec-suite/bin/interp.wasm', '-O   --flag value', '/tmp/exec-suite/bin/s1', 'argA']);

  // Depth 4 succeeds (s4 -> s3 -> s2 -> s1 -> interp.wasm); depth 5 (s5 -> s4) fails with ELOOP
  await h.writeBytes(50, '/tmp/exec-suite/bin/s2', '#!/tmp/exec-suite/bin/s1\n', 0o755);
  await h.writeBytes(50, '/tmp/exec-suite/bin/s3', '#!/tmp/exec-suite/bin/s2\n', 0o755);
  await h.writeBytes(50, '/tmp/exec-suite/bin/s4', '#!/tmp/exec-suite/bin/s3\n', 0o755);
  await h.writeBytes(50, '/tmp/exec-suite/bin/s5', '#!/tmp/exec-suite/bin/s4\n', 0o755);

  const depth4 = await k.proc_resolve_exec(50, '/tmp/exec-suite/bin/s4', JSON.stringify(['s4', 'tail']), '/usr/bin', false);
  assert.equal(depth4.path, '/tmp/exec-suite/bin/interp.wasm');
  assert.equal(depth4.argv.at(-1), 'tail');

  await assert.rejects(
    k.proc_resolve_exec(50, '/tmp/exec-suite/bin/s5', JSON.stringify(['s5']), '/usr/bin', false),
    { errno: 'ELOOP' },
  );

  // MS_NOEXEC mount returns EACCES; PATH search skips EACCES if a later directory succeeds, else returns EACCES
  await h.mkdirAll(50, '/tmp/noexec-mnt');
  await k.sys_mount(50, 'tmpfs', '/tmp/noexec-mnt', 'tmpfs', MS_NOEXEC, '');
  await h.writeBytes(50, '/tmp/noexec-mnt/tool', WASM_BIN, 0o755);
  await h.writeBytes(50, '/tmp/exec-suite/bin/tool', WASM_BIN, 0o755);

  await assert.rejects(
    k.proc_resolve_exec(50, '/tmp/noexec-mnt/tool', JSON.stringify(['tool']), '/usr/bin', false),
    { errno: 'EACCES' },
  );
  const fallbackOk = await k.proc_resolve_exec(
    50,
    'tool',
    JSON.stringify(['tool']),
    '/tmp/noexec-mnt:/tmp/exec-suite/bin',
    true,
  );
  assert.equal(fallbackOk.path, '/tmp/exec-suite/bin/tool');

  await assert.rejects(
    k.proc_resolve_exec(50, 'tool', JSON.stringify(['tool']), '/tmp/noexec-mnt:/no-such-dir', true),
    { errno: 'EACCES' },
  );

  // Zero outside-root /usr fallback inside an empty chroot
  await h.mkdirAll(50, '/tmp/empty-jail');
  await h.writeBytes(50, '/tmp/empty-jail/script.sh', '#!/usr/bin/sh\necho hi\n', 0o755);

  await h.spawn({ pid: 51, ppid: 50, uid: 0, gid: 0, groups: [0] });
  await k.sys_chroot(51, '/tmp/empty-jail');
  await k.sys_chdir(51, '/');

  await assert.rejects(
    k.proc_resolve_exec(51, '/usr/bin/ls', JSON.stringify(['ls']), '/usr/bin', false),
    { errno: 'ENOENT' },
  );
  await assert.rejects(
    k.proc_resolve_exec(51, 'ls', JSON.stringify(['ls']), '/usr/bin:/bin', true),
    { errno: 'ENOENT' },
  );
  await assert.rejects(
    k.proc_resolve_exec(51, '/script.sh', JSON.stringify(['/script.sh']), '/usr/bin', false),
    { errno: 'ENOENT' },
  );

  // Bind-mounting /usr into a populated jail enables chrooted system & #! execution cleanly
  await h.mkdirAll(50, '/tmp/pop-jail/usr');
  await k.proc_symlinkat(50, 'usr/bin', OS_FD_ROOT, '/tmp/pop-jail/bin');
  await k.sys_mount(50, '/usr', '/tmp/pop-jail/usr', '', MS_BIND, '');
  await h.writeBytes(50, '/tmp/pop-jail/run.sh', '#!/bin/sh -e\necho jailed\n', 0o755);

  await h.spawn({ pid: 52, ppid: 50, uid: 0, gid: 0, groups: [0] });
  await k.sys_chroot(52, '/tmp/pop-jail');
  await k.sys_chdir(52, '/');

  const jailedExec = await k.proc_resolve_exec(52, '/run.sh', JSON.stringify(['/run.sh', 'ok']), '/usr/bin', false);
  assert.equal(jailedExec.chroot, true);
  assert.equal(jailedExec.noUsrFallback, true);
  assert.deepEqual(jailedExec.argv.slice(-3), ['-e', '/run.sh', 'ok']);
});
