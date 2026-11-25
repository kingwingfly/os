import { test, expect } from './test.js';
import {
  pageCall,
  pageMkdirp,
  pagePut,
  pageRmrf,
  runTerminal,
  sendTerminalLine,
  terminalInput,
  terminalScreen,
  terminalText,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';
import { connectKernel, hookPageKernel } from './service-auth.js';
import binaryen from 'binaryen';

const sleep = { path: '/usr/bin/sleep', argv: ['sleep', '60'], env: [], cwd: '/' };
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };

async function freshKernel(page, name = '__sessionsKernel') {
  await page.goto('/login');
  const kernel = await connectKernel(page, { name });
  await kernel.value('machine_init_leave');
  return kernel;
}

async function invoke(kernel, proc, command, errno) {
  const result = await kernel.call('process_call', { pid: proc.pid, call: command });
  if (errno) {
    expect(result.err?.errno, JSON.stringify(result)).toBe(errno);
    return;
  }
  expect(result.err, JSON.stringify(result)).toBeUndefined();
  return result.ok;
}

const execProc = kernel => kernel.value('exec', sleep);
const forkProc = (kernel, parent) => kernel.value('fork', { pid: parent.pid });

async function cleanup(kernel, processes) {
  for (const p of processes.reverse()) {
    await kernel.call('kill', { pid: p.pid, signal: 9 });
    if (p.ppid != null) await kernel.call('waitchild', { ppid: p.ppid, pid: p.pid });
    else await kernel.call('wait', { pid: p.pid });
  }
}

test('session and group membership obey parent, exec and session boundaries', async ({ page }) => {
  const kernel = await freshKernel(page);
  const stranger = await connectKernel(page, { name: '__sessionsStranger' });
  const launcher = await execProc(kernel);
  const parent = { ...await forkProc(kernel, launcher), ppid: launcher.pid };
  const processes = [launcher, parent];
  try {
    const session = await invoke(kernel, parent, 'setsid');
    expect([session.sid, session.pgid]).toEqual([parent.pid, parent.pid]);
    await invoke(kernel, parent, 'setsid', 'EPERM');
    await invoke(kernel, parent, { setpgid: { pid: 0, pgid: 0 } }, 'EPERM');
    const child = { ...await forkProc(kernel, parent), ppid: parent.pid };
    processes.push(child);
    expect(await invoke(kernel, child, { getsid: { pid: 0 } })).toMatchObject({ sid: parent.pid, pgid: parent.pid });
    await invoke(kernel, parent, { setpgid: { pid: child.pid, pgid: child.pid } });
    expect(await invoke(kernel, child, { getpgid: { pid: 0 } })).toMatchObject({ pgid: child.pid });
    await invoke(kernel, child, 'setsid', 'EPERM');
    await invoke(kernel, child, { setpgid: { pid: 0, pgid: parent.pid } });
    expect(await invoke(kernel, child, 'setsid')).toMatchObject({ sid: child.pid, pgid: child.pid });
    await invoke(kernel, parent, { setpgid: { pid: child.pid, pgid: parent.pid } }, 'EPERM');
    const foreign = await execProc(kernel);
    processes.push(foreign);
    await invoke(kernel, parent, { setpgid: { pid: foreign.pid, pgid: parent.pid } }, 'ESRCH');
    await invoke(kernel, parent, { setpgid: { pid: -1, pgid: 0 } }, 'EINVAL');
    const next = { ...await forkProc(kernel, parent), ppid: parent.pid };
    processes.push(next);
    await kernel.value('reexec', { ...sleep, pid: next.pid });
    await invoke(kernel, parent, { setpgid: { pid: next.pid, pgid: parent.pid } }, 'EACCES');
    expect(await invoke(kernel, next, { getsid: { pid: 0 } })).toMatchObject({ sid: parent.pid, pgid: parent.pid });
    // Foreign host cannot invoke setsid on another instance's process.
    expect((await stranger.call('process_call', { pid: parent.pid, call: 'setsid' })).err?.errno).toBe('ESRCH');
  } finally {
    await cleanup(kernel, processes);
    await stranger.terminate();
    await kernel.terminate();
  }
});

test('group signals and wait selectors preserve siblings and report each state once', async ({ page }) => {
  const kernel = await freshKernel(page);
  const launcher = await execProc(kernel);
  const parent = { ...await forkProc(kernel, launcher), ppid: launcher.pid };
  const processes = [launcher, parent];
  try {
    await invoke(kernel, parent, 'setsid');
    const a = { ...await forkProc(kernel, parent), ppid: parent.pid };
    const b = { ...await forkProc(kernel, parent), ppid: parent.pid };
    const other = { ...await forkProc(kernel, parent), ppid: parent.pid };
    processes.push(a, b, other);
    await invoke(kernel, parent, { setpgid: { pid: a.pid, pgid: a.pid } });
    await invoke(kernel, parent, { setpgid: { pid: b.pid, pgid: a.pid } });
    await kernel.value('kill', { pid: -a.pid, signal: 0, from: parent.pid });
    await kernel.value('kill', { pid: -a.pid, signal: 19, from: parent.pid });
    for (const child of [a, b]) {
      expect(await invoke(kernel, parent, { waitpid: { pid: -a.pid, options: 3 } })).toMatchObject({
        pid: child.pid,
        stopped: true,
        status: 19 * 256 + 127,
      });
    }
    expect(await invoke(kernel, parent, { waitpid: { pid: -a.pid, options: 3 } })).toEqual({ nothing: true });
    await kernel.value('kill', { pid: -a.pid, signal: 18, from: parent.pid });
    for (const child of [a, b]) {
      expect(await invoke(kernel, parent, { waitpid: { pid: -a.pid, options: 9 } })).toMatchObject({
        pid: child.pid,
        continued: true,
        status: 65535,
      });
    }
    expect(await invoke(kernel, parent, { waitpid: { pid: 0, options: 1 } })).toEqual({ nothing: true });
    await kernel.value('kill', { pid: -a.pid, signal: 9, from: parent.pid });
    for (const child of [a, b]) {
      expect(await invoke(kernel, parent, { waitpid: { pid: -a.pid, options: 1 } })).toMatchObject({
        pid: child.pid,
        signal: 9,
      });
    }
    await invoke(kernel, parent, { waitpid: { pid: -a.pid, options: 1 } }, 'ECHILD');
    expect(await invoke(kernel, parent, { getpgid: { pid: other.pid } })).toMatchObject({ pgid: parent.pid });
    expect(await invoke(kernel, parent, { waitpid: { pid: other.pid, options: 1 } })).toEqual({ nothing: true });
  } finally {
    await cleanup(kernel, processes);
    await kernel.terminate();
  }
});

test('session bootstrap checks every proof before changing any process', async ({ page }) => {
  const kernel = await freshKernel(page);
  const stranger = await connectKernel(page, { name: '__sessionBootStranger' });
  const a = await execProc(kernel), b = await execProc(kernel), processes = [a, b];
  try {
    const beforeA = await invoke(kernel, a, { getsid: { pid: 0 } });
    // Any unowned/nonexistent pid in the batch fails atomically without modifying `a`.
    expect((await kernel.call('session', { pids: [a.pid, 99999] })).err?.errno).toBe('ESRCH');
    expect(await invoke(kernel, a, { getsid: { pid: 0 } })).toEqual(beforeA);
    // Duplicate pid in bootstrap fails EINVAL.
    expect((await kernel.call('session', { pids: [a.pid, a.pid] })).err?.errno).toBe('EINVAL');
    // Another kernel host cannot bootstrap `a`'s session.
    expect((await stranger.call('session', { pids: [a.pid] })).err?.errno).toBe('ESRCH');
    // Process calls cannot invoke session bootstrap.
    expect((await kernel.call('process_call', { pid: a.pid, call: { proc_session: { processes: [{ pid: a.pid, proc: '' }] } } })).err).toBeTruthy();

    const started = await kernel.value('session', { pids: [a.pid, b.pid] });
    expect(started.map(row => [row.sid, row.pgid])).toEqual([[a.pid, a.pid], [a.pid, a.pid]]);
    // Second bootstrap on an already-bootstrapped process is refused.
    expect((await kernel.call('session', { pids: [b.pid] })).err?.errno).toBe('EPERM');
  } finally {
    await cleanup(kernel, processes);
    await stranger.terminate();
    await kernel.terminate();
  }
});

test('orphaning a stopped group sends HUP and CONT and preserves group identity', async ({ page }) => {
  const kernel = await freshKernel(page);
  const launcher = await execProc(kernel);
  const parent = { ...await forkProc(kernel, launcher), ppid: launcher.pid };
  const processes = [launcher, parent];
  try {
    await invoke(kernel, parent, 'setsid');
    const child = { ...await forkProc(kernel, parent), ppid: parent.pid };
    processes.push(child);
    await invoke(kernel, parent, { setpgid: { pid: child.pid, pgid: 0 } });
    await kernel.value('kill', { pid: child.pid, signal: 19, from: parent.pid });
    await kernel.value('exit', { pid: parent.pid, status: 0 });
    // Reparented to PID 1 when `parent` exited; update cleanup ppid.
    child.ppid = null;
    const kept = (await kernel.value('sync')).find(row => row.pid === child.pid);
    expect(kept).toMatchObject({ ppid: 1, sid: parent.pid, pgid: child.pid, state: 'running' });
    expect(kept.pending_signals.map(event => event.signal)).toEqual([1, 18]);
  } finally {
    await cleanup(kernel, processes);
    await kernel.terminate();
  }
});

test('a group signal reaches permitted members without enlarging account authority', async ({ page }) => {
  const kernel = await freshKernel(page);
  await kernel.value('sync_account', ROOT_ACCOUNT);
  const sessionLeader = await execProc(kernel);
  const root = { ...await forkProc(kernel, sessionLeader), ppid: sessionLeader.pid };
  const guest = { ...await forkProc(kernel, sessionLeader), ppid: sessionLeader.pid };
  const processes = [sessionLeader, root, guest];
  try {
    await invoke(kernel, root, { setpgid: { pid: 0, pgid: 0 } });
    // Drop `guest` to unprivileged UID 65534 within the same session; group membership must never grant signaling rights over root.
    await kernel.value('set_proc_cred', { pid: guest.pid, uid: 65534, gid: 65534, groups: [65534] });
    await invoke(kernel, guest, { setpgid: { pid: 0, pgid: root.pid } });
    await kernel.value('kill', { pid: -root.pid, signal: 10, from: guest.pid });

    const rows = await kernel.value('sync');
    expect(rows.find(row => row.pid === root.pid).pending_signals ?? []).toEqual([]);
    expect(rows.find(row => row.pid === guest.pid).pending_signals.map(event => event.signal)).toEqual([10]);

    const metadata = await invoke(kernel, guest, { getpgid: { pid: root.pid } });
    expect(Object.keys(metadata).sort()).toEqual(['pgid', 'pid', 'ppid', 'sid']);
    expect((await kernel.call('kill', { pid: root.pid, signal: 0, from: guest.pid })).err?.errno).toBe('EPERM');
  } finally {
    await cleanup(kernel, processes);
    await kernel.terminate();
  }
});

async function interactive(page) {
  const pageKernel = await hookPageKernel(page);
  await page.goto('/');
  await pageKernel.ready();
  await waitForTerminalReady(page);
  await runTerminal(page, 'sh -i', { wait: false });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy', { timeout: 60_000 });
  await expect.poll(() => terminalText(page), { timeout: 60_000 }).toMatch(/\n\$\s*$/);
  return pageKernel;
}

test('dash owns stopped foreground jobs and can resume them without stopping its shell', async ({ page }) => {
  await interactive(page);
  await sendTerminalLine(page, 'echo shell:$$');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/^shell:\d+\s*$/m);
  await sendTerminalLine(page, 'sleep 60');
  await page.waitForTimeout(500);
  await terminalInput(page).press('Control+z');
  await expect(terminalScreen(page)).toContainText('Stopped', { timeout: 20_000 });
  await sendTerminalLine(page, 'jobs');
  await expect(terminalScreen(page)).toContainText('sleep 60');
  await sendTerminalLine(page, 'fg');
  await page.waitForTimeout(300);
  await terminalInput(page).press('Control+c');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/\n\$\s*$/);
  await sendTerminalLine(page, 'echo rec"ov"ered; exit');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await expect(terminalScreen(page)).toContainText('recovered');
});

test('background reads stop with SIGTTIN and fg gives the child terminal input', async ({ page }) => {
  const pageKernel = await interactive(page);
  await sendTerminalLine(page, 'cat &');
  await expect.poll(async () => (await pageKernel.value('poll', { pids: [] })).some(row => row.argv[0] === 'cat' && row.state === 'stopped'), { timeout: 20_000 }).toBe(true);
  await sendTerminalLine(page, 'jobs');
  await expect(terminalScreen(page)).toContainText('Stopped', { timeout: 20_000 });
  await sendTerminalLine(page, 'fg');
  await page.waitForTimeout(300);
  await sendTerminalLine(page, 'foreground-input');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toContain('foreground-input\nforeground-input');
  await terminalInput(page).press('Control+c');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/\n\$\s*$/);
  await sendTerminalLine(page, 'exit');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
});

test('Ctrl+C targets the foreground pipeline while a background job and the shell survive', async ({ page }) => {
  const pageKernel = await interactive(page);
  await sendTerminalLine(page, 'sleep 60 &');
  const rows = () => pageKernel.value('poll', { pids: [] });
  await expect.poll(async () => (await rows()).some(row => row.argv[0] === 'sleep')).toBe(true);
  const background = (await rows()).find(row => row.argv[0] === 'sleep');
  await sendTerminalLine(page, 'yes | cat');
  await expect.poll(async () => (await rows()).filter(row => ['yes', 'cat'].includes(row.argv[0])).length).toBe(2);
  const foreground = (await rows()).filter(row => ['yes', 'cat'].includes(row.argv[0]));
  expect(new Set(foreground.map(row => row.pgid)).size).toBe(1);
  expect(foreground[0].pgid).not.toBe(background.pgid);
  await terminalInput(page).press('Control+c');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/\n\$\s*$/);
  expect((await rows()).find(row => row.pid === background.pid)?.state).toBe('running');
  await sendTerminalLine(page, 'kill $!; wait $!; echo sur"vi"ved; exit');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await expect(terminalScreen(page)).toContainText('survived');
});

test('stty tostop stops background terminal writes and fg lets them complete', async ({ page }) => {
  const pageKernel = await interactive(page);
  await sendTerminalLine(page, 'stty tostop; echo con"fig"ured');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/configured\s*\n\$\s*$/);
  await sendTerminalLine(page, 'echo back"ground"-write &');
  await expect.poll(async () => (await pageKernel.value('poll', { pids: [] })).some(row => row.ppid !== 1 && row.state === 'stopped')).toBe(true);
  // Registry stop state can precede dash consuming SIGCHLD/wait status. Each
  // jobs invocation is a snapshot; ask again until the shell has observed it.
  await expect.poll(async () => {
    await sendTerminalLine(page, 'jobs');
    return (await terminalText(page)).includes('Stopped (tty output)');
  }).toBe(true);
  await sendTerminalLine(page, 'fg');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/background-write\s*\n\$\s*$/);
  await sendTerminalLine(page, 'stty -tostop; exit');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
});

test('setsid detaches the controlling terminal without closing inherited descriptors', async ({ page }) => {
  const base = '/tmp/session-' + crypto.randomUUID();
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
  await pageMkdirp(page, base, 0o755);
  const module = binaryen.parseText(`(module
    (import "os" "getpgid" (func $pgid (param i32) (result i32)))
    (import "os" "getsid" (func $sid (param i32) (result i32)))
    (import "os" "setsid" (func $setsid (result i32)))
    (import "os" "tcgetpgrp" (func $foreground (param i32) (result i32)))
    (import "os" "tcsetpgrp" (func $setfg (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "detached") (data (i32.const 150) "/dev/tty")
    (func $assert (param i32) (if (i32.eqz (local.get 0)) (then unreachable)))
    (func (export "_start") (local $session i32)
      (call $assert (i32.gt_s (call $foreground (i32.const 0)) (i32.const 0)))
      (call $assert (i32.eq (call $setfg (i32.const 0) (i32.const 2147483647)) (i32.const -63)))
      (call $assert (i32.eq (call $pgid (i32.const -1)) (i32.const -28)))
      (local.set $session (call $setsid))
      (call $assert (i32.gt_s (local.get $session) (i32.const 1)))
      (call $assert (i32.eq (call $sid (i32.const 0)) (local.get $session)))
      (call $assert (i32.eq (call $pgid (i32.const 0)) (local.get $session)))
      (call $assert (i32.eq (call $setsid) (i32.const -63)))
      (call $assert (i32.eq (call $foreground (i32.const 0)) (i32.const -59)))
      (call $assert (i32.eq (call $setfg (i32.const 0) (local.get $session)) (i32.const -59)))
      (call $assert (i32.eq (call $open (i32.const 3) (i32.const 1) (i32.const 150) (i32.const 8) (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 32)) (i32.const 60)))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 8))
      (call $assert (i32.eqz (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))))))`);
  try {
    await pagePut(page, base + '/probe', Buffer.from(module.emitBinary()), { mode: 0o755 });
    await pageCall(page, { chmod: { path: base + '/probe', mode: 0o755 } });
    const out = await page.evaluate(async base => {
      let stdout = '';
      let stderr = '';
      const res = await window.os.exec([{ path: '/usr/bin/sh', argv: ['sh', '-c', `${base}/probe; echo :$?`] }], {
        tty: true,
        onOutput(fd, text) {
          if (fd === 1) stdout += text.replace(/\r\n/g, '\n');
          else if (fd === 2) stderr += text.replace(/\r\n/g, '\n');
        },
      });
      return { status: res.status, stdout, stderr };
    }, base);
    expect(out.status, out.stderr).toBe(0);
    expect(out.stdout.trim()).toBe('detached:0');
  } finally {
    module.dispose();
    await pageRmrf(page, base);
  }
});
