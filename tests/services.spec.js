import { test, expect } from './test.js';
import { api, call, errno, put, rmrf } from './sys.js';
import { readFile } from 'node:fs/promises';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
let base, sequence;
const unit = (name, argv, extra = {}) => ({ name, argv, ...extra });
const text = page => page.evaluate(() => window.serviceRun.output.replace(/\r\n/g, '\n'));
test.beforeEach(async ({ page }) => {
  await page.goto('/'); await page.waitForFunction(() => !!window.os?.exec);
  base = '/guest/services-' + crypto.randomUUID(); sequence = 0;
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
});
test.afterEach(async ({ page }) => {
  await page.evaluate(async () => { window.serviceRun?.group?.signal(9); await window.serviceRun?.done; });
  await rmrf(page.request, base);
});
async function start(page, units, { check = false, raw, argv, shell = false } = {}) {
  const path = base + '/units-' + sequence++ + '.json';
  expect((await put(page.request, '/api/file?path=' + encodeURIComponent(path), { data: raw ?? JSON.stringify({ version: 1, units }) })).ok()).toBe(true);
  await page.evaluate(({ path, check, argv, shell }) => {
    const run = window.serviceRun = { output: '', pids: [] };
    run.done = window.os.exec([shell ? { path: '/usr/bin/sh', argv: ['sh', '-c', 'supervise "$1"', 'sh', path] }
      : { path: '/usr/bin/supervise', argv: argv ?? ['supervise', ...(check ? ['--check'] : []), path] }], {
      tty: true, stdin: '',
      onOutput: (fd, value) => { run.output = (run.output + value).slice(-131072); },
      onJob: group => { run.group = group; },
      onTty: input => { run.input = input; },
    }).then(result => { run.result = result; }, error => { run.error = String(error?.message ?? error); });
  }, { path, check, argv, shell });
}
async function done(page, status = 0) {
  await expect.poll(() => page.evaluate(() => !!window.serviceRun.result || !!window.serviceRun.error), { timeout: 60_000 }).toBe(true);
  const output = await text(page);
  expect(await page.evaluate(() => window.serviceRun.result?.status ?? window.serviceRun.error), output).toBe(status);
  return output;
}
async function waitText(page, value) { await expect.poll(() => text(page), { timeout: 60_000 }).toContain(value); }
async function terminate(page) {
  const pid = await page.evaluate(() => window.serviceRun.group.pids[0]);
  await call(page.request, { kill: { pid: String(pid), signal: 15 } });
}

test('supervise is an immutable ordinary executable with generated help and check-only validation', async ({ page }) => {
  const image = await call(page.request, { stat: { path: '/usr/bin/supervise' } });
  expect(image.mode).toBe(0o100755); expect(image.size).toBeGreaterThan(100000);
  expect(await errno(page.request, { chmod: { path: '/usr/bin/supervise', mode: 0o777 } })).toBe('EROFS');
  await start(page, [unit('check', ['touch', base + '/should-not-exist'])], { check: true });
  expect(await done(page)).toBe('');
  expect(await errno(page.request, { stat: { path: base + '/should-not-exist' } })).toBe('ENOENT');
  await start(page, [], { argv: ['supervise', '--help'] });
  expect(await done(page)).toContain('supervise');
});

test('invalid graphs, identities and unsupported contracts fail before any service starts', async ({ page }) => {
  const first = unit('first', ['touch', base + '/should-not-exist']);
  for (const bad of [
    unit('second', ['true'], { identity: 'root' }),
    unit('second', ['true'], { limits: { cpu: 1024 } }),
    unit('second', ['true'], { readiness: 'health-check' }),
    unit('second', ['true'], { startup_timeout_ms: 60001 }),
    unit('second', ['true'], { environment: { OS_READY_FD: '1' } }),
    unit('second', ['true'], { requires: ['missing'] }),
    unit('second', ['true'], { after: ['second'] }),
  ]) {
    await start(page, [first, bad]);
    expect(await done(page, 1)).not.toContain('started pid');
    expect(await errno(page.request, { stat: { path: base + '/should-not-exist' } })).toBe('ENOENT');
  }
});

test('argv, cwd, explicit environment and null stdin reach the service without implicit shell parsing', async ({ page }) => {
  await start(page, [unit('env', ['sh', '-c', 'printf "cwd:%s env:%s missing:%s\\n" "$PWD" "$EXPLICIT" "${HOME-unset}"; cat; printf STDIN_EOF'], { cwd: base, environment: { EXPLICIT: 'literal;$HOME' } }),
    unit('args', ['printf', 'ARG:%s', '; echo INJECTION'], { after: ['env'] })]);
  const output = await done(page);
  expect(output).toContain(`cwd:${base} env:literal;$HOME missing:unset`);
  expect(output).toContain('STDIN_EOF'); expect(output).toContain('ARG:; echo INJECTION');
});

test('requires blocks on failure while ordering alone lets its command run', async ({ page }) => {
  await start(page, [
    unit('required', ['echo', 'SHOULD_NOT_RUN'], { requires: ['missing'] }),
    unit('ordered', ['echo', 'ORDER_ONLY_RUNS'], { after: ['missing'] }),
    unit('missing', ['/definitely-missing']),
  ]);
  const output = await done(page, 1);
  expect(output).toContain('ORDER_ONLY_RUNS'); expect(output).not.toContain('SHOULD_NOT_RUN');
});

test('on-failure restart has a lifetime budget and a minimum delay', async ({ page }) => {
  const began = Date.now();
  await start(page, [unit('retry', ['sh', '-c', 'echo ATTEMPT; exit 7'], { restart: 'on-failure', max_restarts: 2, restart_delay_ms: 200 })]);
  const output = await done(page, 1);
  expect(output.match(/ATTEMPT/g)).toHaveLength(3); expect(Date.now() - began).toBeGreaterThan(400);
});

test('successful commands do not restart under on-failure', async ({ page }) => {
  await start(page, [unit('once', ['echo', 'ONCE'], { restart: 'on-failure', max_restarts: 2 })]);
  expect((await done(page)).match(/ONCE/g)).toHaveLength(1);
});

test('TERM reaches the service process group and allows its shutdown handler to finish', async ({ page }) => {
  await start(page, [unit('graceful', ['sh', '-c', 'trap "echo CLEAN_STOP; exit 0" TERM; echo SERVICE_READY; while :; do sleep 0.1; done'])]);
  await waitText(page, 'SERVICE_READY');
  const pids = await page.evaluate(() => [...window.serviceRun.group.pids]);
  await terminate(page);
  const output = await done(page, 143);
  expect(output).toContain('CLEAN_STOP'); expect(output).not.toContain('signal 9');
  for (const pid of pids) await expect.poll(() => errno(page.request, { stat: { path: `/proc/${pid}` } })).toBe('ENOENT');
});

test('shutdown continues stopped groups and escalates TERM-ignoring services to KILL', async ({ page }) => {
  await start(page, [unit('stubborn', ['sh', '-c', 'trap "" TERM; echo IGNORING_TERM; while :; do sleep 1; done'], { stop_timeout_ms: 200 })]);
  await waitText(page, 'IGNORING_TERM');
  const output = await text(page), pid = Number(output.match(/stubborn: started pid (\d+)/)[1]);
  await call(page.request, { kill: { pid: '-' + pid, signal: 19 } });
  await terminate(page);
  expect(await done(page, 143)).toContain('stubborn: signal 9');
  await expect.poll(() => errno(page.request, { stat: { path: `/proc/${pid}` } })).toBe('ENOENT');
});

test('shutdown during restart backoff cannot launch another attempt', async ({ page }) => {
  await start(page, [unit('backoff', ['sh', '-c', 'echo ONE_ATTEMPT; exit 1'], { restart: 'always', max_restarts: 3, restart_delay_ms: 10000 })]);
  await waitText(page, 'backoff: exited 1'); await terminate(page);
  expect((await done(page, 143)).match(/ONE_ATTEMPT/g)).toHaveLength(1);
});

test('service launches preserve the supervisor credential snapshot across browser login', async ({ page }) => {
  const creds = await call(page.request, 'getcreds');
  await start(page, [unit('identity', ['sh', '-c', 'id -u; sleep 0.5; exit 1'], { restart: 'on-failure', max_restarts: 1, restart_delay_ms: 200 })]);
  await waitText(page, String(creds.uid));
  expect((await api(page.request, 'login', { headers: { 'CF-Connecting-IP': 'services-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true);
  const output = await done(page, 1);
  expect(output.split('\n').filter(line => line === String(creds.uid))).toHaveLength(2);
  expect(output.split('\n')).not.toContain('0');
});

test('another account resource remains denied even with a forged environment', async ({ page }) => {
  await start(page, [unit('denied', ['sh', '-c', 'echo bad > /root/service-forbidden'], { environment: { USER: 'root', HOME: '/root' } })]);
  expect(await done(page, 1)).toContain('Permission denied');
});

test('failed requirements stop live dependents and do not restart them', async ({ page }) => {
  await start(page, [unit('provider', ['sh', '-c', 'sleep 0.3; exit 1']),
    unit('dependent', ['sh', '-c', 'echo DEPENDENT_STARTED; sleep 30'], { requires: ['provider'], restart: 'always', max_restarts: 2 })]);
  const output = await done(page, 1);
  expect(output.match(/DEPENDENT_STARTED/g)).toHaveLength(1); expect(output).toContain('dependent: signal 15');
});

test('same-group background children are killed when the service leader exits', async ({ page }) => {
  await start(page, [unit('children', ['sh', '-c', 'sleep 30 & echo CHILD:$!; exit 0'])]);
  const output = await done(page);
  const pid = output.match(/CHILD:(\d+)/)?.[1]; expect(pid).toBeTruthy();
  await expect.poll(() => errno(page.request, { stat: { path: `/proc/${pid}` } })).toBe('ENOENT');
});

test('installed dash resolves and executes the same supervisor through PATH', async ({ page }) => {
  await start(page, [unit('from-dash', ['echo', 'SUPERVISED_FROM_DASH'])], { shell: true });
  expect(await done(page)).toContain('SUPERVISED_FROM_DASH');
});

test('terminal Ctrl+C shuts down services through the supervisor foreground group', async ({ page }) => {
  await start(page, [unit('interrupt', ['sh', '-c', 'trap "echo INTERRUPT_CLEANUP; exit 0" TERM; echo INTERRUPT_READY; while :; do sleep 0.1; done'])]);
  await waitText(page, 'INTERRUPT_READY');
  await page.evaluate(() => window.serviceRun.input.write('\x03'));
  expect(await done(page, 130)).toContain('INTERRUPT_CLEANUP');
});

test('idle services do not continuously poll the registry for child exits', async ({ page }) => {
  let waits = 0, supervisor;
  page.on('request', request => {
    if (!request.url().endsWith('/api/sys') || request.method() !== 'POST') return;
    const body = request.postDataJSON();
    if (body.pid === supervisor) waits += body.calls.filter(call => call.waitpid).length;
  });
  await start(page, [unit('idle', ['sleep', '30'])]);
  await waitText(page, 'idle: started pid');
  supervisor = await page.evaluate(() => window.serviceRun.group.pids[0]);
  // Measure idle network traffic over a real interval, rather than asserting an
  // implementation-specific internal wakeup count.
  await page.waitForTimeout(500);
  expect(waits).toBe(0);
  await terminate(page); await done(page, 143);
});

test('coalesced SIGCHLD notifications reap every completed direct child', async ({ page }) => {
  await start(page, Array.from({ length: 6 }, (_, i) => unit('quick-' + i, ['echo', 'CHILD_DONE_' + i])));
  const output = await done(page);
  for (let i = 0; i < 6; i++) expect(output).toContain('CHILD_DONE_' + i);
  expect(output.match(/exited 0/g)).toHaveLength(6);
});

test('notify readiness waits for the complete pipe message while after only orders launch', async ({ page }) => {
  await start(page, [
    unit('provider', ['sh', '-c', `printf REA >&"$OS_READY_FD"; echo PARTIAL_NOTIFICATION; while [ ! -f '${base}/release' ]; do sleep 0.1; done; printf 'DY=1\\n' >&"$OS_READY_FD"; sleep 0.2`], { readiness: 'notify', startup_timeout_ms: 30000 }),
    unit('required', ['echo', 'REQUIRED_STARTED'], { requires: ['provider'] }),
    unit('ordered', ['echo', 'ORDER_ONLY_STARTED'], { after: ['provider'] }),
  ]);
  await waitText(page, 'PARTIAL_NOTIFICATION'); await waitText(page, 'ORDER_ONLY_STARTED');
  const partial = await text(page);
  expect(partial).not.toContain('provider: Ready'); expect(partial).not.toContain('REQUIRED_STARTED');
  expect((await put(page.request, '/api/file?path=' + encodeURIComponent(base + '/release'), { data: 'go' })).ok()).toBe(true);
  const output = await done(page);
  expect(output).toContain('provider: Ready'); expect(output).toContain('REQUIRED_STARTED');
  expect(output.indexOf('provider: Ready')).toBeLessThan(output.indexOf('REQUIRED_STARTED'));
});

test('stdout cannot notify readiness and a clean exit without notification fails its dependents', async ({ page }) => {
  await start(page, [unit('silent', ['sh', '-c', 'printf "READY=1\\n"; exit 0'], { readiness: 'notify' }),
    unit('blocked', ['echo', 'INCORRECT_START'], { requires: ['silent'] })]);
  const output = await done(page, 1);
  expect(output).toContain('READY=1'); expect(output).not.toContain('silent: Ready');
  expect(output).not.toContain('INCORRECT_START');
});

test('notify accepts inherited helper and exec writes including immediate successful exit', async ({ page }) => {
  await start(page, [unit('helper', ['sh', '-c', '(printf REA >&"$OS_READY_FD") & wait; exec sh -c \'printf "DY=1\\n" >&"$OS_READY_FD"\''], { readiness: 'notify' }),
    unit('dependent', ['echo', 'HELPER_ACCEPTED'], { requires: ['helper'] })]);
  const output = await done(page);
  expect(output).toContain('helper: Ready'); expect(output).toContain('HELPER_ACCEPTED');
});

test('the startup deadline stops applying once a service has notified readiness', async ({ page }) => {
  await start(page, [unit('ready-longer', ['sh', '-c', 'printf "READY=1\\n" >&"$OS_READY_FD"; sleep 2; echo STILL_READY'], {
    readiness: 'notify', startup_timeout_ms: 1500,
  })]);
  const output = await done(page);
  expect(output).toContain('ready-longer: Ready'); expect(output).toContain('STILL_READY');
  expect(output).not.toContain('startup deadline exceeded');
});

test('malformed and prematurely closed readiness pipes fail promptly and clean up the group', async ({ page }) => {
  for (const send of ['printf "BROKEN\\n" >&"$OS_READY_FD"', 'eval "exec $OS_READY_FD>&-"']) {
    await start(page, [unit('bad', ['sh', '-c', `trap 'echo CLEANED; exit 0' TERM; ${send}; echo BAD_RUNNING; while :; do sleep 0.1; done`], { readiness: 'notify', startup_timeout_ms: 30000 }),
      unit('blocked', ['echo', 'INCORRECT_START'], { requires: ['bad'] })]);
    const output = await done(page, 1);
    expect(output).toContain('bad: readiness failed:'); expect(output).toContain('CLEANED');
    expect(output).not.toContain('startup deadline exceeded'); expect(output).not.toContain('INCORRECT_START');
  }
});

test('startup deadlines kill TERM-ignoring groups and use a bounded retry budget', async ({ page }) => {
  await start(page, [unit('timeout', ['sh', '-c', 'trap "" TERM; echo TIMEOUT_ATTEMPT; while :; do sleep 1; done'], {
    readiness: 'notify', startup_timeout_ms: 1500, stop_timeout_ms: 100, restart: 'on-failure', max_restarts: 1, restart_delay_ms: 100,
  }), unit('blocked', ['echo', 'INCORRECT_START'], { requires: ['timeout'] })]);
  const output = await done(page, 1);
  expect(output.match(/TIMEOUT_ATTEMPT/g)).toHaveLength(2);
  expect(output.match(/timeout: startup deadline exceeded/g)).toHaveLength(2);
  expect(output.match(/timeout: signal 9/g)).toHaveLength(2);
  expect(output).not.toContain('INCORRECT_START');
  for (const [, pid] of output.matchAll(/timeout: started pid (\d+)/g)) {
    await expect.poll(() => errno(page.request, { stat: { path: `/proc/${pid}` } })).toBe('ENOENT');
  }
});

test('a fresh retry can notify after a failed attempt and retains the original credentials', async ({ page }) => {
  const creds = await call(page.request, 'getcreds');
  await start(page, [unit('retry-notify', ['sh', '-c', `id -u; if [ ! -f '${base}/attempted' ]; then touch '${base}/attempted'; echo FIRST_ATTEMPT; exit 0; fi; printf 'READY=1\\n' >&"$OS_READY_FD"; echo SECOND_READY`], {
    readiness: 'notify', restart: 'on-failure', max_restarts: 1, restart_delay_ms: 3000,
  }), unit('dependent', ['echo', 'AFTER_RETRY'], { requires: ['retry-notify'] })]);
  await waitText(page, 'FIRST_ATTEMPT');
  expect((await api(page.request, 'login', { headers: { 'CF-Connecting-IP': 'notify-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true);
  const output = await done(page);
  expect(output.split('\n').filter(line => line === String(creds.uid))).toHaveLength(2);
  expect(output).toContain('SECOND_READY'); expect(output).toContain('AFTER_RETRY');
  expect(output.match(/retry-notify: Ready/g)).toHaveLength(1);
});

test('a sibling cannot inherit another service readiness descriptor or keep its writer alive', async ({ page }) => {
  await start(page, [unit('provider', ['sh', '-c', `echo "$OS_READY_FD" > '${base}/fd'; echo PIPE_OPEN; while [ ! -f '${base}/checked' ]; do sleep 0.1; done; eval "exec $OS_READY_FD>&-"; sleep 30`], { readiness: 'notify', startup_timeout_ms: 30000 }),
    unit('sibling', ['sh', '-c', `while [ ! -f '${base}/fd' ]; do sleep 0.1; done; read FD < '${base}/fd'; if (printf 'READY=1\\n' >&"$FD") 2>/dev/null; then echo LEAKED_WRITER; else echo PRIVATE_PIPE; fi; echo "env:\${OS_READY_FD-unset}"; touch '${base}/checked'; sleep 30`], { after: ['provider'] }),
    unit('blocked', ['echo', 'INCORRECT_START'], { requires: ['provider'] })]);
  await waitText(page, 'PRIVATE_PIPE'); await waitText(page, 'readiness pipe closed');
  const output = await text(page);
  expect(output).toContain('env:unset'); expect(output).not.toContain('LEAKED_WRITER');
  expect(output).not.toContain('INCORRECT_START');
  await terminate(page); await done(page, 143);
});

test('shutdown while waiting for readiness cleans up without launching dependents or retries', async ({ page }) => {
  await start(page, [unit('starting', ['sh', '-c', 'trap "echo STARTUP_STOPPED; exit 0" TERM; echo WAITING_READY; while :; do sleep 0.1; done'], {
    readiness: 'notify', startup_timeout_ms: 30000, restart: 'always', max_restarts: 2,
  }), unit('blocked', ['echo', 'INCORRECT_START'], { requires: ['starting'] })]);
  await waitText(page, 'WAITING_READY'); await terminate(page);
  const output = await done(page, 143);
  expect(output).toContain('STARTUP_STOPPED'); expect(output.match(/WAITING_READY/g)).toHaveLength(1);
  expect(output).not.toContain('INCORRECT_START'); expect(output).not.toContain('startup deadline exceeded');
});

test('readiness polling uses the local pipe without repeated registry waits', async ({ page }) => {
  let waits = 0, supervisor;
  page.on('request', request => {
    if (!request.url().endsWith('/api/sys') || request.method() !== 'POST') return;
    const body = request.postDataJSON();
    if (body.pid === supervisor) waits += body.calls.filter(call => call.waitpid).length;
  });
  await start(page, [unit('pending', ['sh', '-c', 'echo WAITING_IN_PIPE; exec sleep 30'], { readiness: 'notify', startup_timeout_ms: 30000 })]);
  await waitText(page, 'WAITING_IN_PIPE');
  supervisor = await page.evaluate(() => window.serviceRun.group.pids[0]);
  await page.waitForTimeout(500); expect(waits).toBe(0);
  await terminate(page); await done(page, 143);
});
