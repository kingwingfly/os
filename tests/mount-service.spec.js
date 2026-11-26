// Integrated cases run against the packaged instance with the system and user units installed.
import { test, expect } from './test.js';
import { test as component } from '@playwright/test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { mountsFrame, pageCall, switchLocalUser, waitForMountsReady, waitForTerminalReady, waitForUserServices } from './ui.js';
import { SourceRegistry, mountPageRequest, prepareRenewal, registerPickedFolder, serveMountBackend } from '../web/kernel/source-registry.js';

const target = '/mnt/local/project';
const app = page => mountsFrame(page);
async function boot(page) {
  await page.goto('/');
  await page.waitForFunction(() => typeof window.os?.exec === 'function' && !!window.os.localMounts);
  await waitForUserServices(page);
}
function exec(page, argv, options = {}) {
  return page.evaluate(async ({ argv, options }) => {
    let stdout = '', stderr = '';
    const res = await window.os.exec([{ path: '/usr/bin/' + argv[0], argv }], {
      cwd: '/', ...options, onOutput(fd, text) { if (fd === 1) stdout += text; else stderr += text; },
    });
    return { status: res.status, out: stdout || res.stdout || '', err: stderr };
  }, { argv, options });
}
async function ok(page, argv, options) {
  const r = await exec(page, argv, options);
  expect(r.status, r.err || r.out).toBe(0);
  return r.out;
}
async function ctl(page, ...args) {
  return JSON.parse(await ok(page, ['mountctl', '--json', ...args]));
}
async function open(page, pane = 'mounted') {
  await page.evaluate(pane => window.os.localMounts(pane), pane);
  await waitForMountsReady(page);
  if (pane === 'add') await app(page).getByRole('tab', { name: 'Add mount' }).click();
}
async function storage(page) {
  await open(page, 'add');
  await app(page).locator('[name=kind]').selectOption('storage');
  await app(page).getByRole('button', { name: 'Mount storage' }).click();
  await expect(app(page).locator('[data-selected]')).toHaveText(target);
}

test('M-01 supervised system and user daemons bind sockets with local ownership', async ({ page }) => {
  await boot(page);
  await expect.poll(() => ok(page, ['ps'])).toContain('mountd');
  const service = await ok(page, ['service', 'status', 'mountd.service']);
  expect(service).toMatch(/active|ready|running/i);
  const { uid } = await pageCall(page, 'getcreds');
  for (const [path, mode, owner] of [['/run/mount/control.sock', 0o666, 0], [`/run/user/${uid}/mount.sock`, 0o600, uid]]) {
    const s = await pageCall(page, { stat: { path } });
    expect(s.mode & 0o177777).toBe(0o140000 | mode);
    expect(s.uid).toBe(owner);
  }
});

test('M-02 mounts made by UI and CLI are visible in each other and mountinfo', async ({ page }) => {
  await boot(page); await storage(page);
  for (const cmd of [['mount'], ['findmnt'], ['cat', '/proc/self/mountinfo']]) expect(await ok(page, cmd)).toContain(target);
  const a = (await ctl(page, 'attachments')).attachments.find(a => a.target === target);
  expect(a.source_id).toMatch(/^src:/);
  await ok(page, ['mount', '-t', 'opfs', 'opfs:root', '/mnt/local/cli']);
  await app(page).locator('[data-action=refresh]').click();
  await expect(app(page).locator('[data-mounts]')).toContainText('/mnt/local/cli');
  await ok(page, ['umount', '/mnt/local/cli']);
});

test('M-03 sources, driver filesystems, namespace attachments, and exports have distinct views', async ({ page }) => {
  await boot(page); await storage(page);
  const all = await ctl(page, 'all');
  expect(Object.keys(all).sort()).toEqual(['attachments','exports','filesystems','sources','status']);
  for (const title of ['Sources','Filesystems','Attachments','Exports']) await expect(app(page).getByRole('heading', { name: title, exact: true })).toBeVisible();
  const a = all.attachments.find(a => a.target === target), s = all.sources.find(s => s.id === a.source_id);
  expect(Object.keys(s).sort()).toEqual(['execute','id','kind','label','location','owner_uid','saved','state','writable']);
  expect(all.filesystems.find(f => f.fs_id === a.fs_id).fstype).toBe('opfs');
  expect(JSON.parse(await ok(page, ['findmnt','--sources','-J'])).sources).toContainEqual(s);
});

test('M-04 user mount ceiling survives remount and rejects force', async ({ page }) => {
  await boot(page); await storage(page);
  for (const option of ['suid','dev']) {
    const r = await exec(page, ['mount', '-o', 'remount,' + option, target]);
    expect(r.status).not.toBe(0); expect(r.err).toMatch(/EPERM|permitted/);
  }
  expect((await exec(page, ['umount','-f',target])).status).not.toBe(0);
  await ok(page, ['mount','-o','remount,ro',target]);
  expect((await ctl(page,'attachments')).attachments.find(a => a.target === target)).toMatchObject({nosuid:true,nodev:true,read_only:true});
});

test('M-05 another local account and sudo cannot use a private grant', async ({ page }) => {
  await boot(page); await storage(page);
  const source = (await ctl(page,'attachments')).attachments.find(a => a.target === target).source_id;
  expect((await exec(page,['ls',target],{sudo:true})).status).not.toBe(0);
  expect(JSON.parse(await ok(page,['mountctl','--json','sources'],{sudo:true})).sources.some(s => s.id === source)).toBe(false);
  const user = 'mountb' + Date.now().toString(36), password = 'mount-service-test';
  await ok(page, ['useradd','-m',user], {sudo:true});
  await pageCall(page, {passwd:{username:user,password,force:true}}, {sudo:true});
  await switchLocalUser(page,user,{password,sudo:false});
  expect((await ctl(page,'sources')).sources.some(s => s.id === source)).toBe(false);
  expect((await exec(page,['mountctl','attach','-t','opfs',source,'/mnt/local/b'])).status).not.toBe(0);
  expect((await exec(page,['umount',target])).status).not.toBe(0);
});

test('M-06 busy cwd appears in CLI and UI, ordinary unmount refuses and lazy unmount succeeds', async ({ page }) => {
  await boot(page); await storage(page);
  const sleeping = exec(page, ['sleep','12'], {cwd:target});
  try {
    await expect.poll(async () => (await ctl(page,'busy',target)).processes.some(p => p.reasons.includes('cwd'))).toBe(true);
    const r = await exec(page,['umount',target]);
    expect(r.status).not.toBe(0); expect(r.err).toMatch(/target is busy \(pid \d+ .*cwd.*umount -l/);
    await app(page).locator('[data-action=refresh]').click();
    await expect(app(page).locator('[data-mounts]')).toContainText(/pid \d+ .*cwd/);
    await ok(page,['umount','-l',target]);
    expect((await ctl(page,'attachments')).attachments.some(a => a.target === target)).toBe(false);
  } finally { await sleeping; }
});

test('M-07 picker keeps user activation, rejects OPFS and discards a late account grant', async ({ page }) => {
  await boot(page);
  await page.evaluate(() => { window.showDirectoryPicker = () => {
    window.activated = navigator.userActivation.isActive;
    return new Promise(resolve => { window.finishMountPicker = resolve; });
  }; });
  await open(page,'add');
  const choose = app(page).getByRole('button', {name:'Choose folder…'});
  await choose.click();
  await page.waitForFunction(() => typeof window.finishMountPicker === 'function');
  expect(await page.evaluate(() => window.activated)).toBe(true);
  await page.evaluate(async () => window.finishMountPicker(await navigator.storage.getDirectory()));
  await expect(app(page).getByRole('status')).toContainText(/outside browser storage/);
  for (const name of ['AbortError','NotAllowedError']) {
    await page.evaluate(name => { window.showDirectoryPicker = () => Promise.reject(new DOMException('Folder access denied',name)); },name);
    await choose.click();
    await expect(app(page).getByRole('status')).toContainText(name === 'AbortError' ? 'Cancelled' : 'denied');
    await expect(app(page).locator('[data-helper]')).toBeHidden();
  }
  await page.evaluate(() => { window.showDirectoryPicker = () => new Promise(resolve => { window.lateMountPicker = resolve; }); });
  await choose.click();
  await page.waitForFunction(() => typeof window.lateMountPicker === 'function');
  await page.evaluate(() => { window.dispatchEvent(new Event('os:login-changed')); window.lateMountPicker({kind:'directory'}); });
  await expect(app(page).getByRole('status')).toContainText('Session changed');
  expect((await ctl(page,'attachments')).attachments.some(a => a.target === target)).toBe(false);
});

test('M-08 CLI requires a grant and saved host-folder consent can be renewed after reload', async ({ page, context }) => {
  await page.addInitScript(() => { delete globalThis.SharedWorker; });
  await boot(page);
  const r = await exec(page,['mount','-t','hostfs',target]);
  expect(r.status).not.toBe(0);
  expect(r.err).toMatch(/Choose a folder in Mounts.*EACCES/);
  const directory = await mkdtemp(join(tmpdir(), 'os-mount-saved-'));
  try {
    await writeFile(join(directory, 'note'), 'saved source');
    const cdp = await context.newCDPSession(page);
    async function dropFolder() {
      await page.evaluate(() => {
        addEventListener('dragover', e => e.preventDefault(), { once: true });
        addEventListener('drop', e => {
          e.preventDefault();
          window.savedMountSelection = e.dataTransfer.items[0].getAsFileSystemHandle();
        }, { once: true });
      });
      for (const type of ['dragEnter', 'dragOver', 'drop']) {
        await cdp.send('Input.dispatchDragEvent', { type, x: 500, y: 300, data: { items: [], files: [directory], dragOperationsMask: 1 } });
      }
      await page.evaluate(async () => {
        const handle = await window.savedMountSelection;
        window.showDirectoryPicker = () => Promise.resolve(handle);
      });
    }
    await dropFolder();
    await open(page, 'add');
    await app(page).locator('[name=save]').check();
    await app(page).getByRole('button', { name: 'Choose folder…' }).click();
    await expect(app(page).locator('[data-selected]')).toHaveText(target);
    const { source_id } = (await ctl(page, 'attachments')).attachments.find(a => a.target === target);
    await ok(page, ['umount', target]);
    await page.reload();
    await page.waitForFunction(() => !!window.os?.localMounts);
    await open(page);
    await expect.poll(async () => (await ctl(page, 'sources')).sources.find(s => s.id === source_id)?.saved).toBe(true);
    // Chromium does not automate native permission dialogs. Keep the real saved handle,
    // IndexedDB, CLI and sockets; control only the browser's permission decision.
    await dropFolder();
    async function promptWorkers(enabled) {
      // Only target JS kernel/executor workers (WASI daemon workers block inside Atomics.wait).
      const targets = page.workers().filter(w => /client-kernel|executor/.test(w.url()) && !w.url().includes('wasi-process'));
      await Promise.all(targets.map(w => w.evaluate(({ name, enabled }) => {
        const proto = globalThis.FileSystemHandle?.prototype;
        if (!proto) return;
        const original = globalThis.originalMountQuery ??= proto.queryPermission;
        proto.queryPermission = enabled ? function(options) {
          return this.name === name ? Promise.resolve('prompt') : original.call(this, options);
        } : original;
      }, { name: basename(directory), enabled })));
    }
    await promptWorkers(true);
    const denied = await exec(page, ['mountctl', '--json', 'attach', '-t', 'hostfs', source_id, target]);
    expect(JSON.parse(denied.out)).toMatchObject({ errno: 'EACCES', error: { kind: 'needs_renewal', source_id } });
    await page.exposeFunction('restoreMountPermission', () => promptWorkers(false));
    await page.evaluate(() => {
      const original = FileSystemHandle.prototype.requestPermission;
      FileSystemHandle.prototype.requestPermission = function (options) {
        window.renewalHadActivation = navigator.userActivation.isActive;
        const decision = original.call(this, options);
        return Promise.all([decision, window.restoreMountPermission()]).then(([result]) => result);
      };
    });
    await app(page).locator('[data-action=refresh]').click();
    await app(page).getByRole('button', { name: 'Renew & Mount' }).click();
    await expect(app(page).locator('[data-selected]')).toHaveText(target);
    expect(await page.evaluate(() => window.renewalHadActivation)).toBe(true);
    expect(await ok(page, ['cat', target + '/note'])).toContain('saved source');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('M-09 kernel executes root mount, bind, recursive bind, move and remount', async ({ page }) => {
  await boot(page);
  const opts={sudo:true};
  for (const dir of ['src','bind','recursive','moved']) await ok(page,['mkdir','-p','/tmp/mount-'+dir],opts);
  await ok(page,['mount','-t','tmpfs','tmpfs','/tmp/mount-src'],opts);
  await ok(page,['mount','--bind','/tmp/mount-src','/tmp/mount-bind'],opts);
  await ok(page,['mount','--rbind','/tmp/mount-src','/tmp/mount-recursive'],opts);
  await ok(page,['mount','--move','/tmp/mount-bind','/tmp/mount-moved'],opts);
  await ok(page,['mount','-o','remount,ro','/tmp/mount-moved'],opts);
  expect(await ok(page,['findmnt','/tmp/mount-moved'],opts)).toMatch(/tmpfs.*ro/);
  for (const dir of ['recursive','moved','src']) await ok(page,['umount','/tmp/mount-'+dir],opts);
  const unsupported = await exec(page,['mount','-t','sysfs','sysfs','/tmp/mount-src'],opts);
  expect(unsupported.status).not.toBe(0);
  expect(unsupported.err).toMatch(/ENODEV|No such device/i);
  const volume = '/tmp/mount-src', view = '/tmp/mount-recursive', pack = '/tmp/mount-service.cowpack';
  await ok(page, ['mkfs.cowfs', '--label', 'mount-service', '/dev/vd1'], opts);
  await ok(page, ['mountctl', 'attach', '-t', 'cowfs', '/dev/vd1', volume], opts);
  expect((await exec(page, ['mount', '-t', 'cowfs', '-o', 'rw,excl', '/dev/vd1', view], opts)).status).not.toBe(0);
  await ok(page, ['cowfs', 'subvol', 'create', volume, 'projects'], opts);
  await ok(page, ['mount', '-t', 'cowfs', '-o', 'subvol=projects', '/dev/vd1', view], opts);
  await ok(page, ['umount', view], opts);
  await ok(page, ['cowfs', 'snapshot', 'create', volume, 'release'], opts);
  const filesystems = JSON.parse(await ok(page, ['mountctl', '--json', 'filesystems'], opts)).filesystems;
  expect(filesystems.some(f => f.cowfs?.snapshots.includes('release') && f.cowfs.subvols.includes('projects'))).toBe(true);
  const snapshots = JSON.parse(await ok(page, ['mountctl', '--json', 'sources'], opts)).sources;
  const snapshot = snapshots.find(s => s.kind === 'cowfs_snapshot' && s.label === 'release');
  await ok(page, ['mount', '-t', 'cowfs', '-o', 'ro', snapshot.id, view], opts);
  await ok(page, ['umount', view], opts);
  await ok(page, ['cowfs', 'send', '--archive', '-o', pack, volume, 'release'], opts);
  const loop = (await ok(page, ['losetup', '-f', '--show', pack], opts)).trim();
  await ok(page, ['mount', '-t', 'cowfs', '-o', 'ro', loop, view], opts);
  expect(await ok(page, ['findmnt', view], opts)).toContain(loop);
  await ok(page, ['umount', view], opts);
  await ok(page, ['losetup', '-d', loop], opts);
  await ok(page, ['umount', volume], opts);
});

test('M-10 local mount lifecycle works offline without a cloud credential or outbound requests', async ({ page, context }) => {
  await boot(page);
  await waitForTerminalReady(page);
  // Warm command images and Mounts GUI bundle before taking the installed instance offline.
  for (const cmd of ['mountctl','mount','umount','findmnt','mounts']) await exec(page,[cmd,'--help']);
  await ok(page, ['cat', '/usr/share/gui/mounts/mounts.json']);
  const outbound=[];
  await context.route(/^https?:\/\//, route => { outbound.push(route.request().url()); return route.abort(); });
  await context.setOffline(true);
  await storage(page);
  expect((await ctl(page,'filesystems')).filesystems.some(f => f.fstype === 'cowfs')).toBe(true);
  expect(await ok(page,['findmnt',target])).toContain('opfs');
  await ok(page,['umount',target]);
  const cloud = await exec(page,['mount','-t','cloud','cloud','/mnt/cloud'],{sudo:true});
  expect(cloud.status).not.toBe(0);
  expect(cloud.err).toMatch(/ENOTCONN|not connected/i);
  expect(outbound).toEqual([]);
});

// Exercise grant lifetimes independently of native picker dialogs (whose permission
// prompts cannot be driven by a headless browser). Keep the real registry and page helpers.
function fixture() {
  const saved = new Map(); let permission = 'granted', seq = 0;
  const store = {
    list: async (volume,uid) => [...saved.values()].filter(r => r.volume === volume && r.uid === uid), get: async (volume,uid,id) => saved.get([volume,uid,id].join('/')),
    put: async r => saved.set([r.volume,r.uid,r.id].join('/'),r), remove: async (volume,uid,id) => saved.delete([volume,uid,id].join('/')),
  };
  const dir = path => ({ kind:'directory', name:path.split('/').at(-1), path,
    isSameEntry: async other => other.path === path,
    resolve: async other => other.path === path ? [] : other.path.startsWith(path+'/') ? other.path.slice(path.length+1).split('/') : null,
    queryPermission: async () => permission, requestPermission: () => { permission='granted'; return Promise.resolve(permission); } });
  const registry = new SourceRegistry({ store, opfs:async () => dir('opfs'), uuid:() => String(++seq).padStart(8,'0')+'-0000-4000-8000-000000000000' });
  return { registry,store,dir,revoke:() => {permission='prompt';},permission:() => permission };
}

component('M-08 saved grant reload, synchronous renewal, per-user keys and forget', async () => {
  const f=fixture(), a={id:'a',uid:1000,volume:'volume-a',loginEpoch:1};
  await f.registry.beginSession(a);
  const {source_id} = await f.registry.register('hostfs',{loginEpoch:1,handle:f.dir('host/folder'),writable:true,save:true});
  f.revoke();
  const reloaded={...a,loginEpoch:2};
  await f.registry.beginSession(reloaded);
  const [s]=await f.registry.list(2);
  expect(s).toMatchObject({id:source_id,state:'needs_renewal',saved:true});
  expect(s).not.toHaveProperty('handle');
  const renew=await prepareRenewal(reloaded,s,() => true,(_,args) => f.registry.renew(args.source_id,args.loginEpoch),f.store);
  const result=renew();
  expect(f.permission()).toBe('granted');
  expect((await result).state).toBe('granted');
  await f.registry.beginSession({...a,id:'b',uid:1001,loginEpoch:3});
  expect(await f.registry.list(3)).toEqual([]);
  await f.registry.beginSession({...a,volume:'volume-b',loginEpoch:4});
  expect(await f.registry.list(4)).toEqual([]);
  await f.registry.beginSession({...a,loginEpoch:5});
  await f.registry.forget(source_id,5);
  expect(await f.store.list('volume-a',1000)).toEqual([]);
});

component('M-07 registry serializes overlapping grants and fences pending picker results', async () => {
  const f=fixture();
  await f.registry.beginSession({id:'a',uid:1000,loginEpoch:1});
  const add = path => f.registry.register('hostfs',{loginEpoch:1,handle:f.dir(path)});
  const requests=await Promise.allSettled([add('host/folder'),add('host/folder/child')]);
  expect(requests.map(r => r.status)).toEqual(['fulfilled','rejected']);
  await expect(add('host')).rejects.toMatchObject({errno:'EEXIST'});
  await expect(add('host/folder')).rejects.toMatchObject({errno:'EEXIST'});
  await expect(add('opfs')).rejects.toMatchObject({errno:'EINVAL'});
  let resolve, transmitted=false;
  const pending=registerPickedFolder(new Promise(r => { resolve=r; }),{loginEpoch:1},
    () => f.registry.session.loginEpoch===1, () => { transmitted=true; });
  await f.registry.beginSession({id:'b',uid:1001,loginEpoch:2}); resolve(f.dir('host/new'));
  await expect(pending).rejects.toMatchObject({errno:'ECANCELED'});
  expect(transmitted).toBe(false);
});

component('M-01 page RPC uses the session proxy and backend forwards one stamped socket across partial I/O', async () => {
  const f = fixture();
  await f.registry.beginSession({ id: 'login', uid: 1000, loginEpoch: 1 });
  const op = { op: 'list_sources' }, socket = '/run/user/1000/mount.sock';
  let pageArgs;
  mountPageRequest('unix_rpc', { request: op, socket, pid: 1, uid: 0, loginEpoch: 1 }, {
    registry: f.registry, proxyPid: 47, kernel: { page_unix_rpc: (...args) => { pageArgs = args; } },
  });
  expect(pageArgs.slice(0, 4)).toEqual(['login', 47, socket, JSON.stringify(op)]);
  const bytes = ['{"target_pid":null,"op":', '{"op":"sources"}}\n'];
  const closed = [];
  let received = '', calls = 0;
  const context = {
    pid: 1, sockId: 11, table: {}, registry: f.registry, isMountService: pid => pid === 24,
    socketOp: async ({ pid, args }) => {
      expect(pid).toBe(1);
      switch (args.op) {
        case 'peercred': return { pid: 24, uid: 1000 };
        case 'recvmsg': {
          const first = bytes.length === 2;
          return { data: btoa(bytes.shift()), fds: first ? [{ kind: 'unix_sock', sockId: 29 }] : [] };
        }
        case 'sendmsg': {
          const chunk = atob(args.data).slice(0, 4);
          received += chunk;
          return { sent: chunk.length };
        }
        case 'close': closed.push(args.sockId); return {};
        default: throw new Error(args.op);
      }
    },
    kernel: { mount_backend_call: async (holder, channel, peer, frame, table) => {
      calls++;
      expect([holder, channel, peer, JSON.parse(frame), table]).toEqual([1, 11, 29, { target_pid: null, op: { op: 'sources' } }, context.table]);
      return [];
    } },
  };
  await serveMountBackend(context);
  expect(received).toBe('{"Ok":[]}\n');
  expect(closed).toEqual([29, 11]);
  await expect(serveMountBackend({ ...context, isMountService: () => false })).rejects.toMatchObject({ errno: 'EACCES' });
  expect(calls).toBe(1);
  expect(closed).toEqual([29, 11, 11]);
});
