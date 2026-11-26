import { enqueueSeat } from '../gui/seat-queue.js';
import { asset } from '../release.js';
import { imageBlobRead } from './image-pager.js';
import { createBootProfileStore } from './boot-profile.js';
import { createCowfsStore } from './cowfs-store.js';
// The client kernel: a classic dedicated Worker (one isolated OS instance per tab), so it can
// importScripts the no-modules wasm-bindgen build. The Rust kernel (crates/client-kernel) owns
// this instance's LocalProcessTable, persistent local `os-cowfs` root volume, local accounts
// (`/etc/{passwd,group,shadow,sudoers}`), local `/proc`, instance-local `/run` and `/tmp`,
// local cgroup v2 policy, and explicit remote `ServiceAuth v2` credentials. Boot, PID 1 `/usr/bin/init`,
// exec, fork, wait, kill, pipe, setsid, PTYs, `AF_UNIX`, and `/proc` run 100% locally offline
// with ZERO network RPCs; optional CloudFs (`/mnt/cloud`) and remote devices attach only after
// explicit Cloud Sign-In.
//
// A process belongs exclusively to its port's host identity (never the public tab label). Only
// that port forks it, replaces its image, ends it, waits for its children, or signals as it;
// another tab runs its own isolated Worker instance and cannot observe or address its processes.
importScripts(asset('/client_kernel.js'));

const VERSION = 2;
const ports = new Set();
let kernel;
let starting;
let login;
let cowfsStore;
let bootProfileStore;
let localInitView = null;
let localInitState = 'starting';
let localInitFailures = 0;
let localInitAttempts = 0;
let localInitError = '';
let localInitRunning = false;
let localInitProof = '';
let localInitOwner = null;
let localInitJob = null;
let localInitAbort = false;
let localInitRunId = 0;
let localInitPromise = null;
let bootedOfflineReleaseId = null;
let bootedOfflinePinned = false;
let bootHealthMarked = false;
let bootOptsCached = null;
let kubeletHostLoaded = false;

async function ensureKubeletHostIfNeeded() {
  kubeletHostLoaded = true;
  const [{ ensureKubeletHost }, executor] = await Promise.all([
    import(asset('/kubelet-agent.js')),
    import(asset('/executor-host.js')),
  ]);
  await ensureKubeletHost({
    kernel,
    asset,
    socketOp: args => executor.mountSocketOp({ pid: 1, args }),
  });
}

async function resetKubeletHostIfLoaded() {
  if (!kubeletHostLoaded) return;
  const { resetKubeletHost } = await import(asset('/kubelet-agent.js'));
  await resetKubeletHost();
}
// This instance's unique local identifier (never shared across tabs).
const kernelId = self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
// Each port's host: an identity of its own, made here, and the tab it first said it was.
const hosts = new WeakMap();
// What the kernel does, one thing at a time for serialized lifecycle ops.
let queue = Promise.resolve();
const serially = task => {
  const done = queue.then(task);
  queue = done.catch(() => {});
  return done;
};

// ServiceAuth v2 transport: POST /api/service-auth (lazy first-remote-use only; NEVER X-Registry).
self.serviceAuthPost = async (body, signal) => {
  const response = await fetch('/api/service-auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

// Surface version mismatch notices without auto-reloading (docs/architecture/contract.md §2.10).
self.onProtocolMismatch = value => {
  broadcast({ v: VERSION, type: 'event', event: 'protocol-mismatch', value });
};

// Cookie-authenticated authority batch transport for page VFS calls (NEVER X-Registry).
self.pageSysPost = async (body, extraHeaders = {}) => {
  const response = await fetch('/api/sys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(extraHeaders ?? {}) },
    body,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

self.pagePwrite = async (fd, index, bytes, extraHeaders = {}) => {
  const response = await fetch(`/api/pwrite?fd=${Number(fd)}&index=${Number(index)}`, {
    method: 'PUT',
    headers: extraHeaders ?? {},
    body: bytes,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

self.pageFileRead = async (path, offset, len) => {
  const start = Number(offset);
  const count = Number(len);
  if (count <= 0) return { status: 200, body: new Uint8Array(0), etag: '' };
  const end = start + count - 1;
  const response = await fetch('/api/file?path=' + encodeURIComponent(path), {
    headers: { Range: `bytes=${start}-${end}` },
  });
  const etag = response.headers.get('ETag') ?? '';
  if (response.status === 416) return { status: 416, body: new Uint8Array(0), etag };
  const raw = response.status === 200 || response.status === 206
    ? new Uint8Array(await response.arrayBuffer())
    : new Uint8Array(0);
  const body = response.status === 200 ? raw.subarray(start, start + count) : raw;
  return { status: response.status, body, etag };
};

self.imageBlobRead = imageBlobRead;

self.onKernelMountsChanged = value => {
  broadcast({ v: VERSION, type: 'event', event: 'mounts-changed', value });
};

self.remoteVolumeFetch = async (method, path, headers, bytes) => {
  const response = await fetch(path, {
    method, headers, credentials: 'same-origin', redirect: 'error',
    body: method === 'POST' || method === 'PUT' ? bytes : undefined,
  });
  const length = response.headers.get('Content-Length');
  const limit = method === 'GET' ? 1024 * 1024 : 8 * 1024 * 1024;
  let body = new Uint8Array();
  if (method === 'HEAD' && !response.ok) {
    body = new TextEncoder().encode(JSON.stringify({ errno: response.headers.get('X-OS-Errno') }));
  } else if (method !== 'HEAD' && response.body) {
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > limit) {
          await reader.cancel();
          throw new RangeError('remote volume response exceeds the negotiated limit');
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    body = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
  }
  return { status: response.status, length: length === null ? null : Number(length), body };
};

self.ociRegistryFetch = async (method, url, headers, bytes) => {
  const resolved = new URL(url, self.location.origin);
  if (resolved.origin !== self.location.origin || (resolved.pathname !== '/v2' && !resolved.pathname.startsWith('/v2/'))) {
    throw new Error('OCI registry fetch blocked off-origin or non-/v2 URL');
  }
  const response = await fetch(resolved.href, {
    method, headers, credentials: 'same-origin', redirect: 'error',
    body: method === 'POST' || method === 'PUT' || method === 'PATCH' ? bytes : undefined,
  });
  const limit = 16 * 1024 * 1024;
  let body = new Uint8Array();
  if (method !== 'HEAD' && response.body) {
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > limit) {
          await reader.cancel();
          throw new RangeError('OCI registry response exceeds the 16 MiB bound');
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    body = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
  }
  return {
    status: response.status,
    headers: Array.from(response.headers.entries()),
    body,
  };
};

self.cloudFsPost = async (path, headers, body) => {
  const response = await fetch(path, { method: 'POST', headers, body });
  return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
};
self.cloudFsSleep = ms => new Promise(resolve => setTimeout(resolve, ms));
self.cloudFsTicket = () => self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;

const SEAT_POLICY_DB = 'os-seat-policy-v1';
const SEAT_POLICY_STORE = 'policies';
let seatPolicyDbPromise = null;

function openSeatPolicyDb() {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null);
  seatPolicyDbPromise ??= new Promise(resolve => {
    try {
      const req = indexedDB.open(SEAT_POLICY_DB, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(SEAT_POLICY_STORE)) {
          req.result.createObjectStore(SEAT_POLICY_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return seatPolicyDbPromise;
}

async function readSeatPolicy(uid) {
  try {
    const db = await openSeatPolicyDb();
    if (!db) return null;
    return await new Promise(resolve => {
      const tx = db.transaction(SEAT_POLICY_STORE, 'readonly');
      const req = tx.objectStore(SEAT_POLICY_STORE).get(uid);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => resolve(null);
    });
  } catch {
    return null;
  }
}

async function writeSeatPolicy(uid, sharing, revision) {
  try {
    const db = await openSeatPolicyDb();
    if (!db) return;
    await new Promise(resolve => {
      const tx = db.transaction(SEAT_POLICY_STORE, 'readwrite');
      tx.objectStore(SEAT_POLICY_STORE).put({ sharing, revision }, uid);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
      tx.onabort = () => resolve();
    });
  } catch { /* best-effort persistence */ }
}

async function restoreSeatPolicyForAccount() {
  if (!kernel) return;
  try {
    const creds = JSON.parse(kernel.workspace_credentials());
    if (typeof creds?.uid !== 'number') return;
    const saved = await readSeatPolicy(creds.uid);
    if (saved && typeof saved.sharing === 'string' && typeof saved.revision === 'number') {
      kernel.restore_seat_policy(creds.uid, saved.sharing, BigInt(saved.revision));
    }
  } catch { /* ignore unavailable IDB */ }
}

function buildAssetSizesOption() {
  const raw = typeof __OS_BUILD_ASSET_SIZES__ !== 'undefined'
    ? __OS_BUILD_ASSET_SIZES__
    : globalThis.__OS_BUILD_ASSET_SIZES__;
  if (!raw || typeof raw !== 'object') return null;
  const sizes = {};
  for (const name of ['coreutils', 'utilities', 'dash', 'supervise', 'init', 'mountd', 'exportd', 'kubelet']) {
    const value = raw[`/usr/bin/${name}.wasm`] ?? raw[name];
    if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
      sizes[name] = value;
    }
  }
  const guiAssetSizes = Object.fromEntries(Object.entries(raw).filter(([path]) =>
    [
      '/usr/bin/compositor.wasm',
      '/usr/bin/desktop-shell.wasm',
      '/usr/bin/greeter.wasm',
      '/usr/bin/gui-sample-doc.wasm',
      '/usr/bin/gui-sample-pixel.wasm',
      '/usr/bin/osh.wasm',
      '/usr/bin/terminal.wasm',
      '/usr/bin/files.wasm',
      '/usr/bin/mounts.wasm',
      '/usr/share/gui/samples/doc-view.json',
      '/usr/share/gui/terminal/terminal.json',
      '/usr/share/gui/files/files.json',
      '/usr/share/gui/mounts/mounts.json',
    ].includes(path)));
  return Object.keys(sizes).length > 0 ? { buildAssetSizes: sizes, guiAssetSizes } : null;
}

function randomHex32() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function currentInitStatus() {
  return {
    host: kernelId,
    init: localInitView,
    connected: true,
    coordinator: !localInitAbort && !!localInitOwner,
    reaper: {
      state: localInitState,
      pid: 1,
      failures: localInitFailures,
      attempts: localInitAttempts,
      error: localInitError,
    },
  };
}

function broadcastInitStatus() {
  broadcast({ v: VERSION, type: 'event', event: 'machine_init', value: currentInitStatus() });
}

async function releaseLocalInitOwner() {
  const owner = localInitOwner;
  localInitOwner = null;
  if (!owner || !kernel) return;
  try {
    localInitView = JSON.parse(await kernel.machine_init_action(
      JSON.stringify({ op: 'release', owner }),
      kernelId,
    ));
  } catch { /* already released or rebooted */ }
}

async function waitForPid1BootHealthyAndMark(runId) {
  if (!bootedOfflineReleaseId || bootedOfflinePinned || bootHealthMarked || !kernel) return;
  const targetReleaseId = bootedOfflineReleaseId;
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (runId !== localInitRunId || localInitAbort || !localInitRunning || !kernel) return;
    try {
      await kernel.proc_statat(1, 0x7ffffffd, '/run/os/boot-healthy', true);
      if (runId !== localInitRunId || localInitAbort || !localInitRunning) return;
      if (bootedOfflineReleaseId !== targetReleaseId || bootHealthMarked) return;
      const { createOfflineInstaller } = await import(asset('/offline-installer.js'));
      const installer = createOfflineInstaller();
      // Codex Finding #10: bind health acknowledgement strictly to the boot attempt's own
      // release ID, and ONLY after PID 1 writes `/run/os/boot-healthy` (multi-user + user-session active).
      await installer.markBootHealthy(targetReleaseId);
      bootHealthMarked = true;
      return;
    } catch {
      await new Promise(r => setTimeout(r, 40));
    }
  }
}

async function driveCloudOnlineTarget(action) {
  if (!globalThis.crossOriginIsolated || localInitState !== 'running' || !kernel) return;
  try {
    const { exec } = await import(asset('/executor-host.js'));
    await Promise.race([
      exec([['/usr/bin/service', action, 'cloud-online.target']], {
        stdin: '',
        sudo: true,
      }).catch(() => {}),
      new Promise(r => setTimeout(r, 3000)),
    ]);
  } catch { /* fallback to direct kernel mount/detach already applied */ }
}

async function launchLocalInit() {
  if (!kernel || localInitRunning || localInitAbort) return;
  const runId = ++localInitRunId;
  const previous = localInitPromise;
  localInitRunning = true;
  localInitState = 'starting';
  localInitError = '';
  localInitAttempts++;
  const runPromise = (async () => {
    try {
      if (previous) {
        await Promise.race([previous.catch(() => {}), new Promise(r => setTimeout(r, 2000))]);
      }
      if (runId !== localInitRunId || localInitAbort || !kernel) return;
      if (!localInitProof) localInitProof = randomHex32();
      const inspected = JSON.parse(await kernel.machine_init_action(
        JSON.stringify({ op: 'inspect' }),
        kernelId,
      ));
      if (runId !== localInitRunId || localInitAbort) return;
      const claimed = JSON.parse(await kernel.machine_init_action(
        JSON.stringify({
          op: 'claim',
          owner: {
            boot: inspected.boot,
            host: kernelId,
            proof: localInitProof,
            generation: inspected.generation,
          },
        }),
        kernelId,
      ));
      if (runId !== localInitRunId || localInitAbort) {
        await kernel.machine_init_action(
          JSON.stringify({
            op: 'release',
            owner: {
              boot: claimed.boot,
              host: kernelId,
              proof: localInitProof,
              generation: claimed.generation,
            },
          }),
          kernelId,
        ).catch(() => {});
        return;
      }
      localInitView = claimed;
      const owner = {
        boot: claimed.boot,
        host: kernelId,
        proof: localInitProof,
        generation: claimed.generation,
      };
      localInitOwner = owner;
      broadcastInitStatus();
      if (!globalThis.crossOriginIsolated) {
        // Codex Finding #10: when cross-origin isolation prevents PID 1 from executing,
        // never mark an offline Release v2 generation healthy!
        localInitState = 'running';
        broadcastInitStatus();
        return;
      }
      const { exec } = await import(asset('/executor-host.js'));
      if (runId !== localInitRunId || localInitAbort) return;
      let error = '';
      const token = randomHex32();
      const result = await exec([['init']], {
        stdin: '',
        cancelled: () => runId !== localInitRunId || localInitAbort,
        prepare: async () => [{ ok: await self.kernelRequest('boot_init', { owner, token }) }],
        onJob: job => {
          if (runId !== localInitRunId || localInitAbort) {
            job.signal(9);
            return;
          }
          localInitJob = job;
          if (job.started && job.pids.includes(1) && localInitState !== 'running') {
            localInitState = 'running';
            broadcastInitStatus();
            void waitForPid1BootHealthyAndMark(runId);
          }
        },
        onOutput: (fd, text) => {
          if (fd === 2) error = (error + text).slice(-4096);
        },
      });
      if (runId !== localInitRunId) return;
      localInitJob = null;
      localInitRunning = false;
      if (localInitAbort) {
        await releaseLocalInitOwner();
        localInitState = 'stopped';
        broadcastInitStatus();
        return;
      }
      if (result?.status === 0) {
        await releaseLocalInitOwner();
        localInitState = 'stopped';
        broadcastInitStatus();
        // Ordered shutdown completed cleanly: flush & close `os-cowfs` root volume (Codex #15 & #21).
        let closed = null;
        try {
          closed = JSON.parse(await kernel.close_clean_root());
        } catch (closeErr) {
          localInitError = `clean root close failed: ${closeErr?.message ?? String(closeErr)}`;
          localInitState = 'failed';
          broadcastInitStatus();
          return;
        }
        if (closed?.shutdown?.clean === false) {
          localInitError = 'PID 1 reported unclean shutdown / unmount failure';
          localInitState = 'failed';
          broadcastInitStatus();
          return;
        }
        // Honor `service reboot` cleanly after durable root close (Codex Finding #21).
        if (closed?.shutdown?.mode === 'reboot') {
          try {
            const inspected = JSON.parse(await kernel.machine_init_action(JSON.stringify({ op: 'inspect' }), kernelId));
            // Remount root fresh and reset boot generation before relaunching PID 1.
            await resetKubeletHostIfLoaded();
            await (await import(asset('/executor-host.js'))).resetMountHost();
            await kernel.boot_vfs(bootOptsCached ? JSON.stringify(bootOptsCached) : undefined);
            const prof = bootProfileStore ? await bootProfileStore.load().catch(() => null) : null;
            if (cowfsStore) {
              await kernel.boot_cowfs_root(
                cowfsStore,
                prof ? JSON.stringify(prof) : undefined,
                bootOptsCached ? JSON.stringify(bootOptsCached) : undefined,
              );
            }
            const rebooted = JSON.parse(await kernel.machine_init_action(
              JSON.stringify({ op: 'reboot', boot: inspected.boot }),
              kernelId,
            ));
            localInitView = rebooted;
            const executor = await import(asset('/executor-host.js'));
            void executor.reconcile().catch(() => {});
            await login?.reset?.();
            localInitFailures = 0;
            localInitError = '';
            void launchLocalInit();
          } catch (rbErr) {
            localInitError = `reboot after clean close failed: ${rbErr?.message ?? String(rbErr)}`;
            localInitState = 'failed';
            broadcastInitStatus();
          }
        }
        return;
      }
      await releaseLocalInitOwner();
      localInitFailures++;
      localInitError = error.trim() || `init exited with status ${result?.status ?? 'unknown'}`;
      localInitState = 'failed';
      broadcastInitStatus();
      if (error.trim()) console.warn('local PID 1 init exited:', error.trim());
      if (runId === localInitRunId && !localInitAbort && localInitFailures <= 3) {
        setTimeout(() => {
          if (runId === localInitRunId && !localInitAbort) void launchLocalInit();
        }, 250);
      }
    } catch (err) {
      if (runId !== localInitRunId) return;
      localInitJob = null;
      localInitRunning = false;
      await releaseLocalInitOwner();
      localInitFailures++;
      localInitError = String(err?.message ?? err ?? 'init launch failed');
      localInitState = 'failed';
      broadcastInitStatus();
      console.warn('local PID 1 init launch failed:', err);
      if (runId === localInitRunId && !localInitAbort && localInitFailures <= 3) {
        setTimeout(() => {
          if (runId === localInitRunId && !localInitAbort) void launchLocalInit();
        }, 250);
      }
    } finally {
      if (localInitPromise === runPromise) localInitPromise = null;
    }
  })();
  localInitPromise = runPromise;
  return runPromise;
}

function boot() {
  starting ??= wasm_bindgen(asset('/client_kernel_bg.wasm')).then(async () => {
    self.wasm_bindgen = wasm_bindgen;
    kernel = new wasm_bindgen.Kernel('', kernelId);
    const bootOpts = { ...(buildAssetSizesOption() ?? {}) };
    bootProfileStore = createBootProfileStore();
    cowfsStore = createCowfsStore();
    let bootRes = null;
    const hasIdb = typeof indexedDB !== 'undefined';

    if (!hasIdb) {
      // Headless Node / non-browser harness without IndexedDB: keep Stage 1 tmpfs + `/usr`.
      bootOptsCached = Object.keys(bootOpts).length > 0 ? bootOpts : null;
      if (bootOptsCached) {
        await kernel.boot_vfs(JSON.stringify(bootOptsCached));
      }
    } else {
      try {
        // Codex Finding #11: NEVER swallow profile I/O errors as empty profiles; serialize
        // initial provisioning so concurrent first boots elect one default root UUID.
        let profile = await bootProfileStore.load();

        // Codex Finding #7: when a verified local Release v2 is installed in this profile,
        // feed its exact `root_template` and `base + sysext + confext` composition into boot
        // and bind health acknowledgement strictly to that resolved `releaseId` (Codex #10).
        bootedOfflineReleaseId = null;
        bootedOfflinePinned = false;
        bootHealthMarked = false;
        try {
          const { createOfflineInstaller } = await import(asset('/offline-installer.js'));
          const installer = createOfflineInstaller();
          const st = await installer.getState();
          if (st && (st.active || st.previous || (profile?.generation && st.generations?.[profile.generation]))) {
            const resolved = await installer.resolveInstalledForBoot({
              generation: profile?.generation ?? null,
              verifyAllBlobs: false,
              verifyCache: false,
            });
            bootedOfflineReleaseId = resolved.releaseId;
            bootedOfflinePinned = Boolean(resolved.pinnedGeneration);
            if (resolved.images?.root_template) {
              bootOpts.rootTemplate = JSON.stringify(resolved.images.root_template);
            }
            if (resolved.images?.base) {
              bootOpts.baseImage = JSON.stringify(resolved.images.base);
              bootOpts.extensionImages = [
                ...(resolved.images.sysext ?? []),
                ...(resolved.images.confext ?? []),
              ].map(img => JSON.stringify(img));
            }
          }
        } catch (relErr) {
          // Only enter recovery if an installed release existed and failed verification;
          // no installed release simply boots standard dev assets.
          if (relErr?.message && !relErr.message.includes('No offline Release v2')) {
            throw relErr;
          }
        }

        bootOptsCached = Object.keys(bootOpts).length > 0 ? bootOpts : null;
        const optsJson = bootOptsCached ? JSON.stringify(bootOptsCached) : undefined;

        const runBoot = async currentProfile => {
          const raw = await kernel.boot_cowfs_root(
            cowfsStore,
            currentProfile ? JSON.stringify(currentProfile) : undefined,
            optsJson,
          );
          return JSON.parse(raw);
        };

        const needsFirstUuid = Boolean(profile?.root?.cow_fs && !profile.root.cow_fs.volume_uuid);
        if (needsFirstUuid) {
          bootRes = await bootProfileStore.withProvisionLock(async () => {
            const freshProfile = await bootProfileStore.load();
            const res = await runBoot(freshProfile);
            const mintedUuid = res?.boot_profile?.root?.cow_fs?.volume_uuid ?? null;
            if (mintedUuid && !freshProfile?.root?.cow_fs?.volume_uuid && res?.stage !== 'stage1_recovery') {
              const claim = await bootProfileStore.claimVolumeUuid(mintedUuid, { locked: true });
              if (!claim.won && claim.volumeUuid && claim.volumeUuid !== mintedUuid) {
                // Another tab won first-boot provisioning: close our unexposed volume & reopen winner.
                await kernel.close_clean_root().catch(() => {});
                await kernel.boot_vfs(optsJson);
                return runBoot(claim.profile);
              }
            }
            return res;
          });
        } else {
          bootRes = await runBoot(profile);
        }
      } catch (err) {
        const e = failure(err);
        if (e?.errno === 'EPROTONOSUPPORT') throw err;
        // Codex Findings #8 & #11: NEVER silently fall back to launching init on tmpfs when
        // CowFS / profile / release boot fails in a browser with IndexedDB! Stay in recovery.
        bootRes = {
          stage: 'stage1_recovery',
          recovery: {
            reason: { kind: 'io_error', errno: e?.errno ?? 'EIO', detail: e?.detail ?? String(err) },
            message: `Boot failed and entered Stage 1 recovery: ${e?.detail ?? err?.message ?? String(err)}`,
            available_snapshots: [],
          },
        };
      }
    }
    await restoreSeatPolicyForAccount();
    const value = JSON.parse(await kernel.init());
    const { LoginCoordinator } = await import(asset('/login-session.js'));
    const proof = randomHex32();
    let lastLogin;
    login = new LoginCoordinator({ host: kernelId, proof,
      changed: value => {
        for (const pick of guiPicks.values()) if (pick.session !== guiSession()) retirePick(pick, true);
        const id = value.session?.id;
        if (id && id !== lastLogin) {
          const previous = lastLogin;
          lastLogin = id;
          if (previous) void import(asset('/executor-host.js')).then(executor => {
            if (lastLogin !== previous) return executor.endWorkspace(previous);
          }).catch(() => {});
        }
        broadcast({ v: VERSION, type: 'event', event: 'login', value: { ...value, services: null } });
      },
      call: async action => {
        try {
          return JSON.parse(await kernel.login_session_action(JSON.stringify(action), kernelId));
        } catch (error) {
          throw failure(error);
        }
      },
    });
    await login.tick();
    if (!bootRes || bootRes.stage !== 'stage1_recovery') {
      void launchLocalInit();
    } else {
      localInitState = 'recovery';
      broadcastInitStatus();
    }
    broadcast({ v: VERSION, type: 'event', event: 'started', value });
    return value;
  }).catch(error => {
    kernel = undefined;
    starting = undefined;
    throw error;
  });
  return starting;
}

const guiPorts = new Map(), guiPicks = new Map(), guiJobs = new Map();
let guiExecutor, guiActivation;
const guiSession = () => {
  const state = login?.current(), session = state?.session;
  return state?.connected && session?.id && Number.isSafeInteger(session.generation)
    ? JSON.stringify([session.id, session.uid, session.generation, login.epoch]) : null;
};
const bindingFor = id => JSON.parse(kernel.gui_surface_binding(BigInt(id)));
const guiCanvases = new Map();
let seatEpoch = 0, inputQueue = Promise.resolve();
let compatConn = null, compatConnecting = null, compatQueue = Promise.resolve(), desktopStarting = null;
let desktopActionsSrv = null, desktopActionSeq = 0;
const desktopActionClients = new Map();
const textEncoder = new TextEncoder(), textDecoder = new TextDecoder();
function bytesToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function base64ToBytes(str) {
  if (!str) return new Uint8Array(0);
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function sendSocketBytes(pid, sockId, bytes) {
  let sent = 0;
  while (sent < bytes.length) {
    try {
      const chunk = bytes.subarray(sent, Math.min(bytes.length, sent + 4096));
      const r = await guiExecutor.mountSocketOp({ pid, args: { op: 'sendmsg', sockId, fds: [], data: bytesToBase64(chunk) } });
      if (!r?.sent) throw { errno: 'EPIPE' };
      sent += r.sent;
    } catch (err) {
      if (err?.errno === 'EAGAIN') { await new Promise(r => setTimeout(r, 5)); continue; }
      throw err;
    }
  }
}
function closeDesktopActionsServer() {
  const srv = desktopActionsSrv;
  desktopActionsSrv = null;
  for (const [id, entry] of desktopActionClients) {
    entry.closed = true;
    desktopActionClients.delete(id);
    if (guiExecutor?.mountSocketOp) {
      void guiExecutor.mountSocketOp({ pid: entry.pid, args: { op: 'close', sockId: entry.sockId } }).catch(() => {});
    }
  }
  if (!srv || srv.closed) return;
  srv.closed = true;
  if (srv.sockId != null && guiExecutor?.mountSocketOp) {
    void guiExecutor.mountSocketOp({ pid: srv.pid, args: { op: 'close', sockId: srv.sockId } }).catch(() => {});
  }
  if (srv.path && kernel) {
    void kernel.proc_unlinkat(srv.pid, 0x7ffffffd, srv.path, false).catch(() => {});
  }
}
const MAX_DESKTOP_ACTION_BYTES = 64 * 1024;
const MAX_DESKTOP_ACTION_CONNS = 32;
const MAX_TERMINAL_CTRL_REPLY_BYTES = 8192;

async function ensureDesktopActionsServer(pid, uid, session) {
  if (!session || session !== guiSession()) return;
  if (desktopActionsSrv && !desktopActionsSrv.closed && desktopActionsSrv.session === session) return;
  closeDesktopActionsServer();
  const dir = `/run/user/${uid}`;
  const path = `${dir}/desktop-actions.sock`;
  try { await kernel.proc_mkdirat(pid, 0x7ffffffd, '/run/user', 0o755); } catch {}
  try { await kernel.proc_mkdirat(pid, 0x7ffffffd, dir, 0o700); } catch {}
  const chmodDirRes = JSON.parse(await kernel.proc_sys(pid, JSON.stringify({ calls: [{ chmod: { path: dir, mode: 0o700 } }] })));
  if (chmodDirRes?.results?.[0]?.err) throw { errno: chmodDirRes.results[0].err.errno || 'EACCES' };
  const dirStat = await kernel.proc_statat(pid, 0x7ffffffd, dir, false);
  if (!dirStat || (dirStat.mode & 0o170000) !== 0o040000 || dirStat.uid !== uid || (dirStat.mode & 0o7777) !== 0o700) {
    throw { errno: 'EACCES', detail: `invalid runtime dir ${dir}` };
  }
  if (session !== guiSession()) throw { errno: 'ESTALE', detail: 'session changed before bind' };
  try { await kernel.proc_unlinkat(pid, 0x7ffffffd, path, false); } catch {}
  const sockOp = args => guiExecutor.mountSocketOp({ pid, args });
  const created = await sockOp({ op: 'create', sockType: 1 });
  const sockId = created.sockId;
  const srv = { pid, uid, sockId, path, session, closed: false, activeConns: 0 };
  try {
    await sockOp({ op: 'bind', sockId, path });
    const chmodSockRes = JSON.parse(await kernel.proc_sys(pid, JSON.stringify({ calls: [{ chmod: { path, mode: 0o600 } }] })));
    if (chmodSockRes?.results?.[0]?.err) throw { errno: chmodSockRes.results[0].err.errno || 'EACCES' };
    const sockStat = await kernel.proc_statat(pid, 0x7ffffffd, path, false);
    if (!sockStat || (sockStat.mode & 0o170000) !== 0o140000 || sockStat.uid !== uid || (sockStat.mode & 0o7777) !== 0o600) {
      throw { errno: 'EACCES', detail: `invalid socket mode on ${path}` };
    }
    await sockOp({ op: 'listen', sockId, backlog: 16 });
    await sockOp({ op: 'set_nonblock', sockId, nonblock: true });
    if (session !== guiSession()) {
      throw { errno: 'ESTALE', detail: 'session changed during desktop-actions setup' };
    }
  } catch (err) {
    void sockOp({ op: 'close', sockId }).catch(() => {});
    void kernel.proc_unlinkat(pid, 0x7ffffffd, path, false).catch(() => {});
    throw err;
  }
  desktopActionsSrv = srv;

  const handleClient = async (clientSockId, acceptedCred) => {
    let entry = null;
    if (srv.activeConns >= MAX_DESKTOP_ACTION_CONNS) {
      await sockOp({ op: 'close', sockId: clientSockId }).catch(() => {});
      return;
    }
    srv.activeConns++;
    try {
      if (srv.closed || srv.session !== guiSession()) {
        return;
      }
      const cred = acceptedCred ?? await sockOp({ op: 'peercred', sockId: clientSockId });
      if (cred?.uid !== uid) {
        return;
      }
      let buf = '';
      let bufBytes = 0;
      let actionId = null;
      while (!srv.closed && srv.session === guiSession() && (!entry || !entry.closed)) {
        const r = await sockOp({ op: 'recvmsg', sockId: clientSockId, sabStream: true, bufLen: 4096, maxFds: 0 });
        if (srv.closed || srv.session !== guiSession() || entry?.closed) break;
        if (r?.wouldBlock) { await new Promise(res => setTimeout(res, 15)); continue; }
        const chunk = typeof r?.data === 'string'
          ? base64ToBytes(r.data)
          : r?.data instanceof Uint8Array ? r.data : new Uint8Array(r?.data ?? []);
        if (!chunk.length) {
          if (actionId != null && desktopActionClients.has(actionId) && srv.session === guiSession()) {
            broadcast({ v: VERSION, type: 'event', event: 'desktop-action-cancel', value: { id: actionId } });
          }
          break;
        }
        bufBytes += chunk.length;
        if (bufBytes > MAX_DESKTOP_ACTION_BYTES) {
          break;
        }
        buf += textDecoder.decode(chunk, { stream: true });
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          bufBytes = textEncoder.encode(buf).length;
          if (!line) continue;
          if (srv.closed || srv.session !== guiSession()) break;
          let msg;
          try { msg = JSON.parse(line); } catch { continue; }
          if (actionId == null) {
            actionId = ++desktopActionSeq;
            entry = { id: actionId, pid, sockId: clientSockId, session, closed: false };
            desktopActionClients.set(actionId, entry);
            broadcast({ v: VERSION, type: 'event', event: 'desktop-action', value: { id: actionId, req: msg } });
          } else if (msg?.op === 'cancel') {
            broadcast({ v: VERSION, type: 'event', event: 'desktop-action-cancel', value: { id: actionId } });
          }
        }
      }
    } catch { /* peer closed */ }
    finally {
      srv.activeConns = Math.max(0, srv.activeConns - 1);
      if (entry && !entry.closed) {
        entry.closed = true;
        desktopActionClients.delete(entry.id);
      }
      await sockOp({ op: 'close', sockId: clientSockId }).catch(() => {});
    }
  };

  void (async () => {
    while (!srv.closed) {
      try {
        const res = await sockOp({ op: 'accept', sockId });
        if (srv.closed) break;
        if (res?.wouldBlock) { await new Promise(r => setTimeout(r, 25)); continue; }
        if (res?.sockId != null) void handleClient(res.sockId, res.peerCred);
      } catch {
        if (srv.closed) break;
        await new Promise(r => setTimeout(r, 50));
      }
    }
  })();
}
function closeCompatConn(reason = { errno: 'ECONNRESET' }, preserveConnecting = null) {
  if (compatConnecting && compatConnecting !== preserveConnecting) compatConnecting = null;
  closeDesktopActionsServer();
  const conn = compatConn;
  compatConn = null;
  if (!conn || conn.closed) return;
  conn.closed = true;
  for (const waiter of conn.pending.splice(0)) waiter.reject(reason);
  if (conn.sockId != null && guiExecutor?.mountSocketOp) {
    void guiExecutor.mountSocketOp({ pid: conn.pid, args: { op: 'close', sockId: conn.sockId } }).catch(() => {});
  }
}
async function waitUnitActive(isSystem, sid, unit, timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const resp = await kernel.gui_service_control_rpc(
      isSystem, sid, JSON.stringify({ op: 'status', unit }), guiExecutor.mountSocketOp,
    );
    if (resp?.status === 'unit' && resp.unit?.state === 'active') return resp.unit;
    if (resp?.status === 'unit' && resp.unit?.state === 'failed') {
      throw { errno: 'EIO', detail: resp.unit.last_error || `${unit} failed` };
    }
    if (Date.now() >= deadline) throw { errno: 'ETIMEDOUT', detail: `timed out waiting for ${unit}` };
    await new Promise(r => setTimeout(r, 40));
  }
}
async function ensureCompatConn() {
  const initialSession = guiSession();
  if (compatConn && !compatConn.closed && initialSession && compatConn.session === initialSession) {
    return compatConn;
  }
  if (compatConnecting && initialSession && compatConnecting.session === initialSession) {
    return compatConnecting.promise;
  }
  const connecting = { session: initialSession, promise: null };
  connecting.promise = (async () => {
    guiExecutor ??= await import(asset('/executor-host.js'));
    const workspace = await guiExecutor.currentWorkspace();
    const session = guiSession();
    const sid = workspace?.id || login?.current()?.session?.id;
    const uid = workspace?.identity?.uid ?? login?.current()?.session?.uid;
    if (!session || !sid) throw { errno: 'EACCES', detail: 'no active login session' };
    connecting.session = session;
    if (compatConn && !compatConn.closed && compatConn.session === session) return compatConn;
    closeCompatConn({ errno: 'ESTALE' }, connecting);
    const pid = kernel.gui_compat_proxy(sid);
    const sockOp = args => guiExecutor.mountSocketOp({ pid, args });
    const created = await sockOp({ op: 'create', sockType: 1 });
    const sockId = created.sockId;
    const conn = { pid, sockId, session, rxBuf: new Uint8Array(0), pending: [], closed: false };
    try {
      const deadline = Date.now() + 10000;
      for (;;) {
        if (session !== guiSession()) throw { errno: 'ESTALE', detail: 'login session changed' };
        try {
          await sockOp({ op: 'connect', sockId, path: '/run/gui/seat0.sock' });
          break;
        } catch (err) {
          if (!['ENOENT', 'ECONNREFUSED'].includes(err?.errno) || Date.now() >= deadline) throw err;
          await new Promise(r => setTimeout(r, 25));
        }
      }
      if (session !== guiSession()) throw { errno: 'ESTALE', detail: 'login session changed' };
      const sendRaw = async reqObj => {
        const encoded = kernel.gui_encode_frame(JSON.stringify(reqObj));
        let sent = 0;
        while (sent < encoded.length) {
          try {
            const chunk = encoded.subarray(sent, Math.min(encoded.length, sent + 4096));
            const r = await sockOp({ op: 'sendmsg', sockId, fds: [], data: bytesToBase64(chunk) });
            if (!r?.sent) throw { errno: 'EPIPE' };
            sent += r.sent;
          } catch (err) {
            if (err?.errno === 'EAGAIN') { await new Promise(r => setTimeout(r, 5)); continue; }
            throw err;
          }
        }
      };
      const pump = async () => {
        try {
          while (!conn.closed) {
            const r = await sockOp({ op: 'recvmsg', sockId, sabStream: true, bufLen: 8192, maxFds: 0 });
            if (conn.closed) return;
            if (r?.wouldBlock) { await new Promise(res => setTimeout(res, 12)); continue; }
            const chunk = typeof r?.data === 'string'
              ? base64ToBytes(r.data)
              : r?.data instanceof Uint8Array ? r.data : new Uint8Array(r?.data ?? []);
            if (!chunk.length) { closeCompatConn({ errno: 'ECONNRESET' }); return; }
            const merged = new Uint8Array(conn.rxBuf.length + chunk.length);
            merged.set(conn.rxBuf, 0);
            merged.set(chunk, conn.rxBuf.length);
            conn.rxBuf = merged;
            for (;;) {
              const decoded = kernel.gui_decode_frame(conn.rxBuf);
              if (!decoded) break;
              conn.rxBuf = conn.rxBuf.subarray(decoded.consumed);
              const ev = decoded.event;
              if (['hello', 'created', 'ok', 'error'].includes(ev?.op) && conn.pending.length) {
                conn.pending.shift().resolve(ev);
              } else {
                broadcast({ v: VERSION, type: 'event', event: 'gui-compat-event', value: ev });
              }
            }
          }
        } catch (err) {
          if (!conn.closed) closeCompatConn(failure(err));
        }
      };
      conn.sendRaw = sendRaw;
      compatConn = conn;
      void pump();
      const helloReply = await new Promise((resolve, reject) => {
        conn.pending.push({ resolve, reject });
        sendRaw({ op: 'hello', versions: [1], required: [] }).catch(err => {
          const idx = conn.pending.findIndex(w => w.resolve === resolve);
          if (idx >= 0) conn.pending.splice(idx, 1);
          reject(err);
        });
      });
      if (helloReply?.op !== 'hello' || helloReply.version !== 1) {
        throw { errno: 'EPROTONOSUPPORT' };
      }
      if (conn.closed || session !== guiSession()) {
        throw { errno: 'ESTALE', detail: 'login session changed during compat handshake' };
      }
      if (typeof uid === 'number') {
        await ensureDesktopActionsServer(pid, uid, session).catch(err => {
          console.warn('desktop-actions.sock setup failed:', err);
        });
      }
      if (conn.closed || session !== guiSession()) {
        throw { errno: 'ESTALE', detail: 'login session changed during desktop-actions setup' };
      }
      return conn;
    } catch (err) {
      if (compatConn === conn) closeCompatConn(failure(err), connecting);
      else void sockOp({ op: 'close', sockId }).catch(() => {});
      throw err;
    }
  })();
  compatConnecting = connecting;
  connecting.promise.finally(() => {
    if (compatConnecting === connecting) compatConnecting = null;
  });
  return connecting.promise;
}
function sendCompatReq(reqObj) {
  const run = compatQueue.then(async () => {
    const conn = await ensureCompatConn();
    const reply = await new Promise((resolve, reject) => {
      const waiter = { resolve, reject };
      conn.pending.push(waiter);
      conn.sendRaw(reqObj).catch(err => {
        const idx = conn.pending.indexOf(waiter);
        if (idx >= 0) conn.pending.splice(idx, 1);
        reject(err);
      });
    });
    if (reply?.op === 'error') throw { errno: reply.errno };
    return reply;
  });
  compatQueue = run.catch(() => {});
  return run;
}
async function startOrRestartDesktop(restart) {
  if (!globalThis.crossOriginIsolated) return { supported: false };
  if (desktopStarting && !restart) return desktopStarting;
  const task = (async () => {
    guiExecutor ??= await import(asset('/executor-host.js'));
    const deadline = Date.now() + 15000;
    while ((!login?.current()?.session?.id || localInitState === 'starting') && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 30));
    }
    const workspace = await guiExecutor.currentWorkspace();
    const sid = workspace?.id || login?.current()?.session?.id;
    if (!sid) throw { errno: 'EACCES', detail: 'login session unavailable' };
    if (restart) {
      closeCompatConn({ errno: 'ESTALE' });
      await kernel.gui_service_control_rpc(
        true, sid, JSON.stringify({ op: 'restart', unit: 'compositor.service' }), guiExecutor.mountSocketOp,
      );
    } else {
      await kernel.gui_service_control_rpc(
        true, sid, JSON.stringify({ op: 'start', unit: 'graphical.target' }), guiExecutor.mountSocketOp,
      );
    }
    const compositor = await waitUnitActive(true, sid, 'compositor.service');
    if (restart) {
      await kernel.gui_service_control_rpc(
        false, sid, JSON.stringify({ op: 'restart', unit: 'desktop-shell.service' }), guiExecutor.mountSocketOp,
      );
    } else {
      await kernel.gui_service_control_rpc(
        false, sid, JSON.stringify({ op: 'start', unit: 'graphical.target' }), guiExecutor.mountSocketOp,
      );
    }
    const shell = await waitUnitActive(false, sid, 'desktop-shell.service');
    await ensureCompatConn();
    return { supported: true, compositor, shell, seatEpoch };
  })();
  if (!restart) {
    desktopStarting = task;
    task.finally(() => { if (desktopStarting === task) desktopStarting = null; });
  }
  return task;
}
function guiInput(event) {
  const epoch = seatEpoch, session = guiSession();
  const sent = inputQueue.then(() => enqueueSeat(() => {
    if (epoch !== seatEpoch) throw { errno: 'ESTALE' };
    kernel.gui_host_event(JSON.stringify(event));
    if (event.op === 'pointer_down' || event.op === 'key' || event.op === 'paste') guiActivation = { surface: event.surface_id, session };
    if (event.op === 'host_focus' || (event.op === 'seat_active' && !event.active)) guiActivation = null;
  }, () => guiExecutor?.wakeGuiSeat(), event.op === 'document_message' ? 0 : 32));
  inputQueue = sent.catch(() => {});
  return sent;
}
function revokePort(id) { guiPorts.get(id)?.close(); guiPorts.delete(id); }
function currentPick(pick) {
  if (!pick || guiPicks.get(pick.request) !== pick || !pick.session || pick.session !== guiSession()) return false;
  try {
    const b = bindingFor(pick.surface), live = login.current().session;
    const job = guiJobs.get(b.pid);
    return b.pid === pick.pid && b.endpoint === pick.endpoint && b.session === live.id &&
      b.loginGeneration === live.generation && (!job || job.session === pick.session);
  } catch { return false; }
}
self.onGuiPickCurrent = request => currentPick(guiPicks.get(request));
const guiConsents = new Map();
const pendingMountTransports = new Map();
let nextMountTransportId = 1;
let mountTransportReady = false;
self.openWindowMountTransport = (kind, options = {}) => {
  if (ports.size === 0 || !mountTransportReady) return Promise.resolve(null);
  const id = nextMountTransportId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingMountTransports.delete(id);
      reject({ errno: 'ETIMEDOUT', detail: 'window mount transport timed out' });
    }, 5000);
    pendingMountTransports.set(id, {
      resolve: port => { clearTimeout(timer); pendingMountTransports.delete(id); resolve(port); },
      reject: err => { clearTimeout(timer); pendingMountTransports.delete(id); reject(err); },
    });
    broadcast({ v: VERSION, type: 'event', event: 'mount-transport-open', value: { id, kind, p2p: options.p2p !== false } });
  });
};
function consentMatchesLive(consent) {
  if (!consent || !consent.session || consent.session !== guiSession()) return false;
  try {
    const b = bindingFor(consent.surface), live = login.current().session;
    const job = guiJobs.get(b.pid);
    return b.pid === consent.pid && b.endpoint === consent.endpoint && b.uid === live.uid &&
      b.isMounts === true && b.session === live.id && b.loginGeneration === live.generation &&
      (!job || job.session === consent.session);
  } catch { return false; }
}
function currentConsent(consent) {
  return Boolean(consent && guiConsents.get(consent.request) === consent && consentMatchesLive(consent));
}
function retireConsent(consent, notify, sessionChanged = false, customOutcome = null) {
  if (guiConsents.get(consent.request) !== consent) return;
  guiConsents.delete(consent.request);
  if (notify) {
    void guiInput({
      op: 'mount_consent_result',
      request_id: consent.request,
      surface_id: consent.surface,
      outcome: customOutcome ?? (sessionChanged
        ? { status: 'error', errno: 'ECANCELED', detail: 'Session changed. Choose the folder again.' }
        : { status: 'canceled', errno: 'ECANCELED' }),
    }).catch(reportGui);
  }
}
let nextDropRequestId = 0x400000000000;
const pickerInput = (pick, chosen, meta = {}) => guiInput({
  op: 'picker_result',
  request_id: pick.request,
  surface_id: pick.surface,
  chosen,
  ...(meta.name != null ? { name: meta.name } : {}),
  ...(meta.size != null ? { size: meta.size } : {}),
  ...(meta.index != null ? { index: meta.index } : {}),
  ...(meta.total != null ? { total: meta.total } : {}),
});
function retirePick(pick, notify) {
  if (guiPicks.get(pick.request) !== pick) return;
  guiPicks.delete(pick.request);
  if (pick.createdPaths?.size) void unlinkPick(pick).catch(reportGui);
  if (notify) {
    broadcast({ v: VERSION, type: 'event', event: 'gui-display', value: { op: 'cancel_picker', request_id: pick.request } });
    void pickerInput(pick, false).catch(reportGui);
  }
}
async function unlinkPick(pick) {
  const paths = pick.createdPaths ? [...pick.createdPaths] : [pick.path];
  pick.createdPaths?.clear();
  for (const p of paths) {
    try { await kernel.proc_unlinkat(1, -100, p, false); }
    catch (e) { if (e.errno !== 'ENOENT') throw e; }
  }
}
async function streamFilesToPick(pick, files) {
  const check = () => { if (!currentPick(pick)) throw { errno: 'ECANCELED' }; };
  pick.copying = true;
  const total = files.length;
  try {
    check();
    for (let index = 0; index < total; index++) {
      const file = files[index];
      if (!(file instanceof File)) throw { errno: 'EINVAL' };
      const stagePath = total > 1 ? `/run/gui/pick-${pick.request}-${index}` : pick.path;
      const fd = await kernel.proc_openat(1, -100, stagePath, 1 | 64 | 128, 0o400, true);
      pick.createdPaths.add(stagePath);
      try {
        for (let offset = 0; offset < file.size; offset += 65536) {
          check();
          const chunk = new Uint8Array(await file.slice(offset, offset + 65536).arrayBuffer());
          check();
          if (await kernel.kfd_write(1, fd.kfd, chunk) !== chunk.length) throw { errno: 'EIO' };
        }
      } finally { await kernel.kfd_close(1, fd.kfd); }
      check();
      await pickerInput(pick, true, {
        name: file.name,
        size: file.size,
        index,
        total,
      });
    }
    // The SCM_RIGHTS commit retires the record via PickerDelivered. Reset/unmap can still cancel.
  } catch (error) {
    if (pick.createdPaths.size) await unlinkPick(pick);
    retirePick(pick, true);
    throw error;
  }
}
function reportGui(e) { if (!['ESTALE','ENODEV'].includes(e.errno)) console.error('GUI seat', e); }
self.onGuiDisplayCmd = raw => {
  const cmd = JSON.parse(raw);
  if (cmd.op === 'seat_reset') { seatEpoch++; inputQueue = Promise.resolve(); closeCompatConn({ errno: 'ESTALE' }); }
  if (cmd.op === 'seat_reset' || cmd.op === 'unmap') {
    for (const id of guiPorts.keys()) if (cmd.op === 'seat_reset' || id === cmd.surface_id) revokePort(id);
    for (const pick of guiPicks.values()) if (cmd.op === 'seat_reset' || pick.surface === cmd.surface_id) retirePick(pick, false);
    for (const consent of guiConsents.values()) if (cmd.op === 'seat_reset' || consent.surface === cmd.surface_id) retireConsent(consent, false);
    if (cmd.op === 'seat_reset' || guiActivation?.surface === cmd.surface_id) guiActivation = null;
  }
  if (['unmap','seat_reset','recreate_pixel_canvas'].includes(cmd.op)) {
    const retainSize = cmd.op === 'recreate_pixel_canvas';
    for (const [id, binding] of guiCanvases) if (cmd.op === 'seat_reset' || id === cmd.surface_id) {
      guiExecutor?.disposeGuiCanvas(binding.pid, id, binding.generation, retainSize); guiCanvases.delete(id);
    }
  }
  if (cmd.op === 'document_reply') { guiPorts.get(cmd.surface_id)?.postMessage({ text: cmd.text }); return; }
  if (cmd.op === 'picker_delivered' || cmd.op === 'cancel_picker') {
    const pick = guiPicks.get(cmd.request_id);
    if (pick && !(cmd.op === 'cancel_picker' && pick.cloudDest && pick.streaming)) {
      retirePick(pick, false);
    }
    if (cmd.op === 'picker_delivered') return;
  }
  if (cmd.op === 'pick_file') {
    const session = guiActivation?.surface === cmd.surface_id ? guiActivation.session : null;
    guiActivation = null;
    const pick = {
      session,
      request: cmd.request_id,
      surface: cmd.surface_id,
      path: '/run/gui/pick-' + cmd.request_id,
      createdPaths: new Set(),
      cloudDest: cmd.cloud_dest ?? null,
    };
    try { const binding = bindingFor(pick.surface); pick.pid = binding.pid; pick.endpoint = binding.endpoint; }
    catch { /* The next check cancels a retired endpoint. */ }
    guiPicks.set(pick.request, pick);
    if (!currentPick(pick)) { retirePick(pick, true); return; }
  }
  if (cmd.op === 'mount_consent') {
    const mutating = cmd.action?.action !== 'capabilities';
    const session = mutating
      ? (guiActivation?.surface === cmd.surface_id ? guiActivation.session : null)
      : guiSession();
    if (mutating) guiActivation = null;
    const consent = {
      session,
      request: cmd.request_id,
      surface: cmd.surface_id,
      mutating,
      action: cmd.action,
      cloudAccess: false,
      isMounts: false,
    };
    try {
      const binding = bindingFor(consent.surface);
      consent.pid = binding.pid;
      consent.endpoint = binding.endpoint;
      consent.uid = binding.uid;
      consent.cloudAccess = Boolean(binding.cloudAccess);
      consent.isMounts = Boolean(binding.isMounts);
    } catch { /* The next check cancels a retired endpoint. */ }
    guiConsents.set(consent.request, consent);
    const forbidden = !consent.isMounts || (Boolean(cmd.action?.cloud) && !consent.cloudAccess);
    if (forbidden || !currentConsent(consent)) {
      retireConsent(
        consent,
        true,
        false,
        forbidden ? { status: 'error', errno: 'EACCES', detail: 'Permission denied.' } : null,
      );
      return;
    }
  }
  broadcast({ v: VERSION, type: 'event', event: 'gui-display', value: cmd });
};
async function guiRequest(type, args) {
  guiExecutor ??= await import(asset('/executor-host.js'));
  if (type === 'gui_start_desktop') return startOrRestartDesktop(false);
  if (type === 'gui_restart_desktop') return startOrRestartDesktop(true);
  if (type === 'gui_compat_req') return sendCompatReq(args.req);
  if (type === 'gui_desktop_action_reply') {
    const entry = desktopActionClients.get(args.id);
    if (!entry || entry.closed) return null;
    if (entry.session !== guiSession()) {
      entry.closed = true;
      desktopActionClients.delete(args.id);
      await guiExecutor.mountSocketOp({ pid: entry.pid, args: { op: 'close', sockId: entry.sockId } }).catch(() => {});
      return null;
    }
    const payload = textEncoder.encode(JSON.stringify(args.reply ?? { done: true, status: 0 }) + '\n');
    try {
      await sendSocketBytes(entry.pid, entry.sockId, payload);
    } finally {
      if (args.reply?.done) {
        entry.closed = true;
        desktopActionClients.delete(args.id);
        await guiExecutor.mountSocketOp({ pid: entry.pid, args: { op: 'close', sockId: entry.sockId } }).catch(() => {});
      }
    }
    return null;
  }
  if (type === 'gui_terminal_open_tab') {
    guiExecutor ??= await import(asset('/executor-host.js'));
    const workspace = await guiExecutor.currentWorkspace();
    const sid = workspace?.id || login?.current()?.session?.id;
    const uid = workspace?.identity?.uid ?? login?.current()?.session?.uid;
    if (!sid || typeof uid !== 'number') throw { errno: 'EACCES' };
    const pid = kernel.gui_compat_proxy(sid);
    const sockOp = a => guiExecutor.mountSocketOp({ pid, args: a });
    const created = await sockOp({ op: 'create', sockType: 1 });
    const sockId = created.sockId;
    try {
      const conn = await sockOp({ op: 'connect', sockId, path: `/run/user/${uid}/terminal.sock` });
      const peerCred = conn?.peerCred ?? await sockOp({ op: 'peercred', sockId });
      if (peerCred?.uid !== uid) throw { errno: 'EACCES', detail: 'terminal control socket peer UID mismatch' };
      const reqLine = textEncoder.encode(JSON.stringify({
        op: 'open_tab',
        argv: Array.isArray(args.argv) && args.argv.length ? args.argv : null,
        cwd: typeof args.cwd === 'string' && args.cwd ? args.cwd : null,
      }) + '\n');
      await sendSocketBytes(pid, sockId, reqLine);
      const deadline = Date.now() + 2000;
      let buf = '';
      let bufBytes = 0;
      while (Date.now() < deadline && !buf.includes('\n')) {
        const r = await sockOp({ op: 'recvmsg', sockId, sabStream: true, bufLen: 1024, maxFds: 0 });
        if (r?.wouldBlock) { await new Promise(res => setTimeout(res, 15)); continue; }
        const chunk = typeof r?.data === 'string'
          ? base64ToBytes(r.data)
          : r?.data instanceof Uint8Array ? r.data : new Uint8Array(r?.data ?? []);
        if (!chunk.length) break;
        bufBytes += chunk.length;
        if (bufBytes > MAX_TERMINAL_CTRL_REPLY_BYTES) throw { errno: 'E2BIG', detail: 'terminal control reply too large' };
        buf += textDecoder.decode(chunk, { stream: true });
      }
      const nl = buf.indexOf('\n');
      if (nl < 0) throw { errno: 'EIO', detail: 'terminal control socket closed without reply' };
      let reply;
      try { reply = JSON.parse(buf.slice(0, nl)); } catch {
        throw { errno: 'EIO', detail: 'malformed terminal control reply' };
      }
      if (!reply?.ok) {
        throw { errno: 'EIO', detail: typeof reply?.error === 'string' ? reply.error : 'terminal open_tab failed' };
      }
      return { ok: true, reused: true, tab: reply.tab };
    } catch (err) {
      if (!['ENOENT', 'ECONNREFUSED'].includes(err?.errno)) throw err;
      const launchArgv = [];
      if (typeof args.cwd === 'string' && args.cwd) launchArgv.push('--cwd', args.cwd);
      if (Array.isArray(args.argv) && args.argv.length) launchArgv.push('--', ...args.argv);
      const spawned = await guiRequest('gui_start', {
        program: 'terminal',
        argv: launchArgv,
        cwd: args.cwd ?? undefined,
      });
      return { ok: true, reused: false, pid: spawned };
    } finally {
      await sockOp({ op: 'close', sockId }).catch(() => {});
    }
  }
  if (type === 'gui_files_open_dir' || type === 'gui_files_refresh' || type === 'gui_files_trigger_upload') {
    const workspace = await guiExecutor.currentWorkspace();
    const sid = workspace?.id || login?.current()?.session?.id;
    const uid = workspace?.identity?.uid ?? login?.current()?.session?.uid;
    if (!sid || typeof uid !== 'number') throw { errno: 'EACCES' };
    const pid = kernel.gui_compat_proxy(sid);
    const sockOp = a => guiExecutor.mountSocketOp({ pid, args: a });
    const created = await sockOp({ op: 'create', sockType: 1 });
    const sockId = created.sockId;
    const reqObj = type === 'gui_files_open_dir'
      ? { op: 'open_dir', path: String(args.path ?? '/') }
      : type === 'gui_files_trigger_upload'
      ? { op: 'trigger_upload' }
      : { op: 'refresh' };
    try {
      const conn = await sockOp({ op: 'connect', sockId, path: `/run/user/${uid}/files.sock` });
      const peerCred = conn?.peerCred ?? await sockOp({ op: 'peercred', sockId });
      if (peerCred?.uid !== uid) throw { errno: 'EACCES', detail: 'files control socket peer UID mismatch' };
      const reqLine = textEncoder.encode(JSON.stringify(reqObj) + '\n');
      await sendSocketBytes(pid, sockId, reqLine);
      const deadline = Date.now() + 2000;
      let buf = '';
      let bufBytes = 0;
      while (Date.now() < deadline && !buf.includes('\n')) {
        const r = await sockOp({ op: 'recvmsg', sockId, sabStream: true, bufLen: 1024, maxFds: 0 });
        if (r?.wouldBlock) { await new Promise(res => setTimeout(res, 15)); continue; }
        const chunk = typeof r?.data === 'string'
          ? base64ToBytes(r.data)
          : r?.data instanceof Uint8Array ? r.data : new Uint8Array(r?.data ?? []);
        if (!chunk.length) break;
        bufBytes += chunk.length;
        if (bufBytes > MAX_TERMINAL_CTRL_REPLY_BYTES) throw { errno: 'E2BIG', detail: 'files control reply too large' };
        buf += textDecoder.decode(chunk, { stream: true });
      }
      const nl = buf.indexOf('\n');
      if (nl < 0) throw { errno: 'EIO', detail: 'files control socket closed without reply' };
      let reply;
      try { reply = JSON.parse(buf.slice(0, nl)); } catch {
        throw { errno: 'EIO', detail: 'malformed files control reply' };
      }
      if (!reply?.ok) {
        throw { errno: 'EIO', detail: typeof reply?.error === 'string' ? reply.error : 'files control request failed' };
      }
      return { ok: true, reused: true };
    } catch (err) {
      if (!['ENOENT', 'ECONNREFUSED'].includes(err?.errno)) throw err;
      if (type === 'gui_files_refresh') return { ok: true, reused: false };
      const launchArgv = type === 'gui_files_open_dir'
        ? ['--dir', String(args.path ?? '/')]
        : ['--upload'];
      const spawned = await guiRequest('gui_start', {
        program: 'files',
        argv: launchArgv,
      });
      return { ok: true, reused: false, pid: spawned };
    } finally {
      await sockOp({ op: 'close', sockId }).catch(() => {});
    }
  }
  if (type === 'gui_mounts_focus' || type === 'gui_mounts_refresh') {
    const workspace = await guiExecutor.currentWorkspace();
    const sid = workspace?.id || login?.current()?.session?.id;
    const uid = workspace?.identity?.uid ?? login?.current()?.session?.uid;
    if (!sid || typeof uid !== 'number') throw { errno: 'EACCES' };
    const pid = kernel.gui_compat_proxy(sid);
    const sockOp = a => guiExecutor.mountSocketOp({ pid, args: a });
    const created = await sockOp({ op: 'create', sockType: 1 });
    const sockId = created.sockId;
    const tab = typeof args.tab === 'string' && args.tab ? args.tab : null;
    const reqObj = type === 'gui_mounts_focus'
      ? { op: 'focus', ...(tab ? { tab } : {}) }
      : { op: 'refresh', ...(args.reset ? { reset: true } : {}) };
    try {
      const conn = await sockOp({ op: 'connect', sockId, path: `/run/user/${uid}/mounts.sock` });
      const peerCred = conn?.peerCred ?? await sockOp({ op: 'peercred', sockId });
      if (peerCred?.uid !== uid) throw { errno: 'EACCES', detail: 'mounts control socket peer UID mismatch' };
      const reqLine = textEncoder.encode(JSON.stringify(reqObj) + '\n');
      await sendSocketBytes(pid, sockId, reqLine);
      const deadline = Date.now() + 2000;
      let buf = '';
      let bufBytes = 0;
      while (Date.now() < deadline && !buf.includes('\n')) {
        const r = await sockOp({ op: 'recvmsg', sockId, sabStream: true, bufLen: 1024, maxFds: 0 });
        if (r?.wouldBlock) { await new Promise(res => setTimeout(res, 15)); continue; }
        const chunk = typeof r?.data === 'string'
          ? base64ToBytes(r.data)
          : r?.data instanceof Uint8Array ? r.data : new Uint8Array(r?.data ?? []);
        if (!chunk.length) break;
        bufBytes += chunk.length;
        if (bufBytes > MAX_TERMINAL_CTRL_REPLY_BYTES) throw { errno: 'E2BIG', detail: 'mounts control reply too large' };
        buf += textDecoder.decode(chunk, { stream: true });
      }
      const nl = buf.indexOf('\n');
      if (nl < 0) throw { errno: 'EIO', detail: 'mounts control socket closed without reply' };
      let reply;
      try { reply = JSON.parse(buf.slice(0, nl)); } catch {
        throw { errno: 'EIO', detail: 'malformed mounts control reply' };
      }
      if (!reply?.ok) {
        throw { errno: 'EIO', detail: typeof reply?.error === 'string' ? reply.error : 'mounts control request failed' };
      }
      return { ok: true, reused: true, tab: reply.tab ?? null };
    } catch (err) {
      if (!['ENOENT', 'ECONNREFUSED'].includes(err?.errno)) throw err;
      if (type === 'gui_mounts_refresh') return { ok: true, reused: false };
      const launchArgv = tab ? ['--tab', tab] : [];
      const spawned = await guiRequest('gui_start', {
        program: 'mounts',
        argv: launchArgv,
      });
      return { ok: true, reused: false, pid: spawned };
    } finally {
      await sockOp({ op: 'close', sockId }).catch(() => {});
    }
  }
  if (type === 'gui_mount_consent_result') {
    const { request_id, surface_id, outcome } = args;
    if (outcome?.status === 'granted' || outcome?.status === 'renewed') {
      throw { errno: 'EACCES', detail: 'grant outcomes must commit atomically through gui_mount_consent_commit' };
    }
    const consent = guiConsents.get(request_id);
    if (!consent || consent.surface !== surface_id || !currentConsent(consent)) {
      if (consent) retireConsent(consent, true, Boolean(consent.session && consent.session !== guiSession()));
      throw { errno: 'ECANCELED' };
    }
    guiConsents.delete(request_id);
    await guiInput({
      op: 'mount_consent_result',
      request_id,
      surface_id,
      outcome,
    });
    return null;
  }
  if (type === 'gui_mount_consent_commit') {
    const { request_id, surface_id, handle } = args;
    const consent = guiConsents.get(request_id);
    if (!consent || !consent.mutating || consent.surface !== surface_id || !currentConsent(consent)) {
      if (consent) retireConsent(consent, true, Boolean(consent.session && consent.session !== guiSession()));
      throw { errno: 'ECANCELED' };
    }
    guiConsents.delete(request_id);
    const action = consent.action;
    const VALID_CONSENT_ERRNOS = new Set([
      'EACCES', 'EPERM', 'ENOENT', 'EEXIST', 'EINVAL', 'EBUSY', 'ECANCELED', 'EIO',
      'ENODEV', 'ENOSYS', 'EOPNOTSUPP', 'ENOTCONN', 'ESTALE', 'E2BIG', 'EAGAIN', 'ETIMEDOUT',
    ]);
    const failOutcome = err => {
      const code = err?.errno === 'ENOTSUP'
        ? 'EOPNOTSUPP'
        : (typeof err?.errno === 'string' && VALID_CONSENT_ERRNOS.has(err.errno) ? err.errno : 'EIO');
      return { status: 'error', errno: code, detail: String(err?.detail ?? err?.message ?? err?.errno ?? err) };
    };
    let outcome;
    try {
      if (action?.cloud && !consent.cloudAccess) {
        outcome = { status: 'error', errno: 'EACCES', detail: 'Cloud access not permitted for this process.' };
      } else {
        const local = await guiExecutor.request('source_session', {}, () => {}, () => {});
        if (!consentMatchesLive(consent) || local.uid !== consent.uid) {
          outcome = { status: 'error', errno: 'ECANCELED', detail: 'Session changed. Choose the folder again.' };
        } else if (action.action === 'pick_host_folder') {
          const res = await guiExecutor.request('source_register_host', {
            loginEpoch: local.loginEpoch,
            handle,
            writable: Boolean(action.writable),
            execute: Boolean(action.execute),
            cloud: Boolean(action.cloud),
            save: Boolean(action.save),
          }, () => {}, () => {});
          outcome = {
            status: 'granted',
            source_id: res.source_id,
            label: handle?.name || 'Host folder',
            writable: Boolean(action.writable),
          };
        } else if (action.action === 'renew_host_folder') {
          await guiExecutor.request('source_renew', {
            source_id: action.source_id,
            loginEpoch: local.loginEpoch,
          }, () => {}, () => {});
          outcome = { status: 'renewed', source_id: action.source_id };
        } else if (action.action === 'register_opfs') {
          const res = await guiExecutor.request('source_register_opfs', {
            loginEpoch: local.loginEpoch,
            writable: Boolean(action.writable),
            execute: Boolean(action.execute),
            cloud: Boolean(action.cloud),
          }, () => {}, () => {});
          outcome = {
            status: 'granted',
            source_id: res.source_id,
            label: 'Browser storage',
            writable: Boolean(action.writable),
          };
        } else if (action.action === 'register_helper') {
          const res = await guiExecutor.request('source_register_helper', {
            loginEpoch: local.loginEpoch,
            url: action.url,
            token: action.token,
            writable: Boolean(action.writable),
            execute: Boolean(action.execute),
            cloud: Boolean(action.cloud),
          }, () => {}, () => {});
          outcome = {
            status: 'granted',
            source_id: res.source_id,
            label: 'Local helper',
            writable: Boolean(action.writable),
          };
        } else if (action.action === 'register_share') {
          const res = await guiExecutor.request('source_register_share', {
            loginEpoch: local.loginEpoch,
            address: action.address,
            password: action.password,
            writable: Boolean(action.writable),
            execute: Boolean(action.execute),
          }, () => {}, () => {});
          outcome = {
            status: 'granted',
            source_id: res.source_id,
            label: 'Shared directory',
            writable: Boolean(action.writable),
          };
        } else {
          outcome = { status: 'error', errno: 'EOPNOTSUPP', detail: 'Unsupported mount consent action.' };
        }
      }
    } catch (err) {
      outcome = failOutcome(err);
    }
    await guiInput({
      op: 'mount_consent_result',
      request_id,
      surface_id,
      outcome,
    });
    return null;
  }
  if (type === 'gui_mount_transport_ready') {
    mountTransportReady = true;
    return null;
  }
  if (type === 'gui_mount_transport_port') {
    const entry = pendingMountTransports.get(args.id);
    if (!entry) {
      args.port?.postMessage?.({ type: 'close' });
      args.port?.close?.();
      return null;
    }
    if (args.error || !(args.port instanceof MessagePort)) {
      entry.reject({ errno: args.error || 'ENOTCONN' });
      return null;
    }
    entry.resolve(args.port);
    return null;
  }
  if (type === 'gui_greeter_start' || type === 'gui_greeter_stop') {
    const workspace = await guiExecutor.currentWorkspace();
    const sid = workspace?.id || login?.current()?.session?.id;
    if (!sid) throw { errno: 'EACCES' };
    return kernel.gui_service_control_rpc(
      true,
      sid,
      JSON.stringify({ op: type === 'gui_greeter_start' ? 'start' : 'stop', unit: 'greeter.service' }),
      guiExecutor.mountSocketOp,
    );
  }
  if (type === 'gui_start') {
    // Only this immutable system image can receive the host's explicit seat grant.
    const name = args.program;
    if (!['compositor', 'gui-sample-doc', 'gui-sample-pixel', 'terminal', 'files', 'mounts'].includes(name)) throw { errno: 'EINVAL' };
    const compositor = name === 'compositor';
    const workspace = await guiExecutor.currentWorkspace();
    // The host can designate a verified modal client for this login's compositor.
    // Its command line is fixed and the compositor also checks SO_PEERCRED.uid.
    const modal = args.securityRole;
    if (modal != null && (name !== 'gui-sample-doc' || !['lock','greeter'].includes(modal))) throw { errno: 'EINVAL' };
    const shell = args.shellPid == null ? null : guiJobs.get(args.shellPid);
    if (args.shellPid != null && (!compositor || !shell?.modal || shell.session !== guiSession())) throw { errno: 'EPERM' };
    const argv = [name, ...(compositor ? (shell ? ['--shell-pid', String(args.shellPid)] : []) : modal ? ['--role', modal] : args.argv ?? [])];
    const session = guiSession();
    if (!session || workspace.id !== login.current().session.id) throw { errno: 'EACCES' };
    const defaultCwd = args.cwd || login.current()?.session?.home || '/';
    return new Promise((resolve, reject) => {
      let pid, stderr = '', resolveDone;
      const done = new Promise(r => { resolveDone = r; });
      guiExecutor.exec([{ path: '/usr/bin/' + name, argv }], {
        workspace, cwd: defaultCwd, stdin: '', sudo: compositor || !!modal, guiSystemImage: (compositor || modal) ? name : undefined,
        ...(compositor ? { serviceGrant: { mountNamespace: 'system', devices: ['display','input'] } } : {}),
        ...(shell ? { beforeStart(_pid, image) {
          // Image admission can yield. Only the job originally nominated may receive the seat role.
          if (guiJobs.get(args.shellPid) !== shell || shell.session !== guiSession()) image.resolvedArgv = [name];
        } } : {}),
        onJob(job) {
          if (pid || !job.pids.length) return;
          pid = job.pids[0]; guiJobs.set(pid, { job, modal, session, compositor, program: name, done }); resolve(pid);
        },
        onOutput(fd, text) { if (fd === 2) stderr = (stderr + text).slice(-2048); },
      }).then(result => {
        guiJobs.delete(pid);
        resolveDone();
        const value = { program: name, pid, status: result.status, stderr, stdout: result.stdout };
        broadcast({ v: VERSION, type: 'event', event: 'gui-exit', value });
        if (!pid) reject({ errno: 'ENOEXEC', detail: stderr || 'GUI process failed to launch' });
      }, error => { guiJobs.delete(pid); resolveDone(); reject(error); });
    });
  }
  if (type === 'gui_stop' || type === 'gui_worker_metrics') {
    const entry = guiJobs.get(args.pid);
    if (!entry || entry.session !== guiSession()) throw { errno: 'ESRCH' };
    if (type === 'gui_stop') { entry.job.signal(9); return; }
    if (!entry.compositor) throw { errno: 'EINVAL' };
    return guiExecutor.guiWorkerMetrics(args.pid, args.start === true);
  }
  if (type === 'gui_viewport') return guiInput({ op: 'viewport', bounds: args.bounds, mode: args.mode });
  if (type === 'gui_host_event') {
    if (['picker_result', 'external_drop', 'upload_progress', 'mount_consent_result'].includes(args.event?.op)) throw { errno: 'EACCES' };
    return guiInput(args.event);
  }
  if (type === 'gui_pixel_canvas') {
    const binding = bindingFor(args.surface_id);
    guiExecutor.transferGuiCanvas(args.surface_id, args.generation, args.canvas, args.backend, args.decoration);
    guiCanvases.set(args.surface_id, binding);
    return;
  }
  if (type === 'gui_revoke_port') return revokePort(args.surface_id);
  if (type === 'gui_surface_port') {
    const id = args.surface_id, port = args.port;
    const binding = JSON.parse(kernel.gui_surface_binding(BigInt(id)));
    if (binding.pixel || !(port instanceof MessagePort) || guiPorts.has(id)) throw { errno: 'EACCES' };
    guiPorts.set(id, port);
    port.onmessage = ({ data }) => {
      if (guiPorts.get(id) !== port) return;
      try {
        const current = JSON.parse(kernel.gui_surface_binding(BigInt(id)));
        if (current.endpoint !== binding.endpoint || current.pid !== binding.pid) return;
        if (data?.type !== 'message' || typeof data.text !== 'string') return;
        if (new TextEncoder().encode(data.text).length > 4096) { port.postMessage({ text: 'E2BIG' }); return; }
        void guiInput({ op: 'document_message', surface_id: id, text: data.text })
          .catch(e => port.postMessage({ text: e.errno || 'EIO' }));
      } catch { /* closed socket or stale seat */ }
    };
    return;
  }
  if (type === 'gui_verify_cloud_upload') {
    const surfaceId = args.surface_id;
    const ownerPid = Number(args.owner_pid ?? 0);
    const dest = String(args.dest ?? '');
    if (surfaceId == null || !Number.isInteger(ownerPid) || ownerPid <= 0 || !dest) return false;
    return Boolean(await kernel.gui_verify_cloud_upload(BigInt(surfaceId), ownerPid, dest));
  }
  if (type === 'gui_upload_progress') {
    const { request_id, surface_id, text, done, error } = args;
    const pick = guiPicks.get(request_id);
    if (!pick || pick.surface !== surface_id || !currentPick(pick)) throw { errno: 'ECANCELED' };
    if (!done) pick.streaming = true;
    await guiInput({
      op: 'upload_progress',
      request_id,
      surface_id,
      text: String(text ?? ''),
      done: Boolean(done),
      ...(error != null ? { error: String(error) } : {}),
    });
    if (done) retirePick(pick, false);
    return;
  }
  if (type === 'gui_external_drop') {
    const { surface_id, files } = args;
    if (!Array.isArray(files) || !files.length) return;
    if (guiPicks.size > 0) throw { errno: 'EBUSY', detail: 'An upload is already in progress' };
    const session = guiSession();
    if (!session) throw { errno: 'EACCES' };
    const binding = bindingFor(surface_id);
    const request_id = nextDropRequestId++;
    const pick = {
      session,
      request: request_id,
      surface: surface_id,
      path: '/run/gui/pick-' + request_id,
      pid: binding.pid,
      endpoint: binding.endpoint,
      createdPaths: new Set(),
      cloudDest: null,
    };
    guiPicks.set(request_id, pick);
    if (!currentPick(pick)) {
      guiPicks.delete(request_id);
      throw { errno: 'ECANCELED' };
    }
    try {
      await guiInput({ op: 'external_drop', surface_id, request_id });
    } catch (err) {
      guiPicks.delete(request_id);
      throw err;
    }
    await streamFilesToPick(pick, files);
    return;
  }
  if (type === 'gui_picker_result') {
    const { request_id, surface_id, file, files } = args, pick = guiPicks.get(request_id);
    if (!pick || pick.surface !== surface_id || pick.copying) throw { errno: 'ECANCELED' };
    const list = Array.isArray(files) ? files : (file != null ? [file] : []);
    if (!list.length) {
      retirePick(pick, true);
      return;
    }
    await streamFilesToPick(pick, list);
    return;
  }
  throw { errno: 'EOPNOTSUPP' };
}

function broadcast(message) {
  for (const port of ports) port.postMessage(message);
}

// execve of a pipeline's stages locally inside this instance's LocalProcessTable.
async function execs(args, seat, host) {
  const stages = (args.stages ?? []).map(stage => ({
    path: stage.path,
    local: stage.local,
    runtime: stage.runtime,
    parentPid: stage.parentPid,
    sessionId: stage.sessionId,
    serviceGrant: stage.serviceGrant,
    guiSystemImage: stage.guiSystemImage,
    ...(stage.remote !== undefined ? { remote: stage.remote } : {}),
    argv: stage.argv ?? [],
    env: stage.env ?? [],
    cwd: stage.cwd ?? '/',
    cgroup: stage.cgroup ?? '',
  }));
  const results = JSON.parse(await kernel.execs(JSON.stringify(stages), !!args.sudo, seat ?? '', host));
  if (Array.isArray(results) && results.some(r => r?.ok?.pid != null && kernel.is_service_image(r.ok.pid, 'kubelet'))) {
    await ensureKubeletHostIfNeeded();
  }
  return results;
}
// execve of one image: a pipeline of one stage.
async function exec(args, seat, host) {
  const [result] = await execs({ stages: [args], sudo: args.sudo }, seat, host);
  if (result.err) throw result.err;
  return result.ok;
}

function failure(error) {
  if (typeof error === 'string') {
    try { return JSON.parse(error); } catch { /* not our envelope */ }
  }
  // Structured cloning an Error keeps its message, but drops errno and detail. The
  // protocol carries a plain record so loader failures survive the worker boundary.
  if (error && typeof error === 'object' && error.errno) {
    return { errno: error.errno, detail: error.detail ?? error.message ?? error.errno,
      ...(error.execCommitted ? { execCommitted: true } : {}) };
  }
  return { errno: 'EIO', detail: String(error?.message ?? error) };
}

async function dispatch(message, host, tab, internal = false) {
  const { type, args = {} } = message;
  if (!internal && ['vfs_open_read', 'vfs_read_stream_chunk', 'vfs_close_read_stream'].includes(type)) {
    const executor = await import(asset('/executor-host.js'));
    const { id } = await executor.currentWorkspace();
    return dispatch({ type, args: { ...args, sessionId: id } }, host, tab, true);
  }
  if (!internal && (type.startsWith('proc_') || type.startsWith('kfd_') ||
      ['sys_mount', 'sys_umount2', 'session_begin', 'session_end', 'set_active_session'].includes(type))) throw { errno: 'EPERM' };
  switch (type) {
    case 'init': return boot();
    case 'version': return kernel.version();
    case 'instance_id': return kernel.instance_id();
    case 'namespace': return kernel.namespace();
    case 'workspace_credentials': return JSON.parse(kernel.workspace_credentials());
    case 'sync_account': {
      const value = JSON.parse(kernel.sync_account(typeof args === 'string' ? args : JSON.stringify(args)));
      await restoreSeatPolicyForAccount();
      return value;
    }
    case 'sync_account_from_server': {
      const value = JSON.parse(await kernel.sync_account_from_server());
      await restoreSeatPolicyForAccount();
      return value;
    }
    case 'machine_init_action': return JSON.parse(await kernel.machine_init_action(JSON.stringify(args.action ?? args), host));
    case 'login_session_action': {
      const action = args.action ?? args;
      const value = JSON.parse(await kernel.login_session_action(JSON.stringify(action), host));
      if (action?.op === 'seat_policy' && typeof value?.uid === 'number' && value?.seat_policy) {
        await writeSeatPolicy(value.uid, value.seat_policy.sharing, value.seat_policy.revision);
      }
      return value;
    }
    case 'boot_status': return JSON.parse(kernel.boot_status());
    case 'boot_cowfs_root': {
      const store = args.store ?? cowfsStore ?? createCowfsStore();
      const raw = await kernel.boot_cowfs_root(
        store,
        args.profile != null ? (typeof args.profile === 'string' ? args.profile : JSON.stringify(args.profile)) : undefined,
        args.opts != null ? (typeof args.opts === 'string' ? args.opts : JSON.stringify(args.opts)) : undefined,
      );
      return JSON.parse(raw);
    }
    case 'close_clean_root': return JSON.parse(await kernel.close_clean_root());
    case 'flush_root': return JSON.parse(await kernel.flush_root());
    case 'flush_pending_cloud_revocations': return JSON.parse(await kernel.flush_pending_cloud_revocations());
    case 'cloud_status': return JSON.parse(kernel.cloud_status());
    case 'cloud_sign_in': {
      const res = JSON.parse(await kernel.cloud_sign_in(
        String(args.cloudUser ?? ''),
        Number(args.cloudUid ?? 0),
        Number(args.cloudGid ?? 0),
        JSON.stringify(args.cloudGroups ?? []),
        args.scope != null ? (typeof args.scope === 'string' ? args.scope : JSON.stringify(args.scope)) : undefined,
      ));
      // Codex Finding #27: drive `cloud-online.target` activation through PID 1 when running.
      if (res?.signed_in) {
        await driveCloudOnlineTarget('start');
      }
      return res;
    }
    case 'cloud_sign_out': {
      // Codex Finding #27: drive `cloud-online.target` teardown through PID 1, then immediately
      // clear local kernel authority & queue/flush remote revocations.
      await driveCloudOnlineTarget('stop');
      return JSON.parse(await kernel.cloud_sign_out());
    }
    case 'revoke_cloud_tokens_only': return JSON.parse(await kernel.revoke_cloud_tokens_only());
    case 'machine_init_status': return currentInitStatus();
    case 'machine_init_leave': {
      localInitAbort = true;
      localInitRunId++;
      // Host loss terminates the PID 1 Worker abruptly (SIGKILL), NEVER triggering
      // clean Poweroff / `umount2("/usr")` teardown of the live OS root.
      localInitJob?.signal(9);
      localInitJob = null;
      const prev = localInitPromise;
      await releaseLocalInitOwner();
      if (prev) await Promise.race([prev.catch(() => {}), new Promise(r => setTimeout(r, 2000))]);
      localInitRunning = false;
      localInitState = 'stopped';
      broadcastInitStatus();
      return null;
    }
    case 'machine_init_resume': {
      localInitAbort = false;
      localInitRunning = false;
      localInitFailures = 0;
      localInitError = '';
      void launchLocalInit();
      return currentInitStatus();
    }
    case 'machine_reboot': {
      // Codex Finding #21: authorize UID 0 + active boot identity BEFORE mutating abort flags,
      // advancing run ID, or signalling PID 1 so rejected requests have ZERO side effects!
      kernel.authorize_machine_reboot(String(args.boot ?? ''));
      localInitAbort = true;
      localInitRunId++;
      // Prefer ordered PID 1 teardown (`SIGTERM`) with short grace before `SIGKILL`.
      if (localInitJob) {
        const job = localInitJob;
        localInitJob = null;
        job.signal(15);
        const prevWait = localInitPromise;
        if (prevWait) {
          await Promise.race([prevWait.catch(() => {}), new Promise(r => setTimeout(r, 1000))]);
        }
        job.signal(9);
      }
      localInitOwner = null;
      const prev = localInitPromise;
      if (prev) await Promise.race([prev.catch(() => {}), new Promise(r => setTimeout(r, 1500))]);
      const value = JSON.parse(await kernel.machine_init_action(
        JSON.stringify({ op: 'reboot', boot: args.boot }),
        kernelId,
      ));
      localInitView = value;
      await resetKubeletHostIfLoaded();
      const executor = await import(asset('/executor-host.js'));
      void executor.reconcile().catch(() => {});
      await login.reset();
      localInitAbort = false;
      localInitRunning = false;
      localInitFailures = 0;
      localInitError = '';
      void launchLocalInit();
      return value;
    }
    case 'machine_inspect': return JSON.parse(await kernel.machine_init_action(JSON.stringify({ op: 'inspect' }), kernelId));
    case 'login_lifecycle': {
      if (!['end', 'restart', 'inspect'].includes(args.op)) throw { errno: 'EINVAL' };
      const value = await login.call({ op: args.op, ...(args.op === 'inspect' ? {} : { session: args.session }) });
      if (args.op !== 'inspect') {
        const executor = await import(asset('/executor-host.js'));
        void executor.reconcile().catch(() => {});
        await executor.endWorkspace(args.session);
        await login.reset();
      }
      return value;
    }
    case 'login_status': {
      if (login.view?.shutdown && !login.view.shutdown.complete) {
        try {
          const fresh = JSON.parse(await kernel.login_session_action(JSON.stringify({ op: 'inspect' }), kernelId));
          if (fresh?.id === login.view.id) login.view = fresh;
        } catch { /* keep cached view */ }
      }
      const value = login.current();
      return { ...value, services: null };
    }
    case 'login_configure': return login.control('configure', { file: args.file }, args.expected);
    case 'login_seat_policy': {
      const value = await login.call({ op: 'seat_policy', session: args.session, expected: args.expected, sharing: args.sharing });
      if (typeof value?.uid === 'number' && value?.seat_policy) {
        await writeSeatPolicy(value.uid, value.seat_policy.sharing, value.seat_policy.revision);
      }
      await login.tick();
      const executor = await import(asset('/executor-host.js'));
      executor.setSharingPolicy(() => login.current());
      return value;
    }
    case 'login_refresh': {
      const hadCompat = Boolean((compatConn && !compatConn.closed) || compatConnecting);
      const prevState = login?.current()?.session ?? null;
      const prevUid = prevState?.uid ?? null;
      const prevSession = guiSession();
      guiActivation = null;
      // Tear down the prior UID's compat connection and `/run/user/<old_uid>/desktop-actions.sock`
      // immediately before switching sessions so surviving processes from the prior UID can never
      // invoke desktop actions under the new account.
      closeCompatConn({ errno: 'ESTALE' });
      await restoreSeatPolicyForAccount();
      const res = await login.reset();
      const postResetSession = guiSession();
      for (const consent of [...guiConsents.values()]) {
        if (consent.session !== postResetSession) {
          retireConsent(consent, true, true);
        }
      }
      const nextState = res?.session ?? login?.current()?.session ?? null;
      const nextUid = nextState?.uid ?? null;
      const uidChanged = prevUid !== null && nextUid !== null && prevUid !== nextUid;
      const sameLiveLogin = !uidChanged
        && postResetSession
        && prevState?.id && nextState?.id === prevState.id
        && prevState?.generation === nextState?.generation;
      if (sameLiveLogin) {
        for (const entry of guiJobs.values()) {
          if (entry.session === prevSession) entry.session = postResetSession;
        }
      }
      if (uidChanged) {
        const stopping = [];
        for (const entry of guiJobs.values()) {
          if (entry.session === prevSession && (entry.program === 'files' || entry.program === 'mounts')) {
            try { entry.job.signal(15); } catch {}
            if (entry.done) stopping.push(entry.done);
          }
        }
        if (stopping.length) {
          await Promise.race([
            Promise.allSettled(stopping),
            new Promise(r => setTimeout(r, 1500)),
          ]);
        }
      }
      if (hadCompat && desktopStarting == null) {
        const rebindSession = guiSession();
        const doRebind = async () => {
          if (!rebindSession || guiSession() !== rebindSession) return;
          await ensureCompatConn();
          if (guiSession() === rebindSession) {
            broadcast({ v: VERSION, type: 'event', event: 'gui-compat-rebind', value: { uidChanged } });
          }
        };
        if (args?.skipCompatRebind) {
          void doRebind().catch(() => {});
        } else {
          await doRebind().catch(() => {});
        }
      }
      return res;
    }
    case 'login_leave': await login.stop(); return null;
    case 'login_service_check': login.capture(args.expected); return null;
    case 'login_service_attach': {
      const ticket = login.capture(args.expected);
      const view = JSON.parse(await kernel.login_attach(args.pid, JSON.stringify(ticket.member), BigInt(ticket.generation), args.launch ? JSON.stringify(args.launch) : undefined, host));
      return login.checked(ticket, view);
    }
    case 'login_service_signal': return login.control('signal', { pid: args.pid, signal: args.signal }, args.expected);
    case 'reserve_memory': kernel.reserve_memory(args.pid, BigInt(args.bytes ?? 0), host); return null;
    case 'getcreds_proc': return JSON.parse(await kernel.getcreds_proc(args.pid, host));
    case 'set_proc_cred': return JSON.parse(await kernel.set_proc_cred(args.pid, args.uid, args.gid ?? args.uid, new Uint32Array(args.groups ?? []), args.remote != null ? JSON.stringify(args.remote) : undefined, host));
    case 'attach_remote_device': return JSON.parse(await kernel.attach_remote_device(args.driver, args.pid ?? undefined, host));
    case 'detach_remote_device': kernel.detach_remote_device(args.driver); return null;
    case 'service_auth_hello': return JSON.parse(await kernel.service_auth_hello(args.versions ? JSON.stringify(args.versions) : undefined));
    case 'service_auth_attach': return JSON.parse(await kernel.service_auth_attach());
    case 'mint_remote_cred': return JSON.parse(await kernel.mint_remote_cred(args.pid, args.scope ? JSON.stringify(args.scope) : undefined, !!args.sudo, host));
    case 'detach_instance': return JSON.parse(await kernel.detach_instance());
    case 'exec':
      if (args.serviceGrant && !internal) throw { errno: 'EPERM' };
      return exec(args, tab, host);
    case 'execs':
      if (!internal && args.stages?.some(stage => stage.serviceGrant)) throw { errno: 'EPERM' };
      return execs(args, tab, host);
    // A process's own execve: its image replaced, its pid, credentials and descriptors kept.
    case 'reexec': {
      const image = JSON.parse(await kernel.reexec(args.pid, JSON.stringify(args.local ?? null), args.path, JSON.stringify(args.argv ?? []), JSON.stringify(args.env ?? []), args.cwd ?? '/', tab ?? '', host));
      if (kernel.is_service_image(args.pid, 'mountd')) {
        const executor = await import(asset('/executor-host.js'));
        await executor.ensureMountHost();
      }
      if (kernel.is_service_image(args.pid, 'kubelet')) {
        await ensureKubeletHostIfNeeded();
      }
      return image;
    }
    case 'fork': return JSON.parse(await kernel.fork(args.pid, host, args.emptyMemory === true));
    case 'session': return JSON.parse(await kernel.session(JSON.stringify(args.pids), host));
    case 'boot_init': return JSON.parse(await kernel.boot_init(JSON.stringify(args.owner), args.token, host));
    case 'process_call': return JSON.parse(await kernel.process_call(args.pid, JSON.stringify(args.call), host));
    case 'exit': return JSON.parse(await kernel.exit(args.pid, args.status ?? 0, args.signal ?? undefined, host));
    case 'wait': return JSON.parse(await kernel.wait(args.pid, host));
    // wait4 of a process for its children (`pid`, or any).
    case 'waitchild': return JSON.parse(await kernel.waitchild(args.ppid, args.pid ?? undefined, host));
    // kill(2): as the page's account, or `from` a process this port runs, as that process.
    case 'kill': return JSON.parse(await kernel.kill(args.pid, args.signal ?? undefined, args.from ?? undefined, host));
    case 'poll': return JSON.parse(await kernel.poll(JSON.stringify(args.pids ?? [])));
    case 'tty_fds': return kernel.terminal(args.pid, args.tty, JSON.stringify(args.fds), host);
    case 'sync': return JSON.parse(await kernel.sync(host, JSON.stringify(args?.acknowledged ?? {})));
    case 'getpid': return JSON.parse(await kernel.getpid(args.pid));
    case 'cgroup_create': return JSON.parse(await kernel.cgroup_create(args.path));
    case 'cgroup_set': return JSON.parse(await kernel.cgroup_set(args.path, args.key, args.value));
    case 'cgroup_attach': return JSON.parse(await kernel.cgroup_attach(args.pid, args.path));
    case 'cgroup_remove': return JSON.parse(await kernel.cgroup_remove(args.path));
    case 'cgroup_stat': return JSON.parse(await kernel.cgroup_stat(args.path));
    case 'cgroup_list': return JSON.parse(await kernel.cgroup_list(args.path ?? '/'));
    case 'cloud_renew': await kernel.cloud_renew(); return null;
    case 'boot_vfs': await resetKubeletHostIfLoaded(); await (await import(asset('/executor-host.js'))).resetMountHost(); await kernel.boot_vfs(args.opts != null ? (typeof args.opts === 'string' ? args.opts : JSON.stringify(args.opts)) : undefined); return null;
    case 'session_begin': return await kernel.session_begin(args.sessionId, args.uid, args.gid ?? args.uid, new Uint32Array(args.groups ?? []));
    case 'set_active_session': kernel.set_active_session(args.sessionId ?? undefined); return null;
    case 'session_end': await kernel.session_end(args.sessionId); return null;
    case 'list_mounts': return await kernel.list_mounts(args.sessionId ?? '');
    case 'vfs_sys': return JSON.parse(await kernel.vfs_sys(args.sessionId ?? '', typeof args.batch === 'string' ? args.batch : JSON.stringify(args.batch), args.fdEpoch));
    case 'vfs_open_read': return await kernel.vfs_open_read(
      args.sessionId ?? '',
      args.path,
      args.rangeStart != null ? BigInt(args.rangeStart) : undefined,
      args.rangeEnd != null ? BigInt(args.rangeEnd) : undefined,
      !!args.headOnly,
      !!args.sudo,
    );
    case 'vfs_read_stream_chunk': return await kernel.vfs_read_stream_chunk(args.sessionId, args.streamId, args.maxBytes ?? undefined);
    case 'vfs_close_read_stream': await kernel.vfs_close_read_stream(args.sessionId, args.streamId); return null;
    case 'vfs_read_file': {
      const sid = args.sessionId ?? '';
      const first = await kernel.vfs_read_file(sid, args.path, 0n, args.headOnly ? 0 : (args.rangeStart != null ? 0 : 4 * 1024 * 1024));
      const totalSize = Number(first.stat?.size ?? 0);
      if (args.rangeStart != null) {
        const start = Number(args.rangeStart);
        if (start >= totalSize && totalSize > 0) return { status: 416, totalSize };
        if (start >= totalSize && totalSize === 0) return { status: 416, totalSize: 0 };
        const end = Math.min(totalSize - 1, args.rangeEnd != null ? Number(args.rangeEnd) : totalSize - 1);
        const contentRange = `bytes ${start}-${end}/${totalSize}`;
        if (args.headOnly) return { status: 206, totalSize, contentRange, bytes: new Uint8Array(0) };
        const want = end - start + 1;
        const out = new Uint8Array(want);
        let pos = 0;
        while (pos < want) {
          const step = Math.min(4 * 1024 * 1024, want - pos);
          const part = await kernel.vfs_read_file(sid, args.path, BigInt(start + pos), step);
          if (!part.bytes?.byteLength) break;
          out.set(part.bytes, pos);
          pos += part.bytes.byteLength;
        }
        return { status: 206, totalSize, contentRange, bytes: pos === want ? out : out.subarray(0, pos) };
      }
      if (args.headOnly) return { status: 200, totalSize, bytes: new Uint8Array(0) };
      if (totalSize <= first.bytes.byteLength) return { status: 200, totalSize, bytes: first.bytes };
      const out = new Uint8Array(totalSize);
      out.set(first.bytes, 0);
      let pos = first.bytes.byteLength;
      while (pos < totalSize) {
        const step = Math.min(4 * 1024 * 1024, totalSize - pos);
        const part = await kernel.vfs_read_file(sid, args.path, BigInt(pos), step);
        if (!part.bytes?.byteLength) break;
        out.set(part.bytes, pos);
        pos += part.bytes.byteLength;
      }
      return { status: 200, totalSize, bytes: pos === totalSize ? out : out.subarray(0, pos) };
    }
    case 'vfs_pwrite_chunk': {
      const r = await kernel.vfs_pwrite_chunk(
        args.sessionId ?? '',
        args.fd,
        BigInt(args.offset ?? 0),
        args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data),
        args.chunkIndex != null ? BigInt(args.chunkIndex) : undefined,
      );
      return typeof r === 'number' ? r : (r?.written ?? 0);
    }
    case 'proc_spawn_init': {
      const opts = typeof args.opts === 'string' ? JSON.parse(args.opts) : args.opts;
      if (!internal && opts.serviceGrant != null) throw { errno: 'EPERM' };
      return await kernel.proc_spawn_init(JSON.stringify(opts));
    }
    case 'proc_authorize_service_grant': return kernel.proc_authorize_service_grant(args.pid);
    case 'proc_apply_service_grant':
      if (!internal) throw { errno: 'EPERM' };
      return await kernel.proc_apply_service_grant(args.pid, args.parentPid, typeof args.grant === 'string' ? args.grant : JSON.stringify(args.grant));
    case 'proc_fork': return kernel.proc_fork(args.parentPid, args.childPid, args.cloneFlags ?? 0);
    case 'proc_exec_preserve': await kernel.proc_exec_preserve(args.pid); return null;
    case 'proc_set_creds': kernel.proc_set_creds(args.pid, args.uid, args.gid, new Uint32Array(args.groups ?? []), args.token ?? undefined, args.cloudAccess !== false); return null;
    case 'proc_set_umask': return kernel.proc_set_umask(args.pid, args.umask);
    case 'proc_close_server_fds': await kernel.proc_close_server_fds(args.pid); return null;
    case 'proc_exit': await kernel.proc_exit(args.pid); return null;
    case 'sys_chdir': await kernel.sys_chdir(args.pid, args.path); return null;
    case 'sys_fchdir': await kernel.sys_fchdir(args.pid, args.kfd); return null;
    case 'sys_chroot': await kernel.sys_chroot(args.pid, args.path); return null;
    case 'sys_getcwd': return await kernel.sys_getcwd(args.pid);
    case 'sys_mount': await kernel.sys_mount(args.pid, args.source ?? undefined, args.target, args.fstype ?? undefined, BigInt(args.flags ?? 0), args.data ?? undefined); return null;
    case 'sys_umount2': await kernel.sys_umount2(args.pid, args.target, args.flags ?? 0); return null;
    case 'sys_statfs': return await kernel.sys_statfs(args.pid, args.dirfd ?? 0x7ffffffe, args.path);
    case 'sys_fstatfs': return await kernel.sys_fstatfs(args.pid, args.kfd);
    case 'sys_unshare': kernel.sys_unshare(args.pid, args.flags ?? 0); return null;
    case 'sys_setns': kernel.sys_setns(args.pid, args.kfd, args.nstype ?? 0); return null;
    case 'proc_openat': return await kernel.proc_openat(args.pid, args.dirfd, args.path, args.oflags ?? 0, args.mode ?? 0, !!args.cloexec);
    case 'proc_statat': return await kernel.proc_statat(args.pid, args.dirfd, args.path, args.follow !== false);
    case 'proc_accessat': await kernel.proc_accessat(args.pid, args.dirfd, args.path, args.amode ?? 0, args.follow !== false); return null;
    case 'proc_mkdirat': await kernel.proc_mkdirat(args.pid, args.dirfd, args.path, args.mode ?? 0o777); return null;
    case 'proc_mknodat': await kernel.proc_mknodat(args.pid, args.dirfd, args.path, args.mode, args.rdev ?? undefined); return null;
    case 'proc_unlinkat': await kernel.proc_unlinkat(args.pid, args.dirfd, args.path, !!args.removedir); return null;
    case 'proc_renameat': await kernel.proc_renameat(args.pid, args.olddirfd, args.oldpath, args.newdirfd, args.newpath, args.flags ?? 0); return null;
    case 'proc_linkat': await kernel.proc_linkat(args.pid, args.olddirfd, args.oldpath, args.newdirfd, args.newpath, !!args.follow); return null;
    case 'proc_symlinkat': await kernel.proc_symlinkat(args.pid, args.target, args.newdirfd, args.linkpath); return null;
    case 'proc_readlinkat': return await kernel.proc_readlinkat(args.pid, args.dirfd, args.path);
    case 'proc_utimensat': {
      const encodeTime = v => (typeof v === 'string' && (v.startsWith('"') || v.startsWith('{'))) ? v : JSON.stringify(v ?? 'now');
      await kernel.proc_utimensat(args.pid, args.dirfd, args.path, encodeTime(args.atime), encodeTime(args.mtime), args.follow !== false);
      return null;
    }
    case 'proc_sys': return JSON.parse(await kernel.proc_sys(args.pid, typeof args.batch === 'string' ? args.batch : JSON.stringify(args.batch)));
    case 'kfd_read': return await kernel.kfd_read(args.pid, args.kfd, args.len);
    case 'kfd_write': return await kernel.kfd_write(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data));
    case 'kfd_pread': return await kernel.kfd_pread(args.pid, args.kfd, args.len, BigInt(args.offset ?? 0));
    case 'kfd_pwrite': return await kernel.kfd_pwrite(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data), BigInt(args.offset ?? 0));
    case 'kfd_seek': return (await kernel.kfd_seek(args.pid, args.kfd, BigInt(args.offset ?? 0), args.whence ?? 0)).toString();
    case 'kfd_readdir': return await kernel.kfd_readdir(args.pid, args.kfd);
    case 'kfd_fstat': return await kernel.kfd_fstat(args.pid, args.kfd);
    case 'kfd_ftruncate': await kernel.kfd_ftruncate(args.pid, args.kfd, BigInt(args.size ?? 0)); return null;
    case 'kfd_futimens': {
      const encodeTime = v => (typeof v === 'string' && (v.startsWith('"') || v.startsWith('{'))) ? v : JSON.stringify(v ?? 'now');
      await kernel.kfd_futimens(args.pid, args.kfd, encodeTime(args.atime), encodeTime(args.mtime));
      return null;
    }
    case 'kfd_fsync': await kernel.kfd_fsync(args.pid, args.kfd, !!args.dataOnly); return null;
    case 'kfd_set_append': kernel.kfd_set_append(args.pid, args.kfd, !!args.append); return null;
    case 'kfd_is_append': return kernel.kfd_is_append(args.pid, args.kfd);
    case 'kfd_lock': await kernel.kfd_lock(args.pid, args.kfd, args.family, args.kind, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined, !!args.wait); return null;
    case 'kfd_cancel': kernel.kfd_cancel(args.pid, args.kfd); return null;
    case 'kfd_unlock': await kernel.kfd_unlock(args.pid, args.kfd, args.family, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined); return null;
    case 'kfd_test_lock': return await kernel.kfd_test_lock(args.pid, args.kfd, args.kind, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined);
    case 'kfd_dup': return kernel.kfd_dup(args.pid, args.kfd);
    case 'kfd_dup2': return await kernel.kfd_dup2(args.pid, args.oldKfd, args.newKfd);
    case 'kfd_set_cloexec': kernel.kfd_set_cloexec(args.pid, args.kfd, !!args.cloexec); return null;
    case 'kfd_is_cloexec': return kernel.kfd_is_cloexec(args.pid, args.kfd);
    case 'kfd_close': await kernel.kfd_close(args.pid, args.kfd); return null;
    case 'pty_register': kernel.pty_register(args.index, args.uid ?? 0, args.gid ?? 0, args.mode ?? 0o600); return null;
    case 'pty_close': return kernel.pty_close(args.index);
    case 'proc_resolve_exec': return await kernel.proc_resolve_exec(args.pid, args.file, typeof args.argv === 'string' ? args.argv : JSON.stringify(args.argv ?? []), args.pathEnv ?? undefined, !!args.searchPath);
    case 'session_resolve_exec': return await kernel.session_resolve_exec(args.sessionId ?? '', args.file, typeof args.argv === 'string' ? args.argv : JSON.stringify(args.argv ?? []), args.cwd ?? '/', args.pathEnv ?? undefined, !!args.searchPath, !!args.sudo);
    case 'release_exec_ticket': kernel.release_exec_ticket(args.ticket); return null;
    case 'take_local_exec_bytes': return kernel.take_local_exec_bytes(args.ticket ?? args.digest, args.checkOnly);
    default: throw { errno: 'ENOSYS', detail: `no client-kernel call ${type}` };
  }
}

const isConcurrentCall = type => (
  type.startsWith('cloud_') ||
  type.startsWith('kfd_') ||
  type.startsWith('proc_') ||
  type.startsWith('sys_') ||
  type.startsWith('vfs_') ||
  type.startsWith('pty_') ||
  type.startsWith('session_') ||
  (type.startsWith('login_') && type !== 'login_service_attach') ||
  type.startsWith('machine_init_') ||
  [
    'boot_vfs', 'boot_status', 'flush_root', 'flush_pending_cloud_revocations',
    'revoke_cloud_tokens_only',
    'set_active_session',
    'list_mounts', 'take_local_exec_bytes', 'release_exec_ticket',
  ].includes(type)
);

async function handle(port, message) {
  if (message?.type === 'hello') {
    const versions = Array.isArray(message.versions) ? message.versions : [];
    const boundary = message.boundary ?? 'host-adapter';
    if (boundary !== 'host-adapter' || !versions.includes(VERSION)) {
      const err = { errno: 'EPROTONOSUPPORT', detail: `HostAdapter v${VERSION} required` };
      port.postMessage({ v: VERSION, id: message.id, err });
      port.postMessage({ v: VERSION, type: 'event', event: 'protocol-mismatch', value: { boundary: 'host-adapter', ...err } });
      return;
    }
    port.postMessage({ v: VERSION, id: message.id, ok: { boundary: 'host-adapter', version: VERSION } });
    return;
  }
  if (message?.v !== VERSION) {
    const err = { errno: 'EPROTONOSUPPORT', detail: `HostAdapter v${VERSION} required (received v${message?.v})` };
    port.postMessage({ v: VERSION, id: message?.id, err });
    port.postMessage({ v: VERSION, type: 'event', event: 'protocol-mismatch', value: { boundary: 'host-adapter', ...err } });
    return;
  }
  ports.add(port);
  // A port's authority is an identity of its own, not the tab it names: another port that says
  // the same tab is still another host. The tab it first said it was cannot change.
  if (!hosts.has(port)) hosts.set(port, {
    id: `port-${self.crypto?.randomUUID?.() ?? Math.random()}`,
    tab: message.tab,
  });
  const host = hosts.get(port);
  if (message.tab != null) {
    if (host.tab == null) host.tab = message.tab;
    else if (message.tab !== host.tab) {
      port.postMessage({ v: VERSION, id: message.id, err: { errno: 'EPERM', detail: 'a port speaks for the tab it first said it was' } });
      return;
    }
  }
  try {
    self.kernel = kernel;
    self.kernelRequest = async (type, args) => {
      const run = () => dispatch({ type, args }, host.id, host.tab, true);
      return await (isConcurrentCall(type) ? run() : serially(run)).catch(error => {
        const refused = failure(error);
        throw Object.assign(new Error(refused.detail ?? refused.errno), refused);
      });
    };
    try { await boot(); self.kernel = kernel; } catch (error) {
      if (message.type === 'mount_overlay') {
        port.postMessage({ v: VERSION, id: message.id, ok: null }); return;
      }
      throw error;
    }
    let value;
    if (message.type.startsWith('gui_')) value = await guiRequest(message.type, message.args ?? {});
    else if (message.type === 'run' || message.type === 'unix_rpc' || message.type.startsWith('source_') || message.type.startsWith('mount_') || message.type.startsWith('run_') || message.type.startsWith('console_') || message.type.startsWith('attachment_') || message.type.startsWith('seat_') || ['deliver_signal', 'reconcile'].includes(message.type)) {
      const executor = await import(asset('/executor-host.js'));
      if (message.type === 'console_grant') await login.tick();
      executor.setSharingPolicy(() => login.current());
      value = await executor.request(message.type, message.args ?? {}, value => port.postMessage({ v: VERSION, type: 'event', event: message.type.startsWith('attachment_') ? 'attachment' : 'run', value }), value => broadcast({ v: VERSION, type: 'event', event: 'seat', value }));
    } else if (isConcurrentCall(message.type)) value = await dispatch(message, host.id, host.tab);
    else value = await serially(() => dispatch(message, host.id, host.tab));
    port.postMessage({ v: VERSION, id: message.id, ok: value });
  } catch (error) {
    port.postMessage({ v: VERSION, id: message.id, err: failure(error) });
  }
}

// Exactly one host owns this dedicated Worker instance.
self.onmessage = ({ data }) => handle(self, data);
// Renew local login session leases (zero network RPCs) and remote ServiceAuth v2 / CloudFs leases
// only when explicitly signed in to Cloud.
setInterval(() => {
  if (login) void login.tick().catch(() => {});
}, 5000);
setInterval(() => { if (kernel) void kernel.cloud_renew().catch(() => {}); }, 30000);
