import { verifyRelease, resolveOfflineInstalledRelease } from './release.js';
import { attachConsole, dimensions } from './kernel/page.js';
import { createBootProfileStore } from './kernel/boot-profile.js';
import { createCowfsStore } from './kernel/cowfs-store.js';
import { createImagePager } from './kernel/image-pager.js';
import { createOfflineInstaller, registerOfflineServiceWorker } from './kernel/offline-installer.js';

const IS_WORKER = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(digest));
}

// =============================================================================
// Dedicated Worker entrypoint: hosts real OPFS FileSystemSyncAccessHandle +
// strict IndexedDB + Web Locks (`os-vol:<uuid>`) + compiled `OfflineBootRuntime`
// with ZERO outbound network requests.
// =============================================================================
if (IS_WORKER) {
  let runtime = null;
  let store = null;
  let pager = null;

  async function loadVerifiedWasmBindgen(jsBytes, wasmBytes, expectedWasmSha256) {
    const actualSha = await sha256Hex(wasmBytes);
    if (expectedWasmSha256 && actualSha !== expectedWasmSha256) {
      throw new Error(`client_kernel_bg.wasm SHA-256 mismatch (got ${actualSha}, expected ${expectedWasmSha256})`);
    }
    const jsText = new TextDecoder('utf-8', { fatal: true }).decode(jsBytes);
    const moduleSrc = `${jsText}\nexport default (typeof wasm_bindgen !== 'undefined' ? wasm_bindgen : globalThis.wasm_bindgen);\n`;
    const blobUrl = URL.createObjectURL(new Blob([moduleSrc], { type: 'text/javascript' }));
    let wasmBindgen;
    try {
      const mod = await import(/* @vite-ignore */ blobUrl);
      wasmBindgen = mod.default;
    } finally {
      URL.revokeObjectURL(blobUrl);
    }
    if (typeof wasmBindgen !== 'function') {
      throw new Error('Verified client_kernel.js did not export wasm_bindgen initializer.');
    }
    await wasmBindgen({ module_or_path: wasmBytes });
    return wasmBindgen;
  }

  self.onmessage = async ({ data }) => {
    const { id, cmd, args = {} } = data;
    try {
      let result;
      switch (cmd) {
        case 'boot': {
          pager = createImagePager({
            fetch: async () => {
              throw Object.assign(new Error('Offline standalone boot forbids network fetches.'), { errno: 'ENOTCONN' });
            },
          });
          self.imageBlobRead = pager.imageBlobRead;
          store = createCowfsStore({ dbName: args.cowfsDbName ?? 'os-cowfs-v1' });
          const wasmBindgen = await loadVerifiedWasmBindgen(
            args.clientKernelJsBytes,
            args.clientKernelWasmBytes,
            args.expectedWasmSha256,
          );
          runtime = await wasmBindgen.OfflineBootRuntime.boot(
            store,
            JSON.stringify(args.bootProfile),
            args.initramfsJson,
            args.rootTemplateJson,
            args.baseJson,
            args.extensionsJson ?? [],
          );
          result = {
            status: runtime.status(),
            pagerStats: pager.stats(),
          };
          break;
        }
        case 'status':
          result = runtime.status();
          break;
        case 'exec':
          result = await runtime.exec_command(args.line ?? '');
          break;
        case 'read_file':
          result = [...(await runtime.read_file(args.path))];
          break;
        case 'write_file':
          result = await runtime.write_file(
            args.path,
            new Uint8Array(args.bytes),
            args.mode ?? 0o644,
          );
          break;
        case 'mkdir':
          await runtime.mkdir(args.path, args.mode ?? 0o755);
          result = true;
          break;
        case 'unlink':
          await runtime.unlink(args.path);
          result = true;
          break;
        case 'stat':
          result = await runtime.stat(args.path, args.follow ?? true);
          break;
        case 'statfs':
          result = await runtime.statfs(args.path);
          break;
        case 'readdir':
          result = await runtime.readdir(args.path);
          break;
        case 'sync_fs':
          result = await runtime.sync_fs();
          break;
        case 'snapshot':
          result = await runtime.snapshot(args.name);
          break;
        case 'run_cowfsck':
          result = await runtime.run_cowfsck(args.volumeUuid ?? null);
          break;
        case 'rollback_snapshot':
          result = await runtime.rollback_snapshot(args.snapshotName);
          break;
        case 'fork_from_recovery':
          result = await runtime.fork_from_recovery();
          break;
        case 'switch_root_attempt':
          await runtime.switch_root_attempt(args.callerPid, args.newroot, args.initPath);
          result = true;
          break;
        case 'list_volumes':
          result = await store.listVolumes({ probeLocks: args.probeLocks ?? true });
          break;
        case 'close_clean_with_prune':
          result = runtime ? await runtime.close_clean_with_prune() : null;
          break;
        default:
          throw new Error(`Unknown standalone worker command: ${cmd}`);
      }
      self.postMessage({ id, ok: true, result });
    } catch (err) {
      self.postMessage({
        id,
        ok: false,
        errno: err?.errno ?? null,
        message: err?.message ?? String(err),
      });
    }
  };
}

// =============================================================================
// Window entrypoint: preserves exact attached-terminal behavior when opened
// from a parent terminal (`window.opener`) or when no offline Release v2 is
// installed; otherwise boots Stage 0 -> Stage 1 -> os-cowfs -> switch_root ->
// Stage 2 standalone offline console with ZERO outbound network requests.
// =============================================================================

function runAttachedConsole(owner) {
  const nonce = crypto.randomUUID();
  let listener, peer, activeInput, connected = false, ended = false, access = 'view', state = 'running';
  let status = owner ? 'Connecting to the selected command…' : 'Open this window from a running terminal.';
  const emit = value => listener?.(value);
  const notify = () => emit({ type: 'status', text: status, live: connected && !ended, input: !!activeInput && !ended });
  const left = () => { try { owner?.postMessage({ type: 'os-console-left', nonce }, location.origin); } catch { /* owner gone */ } };
  const close = message => {
    if (ended) return;
    ended = true; connected = false; activeInput = null; status = message; clearTimeout(timeout); notify(); left();
  };
  const describe = () => { if (ended) return; status = state === 'stopped' ? 'Command stopped' : access === 'view' ? 'View only · live output' : activeInput ? 'Keyboard connected' : 'Waiting for foreground input'; notify(); };
  const fit = () => {
    if (!activeInput || ended) return;
    const viewport = document.querySelector('.console-window .transcript');
    if (viewport) void activeInput.resize(dimensions(viewport)).catch(() => {});
  };
  const timeout = owner ? setTimeout(() => close('The connection timed out. Open a new window from the original terminal.'), 30_000) : null;
  window.addEventListener('message', async event => {
    if (ended || connected || !listener || event.origin !== location.origin || event.source !== owner || event.data?.nonce !== nonce) return;
    if (event.data.type === 'os-console-error') { close('The selected command is no longer available.'); return; }
    if (event.data.type !== 'os-console-port' || event.ports.length !== 1) return;
    connected = true; clearTimeout(timeout);
    try {
      peer = await attachConsole(event.ports[0], {
        onOutput: (fd, text) => emit({ type: 'output', text }),
        onMode: mode => emit({ type: 'mode', echo: mode.echo }),
        onSize: size => emit({ type: 'size', columns: size.columns, rows: size.rows }),
        onState: value => { state = value; if (peer) describe(); },
        onTty: input => { activeInput = input; if (peer) { describe(); requestAnimationFrame(fit); } },
        onClose: error => close(error.errno === 'EPIPE' ? 'Command ended' : error.errno === 'ECANCELED' ? 'Sharing ended' : error.errno === 'EOVERFLOW' ? 'Disconnected: output arrived too quickly.' : 'Connection lost. The original window may have closed.'),
      });
      if (ended) { await peer.detach(); return; }
      access = peer.access; describe(); requestAnimationFrame(fit);
    } catch { close('The connection could not be established. Open a new window to try again.'); }
  });
  let writing = Promise.resolve(), queued = 0;
  window.osConsole = {
    listen(callback) {
      listener = callback; notify();
      if (owner) owner.postMessage({ type: 'os-console-ready', nonce }, location.origin);
      const viewport = document.querySelector('.console-window .transcript');
      if (viewport) new ResizeObserver(fit).observe(viewport);
    },
    send(operation, text) {
      if (!activeInput || ended) return;
      const input = activeInput;
      if (queued + text.length > 65536) { status = 'Input is too large; paste a smaller amount.'; notify(); return; }
      queued += text.length;
      writing = writing.then(async () => {
        if (input !== activeInput || ended) return;
        for (let at = 0; at < text.length;) {
          if (input !== activeInput || ended) return;
          let end = Math.min(at + 4096, text.length);
          if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1]) && /[\uDC00-\uDFFF]/.test(text[end])) end--;
          await input[operation === 'reply' ? 'reply' : 'write'](text.slice(at, end)); at = end;
        }
      }).catch(() => { if (!ended) { status = 'Input is unavailable; use the original window to restore control.'; notify(); } })
        .finally(() => { queued -= text.length; });
    },
    detach() { void peer?.detach().catch(() => {}); close('Disconnected. The command remains in the original window.'); },
  };
  window.addEventListener('pagehide', () => { void peer?.detach().catch(() => {}); left(); });
  verifyRelease()
    .then(() => import('./pkg/frontend.js'))
    .then(mod => mod.default())
    .catch(() => {
      document.getElementById('app').textContent = 'The terminal could not load. Close this window and try again.';
      left();
    });
}

function createWorkerRpc() {
  const worker = new Worker(import.meta.url, { type: 'module' });
  const pending = new Map();
  let nextId = 1;
  worker.onmessage = ({ data }) => {
    const waiter = pending.get(data.id);
    if (!waiter) return;
    pending.delete(data.id);
    if (data.ok) {
      waiter.resolve(data.result);
    } else {
      waiter.reject(Object.assign(new Error(data.message || 'Worker error'), { errno: data.errno }));
    }
  };
  worker.onerror = err => {
    for (const waiter of pending.values()) {
      waiter.reject(new Error(err.message || 'Standalone boot worker crashed'));
    }
    pending.clear();
  };
  function call(cmd, args = {}, transfer = []) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, cmd, args }, transfer);
    });
  }
  return { worker, call };
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'className') node.className = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, String(v));
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

async function runStandaloneOfflineBoot(params) {
  document.title = 'Standalone Console · OS';
  const app = document.getElementById('app');
  app.removeAttribute('data-attached-console');
  app.setAttribute('data-standalone-console', '1');

  const profileStore = createBootProfileStore();
  const installer = createOfflineInstaller();
  const cowfsDbName = params.get('cowfs_db') || 'os-cowfs-v1';
  const rpc = createWorkerRpc();
  let currentStatus = null;
  let bootMeta = null;
  let closed = false;

  const transcriptLines = [];

  function render() {
    app.replaceChildren();
    const container = el('div', { className: 'standalone-boot' });
    const stage = currentStatus?.stage ?? 'stage0';
    const rootInfo = currentStatus?.mounted_root ?? null;
    const recovery = currentStatus?.recovery ?? null;

    const badges = el('div', { className: 'standalone-badges' },
      el('span', { className: `standalone-badge${stage === 'stage1_recovery' ? ' recovery' : ''}`, 'data-boot-stage': stage }, `Stage: ${stage}`),
    );
    if (bootMeta?.releaseId) {
      badges.append(el('span', { className: 'standalone-badge', 'data-release-id': bootMeta.releaseId }, `Release: ${bootMeta.releaseId.slice(0, 12)}`));
    }
    if (rootInfo) {
      badges.append(el('span', { className: 'standalone-badge', 'data-volume-uuid': rootInfo.volume_uuid }, `Root: ${rootInfo.volume_uuid.slice(0, 12)}`));
      if (rootInfo.forked_from) {
        badges.append(el('span', { className: 'standalone-badge fork', 'data-forked-from': rootInfo.forked_from }, `Fork of ${rootInfo.forked_from.slice(0, 12)}`));
      }
    }

    const actions = el('div', { className: 'standalone-actions' });
    if (stage === 'stage2' && !closed) {
      actions.append(el('button', {
        className: 'standalone-btn',
        type: 'button',
        'data-action': 'shutdown',
        onClick: async () => {
          const outcome = await api.closeClean();
          transcriptLines.push(`[shutdown] ${JSON.stringify(outcome)}`);
          render();
        },
      }, 'Clean Shutdown'));
    }

    container.append(el('div', { className: 'standalone-header' }, badges, actions));

    if (currentStatus?.banners?.length) {
      for (const msg of currentStatus.banners) {
        container.append(el('div', { className: 'standalone-banner', 'data-fork-banner': '1' }, msg));
      }
    }

    if (stage === 'stage1_recovery' && recovery) {
      const recBox = el('div', { className: 'standalone-recovery', 'data-recovery-chooser': '1', 'data-recovery-kind': recovery.reason?.kind ?? 'unknown' },
        el('strong', {}, 'Stage 1 Recovery Chooser'),
        el('div', { 'data-recovery-message': '1' }, recovery.message),
      );
      const recActions = el('div', { className: 'standalone-actions' });
      if (recovery.reason?.kind === 'volume_busy') {
        recActions.append(el('button', {
          className: 'standalone-btn',
          type: 'button',
          'data-recovery-fork': '1',
          onClick: async () => {
            currentStatus = await api.forkFromRecovery();
            transcriptLines.push(`[recovery] Forked & booted into ${currentStatus.mounted_root?.volume_uuid}`);
            render();
          },
        }, 'Fork & Boot (Copy-on-Write)'));
      }
      if (Array.isArray(recovery.available_snapshots) && recovery.available_snapshots.length > 0) {
        for (const snap of recovery.available_snapshots) {
          recActions.append(el('button', {
            className: 'standalone-btn',
            type: 'button',
            'data-rollback-snapshot': snap,
            onClick: async () => {
              currentStatus = await api.rollbackSnapshot(snap);
              transcriptLines.push(`[recovery] Rolled back to snapshot "${snap}" -> ${currentStatus.mounted_root?.volume_uuid}`);
              render();
            },
          }, `Rollback to snapshot "${snap}"`));
        }
      }
      recActions.append(el('button', {
        className: 'standalone-btn',
        type: 'button',
        'data-recovery-reload': '1',
        onClick: () => location.reload(),
      }, 'Retry Boot'));
      recBox.append(recActions);
      container.append(recBox);
    }

    const output = el('pre', { className: 'standalone-output', 'data-console-output': '1' }, transcriptLines.join('\n'));
    container.append(output);

    if (stage === 'stage2' && !closed) {
      const input = el('input', {
        className: 'standalone-input',
        type: 'text',
        placeholder: 'Type offline command (uname, mount, ls /, cat /etc/sudoers, cowfsck, sync, help)…',
        'data-console-input': '1',
      });
      const form = el('form', {
        className: 'standalone-form',
        onSubmit: async ev => {
          ev.preventDefault();
          const line = input.value.trim();
          if (!line) return;
          input.value = '';
          transcriptLines.push(`$ ${line}`);
          try {
            const res = await api.exec(line);
            if (res.output) transcriptLines.push(res.output.trimEnd());
          } catch (err) {
            transcriptLines.push(`error: ${err.message}`);
          }
          render();
          document.querySelector('[data-console-input]')?.focus();
        },
      }, input, el('button', { className: 'standalone-btn', type: 'submit' }, 'Run'));
      container.append(form);
    }

    app.append(container);
    output.scrollTop = output.scrollHeight;
  }

  async function bootSequence() {
    transcriptLines.push('[stage0] Loading local BootProfile (os-boot-profile-v1)...');
    render();

    const bootProfile = await profileStore.load();
    const overrideRecovery = params.get('recovery') === '1';
    if (overrideRecovery) bootProfile.recovery = true;

    transcriptLines.push('[stage0] Verifying installed Release v2 offline (zero network)...');
    render();
    const boot = await installer.resolveInstalledForBoot({
      generation: bootProfile.generation,
      verifyAllBlobs: true,
      verifyCache: true,
    });
    bootMeta = { releaseId: boot.releaseId, rolledBack: Boolean(boot.rolledBack) };

    const wasmPath = boot.release.loader.client_kernel_wasm;
    const expectedWasmSha = boot.release.loader.client_kernel_sha256;
    const [clientKernelJsBytes, clientKernelWasmBytes] = await Promise.all([
      installer.readVerifiedBootAsset(boot, '/client_kernel.js'),
      installer.readVerifiedBootAsset(boot, wasmPath),
    ]);

    const actualWasmSha = await sha256Hex(clientKernelWasmBytes);
    if (actualWasmSha !== expectedWasmSha) {
      throw new Error(`Stage 0 loader verification failed: client_kernel_bg.wasm digest mismatch.`);
    }

    const initramfsJson = JSON.stringify(boot.images.initramfs);
    const rootTemplateJson = JSON.stringify(boot.images.root_template);
    const baseJson = JSON.stringify(boot.images.base);
    const extensionsJson = [
      ...(boot.images.sysext ?? []),
      ...(boot.images.confext ?? []),
    ].map(img => JSON.stringify(img));

    transcriptLines.push('[stage1] Booting Stage 1 initramfs -> cowfsck -> os-cowfs -> switch_root...');
    render();

    const jsCopy = new Uint8Array(clientKernelJsBytes);
    const wasmCopy = new Uint8Array(clientKernelWasmBytes);
    const bootRes = await rpc.call(
      'boot',
      {
        cowfsDbName,
        bootProfile,
        initramfsJson,
        rootTemplateJson,
        baseJson,
        extensionsJson,
        clientKernelJsBytes: jsCopy,
        clientKernelWasmBytes: wasmCopy,
        expectedWasmSha256: expectedWasmSha,
      },
      [jsCopy.buffer, wasmCopy.buffer],
    );

    currentStatus = bootRes.status;

    // Persist first-boot minted volume UUID into local `os-boot-profile-v1` IDB store.
    if (
      currentStatus.mounted_root?.first_boot_seeded
      && bootProfile.root?.cow_fs
      && !bootProfile.root.cow_fs.volume_uuid
    ) {
      await profileStore.setVolumeUuid(currentStatus.mounted_root.volume_uuid);
    }

    // Mark installed Release v2 generation healthy once Stage 2 reaches ready state.
    if (currentStatus.stage === 'stage2' && !boot.pinnedGeneration) {
      await installer.markBootHealthy(boot.releaseId).catch(() => {});
    }

    if (currentStatus.stage === 'stage2') {
      transcriptLines.push(
        `[stage2] Ready on os-cowfs volume ${currentStatus.mounted_root.volume_uuid} (PID 1 = ${currentStatus.pid1.path}, started=${currentStatus.pid1.started})`,
      );
    } else if (currentStatus.stage === 'stage1_recovery') {
      transcriptLines.push(`[stage1] Paused in Stage 1 Recovery: ${currentStatus.recovery?.message}`);
    }
    render();

    const summary = {
      status: currentStatus,
      releaseId: boot.releaseId,
      rolledBack: Boolean(boot.rolledBack),
      bootProfile: await profileStore.load(),
      pagerStats: bootRes.pagerStats,
    };
    window.__osStandaloneBoot = summary;
    return summary;
  }

  const api = {
    bootProfileStore: profileStore,
    installer,
    registerOfflineServiceWorker,
    status: () => rpc.call('status'),
    exec: line => rpc.call('exec', { line }),
    readFile: async path => new Uint8Array(await rpc.call('read_file', { path })),
    readText: async path => new TextDecoder('utf-8').decode(new Uint8Array(await rpc.call('read_file', { path }))),
    writeFile: (path, bytes, mode = 0o644) => {
      const data = typeof bytes === 'string' ? [...new TextEncoder().encode(bytes)] : [...bytes];
      return rpc.call('write_file', { path, bytes: data, mode });
    },
    mkdir: (path, mode = 0o755) => rpc.call('mkdir', { path, mode }),
    unlink: path => rpc.call('unlink', { path }),
    stat: (path, follow = true) => rpc.call('stat', { path, follow }),
    statfs: path => rpc.call('statfs', { path }),
    readdir: path => rpc.call('readdir', { path }),
    syncFs: () => rpc.call('sync_fs'),
    snapshot: name => rpc.call('snapshot', { name }),
    runCowfsck: (volumeUuid = null) => rpc.call('run_cowfsck', { volumeUuid }),
    rollbackSnapshot: async snapshotName => {
      currentStatus = await rpc.call('rollback_snapshot', { snapshotName });
      if (currentStatus.mounted_root?.volume_uuid) {
        await profileStore.setVolumeUuid(currentStatus.mounted_root.volume_uuid);
      }
      render();
      return currentStatus;
    },
    forkFromRecovery: async () => {
      currentStatus = await rpc.call('fork_from_recovery');
      render();
      return currentStatus;
    },
    switchRootAttempt: (callerPid, newroot, initPath) =>
      rpc.call('switch_root_attempt', { callerPid, newroot, initPath }),
    listVolumes: (probeLocks = true) => rpc.call('list_volumes', { probeLocks }),
    closeClean: async () => {
      if (closed) return null;
      closed = true;
      const outcome = await rpc.call('close_clean_with_prune');
      rpc.worker.terminate();
      return outcome;
    },
  };

  window.addEventListener('pagehide', () => {
    if (!closed) {
      void rpc.call('close_clean_with_prune').catch(() => {});
    }
  });

  window.osStandaloneConsole = api;
  api.ready = bootSequence().catch(err => {
    transcriptLines.push(`[boot-error] ${err?.message ?? String(err)}`);
    currentStatus = {
      stage: 'stage1_recovery',
      recovery: {
        reason: { kind: 'boot_error' },
        message: err?.message ?? String(err),
        available_snapshots: [],
      },
      banners: [],
    };
    render();
    const failed = { error: err?.message ?? String(err), status: currentStatus };
    window.__osStandaloneBoot = failed;
    return failed;
  });
}

if (!IS_WORKER) {
  const owner = window.opener;
  const params = new URLSearchParams(location.search);
  if (owner) {
    runAttachedConsole(owner);
  } else if (params.get('standalone') === '1') {
    void runStandaloneOfflineBoot(params);
  } else {
    resolveOfflineInstalledRelease()
      .then(installed => {
        if (installed) {
          void runStandaloneOfflineBoot(params);
        } else {
          runAttachedConsole(null);
        }
      })
      .catch(() => runAttachedConsole(null));
  }
}
