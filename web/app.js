import { verifyRelease, refreshOnlineTrustRoot } from './release.js';
import { installSelectMenus } from './select-menu.js';
import { inspectFaststart } from './faststart.mjs';
import { uploadFile, Cancelled } from './upload.mjs';
import { exec, closeConsole, grantConsole, revokeConsole, attachConsole, loginSession, configureSeatSharing, configureLoginServices, startLoginServices, signalLoginServices, endLoginSession, restartLoginSession, rebootMachine, machineInit, seatStatus, setSeatActive, bootStatus, closeCleanRoot, cloudStatus, cloudSignInKernel, cloudSignOutKernel, revokeCloudTokensOnly } from './kernel/page.js';
import { kernelCall, kernelPort } from './kernel/protocol.js';
import { installConsoleSharing } from './console-sharing.js';
import { executionSupport } from './kernel/capabilities.js';
import { installLocalFiles } from './local-files.js';
import { shareMount, attachShared, sharedMounts, revokeMount, mountTransports, sharingDialog, mountLocal, localMountList, unmountLocal, activatePrivate, localMounts } from './mount-api.js';
import { installDesktopCompatBridge } from './gui/compat-bridge.js';

installLocalFiles();

const changed = (reason = null) => window.dispatchEvent(new CustomEvent('os:changed', { detail: reason }));

const desktopBridge = installDesktopCompatBridge({
  onSessionEnded: () => { void identityChanged('ended'); },
  onChanged: () => changed(),
});

const DEFAULT_CONFIG = {
  branding: {
    name: 'OS',
    subtitle: '',
    heading: 'Your OS, in the browser.',
    description: 'A browser OS with processes, a filesystem, local accounts, and applications.',
  },
  games: {},
};
let configuration = DEFAULT_CONFIG;

function resolveRegisteredGameUrl(entry) {
  if (typeof entry !== 'string' || !entry) return null;
  const games = configuration?.games;
  if (!games || !Object.hasOwn(games, entry)) return null;
  const url = games[entry];
  if (typeof url !== 'string' || !/^\/content\/[a-zA-Z0-9._/-]+\.html$/.test(url) || url.split('/').includes('..')) {
    return null;
  }
  return url;
}
desktopBridge.setGameResolver(resolveRegisteredGameUrl);

export const ready = verifyRelease()
  .catch(() => {})
  .then(() => fetch('/os-config.json').then(r => (r.ok ? r.json() : DEFAULT_CONFIG)).catch(() => DEFAULT_CONFIG))
  .then(loaded => {
    configuration = loaded && loaded.branding ? loaded : DEFAULT_CONFIG;
    document.title = configuration.branding.name + configuration.branding.subtitle;
    const desc = document.querySelector('meta[name="description"]');
    if (desc) desc.content = configuration.branding.description;
    // Ratchet online publisher trust asynchronously AFTER boot (Stage 0 stays 0-network).
    void refreshOnlineTrustRoot().catch(() => {});
  });

const $ = id => document.getElementById(id);

async function api(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    let error;
    try { error = (await response.json()).error; } catch {}
    const failure = new Error(error || `Request failed (${response.status})`);
    failure.status = response.status;
    throw failure;
  }
  return response;
}

// Explicit Cloud / Cluster Sign-In (`#57` L3d): authenticates against `/api/cloud-auth/login`,
// mints scoped `ServiceAuth v2` credentials, mounts optional `/mnt/cloud` and remote devices,
// and connects `/api/events` WebSocket via `mediaBroker`. NEVER mutates local `/etc/passwd`!
let cloudSignedIn = false;
let pendingCloudLogout = false;

async function flushPendingCloudSignOut() {
  let revStatus = null;
  try {
    revStatus = await kernelCall('flush_pending_cloud_revocations');
  } catch { /* retry later when online */ }
  if (pendingCloudLogout) {
    try {
      const res = await fetch('/api/cloud-auth/logout', { method: 'POST' });
      if (res.ok) pendingCloudLogout = false;
    } catch { /* stay pending until acknowledged */ }
  }
  return {
    ...(revStatus ?? {}),
    remote_signed_out: !pendingCloudLogout && Boolean(revStatus?.remote_revoked ?? true),
    pending_logout: pendingCloudLogout,
  };
}

window.addEventListener('online', () => {
  if (pendingCloudLogout) void flushPendingCloudSignOut();
});

async function cloudSignIn(username, password, scope) {
  if (pendingCloudLogout) {
    await flushPendingCloudSignOut().catch(() => {});
  }
  const response = await api('/api/cloud-auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const payload = await response.json();
  if (typeof payload?.uid !== 'number' || !Number.isInteger(payload.uid) || payload.uid < 0) {
    throw new Error('Cloud login response omitted authenticated numeric uid.');
  }
  const status = await cloudSignInKernel({
    cloudUser: payload.username ?? payload.user ?? username,
    cloudUid: payload.uid,
    cloudGid: typeof payload.gid === 'number' && Number.isInteger(payload.gid) ? payload.gid : payload.uid,
    cloudGroups: Array.isArray(payload.groups) ? payload.groups : [],
    scope: scope ?? { cloud_fs: true, devices: ['archive', 'media', 'present', 'snd'], containers: true, relay: false },
  });
  pendingCloudLogout = false;
  cloudSignedIn = !!status?.signed_in;
  desktopBridge.mediaBroker.setCloudSignedIn(cloudSignedIn);
  window.dispatchEvent(new CustomEvent('os:cloud-changed', { detail: status }));
  changed();
  return status;
}

async function cloudSignOut() {
  cloudSignedIn = false;
  desktopBridge.mediaBroker.setCloudSignedIn(false);
  const status = await cloudSignOutKernel();
  pendingCloudLogout = true;
  try {
    const res = await fetch('/api/cloud-auth/logout', { method: 'POST' });
    if (res.ok) pendingCloudLogout = false;
  } catch { /* remain pending until retried online */ }
  const combined = {
    ...status,
    remote_signed_out: !pendingCloudLogout && Boolean(status?.remote_revoked ?? true),
    pending_logout: pendingCloudLogout,
  };
  window.dispatchEvent(new CustomEvent('os:cloud-changed', { detail: combined }));
  changed();
  return combined;
}

export function started() {
  window.dispatchEvent(new Event('os:desktop-ready'));
  installSelectMenus();
  installConsoleSharing();
  const support = executionSupport();
  if (!support.supported) {
    const notice = document.createElement('aside'); notice.className = 'execution-notice';
    notice.setAttribute('role', 'status'); notice.textContent = support.reason;
    document.querySelector('.topbar')?.after(notice);
  }
  void loginSession().catch(() => {});
  void machineInit().catch(() => {});
  void seatStatus().catch(() => {});
}

const windows = 'BroadcastChannel' in window ? new BroadcastChannel('os-session') : null;
if (windows) windows.onmessage = () => void identityChanged('window');
async function identityChanged(reason = null) {
  window.dispatchEvent(new Event('os:login-changed'));
  desktopBridge.mediaBroker.reconnectIfCloudSignedIn();
  if (!reason) windows?.postMessage('changed');
  // A private preview must not survive switching to a less privileged account.
  await desktopBridge.closePreview();
  changed(reason);
}

let uploading = null;
async function uploadFiles(files, path, progress) {
  if (!files.length) return [];
  if (uploading) throw new Error('An upload is already going on in this page; wait for it, or cancel it');
  const controller = uploading = new AbortController();
  const results = [];
  try {
    const rust = window.osUploads;
    for (const file of files) {
      if (controller.signal.aborted) { results.push(`✕ ${file.name}: Upload cancelled`); continue; }
      try {
        if (file.size > rust.maxFile) throw new Error(`Exceeds the ${rust.maxFile / 1e9} GB limit`);
        let warning = null;
        if (/\.(mp4|m4v|mov|m4a)$/i.test(file.name)) {
          progress(`↑ ${file.name} · checking faststart`);
          warning = await faststartWarning(file);
        }
        const flagged = warning ? ' · ⚠ not faststart' : '';
        const destination = (path === '/' ? '' : path.replace(/\/$/, '')) + '/' + file.name;
        const done = await uploadFile(file, destination, {
          signal: controller.signal,
          progress: state => { progress(`↑ ${file.name} · ${state}${flagged}`); if (!state.startsWith('hashing')) changed(); },
        });
        results.push(`✓ ${file.name}${done.resumed ? ' (resumed)' : ''}`);
        if (warning) results.push(`  ⚠ ${warning}`);
      } catch (error) { results.push(`✕ ${file.name}: ${error instanceof Cancelled ? 'Upload cancelled' : error.message}`); }
    }
    return results;
  } finally { uploading = null; changed(); }
}

async function faststartWarning(file) {
  const fix = `to stream it, run faststart '${file.name.replaceAll("'", "'\\''")}' once it has uploaded`;
  try {
    if ((await inspectFaststart(file)).faststart) return null;
    return `not faststart: its index (moov) is after its media, so it plays only once the end has downloaded, and not until its upload completes; ${fix}`;
  } catch (error) {
    return `faststart could not be checked (${error.message}); if it does not play while downloading, ${fix}`;
  }
}

function cancelUploads() { if (!uploading) return false; uploading.abort(); return true; }

const chooser = Object.assign(document.createElement('input'), { type: 'file', multiple: true });
let choosing = null;
function cancelChoosing() { if (!choosing) return false; choosing([]); return true; }
function chooseFiles() {
  choosing?.([]);
  return new Promise(resolve => {
    choosing = files => { choosing = null; chooser.onchange = chooser.oncancel = null; resolve(files); };
    chooser.value = '';
    chooser.onchange = () => choosing?.([...chooser.files]);
    chooser.oncancel = () => choosing?.([]);
    chooser.click();
  });
}

document.addEventListener('keydown', event => {
  if (event.key !== 'Escape' || event.defaultPrevented || event.isComposing || document.fullscreenElement) return;
  const dialog = document.querySelector('dialog[open]:modal');
  if (!dialog) return;
  event.preventDefault();
  if (dialog.dispatchEvent(new Event('cancel', { cancelable: true }))) dialog.close();
});

if (window.visualViewport) {
  const viewport = window.visualViewport;
  let tallest = 0, width = 0;
  const fit = () => {
    const root = document.documentElement;
    if (viewport.width !== width) { width = viewport.width; tallest = 0; }
    tallest = Math.max(tallest, viewport.height);
    root.style.setProperty('--app-height', `${viewport.height}px`);
    root.style.setProperty('--app-top', `${viewport.offsetTop}px`);
    root.classList.toggle('keyboard', viewport.height < tallest * 0.8);
    if (document.activeElement?.classList.contains('command-input')) document.activeElement.scrollIntoView({ block: 'nearest' });
  };
  viewport.addEventListener('resize', fit); viewport.addEventListener('scroll', fit); fit();
}

const activeDesktopCancels = new Map();
function isSafeAbsPath(value) {
  return typeof value === 'string' && value.length > 0 && value.startsWith('/') && !value.includes('\0');
}
function sanitizeDeviceName(raw, prefix) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.startsWith(prefix + '/') ? raw.slice(prefix.length + 1) : raw;
  if (!trimmed || trimmed === '.' || trimmed === '..' || /[/\\\0]/.test(trimmed)) return null;
  return trimmed;
}

function installDesktopActionBridge() {
  const port = kernelPort();
  const reply = (id, payload) => port.request('gui_desktop_action_reply', { id, reply: payload }).catch(() => {});
  port.on('desktop-action-cancel', ({ id }) => {
    const cancel = activeDesktopCancels.get(id);
    if (cancel) cancel();
  });
  port.on('desktop-action', async ({ id, req }) => {
    try {
      if (!req || typeof req.op !== 'string') {
        await reply(id, { done: true, status: 2, stderr: 'invalid desktop action\n' });
        return;
      }
      if (req.op === 'open' && typeof req.path === 'string' && req.path.startsWith('/dev/snd/')) {
        const safeName = sanitizeDeviceName(req.path, '/dev/snd');
        if (!safeName) {
          await reply(id, { done: true, status: 2, stderr: 'open: invalid sound device\n' });
          return;
        }
        await desktopBridge.mediaBroker.listenStandalone(`/dev/snd/${safeName}`);
        await reply(id, { done: true, status: 0 });
        return;
      }
      if (req.op === 'stream') {
        if (req.path != null && !isSafeAbsPath(req.path)) {
          await reply(id, { done: true, status: 2, stderr: 'stream: invalid path\n' });
          return;
        }
        let safeName = null;
        if (req.name != null) {
          safeName = sanitizeDeviceName(req.name, '/dev/snd');
          if (!safeName) {
            await reply(id, { done: true, status: 2, stderr: `stream: invalid device name: ${String(req.name)}\n` });
            return;
          }
        }
        activeDesktopCancels.set(id, () => { desktopBridge.mediaBroker.stopRecording(); });
        const saved = await desktopBridge.mediaBroker.recordSound(req.path ?? null, safeName, req.acl ?? null, text => {
          void reply(id, { done: false, progress: text });
        });
        activeDesktopCancels.delete(id);
        const sec = Math.floor(saved.seconds ?? 0);
        const clk = `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;
        const note = saved.note || '';
        const summary = req.path
          ? `✓ ${req.path} · ${clk}${note}\n`
          : `✓ ${saved.device || ''} · ${clk}${note}\n`;
        await reply(id, { done: true, status: 0, stdout: summary });
        return;
      }
      if (req.op === 'focus_app') {
        if (!['terminal', 'mounts', 'files'].includes(req.app_id)) {
          await reply(id, { done: true, status: 2, stderr: 'focus_app: unsupported app\n' });
          return;
        }
        window.osDesktop?.show?.(req.app_id);
        await reply(id, { done: true, status: 0 });
        return;
      }
      if (req.op === 'open_dir') {
        if (!isSafeAbsPath(req.path)) {
          await reply(id, { done: true, status: 2, stderr: 'open_dir: invalid path\n' });
          return;
        }
        await window.osDesktop?.openFilesDir?.(req.path);
        await reply(id, { done: true, status: 0 });
        return;
      }
      if (req.op === 'open_terminal_tab') {
        const argv = Array.isArray(req.argv)
          ? req.argv.filter(s => typeof s === 'string' && !s.includes('\0'))
          : [];
        const cwd = isSafeAbsPath(req.cwd) ? req.cwd : null;
        await window.osDesktop?.openTerminalTab?.(argv, cwd);
        await reply(id, { done: true, status: 0 });
        return;
      }
      if (req.op === 'upload') {
        const targetDir = req.dir ?? '/';
        if (!isSafeAbsPath(targetDir)) {
          await reply(id, { done: true, status: 2, stderr: 'upload: invalid directory\n' });
          return;
        }
        activeDesktopCancels.set(id, () => { cancelChoosing(); cancelUploads(); });
        const files = await chooseFiles();
        if (!files.length) {
          activeDesktopCancels.delete(id);
          await reply(id, { done: true, status: 0 });
          return;
        }
        const results = await uploadFiles(files, targetDir, text => {
          void reply(id, { done: false, progress: text });
        });
        activeDesktopCancels.delete(id);
        const failed = results.some(line => line.startsWith('✕'));
        await reply(id, { done: true, status: failed ? 1 : 0, stdout: results.join('\n') + '\n' });
        return;
      }
      await reply(id, { done: true, status: 127, stderr: `unsupported desktop action: ${req.op}\n` });
    } catch (err) {
      activeDesktopCancels.delete(id);
      await reply(id, { done: true, status: 1, stderr: `${err?.message || err}\n` });
    }
  });
}
installDesktopActionBridge();

async function open(path) {
  if (typeof path === 'string' && path.startsWith('/dev/snd/')) {
    return desktopBridge.mediaBroker.listenStandalone(path);
  }
  return desktopBridge.openPreview(path);
}

window.os = {
  bootStatus,
  closeCleanRoot,
  cloudSignIn,
  cloudSignOut,
  cloudStatus,
  revokeCloudTokensOnly,
  shareMount,
  attachShared,
  sharedMounts,
  revokeMount,
  mountTransports,
  sharingDialog,
  mountLocal,
  localMountList,
  unmountLocal,
  activatePrivate,
  localMounts,
  loginSession,
  configureSeatSharing,
  configureLoginServices,
  startLoginServices,
  signalLoginServices,
  endLoginSession,
  restartLoginSession,
  rebootMachine,
  machineInit,
  seatStatus,
  setSeatActive,
  config: () => configuration.branding,
  exec,
  closeConsole,
  grantConsole,
  revokeConsole,
  attachConsole,
  open,
  presentFile: (path, name) => desktopBridge.presentFile(path, name ?? null),
  stopPresenting: name => desktopBridge.stopPresenting(name),
  recordSound: (path, name, acl, told) => desktopBridge.mediaBroker.recordSound(path, name, acl, told),
  stopRecording: () => desktopBridge.mediaBroker.stopRecording(),
  chooseFiles,
  cancelChoosing,
  uploadFiles,
  cancelUploads,
  uploading: () => uploading !== null,
  focusInput: () => { restoreTerminalFocus(); },
};

function restoreTerminalFocus() {
  requestAnimationFrame(() => {
    if (document.querySelector('dialog[open]:modal') || document.activeElement?.closest?.('dialog[open]')) return;
    window.osDesktop?.focusApp?.('terminal');
  });
}
$('console-share')?.addEventListener('close', () => { restoreTerminalFocus(); });
