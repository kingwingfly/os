import { verifyRelease, refreshOnlineTrustRoot } from './release.js';
import { installSelectMenus } from './select-menu.js';
import { inspectFaststart } from './faststart.mjs';
import { uploadFile, Cancelled } from './upload.mjs';
import { exec, closeConsole, grantConsole, revokeConsole, attachConsole, loginSession, configureSeatSharing, configureLoginServices, startLoginServices, signalLoginServices, endLoginSession, restartLoginSession, rebootMachine, machineInit, seatStatus, setSeatActive, bootStatus, closeCleanRoot, cloudStatus, cloudSignInKernel, cloudSignOutKernel, revokeCloudTokensOnly } from './kernel/page.js';
import { kernelCall, kernelPort } from './kernel/protocol.js';
import { answered as resultOf, call, sys } from './http.mjs';
import { migratePreferences } from './compat.mjs';
import { installConsoleSharing } from './console-sharing.js';
import { executionSupport } from './kernel/capabilities.js';
import { installLocalFiles } from './local-files.js';
import { shareMount, attachShared, sharedMounts, revokeMount, mountTransports, sharingDialog, mountLocal, localMountList, unmountLocal, activatePrivate, localMounts } from './mount-api.js';
import { installDesktopCompatBridge } from './gui/compat-bridge.js';

installLocalFiles();

const changed = (reason = null) => window.dispatchEvent(new CustomEvent('os:changed', { detail: reason }));

let changingSession = 0;
const desktopBridge = installDesktopCompatBridge({
  onSessionEnded: () => { if (!changingSession) void identityChanged('ended'); },
  onChanged: () => changed(),
});

for (const name of ['localStorage', 'sessionStorage']) {
  try { migratePreferences(window[name]); } catch { /* storage can be disabled or full */ }
}

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
let directory = '/';

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

// Local OS account identity (100% offline via local `os-cowfs` `/etc/passwd`, ZERO network RPCs)
// and whether it may write in `path` (local VFS `access`).
let cloudSignedIn = false;
async function session(path = directory) {
  const [creds, writable] = await sys(['getcreds', { access: { path, mode: 3 } }]);
  const who = resultOf(creds);
  return {
    authenticated: who.signed_in,
    writable: who.signed_in,
    username: who.user,
    uid: who.uid,
    gid: who.gid,
    group: who.group,
    groups: who.group_names,
    home: who.home,
    can_sudo: who.can_sudo,
    sudo_active: who.sudo_active,
    can_write: 'ok' in writable,
  };
}

// Explicit Cloud / Cluster Sign-In (`#57` L3d): authenticates against `/api/cloud-auth/login`,
// mints scoped `ServiceAuth v2` credentials, mounts optional `/mnt/cloud` and remote devices,
// and connects `/api/events` WebSocket via `mediaBroker`. NEVER mutates local `/etc/passwd`!
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

const SESSION_CHANGES = new Set(['login', 'logout', 'passwd', 'register', 'unregister']);
async function post(endpoint, data) {
  const changes = SESSION_CHANGES.has(endpoint);
  if (changes) changingSession++;
  try { return await postJson(endpoint, data); } catch (error) { if (changes) changingSession--; throw error; }
}
async function postJson(endpoint, data) {
  switch (endpoint) {
    case 'login': return call('login', { username: data.username ?? 'root', password: data.password ?? '', force: !!data.force }, { sudo: !!data.sudo });
    case 'logout': return call('logout');
    case 'sudo': return call('sudo', { password: data.password ?? '', revoke: !!data.revoke });
    case 'passwd': return call('passwd', { username: data.username ?? null, password: data.password ?? '', current_password: data.current_password ?? null, force: !!data.force }, { sudo: !!data.sudo });
    case 'register': return call('useradd', { name: data.username, password: data.password ?? '', short_password: !!data.short_password, create_home: !!data.create_home });
    case 'unregister': return call('userdel', { name: (await call('getcreds')).user, remove: !!data.remove, password: data.password ?? '' });
  }
  throw new Error('no such account call: ' + endpoint);
}

let dialogs = Promise.resolve();
function credentials(options) {
  const answer = dialogs.then(() => askCredentials(options));
  dialogs = answer.catch(() => {});
  return answer;
}
function askCredentials({ title, description, username, chooseUser = false, newPassword = false, currentPassword = false, action, submit }) {
  return new Promise(resolve => {
    const dialog = $('auth'), form = $('auth-form'), password = $('password'), user = $('username');
    $('auth-title').textContent = title; $('auth-description').textContent = description; $('auth-error').textContent = '';
    $('username-field').hidden = !chooseUser; user.value = username || 'root'; user.required = chooseUser;
    $('current-password-field').hidden = !currentPassword; $('current-password').required = currentPassword;
    $('confirm-password-field').hidden = !newPassword; $('confirm-password').required = newPassword;
    $('password-label').textContent = newPassword ? 'New password' : 'Password';
    password.autocomplete = newPassword ? 'new-password' : 'current-password';
    for (const id of ['password', 'current-password', 'confirm-password']) $(id).value = '';
    const button = form.querySelector('[type=submit]'); button.textContent = action || (newPassword ? 'Save password' : 'Confirm'); button.disabled = false;
    let completed = false;
    const finish = result => {
      if (completed) return; completed = true;
      for (const id of ['password', 'current-password', 'confirm-password']) $(id).value = '';
      dialog.close(); form.onsubmit = null; dialog.oncancel = null; $('cancel-auth').onclick = null;
      resolve(result);
    };
    form.onsubmit = async event => {
      event.preventDefault(); button.disabled = true;
      try {
        if (newPassword && password.value !== $('confirm-password').value) throw new Error('New passwords do not match');
        const result = await submit({ username: user.value.trim(), password: password.value, current_password: $('current-password').value });
        finish(result);
      } catch (error) { $('auth-error').textContent = error.message; }
      finally { for (const id of ['password', 'current-password', 'confirm-password']) $(id).value = ''; button.disabled = false; }
    };
    dialog.oncancel = event => { event.preventDefault(); if (!button.disabled) finish(null); };
    $('cancel-auth').onclick = () => { if (!button.disabled) finish(null); };
    dialog.showModal(); (currentPassword ? $('current-password') : password).focus();
  });
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
  if (!reason) changingSession = 0;
  desktopBridge.mediaBroker.reconnectIfCloudSignedIn();
  if (!reason) windows?.postMessage('changed');
  // A private preview must not survive switching to a less privileged account.
  await desktopBridge.closePreview();
  changed(reason);
}

async function signIn(username, switching = false) {
  let result;
  if (switching && (await session()).uid === 0) result = await post('login', { username, switch: true, force: true });
  else result = await credentials({
    title: switching ? `Switch to ${username}` : 'Sign in',
    description: 'Access is determined by the file owner, group, and rwx permissions.',
    username,
    chooseUser: !switching,
    submit: fields => post('login', { username: switching ? username : fields.username, password: fields.password, switch: switching }),
  });
  if (result) await identityChanged();
  return result;
}
async function unlock(path = directory) {
  const current = await session(path);
  if (current.authenticated || current.can_write) return true;
  throw new Error('Permission denied: sign in with su USER before retrying; your account will not change automatically');
}

async function sudoAuthenticate() {
  await dialogs;
  const current = await session();
  if (!current.authenticated) throw new Error('guest cannot use sudo; sign in to a wheel account with su USER first');
  if (!current.can_sudo) throw new Error('Current account is not in the wheel group');
  if (current.sudo_active) return true;
  return !!await credentials({
    title: `sudo · ${current.username}`,
    description: 'Verify your own password. sudo authorization lasts 5 minutes; ordinary operations still use your current account.',
    submit: fields => post('sudo', { password: fields.password }),
  });
}

async function accountCommand(args, cwd) {
  if (args[0] === 'man') {
    if (args.length > 2) throw new Error('Usage: man [COMMAND]');
    await desktopBridge.openManual(args[1] ?? null);
    return {};
  }
  if (args[0] === 'vim') {
    if (args.length !== 2) throw new Error('Usage: vim <PATH>');
    let value = args[1]; const current = await session();
    if (value === '~') value = current.home; else if (value.startsWith('~/')) value = current.home + value.slice(1);
    if (/[\\\x00-\x1f]/.test(value)) throw new Error('Invalid file path');
    const parts = []; for (const part of (value.startsWith('/') ? value : cwd + '/' + value).split('/')) { if (part === '..') parts.pop(); else if (part && part !== '.') parts.push(part); }
    const target = '/' + parts.join('/');
    await kernelCall('gui_start', { program: 'editor', argv: ['--wait', '--', target] });
    return {};
  }
  let sudo = args[0] === 'sudo';
  if (sudo) {
    args = args.slice(1);
    if (args.length === 1 && args[0] === '-k') { await post('sudo', { revoke: true }); return { output: 'sudo authorization revoked' }; }
    if (!args.length) throw new Error('Usage: sudo <COMMAND> / sudo -u USER / sudo -k');
    if (args[0] === '-u') {
      if (args.length !== 2 || args[1].startsWith('-')) throw new Error('Usage: sudo -u USER (switch accounts; exit returns to guest)');
      if (!await sudoAuthenticate()) throw new Error('sudo canceled');
      const result = await post('login', { username: args[1], sudo: true, force: true });
      await identityChanged();
      return { output: `Current account: ${result.username}`, home: result.home };
    }
    if (!await sudoAuthenticate()) throw new Error('sudo canceled');
  }
  if (args[0] === 'passwd') {
    const force = args.includes('--force');
    const rest = args.slice(1).filter(arg => arg !== '--force');
    if (rest.length > 1 || rest[0]?.startsWith('-') || args.filter(arg => arg === '--force').length > 1) throw new Error('Usage: passwd [--force] [USER]; enter the password in the dialog');
    let current = await session();
    if (!current.authenticated) throw new Error('Sign in with su USER before changing a password');
    const username = rest[0] || current.username;
    const result = await credentials({
      title: `Change password for ${username}`,
      description: (force ? '--force enabled: short passwords are allowed, but cannot be empty. ' : 'Use at least 12 characters, or run passwd --force to allow a short password. ') + 'Saving revokes all previous sessions for this account.',
      newPassword: true,
      currentPassword: !sudo && current.uid !== 0,
      submit: fields => post('passwd', { username, password: fields.password, current_password: fields.current_password, sudo, force }),
    });
    if (!result) throw new Error('Password change canceled');
    await identityChanged(); return { output: `Password updated for ${username}` };
  }
  if (['su', 'login'].includes(args[0])) {
    if (sudo) throw new Error('Use su root to switch accounts');
    const loginShell = args[0] === 'login' || args[1] === '-';
    const rest = args.slice(args[1] === '-' ? 2 : 1);
    if (rest.length > 1 || rest[0]?.startsWith('-')) throw new Error('Usage: su [-] [USER] / login [USER]');
    const result = await signIn(rest[0] || 'root', args[0] === 'su');
    if (!result) throw new Error('Sign-in canceled');
    return { output: `Current account: ${result.user ?? result.username}`, home: loginShell ? result.home : undefined };
  }
  if (['logout', 'exit'].includes(args[0])) {
    if (sudo || args.length !== 1) throw new Error(`Usage: ${args[0]}`);
    const out = await post('logout', {}); await identityChanged();
    const user = out?.username ?? 'user';
    return { output: `Returned to local account: ${user}`, home: out?.home ?? '/home/user' };
  }
  return { program: true };
}

let uploading = null;
async function uploadFiles(files, path, progress) {
  if (!files.length) return [];
  if (uploading) throw new Error('An upload is already going on in this page; wait for it, or cancel it');
  const controller = uploading = new AbortController();
  const results = [];
  try {
    if (!await unlock(path)) return [];
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
  unlock,
  sudo: sudoAuthenticate,
  chooseFiles,
  cancelChoosing,
  uploadFiles,
  cancelUploads,
  uploading: () => uploading !== null,
  accountCommand,
  setDirectory: path => { directory = path; },
  focusInput: () => { restoreTerminalFocus(); },
};

function restoreTerminalFocus() {
  requestAnimationFrame(() => {
    if (document.querySelector('dialog[open]:modal') || document.activeElement?.closest?.('dialog[open]')) return;
    window.osDesktop?.focusApp?.('terminal');
  });
}
for (const id of ['auth', 'console-share']) {
  $(id)?.addEventListener('close', () => { restoreTerminalFocus(); });
}
