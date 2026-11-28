// Thin host presentation bridge connecting the browser page to the supervised
// `compositor` and `desktop-shell` WASI processes over `/run/gui/seat0.sock` via `kernelPort()`.
// All desktop applications (`terminal`, `files`, `mounts`, `editor`, `preview`) run as ordinary
// unprivileged WASIX GUI processes (`#64` `L6c`). Zero Window compat apps remain.
import { kernelCall, kernelPort } from '../kernel/protocol.js';
import { HostPresentationAdapter } from './host-adapter.js';
import { createHostMediaBroker } from './media-broker.js';
import { inspectFaststart } from '../faststart.mjs';
import { uploadFile, Cancelled } from '../upload.mjs';
import { savedSourceStore } from '../kernel/source-registry.js';

const LEGACY_KEY = 'os-desktop';
const FILES_SAVED_KEY = 'os-files';
const SEAT_ID = 'seat0';

const VALID_ERRNOS = new Set([
  'EACCES', 'EPERM', 'ENOENT', 'EEXIST', 'EINVAL', 'EBUSY', 'ECANCELED', 'EIO',
  'ENODEV', 'ENOSYS', 'EOPNOTSUPP', 'ENOTCONN', 'ESTALE', 'E2BIG', 'EAGAIN', 'ETIMEDOUT',
]);
function normalizeErrno(code) {
  if (code === 'ENOTSUP') return 'EOPNOTSUPP';
  if (typeof code === 'string' && VALID_ERRNOS.has(code)) return code;
  return 'EIO';
}
function classifyConsentError(err) {
  if (err?.name === 'AbortError') return { status: 'canceled', errno: 'ECANCELED' };
  if (['NotSupportedError', 'DataCloneError'].includes(err?.name)) {
    return {
      status: 'unsupported',
      origin: location.origin,
      detail: 'This browser could not provide a usable directory handle to OS.',
    };
  }
  return {
    status: 'error',
    errno: normalizeErrno(err?.errno),
    detail: String(err?.message ?? err?.detail ?? err?.errno ?? err),
  };
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

const $ = id => document.getElementById(id);

export function installDesktopCompatBridge({ onSessionEnded, onChanged, onCloudSignIn, onCloudSignOut } = {}) {
  let callbacks = {};
  let port = null;
  let adapter = null;
  let areaEl = null;
  let started = false;
  let desktopActive = false;
  let bootPromise = null;
  let desktopReadyResolve = null;
  const desktopReady = new Promise(resolve => { desktopReadyResolve = resolve; });
  const waitDesktopReady = () => (bootPromise ?? desktopReady).catch(() => {});
  let supported = true;
  let focusedSurface = null;
  let focusedApp = null;
  let greeterSurfaces = new Set();
  let modalInert = false;
  const nativeAppToSurface = new Map();
  const nativeSurfaceToApp = new Map();
  let sessionEpoch = 0;
  const bootPendingApps = new Set();
  const pendingAppLaunches = new Map();
  const LAUNCH_PENDING_TIMEOUT_MS = 10000;
  let initialTerminalMapped = false;
  let initialFilesMapped = false;
  let preferredBootFocusApp = null;
  let filesRefreshInFlight = false;
  let filesRefreshPending = false;
  let mountsRefreshInFlight = false;
  let mountsRefreshPending = false;
  let mountsRefreshReset = false;
  let settingsRefreshInFlight = false;
  let settingsRefreshPending = false;
  let loginChangeEpoch = 0;
  const savedHandles = new Map();
  let savedHandlesOwner = null;
  const activePickControllers = new Map();
  const pendingPickChoosers = new Map();
  let layoutReadyResolve = null;
  let listenersInstalled = false;
  let gameUrlResolver = () => null;

  const mediaBroker = createHostMediaBroker({
    sendMediaEvent: (surfaceId, payload) => {
      if (!port || !desktopActive) return;
      void port.request('gui_media_event', { surface_id: surfaceId, payload }).catch(() => {});
    },
    sendSessionEvent: (surfaceId, eventJson) => {
      if (!port || !desktopActive) return;
      void port.request('gui_session_event', { surface_id: surfaceId, event_json: eventJson }).catch(() => {});
    },
    onSessionEnded: () => onSessionEnded?.(),
    onChanged: () => onChanged?.(),
  });

  function setModalInert(active) {
    const next = Boolean(active);
    if (modalInert === next) return;
    modalInert = next;
    for (const el of [document.querySelector('.topbar'), document.querySelector('.dock')]) {
      if (el) el.inert = next;
    }
    if (next) {
      const overlay = document.querySelector('.greeter-modal-overlay');
      if (
        document.activeElement instanceof HTMLElement &&
        (!overlay || !overlay.contains(document.activeElement))
      ) {
        document.activeElement.blur();
      }
      requestAnimationFrame(() => {
        document
          .querySelector('.greeter-modal-overlay button, .greeter-modal-overlay a')
          ?.focus?.({ preventScroll: true });
      });
    }
  }

  const sendHostInput = event => {
    if (!port || !desktopActive) return Promise.resolve();
    return port.request('gui_host_event', { event }).catch(() => {});
  };

  function areaBounds() {
    if (!areaEl) return { x: 0, y: 0, width: 1024, height: 640 };
    const r = areaEl.getBoundingClientRect();
    return {
      x: 0,
      y: 0,
      width: Math.max(1, Math.round(r.width)),
      height: Math.max(1, Math.round(r.height)),
    };
  }

  function sendViewport() {
    if (!desktopActive || !areaEl) return;
    const bounds = areaBounds();
    if (bounds.width <= 1 || bounds.height <= 1) return;
    void port.request('gui_viewport', { bounds, mode: 'local_lease' }).catch(() => {});
  }

  function applyStaticFallback() {
    callbacks.onFocus?.('terminal');
  }

  function focusNativeSurface(surfaceId) {
    if (modalInert || greeterSurfaces.size > 0) return;
    const s = adapter?.surfaces.get(surfaceId);
    if (!s) return;
    adapter.focus(s);
  }

  function clearPendingAppLaunch(appId, entry = null) {
    const cur = pendingAppLaunches.get(appId);
    if (!cur || (entry && cur !== entry)) return;
    if (cur.timer != null) clearTimeout(cur.timer);
    pendingAppLaunches.delete(appId);
  }

  function clearAllPendingAppLaunches() {
    for (const cur of pendingAppLaunches.values()) {
      if (cur.timer != null) clearTimeout(cur.timer);
    }
    pendingAppLaunches.clear();
    bootPendingApps.clear();
  }

  function isAppLaunchPending(appId) {
    return bootPendingApps.has(appId) || pendingAppLaunches.has(appId);
  }

  function startTrackedAppLaunch(appId, startFn, { force = false } = {}) {
    if (!supported || !desktopActive || !port) return Promise.resolve(null);
    if (!force) {
      const existing = pendingAppLaunches.get(appId);
      if (existing) return existing.promise;
      if (bootPendingApps.has(appId)) {
        return waitForNativeSurface(appId, LAUNCH_PENDING_TIMEOUT_MS);
      }
    } else {
      clearPendingAppLaunch(appId);
    }
    const epoch = sessionEpoch;
    const entry = { promise: null, timer: null, epoch };
    entry.timer = setTimeout(() => {
      clearPendingAppLaunch(appId, entry);
    }, LAUNCH_PENDING_TIMEOUT_MS);
    pendingAppLaunches.set(appId, entry);
    entry.promise = Promise.resolve()
      .then(() => startFn())
      .then(result => {
        if (!result || epoch !== sessionEpoch || (result?.reused === true && nativeAppToSurface.has(appId))) {
          clearPendingAppLaunch(appId, entry);
        }
        return result;
      })
      .catch(err => {
        clearPendingAppLaunch(appId, entry);
        console.warn(`${appId} launch failed:`, err);
        return null;
      });
    return entry.promise;
  }

  function launchTerminal(argv = [], cwd = null, opts = {}) {
    return startTrackedAppLaunch('terminal', () =>
      port.request('gui_start', {
        program: 'terminal',
        ...(argv.length ? { argv } : {}),
        ...(cwd ? { cwd } : {}),
      }),
      opts,
    );
  }

  function launchFiles(argv = [], cwd = null, opts = {}) {
    return startTrackedAppLaunch('files', () =>
      port.request('gui_start', {
        program: 'files',
        ...(argv.length ? { argv } : {}),
        ...(cwd ? { cwd } : {}),
      }),
      opts,
    );
  }

  async function waitForNativeSurface(appId, timeoutMs = 8000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const id = nativeAppToSurface.get(appId);
      if (id != null) return id;
      await new Promise(r => setTimeout(r, 25));
    }
    return null;
  }

  async function openMounts(pane = 'mounted') {
    if (!desktopActive) await waitDesktopReady();
    if (!supported || !desktopActive || !port) return null;
    if (!initialTerminalMapped || !initialFilesMapped) preferredBootFocusApp = 'mounts';
    const normalized = pane === 'sharing' ? 'publish' : (typeof pane === 'string' && pane ? pane : 'mounted');
    let res = null;
    if (!nativeAppToSurface.has('mounts')) {
      if (pendingAppLaunches.has('mounts')) {
        await waitForNativeSurface('mounts', 5000);
        if (nativeAppToSurface.has('mounts')) {
          res = await port.request('gui_mounts_focus', { tab: normalized }).catch(err => {
            console.warn('openMounts failed:', err);
            return null;
          });
        }
      } else {
        res = await startTrackedAppLaunch('mounts', () =>
          port.request('gui_mounts_focus', { tab: normalized }),
        );
      }
    } else {
      res = await port.request('gui_mounts_focus', { tab: normalized }).catch(err => {
        console.warn('openMounts failed:', err);
        return null;
      });
    }
    const nativeId = nativeAppToSurface.get('mounts') ?? await waitForNativeSurface('mounts', 5000);
    if (nativeId != null) {
      await sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
      await sendHostInput({ op: 'focus_request', surface_id: nativeId });
      focusNativeSurface(nativeId);
    }
    return res;
  }

  function refreshMounts(reset = false) {
    if (!supported || !desktopActive || !port || !nativeAppToSurface.has('mounts')) return;
    if (reset) mountsRefreshReset = true;
    if (mountsRefreshInFlight) {
      mountsRefreshPending = true;
      return;
    }
    mountsRefreshInFlight = true;
    void (async () => {
      try {
        do {
          mountsRefreshPending = false;
          const doReset = mountsRefreshReset;
          mountsRefreshReset = false;
          if (!desktopActive || !nativeAppToSurface.has('mounts')) break;
          await port.request('gui_mounts_refresh', { reset: doReset }).catch(() => {});
        } while (mountsRefreshPending);
      } finally {
        mountsRefreshInFlight = false;
      }
    })();
  }

  async function openPreviewRequest(req, { speaker = false } = {}) {
    if (!desktopActive) await waitDesktopReady();
    if (!supported || !desktopActive || !port) return null;
    const res = await port.request('gui_preview_open', { req, speaker });
    const nativeId = nativeAppToSurface.get('preview') ?? await waitForNativeSurface('preview', 5000);
    if (nativeId != null) {
      await sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
      await sendHostInput({ op: 'focus_request', surface_id: nativeId });
      focusNativeSurface(nativeId);
    }
    return res;
  }

  async function openPreview(path) {
    return openPreviewRequest({ op: 'open', path });
  }

  async function openManual(command = null) {
    return openPreviewRequest({ op: 'manual', command: command || null });
  }

  async function openSpeaker(path) {
    return openPreviewRequest({ op: 'open', path }, { speaker: true });
  }

  async function presentFile(path, name = null) {
    return openPreviewRequest({ op: 'present', path, name: name ?? null });
  }

  async function stopPresenting(name) {
    if (!desktopActive) await waitDesktopReady();
    if (!supported || !desktopActive || !port) return null;
    const pid = await port.request('gui_start', { program: 'preview', argv: ['--stop-present', String(name)] });
    return { pid, device: `/dev/present/${name}` };
  }

  async function closePreview() {
    if (!port) return;
    await port.request('gui_close_app', { program: 'preview' }).catch(() => {});
  }

  async function openSettings(section = 'accounts') {
    if (!desktopActive) await waitDesktopReady();
    if (!supported || !desktopActive || !port) return null;
    if (!initialTerminalMapped || !initialFilesMapped) preferredBootFocusApp = 'settings';
    const normalized = ['accounts', 'system', 'appearance'].includes(section) ? section : 'accounts';
    let res = null;
    if (!nativeAppToSurface.has('settings')) {
      if (pendingAppLaunches.has('settings')) {
        await waitForNativeSurface('settings', 5000);
        if (nativeAppToSurface.has('settings')) {
          res = await port.request('gui_settings_focus', { section: normalized }).catch(err => {
            console.warn('openSettings failed:', err);
            return null;
          });
        }
      } else {
        res = await startTrackedAppLaunch('settings', () =>
          port.request('gui_settings_focus', { section: normalized }),
        );
      }
    } else {
      res = await port.request('gui_settings_focus', { section: normalized }).catch(err => {
        console.warn('openSettings failed:', err);
        return null;
      });
    }
    const nativeId = nativeAppToSurface.get('settings') ?? await waitForNativeSurface('settings', 5000);
    if (nativeId != null) {
      await sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
      await sendHostInput({ op: 'focus_request', surface_id: nativeId });
      focusNativeSurface(nativeId);
    }
    return res;
  }

  function refreshSettings() {
    if (!supported || !desktopActive || !port || !nativeAppToSurface.has('settings')) return;
    if (settingsRefreshInFlight) {
      settingsRefreshPending = true;
      return;
    }
    settingsRefreshInFlight = true;
    void (async () => {
      try {
        do {
          settingsRefreshPending = false;
          if (!desktopActive || !nativeAppToSurface.has('settings')) break;
          await port.request('gui_settings_refresh').catch(() => {});
        } while (settingsRefreshPending);
      } finally {
        settingsRefreshInFlight = false;
      }
    })();
  }

  function readHostPreferences() {
    const theme = document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
    let dock_autohide = false;
    try { dock_autohide = localStorage.getItem('os-dock-autohide') === 'true'; } catch {}
    const fullscreen = Boolean(document.fullscreenElement);
    return { theme, dock_autohide, fullscreen };
  }

  function applyHostPreferences(theme, dockAutohide, source = 'portal') {
    const normalizedTheme = theme === 'dark' ? 'dark' : 'light';
    const normalizedDock = Boolean(dockAutohide);
    document.documentElement.dataset.theme = normalizedTheme;
    try { localStorage.setItem('os-theme', normalizedTheme); } catch {}
    try { localStorage.setItem('os-dock-autohide', normalizedDock ? 'true' : 'false'); } catch {}
    window.dispatchEvent(new CustomEvent('os:theme', { detail: normalizedTheme }));
    window.dispatchEvent(new CustomEvent('os:preferences-changed', {
      detail: { theme: normalizedTheme, dock_autohide: normalizedDock, source },
    }));
    return readHostPreferences();
  }

  function syncSettingsPreferences(prefs) {
    if (!supported || !desktopActive || !port || !nativeAppToSurface.has('settings')) return;
    void port.request('gui_settings_sync_prefs', {
      theme: prefs.theme === 'dark' ? 'dark' : 'light',
      dock_autohide: Boolean(prefs.dock_autohide),
      fullscreen: Boolean(document.fullscreenElement),
    }).catch(() => {});
  }

  async function loadUserSettingsFromDisk() {
    if (!supported || !desktopActive || !port) return;
    try {
      const saved = await port.request('gui_user_settings_read');
      if (saved && saved.version === 1 && (saved.theme === 'light' || saved.theme === 'dark')) {
        applyHostPreferences(saved.theme, Boolean(saved.dock_autohide), 'disk');
      }
    } catch { /* no saved settings yet */ }
  }

  async function gatherAccountPortalState(cloudOverride = null) {
    const [boot, cloudRaw] = await Promise.all([
      kernelCall('boot_status').catch(() => null),
      cloudOverride ? Promise.resolve(cloudOverride) : kernelCall('cloud_status').catch(() => null),
    ]);
    const acct = boot?.account ?? {};
    const root = boot?.mounted_root ?? {};
    const local = {
      username: String(acct.user ?? 'user'),
      uid: Number.isInteger(acct.uid) ? acct.uid : 1000,
      gid: Number.isInteger(acct.gid) ? acct.gid : 1000,
      home: String(acct.home ?? '/home/user'),
      root_volume_uuid: typeof root.uuid === 'string' && root.uuid ? root.uuid : null,
      forked_from: typeof root.forked_from === 'string' && root.forked_from ? root.forked_from : null,
      ephemeral_if_unmodified: Boolean(root.ephemeral_if_unmodified),
      can_sudo: Boolean(acct.can_sudo),
      root_fstype: String(boot?.root_fstype ?? 'cowfs'),
    };
    const rawScope = cloudRaw?.scope ?? {};
    const cloud = {
      signed_in: Boolean(cloudRaw?.signed_in),
      cloud_user: typeof cloudRaw?.cloud_user === 'string' && cloudRaw.cloud_user ? cloudRaw.cloud_user : null,
      scope: {
        cloud_fs: Boolean(rawScope.cloud_fs),
        devices: Array.isArray(rawScope.devices) ? rawScope.devices.map(String) : [],
        containers: Boolean(rawScope.containers),
        relay: Boolean(rawScope.relay),
        volumes: Boolean(rawScope.volumes),
        volume_ids: Array.isArray(rawScope.volume_ids) ? rawScope.volume_ids.map(String) : [],
        volumes_ro: Boolean(rawScope.volumes_ro),
        registry_pull: Boolean(rawScope.registry_pull),
        registry_push: Boolean(rawScope.registry_push),
        registry_repos: Array.isArray(rawScope.registry_repos) ? rawScope.registry_repos.map(String) : [],
        cluster_read: Boolean(rawScope.cluster_read),
        cluster_write: Boolean(rawScope.cluster_write),
        cluster_watch: Boolean(rawScope.cluster_watch),
        cluster_lease: Boolean(rawScope.cluster_lease),
        cluster_compact: Boolean(rawScope.cluster_compact),
        cluster_prefixes: Array.isArray(rawScope.cluster_prefixes) ? rawScope.cluster_prefixes.map(String) : [],
        ...(typeof rawScope.cluster_node_id === 'string' ? { cluster_node_id: rawScope.cluster_node_id } : {}),
        ...(rawScope.net ? { net: rawScope.net } : {}),
        ...(rawScope.overlay ? { overlay: rawScope.overlay } : {}),
      },
      cloud_mount_active: Boolean(cloudRaw?.cloud_mounted),
      attached_devices: Array.isArray(cloudRaw?.attached_devices) ? cloudRaw.attached_devices.map(String) : [],
    };
    return { local, cloud };
  }

  async function handleHostPortal(cmd) {
    if (!port || !desktopActive) return;
    const { request_id, surface_id, request } = cmd;
    const portalKind = request?.portal;
    const action = request?.action;
    const beforeEpoch = loginChangeEpoch;
    const sessionStale = () => beforeEpoch !== loginChangeEpoch;
    const sendResponse = response =>
      port.request('gui_portal_result', { request_id, surface_id, response }).catch(() => {});

    if (portalKind === 'mounts') {
      const sendOutcome = outcome => sendResponse({ portal: 'mounts', outcome });
      if (!action || typeof action.action !== 'string') {
        await sendOutcome({ status: 'error', errno: 'EINVAL', detail: 'Invalid mount consent request.' });
        return;
      }
      if (action.action === 'pick_host_folder') {
        if (typeof window.showDirectoryPicker !== 'function') {
          await sendOutcome({
            status: 'unsupported',
            origin: location.origin,
            detail: 'This browser does not expose the directory picker API that OS uses for direct host-folder mounts.',
          });
          return;
        }
        let selection;
        try {
          selection = window.showDirectoryPicker({ mode: action.writable ? 'readwrite' : 'read', id: 'os-host-folder' });
        } catch (err) {
          selection = Promise.reject(err);
        }
        try {
          const handle = await selection;
          if (sessionStale()) {
            await sendOutcome({ status: 'error', errno: 'ECANCELED', detail: 'Session changed. Choose the folder again.' });
            return;
          }
          try {
            await port.request('gui_portal_commit', { request_id, surface_id, handle });
          } catch (err) {
            if (['DataCloneError', 'NotSupportedError'].includes(err?.name)) {
              await sendOutcome(classifyConsentError(err));
            }
          }
        } catch (err) {
          await sendOutcome(classifyConsentError(err));
        }
        return;
      }
      if (action.action === 'renew_host_folder') {
        try {
          const cached = savedHandlesOwner ? savedHandles.get(action.source_id) : null;
          const cachedOwner = savedHandlesOwner;
          let permPromise;
          let usedCached = false;
          if (cached?.handle?.requestPermission && cachedOwner
            && cached.volume === cachedOwner.volume && cached.uid === cachedOwner.uid) {
            permPromise = cached.handle.requestPermission({ mode: action.writable ? 'readwrite' : 'read' });
            usedCached = true;
          }
          const local = await kernelCall('source_session');
          if (sessionStale()) {
            await sendOutcome({ status: 'error', errno: 'ECANCELED', detail: 'Session changed. Renew the folder again.' });
            return;
          }
          if (usedCached && (cached.volume !== local.volume || cached.uid !== local.uid)) {
            permPromise = null;
            usedCached = false;
          }
          if (!permPromise) {
            const store = savedSourceStore();
            const record = await store.get(local.volume, local.uid, action.source_id);
            if (sessionStale()) {
              await sendOutcome({ status: 'error', errno: 'ECANCELED', detail: 'Session changed. Renew the folder again.' });
              return;
            }
            if (!record || record.volume !== local.volume || record.uid !== local.uid) {
              await sendOutcome({ status: 'error', errno: 'ENOENT', detail: 'Saved folder unavailable.' });
              return;
            }
            permPromise = record.handle.requestPermission({ mode: action.writable ? 'readwrite' : 'read' });
          }
          const result = await permPromise;
          if (sessionStale()) {
            await sendOutcome({ status: 'error', errno: 'ECANCELED', detail: 'Session changed. Renew the folder again.' });
            return;
          }
          if (result !== 'granted') {
            await sendOutcome({ status: 'error', errno: 'EACCES', detail: 'Folder access denied.' });
            return;
          }
          await port.request('gui_portal_commit', { request_id, surface_id }).catch(() => {});
        } catch (err) {
          await sendOutcome(classifyConsentError(err));
        }
        return;
      }
      if (action.action === 'capabilities') {
        try {
          const host_picker = typeof window.showDirectoryPicker === 'function';
          const browser_label = /Firefox|FxiOS/.test(navigator.userAgent)
            ? 'Firefox'
            : /Safari/.test(navigator.userAgent) && !/Chrome|Chromium|CriOS|Edg|OPR/.test(navigator.userAgent)
            ? 'Safari'
            : 'This browser';
          const [local, cloud] = await Promise.all([
            kernelCall('source_session').catch(() => null),
            kernelCall('cloud_status').catch(() => null),
          ]);
          if (sessionStale()) {
            await sendOutcome({ status: 'canceled', errno: 'ECANCELED' });
            return;
          }
          savedHandles.clear();
          savedHandlesOwner = null;
          if (local?.volume && Number.isSafeInteger(local?.uid)) {
            try {
              const list = await savedSourceStore().list(local.volume, local.uid);
              if (sessionStale()) {
                await sendOutcome({ status: 'canceled', errno: 'ECANCELED' });
                return;
              }
              savedHandlesOwner = { volume: local.volume, uid: local.uid };
              for (const rec of list) {
                if (rec?.id && rec?.handle && rec.volume === local.volume && rec.uid === local.uid) {
                  savedHandles.set(rec.id, rec);
                }
              }
            } catch { /* IDB unavailable */ }
          }
          if (sessionStale()) {
            await sendOutcome({ status: 'canceled', errno: 'ECANCELED' });
            return;
          }
          await sendOutcome({
            status: 'capabilities',
            host_picker,
            origin: location.origin,
            browser_label,
            relay_ready: local?.relayUid != null,
            account_user: String(cloud?.cloud_user ?? ''),
            signed_in: Boolean(cloud?.signed_in),
          });
        } catch (err) {
          await sendOutcome(classifyConsentError(err));
        }
        return;
      }
      if (['register_opfs', 'register_helper', 'register_share'].includes(action.action)) {
        if (sessionStale()) {
          await sendOutcome({ status: 'error', errno: 'ECANCELED', detail: 'Session changed. Try again.' });
          return;
        }
        await port.request('gui_portal_commit', { request_id, surface_id }).catch(() => {});
        return;
      }
      await sendOutcome({ status: 'error', errno: 'EOPNOTSUPP', detail: 'Unsupported mount consent action.' });
      return;
    }

    if (portalKind === 'account') {
      const sendOutcome = outcome => sendResponse({ portal: 'account', outcome });
      if (!action || typeof action.action !== 'string') {
        await sendOutcome({ status: 'error', errno: 'EINVAL', detail: 'Invalid account portal request.' });
        return;
      }
      if (action.action === 'status') {
        try {
          const { local, cloud } = await gatherAccountPortalState();
          if (sessionStale()) {
            await sendOutcome({ status: 'canceled', errno: 'ECANCELED' });
            return;
          }
          await sendOutcome({ status: 'state', local, cloud, notice: null });
        } catch (err) {
          await sendOutcome({ status: 'error', errno: normalizeErrno(err?.errno), detail: String(err?.message ?? err) });
        }
        return;
      }
      if (action.action === 'cloud_sign_in') {
        if (typeof onCloudSignIn !== 'function') {
          await sendOutcome({ status: 'error', errno: 'ENOSYS', detail: 'Cloud sign-in is unavailable.' });
          return;
        }
        try {
          const status = await onCloudSignIn(action.username, action.password, action.scope);
          if (sessionStale()) {
            await sendOutcome({ status: 'canceled', errno: 'ECANCELED' });
            return;
          }
          const { local, cloud } = await gatherAccountPortalState(status);
          await sendOutcome({
            status: 'state',
            local,
            cloud,
            notice: 'Cloud credentials active; local OS account unchanged.',
          });
        } catch (err) {
          await sendOutcome({
            status: 'error',
            errno: normalizeErrno(err?.errno),
            detail: String(err?.message ?? err?.detail ?? err),
          });
        }
        return;
      }
      if (action.action === 'cloud_sign_out') {
        if (typeof onCloudSignOut !== 'function') {
          await sendOutcome({ status: 'error', errno: 'ENOSYS', detail: 'Cloud sign-out is unavailable.' });
          return;
        }
        try {
          const status = await onCloudSignOut();
          if (sessionStale()) {
            await sendOutcome({ status: 'canceled', errno: 'ECANCELED' });
            return;
          }
          const { local, cloud } = await gatherAccountPortalState(status);
          await sendOutcome({
            status: 'state',
            local,
            cloud,
            notice: 'Signed out of Cloud; local processes unaffected.',
          });
        } catch (err) {
          await sendOutcome({
            status: 'error',
            errno: normalizeErrno(err?.errno),
            detail: String(err?.message ?? err?.detail ?? err),
          });
        }
        return;
      }
      if (action.action === 'switch_local_user') {
        try {
          const { local } = await gatherAccountPortalState();
          void api.openTerminalTab(['/usr/bin/su'], local.home);
          await sendOutcome({ status: 'action_done', notice: 'Opened local user switch prompt in Terminal.' });
        } catch (err) {
          await sendOutcome({ status: 'error', errno: normalizeErrno(err?.errno), detail: String(err?.message ?? err) });
        }
        return;
      }
      if (action.action === 'open_mounts') {
        void openMounts(action.tab || 'mounted');
        await sendOutcome({ status: 'action_done', notice: null });
        return;
      }
      await sendOutcome({ status: 'error', errno: 'EOPNOTSUPP', detail: 'Unsupported account portal action.' });
      return;
    }

    if (portalKind === 'desktop') {
      const sendOutcome = outcome => sendResponse({ portal: 'desktop', outcome });
      if (!action || typeof action.action !== 'string') {
        await sendOutcome({ status: 'error', errno: 'EINVAL', detail: 'Invalid desktop portal request.' });
        return;
      }
      if (action.action === 'get_preferences') {
        const prefs = readHostPreferences();
        await sendOutcome({ status: 'preferences', ...prefs });
        return;
      }
      if (action.action === 'apply_preferences') {
        const prefs = applyHostPreferences(action.theme, action.dock_autohide, 'portal');
        await sendOutcome({ status: 'preferences', ...prefs });
        return;
      }
      if (action.action === 'set_fullscreen') {
        try {
          if (action.active) {
            const target = document.querySelector('.desktop') || document.documentElement;
            if (typeof target?.requestFullscreen === 'function' && !document.fullscreenElement) {
              await target.requestFullscreen();
            }
          } else if (document.fullscreenElement && typeof document.exitFullscreen === 'function') {
            await document.exitFullscreen();
          }
          const prefs = readHostPreferences();
          await sendOutcome({ status: 'preferences', ...prefs });
        } catch (err) {
          await sendOutcome({ status: 'error', errno: 'EACCES', detail: String(err?.message ?? err) });
        }
        return;
      }
      await sendOutcome({ status: 'error', errno: 'EOPNOTSUPP', detail: 'Unsupported desktop portal action.' });
      return;
    }
  }

  async function openFilesDir(path) {
    if (!desktopActive) await waitDesktopReady();
    if (!supported || !desktopActive || !port) return null;
    if (!initialTerminalMapped) preferredBootFocusApp = 'files';
    if (!nativeAppToSurface.has('files') && isAppLaunchPending('files')) {
      await waitForNativeSurface('files', 5000);
    }
    const res = !nativeAppToSurface.has('files')
      ? await startTrackedAppLaunch('files', () => port.request('gui_files_open_dir', { path }))
      : await port.request('gui_files_open_dir', { path }).catch(err => {
          console.warn('openFilesDir failed:', err);
          return null;
        });
    const nativeId = nativeAppToSurface.get('files') ?? await waitForNativeSurface('files', 4000);
    if (nativeId != null) {
      await sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
      await sendHostInput({ op: 'focus_request', surface_id: nativeId });
      focusNativeSurface(nativeId);
    }
    return res;
  }

  function refreshFiles() {
    if (!supported || !desktopActive || !port || !nativeAppToSurface.has('files')) return;
    if (filesRefreshInFlight) {
      filesRefreshPending = true;
      return;
    }
    filesRefreshInFlight = true;
    void (async () => {
      try {
        do {
          filesRefreshPending = false;
          if (!desktopActive || !nativeAppToSurface.has('files')) break;
          await port.request('gui_files_refresh').catch(() => {});
        } while (filesRefreshPending);
      } finally {
        filesRefreshInFlight = false;
      }
    })();
  }

  async function triggerFilesUpload() {
    if (!desktopActive) await waitDesktopReady();
    if (!supported || !desktopActive || !port) return;
    let nativeId = nativeAppToSurface.get('files');
    if (nativeId == null) {
      await launchFiles();
      nativeId = await waitForNativeSurface('files', 5000);
    }
    if (nativeId == null) return;
    await sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
    focusNativeSurface(nativeId);
    await sendHostInput({
      op: 'pointer_down',
      surface_id: nativeId,
      hit_region: 'content',
      x: 0,
      y: 0,
      pointer_id: 0,
      button: 0,
      timestamp_ms: Date.now(),
    });
    await sendHostInput({
      op: 'pointer_up',
      surface_id: nativeId,
      pointer_id: 0,
      button: 0,
      x: 0,
      y: 0,
      canceled: false,
    });
    await port.request('gui_files_trigger_upload').catch(() => {});
  }

  function cancelHostPick(requestId) {
    const chooserCancel = pendingPickChoosers.get(requestId);
    if (chooserCancel) {
      pendingPickChoosers.delete(requestId);
      chooserCancel();
    }
    const controller = activePickControllers.get(requestId);
    if (controller) {
      controller.abort();
    }
  }

  async function handleHostPick(cmd) {
    if (!port || !desktopActive) return;
    const { request_id, surface_id, owner_pid, multiple, cloud_dest } = cmd;
    const files = await new Promise(resolve => {
      const input = document.createElement('input');
      input.type = 'file';
      input.multiple = Boolean(multiple);
      let settled = false;
      const done = list => {
        if (settled) return;
        settled = true;
        pendingPickChoosers.delete(request_id);
        input.onchange = input.oncancel = null;
        resolve(list);
      };
      pendingPickChoosers.set(request_id, () => done(null));
      input.onchange = () => done([...(input.files || [])]);
      input.oncancel = () => done([]);
      input.click();
    });
    if (files === null) return;
    if (!files.length) {
      await port.request('gui_picker_result', { request_id, surface_id, file: null }).catch(() => {});
      return;
    }
    if (cloud_dest) {
      const allowed = await port.request('gui_verify_cloud_upload', {
        surface_id,
        owner_pid: owner_pid ?? 0,
        dest: cloud_dest,
      }).catch(() => false);
      if (!allowed) {
        const lines = files.map(f => `✕ ${f.name}: Permission denied`);
        await port.request('gui_upload_progress', {
          request_id,
          surface_id,
          text: lines.join('\n'),
          done: true,
          error: 'Permission denied',
        }).catch(() => {});
        return;
      }
      const controller = new AbortController();
      activePickControllers.set(request_id, controller);
      const results = [];
      const rust = window.osUploads;
      const sendProgress = (text, done = false, error = null) =>
        port.request('gui_upload_progress', {
          request_id,
          surface_id,
          text,
          done,
          ...(error ? { error } : {}),
        }).catch(() => {});
      try {
        await sendProgress('↑ starting', false);
        for (const file of files) {
          if (controller.signal.aborted) {
            results.push(`✕ ${file.name}: Upload cancelled`);
            continue;
          }
          try {
            if (rust?.maxFile && file.size > rust.maxFile) {
              throw new Error(`Exceeds the ${rust.maxFile / 1e9} GB limit`);
            }
            let warning = null;
            if (/\.(mp4|m4v|mov|m4a)$/i.test(file.name)) {
              await sendProgress(`↑ ${file.name} · checking faststart`, false);
              warning = await faststartWarning(file);
            }
            const flagged = warning ? ' · ⚠ not faststart' : '';
            const base = cloud_dest === '/' ? '' : cloud_dest.replace(/\/$/, '');
            const destination = `${base}/${file.name}`;
            const done = await uploadFile(file, destination, {
              signal: controller.signal,
              progress: state => {
                void sendProgress(`↑ ${file.name} · ${state}${flagged}`, false);
                if (!state.startsWith('hashing')) {
                  window.dispatchEvent(new CustomEvent('os:changed', { detail: null }));
                }
              },
            });
            results.push(`✓ ${file.name}${done.resumed ? ' (resumed)' : ''}`);
            if (warning) results.push(`  ⚠ ${warning}`);
          } catch (error) {
            results.push(`✕ ${file.name}: ${error instanceof Cancelled ? 'Upload cancelled' : error.message}`);
          }
        }
      } finally {
        activePickControllers.delete(request_id);
        await sendProgress(results.join('\n'), true);
        window.dispatchEvent(new CustomEvent('os:changed', { detail: null }));
      }
      return;
    }
    await port.request('gui_picker_result', { request_id, surface_id, files }).catch(() => {});
  }

  async function showApp(appId) {
    if (!desktopActive) await waitDesktopReady();
    if (!supported || !desktopActive || !port) return;
    if (!initialTerminalMapped || !initialFilesMapped) preferredBootFocusApp = appId;
    const nativeId = nativeAppToSurface.get(appId);
    if (nativeId != null) {
      await sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
      await sendHostInput({ op: 'focus_request', surface_id: nativeId });
      focusNativeSurface(nativeId);
      return;
    }
    if (appId === 'terminal') await launchTerminal();
    else if (appId === 'files') await launchFiles();
    else if (appId === 'mounts') await openMounts('mounted');
    else if (appId === 'settings') await openSettings('accounts');
    else if (appId === 'manual') await openManual(null);
  }

  function handleDisplayCmd(cmd) {
    if (cmd.op === 'seat_reset') {
      const wasActive = desktopActive;
      desktopActive = false;
      sessionEpoch++;
      nativeAppToSurface.clear();
      nativeSurfaceToApp.clear();
      clearAllPendingAppLaunches();
      savedHandles.clear();
      savedHandlesOwner = null;
      initialTerminalMapped = false;
      initialFilesMapped = false;
      preferredBootFocusApp = null;
      for (const cancel of pendingPickChoosers.values()) cancel();
      pendingPickChoosers.clear();
      for (const ctrl of activePickControllers.values()) ctrl.abort();
      activePickControllers.clear();
      focusedSurface = null;
      focusedApp = null;
      mediaBroker.resetAll();
      setModalInert(false);
      if (greeterSurfaces.size > 0) {
        greeterSurfaces.clear();
        callbacks.onGreeterModal?.(false);
      }
      adapter?.display(cmd);
      if (wasActive) callbacks.onGraphicalEnded?.(true);
      return;
    }
    if (cmd.op === 'shell_state') {
      callbacks.onShellState?.(cmd.state);
      return;
    }
    if (cmd.op === 'launch_app') {
      const id = cmd.app_id;
      if (id === 'manual') {
        void openManual(null);
      } else if (id === 'upload') {
        void triggerFilesUpload();
      } else if (id === 'mounts') {
        void openMounts('mounted');
      } else if (id === 'settings') {
        void openSettings('accounts');
      } else if (id === 'terminal' || id === 'files') {
        void showApp(id);
      }
      return;
    }
    if (cmd.op === 'legacy_layout_migrated') {
      try { localStorage.removeItem(LEGACY_KEY); } catch {}
      return;
    }
    if (cmd.op === 'layout_ready') {
      if (layoutReadyResolve) {
        const resolve = layoutReadyResolve;
        layoutReadyResolve = null;
        resolve();
      }
      return;
    }
    if (cmd.op === 'map') {
      if (cmd.role === 'greeter' || cmd.role === 'lock') {
        greeterSurfaces.add(cmd.surface_id);
        setModalInert(true);
        callbacks.onGreeterModal?.(true);
        return;
      }
      if (cmd.app_id) {
        clearPendingAppLaunch(cmd.app_id);
        bootPendingApps.delete(cmd.app_id);
        nativeAppToSurface.set(cmd.app_id, cmd.surface_id);
        nativeSurfaceToApp.set(cmd.surface_id, cmd.app_id);
      }
      void adapter?.display(cmd);
      if ((cmd.app_id === 'terminal' && !initialTerminalMapped) || (cmd.app_id === 'files' && !initialFilesMapped)) {
        if (cmd.app_id === 'terminal') initialTerminalMapped = true;
        if (cmd.app_id === 'files') initialFilesMapped = true;
        const keepApp = preferredBootFocusApp;
        if (initialTerminalMapped && initialFilesMapped) preferredBootFocusApp = null;
        if (keepApp && keepApp !== cmd.app_id) {
          const keepId = nativeAppToSurface.get(keepApp);
          if (keepId != null) {
            void sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: keepId } });
            void sendHostInput({ op: 'focus_request', surface_id: keepId });
            focusNativeSurface(keepId);
          }
        }
      }
      return;
    }
    if (cmd.op === 'unmap') {
      if (greeterSurfaces.delete(cmd.surface_id)) {
        const stillModal = greeterSurfaces.size > 0;
        setModalInert(stillModal);
        callbacks.onGreeterModal?.(stillModal);
        return;
      }
      mediaBroker.cleanupSurface(cmd.surface_id);
      const nativeApp = nativeSurfaceToApp.get(cmd.surface_id);
      if (nativeApp) {
        nativeSurfaceToApp.delete(cmd.surface_id);
        if (nativeAppToSurface.get(nativeApp) === cmd.surface_id) {
          nativeAppToSurface.delete(nativeApp);
          for (const [sid, aid] of nativeSurfaceToApp) {
            if (aid === nativeApp) {
              nativeAppToSurface.set(nativeApp, sid);
              break;
            }
          }
        }
      }
      void adapter?.display(cmd);
      return;
    }
    if (cmd.op === 'focus') {
      focusedSurface = cmd.surface_id ?? null;
      const isModal = Boolean(cmd.modal) || greeterSurfaces.size > 0;
      setModalInert(isModal);
      const nextApp = !isModal && focusedSurface != null
        ? (nativeSurfaceToApp.get(focusedSurface) ?? null)
        : null;
      focusedApp = nextApp;
      callbacks.onFocus?.(nextApp);
      void adapter?.display(cmd);
      return;
    }
    if (cmd.op === 'update_surface_chrome') {
      if (nativeSurfaceToApp.get(cmd.surface_id) === 'files') {
        const title = cmd.chrome?.title || '';
        if (title.startsWith('Files — ')) {
          try { sessionStorage.setItem(FILES_SAVED_KEY, title.slice('Files — '.length)); } catch {}
        }
      }
      void adapter?.display(cmd);
      return;
    }
    void adapter?.display(cmd);
  }

  function installDomListeners() {
    if (listenersInstalled) return;
    listenersInstalled = true;

    const ro = new ResizeObserver(() => {
      if (!supported) applyStaticFallback();
      else sendViewport();
    });
    if (areaEl) ro.observe(areaEl);
    window.addEventListener('resize', () => {
      if (!supported) applyStaticFallback();
      else sendViewport();
    });

    // External OS file drag-and-drop onto Files (ignores drops targeting Terminal).
    let dropDepth = 0;
    const isTerminalDropTarget = target =>
      target instanceof Element && Boolean(target.closest('.surface[data-app-id="terminal"]'));
    window.addEventListener('dragenter', e => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      if (isTerminalDropTarget(e.target)) return;
      e.preventDefault();
      dropDepth++;
      const dz = $('dropzone');
      if (dz) dz.hidden = false;
    }, true);
    window.addEventListener('dragover', e => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      if (isTerminalDropTarget(e.target)) return;
      e.preventDefault();
    }, true);
    window.addEventListener('dragleave', () => {
      if (--dropDepth <= 0) {
        dropDepth = 0;
        const dz = $('dropzone');
        if (dz) dz.hidden = true;
      }
    }, true);
    window.addEventListener('drop', e => {
      e.preventDefault();
      dropDepth = 0;
      const dz = $('dropzone');
      if (dz) dz.hidden = true;
      if (isTerminalDropTarget(e.target)) return;
      const files = [...(e.dataTransfer?.files || [])];
      if (!files.length || !desktopActive || !port) return;
      const filesSurfaceId = nativeAppToSurface.get('files');
      if (filesSurfaceId == null) return;
      void port.request('gui_external_drop', { surface_id: filesSurfaceId, files }).catch(err => {
        console.warn('external drop failed:', err);
      });
    }, true);

    window.addEventListener('os-open-directory', e => {
      const path = e?.detail;
      if (typeof path === 'string' && path) void openFilesDir(path);
    });
    for (const evName of ['os:mounts-changed', 'os:changed', 'os:cloud-changed', 'os-remote']) {
      window.addEventListener(evName, () => refreshFiles());
    }
    for (const evName of ['os:mounts-changed', 'os:cloud-changed']) {
      window.addEventListener(evName, () => refreshMounts(false));
    }
    for (const evName of ['os:cloud-changed', 'os:changed']) {
      window.addEventListener(evName, () => refreshSettings());
    }
    window.addEventListener('os:preferences-changed', e => {
      const detail = e?.detail;
      if (!detail || detail.source !== 'chrome') return;
      const theme = detail.theme === 'dark' ? 'dark' : 'light';
      const dock_autohide = Boolean(detail.dock_autohide);
      if (supported && desktopActive && port) {
        void port.request('gui_user_settings_write', { theme, dock_autohide }).catch(() => {});
      }
      syncSettingsPreferences({ theme, dock_autohide });
    });
    document.addEventListener('fullscreenchange', () => {
      syncSettingsPreferences(readHostPreferences());
    });
    window.addEventListener('os:login-changed', () => {
      loginChangeEpoch++;
      savedHandles.clear();
      savedHandlesOwner = null;
      refreshMounts(true);
      refreshSettings();
      void loadUserSettingsFromDisk();
    });
  }

  async function bootDesktopSession(restart) {
    if (!window.crossOriginIsolated) {
      supported = false;
      applyStaticFallback();
      return { supported: false };
    }
    const epoch = ++sessionEpoch;
    clearAllPendingAppLaunches();
    bootPendingApps.add('files');
    bootPendingApps.add('terminal');
    try {
      supported = true;
      const res = await port.request(restart ? 'gui_restart_desktop' : 'gui_start_desktop');
      if (res?.supported === false) {
        supported = false;
        applyStaticFallback();
        return res;
      }
      if (epoch !== sessionEpoch) return res;
      desktopActive = true;
      callbacks.onGraphicalEnded?.(false);
      sendViewport();
      void loadUserSettingsFromDisk();

      let legacyJson = null;
      try { legacyJson = localStorage.getItem(LEGACY_KEY); } catch {}
      const layoutReady = new Promise(resolve => {
        layoutReadyResolve = resolve;
        setTimeout(resolve, 1500);
      });
      await sendHostInput({
        op: 'seat_layout_init',
        seat_id: SEAT_ID,
        legacy_json: legacyJson,
      });
      await layoutReady;
      if (epoch !== sessionEpoch || !desktopActive) return res;

      // Spawn ordinary `/usr/bin/files` and `/usr/bin/terminal` GUI processes.
      // Default initial boot focus to `terminal` (or `preview` if `?speaker=` popup).
      const speakerDeck = new URLSearchParams(location.search).get('speaker');
      preferredBootFocusApp ??= speakerDeck ? 'preview' : 'terminal';
      let savedFilesDir = null;
      try { savedFilesDir = sessionStorage.getItem(FILES_SAVED_KEY); } catch {}
      bootPendingApps.delete('files');
      if (!nativeAppToSurface.has('files')) {
        await launchFiles(savedFilesDir ? ['--dir', savedFilesDir] : []);
      }
      if (epoch !== sessionEpoch || !desktopActive) return res;
      bootPendingApps.delete('terminal');
      if (!nativeAppToSurface.has('terminal')) {
        await launchTerminal();
      }
      if (speakerDeck) {
        document.title = 'Speaker view · ' + speakerDeck.split('/').pop();
        void openSpeaker(speakerDeck).catch(err => console.warn('speaker popup launch failed:', err));
      }
      return res;
    } finally {
      if (epoch === sessionEpoch) bootPendingApps.clear();
    }
  }

  const api = {
    start(cbs = {}) {
      callbacks = cbs;
      areaEl = document.querySelector('.desktop-area');
      installDomListeners();
      if (started) return;
      started = true;
      if (!window.crossOriginIsolated) {
        supported = false;
        applyStaticFallback();
        desktopReadyResolve?.();
        return;
      }
      port = kernelPort();
      if (areaEl && !adapter) {
        adapter = new HostPresentationAdapter(areaEl, {
          input: event => {
            if (event.op === 'host_focus' && (!adapter || adapter.surfaces.size === 0)) {
              return;
            }
            return sendHostInput(event);
          },
          canvas: (surface_id, generation, canvas, backend, decoration) =>
            port.request('gui_pixel_canvas', { surface_id, generation, canvas, backend, decoration }, [canvas]),
          port: (surface_id, p) => port.request('gui_surface_port', { surface_id, port: p }, [p]),
          revoke: surface_id => port.request('gui_revoke_port', { surface_id }),
          pick: cmd => void handleHostPick(cmd),
          cancelPick: requestId => cancelHostPick(requestId),
          portal: cmd => void handleHostPortal(cmd),
          exportFile: cmd => {
            if (!cmd?.data || typeof cmd.filename !== 'string') return;
            let bytes;
            if (cmd.data instanceof Uint8Array) bytes = cmd.data;
            else if (typeof cmd.data === 'string') {
              const bin = atob(cmd.data);
              bytes = new Uint8Array(bin.length);
              for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            } else {
              bytes = new Uint8Array(cmd.data);
            }
            const url = URL.createObjectURL(new Blob([bytes], { type: cmd.mime || 'application/octet-stream' }));
            const a = document.createElement('a');
            a.href = url;
            a.download = cmd.filename;
            a.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          },
          fullscreenResult: (surfaceId, active, error) => {
            if (!port || !desktopActive) return;
            void port.request('gui_fullscreen_result', {
              surface_id: surfaceId,
              active: Boolean(active),
              ...(error ? { error: String(error) } : {}),
            }).catch(() => {});
          },
          resolveGameUrl: entry => gameUrlResolver(entry),
          mediaControl: cmd => void mediaBroker.handleMediaControl(cmd),
          sessionEvents: cmd => mediaBroker.handleSessionEventsCmd(cmd),
          clipboard: item => {
            let bytes;
            if (item?.data instanceof Uint8Array) bytes = item.data;
            else if (typeof item?.data === 'string') {
              const bin = atob(item.data);
              bytes = new Uint8Array(bin.length);
              for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            } else {
              bytes = new Uint8Array(item?.data ?? []);
            }
            return navigator.clipboard?.writeText?.(new TextDecoder().decode(bytes));
          },
          error: () => {},
        });
      }
      port.on('gui-display', handleDisplayCmd);
      port.on('gui-session-rebind', info => {
        if (!supported || !desktopActive) return;
        const uidChanged = Boolean(info?.uidChanged);
        const hadFiles = info?.hadFiles !== false;
        void (async () => {
          if (uidChanged) {
            try { sessionStorage.removeItem(FILES_SAVED_KEY); } catch {}
            // `login_refresh` has already terminated the prior UID's `files` process, though
            // compositor `unmap` may still be in flight; relaunch Files for the new UID iff
            // Files was open before the switch (`unmap` only removes matching surface IDs).
            if (hadFiles) await launchFiles([], null, { force: true });
          }
        })();
      });
      bootPromise = bootDesktopSession(false).catch(err => {
        console.warn('desktop-shell startup failed:', err);
      }).finally(() => {
        bootPromise = null;
        desktopReadyResolve?.();
      });
    },
    show(appId) { void showApp(appId); },
    shellInput(action) {
      const act = action?.action;
      const appId = action?.app_id;
      if (
        (act === 'toggle_app' || act === 'launch') &&
        appId &&
        !nativeAppToSurface.has(appId) &&
        isAppLaunchPending(appId)
      ) {
        if (!initialTerminalMapped || !initialFilesMapped) {
          preferredBootFocusApp = appId;
        }
        if (desktopActive && act === 'launch') {
          void sendHostInput({ op: 'shell_input', action: { action: 'close_launcher' } });
        }
        return;
      }
      const send = () => {
        if (!supported || !desktopActive) return;
        void sendHostInput({ op: 'shell_input', action });
      };
      if (!desktopActive && bootPromise) void bootPromise.then(send);
      else send();
    },
    async restartGraphical() {
      bootPromise = bootDesktopSession(true).finally(() => {
        bootPromise = null;
      });
      return bootPromise;
    },
    async startGreeter() {
      if (!port) return;
      return port.request('gui_greeter_start');
    },
    async stopGreeter() {
      if (!port) return;
      return port.request('gui_greeter_stop');
    },
    focusApp(appId) {
      if (!supported || !desktopActive) return;
      const nativeId = nativeAppToSurface.get(appId);
      if (nativeId != null) {
        void sendHostInput({ op: 'focus_request', surface_id: nativeId });
        focusNativeSurface(nativeId);
      }
    },
    async openTerminalTab(argv = [], cwd = null) {
      if (!desktopActive) await waitDesktopReady();
      if (!supported || !desktopActive || !port) return null;
      if (!nativeAppToSurface.has('terminal') && isAppLaunchPending('terminal')) {
        await waitForNativeSurface('terminal', 5000);
      }
      const payload = {
        argv: Array.isArray(argv) ? argv : [],
        cwd: typeof cwd === 'string' && cwd ? cwd : null,
      };
      const res = !nativeAppToSurface.has('terminal')
        ? await startTrackedAppLaunch('terminal', () => port.request('gui_terminal_open_tab', payload))
        : await port.request('gui_terminal_open_tab', payload).catch(err => {
            console.warn('openTerminalTab failed:', err);
            return null;
          });
      const nativeId = nativeAppToSurface.get('terminal') ?? await waitForNativeSurface('terminal', 5000);
      if (nativeId != null) {
        void sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
        focusNativeSurface(nativeId);
      }
      return res;
    },
    openFilesDir(path) { return openFilesDir(path); },
    refreshFiles() { refreshFiles(); },
    openMounts(pane = 'mounted') { return openMounts(pane); },
    refreshMounts() { refreshMounts(); },
    openSettings(section = 'accounts') { return openSettings(section); },
    refreshSettings() { refreshSettings(); },
    openPreview(path) { return openPreview(path); },
    openManual(command = null) { return openManual(command); },
    openSpeaker(path) { return openSpeaker(path); },
    presentFile(path, name = null) { return presentFile(path, name); },
    stopPresenting(name) { return stopPresenting(name); },
    closePreview() { return closePreview(); },
    setGameResolver(fn) { gameUrlResolver = typeof fn === 'function' ? fn : () => null; },
    mediaBroker,
  };

  window.osDesktop = api;
  return api;
}
