// COMPAT-BRIDGE (#61): remove in #65 once files/terminal/viewer/editor/mounts run as native GUI clients.
// Thin presentation bridge connecting the page's `.window` elements to the supervised `compositor`
// and `desktop-shell` WASI processes over `/run/gui/seat0.sock` via `kernelPort()`.
import { kernelPort } from '../kernel/protocol.js';
import { HostPresentationAdapter, gestureRect } from './host-adapter.js';
import { reservedShortcut } from './document-frame.js';

const LEGACY_KEY = 'os-desktop';
const SEAT_ID = 'seat0';
const APPS = {
  files: { title: 'Files', element: 'window-files', min: { width: 280, height: 180 } },
  mounts: { title: 'Mounts', element: 'window-mounts', min: { width: 280, height: 180 } },
  viewer: { title: 'Preview', element: 'viewer', min: { width: 280, height: 180 } },
  editor: { title: 'Editor', element: 'editor', min: { width: 280, height: 180 } },
};

const appIds = Object.keys(APPS);
const $ = id => document.getElementById(id);

function elementFor(appId) {
  const info = APPS[appId];
  return info ? $(info.element) : null;
}

function windowAppOf(target) {
  if (!(target instanceof Element)) return null;
  const win = target.closest('.window[data-window]');
  const appId = win?.getAttribute('data-window');
  return appId && Object.hasOwn(APPS, appId) ? { appId, element: win } : null;
}

function focusInto(appId) {
  const el = elementFor(appId);
  if (!el) return;
  if (el.contains(document.activeElement)) return;
  el.focus({ preventScroll: true });
}

function applyWindowRect(el, rect, zIndex) {
  const z = 20 + (zIndex || 1);
  el.setAttribute('style', `left:${rect.x}px;top:${rect.y}px;width:${rect.width}px;height:${rect.height}px;z-index:${z}`);
}

export function installDesktopCompatBridge() {
  let callbacks = {};
  let port = null;
  let adapter = null;
  let areaEl = null;
  let started = false;
  let desktopActive = false;
  let bootPromise = null;
  let supported = true;
  let focusedSurface = null;
  let focusedApp = null;
  let greeterSurfaces = new Set();
  let modalInert = false;
  const appToSurface = new Map();
  const surfaceToApp = new Map();
  const nativeAppToSurface = new Map();
  const nativeSurfaceToApp = new Map();
  const surfaceRects = new Map();
  const surfaceZ = new Map();
  const surfaceVisible = new Map();
  const opening = new Map();
  let terminalLaunching = null;
  let initialTerminalMapped = false;
  let preferredBootFocusApp = null;
  let userClosedFiles = false;
  let layoutReadyResolve = null;
  let drag = null;
  let previewEl = null;
  let listenersInstalled = false;

  function setModalInert(active) {
    const next = Boolean(active);
    if (modalInert === next) return;
    modalInert = next;
    const targets = [
      document.querySelector('.topbar'),
      document.querySelector('.dock'),
      ...appIds.map(elementFor),
    ];
    for (const el of targets) {
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
    const b = areaBounds();
    const compact = b.width <= 650;
    const filesEl = elementFor('files');
    const termEl = elementFor('terminal');
    const mountsEl = elementFor('mounts');
    if (mountsEl) mountsEl.classList.add('window-hidden');
    if (compact) {
      if (filesEl) {
        applyWindowRect(filesEl, b, 1);
        filesEl.classList.add('window-hidden');
        filesEl.classList.remove('window-focused');
      }
      if (termEl) {
        applyWindowRect(termEl, b, 2);
        termEl.classList.remove('window-hidden');
        termEl.classList.add('window-focused', 'window-filled');
      }
    } else {
      const filesW = Math.min(420, Math.max(280, Math.round(b.width * 0.34)));
      const h = Math.max(180, b.height - 20);
      if (filesEl) {
        applyWindowRect(filesEl, { x: 10, y: 10, width: filesW, height: h }, 1);
        filesEl.classList.remove('window-hidden', 'window-focused', 'window-filled');
      }
      if (termEl) {
        applyWindowRect(termEl, { x: 20 + filesW, y: 10, width: Math.max(280, b.width - filesW - 30), height: h }, 2);
        termEl.classList.remove('window-hidden', 'window-filled');
        termEl.classList.add('window-focused');
      }
    }
    callbacks.onFocus?.('terminal');
  }

  function createCompatSurface(appId) {
    if (!supported || !desktopActive || !port) return Promise.resolve(null);
    const existing = appToSurface.get(appId);
    if (existing != null) return Promise.resolve(existing);
    if (opening.has(appId)) return opening.get(appId);
    const info = APPS[appId];
    if (!info) return Promise.resolve(null);
    const task = port.request('gui_compat_req', {
      req: {
        op: 'create_surface',
        spec: {
          role: 'window',
          kind: { host: { component: appId } },
          title: info.title,
          rect: { x: 0, y: 0, width: 0, height: 0 },
          min_size: info.min,
          max_size: null,
          resizable: true,
          app_id: appId,
        },
      },
    }).then(reply => {
      if (reply?.op === 'created') {
        const id = reply.surface_id;
        const el = elementFor(appId);
        if (el?.tagName === 'DIALOG' && !el.hasAttribute('open')) {
          void port.request('gui_compat_req', { req: { op: 'destroy', surface_id: id } }).catch(() => {});
          return null;
        }
        appToSurface.set(appId, id);
        surfaceToApp.set(id, appId);
        return id;
      }
      return null;
    }).catch(() => null).finally(() => {
      opening.delete(appId);
    });
    opening.set(appId, task);
    return task;
  }

  async function destroyCompatSurface(appId) {
    if (opening.has(appId)) {
      await opening.get(appId).catch(() => null);
    }
    const id = appToSurface.get(appId);
    if (id == null || !port) return;
    appToSurface.delete(appId);
    surfaceToApp.delete(id);
    surfaceRects.delete(id);
    surfaceZ.delete(id);
    surfaceVisible.delete(id);
    const el = elementFor(appId);
    if (el && el.tagName !== 'DIALOG') el.classList.add('window-hidden');
    await port.request('gui_compat_req', { req: { op: 'destroy', surface_id: id } }).catch(() => {});
  }

  function focusNativeSurface(surfaceId) {
    const s = adapter?.surfaces.get(surfaceId);
    if (!s) return;
    if (
      document.activeElement instanceof HTMLElement &&
      document.activeElement.closest('.window')
    ) {
      document.activeElement.blur();
    }
    adapter.focus(s);
  }

  function launchTerminal(argv = [], cwd = null) {
    if (!supported || !desktopActive || !port) return Promise.resolve(null);
    if (!argv.length && !cwd && terminalLaunching) return terminalLaunching;
    const task = port.request('gui_start', {
      program: 'terminal',
      ...(argv.length ? { argv } : {}),
      ...(cwd ? { cwd } : {}),
    }).catch(err => {
      console.warn('terminal launch failed:', err);
      return null;
    });
    if (!argv.length && !cwd) {
      terminalLaunching = task;
      task.finally(() => {
        if (terminalLaunching === task) terminalLaunching = null;
      });
    }
    return task;
  }

  async function showApp(appId) {
    if (!desktopActive && bootPromise) await bootPromise.catch(() => {});
    if (!supported) return;
    if (!desktopActive) return;
    if (appId === 'terminal') {
      const nativeId = nativeAppToSurface.get('terminal');
      if (nativeId != null) {
        await sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
        focusNativeSurface(nativeId);
        return;
      }
      await launchTerminal();
      return;
    }
    if (appId === 'files') userClosedFiles = false;
    if (!initialTerminalMapped) preferredBootFocusApp = appId;
    const existing = appToSurface.get(appId);
    if (existing != null) {
      if (surfaceVisible.get(existing) === false) {
        await port.request('gui_compat_req', {
          req: { op: 'request_state', surface_id: existing, state: 'normal' },
        }).catch(() => {});
      }
      await sendHostInput({ op: 'focus_request', surface_id: existing });
      focusInto(appId);
      return;
    }
    await createCompatSurface(appId);
    focusInto(appId);
  }

  function hidePreview() {
    if (previewEl) previewEl.hidden = true;
  }

  function drawCompatDrag(d) {
    if (!d.latest || !d.lease || !areaEl) return;
    const { x, y } = d.latest;
    d.latest = null;
    const l = d.lease;
    const b = l.bounds;
    const dx = Math.round(x - d.startX);
    const dy = Math.round(y - d.startY);
    const rect = gestureRect(l.start_rect, dx, dy, l);
    d.rect = rect;
    const area = areaEl.getBoundingClientRect();
    const px = x - area.left;
    const py = y - area.top;
    const movedEnough = Math.abs(dx) + Math.abs(dy) >= 6;
    const snap = l.op !== 'move' || !movedEnough
      ? null
      : py <= b.y + 2 ? 'top'
      : px <= b.x + 2 ? 'left'
      : px >= b.x + b.width - 2 ? 'right'
      : null;
    d.snap = l.snap_zones.includes(snap) ? snap : null;
    if (previewEl) {
      previewEl.hidden = !d.snap;
      if (d.snap) {
        const half = Math.floor(b.width / 2);
        const srect = d.snap === 'top' ? b : d.snap === 'left' ? { ...b, width: half } : { ...b, x: b.x + half, width: b.width - half };
        previewEl.style.left = srect.x + 'px';
        previewEl.style.top = srect.y + 'px';
        previewEl.style.width = srect.width + 'px';
        previewEl.style.height = srect.height + 'px';
      }
    }
    applyWindowRect(d.el, rect, surfaceZ.get(d.surfaceId) || 1);
    if (d.el.classList.contains('window-filled') && l.restore_rect && movedEnough) {
      d.el.classList.remove('window-filled');
    }
    const now = performance.now();
    if (now - d.lastProgress >= 100) {
      d.lastProgress = now;
      void sendHostInput({
        op: 'interactive_op_progress',
        serial: ++d.serial,
        lease_id: l.lease_id,
        surface_id: d.surfaceId,
        rect,
        snap_hint: d.snap,
      });
    }
  }

  function finishCompatDrag(d, canceled) {
    if (!d || d.committed) return;
    d.committed = true;
    if (d.fallbackTimer != null) {
      clearTimeout(d.fallbackTimer);
      d.fallbackTimer = null;
    }
    if (drag === d) drag = null;
    document.body?.classList.remove('window-dragging');
    hidePreview();
    if (d.captureEl?.hasPointerCapture?.(d.pointerId)) {
      try { d.captureEl.releasePointerCapture(d.pointerId); } catch {}
    }
    if (d.lease) {
      if (d.latest) drawCompatDrag(d);
      if (!canceled && d.snap) {
        const b = d.lease.bounds;
        const half = Math.floor(b.width / 2);
        const snapped = d.snap === 'top' ? b : d.snap === 'left' ? { ...b, width: half } : { ...b, x: b.x + half, width: b.width - half };
        applyWindowRect(d.el, snapped, surfaceZ.get(d.surfaceId) || 1);
        d.el.classList.add('window-filled');
      } else if (canceled) {
        const prev = surfaceRects.get(d.surfaceId);
        if (prev) applyWindowRect(d.el, prev, surfaceZ.get(d.surfaceId) || 1);
      }
      void sendHostInput({
        op: 'interactive_op_end',
        lease_id: d.lease.lease_id,
        surface_id: d.surfaceId,
        rect: d.rect,
        snap_hint: d.snap ?? null,
        canceled,
      });
    } else {
      void sendHostInput({
        op: 'pointer_up',
        surface_id: d.surfaceId,
        pointer_id: d.pointerId,
        button: 0,
        x: 0,
        y: 0,
        canceled: Boolean(canceled),
      });
    }
  }

  function handleDisplayCmd(cmd) {
    if (cmd.op === 'seat_reset') {
      const wasActive = desktopActive;
      desktopActive = false;
      appToSurface.clear();
      surfaceToApp.clear();
      nativeAppToSurface.clear();
      nativeSurfaceToApp.clear();
      terminalLaunching = null;
      initialTerminalMapped = false;
      preferredBootFocusApp = null;
      userClosedFiles = false;
      surfaceRects.clear();
      surfaceZ.clear();
      surfaceVisible.clear();
      focusedSurface = null;
      focusedApp = null;
      if (drag?.fallbackTimer != null) clearTimeout(drag.fallbackTimer);
      drag = null;
      hidePreview();
      document.body?.classList.remove('window-dragging');
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
      if (id === 'manual' || id === 'upload') {
        callbacks.onLaunchApp?.(id);
      } else if (id === 'mounts') {
        callbacks.onLaunchApp?.('mounts');
        void showApp('mounts');
      } else if (id === 'terminal' || Object.hasOwn(APPS, id)) {
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
      if (cmd.compat_app != null) {
        if (Object.hasOwn(APPS, cmd.compat_app)) {
          appToSurface.set(cmd.compat_app, cmd.surface_id);
          surfaceToApp.set(cmd.surface_id, cmd.compat_app);
          surfaceRects.set(cmd.surface_id, cmd.rect);
          surfaceVisible.set(cmd.surface_id, true);
          const el = elementFor(cmd.compat_app);
          if (el) {
            applyWindowRect(el, cmd.rect, surfaceZ.get(cmd.surface_id) || 1);
            el.classList.remove('window-hidden');
          }
        }
        return;
      }
      if (cmd.app_id) {
        nativeAppToSurface.set(cmd.app_id, cmd.surface_id);
        nativeSurfaceToApp.set(cmd.surface_id, cmd.app_id);
      }
      void adapter?.display(cmd);
      if (cmd.app_id === 'terminal' && !initialTerminalMapped) {
        initialTerminalMapped = true;
        const keepApp = preferredBootFocusApp;
        preferredBootFocusApp = null;
        if (keepApp && keepApp !== 'terminal') {
          const keepId = appToSurface.get(keepApp);
          if (keepId != null) {
            void sendHostInput({ op: 'focus_request', surface_id: keepId });
            focusInto(keepApp);
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
      const appId = surfaceToApp.get(cmd.surface_id);
      if (appId) {
        surfaceToApp.delete(cmd.surface_id);
        const isCurrent = appToSurface.get(appId) === cmd.surface_id;
        if (isCurrent) appToSurface.delete(appId);
        surfaceRects.delete(cmd.surface_id);
        surfaceZ.delete(cmd.surface_id);
        surfaceVisible.delete(cmd.surface_id);
        if (isCurrent) {
          const el = elementFor(appId);
          if (el && el.tagName !== 'DIALOG') {
            el.classList.add('window-hidden');
            el.classList.remove('window-focused');
          }
        }
        return;
      }
      void adapter?.display(cmd);
      return;
    }
    if (cmd.op === 'geometry') {
      const appId = surfaceToApp.get(cmd.surface_id);
      if (appId) {
        surfaceRects.set(cmd.surface_id, cmd.rect);
        surfaceZ.set(cmd.surface_id, cmd.z_index || 1);
        surfaceVisible.set(cmd.surface_id, cmd.visible !== false);
        const el = elementFor(appId);
        if (el) {
          applyWindowRect(el, cmd.rect, cmd.z_index || 1);
          const isDialog = el.tagName === 'DIALOG';
          const isOpen = !isDialog || el.hasAttribute('open');
          el.classList.toggle('window-hidden', cmd.visible === false && (isOpen || !isDialog));
          el.classList.toggle('window-filled', Boolean(cmd.filled));
        }
        return;
      }
      void adapter?.display(cmd);
      return;
    }
    if (cmd.op === 'focus') {
      const prevSurface = focusedSurface;
      focusedSurface = cmd.surface_id ?? null;
      const isModal = Boolean(cmd.modal) || greeterSurfaces.size > 0;
      setModalInert(isModal);
      const nextApp = !isModal && focusedSurface != null
        ? (surfaceToApp.get(focusedSurface) ?? nativeSurfaceToApp.get(focusedSurface) ?? null)
        : null;
      const appChanged = nextApp !== focusedApp;
      focusedApp = nextApp;
      for (const appId of appIds) {
        const el = elementFor(appId);
        if (el) el.classList.toggle('window-focused', appId === nextApp);
      }
      callbacks.onFocus?.(nextApp);
      if (nextApp && Object.hasOwn(APPS, nextApp) && (appChanged || prevSurface !== focusedSurface) && !drag) {
        focusInto(nextApp);
      }
      void adapter?.display(cmd);
      return;
    }
    if (cmd.op === 'begin_interactive_op') {
      const l = cmd.lease;
      if (drag && drag.surfaceId === l.surface_id && drag.pointerId === l.pointer_id) {
        drag.lease = l;
        drag.rect = l.start_rect;
        if (drag.latest) drawCompatDrag(drag);
        if (drag.ended != null) finishCompatDrag(drag, drag.ended);
        return;
      }
      if (surfaceToApp.has(l.surface_id)) {
        void sendHostInput({
          op: 'interactive_op_end',
          lease_id: l.lease_id,
          surface_id: l.surface_id,
          rect: l.start_rect,
          snap_hint: null,
          canceled: true,
        });
        return;
      }
      void adapter?.display(cmd);
      return;
    }
    if (cmd.op === 'cancel_interactive_op') {
      if (drag && drag.lease?.lease_id === cmd.lease_id) {
        const d = drag;
        if (d.fallbackTimer != null) clearTimeout(d.fallbackTimer);
        drag = null;
        document.body?.classList.remove('window-dragging');
        hidePreview();
        if (d.captureEl?.hasPointerCapture?.(d.pointerId)) {
          try { d.captureEl.releasePointerCapture(d.pointerId); } catch {}
        }
        const prev = surfaceRects.get(d.surfaceId);
        if (prev) applyWindowRect(d.el, prev, surfaceZ.get(d.surfaceId) || 1);
        return;
      }
      void adapter?.display(cmd);
      return;
    }
    void adapter?.display(cmd);
  }

  function handleCompatEvent(ev) {
    if (ev?.op === 'close_requested') {
      const appId = surfaceToApp.get(ev.surface_id);
      if (!appId) return;
      if (appId === 'viewer') $('close-viewer')?.click();
      else if (appId === 'editor') $('editor-close')?.click();
      else {
        if (appId === 'files') userClosedFiles = true;
        void destroyCompatSurface(appId);
      }
    }
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

    document.addEventListener('pointerdown', e => {
      if (e.button !== 0 || !desktopActive) return;
      const found = windowAppOf(e.target);
      if (!found) return;
      const surfaceId = appToSurface.get(found.appId);
      if (surfaceId == null) return;
      if (focusedSurface !== surfaceId) {
        void sendHostInput({ op: 'focus_request', surface_id: surfaceId });
      }
      const target = e.target;
      if (!(target instanceof Element)) return;
      const resizeEl = target.closest('.window-resize[data-edge]');
      const barEl = target.closest('[data-window-bar]');
      const onControl = target.closest('button,a,input,select,textarea');
      let hit = null;
      if (resizeEl) {
        hit = { edge: resizeEl.getAttribute('data-edge') };
      } else if (barEl && !onControl) {
        hit = 'titlebar';
      }
      if (!hit) return;
      const captureEl = resizeEl || barEl;
      if (areaBounds().width <= 650 || greeterSurfaces.size > 0 || modalInert) return;
      e.preventDefault();
      document.body?.classList.add('window-dragging');
      drag = {
        surfaceId,
        appId: found.appId,
        el: found.element,
        captureEl,
        captured: false,
        pointerId: e.pointerId,
        startX: e.clientX,
        startY: e.clientY,
        lease: null,
        latest: null,
        ended: null,
        committed: false,
        fallbackTimer: null,
        rect: surfaceRects.get(surfaceId) || { x: 0, y: 0, width: 300, height: 200 },
        snap: null,
        serial: 0,
        lastProgress: -Infinity,
      };
      void sendHostInput({
        op: 'pointer_down',
        surface_id: surfaceId,
        hit_region: hit,
        x: Math.round(e.clientX),
        y: Math.round(e.clientY),
        pointer_id: e.pointerId,
        button: 0,
        timestamp_ms: Date.now(),
      });
    }, false);

    window.addEventListener('pointermove', e => {
      if (!drag || e.pointerId !== drag.pointerId || drag.ended != null) return;
      if (!drag.captured && drag.captureEl) {
        drag.captured = true;
        try { drag.captureEl.setPointerCapture(drag.pointerId); } catch {}
      }
      drag.latest = { x: e.clientX, y: e.clientY };
      if (drag.lease) drawCompatDrag(drag);
    });

    const onUp = (e, canceled) => {
      if (!drag || e.pointerId !== drag.pointerId || drag.ended != null) return;
      const d = drag;
      if (!canceled && Number.isFinite(e.clientX)) {
        if (Math.abs(e.clientX - d.startX) > 0 || Math.abs(e.clientY - d.startY) > 0) {
          d.latest = { x: e.clientX, y: e.clientY };
        }
      }
      d.ended = canceled;
      if (d.lease || canceled || !d.latest) {
        finishCompatDrag(d, canceled);
        return;
      }
      // Fast drag completed before BeginInteractiveOp arrived: release UI capture immediately
      // and give the compositor a short window to hand over the lease before clearing cleanly.
      document.body?.classList.remove('window-dragging');
      if (d.captureEl?.hasPointerCapture?.(d.pointerId)) {
        try { d.captureEl.releasePointerCapture(d.pointerId); } catch {}
      }
      d.fallbackTimer = setTimeout(() => {
        if (drag === d && !d.committed) finishCompatDrag(d, true);
      }, 200);
    };
    window.addEventListener('pointerup', e => onUp(e, false), true);
    window.addEventListener('pointercancel', e => onUp(e, true), true);

    document.addEventListener('dblclick', e => {
      if (!desktopActive) return;
      const found = windowAppOf(e.target);
      if (!found || !(e.target instanceof Element)) return;
      if (!e.target.closest('[data-window-bar]') || e.target.closest('button,a,input')) return;
      const surfaceId = appToSurface.get(found.appId);
      if (surfaceId != null) void sendHostInput({ op: 'titlebar_double_click', surface_id: surfaceId });
    });

    document.addEventListener('click', e => {
      if (!desktopActive || !(e.target instanceof Element)) return;
      const found = windowAppOf(e.target);
      if (!found) return;
      const btn = e.target.closest('[data-window-action]');
      if (!btn) return;
      const surfaceId = appToSurface.get(found.appId);
      if (surfaceId == null) return;
      const action = btn.getAttribute('data-window-action');
      if (action === 'minimize') {
        void sendHostInput({ op: 'chrome_action', surface_id: surfaceId, state: 'minimized' });
      } else if (action === 'maximize') {
        void sendHostInput({ op: 'chrome_action', surface_id: surfaceId, state: 'maximized' });
      } else if (action === 'close') {
        void sendHostInput({ op: 'chrome_action', surface_id: surfaceId, state: null });
      }
    });

    document.addEventListener('focusin', e => {
      if (!desktopActive) return;
      const found = windowAppOf(e.target);
      if (!found) return;
      const surfaceId = appToSurface.get(found.appId);
      if (surfaceId != null && focusedSurface !== surfaceId) {
        void sendHostInput({ op: 'focus_request', surface_id: surfaceId });
      }
    });

    document.addEventListener('keydown', e => {
      if (!desktopActive || !e.isTrusted || e.isComposing || e.keyCode === 229 || e.metaKey) return;
      if (e.key === 'Escape' && drag) {
        e.preventDefault();
        finishCompatDrag(drag, true);
        return;
      }
      // Native `.surface` windows are handled once by HostPresentationAdapter.
      if (focusedSurface == null || !surfaceToApp.has(focusedSurface)) return;
      const key = reservedShortcut(e);
      if (!key) return;
      e.preventDefault();
      void sendHostInput({ op: 'shortcut', surface_id: focusedSurface, key });
    });
  }

  async function bootDesktopSession(restart) {
    if (!window.crossOriginIsolated) {
      supported = false;
      applyStaticFallback();
      return { supported: false };
    }
    supported = true;
    const res = await port.request(restart ? 'gui_restart_desktop' : 'gui_start_desktop');
    if (res?.supported === false) {
      supported = false;
      applyStaticFallback();
      return res;
    }
    desktopActive = true;
    callbacks.onGraphicalEnded?.(false);
    sendViewport();

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

    // Register initial compat windows and spawn the ordinary `/usr/bin/terminal` GUI process (#62 L6a).
    await createCompatSurface('files');
    await launchTerminal();
    if ($('window-mounts') && !$('window-mounts').classList.contains('window-hidden')) {
      await createCompatSurface('mounts');
    }
    if ($('viewer')?.hasAttribute('open')) await createCompatSurface('viewer');
    if ($('editor')?.hasAttribute('open')) await createCompatSurface('editor');
    return res;
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
        return;
      }
      port = kernelPort();
      if (areaEl && !adapter) {
        adapter = new HostPresentationAdapter(areaEl, {
          input: event => {
            if (
              event.op === 'host_focus' &&
              (drag || !adapter || adapter.surfaces.size === 0 || windowAppOf(document.activeElement))
            ) {
              return;
            }
            return sendHostInput(event);
          },
          canvas: (surface_id, generation, canvas, backend, decoration) =>
            port.request('gui_pixel_canvas', { surface_id, generation, canvas, backend, decoration }, [canvas]),
          port: (surface_id, p) => port.request('gui_surface_port', { surface_id, port: p }, [p]),
          revoke: surface_id => port.request('gui_revoke_port', { surface_id }),
          pick: () => {},
          clipboard: item => navigator.clipboard?.writeText?.(new TextDecoder().decode(new Uint8Array(item.data))),
          error: () => {},
        });
        previewEl = adapter.preview;
      } else if (areaEl && !previewEl) {
        previewEl = document.createElement('div');
        previewEl.className = 'snap-preview';
        previewEl.hidden = true;
        areaEl.append(previewEl);
      }
      port.on('gui-display', handleDisplayCmd);
      port.on('gui-compat-event', handleCompatEvent);
      port.on('gui-compat-rebind', () => {
        if (!supported || !desktopActive) return;
        const mountsOpen = $('window-mounts') && !$('window-mounts').classList.contains('window-hidden');
        const viewerOpen = Boolean($('viewer')?.hasAttribute('open'));
        const editorOpen = Boolean($('editor')?.hasAttribute('open'));
        appToSurface.clear();
        surfaceToApp.clear();
        void (async () => {
          if (!userClosedFiles) await createCompatSurface('files');
          if (mountsOpen) await createCompatSurface('mounts');
          if (viewerOpen) await createCompatSurface('viewer');
          if (editorOpen) await createCompatSurface('editor');
        })();
      });
      bootPromise = bootDesktopSession(false).catch(err => {
        console.warn('desktop-shell startup failed:', err);
      }).finally(() => {
        bootPromise = null;
      });
    },
    show(appId) { void showApp(appId); },
    setCompatOpen(appId, open) {
      const apply = () => {
        if (!supported || !desktopActive) return;
        if (open) void showApp(appId);
        else void destroyCompatSurface(appId);
      };
      if (!desktopActive && bootPromise) void bootPromise.then(apply);
      else apply();
    },
    shellInput(action) {
      const send = () => {
        if (!supported || !desktopActive) return;
        void sendHostInput({ op: 'shell_input', action });
      };
      if (!desktopActive && bootPromise) void bootPromise.then(send);
      else send();
    },
    setFullscreen(active) {
      const send = () => {
        if (!supported || !desktopActive) return;
        void sendHostInput({ op: 'fullscreen_changed', active: Boolean(active) });
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
        return;
      }
      const compatId = appToSurface.get(appId);
      if (compatId != null) {
        void sendHostInput({ op: 'focus_request', surface_id: compatId });
        focusInto(appId);
      }
    },
    async openTerminalTab(argv = [], cwd = null) {
      if (!desktopActive && bootPromise) await bootPromise.catch(() => {});
      if (!supported || !desktopActive || !port) return null;
      const res = await port.request('gui_terminal_open_tab', {
        argv: Array.isArray(argv) ? argv : [],
        cwd: typeof cwd === 'string' && cwd ? cwd : null,
      }).catch(err => {
        console.warn('openTerminalTab failed:', err);
        return null;
      });
      const nativeId = nativeAppToSurface.get('terminal');
      if (nativeId != null) {
        void sendHostInput({ op: 'shell_input', action: { action: 'focus', surface_id: nativeId } });
        focusNativeSurface(nativeId);
      }
      return res;
    },
  };

  window.osDesktop = api;
  return api;
}
