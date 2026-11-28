import { documentFrame, reservedShortcut } from './document-frame.js';

export function gestureRect(start, dx, dy, lease) {
  const { bounds: b, min_size: min, max_size: max, op, restore_rect: restore } = lease;
  const clamp = (n, low, high) => Math.min(Math.max(n, Math.min(low, high)), high);
  let { x, y, width, height } = start;
  if (op === 'move') {
    if (restore) {
      if (Math.abs(dx) + Math.abs(dy) < 6) return { ...start };
      width = restore.width;
      height = restore.height;
    }
    x += dx; y += dy;
  } else {
    const edge = op.resize.edge;
    if (edge.includes('e')) width = clamp(width + dx, min.width, Math.min(max?.width ?? Infinity, b.x + b.width - x));
    if (edge.includes('s')) height = clamp(height + dy, min.height, Math.min(max?.height ?? Infinity, b.y + b.height - y));
    if (edge.includes('w')) {
      width = clamp(width - dx, min.width, Math.min(max?.width ?? Infinity, start.x + start.width - b.x));
      x += start.width - width;
    }
    if (edge.includes('n')) {
      height = clamp(height - dy, min.height, Math.min(max?.height ?? Infinity, start.y + start.height - b.y));
      y += start.height - height;
    }
  }
  width = Math.min(width, b.width); height = Math.min(height, b.height);
  return { x: clamp(x, b.x, b.x + b.width - width), y: clamp(y, b.y, b.y + b.height - height), width, height };
}
export function dragStatistics(samples, messages, durationMs, dispatched = samples.length) {
  const sorted = [...samples].sort((a, b) => a - b);
  const at = q => sorted[Math.max(0, Math.ceil(sorted.length * q) - 1)] ?? 0;
  return { samples: sorted.length, p50: at(.5), p95: at(.95), p99: at(.99), max: at(1), late: sorted.filter(n => n > 16.7).length, missed: dispatched - sorted.length, messages, messagesPerSecond: messages * 1000 / Math.max(1, durationMs) };
}
function place(el, rect) {
  el.style.transform = 'translate3d(' + rect.x + 'px,' + rect.y + 'px,0)';
  el.style.width = rect.width + 'px'; el.style.height = rect.height + 'px';
}
function rectsOverlap(a, b) {
  if (!a || !b) return false;
  return a.x < b.x + b.width
    && a.x + a.width > b.x
    && a.y < b.y + b.height
    && a.y + a.height > b.y;
}
const make = (tag, cls) => { const el = document.createElement(tag); if (cls) el.className = cls; return el; };
const controls = [['close', 'Close', '×'], ['minimize', 'Minimize', '−'], ['maximize', 'Maximize', '+']];
const hostControl = el => el?.closest?.('nav, .picker, .titlebar button, .topbar, .sys-menu-popover, .cc-popover, .nc-popover, .cloud-panel-popover');
const utf8 = new TextEncoder();
export class HostPresentationAdapter {
  constructor(root, transport) {
    this.root = root; this.transport = transport; this.surfaces = new Map(); this.mode = 'local_lease'; this.z = 20;
    this.desktop = make('div', 'desktop-layer'); this.modal = make('div', 'modal-layer');
    this.preview = make('div', 'snap-preview'); this.preview.hidden = true;
    this.alerts = make('aside', 'notifications'); this.alerts.setAttribute('aria-live', 'polite');
    root.append(this.desktop, this.preview, this.modal, this.alerts);
    this.messages = 0; this.active = null;
    this.serial = 0;
    this.dragSeq = 0;
    this.frames = null;
    this.hostControlFocus = -Infinity;
    this.fullscreenSurfaceId = null;
    this.shieldPress = null;
    let pasteChord = null;
    document.addEventListener?.('fullscreenchange', () => {
      const fsEl = document.fullscreenElement;
      const matched = fsEl ? this.surfaceOf(fsEl) : null;
      const prev = this.fullscreenSurfaceId;
      this.fullscreenSurfaceId = matched?.id ?? null;
      if (prev != null && prev !== this.fullscreenSurfaceId) {
        this.transport.fullscreenResult?.(prev, false, null);
      }
      if (this.fullscreenSurfaceId != null) {
        this.transport.fullscreenResult?.(this.fullscreenSurfaceId, true, null);
      }
    });
    window.addEventListener('message', e => {
      if (e.origin !== location.origin || e.data !== 'close-game') return;
      for (const s of this.surfaces.values()) {
        if (s.gameFrame?.contentWindow === e.source) {
          this.input({ op: 'chrome_action', surface_id: s.id, state: null });
          return;
        }
      }
    });
    window.addEventListener('pointermove', e => {
      if (!e.isTrusted) return;
      if (this.drag) return this.move(e);
      if (this.tracking != null) return this.dropTarget(e, false);
      const s = this.surfaceOf(e.target);
      if (s?.canvas === e.target && document.activeElement === s.canvas) {
        this.input({ op: 'pointer_move', surface_id: s.id, pointer_id: e.pointerId, ...this.local(s, e) });
      }
    }, true);
    const release = (e, canceled) => {
      if (!e.isTrusted) return;
      if (this.shieldPress && e.pointerId === this.shieldPress.pointerId) {
        this.scheduleShieldRelease(this.shieldPress);
        return;
      }
      if (!canceled && e.button !== 0) return;
      if (this.drag) { this.end(e, canceled); return; }
      this.release(e, canceled);
    };
    window.addEventListener('pointerup', e => release(e, false), true);
    window.addEventListener('pointercancel', e => release(e, true), true);
    window.addEventListener('lostpointercapture', e => {
      // Never cancel a titlebar/edge drag on lostpointercapture: on macOS Chrome trackpad
      // (Force Touch / tap-to-drag / three-finger drag), capture can drop while the pointer is
      // still active. Window-level pointermove/pointerup/pointercancel/blur handle drag lifecycle.
      if (this.drag) return;
      if (this.shieldPress && e.target !== this.shieldPress.s.shield) return;
      if (!this.shieldPress && this.press && e.target !== this.press.s.canvas) return;
      release(e, true);
    }, true);
    window.addEventListener('blur', () => setTimeout(() => {
      if (!document.hasFocus()) {
        if (this.drag) this.end({ pointerId: this.drag.pointer }, true);
        if (this.shieldPress) { this.shieldPress = null; this.syncFocusShields(); }
        this.press = null;
        this.input({ op: 'host_focus' });
      }
    }, 0));
    window.addEventListener('focusin', e => {
      pasteChord = null;
      const control = hostControl(e.target);
      if (control) this.hostControlFocus = Math.max(this.hostControlFocus, performance.timeOrigin + e.timeStamp);
      // Do not send host_focus (which cancels active drag leases) on transient body/chrome focus
      // shifts while a window move/resize drag is in flight.
      if (this.drag && !control) return;
      if (control || !this.surfaceOf(e.target)) {
        this.press = null;
        this.input({ op: 'host_focus' });
      }
    }, true);
    window.addEventListener('keydown', e => {
      if (!e.isTrusted || e.isComposing || e.keyCode === 229) return;
      const s = this.surfaceOf(document.activeElement);
      if (!s || this.surfaceOf(e.target) !== s) { this.input({ op: 'host_focus' }); return; }
      if (e.key === 'Escape' && this.drag) { this.end({ pointerId: this.drag.pointer }, true); return; }
      const key = reservedShortcut(e);
      if (key === 'lock') { e.preventDefault(); window.dispatchEvent(new CustomEvent('os:lock-screen')); return; }
      if (key) { e.preventDefault(); this.input({ op: 'shortcut', surface_id: s.id, key }); }
      else if (document.activeElement === s.canvas) {
        pasteChord = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v' ? s : null;
        this.input({ op: 'key', surface_id: s.id, key: e.key, code: e.code, ctrl: e.ctrlKey, alt: e.altKey, shift: e.shiftKey, meta: e.metaKey, paste: false });
      }
    });
    window.addEventListener('paste', e => {
      const s = this.surfaceOf(document.activeElement);
      if (!e.isTrusted || !s?.canvas || document.activeElement !== s.canvas) return;
      e.preventDefault();
      pasteChord = null;
      const text = e.clipboardData?.types.includes('text/plain') ? e.clipboardData.getData('text/plain') : null;
      if (text === null || (text.length <= 1048576 && utf8.encode(text).length <= 1048576)) {
        this.input({ op: 'paste', surface_id: s.id, text });
      }
    });
    window.addEventListener('keyup', e => {
      if (e.isTrusted && pasteChord && e.key.toLowerCase() === 'v') {
        if (document.activeElement === pasteChord.canvas) this.input({ op: 'paste', surface_id: pasteChord.id, text: null });
        pasteChord = null;
      }
    });
  }
  canPress(pressedAt) { return pressedAt > this.hostControlFocus && !hostControl(document.activeElement); }
  surfaceOf(el) { return this.surfaces.get(Number(el?.closest?.('.surface')?.dataset.surfaceId)); }
  local(s, e) {
    const box = s.content.getBoundingClientRect();
    return { x: Math.round(e.clientX - box.left), y: Math.round(e.clientY - box.top) };
  }
  dropTarget(e, drop) {
    if (this.tracking !== e.pointerId) return;
    const s = this.surfaceOf(document.elementFromPoint(e.clientX, e.clientY));
    if (s) return this.input({ op: drop ? 'dnd_drop' : 'dnd_hover', surface_id: s.id, pointer_id: e.pointerId,
      ...(drop ? { button: 0 } : this.local(s, e)) });
  }
  release(e, canceled) {
    const p = this.press;
    if (!p || p.pointer !== e.pointerId) return;
    this.press = null;
    if (!canceled && this.tracking === e.pointerId) this.dropTarget(e, true);
    return this.input({ op: 'pointer_up', surface_id: p.s.id, pointer_id: e.pointerId, button: 0, canceled, ...this.local(p.s, e) });
  }
  control(s, data) {
    const surface_id = s.id;
    if (data.op === 'shortcut' && data.key === 'cancel' && this.drag) return this.end({ pointerId: this.drag.pointer }, true);
    if (data.op === 'shortcut' && data.key === 'lock') {
      window.dispatchEvent(new CustomEvent('os:lock-screen'));
      return;
    }
    // Ignore stale async iframe pointer/focus messages while a host window drag is active so
    // an in-flight MessageChannel event cannot steal focus and cancel the drag lease.
    if (this.drag && data.op !== 'pointer_up') return;
    if (data.op === 'pointer_down') {
      if (this.press && this.press.pointer !== data.pointer_id) return;
      this.press = { s, pointer: data.pointer_id };
      return this.input({ op: 'pointer_down', pointer_id: data.pointer_id, button: data.button, surface_id, hit_region: 'content', x: 0, y: 0, timestamp_ms: Date.now() });
    }
    if (data.op === 'pointer_move' || data.op === 'pointer_up') {
      if (data.op === 'pointer_up' && data.lost && this.tracking === data.pointer_id) return;
      const box = s.frame.getBoundingClientRect();
      const e = { pointerId: data.pointer_id, clientX: box.left + data.x, clientY: box.top + data.y };
      return data.op === 'pointer_up' ? this.release(e, data.canceled) : this.dropTarget(e, false);
    }
    if (['key','paste','shortcut','focus_request'].includes(data.op)) return this.input({ ...data, surface_id });
  }
  input(event) { return this.transport.input(event); }
  focus(s) {
    const target = s.frame || s.canvas;
    if (!target || this.drag?.s === s) return;
    // Never steal keyboard focus from an open host popover, menu, or modal dialog.
    const active = document.activeElement;
    if (active && active !== document.body && !this.surfaceOf(active)
      && active.closest?.('.cloud-panel-popover, .sys-menu-popover, .cc-popover, .nc-popover, .greeter-modal-overlay, dialog[open], [role="menu"]')) {
      return;
    }
    if (document.activeElement !== target) {
      target.focus({ preventScroll: true });
    }
    if (s.frame) {
      try { s.frame.contentWindow?.focus?.(); } catch {}
      queueMicrotask(() => {
        if (this.active !== s.id || this.desktop.inert || this.drag?.s === s || this.surfaces.get(s.id) !== s) return;
        const cur = document.activeElement;
        if (cur && cur !== document.body && cur !== target && !this.surfaceOf(cur)
          && cur.closest?.('.cloud-panel-popover, .sys-menu-popover, .cc-popover, .nc-popover, .greeter-modal-overlay, dialog[open], [role="menu"]')) {
          return;
        }
        if (document.activeElement !== target) {
          target.focus({ preventScroll: true });
        }
        try { s.frame.contentWindow?.focus?.(); } catch {}
      });
    }
  }
  bounds() { return { x: 0, y: 0, width: Math.max(1, this.root.clientWidth), height: Math.max(1, this.root.clientHeight) }; }
  chrome(id, s) {
    const bar = make('header', 'titlebar');
    s.bar = bar;
    const lights = make('div', 'traffic-lights');
    s.title = make('span', 'title');
    s.buttons = new Map();
    for (const [key, label, glyph] of controls) {
      const button = make('button', 'tl tl-' + key); button.type = 'button'; button.textContent = glyph; button.setAttribute('aria-label', label);
      button.title = label; s.buttons.set(key, button);
      button.onclick = () => this.input({ op: 'chrome_action', surface_id: id, state: key === 'close' ? null : key === 'minimize' ? 'minimized' : s.state === 'maximized' ? 'normal' : 'maximized' });
      lights.append(button);
    }
    const spacer = make('span', 'titlebar-spacer');
    spacer.setAttribute('aria-hidden', 'true');
    bar.append(lights, s.title, spacer);
    s.element.prepend(bar);
    bar.addEventListener('dragstart', e => e.preventDefault());
    bar.addEventListener('dblclick', e => {
      if (e.target?.closest?.('button')) return;
      if (this.drag) {
        if (this.drag.moved) return;
        this.cancel();
      }
      this.finishing = null;
      this.input({ op: 'titlebar_double_click', surface_id: id });
    });
    for (const edge of ['n','s','e','w','ne','nw','se','sw']) { const handle = make('div', 'resize'); handle.dataset.edge = edge; s.element.append(handle); }
  }
  async map(cmd) {
    if (cmd.compat_app != null) return;
    const id = cmd.surface_id, modal = ['lock','greeter'].includes(cmd.role);
    const element = make('section', 'surface'), content = make('div', 'content'), live = make('div', 'sr-only');
    element.dataset.surfaceId = id; element.dataset.role = cmd.role; element.dataset.pid = cmd.owner_pid;
    if (cmd.app_id) element.dataset.appId = cmd.app_id;
    element.setAttribute('role', modal ? 'dialog' : 'region'); element.setAttribute('aria-label', cmd.role);
    if (modal) element.setAttribute('aria-modal', 'true');
    const s = { element, content, live, role: cmd.role, id, rect: cmd.rect, state: 'normal', zIndex: ++this.z, controller: new AbortController() };
    element.style.zIndex = String(s.zIndex);
    this.surfaces.set(id, s); element.append(content, live); live.setAttribute('aria-live', 'polite');
    if (cmd.role === 'window') {
      this.chrome(id, s);
      const shield = make('div', 'focus-shield');
      shield.hidden = true;
      shield.setAttribute('aria-hidden', 'true');
      shield.addEventListener('pointerdown', e => {
        if (!e.isTrusted) return;
        e.preventDefault();
        e.stopPropagation();
        this.press = null;
        const press = { s, pointerId: e.pointerId, releasing: false };
        this.shieldPress = press;
        try { shield.setPointerCapture(e.pointerId); } catch {}
        this.input({ op: 'focus_request', surface_id: id });
      });
      for (const type of ['mousedown', 'mouseup', 'dblclick', 'auxclick', 'contextmenu']) {
        shield.addEventListener(type, e => {
          e.preventDefault();
          e.stopPropagation();
        });
      }
      shield.addEventListener('click', e => {
        e.preventDefault();
        e.stopPropagation();
        if (this.shieldPress?.s === s && this.shieldPress.releasing) {
          this.finalizeShieldRelease(this.shieldPress);
        }
      });
      s.shield = shield;
      content.append(shield);
    }
    place(element, cmd.rect); (modal ? this.modal : this.desktop).append(element);
    this.syncFocusShields();
    element.addEventListener('pointerdown', e => {
      if (!e.isTrusted || e.button !== 0) return;
      const targetEl = e.target instanceof Element ? e.target : e.target?.parentElement;
      const edge = targetEl?.dataset?.edge;
      const hit = edge ? { edge } : targetEl?.closest('.titlebar button') ? 'chrome_button' : targetEl?.closest('.titlebar') ? 'titlebar' : 'content';
      if (hit === 'chrome_button' || (hit === 'content' && e.target !== s.canvas)) return;
      if (hit === 'content' && this.drag) return;
      if (hit === 'content' && this.press && this.press.pointer !== e.pointerId) return;
      let startedDrag = null;
      let sentPointerId = e.pointerId;
      if (hit !== 'content') {
        // Recover cleanly if a previous drag lost its pointerup (e.g. macOS Mission Control).
        if (this.drag) this.end({ pointerId: this.drag.pointer }, true);
        this.press = null;
        this.finishing = null;
        e.preventDefault(); this.root.classList.add('chrome-drag');
        const captureTarget = hit === 'titlebar' && s.bar ? s.bar : element;
        const dragToken = 1_000_000 + (++this.dragSeq);
        sentPointerId = dragToken;
        startedDrag = this.drag = { s, captureTarget, start: s.rect, x: e.clientX, y: e.clientY, pointer: e.pointerId, dragToken, moved: false, latest: null, rect: s.rect, sent: new Map(), lastProgress: -Infinity };
        element.tabIndex = -1;
        if (!s.frame || document.activeElement !== s.frame) element.focus({ preventScroll: true });
        try { captureTarget.setPointerCapture(e.pointerId); } catch {}
        this.messages++;
      }
      if (hit === 'content') {
        this.press = { s, pointer: e.pointerId };
        if (e.target === s.canvas) { try { s.canvas.setPointerCapture(e.pointerId); } catch {} }
      }
      Promise.resolve(this.input({ op: 'pointer_down', surface_id: id, hit_region: hit, ...this.local(s, e), button: 0, pointer_id: sentPointerId, timestamp_ms: Date.now() }))
        .catch(() => {
          if (startedDrag && this.drag === startedDrag) this.cancel();
          if (startedDrag && this.finishing === startedDrag) this.finishing = null;
        });
    });
    element.addEventListener('focusin', e => {
      if (this.drag?.s === s) return;
      if (!hostControl(e.target) && this.active !== id) this.input({ op: 'focus_request', surface_id: id });
    });
    if (cmd.document) {
      const loader = make('div', 'surface-loading');
      loader.setAttribute('role', 'status');
      loader.setAttribute('aria-live', 'polite');
      const spin = make('span', 'loading-spinner');
      spin.setAttribute('aria-hidden', 'true');
      const lbl = make('span', 'surface-loading-label');
      lbl.textContent = 'Loading…';
      loader.append(spin, lbl);
      content.append(loader);
      try {
        s.frame = await documentFrame(cmd.document, s.titleText || 'Document', {
          port: port => this.transport.port(id, port), revoke: () => this.transport.revoke(id),
          control: data => this.control(s, data), canPress: at => this.canPress(at), error: this.transport.error,
        }, s.controller.signal);
      } catch (err) {
        loader.remove();
        throw err;
      }
      if (s.controller.signal.aborted) { loader.remove(); return; }
      s.frame.title = s.titleText || 'Document'; content.append(s.frame);
      if (this.active === id) this.focus(s);
      s.frame.addEventListener('load', () => {
        loader.remove();
        if (this.active === id && !s.controller.signal.aborted) this.focus(s);
      }, { once: true, signal: s.controller.signal });
    } else this.canvas(s, cmd.generation, null);
  }
  canvas(s, generation, backend) {
    const width = s.content.clientWidth, height = s.content.clientHeight;
    if (s.element.offsetWidth) {
      s.decoration = { width: s.element.offsetWidth - width, height: s.element.offsetHeight - height };
    }
    const el = make('canvas'); el.width = Math.max(1, width); el.height = Math.max(1, height);
    el.tabIndex = 0; el.dataset.generation = generation; el.dataset.backend = backend || 'auto'; el.setAttribute('role', 'img');
    const restore = this.active === s.id && (!s.canvas || document.activeElement === s.canvas);
    s.content.replaceChildren(el);
    if (s.shield) s.content.append(s.shield);
    s.canvas = el; this.a11y(s); if (restore) this.focus(s);
    this.transport.canvas(s.id, generation, el.transferControlToOffscreen(), backend, s.decoration);
  }
  isObscuredByHigherWindow(s) {
    if (!s || s.role !== 'window' || s.element.hidden || this.active === s.id) return false;
    const rect = (this.drag?.s === s && this.drag.rect) ? this.drag.rect : s.rect;
    const z = s.zIndex ?? (Number(s.element.style.zIndex) || 0);
    for (const other of this.surfaces.values()) {
      if (other === s || other.role !== 'window' || other.element.hidden) continue;
      const otherZ = other.zIndex ?? (Number(other.element.style.zIndex) || 0);
      if (otherZ > z || (otherZ === z && this.active === other.id)) {
        const otherRect = (this.drag?.s === other && this.drag.rect) ? this.drag.rect : other.rect;
        if (rectsOverlap(rect, otherRect)) return true;
      }
    }
    return false;
  }
  syncFocusShields() {
    for (const surf of this.surfaces.values()) {
      if (!surf.shield) continue;
      const active = this.shieldPress?.s === surf || this.isObscuredByHigherWindow(surf);
      surf.shield.hidden = !active;
      surf.element.dataset.obscured = active ? 'true' : 'false';
    }
  }
  finalizeShieldRelease(press) {
    if (!press || this.shieldPress !== press) return;
    this.shieldPress = null;
    this.syncFocusShields();
    if (this.active === press.s.id && this.surfaces.get(press.s.id) === press.s) {
      this.focus(press.s);
    }
  }
  scheduleShieldRelease(press) {
    if (!press || this.shieldPress !== press || press.releasing) return;
    press.releasing = true;
    try {
      if (press.s.shield?.hasPointerCapture?.(press.pointerId)) {
        press.s.shield.releasePointerCapture(press.pointerId);
      }
    } catch {}
    setTimeout(() => this.finalizeShieldRelease(press), 0);
  }
  a11y(s) {
    if (!s.canvas) return;
    s.canvas.setAttribute('aria-label', s.a11y?.label || s.titleText || 'Pixel surface');
    if (s.a11y?.role_description) s.canvas.setAttribute('aria-roledescription', s.a11y.role_description);
    s.live.textContent = s.a11y?.live_announcement || '';
  }
  unmountGame(s) {
    if (!s?.gameFrame) return;
    const frame = s.gameFrame;
    s.gameFrame = null;
    try { void frame.contentWindow?.signal?.dispose?.(); } catch {}
    frame.remove();
  }
  syncFilledState() {
    let anyFilled = false;
    for (const surf of this.surfaces.values()) {
      if (surf.role === 'window' && !surf.element.hidden && surf.element.dataset.filled === 'true') {
        anyFilled = true;
        break;
      }
    }
    if (this._anyFilled !== anyFilled) {
      this._anyFilled = anyFilled;
      try {
        window.dispatchEvent(new CustomEvent('os:window-filled', { detail: anyFilled }));
      } catch {}
    }
  }
  remove(id) {
    const s = this.surfaces.get(id);
    if (!s) return;
    if (document.fullscreenElement && s.element.contains(document.fullscreenElement)) {
      void document.exitFullscreen().catch(() => {});
    }
    if (this.fullscreenSurfaceId === id) this.fullscreenSurfaceId = null;
    this.unmountGame(s);
    if (this.drag?.s === s) this.cancel();
    if (this.finishing?.s === s) this.finishing = null;
    if (this.press?.s === s) this.press = null;
    if (this.shieldPress?.s === s) this.shieldPress = null;
    s.controller.abort(); s.element.remove(); this.surfaces.delete(id);
    this.syncFilledState();
    this.syncFocusShields();
  }
  async display(cmd) {
    const id = cmd.surface_id, s = this.surfaces.get(id);
    switch (cmd.op) {
      case 'dnd_tracking': this.tracking = cmd.active ? cmd.pointer_id : null; this.root.classList.toggle('dnd-active', cmd.active); return;
      case 'cancel_picker': return this.transport.cancelPick?.(cmd.request_id);
      case 'map': return this.map(cmd);
      case 'unmap': return this.remove(id);
      case 'seat_reset':
        this.cancel(); this.finishing = null; this.shieldPress = null; for (const id of [...this.surfaces.keys()]) this.remove(id);
        this.tracking = null; this.press = null; this.root.classList.remove('dnd-active'); this.desktop.inert = false; this.alerts.replaceChildren(); this.active = null; return;
      case 'geometry':
        if (!s) return;
        s.rect = cmd.rect; s.state = cmd.state; place(s.element, s.rect);
        s.element.hidden = s.element.inert = cmd.visible === false || cmd.state === 'minimized';
        s.element.dataset.filled = String(Boolean(cmd.filled));
        if (cmd.z_index) {
          s.zManaged = true;
          const z = 20 + cmd.z_index;
          s.zIndex = z;
          s.element.style.zIndex = String(z);
          if (z > this.z) this.z = z;
        }
        this.syncFilledState();
        this.syncFocusShields();
        return;
      case 'focus':
        this.desktop.inert = cmd.modal; this.alerts.hidden = cmd.modal;
        if (s) {
          const changed = this.active !== id;
          this.active = id;
          if (changed && !s.zManaged) {
            s.zIndex = ++this.z;
            s.element.style.zIndex = String(s.zIndex);
          }
          this.focus(s);
        } else this.active = id;
        this.syncFocusShields();
        return;
      case 'update_surface_chrome':
        if (!s?.title) return;
        s.titleText = s.title.textContent = cmd.chrome.title; s.element.setAttribute('aria-label', cmd.chrome.title);
        s.element.dataset.focused = cmd.chrome.focused; s.element.dataset.resizable = cmd.chrome.resizable;
        if (s.frame) s.frame.title = cmd.chrome.title;
        for (const [k, el] of s.buttons) { el.hidden = !cmd.chrome['show_' + k]; if (k === 'maximize') el.setAttribute('aria-label', cmd.chrome.state === 'maximized' ? 'Restore' : 'Maximize'); }
        return;
      case 'set_a11y': if (s) { s.a11y = cmd.a11y; this.a11y(s); } return;
      case 'recreate_pixel_canvas': if (s) this.canvas(s, cmd.generation, cmd.backend); return;
      case 'set_drag_mode': this.mode = cmd.mode; return;
      case 'begin_interactive_op': {
        const l = cmd.lease;
        const d = (this.drag && this.drag.s.id === l.surface_id && this.drag.dragToken === l.pointer_id)
          ? this.drag
          : (this.finishing && this.finishing.s.id === l.surface_id && this.finishing.dragToken === l.pointer_id)
            ? this.finishing
            : null;
        if (!d) {
          return this.input({ op: 'interactive_op_end', surface_id: l.surface_id, lease_id: l.lease_id, rect: l.start_rect, snap_hint: null, canceled: true });
        }
        this.messages++; d.lease = l; d.start = d.rect = l.start_rect;
        if (d === this.finishing || d.ended != null) {
          if (this.finishing === d) this.finishing = null;
          this.commit(d, Boolean(d.ended));
        } else if (d.latest) {
          this.draw(d);
        }
        return;
      }
      case 'drag_frame': {
        const d = this.drag;
        if (!d || d.lease?.lease_id !== cmd.lease_id) return;
        this.messages++;
        d.frame = { rect: cmd.rect, dispatch: d.sent.get(cmd.serial) };
        for (const serial of d.sent.keys()) { if (serial > cmd.serial) break; d.sent.delete(serial); }
        if (d.raf == null) d.raf = requestAnimationFrame(() => {
          d.raf = null;
          if (this.drag === d) { place(s.element, d.frame.rect); this.record(d.frame.dispatch); }
        });
        return;
      }
      case 'cancel_interactive_op': if (this.drag?.lease?.lease_id === cmd.lease_id) this.cancel(); return;
      case 'notify': {
        const el = make('div'); el.dataset.notification = cmd.id; el.textContent = 'Process ' + cmd.owner_pid + ' · ' + cmd.title + ' — ' + cmd.body; this.alerts.append(el);
        try {
          window.dispatchEvent(new CustomEvent('os:notify', {
            detail: { id: cmd.id, pid: cmd.owner_pid, title: cmd.title, body: cmd.body, at: Date.now() },
          }));
        } catch {}
        return;
      }
      case 'dismiss_notification':
        this.alerts.querySelector('[data-notification="' + cmd.id + '"]')?.remove();
        try {
          window.dispatchEvent(new CustomEvent('os:notify-dismiss', { detail: { id: cmd.id } }));
        } catch {}
        return;
      case 'clipboard_write': void this.transport.clipboard?.(cmd.item).catch(this.transport.error); return;
      case 'pick_file': return this.transport.pick(cmd);
      case 'portal': return this.transport.portal?.(cmd);
      case 'export_file': return this.transport.exportFile?.(cmd);
      case 'set_fullscreen': {
        if (!s) return;
        if (!cmd.active) {
          if (document.fullscreenElement && s.element.contains(document.fullscreenElement)) {
            void document.exitFullscreen().catch(err =>
              this.transport.fullscreenResult?.(id, false, String(err?.message ?? err)),
            );
          } else {
            this.fullscreenSurfaceId = null;
            this.transport.fullscreenResult?.(id, false, null);
          }
          return;
        }
        try {
          if (typeof s.element.requestFullscreen !== 'function') {
            throw new Error('Fullscreen API is unavailable in this environment');
          }
          if (document.fullscreenEnabled === false) {
            throw new Error('Fullscreen is not permitted for this page');
          }
          void Promise.resolve(s.element.requestFullscreen()).catch(err =>
            this.transport.fullscreenResult?.(id, false, String(err?.message ?? err)),
          );
        } catch (err) {
          this.transport.fullscreenResult?.(id, false, String(err?.message ?? err));
        }
        return;
      }
      case 'set_game_embed': {
        if (!s) return;
        this.unmountGame(s);
        if (!cmd.entry) return;
        const url = this.transport.resolveGameUrl?.(cmd.entry);
        if (!url) return;
        const gf = document.createElement('iframe');
        gf.className = 'game-embed-frame';
        gf.src = url;
        gf.title = cmd.title || cmd.entry;
        gf.allow = 'autoplay; fullscreen';
        s.gameFrame = gf;
        s.content.append(gf);
        gf.focus();
        return;
      }
      case 'media_control': return this.transport.mediaControl?.(cmd);
      case 'session_events': return this.transport.sessionEvents?.(cmd);
    }
  }
  record(dispatch) {
    if (dispatch && this.frames) this.frames.push({ x: dispatch.x, y: dispatch.y, latency: performance.now() - dispatch.at });
  }
  move(e) {
    const d = this.drag;
    if (!d || d.pointer !== e.pointerId || d.ended != null) return;
    if (e.pointerType === 'mouse' && (e.buttons & 1) === 0) {
      this.end(e, false);
      return;
    }
    if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) >= 3) d.moved = true;
    d.last = d.latest = { x: e.clientX, y: e.clientY, at: e.timeStamp };
    if (!d.lease) return;
    if (this.mode === 'roundtrip') this.draw(d);
    else if (d.raf == null) d.raf = requestAnimationFrame(() => { d.raf = null; if (this.drag === d) this.draw(d); });
  }
  draw(d) {
    if (!d.latest) return;
    const dispatch = d.latest, { x, y } = dispatch; d.latest = null;
    const serial = ++this.serial;
    const l = d.lease, b = l.bounds, rect = gestureRect(d.start, Math.round(x - d.x), Math.round(y - d.y), l); d.rect = rect;
    const area = this.root.getBoundingClientRect(), px = x - area.left, py = y - area.top;
    const snap = l.op !== 'move' ? null : py <= b.y + 12 ? 'top' : px <= b.x + 12 ? 'left' : px >= b.x + b.width - 12 ? 'right' : null;
    d.snap = l.snap_zones.includes(snap) ? snap : null; this.preview.hidden = !d.snap;
    if (d.snap) place(this.preview, d.snap === 'top' ? b : { ...b, x: b.x + (d.snap === 'right' ? Math.floor(b.width / 2) : 0), width: Math.floor(b.width / 2) });
    if (this.mode === 'local_lease') { place(d.s.element, rect); this.record(dispatch); } else if (this.frames) d.sent.set(serial, dispatch);
    const now = performance.now();
    if (this.mode === 'roundtrip' || now - d.lastProgress >= 100) {
      d.lastProgress = now; this.messages++;
      this.input({ op: 'interactive_op_progress', serial, surface_id: d.s.id, lease_id: l.lease_id, rect, snap_hint: d.snap });
    }
  }
  detachDrag(d, restore, releaseCapture = true) {
    if (this.drag === d) this.drag = null;
    this.root.classList.remove('chrome-drag');
    cancelAnimationFrame(d.raf);
    if (releaseCapture) {
      try {
        if (d.captureTarget?.hasPointerCapture(d.pointer)) d.captureTarget.releasePointerCapture(d.pointer);
      } catch {}
    }
    if (restore) place(d.s.element, d.s.rect);
    this.preview.hidden = true;
    this.syncFocusShields();
  }
  end(e, canceled) {
    const d = this.drag; if (!d || e.pointerId !== d.pointer || d.ended != null) return;
    if (!canceled && Number.isFinite(e.clientX) && (!d.last || d.last.x !== e.clientX || d.last.y !== e.clientY)) {
      d.latest = { x: e.clientX, y: e.clientY, at: e.timeStamp };
    }
    d.ended = canceled;
    this.detachDrag(d, canceled, canceled);
    if (d.lease) this.commit(d, canceled);
    else if (canceled) {
      this.input({ op: 'pointer_up', surface_id: d.s.id, pointer_id: d.dragToken, button: 0, x: 0, y: 0, canceled: true });
    } else {
      this.finishing = d;
    }
    if (this.active === d.s.id && this.surfaces.get(d.s.id) === d.s) {
      this.focus(d.s);
    }
  }
  commit(d, canceled) {
    if (d.latest) this.draw(d);
    this.preview.hidden = true;
    if (!canceled && d.snap && d.lease) {
      const b = d.lease.bounds;
      const half = Math.floor(b.width / 2);
      const snapped = d.snap === 'top' ? b : d.snap === 'left' ? { ...b, width: half } : { ...b, x: b.x + half, width: b.width - half };
      d.s.rect = snapped;
      place(d.s.element, snapped);
    } else if (!canceled && d.rect) {
      d.s.rect = d.rect;
    }
    this.syncFocusShields();
    this.messages++;
    this.input({ op: 'interactive_op_end', lease_id: d.lease.lease_id, surface_id: d.s.id, rect: d.rect, snap_hint: d.snap ?? null, canceled });
  }
  cancel() {
    const d = this.drag; if (!d) return;
    this.detachDrag(d, true);
  }
}
