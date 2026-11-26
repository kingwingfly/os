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
const make = (tag, cls) => { const el = document.createElement(tag); if (cls) el.className = cls; return el; };
const controls = [['minimize', 'Minimize', '−'], ['maximize', 'Maximize', '□'], ['close', 'Close', '×']];
const hostControl = el => el?.closest?.('nav, .picker, .titlebar button');
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
    this.frames = null;
    this.hostControlFocus = -Infinity;
    let pasteChord = null;
    window.addEventListener('pointermove', e => {
      if (!e.isTrusted) return;
      if (this.drag) return this.move(e);
      if (this.tracking != null) return this.dropTarget(e, false);
      const s = this.surfaceOf(e.target);
      if (s?.canvas === e.target && document.activeElement === s.canvas) {
        this.input({ op: 'pointer_move', surface_id: s.id, pointer_id: e.pointerId, ...this.local(s, e) });
      }
    });
    const release = (e, canceled) => {
      if (!e.isTrusted || (!canceled && e.button !== 0)) return;
      if (this.drag) { this.end(e, canceled); return; }
      this.release(e, canceled);
    };
    window.addEventListener('pointerup', e => release(e, false), true);
    for (const type of ['pointercancel', 'lostpointercapture']) window.addEventListener(type, e => release(e, true), true);
    window.addEventListener('blur', () => setTimeout(() => {
      if (!document.hasFocus()) {
        if (this.drag) this.end({ pointerId: this.drag.pointer }, true);
        this.press = null;
        this.input({ op: 'host_focus' });
      }
    }, 0));
    window.addEventListener('focusin', e => {
      pasteChord = null;
      const control = hostControl(e.target);
      if (control) this.hostControlFocus = Math.max(this.hostControlFocus, performance.timeOrigin + e.timeStamp);
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
    if (data.op === 'shortcut' && data.key === 'cancel' && this.drag) return this.end({ pointerId: this.drag.pointer }, true);
    if (['key','paste','shortcut','focus_request'].includes(data.op)) return this.input({ ...data, surface_id });
  }
  input(event) { return this.transport.input(event); }
  focus(s) {
    const target = s.frame || s.canvas;
    if (!target || document.activeElement === target || this.drag?.s === s) return;
    // Never steal keyboard focus from an open host popover, menu, or modal dialog.
    const active = document.activeElement;
    if (active && active !== document.body && !this.surfaceOf(active)
      && active.closest?.('.cloud-panel-popover, .greeter-modal-overlay, dialog[open], [role="menu"]')) {
      return;
    }
    target.focus({ preventScroll: true });
  }
  bounds() { return { x: 0, y: 0, width: Math.max(1, this.root.clientWidth), height: Math.max(1, this.root.clientHeight) }; }
  chrome(id, s) {
    const bar = make('header', 'titlebar'); s.title = make('span', 'title');
    bar.append(s.title); s.buttons = new Map();
    for (const [key, label, glyph] of controls) {
      const button = make('button'); button.type = 'button'; button.textContent = glyph; button.setAttribute('aria-label', label);
      button.title = label; s.buttons.set(key, button);
      button.onclick = () => this.input({ op: 'chrome_action', surface_id: id, state: key === 'close' ? null : key === 'minimize' ? 'minimized' : s.state === 'maximized' ? 'normal' : 'maximized' });
      bar.append(button);
    }
    s.element.prepend(bar);
    bar.addEventListener('dblclick', e => {
      if (!e.target?.closest?.('button')) this.input({ op: 'titlebar_double_click', surface_id: id });
    });
    for (const edge of ['n','s','e','w','ne','nw','se','sw']) { const handle = make('div', 'resize'); handle.dataset.edge = edge; s.element.append(handle); }
  }
  async map(cmd) {
    if (cmd.compat_app != null) {
      this.transport.compatDisplay?.(cmd);
      return;
    }
    const id = cmd.surface_id, modal = ['lock','greeter'].includes(cmd.role);
    const element = make('section', 'surface'), content = make('div', 'content'), live = make('div', 'sr-only');
    element.dataset.surfaceId = id; element.dataset.role = cmd.role; element.dataset.pid = cmd.owner_pid;
    if (cmd.app_id) element.dataset.appId = cmd.app_id;
    element.setAttribute('role', modal ? 'dialog' : 'region'); element.setAttribute('aria-label', cmd.role);
    if (modal) element.setAttribute('aria-modal', 'true');
    const s = { element, content, live, role: cmd.role, id, rect: cmd.rect, state: 'normal', controller: new AbortController() };
    this.surfaces.set(id, s); element.append(content, live); live.setAttribute('aria-live', 'polite');
    if (cmd.role === 'window') this.chrome(id, s);
    place(element, cmd.rect); (modal ? this.modal : this.desktop).append(element);
    element.addEventListener('pointerdown', e => {
      if (!e.isTrusted || e.button !== 0 || this.drag || (this.press && this.press.pointer !== e.pointerId)) return;
      const edge = e.target.dataset.edge;
      const hit = edge ? { edge } : e.target.closest('.titlebar button') ? 'chrome_button' : e.target.closest('.titlebar') ? 'titlebar' : 'content';
      if (hit === 'chrome_button' || (hit === 'content' && e.target !== s.canvas)) return;
      if (hit !== 'content') {
        e.preventDefault(); this.root.classList.add('chrome-drag');
        this.drag = { s, start: s.rect, x: e.clientX, y: e.clientY, pointer: e.pointerId, latest: null, rect: s.rect, sent: new Map(), lastProgress: -Infinity };
        element.tabIndex = -1;
        if (!s.frame || document.activeElement !== s.frame) element.focus({ preventScroll: true });
        element.setPointerCapture(e.pointerId);
        this.messages++;
      }
      if (hit === 'content') {
        this.press = { s, pointer: e.pointerId };
        if (e.target === s.canvas) s.canvas.setPointerCapture(e.pointerId);
      }
      this.input({ op: 'pointer_down', surface_id: id, hit_region: hit, ...this.local(s, e), button: 0, pointer_id: e.pointerId, timestamp_ms: Date.now() });
    });
    element.addEventListener('focusin', e => {
      if (!hostControl(e.target) && this.active !== id) this.input({ op: 'focus_request', surface_id: id });
    });
    if (cmd.document) {
      s.frame = await documentFrame(cmd.document, s.titleText || 'Document', {
        port: port => this.transport.port(id, port), revoke: () => this.transport.revoke(id),
        control: data => this.control(s, data), canPress: at => this.canPress(at), error: this.transport.error,
      }, s.controller.signal);
      if (s.controller.signal.aborted) return;
      s.frame.title = s.titleText || 'Document'; content.append(s.frame);
      if (this.active === id) this.focus(s);
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
    s.content.replaceChildren(el); s.canvas = el; this.a11y(s); if (restore) this.focus(s);
    this.transport.canvas(s.id, generation, el.transferControlToOffscreen(), backend, s.decoration);
  }
  a11y(s) {
    if (!s.canvas) return;
    s.canvas.setAttribute('aria-label', s.a11y?.label || s.titleText || 'Pixel surface');
    if (s.a11y?.role_description) s.canvas.setAttribute('aria-roledescription', s.a11y.role_description);
    s.live.textContent = s.a11y?.live_announcement || '';
  }
  remove(id) {
    const s = this.surfaces.get(id);
    if (!s) return;
    if (this.drag?.s === s) this.cancel();
    if (this.press?.s === s) this.press = null;
    s.controller.abort(); s.element.remove(); this.surfaces.delete(id);
  }
  async display(cmd) {
    const id = cmd.surface_id, s = this.surfaces.get(id);
    switch (cmd.op) {
      case 'dnd_tracking': this.tracking = cmd.active ? cmd.pointer_id : null; this.root.classList.toggle('dnd-active', cmd.active); return;
      case 'cancel_picker': return this.transport.cancelPick?.(cmd.request_id);
      case 'map': return this.map(cmd);
      case 'unmap': return this.remove(id);
      case 'seat_reset':
        this.cancel(); for (const id of [...this.surfaces.keys()]) this.remove(id);
        this.tracking = null; this.press = null; this.root.classList.remove('dnd-active'); this.desktop.inert = false; this.alerts.replaceChildren(); this.active = null; return;
      case 'geometry':
        if (!s) return;
        s.rect = cmd.rect; s.state = cmd.state; place(s.element, s.rect);
        s.element.hidden = s.element.inert = cmd.visible === false || cmd.state === 'minimized';
        s.element.dataset.filled = String(Boolean(cmd.filled));
        if (cmd.z_index) {
          s.zManaged = true;
          const z = 20 + cmd.z_index;
          s.element.style.zIndex = String(z);
          if (z > this.z) this.z = z;
        }
        return;
      case 'focus':
        this.desktop.inert = cmd.modal; this.alerts.hidden = cmd.modal;
        if (s) {
          const changed = this.active !== id;
          this.active = id;
          if (changed && !s.zManaged) s.element.style.zIndex = String(++this.z);
          this.focus(s);
        } else this.active = id;
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
        const d = this.drag, l = cmd.lease;
        if (d?.s.id !== l.surface_id || d.pointer !== l.pointer_id) {
          return this.input({ op: 'interactive_op_end', surface_id: l.surface_id, lease_id: l.lease_id, rect: l.start_rect, snap_hint: null, canceled: true });
        }
        this.messages++; d.lease = l; d.start = d.rect = l.start_rect;
        if (d.latest) this.draw(d);
        if (d.ended != null) this.commit(d, d.ended);
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
        const el = make('div'); el.dataset.notification = cmd.id; el.textContent = 'Process ' + cmd.owner_pid + ' · ' + cmd.title + ' — ' + cmd.body; this.alerts.append(el); return;
      }
      case 'dismiss_notification': this.alerts.querySelector('[data-notification="' + cmd.id + '"]')?.remove(); return;
      case 'clipboard_write': void this.transport.clipboard?.(cmd.item).catch(this.transport.error); return;
      case 'pick_file': return this.transport.pick(cmd);
      case 'mount_consent': return this.transport.mountConsent?.(cmd);
    }
  }
  record(dispatch) {
    if (dispatch && this.frames) this.frames.push({ x: dispatch.x, y: dispatch.y, latency: performance.now() - dispatch.at });
  }
  move(e) {
    const d = this.drag;
    if (!d || d.pointer !== e.pointerId || d.ended != null) return;
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
  end(e, canceled) {
    const d = this.drag; if (!d || e.pointerId !== d.pointer || d.ended != null) return;
    if (!canceled && Number.isFinite(e.clientX) && (!d.last || d.last.x !== e.clientX || d.last.y !== e.clientY)) {
      d.latest = { x: e.clientX, y: e.clientY, at: e.timeStamp };
    }
    d.ended = canceled;
    if (d.lease) this.commit(d, canceled);
    else if (canceled) {
      this.cancel();
      this.input({ op: 'pointer_up', surface_id: d.s.id, pointer_id: d.pointer, button: 0, x: 0, y: 0, canceled: true });
    }
  }
  commit(d, canceled) {
    if (d.latest) this.draw(d);
    if (!canceled && d.snap && d.lease) {
      const b = d.lease.bounds;
      const half = Math.floor(b.width / 2);
      const snapped = d.snap === 'top' ? b : d.snap === 'left' ? { ...b, width: half } : { ...b, x: b.x + half, width: b.width - half };
      place(d.s.element, snapped);
    }
    this.messages++;
    this.input({ op: 'interactive_op_end', lease_id: d.lease.lease_id, surface_id: d.s.id, rect: d.rect, snap_hint: d.snap ?? null, canceled });
  }
  cancel() {
    const d = this.drag; if (!d) return;
    this.drag = null; this.root.classList.remove('chrome-drag');
    cancelAnimationFrame(d.raf); if (d.s.element.hasPointerCapture(d.pointer)) d.s.element.releasePointerCapture(d.pointer);
    place(d.s.element, d.s.rect); this.preview.hidden = true; this.drag = null;
  }
}
