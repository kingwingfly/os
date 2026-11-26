(() => {
  'use strict';

  const MAX_ASSEMBLED_BYTES = 256 * 1024;
  const root = document.getElementById('mount-manager');
  if (!root) return;

  // Inline accessible custom select combobox (matching web/select-menu.js) so
  // native <select> elements inside the sealed opaque iframe share OS styling.
  function installSelectMenus() {
    let sequence = 0;
    let active;
    const controls = new Map();
    const setAttr = (node, name, value) => {
      if (node.getAttribute(name) !== String(value)) node.setAttribute(name, value);
    };
    function enhance(select) {
      if (controls.has(select) || select.multiple || select.size > 1) return;
      const controller = new AbortController();
      const listen = (node, event, fn) => node.addEventListener(event, fn, { signal: controller.signal });
      const button = document.createElement('button');
      const caption = document.createElement('span');
      const arrow = document.createElement('span');
      const menu = document.createElement('div');
      const id = `os-select-${++sequence}`;
      button.type = 'button';
      button.className = 'os-select';
      button.setAttribute('role', 'combobox');
      button.setAttribute('aria-haspopup', 'listbox');
      button.setAttribute('aria-expanded', 'false');
      caption.id = id + '-value';
      button.setAttribute('aria-describedby', caption.id);
      arrow.textContent = '⌄';
      arrow.setAttribute('aria-hidden', 'true');
      button.append(caption, arrow);
      menu.className = 'os-select-menu';
      menu.id = id;
      menu.setAttribute('role', 'listbox');
      select.classList.add('os-select-native');
      select.tabIndex = -1;
      select.setAttribute('aria-hidden', 'true');
      select.after(button);
      let options = [];
      let rows = [];
      let cursor = -1;
      let search = '';
      let searched = 0;
      const isDisabled = opt => opt.disabled || opt.parentElement?.disabled;
      function label() {
        if (select.getAttribute('aria-label')) return select.getAttribute('aria-label');
        if (select.hasAttribute('aria-labelledby')) {
          return select.getAttribute('aria-labelledby')
            .split(/\s+/)
            .map(ref => document.getElementById(ref)?.textContent ?? '')
            .join(' ')
            .trim();
        }
        return [...(select.labels ?? [])]
          .map(lbl => {
            const copy = lbl.cloneNode(true);
            copy.querySelectorAll('select,.os-select,small').forEach(node => node.remove());
            return copy.textContent.trim();
          })
          .join(' ') || 'Choose an option';
      }
      function sync() {
        const text = select.selectedOptions[0]?.label || '—';
        if (caption.textContent !== text) caption.textContent = text;
        button.disabled = select.matches(':disabled') || ![...select.options].some(opt => !isDisabled(opt));
        setAttr(button, 'aria-label', label());
        setAttr(button, 'aria-required', select.required);
        if (select.validity.valid) button.removeAttribute('aria-invalid');
        if (active === control) {
          if (button.disabled) close();
          else { render(); position(); }
        }
      }
      function highlight(index) {
        cursor = index;
        rows.forEach((row, i) => row.classList.toggle('active', i === index));
        if (rows[index]) {
          button.setAttribute('aria-activedescendant', rows[index].id);
          rows[index].scrollIntoView({ block: 'nearest' });
        } else {
          button.removeAttribute('aria-activedescendant');
        }
      }
      function render() {
        options = [...select.options];
        rows = [];
        menu.replaceChildren();
        menu.setAttribute('aria-label', label());
        for (const [index, option] of options.entries()) {
          const row = document.createElement('div');
          row.id = `${id}-${index}`;
          row.setAttribute('role', 'option');
          row.setAttribute('aria-label', option.label);
          row.setAttribute('aria-selected', String(option.selected));
          row.setAttribute('aria-disabled', String(!!isDisabled(option)));
          row.textContent = option.label;
          row.onpointerdown = event => event.preventDefault();
          row.onpointermove = () => { if (!isDisabled(option) && cursor !== index) highlight(index); };
          row.onclick = () => choose(index);
          rows.push(row);
          menu.append(row);
        }
        highlight(options[cursor] && !isDisabled(options[cursor]) ? cursor : select.selectedIndex);
      }
      function position() {
        if (active !== control) return;
        const bounds = button.getBoundingClientRect();
        const viewport = window.visualViewport;
        if (!bounds.width || !bounds.height || !button.isConnected) { close(); return; }
        const left = viewport?.offsetLeft ?? 0;
        const top = viewport?.offsetTop ?? 0;
        const width = viewport?.width ?? innerWidth;
        const height = viewport?.height ?? innerHeight;
        const menuWidth = Math.min(Math.max(bounds.width, 180), width - 16);
        menu.style.width = `${menuWidth}px`;
        menu.style.left = `${Math.max(left + 8, Math.min(bounds.left, left + width - menuWidth - 8))}px`;
        const below = top + height - bounds.bottom - 12;
        const above = bounds.top - top - 12;
        const up = below < Math.min(menu.scrollHeight, 220) && above > below;
        const available = Math.max(40, Math.min(320, up ? above : below));
        menu.style.maxHeight = `${available}px`;
        menu.style.top = `${up ? bounds.top - Math.min(menu.scrollHeight, available) - 4 : bounds.bottom + 4}px`;
      }
      function close() {
        if (active !== control) return;
        active = undefined;
        button.setAttribute('aria-expanded', 'false');
        button.removeAttribute('aria-activedescendant');
        button.removeAttribute('aria-controls');
        if (menu.hidePopover) { try { menu.hidePopover(); } catch {} }
        menu.remove();
        search = '';
      }
      function open() {
        if (button.disabled) return;
        active?.close();
        active = control;
        cursor = select.selectedIndex;
        search = '';
        document.body.append(menu);
        if (menu.showPopover) {
          try { menu.popover = 'manual'; menu.showPopover(); } catch {}
        }
        button.setAttribute('aria-expanded', 'true');
        button.setAttribute('aria-controls', id);
        render();
        position();
        highlight(cursor);
      }
      function choose(index) {
        if (!options[index] || isDisabled(options[index])) return;
        const changed = select.selectedIndex !== index;
        select.selectedIndex = index;
        close();
        sync();
        button.focus({ preventScroll: true });
        if (changed) {
          select.dispatchEvent(new Event('input', { bubbles: true }));
          select.dispatchEvent(new Event('change', { bubbles: true }));
        }
      }
      function step(delta) {
        let index = cursor;
        for (let count = 0; count < options.length; count++) {
          index = (index + delta + options.length) % options.length;
          if (!isDisabled(options[index])) { highlight(index); break; }
        }
      }
      listen(button, 'click', () => (active === control ? close() : open()));
      listen(button, 'keydown', event => {
        if (event.isComposing || event.ctrlKey || event.metaKey) return;
        const opened = active === control;
        if (event.key === 'Escape') {
          if (opened) { event.preventDefault(); event.stopPropagation(); close(); }
          return;
        }
        if (event.key === 'Tab') { if (opened) choose(cursor); return; }
        if (['Enter', ' ', 'ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
          event.preventDefault();
          event.stopPropagation();
          if (!opened) open();
          if (event.key === 'Home') { cursor = -1; step(1); }
          else if (event.key === 'End') { cursor = 0; step(-1); }
          else if (opened && event.key === 'ArrowDown') step(1);
          else if (opened && event.key === 'ArrowUp') step(-1);
          else if (opened && (event.key === 'Enter' || event.key === ' ')) choose(cursor);
        } else if (event.key.length === 1 && !event.altKey) {
          event.preventDefault();
          const now = performance.now();
          search = now - searched > 700 ? event.key : search + event.key;
          searched = now;
          options = [...select.options];
          const repeated = [...search].every(ch => ch === search[0]);
          const prefix = (repeated ? search[0] : search).toLocaleLowerCase();
          const start = repeated ? (opened ? cursor : select.selectedIndex) + 1 : 0;
          for (let offset = 0; offset < options.length; offset++) {
            const index = (start + offset) % options.length;
            if (!isDisabled(options[index]) && options[index].label.toLocaleLowerCase().startsWith(prefix)) {
              if (opened) highlight(index);
              else { const typed = search; choose(index); search = typed; }
              break;
            }
          }
        }
      });
      listen(select, 'change', sync);
      listen(select, 'focus', () => button.focus({ preventScroll: true }));
      listen(select, 'invalid', event => {
        event.preventDefault();
        button.setAttribute('aria-invalid', 'true');
        button.focus();
      });
      if (select.form) listen(select.form, 'reset', () => queueMicrotask(sync));
      const observer = new MutationObserver(sync);
      observer.observe(select, { childList: true, subtree: true, attributes: true, characterData: true });
      const resize = new ResizeObserver(position);
      resize.observe(button);
      let scheduled = false;
      for (const prop of ['value', 'selectedIndex']) {
        const own = Object.getOwnPropertyDescriptor(select, prop);
        const desc = own ?? Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, prop);
        if (!desc?.get || !desc?.set || own?.configurable === false) continue;
        Object.defineProperty(select, prop, {
          configurable: true,
          enumerable: desc.enumerable,
          get() { return desc.get.call(this); },
          set(value) {
            desc.set.call(this, value);
            if (!scheduled) {
              scheduled = true;
              queueMicrotask(() => { scheduled = false; if (!controller.signal.aborted) sync(); });
            }
          },
        });
      }
      const control = { button, menu, close, position, sync };
      controls.set(select, control);
      sync();
    }
    root.querySelectorAll('select').forEach(enhance);
    document.addEventListener('pointerdown', event => {
      if (active && !active.button.contains(event.target) && !active.menu.contains(event.target)) active.close();
    }, true);
    document.addEventListener('focusin', event => {
      if (active && event.target !== active.button && !active.menu.contains(event.target)) active.close();
    });
    document.addEventListener('scroll', event => {
      if (active && !active.menu.contains(event.target)) active.position();
    }, true);
    window.addEventListener('resize', () => active?.position());
  }

  installSelectMenus();

  const query = sel => root.querySelector(sel);
  const addForm = query('[data-add-form]');
  const exportForm = query('[data-export-form]');
  const sharedForm = query('[data-shared-form]');
  const noticeEl = query('.mount-notice');
  const connectBtn = query('[data-connect]');
  const shareBtn = query('[data-share]');
  const connectShareBtn = query('[data-connect-share]');

  let state = {
    tab: 'mounted',
    uid: 1000,
    selected: null,
    helper_mode: false,
    helper_reason: 'This browser does not expose the directory picker API that OS uses for direct host-folder mounts.',
    origin: '',
    relay_ready: false,
    submitting: false,
    ready_for_consent: false,
    notice: '',
    attachments: [],
    sources: [],
    filesystems: [],
    exports: [],
  };
  let extensionNameDraft = 'tools';
  let lastExportSourcesKey = '';

  const chunks = new Map();
  let chunkBytes = 0;

  function send(msg) {
    window.gui?.send(JSON.stringify(msg));
  }

  function makeButton(label, onClick, title) {
    const el = document.createElement('button');
    el.type = 'button';
    el.textContent = label;
    if (title) el.title = title;
    el.addEventListener('click', onClick);
    return el;
  }

  function syncAddSourceUi() {
    const kind = addForm.elements.kind.value;
    const helper = Boolean(state.helper_mode);
    for (const item of root.querySelectorAll('[data-source]')) {
      item.hidden = item.dataset.source !== kind;
    }
    query('[data-helper]').hidden = !helper;
    query('[data-save]').hidden = helper || kind !== 'host';
    query('[data-browser-limitation]').textContent = state.helper_reason || '';
    for (const field of ['url', 'token']) {
      addForm.elements[field].disabled = kind !== 'host' || !helper;
    }
    connectBtn.textContent = kind === 'storage' ? 'Mount storage' : helper ? 'Connect folder' : 'Choose folder…';
    connectBtn.disabled = !state.ready_for_consent || Boolean(state.submitting);
    const origin = state.origin || 'http://127.0.0.1:8787';
    const flags = `${addForm.elements.writable.checked ? ' --write' : ''}${addForm.elements.execute.checked ? ' --execute' : ''}`;
    query('[data-helper-command]').textContent = `os-local-helper --root /path/to/folder --origin ${origin}${flags}`;
  }

  function renderTabs() {
    const activeTab = state.tab || 'mounted';
    for (const tab of root.querySelectorAll('[data-pane]')) {
      const active = tab.dataset.pane === activeTab;
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
    }
    for (const view of root.querySelectorAll('[data-view]')) {
      view.hidden = view.dataset.view !== activeTab;
    }
  }

  function renderMounted() {
    const attachments = Array.isArray(state.attachments) ? state.attachments : [];
    const tbody = query('[data-mounts]');
    tbody.replaceChildren();
    query('[data-empty]').hidden = attachments.some(m => m.user_mount);
    query('.mount-table-scroll').hidden = attachments.length === 0;
    for (const m of attachments) {
      const row = tbody.insertRow();
      row.dataset.path = m.target;
      row.classList.toggle('selected', m.target === state.selected);
      row.insertCell().append(makeButton(m.target, () => send({ t: 'select_mount', target: m.target })));
      row.insertCell().textContent = m.kind_label || m.fstype;
      row.insertCell().textContent = (m.options || []).join(',');
      row.insertCell().textContent = m.mode_str || '—';
      row.insertCell().textContent = m.busy_summary || '';
    }

    const current = attachments.find(m => m.target === state.selected);
    const details = query('[data-details]');
    details.hidden = !current;
    const actions = query('[data-mount-actions]');
    const existingExt = actions.querySelector('input[aria-label="Extension name"]');
    if (existingExt) extensionNameDraft = existingExt.value;
    actions.replaceChildren();
    query('[data-selected]').textContent = current ? current.target : '';
    if (current) {
      query('[data-description]').textContent = [
        current.source_label,
        current.health,
        ...(current.options || []),
        current.uncertain_writes ? 'Some writes may not have completed' : '',
      ].filter(Boolean).join(' · ');
      actions.append(makeButton('Open in Files', () => send({ t: 'open_in_files', target: current.target })));
      if (current.can_unmount) {
        actions.append(makeButton(
          current.is_private_ext ? 'Deactivate' : 'Unmount',
          () => send({ t: 'unmount', target: current.target, lazy: false }),
        ));
        actions.append(makeButton(
          'Lazy unmount',
          () => send({ t: 'unmount', target: current.target, lazy: true }),
        ));
      }
      if (current.can_activate_package && current.source_id) {
        const label = document.createElement('label');
        label.textContent = 'Extension name';
        const input = document.createElement('input');
        input.value = extensionNameDraft || 'tools';
        input.maxLength = 80;
        input.setAttribute('aria-label', 'Extension name');
        input.addEventListener('input', () => { extensionNameDraft = input.value; });
        label.append(input);
        actions.append(label, makeButton('Activate package', () => {
          send({ t: 'activate_package', source_id: current.source_id, name: input.value });
        }));
      }
    }

    const fsList = query('[data-filesystems]');
    fsList.replaceChildren();
    for (const f of (state.filesystems || [])) {
      const li = document.createElement('li');
      li.textContent = `${f.label} · ${f.fstype} · ${f.bfree} of ${f.blocks} blocks free`;
      fsList.append(li);
    }

    const expList = query('[data-exports]');
    expList.replaceChildren();
    for (const e of (state.exports || [])) {
      const li = document.createElement('li');
      li.textContent = `${e.name} · ${e.address} · ${e.active_clients} clients`;
      expList.append(li);
    }

    const srcList = query('[data-sources]');
    srcList.replaceChildren();
    for (const s of (state.sources || [])) {
      const li = document.createElement('li');
      li.textContent = `${s.label} · ${s.id} · ${s.state}`;
      if (s.can_manage) {
        li.append(makeButton('Forget', () => send({ t: 'forget_source', source_id: s.id })));
      }
      if (s.can_mount) {
        li.append(makeButton('Mount', () => send({
          t: 'mount_existing_source',
          source_id: s.id,
          kind: s.kind,
          name: addForm.elements.name.value,
          writable: Boolean(s.writable),
          execute: Boolean(s.execute),
        })));
      }
      if (s.can_renew) {
        li.append(makeButton('Renew & Mount', () => send({
          t: 'renew_and_mount',
          source_id: s.id,
          kind: s.kind,
          name: addForm.elements.name.value,
          writable: Boolean(s.writable),
          execute: Boolean(s.execute),
        })));
      }
      srcList.append(li);
    }
  }

  function renderPublish() {
    const publishable = (state.attachments || []).filter(a => a.publishable);
    const key = publishable.map(a => a.target).join('\0');
    const sourceSelect = exportForm.elements.source;
    if (key !== lastExportSourcesKey) {
      lastExportSourcesKey = key;
      const prev = sourceSelect.value;
      sourceSelect.replaceChildren();
      for (const m of publishable) {
        sourceSelect.add(new Option(m.target, m.target));
      }
      if ([...sourceSelect.options].some(opt => opt.value === prev)) {
        sourceSelect.value = prev;
      }
    }
    shareBtn.disabled = !sourceSelect.length || Boolean(state.submitting);

    const shares = query('[data-shares]');
    shares.replaceChildren();
    const exports = Array.isArray(state.exports) ? state.exports : [];
    for (const grant of exports) {
      const row = document.createElement('li');
      const info = document.createElement('div');
      const name = document.createElement('strong');
      const detail = document.createElement('small');
      const address = document.createElement('input');
      name.textContent = grant.name;
      detail.textContent = `OS permissions${grant.password_protected ? ' or password' : ''} · until ${new Date(grant.expires_at).toLocaleTimeString()}`;
      address.value = grant.address;
      address.readOnly = true;
      address.setAttribute('aria-label', 'Export address');
      address.addEventListener('click', () => address.select());
      const actions = document.createElement('div');
      actions.className = 'mount-actions';
      actions.append(
        makeButton('Copy address', () => send({ t: 'copy_address', address: address.value })),
        makeButton('Stop publishing', () => send({ t: 'revoke_export', id: grant.id })),
      );
      info.append(name, detail, address);
      row.append(info, actions);
      shares.append(row);
    }
    if (!shares.children.length) {
      shares.textContent = 'No directories published.';
    }
  }

  function applySnapshot(msg) {
    state = msg;
    if (msg.reset_forms) {
      addForm.reset();
      exportForm.reset();
      sharedForm.reset();
      query('[data-mount-path]').textContent = '/mnt/local/project';
      query('[data-shared-path]').textContent = '/mnt/shared/shared';
      addForm.elements.kind.dispatchEvent(new Event('change'));
    }
    if (Array.isArray(msg.clear_fields)) {
      if (msg.clear_fields.includes('token')) addForm.elements.token.value = '';
      if (msg.clear_fields.includes('password')) sharedForm.elements.password.value = '';
      if (msg.clear_fields.includes('export_password')) exportForm.elements.password.value = '';
    }
    noticeEl.textContent = typeof msg.notice === 'string' ? msg.notice : '';
    renderTabs();
    renderMounted();
    renderPublish();
    syncAddSourceUi();
    connectShareBtn.disabled = Boolean(state.submitting);
  }

  function dispatch(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.t === 'chunk') {
      const { id, i, n, d } = msg;
      if (typeof id !== 'number' || typeof i !== 'number' || typeof n !== 'number' || typeof d !== 'string') return;
      if (n <= 0 || n > 256 || i < 0 || i >= n) return;
      let bucket = chunks.get(id);
      if (!bucket || bucket.parts.length !== n) {
        if (bucket) chunkBytes = Math.max(0, chunkBytes - bucket.bytes);
        bucket = { parts: new Array(n).fill(null), received: 0, bytes: 0 };
        chunks.set(id, bucket);
      }
      if (bucket.parts[i] !== null) return;
      if (chunkBytes + d.length > MAX_ASSEMBLED_BYTES) {
        chunks.clear();
        chunkBytes = 0;
        return;
      }
      bucket.parts[i] = d;
      bucket.received += 1;
      bucket.bytes += d.length;
      chunkBytes += d.length;
      if (bucket.received === n) {
        chunks.delete(id);
        chunkBytes = Math.max(0, chunkBytes - bucket.bytes);
        try { dispatch(JSON.parse(bucket.parts.join(''))); } catch {}
      }
      return;
    }
    if (msg.t === 'snapshot') {
      applySnapshot(msg);
    } else if (msg.t === 'notice') {
      noticeEl.textContent = typeof msg.text === 'string' ? msg.text : '';
      state.submitting = Boolean(msg.submitting);
      syncAddSourceUi();
      connectShareBtn.disabled = Boolean(state.submitting);
    }
  }

  // Tab bar interaction + ARIA roving tabindex keyboard navigation.
  const tabs = [...root.querySelectorAll('[data-pane]')];
  for (const tab of tabs) {
    tab.addEventListener('click', () => {
      state.tab = tab.dataset.pane;
      renderTabs();
      send({ t: 'select_tab', tab: tab.dataset.pane });
    });
    tab.addEventListener('keydown', event => {
      const index = tabs.indexOf(tab);
      const next = ['ArrowRight', 'ArrowDown'].includes(event.key)
        ? (index + 1) % tabs.length
        : ['ArrowLeft', 'ArrowUp'].includes(event.key)
        ? (index + tabs.length - 1) % tabs.length
        : event.key === 'Home' ? 0
        : event.key === 'End' ? tabs.length - 1
        : null;
      if (next !== null) {
        event.preventDefault();
        tabs[next].focus();
        state.tab = tabs[next].dataset.pane;
        renderTabs();
        send({ t: 'select_tab', tab: tabs[next].dataset.pane });
      }
    });
  }

  query('[data-action="add"]').addEventListener('click', () => {
    state.tab = 'add';
    renderTabs();
    send({ t: 'select_tab', tab: 'add' });
  });
  query('[data-action="refresh"]').addEventListener('click', () => send({ t: 'refresh' }));
  query('[data-action="sharing-refresh"]').addEventListener('click', () => send({ t: 'refresh' }));

  addForm.elements.kind.addEventListener('change', syncAddSourceUi);
  addForm.elements.writable.addEventListener('change', syncAddSourceUi);
  addForm.elements.execute.addEventListener('change', syncAddSourceUi);
  addForm.elements.name.addEventListener('input', () => {
    query('[data-mount-path]').textContent = '/mnt/local/' + addForm.elements.name.value;
  });

  function submitAdd(event) {
    event?.preventDefault?.();
    if (!addForm.reportValidity() || state.submitting) return;
    const kind = addForm.elements.kind.value;
    const name = addForm.elements.name.value;
    const writable = addForm.elements.writable.checked;
    const execute = addForm.elements.execute.checked;
    const cloud = addForm.elements.cloud.checked;
    noticeEl.textContent = '';
    if (kind === 'storage') {
      send({ t: 'mount_opfs', name, writable, execute, cloud });
    } else if (state.helper_mode) {
      send({
        t: 'mount_helper',
        name,
        url: addForm.elements.url.value,
        token: addForm.elements.token.value,
        writable,
        execute,
        cloud,
      });
    } else {
      send({
        t: 'pick_host_folder',
        name,
        writable,
        execute,
        cloud,
        save: addForm.elements.save.checked,
      });
    }
  }
  connectBtn.addEventListener('click', submitAdd);
  addForm.addEventListener('keydown', event => {
    if (event.key === 'Enter' && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      submitAdd();
    }
  });

  function submitExport(event) {
    event?.preventDefault?.();
    if (!exportForm.reportValidity() || !exportForm.elements.source.value) return;
    noticeEl.textContent = '';
    send({
      t: 'publish_export',
      source: exportForm.elements.source.value,
      subpath: exportForm.elements.path.value,
      name: exportForm.elements.name.value,
      seconds: Number(exportForm.elements.seconds.value) || 900,
      password: exportForm.elements.password.value,
    });
  }
  shareBtn.addEventListener('click', submitExport);
  exportForm.addEventListener('keydown', event => {
    if (event.key === 'Enter' && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      submitExport();
    }
  });

  sharedForm.elements.name.addEventListener('input', () => {
    query('[data-shared-path]').textContent = '/mnt/shared/' + sharedForm.elements.name.value;
  });
  function submitShared(event) {
    event?.preventDefault?.();
    if (!sharedForm.reportValidity() || state.submitting) return;
    noticeEl.textContent = '';
    send({
      t: 'connect_share',
      name: sharedForm.elements.name.value,
      address: sharedForm.elements.address.value.trim(),
      password: sharedForm.elements.password.value,
      writable: sharedForm.elements.writable.checked,
      execute: sharedForm.elements.execute.checked,
    });
  }
  connectShareBtn.addEventListener('click', submitShared);
  sharedForm.addEventListener('keydown', event => {
    if (event.key === 'Enter' && event.target instanceof HTMLInputElement) {
      event.preventDefault();
      submitShared();
    }
  });

  if (typeof ResizeObserver !== 'undefined') {
    const nav = query('.mount-nav');
    new ResizeObserver(entries => {
      nav.setAttribute('aria-orientation', entries[0].contentRect.width <= 720 ? 'horizontal' : 'vertical');
    }).observe(root);
  }

  window.gui.onmessage = raw => {
    try { dispatch(JSON.parse(raw)); } catch {}
  };

  syncAddSourceUi();
  send({ t: 'ready' });
})();
