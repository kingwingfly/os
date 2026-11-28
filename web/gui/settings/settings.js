(() => {
  'use strict';

  const MAX_ASSEMBLED_BYTES = 256 * 1024;
  const root = document.getElementById('settings-app');
  if (!root) return;

  let seq = 0;
  const chunks = new Map();
  let state = null;

  function send(msg) {
    const raw = JSON.stringify(msg);
    if (new TextEncoder().encode(raw).length <= 3900) {
      window.gui?.send(raw);
      return;
    }
    const id = ++seq;
    const partSize = 3200;
    const parts = [];
    for (let i = 0; i < raw.length; i += partSize) parts.push(raw.slice(i, i + partSize));
    parts.forEach((d, i) => {
      window.gui?.send(JSON.stringify({ t: 'chunk', id, i, n: parts.length, d }));
    });
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function renderMeta(dl, rows) {
    dl.replaceChildren();
    for (const [label, value, title] of rows) {
      const wrap = el('div', 'meta-item');
      wrap.append(el('dt', null, label));
      const dd = el('dd', null, value);
      if (title) dd.title = title;
      wrap.append(dd);
      dl.append(wrap);
    }
  }

  function shortUuid(id) {
    return typeof id === 'string' && id.length > 8 ? id.slice(0, 8) : (id || '—');
  }

  function buildScopeFromForm(form) {
    const fd = new FormData(form);
    const devices = [];
    if (fd.has('dev_archive')) devices.push('archive');
    if (fd.has('dev_media')) devices.push('media');
    if (fd.has('dev_present')) devices.push('present');
    if (fd.has('dev_snd')) devices.push('snd');
    const volumes = fd.has('volumes');
    const rawIds = String(fd.get('volume_ids') || '');
    const volume_ids = volumes
      ? rawIds.split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
      : [];
    return {
      cloud_fs: fd.has('cloud_fs'),
      devices,
      containers: fd.has('containers'),
      relay: fd.has('relay'),
      volumes,
      volume_ids,
      volumes_ro: volumes && fd.has('volumes_ro'),
    };
  }

  function render() {
    if (!state) return;
    const section = state.section || 'accounts';

    for (const tab of root.querySelectorAll('.settings-nav [role="tab"]')) {
      const active = tab.dataset.section === section;
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
    }
    for (const pane of root.querySelectorAll('[role="tabpanel"]')) {
      pane.hidden = pane.dataset.view !== section;
    }

    const errEl = root.querySelector('[data-error]');
    if (state.error) {
      errEl.textContent = state.error;
      errEl.hidden = false;
    } else {
      errEl.textContent = '';
      errEl.hidden = true;
    }

    const noticeEl = root.querySelector('[data-notice]');
    if (state.notice) {
      noticeEl.textContent = state.notice;
      noticeEl.hidden = false;
    } else {
      noticeEl.textContent = '';
      noticeEl.hidden = true;
    }

    const local = state.local || {};
    const cloud = state.cloud || {};
    const signedIn = Boolean(cloud.signed_in);
    const busy = Boolean(state.busy);

    const sidebarStatus = root.querySelector('[data-sidebar-status]');
    if (sidebarStatus) {
      sidebarStatus.textContent = signedIn
        ? `Cloud: ${cloud.cloud_user || 'Connected'}`
        : `Local: ${local.username || 'user'} · Offline`;
      sidebarStatus.classList.toggle('online', signedIn);
    }

    const cloudBadge = root.querySelector('[data-cloud-badge]');
    if (cloudBadge) {
      cloudBadge.textContent = signedIn ? 'ServiceAuth v2' : 'Offline / Signed out';
      cloudBadge.classList.toggle('badge-online', signedIn);
    }

    const signinForm = root.querySelector('[data-signin-form]');
    const connectedBox = root.querySelector('[data-connected-box]');
    if (signinForm) signinForm.hidden = signedIn;
    if (connectedBox) connectedBox.hidden = !signedIn;

    const signinBtn = root.querySelector('[data-signin-btn]');
    if (signinBtn) {
      signinBtn.disabled = busy;
      signinBtn.textContent = busy ? 'Signing in…' : 'Sign in to Cloud';
    }
    const signoutBtn = root.querySelector('[data-signout-btn]');
    if (signoutBtn) {
      signoutBtn.disabled = busy;
      signoutBtn.textContent = busy ? 'Signing out…' : 'Sign out of Cloud';
    }
    const scopeFieldset = root.querySelector('[data-scope-fieldset]');
    if (scopeFieldset) scopeFieldset.disabled = busy;
    for (const inp of root.querySelectorAll('#cloud-auth-user, #cloud-auth-pass')) {
      inp.disabled = busy;
    }

    if (signedIn) {
      const userEl = root.querySelector('[data-cloud-user]');
      if (userEl) userEl.textContent = cloud.cloud_user || 'cloud';
      const chips = root.querySelector('[data-scope-chips]');
      if (chips) {
        chips.replaceChildren();
        const sc = cloud.scope || {};
        const labels = [];
        if (sc.cloud_fs) labels.push(cloud.cloud_mount_active ? '/mnt/cloud (mounted)' : 'cloud_fs');
        if (Array.isArray(sc.devices) && sc.devices.length) labels.push(`devices: ${sc.devices.join(', ')}`);
        if (sc.containers) labels.push('containers');
        if (sc.volumes) labels.push(sc.volumes_ro ? 'volumes (ro)' : 'volumes');
        if (sc.relay) labels.push('relay');
        if (!labels.length) labels.push('No active remote scopes');
        for (const text of labels) chips.append(el('span', 'chip', text));
      }
    }

    const forkBadge = root.querySelector('[data-fork-badge]');
    if (forkBadge) {
      forkBadge.hidden = !local.forked_from;
      if (local.forked_from) {
        forkBadge.title = local.ephemeral_if_unmodified
          ? `O(1) fork of ${local.forked_from} (pruned on clean shutdown if unmodified)`
          : `Modified O(1) fork of ${local.forked_from} (retained)`;
      }
    }

    const localSummary = root.querySelector('[data-local-summary]');
    if (localSummary) {
      const rows = [
        ['Account', `${local.username || 'user'} (uid=${local.uid ?? 1000}, gid=${local.gid ?? 1000})`],
        ['Home', local.home || '/home/user'],
      ];
      if (local.root_volume_uuid) {
        rows.push(['Root volume', shortUuid(local.root_volume_uuid), local.root_volume_uuid]);
      }
      renderMeta(localSummary, rows);
    }

    const systemDetails = root.querySelector('[data-system-details]');
    if (systemDetails) {
      renderMeta(systemDetails, [
        ['Local account', `${local.username || 'user'} (uid=${local.uid ?? 1000}, gid=${local.gid ?? 1000})`],
        ['Home directory', local.home || '/home/user'],
        ['Local sudo', local.can_sudo ? 'Enabled (wheel)' : 'Standard user'],
        ['Root filesystem', local.root_fstype || 'cowfs'],
        ['Root volume UUID', local.root_volume_uuid || '—'],
        ['Volume lineage', local.forked_from ? `Fork of ${local.forked_from}` : 'Primary root volume'],
      ]);
    }

    const pathEl = root.querySelector('[data-settings-path]');
    if (pathEl && state.settings_path) pathEl.textContent = state.settings_path;

    const activeTheme = state.theme === 'dark' ? 'dark' : 'light';
    for (const btn of root.querySelectorAll('[data-theme-choice]')) {
      btn.setAttribute('aria-pressed', String(btn.dataset.themeChoice === activeTheme));
      btn.disabled = busy;
    }

    const autohideBtn = root.querySelector('[data-pref-autohide]');
    if (autohideBtn) {
      autohideBtn.setAttribute('aria-checked', String(Boolean(state.dock_autohide)));
      autohideBtn.disabled = busy;
    }

    const fsBtn = root.querySelector('[data-pref-fullscreen]');
    if (fsBtn) {
      fsBtn.textContent = state.fullscreen ? 'Exit Fullscreen' : 'Enter Fullscreen';
      fsBtn.disabled = busy;
    }
  }

  function triggerSignIn() {
    if (!signinForm) return;
    const userInput = signinForm.querySelector('#cloud-auth-user');
    const passInput = signinForm.querySelector('#cloud-auth-pass');
    const username = (userInput?.value || '').trim();
    const password = passInput?.value || '';
    if (!username || !password) return;
    if (passInput) passInput.value = '';
    send({
      t: 'cloud_sign_in',
      username,
      password,
      scope: buildScopeFromForm(signinForm),
    });
  }

  root.addEventListener('click', e => {
    const tab = e.target.closest('.settings-nav [role="tab"]');
    if (tab && tab.dataset.section) {
      send({ t: 'select_section', section: tab.dataset.section });
      return;
    }
    const actionBtn = e.target.closest('[data-action]');
    if (actionBtn) {
      const action = actionBtn.dataset.action;
      if (action === 'refresh') send({ t: 'refresh' });
      else if (action === 'switch-user') send({ t: 'switch_local_user' });
      else if (action === 'open-mounts') send({ t: 'open_mounts', tab: 'mounted' });
      return;
    }
    if (e.target.closest('[data-signin-btn]')) {
      triggerSignIn();
      return;
    }
    if (e.target.closest('[data-signout-btn]')) {
      send({ t: 'cloud_sign_out' });
      return;
    }
    const themeBtn = e.target.closest('[data-theme-choice]');
    if (themeBtn && state) {
      send({
        t: 'set_preferences',
        theme: themeBtn.dataset.themeChoice === 'dark' ? 'dark' : 'light',
        dock_autohide: Boolean(state.dock_autohide),
      });
      return;
    }
    if (e.target.closest('[data-pref-autohide]') && state) {
      send({
        t: 'set_preferences',
        theme: state.theme === 'dark' ? 'dark' : 'light',
        dock_autohide: !state.dock_autohide,
      });
      return;
    }
    if (e.target.closest('[data-pref-fullscreen]') && state) {
      send({ t: 'set_fullscreen', active: !state.fullscreen });
    }
  });

  const signinForm = root.querySelector('[data-signin-form]');
  if (signinForm) {
    const volToggle = signinForm.querySelector('input[name="volumes"]');
    const volExtra = signinForm.querySelector('[data-volume-extra]');
    volToggle?.addEventListener('change', () => {
      if (volExtra) volExtra.hidden = !volToggle.checked;
    });
    signinForm.addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.target.matches('input[type="text"], input[type="password"], input:not([type])')) {
        e.preventDefault();
        triggerSignIn();
      }
    });
    signinForm.addEventListener('submit', e => {
      e.preventDefault();
      triggerSignIn();
    });
  }

  function applyMsg(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.t === 'chunk') {
      let entry = chunks.get(msg.id);
      if (!entry) {
        entry = { parts: new Array(msg.n).fill(null), bytes: 0 };
        chunks.set(msg.id, entry);
      }
      if (msg.i >= 0 && msg.i < entry.parts.length && entry.parts[msg.i] === null) {
        entry.parts[msg.i] = msg.d;
        entry.bytes += msg.d.length;
      }
      if (entry.bytes > MAX_ASSEMBLED_BYTES) {
        chunks.delete(msg.id);
        return;
      }
      if (entry.parts.every(p => typeof p === 'string')) {
        chunks.delete(msg.id);
        try { applyMsg(JSON.parse(entry.parts.join(''))); } catch {}
      }
      return;
    }
    if (msg.t === 'snapshot') {
      state = msg;
      render();
    }
  }

  if (window.gui) {
    window.gui.onmessage = text => {
      try { applyMsg(JSON.parse(text)); } catch {}
    };
    send({ t: 'ready' });
  }
})();
