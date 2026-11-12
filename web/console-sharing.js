import { entry, entryPath } from './release.js';
import { currentSeat, consoleStatus, grantConsole, revokeConsole, stopConsoleSharing, loginSession, configureSeatSharing } from './kernel/page.js';
import { sharingAllowed } from './kernel/sharing-policy.js';

// Only a window opened by this action can receive the paired port. The URL,
// window name and readiness nonce are not grants and contain no credentials.
export function installConsoleSharing() {
  const dialog = document.getElementById('console-share');
  const form = dialog.querySelector('form'), error = document.getElementById('console-share-error');
  const windows = new Set();
  let selected, preference, resumeFocus, activeSeat = currentSeat().active;
  const save = document.getElementById('console-share-save');
  const policyControls = value => {
    preference = value?.session;
    form.elements.sharing.value = preference?.seat_policy?.sharing ?? 'none';
    form.elements.sharing.disabled = save.disabled = !value?.connected;
    form.elements.access[0].disabled = !sharingAllowed(value, 'view');
    form.elements.access[1].disabled = !sharingAllowed(value, 'control') || !!consoleStatus(selected?.terminalId)?.control;
    if (form.elements.access[1].disabled) form.elements.access.value = 'view';
    form.querySelector('[type=submit]').disabled = !sharingAllowed(value, 'view');
  };
  const text = (element, value) => { if (element.textContent !== value) element.textContent = value; };
  const update = () => {
    for (const panel of document.querySelectorAll('.terminal-panel[data-terminal]')) {
      const status = consoleStatus(panel.dataset.terminal), actions = panel.querySelector('.console-actions');
      if (!actions) continue;
      // Keep the toolbar in place while short commands start and finish.
      actions.hidden = false;
      actions.querySelector('[data-console-open]').disabled = !status?.ready;
      actions.querySelector('[data-console-stop]').hidden = !status?.count;
      text(actions.querySelector('.console-status'), !currentSeat().active ? 'Terminal input paused' : status?.control ? 'Keyboard in another window' : status?.count ? `Shared with ${status.count} window${status.count === 1 ? '' : 's'}` : '');
      panel.querySelector('.command-input').disabled = !currentSeat().active || !!status?.control;
      for (const button of panel.querySelectorAll('.touch-keys button')) button.disabled = !currentSeat().active || !!status?.control;
    }
  };
  const release = record => {
    if (!windows.delete(record)) return;
    clearTimeout(record.timer); record.port?.close();
    if (record.grant) void revokeConsole(record.grant).catch(() => {});
  };
  const fail = (record, message) => {
    if (!record.nonce && !record.window.closed) { record.error = message; return; }
    try { record.window.postMessage({ type: 'os-console-error', nonce: record.nonce, message }, location.origin); } catch { /* window gone */ }
    release(record);
  };
  const deliver = record => {
    if (record.error && record.nonce) { fail(record, record.error); return; }
    if (!record.grant || !record.nonce || record.sent || !windows.has(record)) return;
    try {
      // Navigation or reload invalidates the prepared receiver. Never deliver a
      // delayed grant to an unrelated document in the same WindowProxy.
      if (!['/console', '/console.html'].includes(entryPath(record.window.location.pathname))) throw new Error('The attached window navigated away.');
      record.window.postMessage({ type: 'os-console-port', nonce: record.nonce }, location.origin, [record.port]);
      record.sent = true; record.port = null; clearTimeout(record.timer);
    } catch { fail(record, 'The attached window is no longer available.'); }
  };
  window.addEventListener('message', event => {
    if (event.origin !== location.origin) return;
    const record = [...windows].find(record => record.window === event.source);
    if (!record) return;
    if (event.data?.type === 'os-console-ready' && !record.nonce && typeof event.data.nonce === 'string' && event.data.nonce.length === 36) {
      record.nonce = event.data.nonce; deliver(record);
    } else if (event.data?.type === 'os-console-left' && event.data.nonce === record.nonce) release(record);
  });
  document.addEventListener('click', event => {
    const button = event.target.closest?.('[data-console-open],[data-console-stop]');
    if (!button) return;
    const terminalId = button.closest('[data-terminal]').dataset.terminal, status = consoleStatus(terminalId);
    if (button.hasAttribute('data-console-stop')) {
      if (status) void stopConsoleSharing(status.run).then(() => document.getElementById('command')?.focus()).catch(() => {});
      return;
    }
    if (!status?.ready) return;
    selected = { terminalId, run: status.run };
    form.reset(); error.textContent = '';
    policyControls(null);
    dialog.showModal();
    const opening = selected;
    void loginSession().then(value => { if (dialog.open && opening === selected) policyControls(value); })
      .catch(() => { error.textContent = 'Reconnect to load sharing preferences.'; });
  });
  save.onclick = async () => {
    save.disabled = true;
    try {
      await configureSeatSharing(form.elements.sharing.value, preference);
      policyControls(await loginSession());
      error.textContent = 'Preference saved.';
    } catch {
      error.textContent = 'The account or preference changed. Reopen this dialog and try again.';
    } finally { save.disabled = !preference; }
  };
  document.getElementById('console-share-cancel').onclick = () => dialog.close();
  form.onsubmit = event => {
    event.preventDefault();
    if (!selected) return;
    if (windows.size >= 16) { error.textContent = 'Close an attached window before opening another.'; return; }
    // Open synchronously from the click, before any asynchronous kernel request.
    const recipient = window.open(entry('/console.html'), '_blank', 'popup,width=960,height=640');
    if (!recipient) { error.textContent = 'Allow pop-ups for this site, then try again.'; return; }
    const channel = new MessageChannel();
    const record = { window: recipient, port: channel.port2 };
    windows.add(record);
    record.timer = setTimeout(() => { fail(record, 'The connection timed out. Open a new window to try again.'); release(record); }, 30_000);
    const { terminalId, run } = selected, access = form.elements.access.value;
    dialog.close();
    void grantConsole(terminalId, channel.port1, { access, run }).then(grant => {
      if (!windows.has(record)) { void revokeConsole(grant).catch(() => {}); return; }
      record.grant = grant; deliver(record);
    }).catch(() => fail(record, 'The selected command is no longer available.'));
  };
  setInterval(() => { for (const record of windows) if (record.window.closed) release(record); }, 1000);
  window.addEventListener('os:console-state', update);
  window.addEventListener('os:seat', () => {
    const active = currentSeat().active;
    if (activeSeat && !active) resumeFocus = document.activeElement?.classList.contains('command-input') ? document.activeElement : null;
    update();
    if (!activeSeat && active && resumeFocus) {
      const input = resumeFocus; resumeFocus = null;
      requestAnimationFrame(() => {
        if (input.isConnected && !input.disabled && !input.closest('.terminal-panel')?.hidden &&
            !document.querySelector('dialog[open]:modal') && [document.body, input].includes(document.activeElement)) {
          input.blur(); input.focus();
        }
      });
    }
    activeSeat = active;
  });
  new MutationObserver(update).observe(document.getElementById('app'), { childList: true, subtree: true });
  update();
}
