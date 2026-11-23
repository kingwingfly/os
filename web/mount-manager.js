import { kernelCall } from './kernel/protocol.js';
import { registerPickedFolder, registerHelperFolder, registerSharedFolder, prepareRenewal } from './kernel/source-registry.js';
import { shareMount, revokeMount } from './mount-sharing-ui.js';

let manager;
const kinds = {
  directory: 'Host folder · browser',
  'native-directory': 'Host folder · helper',
  'browser-storage': 'Browser storage',
  snapshot: 'File image',
  'private-extension': 'Private extension',
  shared: 'Shared directory',
  tmpfs: 'Memory filesystem · tmpfs',
  image: 'Image filesystem',
  cloud: 'Cloud filesystem',
  proc: 'Process filesystem · proc',
  devtmpfs: 'Device filesystem · devtmpfs',
  devpts: 'Pseudo-terminals · devpts',
  opfs: 'Browser storage',
  hostfs: 'Host folder · browser',
  helperfs: 'Host folder · helper',
  sharefs: 'Shared directory',
};
const button = (label, action, title) => {
  const element = document.createElement('button'); element.type = 'button'; element.textContent = label;
  if (title) element.title = title;
  element.onclick = async () => { element.disabled = true; try { await action(); } finally { element.disabled = false; } };
  return element;
};
const permissionGrid = () => `<table class="mount-mode" aria-label="Mount permissions"><thead><tr><th>Class</th><th>r</th><th>w</th><th>x</th></tr></thead><tbody>
  <tr><th scope="row">u</th><td><input type="checkbox" checked disabled aria-label="User read"></td><td><input type="checkbox" name="writable" aria-label="User write"></td><td><input type="checkbox" name="execute" checked aria-label="User execute"></td></tr>
  <tr><th scope="row">g</th><td colspan="3" title="Initially no access; change with chmod or setfacl">—</td></tr>
  <tr><th scope="row">o</th><td colspan="3" title="Initially no access; change with chmod or setfacl">—</td></tr></tbody></table>`;

export function openMountManager(pane = 'mounted') {
  if (!manager) manager = createManager(document.getElementById('mount-manager'));
  dispatchEvent(new Event('os-open-mounts'));
  manager.show(pane);
}

function createManager(root) {
  if (!root) throw new Error('Open Mounts from the desktop.');
  root.innerHTML = `<nav class="mount-nav" role="tablist" aria-label="Mount manager">
      <button type="button" role="tab" id="mount-tab-mounted" aria-controls="mount-pane-mounted" data-pane="mounted">Mounted</button>
      <button type="button" role="tab" id="mount-tab-add" aria-controls="mount-pane-add" data-pane="add">Add mount</button>
      <button type="button" role="tab" id="mount-tab-connect" aria-controls="mount-pane-connect" data-pane="connect">Connect</button>
      <button type="button" role="tab" id="mount-tab-publish" aria-controls="mount-pane-publish" data-pane="publish">Publish</button>
    </nav><div class="mount-content"><p class="mount-notice" role="status"></p>
    <section role="tabpanel" id="mount-pane-mounted" aria-labelledby="mount-tab-mounted" data-view="mounted">
      <div class="mount-pane-heading"><div><h2>Attachments</h2></div><button type="button" data-action="refresh">Refresh</button></div>
      <div class="mount-table-scroll"><table class="mount-table"><thead><tr><th>Mount point</th><th>Source</th><th>Mount options</th><th>Busy processes</th></tr></thead><tbody data-mounts></tbody></table></div>
      <div class="mount-empty" data-empty><span aria-hidden="true">▱</span><p>No filesystems mounted.</p><button type="button" data-action="add">Add mount</button></div>
      <section class="mount-details" data-details hidden aria-label="Selected mount"><div><h3 data-selected></h3><p data-description></p></div><div class="mount-actions" data-mount-actions></div></section>
      <section><h2>Sources</h2><ul data-sources></ul></section>
      <section><h2>Filesystems</h2><ul data-filesystems></ul></section>
      <section><h2>Exports</h2><ul data-exports></ul></section>
    </section>
    <section role="tabpanel" id="mount-pane-add" aria-labelledby="mount-tab-add" data-view="add" hidden>
      <div class="mount-pane-heading"><div><h2>Mount local storage</h2><p>Choose an existing filesystem and where to mount it.</p></div></div>
      <form class="mount-form" data-add-form>
        <div class="mount-fields"><label>Source<select name="kind"><option value="host">Host folder</option><option value="storage">Browser storage</option></select></label>
          <label>Mount name<input name="name" aria-label="Mount name" aria-describedby="local-mount-path" value="project" required pattern="[a-zA-Z0-9_.\\-]+" maxlength="80" autocomplete="off"><small id="local-mount-path" data-mount-path>/mnt/local/project</small></label></div>
        <div class="mount-source" data-source="host"><p>Use a folder on this computer. Read and write its files in place.</p>
          <div data-helper hidden><p data-browser-limitation></p><p>Use <strong>Chrome or Edge on macOS, Windows or Linux</strong> to mount folders directly.</p>
            <p>To stay in this browser, connect <code>os-local-helper</code> (currently Linux only).</p>
            <pre class="mount-helper-command"><code data-helper-command></code></pre>
            <div class="mount-fields"><label>Helper URL<input name="url" type="url" placeholder="http://127.0.0.1:port/" required></label><label>Token<input name="token" type="password" required autocomplete="off"></label></div></div></div>
        <div class="mount-source" data-source="storage" hidden><p>This browser profile’s OS workspace. Mounting it again opens the same files at another path; it does not create a new disk. Unmounting keeps the files.</p></div>
        <div class="mount-grants"><div><h3>Mount access</h3>${permissionGrid()}<p>Host file modes are unchanged. Private by default. Use chmod or setfacl to define OS account access.</p></div>
          <label class="mount-check"><input name="cloud" type="checkbox">Cloud access<small>Let programs use your cloud files and services.</small></label></div>
        <label data-save><input type="checkbox" name="save"> Save folder permission for this account</label>
        <div class="mount-actions"><button type="submit" class="primary" data-connect disabled>Choose folder…</button></div>
      </form>
    </section>
    <section role="tabpanel" id="mount-pane-publish" aria-labelledby="mount-tab-publish" data-view="publish" hidden>
      <div class="mount-pane-heading"><div><h2>Publish a directory</h2><p>Offer a folder to other OS accounts. Keep this tab online.</p></div><button type="button" data-action="sharing-refresh">Refresh</button></div>
      <section class="mount-sharing-section"><h3>Published by you</h3><ul class="mount-share-list" data-shares></ul></section>
      <form class="mount-form mount-export" data-export-form><h3>New export</h3><div class="mount-fields">
        <label>Filesystem<select name="source" required></select></label><label>Subdirectory<input name="path" placeholder="Whole filesystem" autocomplete="off"></label>
        <label>Name<input name="name" value="shared" maxlength="80" required></label>
        <label>Expires in<select name="seconds"><option value="300">5 minutes</option><option value="900" selected>15 minutes</option><option value="3600">1 hour</option></select></label>
        <label>Export password (optional)<input type="password" name="password" maxlength="256" autocomplete="new-password"></label></div>
        <p class="mount-hint">Use <code>chmod</code> or <code>setfacl</code> to allow other accounts. An optional password grants your access inside this directory, within the source mount’s limits. Receivers choose whether to mount.</p>
        <div class="mount-actions"><button type="submit" class="primary" data-share disabled>Publish</button></div></form>
    </section>
    <section role="tabpanel" id="mount-pane-connect" aria-labelledby="mount-tab-connect" data-view="connect" hidden>
      <div class="mount-pane-heading"><div><h2>Connect to a shared folder</h2><p>Paste an address from its owner. Mount only the access you need.</p></div></div>
      <form class="mount-form" data-shared-form><div class="mount-fields">
        <label class="mount-field-wide">Export address<input name="address" placeholder="osfs:…" required autocomplete="off" spellcheck="false"></label>
        <label>Mount name<input name="name" aria-label="Mount name" aria-describedby="shared-mount-path" value="shared" pattern="[a-zA-Z0-9_.\\-]+" maxlength="80" required><small id="shared-mount-path" data-shared-path>/mnt/shared/shared</small></label>
        <label>Password (if needed)<input type="password" name="password" maxlength="256" autocomplete="off"></label></div>
        <fieldset class="mount-export-mode"><legend>Requested access</legend><label><input type="checkbox" checked disabled>r</label><label><input type="checkbox" name="writable">w</label><label><input type="checkbox" name="execute">x</label></fieldset>
        <div class="mount-actions"><button type="submit" class="primary">Mount</button></div></form>
    </section></div>`;
  const query = selector => root.querySelector(selector), add = query('[data-add-form]'), exports = query('[data-export-form]');
  const shared = query('[data-shared-form]');
  const notice = query('.mount-notice'); let selected, mounts = [], pane, refreshRevision = 0, epoch = 0;
  let helper = typeof window.showDirectoryPicker !== 'function';
  const browser = /Firefox|FxiOS/.test(navigator.userAgent) ? 'Firefox' : /Safari/.test(navigator.userAgent) && !/Chrome|Chromium|CriOS|Edg|OPR/.test(navigator.userAgent) ? 'Safari' : 'This browser';
  let helperReason = `${browser} does not expose the directory picker API that OS uses for direct host-folder mounts.`;
  const error = failure => { notice.textContent = failure?.message ?? failure?.errno ?? String(failure); };
  const action = fn => async () => { notice.textContent = ''; try { await fn(); } catch (failure) { error(failure); } };
  const browse = path => dispatchEvent(new CustomEvent('os-open-directory', { detail: path }));
  let session, submitting = false, exportRows = [];
  const status = list => list.map(p => `pid ${p.pid} ${p.comm} [${p.reasons.join(', ')}]`).join(', ');
  async function identify() {
    const before = epoch;
    const local = await kernelCall('source_session');
    if (before !== epoch || !Number.isSafeInteger(local?.uid) || !Number.isSafeInteger(local.loginEpoch)) throw new Error('Session changed.');
    session = local;
    query('[data-connect]').disabled = submitting;
    return local;
  }
  async function rpc(request, local = session) {
    if (!local) local = await identify();
    const before = epoch;
    const args = { socket: `/run/user/${local.uid}/mount.sock`, request, loginEpoch: local.loginEpoch };
    let reply;
    try { reply = await kernelCall('unix_rpc', args); }
    catch (e) {
      if (before !== epoch || !['ENOENT','ECONNREFUSED'].includes(e.errno)) throw e;
      reply = await kernelCall('unix_rpc', { ...args, socket: '/run/mount/control.sock' });
    }
    if (before !== epoch) throw new Error('Session changed.');
    if (reply.status === 'error') {
      const details = reply.error.kind === 'busy' ? status(reply.error.processes) : '';
      throw Object.assign(new Error([reply.message, details].filter(Boolean).join(' · ')), { errno: reply.errno });
    }
    return reply;
  }
  function select(path) {
    selected = path;
    const current = mounts.find(m => m.target === path);
    query('[data-details]').hidden = !current;
    for (const row of query('[data-mounts]').rows) row.classList.toggle('selected', row.dataset.path === path);
    const actions = query('[data-mount-actions]'); actions.replaceChildren();
    query('[data-selected]').textContent = path ?? '';
    if (!current) return;
    query('[data-description]').textContent = [current.source_label, current.health, ...current.options,
      current.uncertain_writes ? 'Some writes may not have completed' : ''].filter(Boolean).join(' · ');
    actions.append(button('Open in Files', () => browse(path)));
    if (current.owner_uid === session.uid || session.uid === 0) {
      const detach = lazy => action(async () => { await rpc({ op: 'detach', target: path, lazy }); await refresh(); });
      actions.append(button(path.startsWith('/opt/private/') ? 'Deactivate' : 'Unmount', detach(false)));
      if (current.busy_pids?.length) actions.append(button('Lazy unmount', detach(true)));
    }
    if (current.source_id && current.user_mount && !path.startsWith('/opt/private/') && (!current.noexec || current.source_label?.startsWith('snapshot:'))) {
      const label = document.createElement('label'); label.textContent = 'Extension name';
      const name = document.createElement('input'); name.value = 'tools'; name.maxLength = 80; name.setAttribute('aria-label', 'Extension name'); label.append(name);
      actions.append(label, button('Activate package', action(async () => {
        await rpc({ op: 'activate_private', source_id: current.source_id, name: name.value, execute: true });
        selected = '/opt/private/' + name.value; await refresh();
      })));
    }
  }
  function list(selector, rows, label) {
    const container = query(selector); container.replaceChildren();
    return rows.map(item => {
      const row = document.createElement('li'); row.textContent = label(item);
      container.append(row); return row;
    });
  }
  async function mountSource(local, id, fstype, name, writable, execute) {
    const target = (fstype === 'sharefs' ? '/mnt/shared/' : '/mnt/local/') + name;
    await rpc({ op: 'attach', source_id: id, source: id, target, fstype, flags: (writable ? 0 : 1) | (execute ? 0 : 8) }, local);
    selected = target; show('mounted');
  }
  async function refresh() {
    const before = epoch, serial = ++refreshRevision, local = await identify();
    const values = await rpc({ op: 'list_all', include_busy: true }, local);
    const current = () => before === epoch && serial === refreshRevision;
    if (!current()) return;
    mounts = values.attachments; exportRows = values.exports;
    const body = query('[data-mounts]'); body.replaceChildren();
    query('[data-empty]').hidden = mounts.some(m => m.user_mount);
    query('.mount-table-scroll').hidden = mounts.length === 0;
    for (const mount of mounts) {
      const row = body.insertRow(); row.dataset.path = mount.target;
      row.insertCell().append(button(mount.target, () => select(mount.target)));
      row.insertCell().textContent = kinds[mount.fstype] ?? mount.fstype;
      row.insertCell().textContent = mount.options.join(',');
      row.insertCell().textContent = status(mount.busy_pids ?? []);
    }
    select(mounts.some(m => m.target === selected) ? selected : mounts.find(m => m.user_mount)?.target);
    list('[data-filesystems]', values.filesystems, f => `${f.label} · ${f.fstype} · ${f.bfree} of ${f.blocks} blocks free`);
    list('[data-exports]', values.exports, e => `${e.name} · ${e.address} · ${e.active_clients} clients`);
    const rows = list('[data-sources]', values.sources, s => `${s.label} · ${s.id} · ${s.state}`);
    await Promise.all(values.sources.map(async (s, i) => {
      if (s.owner_uid !== local.uid) return;
      rows[i].append(button('Forget', action(async () => { await rpc({ op: 'forget_source', source_id: s.id }, local); await refresh(); })));
      if (s.state === 'granted' && !mounts.some(m => m.source_id === s.id)) {
        rows[i].append(button('Mount', action(() => mountSource(local, s.id, s.kind, add.elements.name.value, s.writable, s.execute))));
      }
      if (s.state !== 'needs_renewal') return;
      const renew = await prepareRenewal(local, s, current, kernelCall);
      if (!current()) return;
      rows[i].append(button('Renew & Mount', action(async () => {
        await renew();
        if (before !== epoch) return;
        await mountSource(local, s.id, s.kind, add.elements.name.value, s.writable, s.execute);
      })));
    }));
  }
  function source() {
    const kind = add.elements.kind.value;
    for (const item of root.querySelectorAll('[data-source]')) item.hidden = item.dataset.source !== kind;
    query('[data-helper]').hidden = !helper;
    query('[data-save]').hidden = helper || kind !== 'host';
    query('[data-browser-limitation]').textContent = helperReason;
    for (const name of ['url','token']) add.elements[name].disabled = kind !== 'host' || !helper;
    query('[data-connect]').textContent = kind === 'storage' ? 'Mount storage' : helper ? 'Connect folder' : 'Choose folder…';
    query('[data-helper-command]').textContent = `os-local-helper --root /path/to/folder --origin ${location.origin}${add.elements.writable.checked ? ' --write' : ''}${add.elements.execute.checked ? ' --execute' : ''}`;
  }
  add.elements.kind.onchange = source; source();
  add.elements.writable.onchange = source; add.elements.execute.onchange = source;
  add.elements.name.oninput = () => { query('[data-mount-path]').textContent = '/mnt/local/' + add.elements.name.value; };
  const submitMount = event => {
    event.preventDefault();
    if (!session) return;
    const local = session, { loginEpoch } = local, before = epoch;
    const current = () => before === epoch && session?.loginEpoch === loginEpoch;
    const trigger = query('[data-connect]'); submitting = true; trigger.disabled = true;
    const name = add.elements.name.value, options = { loginEpoch, execute: add.elements.execute.checked,
      writable: add.elements.writable.checked, cloud: add.elements.cloud.checked };
    const fstype = add.elements.kind.value === 'storage' ? 'opfs' : helper ? 'helperfs' : 'hostfs';
    notice.textContent = '';
    // Call the picker on the submit/click stack, before any promise or worker round trip.
    let registration;
    try {
      if (fstype === 'hostfs') {
        const selection = window.showDirectoryPicker({ mode: options.writable ? 'readwrite' : 'read', id: 'os-host-folder' });
        registration = registerPickedFolder(selection, { ...options, save: add.elements.save.checked }, current, kernelCall);
      } else if (fstype === 'opfs') registration = kernelCall('source_register_opfs', options);
      else registration = registerHelperFolder(add, options, kernelCall);
    } catch (e) { registration = Promise.reject(e); }
    void registration.then(async ({ source_id }) => {
      if (!current()) return;
      add.elements.token.value = '';
      await mountSource(local, source_id, fstype, name, options.writable, options.execute);
    }).catch(failure => {
      if (!current()) return;
      if (failure?.name === 'AbortError') { notice.textContent = 'Cancelled.'; return; }
      if (['NotSupportedError', 'DataCloneError'].includes(failure?.name)) {
        helper = true; helperReason = 'This browser could not provide a usable directory handle to OS.'; source();
      }
      error(failure);
    }).finally(() => { if (before === epoch) { submitting = false; trigger.disabled = !session; } });
  };
  query('[data-connect]').onclick = event => {
    if (add.reportValidity()) submitMount(event);
    else event.preventDefault();
  };
  add.onsubmit = submitMount;
  async function refreshSharing() {
    const before = epoch;
    await refresh();
    if (before !== epoch) return;
    const shares = query('[data-shares]'); shares.replaceChildren();
    const selectedSource = exports.elements.source.value;
    exports.elements.source.replaceChildren();
    for (const mount of mounts.filter(item => ['opfs','hostfs','helperfs'].includes(item.fstype))) exports.elements.source.add(new Option(mount.target, mount.target));
    if ([...exports.elements.source.options].some(option => option.value === selectedSource)) exports.elements.source.value = selectedSource;
    query('[data-share]').disabled = !exports.elements.source.length;
    for (const grant of exportRows) {
      const row = document.createElement('li'), information = document.createElement('div'), name = document.createElement('strong'), detail = document.createElement('small'), address = document.createElement('input');
      name.textContent = grant.name;
      detail.textContent = `OS permissions${grant.password_protected ? ' or password' : ''} · until ${new Date(grant.expires_at * 1000).toLocaleTimeString()}`;
      address.value = grant.address; address.readOnly = true; address.setAttribute('aria-label', 'Export address'); address.onclick = () => address.select();
      const actions = document.createElement('div'); actions.className = 'mount-actions';
      actions.append(button('Copy address', action(async () => { await navigator.clipboard.writeText(address.value); notice.textContent = 'Address copied.'; })),
        button('Stop publishing', action(async () => { await revokeMount(grant.id); await refreshSharing(); })));
      information.append(name, detail, address); row.append(information, actions);
      shares.append(row);
    }
    if (!shares.children.length) shares.textContent = 'No directories published.';
  }
  exports.onsubmit = event => { event.preventDefault(); query('[data-share]').disabled = true; const before = epoch;
    const args = { path: exports.elements.source.value + (exports.elements.path.value ? '/' + exports.elements.path.value : ''), name: exports.elements.name.value,
      seconds: Number(exports.elements.seconds.value), password: exports.elements.password.value };
    void action(async () => {
      await shareMount(args); if (before !== epoch) return;
      exports.elements.password.value = ''; await refreshSharing();
    })().finally(() => { query('[data-share]').disabled = !exports.elements.source.length; });
  };
  shared.elements.name.oninput = () => { query('[data-shared-path]').textContent = '/mnt/shared/' + shared.elements.name.value; };
  shared.onsubmit = event => { event.preventDefault(); const trigger = shared.querySelector('[type=submit]'), before = epoch; trigger.disabled = true;
    const name = shared.elements.name.value, writable = shared.elements.writable.checked, execute = shared.elements.execute.checked;
    void action(async () => {
      const local = session ?? await identify();
      const { source_id } = await registerSharedFolder(shared, { loginEpoch: local.loginEpoch, writable, execute }, kernelCall);
      if (before !== epoch) return;
      shared.elements.password.value = '';
      await mountSource(local, source_id, 'sharefs', name, writable, execute);
    })().finally(() => { trigger.disabled = false; });
  };
  function show(next) {
    pane = next === 'sharing' ? 'publish' : next; notice.textContent = '';
    for (const tab of root.querySelectorAll('[data-pane]')) { const active = tab.dataset.pane === pane; tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1; }
    for (const view of root.querySelectorAll('[data-view]')) view.hidden = view.dataset.view !== pane;
    if (pane !== 'connect') void action(pane === 'publish' ? refreshSharing : refresh)();
  }
  for (const tab of root.querySelectorAll('[data-pane]')) {
    tab.onclick = () => show(tab.dataset.pane);
    tab.onkeydown = event => {
      const tabs = [...root.querySelectorAll('[data-pane]')], index = tabs.indexOf(tab);
      const next = ['ArrowRight', 'ArrowDown'].includes(event.key) ? (index + 1) % tabs.length : ['ArrowLeft', 'ArrowUp'].includes(event.key) ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null;
      if (next !== null) { event.preventDefault(); tabs[next].focus(); show(tabs[next].dataset.pane); }
    };
  }
  query('[data-action=add]').onclick = () => show('add');
  query('[data-action=refresh]').onclick = action(refresh);
  query('[data-action=sharing-refresh]').onclick = action(refreshSharing);
  const resized = new ResizeObserver(entries => query('.mount-nav').setAttribute('aria-orientation', entries[0].contentRect.width <= 720 ? 'horizontal' : 'vertical'));
  resized.observe(root);
  const reset = () => {
    epoch++; refreshRevision++; session = undefined; submitting = false; selected = undefined; mounts = []; exportRows = [];
    query('[data-connect]').disabled = true;
    add.reset(); exports.reset(); shared.reset(); source(); query('[data-mount-path]').textContent = '/mnt/local/project';
    query('[data-shared-path]').textContent = '/mnt/shared/shared';
    for (const selector of ['[data-mounts]', '[data-shares]', '[data-sources]', '[data-filesystems]', '[data-exports]', '[data-mount-actions]']) query(selector).replaceChildren();
    query('[data-details]').hidden = true;
    query('[data-share]').disabled = true;
    notice.textContent = 'Session changed. Refresh to view its mounts.';
  };
  addEventListener('os:login-changed', reset);
  addEventListener('os:mounts-changed', () => {
    if (pane === 'mounted') void action(refresh)();
    else if (pane === 'publish') void action(refreshSharing)();
  });
  let login;
  addEventListener('os:login-session', ({ detail }) => {
    if (!detail?.connected) return;
    if (login && (login !== detail.session?.id || detail.session?.shutdown)) reset();
    login = detail.session?.id;
  });
  return { show };
}
