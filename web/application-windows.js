import { entry, entryPath } from './release.js';
import { ApplicationSupervisor, applicationCatalog } from './application-supervisor.js';
import { applicationContext } from './application-context.js';

export function installApplications() {
  const dialog = document.getElementById('applications'), list = document.getElementById('application-list');
  const error = document.getElementById('application-error');
  const ownsDocument = record => {
    try {
      if (!record.nonce && !record.window.closed && record.window.location.href === 'about:blank') return true;
      return !record.window.closed && ['/shell', '/shell.html'].includes(entryPath(record.window.location.pathname))
        && new URLSearchParams(record.window.location.search).get('managed') === '1'
        && (!record.nonce || record.window.osManagedApplicationNonce === record.nonce);
    } catch { return false; }
  };
  const render = () => {
    list.replaceChildren();
    const records = supervisor.snapshot();
    if (!records.length) { const item = document.createElement('li'); item.textContent = 'No applications opened from this desktop.'; list.append(item); }
    for (const record of records) {
      const item = document.createElement('li'); item.dataset.application = record.id;
      const title = document.createElement('strong'); title.textContent = applicationCatalog[record.target].title;
      const status = document.createElement('span'); status.className = 'application-state'; status.textContent = record.state;
      const reason = document.createElement('p'); reason.textContent = record.reason;
      const stop = document.createElement('button'); stop.type = 'button'; stop.textContent = 'Stop';
      stop.disabled = !['starting', 'ready'].includes(record.state); stop.onclick = () => supervisor.stop(record.id);
      const show = document.createElement('button'); show.type = 'button'; show.textContent = 'Show window';
      const owned = supervisor.records.get(record.id); show.disabled = !ownsDocument(owned);
      show.onclick = () => { if (ownsDocument(owned)) owned.window.focus(); };
      item.append(title, status, reason, show, stop); list.append(item);
    }
  };
  const supervisor = new ApplicationSupervisor({
    open: path => window.open(entry(path), '_blank', 'popup,width=960,height=640'),
    context: cancelled => applicationContext(cancelled),
    connect: (record, receive) => {
      if (!ownsDocument(record)) throw new Error('Application document changed.');
      const channel = new MessageChannel();
      channel.port1.onmessage = event => receive(event.data);
      channel.port1.onmessageerror = () => supervisor.fail(record, 'Application connection lost.');
      channel.port1.start();
      try { record.window.postMessage({ type: 'os-application-port', nonce: record.nonce, context: record.context }, location.origin, [channel.port2]); }
      catch (error) { channel.port1.close(); channel.port2.close(); throw error; }
      return channel.port1;
    },
    close: record => { if (ownsDocument(record)) record.window.close(); },
    changed: render,
  });
  window.addEventListener('message', event => {
    if (event.origin === location.origin && event.data?.type === 'os-application-hello') supervisor.hello(event.source, event.data.nonce);
  });
  window.addEventListener('os:login-session', event => supervisor.login(event.detail));
  window.addEventListener('os:machine-init', event => supervisor.boot(event.detail));
  window.addEventListener('pagehide', () => supervisor.stopAll('The owning desktop left.'));
  setInterval(() => supervisor.tick(), 1000);
  // Page lifecycle suspends this timer in the back/forward cache; timestamps still fence
  // expired records when the document resumes. Children also watch their private peer.
  document.addEventListener('click', event => {
    if (event.target.closest?.('[data-applications]')) { error.textContent = ''; render(); dialog.showModal(); }
  });
  document.getElementById('applications-close').onclick = () => dialog.close();
  document.getElementById('application-shell').onclick = () => {
    error.textContent = '';
    try { supervisor.launch('shell'); } catch (failure) { error.textContent = failure.message; }
  };
  render();
  return { list: () => supervisor.snapshot(), launch: target => supervisor.launch(target), stop: id => supervisor.stop(id) };
}
