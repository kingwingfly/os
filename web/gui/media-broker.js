// Blind host media, live-sound, speaker-popup, and `/api/events` transport broker (`#64` `L6c-2`).
//
// Replaces `web/dev.mjs`, `web/sound.mjs`, and `web/record.mjs`.
// Owns browser-only Window APIs (`RTCPeerConnection`, `navigator.mediaDevices.getUserMedia`,
// `MediaRecorder`, `#listening` `<audio>` elements, `BroadcastChannel('os-present')`,
// `window.open('/?speaker=...')`, and `window.WebSocket('/api/events')`).
// Zero network requests on boot; `/api/events` connects strictly when Cloud-signed-in or when
// an active presentation/live-sound subscription requests it.
import { O_APPEND, O_CREAT, O_EXCL, O_WRONLY, answered, call, closeOnLeaving, hold, pwrite, sys } from '../http.mjs';

const ICE = [{ urls: 'stun:stun.cloudflare.com:3478' }];
const SND_PUBLISH = 0x5101;
const SND_LISTEN = 0x5102;
const SND_ANSWER = 0x5103;
const O_RDONLY = 0;
const RECORDED_MIME = 'audio/webm;codecs=opus';
const RECORD_RETRIES = 3;
const LISTEN_RETRY_MS = [1000, 2000, 5000, 10000, 20000];

const $ = id => document.getElementById(id);
const fmtSize = bytes => bytes < 1e3 ? `${bytes} B` : bytes < 1e6 ? `${(bytes / 1e3).toFixed(1)} KB` : `${(bytes / 1e6).toFixed(1)} MB`;
export const fmtClock = seconds => `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;

function waitConnected(pc) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('The sound did not connect')), 10_000);
    const check = () => {
      if (pc.connectionState === 'connected') {
        clearTimeout(timer);
        resolve();
      } else if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        clearTimeout(timer);
        reject(new Error('The sound did not connect'));
      }
    };
    pc.addEventListener('connectionstatechange', check);
    check();
  });
}

function keptServerFd(fd) {
  const release = hold(fd);
  const leaving = () => navigator.sendBeacon(
    '/api/sys',
    new Blob([JSON.stringify({ calls: [{ close: { fd } }] })], { type: 'application/json' }),
  );
  addEventListener('pagehide', leaving);
  return async () => {
    release();
    removeEventListener('pagehide', leaving);
    await sys([{ close: { fd } }]).catch(() => {});
  };
}

function recordingName(path) {
  const slash = path.lastIndexOf('/');
  const dir = slash > 0 ? path.slice(0, slash) : '';
  const file = path.slice(slash + 1);
  const stem = /\.slides\.md$/i.test(file)
    ? file.slice(0, -'.slides.md'.length)
    : file.includes('.') ? file.slice(0, file.lastIndexOf('.')) : file;
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
  return `${dir}/${stem || file}-${stamp}.weba`;
}

async function publishLiveSound(name, microphone, { acl = null } = {}) {
  const pc = new RTCPeerConnection({ iceServers: ICE, bundlePolicy: 'max-bundle' });
  let endFd = null;
  let device = null;
  let version = null;
  const end = async () => {
    try { pc.close(); } catch {}
    if (endFd) {
      const fn = endFd;
      endFd = null;
      await fn();
    }
  };
  try {
    const transceiver = pc.addTransceiver(microphone.getAudioTracks()[0], { direction: 'sendonly' });
    await pc.setLocalDescription(await pc.createOffer());
    const offer = { sdp: pc.localDescription.sdp, mid: transceiver.mid };
    const defaultName = (await window.os?.cloudStatus?.().catch(() => null))?.cloud_user ?? (await call('getcreds')).user;
    device = `/dev/snd/${name ?? defaultName}`;
    answered((await sys([{ mknod: { path: device, mode: 0o666, rdev: 'snd' } }]))[0]);
    if (acl) {
      const why = await window.osUploads.setfacl(device, acl);
      if (why) {
        await sys([{ unlink: { path: device } }]).catch(() => {});
        throw new Error(why.replace(/^setfacl:/, 'stream -m:'));
      }
    }
    const { fd } = await call('open', { path: device, flags: O_WRONLY });
    endFd = keptServerFd(fd);
    const ans = await call('ioctl', { fd, request: SND_PUBLISH, arg: offer });
    device = ans.device ?? device;
    version = ans.version ?? null;
    await pc.setRemoteDescription({ type: 'answer', sdp: ans.sdp });
    await waitConnected(pc);
    return { device, version, end };
  } catch (error) {
    await end();
    throw error;
  }
}

async function recordToCloudFile(destination, microphone, { acl = null, progress = () => {}, begun: onBegun = () => {}, signal }) {
  if (!window.MediaRecorder?.isTypeSupported(RECORDED_MIME)) {
    throw new Error('This browser cannot record Opus in WebM');
  }
  const rust = window.osUploads;
  let begun;
  try {
    begun = await call('open', { path: destination, flags: O_WRONLY | O_CREAT | O_EXCL | O_APPEND, mode: 0o666 });
  } catch (error) {
    throw error.errno === 'EEXIST' ? new Error('File already exists; rename it before recording') : error;
  }
  const fd = begun.fd;
  const chunkSize = begun.chunk_size;
  if (acl) {
    const why = await rust.setfacl(destination, acl);
    if (why) {
      await sys([{ discard: { fd } }], { fdEpoch: begun.fd_epoch }).catch(() => {});
      throw new Error(why.replace(/^setfacl:/, 'stream -m:'));
    }
  }
  const leaving = () => closeOnLeaving([fd], begun.fd_epoch);
  addEventListener('pagehide', leaving);
  onBegun(begun);
  let failure = null;
  let full = false;
  let sent = 0;
  let index = 0;
  let pending = new Uint8Array(0);
  let queue = Promise.resolve();
  const sendChunk = bytes => {
    const at = index++;
    queue = queue.then(async () => {
      for (let attempt = 0; ; attempt++) {
        if (failure || full) return;
        try {
          await pwrite(fd, at, bytes, rust.sha256(bytes), begun.fd_epoch);
          sent += bytes.length;
          return;
        } catch (error) {
          if (error.status === 413) { full = true; return; }
          const refused = error.status >= 400 && error.status < 500 && (error.status !== 400 || attempt + 1 >= RECORD_RETRIES);
          if (refused || (signal.aborted && attempt + 1 >= RECORD_RETRIES)) {
            failure = error;
            return;
          }
          await new Promise(resolve => setTimeout(resolve, Math.min(10_000, 1000 * 2 ** attempt)));
        }
      }
    });
  };
  const recorder = new MediaRecorder(microphone, { mimeType: RECORDED_MIME, audioBitsPerSecond: 64_000 });
  let ended = false;
  const stopped = new Promise(resolve => { recorder.onstop = () => { ended = true; resolve(); }; });
  recorder.onerror = () => { ended = true; };
  let reading = Promise.resolve();
  recorder.ondataavailable = event => {
    reading = reading.then(async () => {
      const bytes = new Uint8Array(await event.data.arrayBuffer());
      const joined = new Uint8Array(pending.length + bytes.length);
      joined.set(pending);
      joined.set(bytes, pending.length);
      pending = joined;
      while (pending.length >= chunkSize) {
        sendChunk(pending.slice(0, chunkSize));
        pending = pending.slice(chunkSize);
      }
    });
  };
  const started = performance.now();
  const say = () => progress(`● ${fmtClock((performance.now() - started) / 1000)} · ${fmtSize(sent + pending.length)}`);
  const ticking = setInterval(say, 1000);
  say();
  const lease = hold(fd, () => {
    failure ??= Object.assign(new Error('closed elsewhere'), { errno: 'EBADF', status: 409 });
  });
  try {
    recorder.start(1000);
    await new Promise(resolve => {
      const check = setInterval(() => {
        if (failure || full || signal.aborted || ended || recorder.state === 'inactive') {
          clearInterval(check);
          resolve();
        }
      }, 250);
    });
    const itself = !signal.aborted && !failure && !full;
    if (recorder.state !== 'inactive') recorder.stop();
    await Promise.race([stopped, new Promise(resolve => setTimeout(resolve, 2000))]);
    await reading;
    if (pending.length) {
      sendChunk(pending);
      pending = new Uint8Array(0);
    }
    await queue;
    if (failure) {
      throw failure.status === 409 ? new Error('stopped elsewhere; what arrived is kept') : failure;
    }
    const done = await call('close', { fd }, { fdEpoch: begun.fd_epoch });
    return {
      ...done,
      seconds: (performance.now() - started) / 1000,
      ...(full
        ? { stopped: 'it reached the largest a file may be (1 GB)' }
        : itself ? { stopped: 'the microphone stopped' } : {}),
    };
  } finally {
    clearInterval(ticking);
    lease();
    removeEventListener('pagehide', leaving);
    if (recorder.state !== 'inactive') recorder.stop();
  }
}

export function createHostMediaBroker({
  sendMediaEvent,
  sendSessionEvent,
  onSessionEnded,
  onChanged,
}) {
  let cloudSignedIn = false;
  let speakerPopup = null; // { win, path }
  let muted = false;
  let activeRecording = null; // { controller, surfaceId, device, version }
  const listeningStreams = new Map(); // streamId -> { pc, audio, label, isVoice, surfaceId, standalone, version }
  const captureStreams = new Map(); // streamId -> { pc, mic, surfaceId }
  const subscribedSurfaces = new Set();
  const surfaceFollowed = new Map(); // surfaceId -> string[]
  const standaloneFollowed = new Set();

  // Cross-window slide/PDF sync (`BroadcastChannel('os-present')`).
  const localPresented = new Map(); // path -> [col, row]
  const presentChannel = 'BroadcastChannel' in window ? new BroadcastChannel('os-present') : null;
  if (presentChannel) {
    presentChannel.onmessage = event => {
      const d = event.data;
      if (!d || typeof d !== 'object') return;
      if (typeof d.ask_where === 'string') {
        const at = localPresented.get(d.ask_where);
        if (at) presentChannel.postMessage({ path: d.ask_where, at });
        return;
      }
      if (typeof d.path !== 'string' || !Array.isArray(d.at) || d.at.length < 2) return;
      localPresented.set(d.path, [Number(d.at[0]) || 0, Number(d.at[1]) || 0]);
      for (const sid of subscribedSurfaces) {
        sendMediaEvent(sid, {
          event: 'present_broadcast',
          path: d.path,
          column: Number(d.at[0]) || 0,
          row: Number(d.at[1]) || 0,
        });
      }
    };
  }

  // `/api/events` WebSocket pipe (strictly lazy; 0 connections offline).
  let ws = null;
  let wsRetry = 0;
  let wsReconnectTimer = null;
  let inotifyTimer = null;
  const outbox = [];

  function allFollowedDevices() {
    const set = new Set(standaloneFollowed);
    for (const list of surfaceFollowed.values()) {
      for (const dev of list) set.add(dev);
    }
    return [...set];
  }

  function wantsSocket() {
    return cloudSignedIn || allFollowedDevices().length > 0;
  }

  function sendWs(payloadObj) {
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(payloadObj));
    } else {
      if (payloadObj.present?.path) {
        for (let i = outbox.length - 1; i >= 0; i--) {
          if (outbox[i].present?.path === payloadObj.present.path || outbox[i].where === payloadObj.present.path) {
            outbox.splice(i, 1);
          }
        }
      }
      outbox.push(payloadObj);
    }
  }

  function syncFollows() {
    const devices = allFollowedDevices();
    if (devices.length > 0) {
      ensureSocket();
      sendWs({ follow: devices });
    } else if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ follow: [] }));
    }
  }

  function stopSocket() {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
    const old = ws;
    ws = null;
    wsRetry = 0;
    try { old?.close(); } catch {}
  }

  function ensureSocket(force = false) {
    if (!force && !wantsSocket()) return;
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    openSocket(force);
  }

  function openSocket(force = false) {
    if (!force && !wantsSocket()) return;
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
    try { ws?.close(); } catch {}
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = ws = new WebSocket(`${proto}://${location.host}/api/events`);
    let ping = null;
    socket.onopen = () => {
      const reconnected = wsRetry > 0;
      if (reconnected) onChanged?.();
      wsRetry = 0;
      ping = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) socket.send('ping');
      }, 30_000);
      const devices = allFollowedDevices();
      if (devices.length > 0) {
        socket.send(JSON.stringify({ follow: devices }));
      }
      for (const msg of outbox.splice(0)) {
        socket.send(JSON.stringify(msg));
      }
      if (reconnected) {
        const raw = JSON.stringify({ reconnected: true });
        for (const sid of subscribedSurfaces) {
          sendSessionEvent(sid, raw);
        }
      }
    };
    socket.onmessage = event => {
      if (ws !== socket) return;
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      if (msg.session === 'ended') {
        onSessionEnded?.();
        return;
      }
      if (msg.signal) {
        window.dispatchEvent(new CustomEvent('os:signal', { detail: msg.signal }));
        return;
      }
      if (Array.isArray(msg.inotify)) {
        window.dispatchEvent(new CustomEvent('os:inotify', { detail: msg.inotify }));
        clearTimeout(inotifyTimer);
        inotifyTimer = setTimeout(() => window.dispatchEvent(new CustomEvent('os-remote')), 250);
        return;
      }
      // Handle standalone `/dev/snd/*` end/replacement notifications.
      if (msg.device) {
        const { name, version, ended, replaced } = msg.device;
        if (ended && activeRecording?.device === name && (!version || activeRecording.version === version)) {
          activeRecording.controller.abort();
        }
        const st = listeningStreams.get(name);
        if (st?.standalone) {
          if (replaced) {
            void listenStandalone(name, 0).catch(() => stopStream(name));
          } else {
            stopStream(name);
          }
        }
      }
      if (msg.followed) {
        const { name, version } = msg.followed;
        const st = listeningStreams.get(name);
        if (st?.standalone && st.version && version && st.version !== version) {
          void listenStandalone(name, 0).catch(() => stopStream(name));
        }
      }
      // Forward all presentation/sound/asking/granted/denied/device/followed messages to Preview.
      if (subscribedSurfaces.size > 0) {
        for (const sid of subscribedSurfaces) {
          sendSessionEvent(sid, event.data);
        }
      }
    };
    socket.onclose = () => {
      clearInterval(ping);
      if (ws === socket && wantsSocket()) {
        wsReconnectTimer = setTimeout(() => openSocket(false), Math.min(30_000, 1000 * 2 ** wsRetry++));
      }
    };
  }

  // `#listening` player UI on the main page (persists across Preview open/close).
  function updatePlayerUi() {
    const player = $('listening');
    if (!player) return;
    const main = [];
    const voices = [];
    for (const st of listeningStreams.values()) {
      if (st.isVoice) voices.push(st.label);
      else main.push(st.label);
    }
    const names = [...main, ...voices];
    player.hidden = names.length === 0;
    if (!names.length) {
      delete player.dataset.state;
    } else if (!player.dataset.state) {
      player.dataset.state = 'connecting';
    }
    const nameEl = $('listening-name');
    if (nameEl) nameEl.textContent = names.join(' · ');
  }

  function allAudioEls() {
    return [...listeningStreams.values()].map(st => st.audio).filter(Boolean);
  }

  function installPlayerButtons() {
    const playBtn = $('listening-play');
    const muteBtn = $('listening-mute');
    const stopBtn = $('listening-stop');
    if (playBtn) {
      playBtn.onclick = () => {
        Promise.all(allAudioEls().map(a => a.play())).then(() => {
          const player = $('listening');
          if (player) player.dataset.state = 'live';
        }, () => {});
      };
    }
    if (muteBtn) {
      muteBtn.onclick = () => {
        muted = !muted;
        for (const a of allAudioEls()) a.muted = muted;
        muteBtn.textContent = muted ? 'Unmute' : 'Mute';
      };
    }
    if (stopBtn) {
      stopBtn.onclick = () => {
        const entries = [...listeningStreams.entries()];
        for (const [streamId, st] of entries) {
          stopStream(streamId);
          if (st.surfaceId != null) {
            sendMediaEvent(st.surfaceId, {
              event: 'stream_state',
              stream_id: streamId,
              state: 'stopped_by_user',
            });
          }
        }
      };
    }
  }
  installPlayerButtons();

  function stopStream(streamId) {
    const st = listeningStreams.get(streamId);
    if (!st) return;
    listeningStreams.delete(streamId);
    if (st.retryTimer != null) clearTimeout(st.retryTimer);
    try { st.pc?.close(); } catch {}
    if (st.audio) {
      st.audio.srcObject = null;
      st.audio.remove();
    }
    if (st.standalone) {
      standaloneFollowed.delete(streamId);
      syncFollows();
    }
    updatePlayerUi();
  }

  function stopCapture(streamId) {
    const cap = captureStreams.get(streamId);
    if (!cap) return;
    captureStreams.delete(streamId);
    try { cap.pc?.close(); } catch {}
    cap.mic?.getTracks().forEach(t => { try { t.stop(); } catch {} });
  }

  // Standalone `open /dev/snd/NAME` listener (no Preview window needed; validates ACL via server).
  async function listenStandalone(device, attempt = 0) {
    stopStream(device);
    const audio = Object.assign(document.createElement('audio'), {
      id: 'listening-audio',
      autoplay: true,
      hidden: true,
      muted,
    });
    document.body.append(audio);
    const player = $('listening');
    const st = {
      pc: null,
      audio,
      label: device,
      isVoice: false,
      surfaceId: null,
      standalone: true,
      version: null,
      retryTimer: null,
    };
    listeningStreams.set(device, st);
    if (player) player.dataset.state = 'connecting';
    updatePlayerUi();

    const pc = new RTCPeerConnection({ iceServers: ICE, bundlePolicy: 'max-bundle' });
    st.pc = pc;
    let fd = null;
    try {
      pc.ontrack = ev => { audio.srcObject = new MediaStream([ev.track]); };
      const opened = await call('open', { path: device, flags: O_RDONLY });
      fd = opened.fd;
      const offered = await call('ioctl', { fd, request: SND_LISTEN, arg: null });
      st.version = offered.version ?? null;
      await pc.setRemoteDescription({ type: 'offer', sdp: offered.sdp });
      await pc.setLocalDescription(await pc.createAnswer());
      await call('ioctl', { fd, request: SND_ANSWER, arg: { session: offered.session, sdp: pc.localDescription.sdp } });
      await sys([{ close: { fd } }]).catch(() => {});
      fd = null;
      await waitConnected(pc);
      if (listeningStreams.get(device) !== st) {
        pc.close();
        audio.remove();
        return;
      }
      if (player) player.dataset.state = 'live';
      standaloneFollowed.add(device);
      syncFollows();
      pc.addEventListener('connectionstatechange', () => {
        if (pc.connectionState === 'failed' && listeningStreams.get(device) === st) {
          if (attempt < LISTEN_RETRY_MS.length) {
            if (player) player.dataset.state = 'connecting';
            st.retryTimer = setTimeout(() => {
              if (listeningStreams.get(device) === st) {
                void listenStandalone(device, attempt + 1).catch(() => stopStream(device));
              }
            }, LISTEN_RETRY_MS[attempt]);
          } else {
            stopStream(device);
          }
        }
      });
      try { await audio.play(); } catch {
        if (listeningStreams.get(device) === st && player) player.dataset.state = 'paused';
      }
    } catch (error) {
      if (fd != null) await sys([{ close: { fd } }]).catch(() => {});
      try { pc.close(); } catch {}
      if (listeningStreams.get(device) === st) {
        if (attempt > 0 && attempt < LISTEN_RETRY_MS.length && !(error.status >= 400 && error.status < 500)) {
          audio.remove();
          st.audio = null;
          st.retryTimer = setTimeout(() => {
            if (listeningStreams.get(device) === st) {
              void listenStandalone(device, attempt + 1).catch(() => stopStream(device));
            }
          }, LISTEN_RETRY_MS[attempt]);
          return;
        }
        stopStream(device);
      } else {
        audio.remove();
      }
      throw error;
    }
  }

  // Record + live sound (used by both `stream` CLI desktop-action and Preview bar `GoLive`).
  async function recordSound(path, name, acl, onProgress, surfaceId = null) {
    if (activeRecording) {
      throw new Error('This page is recording already; stop it with Ctrl+C in its tab');
    }
    const controller = new AbortController();
    const sinceMs = Date.now();
    const rec = activeRecording = {
      controller,
      surfaceId,
      device: null,
      version: null,
      recording: path,
      sinceMs,
      progress: '',
    };
    const emitLive = (active, note = null) => {
      if (surfaceId == null) return;
      sendMediaEvent(surfaceId, {
        event: 'live_sound_state',
        device: rec.device,
        version: rec.version,
        recording: rec.recording,
        since_ms: rec.sinceMs,
        progress: rec.progress,
        note,
        active,
      });
    };
    emitLive(true);
    const report = text => {
      rec.progress = text;
      emitLive(true);
      onProgress?.(text);
    };
    let microphone = null;
    let live = null;
    let liveNote = '';
    let speaking = Promise.resolve();
    try {
      try {
        microphone = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        });
      } catch (error) {
        throw new Error('No microphone: ' + error.message);
      }
      if (!path) {
        live = await publishLiveSound(name, microphone, { acl });
        rec.device = live.device;
        rec.version = live.version;
        emitLive(true);
        const started = performance.now();
        const track = microphone.getAudioTracks()[0];
        const seconds = () => (performance.now() - started) / 1000;
        const say = () => report(`● live as ${live.device} · ${fmtClock(seconds())}`);
        const ticking = setInterval(say, 1000);
        say();
        try {
          await new Promise(resolve => {
            controller.signal.addEventListener('abort', resolve, { once: true });
            track.addEventListener('ended', resolve, { once: true });
          });
        } finally {
          clearInterval(ticking);
        }
        return {
          seconds: seconds(),
          device: live.device,
          note: track.readyState === 'ended' && !controller.signal.aborted ? ' · the microphone stopped' : '',
        };
      }
      const saved = await recordToCloudFile(path, microphone, {
        acl,
        signal: controller.signal,
        progress: text => report(text + liveNote),
        begun: () => {
          speaking = publishLiveSound(name, microphone, { acl }).then(
            sent => {
              live = sent;
              rec.device = sent.device;
              rec.version = sent.version;
              liveNote = ` · live as ${sent.device}`;
              emitLive(true);
            },
            error => {
              liveNote = ` · not live: ${error.message}`;
            },
          );
        },
      });
      await speaking;
      return {
        ...saved,
        device: live?.device ?? null,
        note: liveNote + (saved.stopped ? ` · ${saved.stopped}` : ''),
      };
    } finally {
      if (activeRecording === rec) activeRecording = null;
      microphone?.getTracks().forEach(t => { try { t.stop(); } catch {} });
      await speaking;
      await live?.end();
      onChanged?.();
    }
  }

  function stopRecording() {
    if (!activeRecording) return false;
    activeRecording.controller.abort();
    return true;
  }

  async function handleMediaControl(cmd) {
    const { surface_id: surfaceId, request_id: requestId, control: op } = cmd;
    const action = op?.action;
    if (!op || typeof action !== 'string') return;
    try {
      if (action === 'fetch_present_state') {
        const device = String(op.device ?? '');
        const seg = device.startsWith('/dev/present/') ? device.slice('/dev/present/'.length) : '';
        if (!seg || seg === '.' || seg === '..' || /[/\\\0]/.test(seg)) {
          sendMediaEvent(surfaceId, {
            event: 'present_state',
            request_id: requestId,
            device,
            body_json: null,
            error: 'Invalid presentation device',
          });
          return;
        }
        // Async non-blocking fetch in page context so concurrent replacements and Close never stall.
        void (async () => {
          try {
            const response = await fetch('/api/file?path=' + encodeURIComponent(device));
            const text = await response.text();
            if (!response.ok) {
              let msg = `Request failed (${response.status})`;
              try {
                const parsed = JSON.parse(text);
                if (typeof parsed?.error === 'string' && parsed.error) msg = parsed.error;
              } catch {}
              sendMediaEvent(surfaceId, {
                event: 'present_state',
                request_id: requestId,
                device,
                body_json: null,
                error: msg,
              });
              return;
            }
            sendMediaEvent(surfaceId, {
              event: 'present_state',
              request_id: requestId,
              device,
              body_json: text,
              error: null,
            });
          } catch (err) {
            sendMediaEvent(surfaceId, {
              event: 'present_state',
              request_id: requestId,
              device,
              body_json: null,
              error: String(err?.message ?? err),
            });
          }
        })();
        return;
      }
      if (action === 'open_speaker') {
        const deckPath = String(op.path ?? '');
        const url = `/?speaker=${encodeURIComponent(deckPath)}`;
        if (speakerPopup && !speakerPopup.win.closed) {
          if (speakerPopup.path !== deckPath) {
            try {
              speakerPopup.win.location.href = url;
              speakerPopup.path = deckPath;
            } catch {
              sendMediaEvent(surfaceId, { event: 'speaker_opened', request_id: requestId, ok: false });
              return;
            }
          }
          try { speakerPopup.win.focus(); } catch {}
          sendMediaEvent(surfaceId, { event: 'speaker_opened', request_id: requestId, ok: true });
          return;
        }
        const opened = window.open(url, '_blank', 'popup,width=1280,height=800');
        speakerPopup = opened ? { win: opened, path: deckPath } : null;
        sendMediaEvent(surfaceId, { event: 'speaker_opened', request_id: requestId, ok: Boolean(opened) });
        return;
      }
      if (action === 'broadcast_present') {
        const at = [Number(op.column) || 0, Number(op.row) || 0];
        if (typeof op.path === 'string') {
          localPresented.set(op.path, at);
          if (op.path.startsWith('/mnt/cloud/')) {
            localPresented.set(op.path.slice('/mnt/cloud'.length), at);
          }
        }
        presentChannel?.postMessage({ path: op.path, at });
        return;
      }
      if (action === 'listen_sdp') {
        const streamId = String(op.stream_id);
        const label = String(op.label || streamId);
        const isVoice = Boolean(op.is_voice);
        stopStream(streamId);
        const audio = Object.assign(document.createElement('audio'), {
          ...(isVoice ? { className: 'voice-audio' } : { id: 'listening-audio' }),
          autoplay: true,
          hidden: true,
          muted,
        });
        document.body.append(audio);
        const pc = new RTCPeerConnection({ iceServers: ICE, bundlePolicy: 'max-bundle' });
        const st = { pc, audio, label, isVoice, surfaceId, standalone: false, version: null };
        listeningStreams.set(streamId, st);
        const player = $('listening');
        if (player && (!player.dataset.state || !isVoice)) player.dataset.state = 'connecting';
        updatePlayerUi();
        pc.ontrack = ev => { audio.srcObject = new MediaStream([ev.track]); };
        await pc.setRemoteDescription({ type: 'offer', sdp: String(op.offer_sdp) });
        await pc.setLocalDescription(await pc.createAnswer());
        sendMediaEvent(surfaceId, {
          event: 'sdp_answer',
          request_id: requestId,
          stream_id: streamId,
          sdp: pc.localDescription.sdp,
        });
        void waitConnected(pc).then(async () => {
          if (listeningStreams.get(streamId) !== st) return;
          if (player) player.dataset.state = 'live';
          try { await audio.play(); } catch {
            if (listeningStreams.get(streamId) === st && player) player.dataset.state = 'paused';
          }
          pc.addEventListener('connectionstatechange', () => {
            if (pc.connectionState === 'failed' && listeningStreams.get(streamId) === st) {
              sendMediaEvent(surfaceId, { event: 'stream_state', stream_id: streamId, state: 'failed' });
            }
          });
        }, () => {
          if (listeningStreams.get(streamId) === st) {
            sendMediaEvent(surfaceId, { event: 'stream_state', stream_id: streamId, state: 'failed' });
          }
        });
        return;
      }
      if (action === 'stop_listen') {
        if (op.stream_id) {
          stopStream(op.stream_id);
        } else {
          for (const [sid, st] of [...listeningStreams.entries()]) {
            if (st.surfaceId === surfaceId) stopStream(sid);
          }
        }
        return;
      }
      if (action === 'capture_mic_offer') {
        const streamId = String(op.stream_id);
        stopCapture(streamId);
        const mic = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        });
        const pc = new RTCPeerConnection({ iceServers: ICE, bundlePolicy: 'max-bundle' });
        const transceiver = pc.addTransceiver(mic.getAudioTracks()[0], { direction: 'sendonly' });
        await pc.setLocalDescription(await pc.createOffer());
        captureStreams.set(streamId, { pc, mic, surfaceId });
        mic.getAudioTracks()[0].addEventListener('ended', () => {
          if (captureStreams.has(streamId)) {
            stopCapture(streamId);
            sendMediaEvent(surfaceId, { event: 'stream_state', stream_id: streamId, state: 'mic_ended' });
          }
        }, { once: true });
        sendMediaEvent(surfaceId, {
          event: 'mic_offer',
          request_id: requestId,
          stream_id: streamId,
          sdp: pc.localDescription.sdp,
          mid: transceiver.mid ?? '0',
        });
        return;
      }
      if (action === 'capture_mic_answer') {
        const streamId = String(op.stream_id);
        const cap = captureStreams.get(streamId);
        if (!cap) return;
        await cap.pc.setRemoteDescription({ type: 'answer', sdp: String(op.answer_sdp) });
        await waitConnected(cap.pc);
        sendMediaEvent(surfaceId, { event: 'mic_connected', request_id: requestId, stream_id: streamId });
        return;
      }
      if (action === 'stop_capture') {
        stopCapture(String(op.stream_id));
        return;
      }
      if (action === 'go_live') {
        if (activeRecording) {
          stopRecording();
          return;
        }
        const deckPath = String(op.path ?? '');
        if (!deckPath.startsWith('/') || deckPath.includes('\0') || deckPath.split('/').includes('..')) {
          sendMediaEvent(surfaceId, {
            event: 'live_sound_state',
            device: null,
            version: null,
            recording: null,
            since_ms: 0,
            progress: '',
            note: 'Invalid path',
            active: false,
          });
          return;
        }
        const keep = Boolean(op.keep);
        const dest = keep ? recordingName(deckPath) : null;
        void recordSound(dest, null, null, null, surfaceId).then(
          saved => {
            sendMediaEvent(surfaceId, {
              event: 'live_sound_state',
              device: null,
              version: null,
              recording: null,
              since_ms: 0,
              progress: '',
              note: dest ? `Saved ${dest}` : (saved?.note || null),
              active: false,
            });
          },
          error => {
            sendMediaEvent(surfaceId, {
              event: 'live_sound_state',
              device: null,
              version: null,
              recording: null,
              since_ms: 0,
              progress: '',
              note: error?.message || String(error),
              active: false,
            });
          },
        );
        return;
      }
    } catch (error) {
      sendMediaEvent(surfaceId, {
        event: 'error',
        request_id: requestId,
        stream_id: op?.stream_id ?? null,
        detail: String(error?.message ?? error),
      });
    }
  }

  function handleSessionEventsCmd(cmd) {
    const { surface_id: surfaceId, control: op } = cmd;
    const action = op?.action;
    if (!op || typeof action !== 'string') return;
    if (action === 'subscribe') {
      subscribedSurfaces.add(surfaceId);
      return;
    }
    if (action === 'unsubscribe') {
      subscribedSurfaces.delete(surfaceId);
      surfaceFollowed.delete(surfaceId);
      syncFollows();
      return;
    }
    if (action === 'send' && typeof op.payload_json === 'string') {
      let parsed;
      try { parsed = JSON.parse(op.payload_json); } catch { return; }
      if (Array.isArray(parsed.follow)) {
        const list = parsed.follow.filter(x => typeof x === 'string' && x.length > 0);
        if (list.length) surfaceFollowed.set(surfaceId, list);
        else surfaceFollowed.delete(surfaceId);
        syncFollows();
        return;
      }
      if (typeof parsed.where === 'string' && parsed.where) {
        presentChannel?.postMessage({ ask_where: parsed.where });
      }
      // Only open/send `present` / `where` if we have a socket or are signed in to Cloud.
      if (cloudSignedIn || ws?.readyState === WebSocket.OPEN) {
        if (cloudSignedIn) ensureSocket();
        sendWs(parsed);
      }
    }
  }

  function cleanupSurface(surfaceId) {
    subscribedSurfaces.delete(surfaceId);
    surfaceFollowed.delete(surfaceId);
    for (const [sid, st] of [...listeningStreams.entries()]) {
      if (st.surfaceId === surfaceId) stopStream(sid);
    }
    for (const [sid, cap] of [...captureStreams.entries()]) {
      if (cap.surfaceId === surfaceId) stopCapture(sid);
    }
    if (activeRecording?.surfaceId === surfaceId) {
      stopRecording();
    }
    syncFollows();
  }

  function resetAll() {
    for (const sid of [...subscribedSurfaces]) cleanupSurface(sid);
    for (const sid of [...listeningStreams.keys()]) stopStream(sid);
    for (const sid of [...captureStreams.keys()]) stopCapture(sid);
    stopRecording();
  }

  function setCloudSignedIn(signedIn) {
    cloudSignedIn = Boolean(signedIn);
    if (cloudSignedIn) {
      openSocket(true);
    } else if (!wantsSocket()) {
      stopSocket();
    }
  }

  function reconnectIfCloudSignedIn() {
    if (cloudSignedIn) openSocket(true);
  }

  return {
    handleMediaControl,
    handleSessionEventsCmd,
    cleanupSurface,
    resetAll,
    setCloudSignedIn,
    reconnectIfCloudSignedIn,
    listenStandalone,
    recordSound,
    stopRecording,
  };
}
