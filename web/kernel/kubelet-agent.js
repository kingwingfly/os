// Portable Browser & Node `kubelet` worker node agent (Phase 9.1b #84).
//
// Runs identically inside:
// 1. A browser tab's kernel worker (lazily activated ONLY when `/usr/bin/kubelet` is started via
//    `kubelet.service`, speaking `abi::kubelet_ctl` over `/run/kubelet/host.sock`), and
// 2. Node.js (`tests/kubelet-multinode.mjs`) using the real compiled `client_kernel_bg.wasm`
//    `SandboxKernel` + `worker_threads` `sandbox-worker.js` against a live Miniflare Worker.
//
// ZERO outbound network calls occur until `enroll()` or `start()` is explicitly invoked.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const KUBELET_DB_NAME = 'os-kubelet-enrollment-v1';
const KUBELET_DB_STORE = 'enrollments';
const KUBELET_STORAGE_KEY = 'default';
const SAB_BYTES = 4 * 1024 * 1024;
const WATCH_TICKET_VERSION = 1;
const CLUSTER_PROTOCOL_VERSION = 1;
const AUTH_V2_VERSION = 2;

function bytesToB64(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeRecord(obj) {
  return bytesToB64(encoder.encode(JSON.stringify(obj)));
}

function decodeRecord(kv) {
  return JSON.parse(decoder.decode(b64ToBytes(kv.value_b64)));
}

function randomHex(byteLen = 32) {
  const buf = new Uint8Array(byteLen);
  crypto.getRandomValues(buf);
  let out = '';
  for (let i = 0; i < buf.length; i++) out += buf[i].toString(16).padStart(2, '0');
  return out;
}

function nowSecs() {
  return Math.floor(Date.now() / 1000);
}

function monoMs() {
  return Math.floor(typeof performance !== 'undefined' ? performance.now() : Date.now());
}

export function computeSelfFenceDeadlineMs(sendMonoMs, ttlSecs) {
  const ttlMs = Math.max(1, Number(ttlSecs || 5)) * 1000;
  const safety = Math.min(2000, Math.floor(ttlMs / 3));
  return sendMonoMs + Math.max(500, ttlMs - safety);
}

function createIndexedDbStorage() {
  let dbPromise = null;
  function openDb() {
    if (typeof indexedDB === 'undefined') return Promise.resolve(null);
    dbPromise ??= new Promise(resolve => {
      try {
        const req = indexedDB.open(KUBELET_DB_NAME, 1);
        req.onupgradeneeded = () => {
          if (!req.result.objectStoreNames.contains(KUBELET_DB_STORE)) {
            req.result.createObjectStore(KUBELET_DB_STORE);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
    return dbPromise;
  }
  return {
    async load() {
      const db = await openDb();
      if (!db) return null;
      return new Promise(resolve => {
        try {
          const tx = db.transaction(KUBELET_DB_STORE, 'readonly');
          const req = tx.objectStore(KUBELET_DB_STORE).get(KUBELET_STORAGE_KEY);
          req.onsuccess = () => resolve(req.result ?? null);
          req.onerror = () => resolve(null);
        } catch {
          resolve(null);
        }
      });
    },
    async save(enrollment) {
      const db = await openDb();
      if (!db) return;
      return new Promise(resolve => {
        try {
          const tx = db.transaction(KUBELET_DB_STORE, 'readwrite');
          tx.objectStore(KUBELET_DB_STORE).put(enrollment, KUBELET_STORAGE_KEY);
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
          tx.onabort = () => resolve();
        } catch {
          resolve();
        }
      });
    },
    async clear() {
      const db = await openDb();
      if (!db) return;
      return new Promise(resolve => {
        try {
          const tx = db.transaction(KUBELET_DB_STORE, 'readwrite');
          tx.objectStore(KUBELET_DB_STORE).delete(KUBELET_STORAGE_KEY);
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
        } catch {
          resolve();
        }
      });
    },
  };
}

function validRepoName(repo) {
  if (typeof repo !== 'string' || !repo.length || repo.length > 128) return false;
  const parts = repo.split('/');
  if (!parts.length) return false;
  for (const seg of parts) {
    if (!seg.length || seg === '.' || seg === '..') return false;
    if (seg.startsWith('.') || seg.endsWith('.') || seg.startsWith('-') || seg.endsWith('-')) return false;
    if (!/^[a-z0-9._-]+$/.test(seg)) return false;
  }
  return true;
}

function validInputMountName(name) {
  if (typeof name !== 'string' || !name.length || name.length > 64) return false;
  if (name === '.' || name === '..' || name === 'primary') return false;
  return /^[A-Za-z0-9._-]+$/.test(name);
}

function validEntrypoint(ep) {
  if (typeof ep !== 'string' || !ep.startsWith('/') || ep.length > 512 || ep.includes('\0')) return false;
  return !ep.split('/').includes('..');
}

function parseBoundedInt(raw, fallback, min, max) {
  if (raw === undefined || raw === null || raw === '') return fallback;
  if (typeof raw !== 'string' && typeof raw !== 'number') return null;
  const s = String(raw).trim();
  if (!/^\d+$/.test(s)) return null;
  const n = Number(s);
  if (!Number.isSafeInteger(n)) return null;
  return Math.min(max, Math.max(min, n));
}

function parseTaskSpec(wl) {
  const labels = wl.labels || {};
  if (labels['os.task/sdk_version'] !== '1') return null;
  const entrypoint = labels['os.task/entrypoint'];
  const output_repo = labels['os.task/output_repo'];
  if (!validEntrypoint(entrypoint) || !validRepoName(output_repo)) return null;
  const parseJson = (key, fallback) => {
    if (!labels[key]) return fallback;
    try { return JSON.parse(labels[key]); } catch { return null; }
  };
  const args = parseJson('os.task/args_json', []);
  if (!Array.isArray(args) || args.length > 256 || !args.every(a => typeof a === 'string')) return null;
  const env = parseJson('os.task/env_json', {});
  if (!env || typeof env !== 'object' || Array.isArray(env)) return null;
  for (const [k, v] of Object.entries(env)) {
    if (typeof k !== 'string' || typeof v !== 'string' || !k.length || k.includes('=') || k.includes('\0') || v.includes('\0')) {
      return null;
    }
  }
  const extra_inputs = parseJson('os.task/extra_inputs_json', {});
  if (!extra_inputs || typeof extra_inputs !== 'object' || Array.isArray(extra_inputs)) return null;
  const extraEntries = Object.entries(extra_inputs);
  if (extraEntries.length > 16) return null;
  for (const [name, ref] of extraEntries) {
    if (!validInputMountName(name) || typeof ref !== 'string' || !ref.length || ref.length > 512) return null;
  }
  const timeout_secs = parseBoundedInt(labels['os.task/timeout_secs'], 300, 1, 86_400);
  const memory_max_bytes = parseBoundedInt(labels['os.task/memory_max_bytes'], 128 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024);
  const pids_max = parseBoundedInt(labels['os.task/pids_max'], 16, 1, 256);
  if (timeout_secs === null || memory_max_bytes === null || pids_max === null) return null;
  return {
    workload_id: wl.workload_id,
    image_ref: wl.image_ref,
    entrypoint,
    args,
    env,
    input_snapshot_ref: wl.input_snapshot_ref ?? null,
    extra_inputs,
    output_repo,
    timeout_secs,
    memory_max_bytes,
    pids_max,
    required_host: labels['os.task/required_host'] || null,
    required_node: labels['os.task/required_node'] || null,
    required_caps: labels['os.task/required_caps']
      ? labels['os.task/required_caps'].split(',').map(s => s.trim()).filter(Boolean)
      : [],
  };
}

function exactRange(key) {
  return { op: 'range', key, range_end: 'exact', limit: 1 };
}

function normalizeUrl(base, path) {
  const root = (base || (typeof self !== 'undefined' && self.location ? self.location.origin : '')).replace(/\/+$/, '');
  return path.startsWith('http://') || path.startsWith('https://') ? path : `${root}${path}`;
}

function defaultOciFetch(fetchImpl, baseUrl) {
  return async (method, url, headersObj, bodyBytes) => {
    const resolved = normalizeUrl(baseUrl, url);
    const headers = {};
    if (headersObj && typeof headersObj === 'object') {
      for (const [k, v] of Object.entries(headersObj)) headers[k] = String(v);
    }
    const init = {
      method,
      headers,
      credentials: 'omit',
      redirect: 'error',
    };
    if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
      init.body = bodyBytes instanceof Uint8Array ? bodyBytes : new Uint8Array(bodyBytes || 0);
    }
    const resp = await fetchImpl(resolved, init);
    const body = method === 'HEAD'
      ? new Uint8Array(0)
      : new Uint8Array(await resp.arrayBuffer());
    const outHeaders = [];
    resp.headers.forEach((v, k) => outHeaders.push([k, v]));
    return { status: resp.status, headers: outHeaders, body };
  };
}

export class KubeletAgent {
  constructor(opts = {}) {
    this.baseUrl = (opts.baseUrl || (typeof self !== 'undefined' && self.location ? self.location.origin : '')).replace(/\/+$/, '');
    this.hostKind = opts.hostKind || 'browser';
    this.capabilities = opts.capabilities || ['wasix', 'cowfs', 'oci'];
    this.labels = { ...(opts.labels || {}) };
    this.leaseTtlSecs = Math.max(5, Math.min(300, Number(opts.leaseTtlSecs || 15)));
    this.fetchImpl = opts.fetchImpl || globalThis.fetch.bind(globalThis);
    this.WebSocketImpl = opts.WebSocketImpl || globalThis.WebSocket;
    this.storage = opts.storage || createIndexedDbStorage();
    this.getSandboxKernel = opts.getSandboxKernel || (() => globalThis.wasm_bindgen?.SandboxKernel);
    this.createSandboxWorker = opts.createSandboxWorker || (() => {
      const workerUrl = opts.sandboxWorkerUrl || '/sandbox-worker.js';
      return new Worker(workerUrl, { type: 'module' });
    });

    this.enrollment = null;
    this.state = 'stopped';
    this.running = false;
    this.draining = false;
    this.nodeGeneration = 0;
    this.leaseId = 0;
    this.nodeModRevision = 0;
    this.selfFenceDeadlineMs = 0;
    this.activeAttempt = null;
    this.completedAttempts = 0;
    this.lastError = null;

    this._stopRequested = false;
    this._wakeResolve = null;
    this._ws = null;
    this._loopPromise = null;
    this._kaTimer = null;
    this._authRenewTimer = null;
    this._fenceTimer = null;
    this._pollInFlight = false;
  }

  async loadEnrollment() {
    if (!this.enrollment && this.storage) {
      const loaded = await this.storage.load();
      if (loaded && loaded.token && loaded.enrollment_id && loaded.node_id) {
        this.enrollment = loaded;
        if (this.state === 'stopped') this.state = 'enrolled';
      }
    }
    return this.enrollment;
  }

  status() {
    return {
      state: this.state,
      enrolled: Boolean(this.enrollment),
      running: this.running,
      node_id: this.enrollment?.node_id ?? null,
      cluster: this.enrollment?.cluster ?? null,
      tenant: this.enrollment?.tenant ?? null,
      enrollment_id: this.enrollment?.enrollment_id ?? null,
      instance_id: this.enrollment?.instance_id ?? null,
      node_generation: this.nodeGeneration,
      active_attempts: this.activeAttempt ? 1 : 0,
      completed_attempts: this.completedAttempts,
      last_error: this.lastError,
    };
  }

  isSelfFenced() {
    return this.leaseId === 0 || this.selfFenceDeadlineMs === 0 || monoMs() >= this.selfFenceDeadlineMs;
  }

  _wake() {
    const fn = this._wakeResolve;
    this._wakeResolve = null;
    if (fn) fn();
  }

  _waitWake(ms) {
    return new Promise(resolve => {
      const timer = setTimeout(() => {
        if (this._wakeResolve === done) this._wakeResolve = null;
        resolve();
      }, ms);
      const done = () => {
        clearTimeout(timer);
        resolve();
      };
      this._wakeResolve = done;
    });
  }

  async _serviceAuthPost(reqObj, enrollmentId = null) {
    const url = normalizeUrl(this.baseUrl, '/api/service-auth');
    const headers = { 'Content-Type': 'application/json' };
    if (enrollmentId) headers['X-OS-Node-Enrollment'] = enrollmentId;
    const resp = await this.fetchImpl(url, {
      method: 'POST',
      headers,
      credentials: 'omit',
      body: JSON.stringify(reqObj),
    });
    const text = await resp.text();
    let parsed = null;
    try { parsed = JSON.parse(text); } catch { /* raw text */ }
    if (!resp.ok) {
      const err = new Error(parsed?.error || `service-auth HTTP ${resp.status}`);
      err.status = resp.status;
      err.errno = parsed?.errno || (resp.status === 403 ? 'EACCES' : 'EIO');
      throw err;
    }
    return parsed;
  }

  async _clusterRpc(call) {
    if (!this.enrollment) throw Object.assign(new Error('node not enrolled'), { errno: 'EACCES' });
    const url = normalizeUrl(this.baseUrl, '/api/cluster/rpc');
    const resp = await this.fetchImpl(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-OS-Instance': this.enrollment.instance_id,
        'X-Process-Token': this.enrollment.token,
      },
      credentials: 'omit',
      body: JSON.stringify({
        version: CLUSTER_PROTOCOL_VERSION,
        cluster: this.enrollment.cluster,
        call,
      }),
    });
    const text = await resp.text();
    let parsed = null;
    try { parsed = JSON.parse(text); } catch { /* ignore */ }
    if (!resp.ok) {
      const err = new Error(parsed?.detail || parsed?.error || `cluster RPC HTTP ${resp.status}`);
      err.status = resp.status;
      err.errno = parsed?.errno || (resp.status === 403 ? 'EACCES' : 'EIO');
      throw err;
    }
    return parsed;
  }

  async _ociRequest(token, method, path, headers = {}, body = null) {
    const url = normalizeUrl(this.baseUrl, path);
    const send = async extra => {
      const hdrs = { ...headers, ...extra };
      const init = { method, headers: hdrs, credentials: 'omit', redirect: 'error' };
      if (body != null && (method === 'PUT' || method === 'POST' || method === 'PATCH')) {
        init.body = body;
      }
      return this.fetchImpl(url, init);
    };
    const first = await send({});
    if (first.status !== 401) return first;
    const www = first.headers.get('www-authenticate') || '';
    const realm = www.match(/realm="([^"]+)"/)?.[1];
    if (!realm) return first;
    const service = www.match(/service="([^"]+)"/)?.[1];
    const scope = www.match(/scope="([^"]+)"/)?.[1];
    const tokUrl = new URL(realm, this.baseUrl);
    if (service) tokUrl.searchParams.set('service', service);
    if (scope) tokUrl.searchParams.set('scope', scope);
    const tokResp = await this.fetchImpl(tokUrl.href, {
      method: 'GET',
      headers: {
        'X-OS-Instance': this.enrollment.instance_id,
        'X-Process-Token': token,
      },
      credentials: 'omit',
      redirect: 'error',
    });
    if (!tokResp.ok) return first;
    const tokJson = await tokResp.json();
    const bearer = tokJson?.token || tokJson?.access_token;
    if (!bearer) return first;
    return send({ Authorization: `Bearer ${bearer}` });
  }

  async enroll(bootstrapToken, opts = {}) {
    if (opts.controlPlaneUrl) {
      this.baseUrl = opts.controlPlaneUrl.replace(/\/+$/, '');
    }
    const instanceId = `node-inst-${randomHex(16)}`;
    const hostProof = randomHex(32);
    const reply = await this._serviceAuthPost({
      exchange_bootstrap_token: {
        bootstrap_token: bootstrapToken,
        instance: { instance: instanceId, host: this.hostKind },
        host_proof: hostProof,
      },
    });
    const issued = reply?.node_enrolled;
    if (!issued) {
      throw Object.assign(new Error('unexpected exchange_bootstrap_token reply'), { errno: 'EIO' });
    }
    this.enrollment = {
      base_url: this.baseUrl,
      node_id: issued.node_id,
      cluster: issued.cluster,
      tenant: issued.tenant,
      enrollment_id: issued.enrollment_id,
      ns: issued.ns,
      instance_id: issued.instance_id,
      host_proof: hostProof,
      token: issued.token,
      scope: issued.scope,
      expires: issued.expires,
    };
    if (opts.labels && typeof opts.labels === 'object') {
      this.labels = { ...this.labels, ...opts.labels };
    }
    this.state = 'enrolled';
    this.lastError = null;
    if (this.storage) await this.storage.save(this.enrollment);
    return this.enrollment;
  }

  async _registerNode() {
    const en = this.enrollment;
    const metaKey = `/t/${en.tenant}/node-meta/${en.node_id}`;
    const nodeKey = `/t/${en.tenant}/nodes/${en.node_id}`;

    // Read durable node-meta to guarantee strictly monotonic node_generation across restarts.
    let prevGen = this.nodeGeneration;
    let prevEnrolledAt = nowSecs();
    let prevNodeModRev = null;
    try {
      const mr = await this._clusterRpc({ op: 'range', key: metaKey, range_end: 'exact', limit: 1 });
      if (mr.kvs?.length) {
        const meta = decodeRecord(mr.kvs[0]);
        prevEnrolledAt = meta.enrolled_at || prevEnrolledAt;
        const storedGen = Number(meta.labels?.['os.node/last_generation'] || 0);
        if (storedGen > prevGen) prevGen = storedGen;
      }
      const nr = await this._clusterRpc({ op: 'range', key: nodeKey, range_end: 'exact', limit: 1 });
      if (nr.kvs?.length) {
        prevNodeModRev = nr.kvs[0].mod_revision;
        const oldNode = decodeRecord(nr.kvs[0]);
        if (oldNode.node_generation > prevGen) prevGen = oldNode.node_generation;
      }
    } catch (e) {
      if (e.errno === 'EACCES') throw e;
    }

    const sendMs = monoMs();
    const granted = await this._clusterRpc({
      op: 'lease_grant',
      ttl_secs: this.leaseTtlSecs,
      node_id: en.node_id,
    });
    const leaseId = granted.lease_id;
    const ttlSecs = granted.ttl_secs;

    const nextGen = prevGen + 1;
    const now = nowSecs();
    const metaLabels = {
      ...this.labels,
      'os.node/last_generation': String(nextGen),
    };
    const metaRec = {
      node_id: en.node_id,
      host_kind: this.hostKind,
      labels: metaLabels,
      capabilities: [...this.capabilities],
      enrolled_at: prevEnrolledAt,
    };
    const nodeRec = {
      node_id: en.node_id,
      node_generation: nextGen,
      instance_id: en.instance_id,
      lease_id: leaseId,
      status: this.draining ? 'draining' : 'ready',
      heartbeat_at: now,
    };
    const guard = prevNodeModRev != null
      ? { key: nodeKey, op: 'equal', target: { mod_revision: prevNodeModRev } }
      : { key: nodeKey, op: 'equal', target: { version: 0 } };
    const txn = await this._clusterRpc({
      op: 'txn',
      compare: [guard],
      success: [
        { op: 'put', key: metaKey, value_b64: encodeRecord(metaRec), lease_id: 0, prev_kv: false },
        { op: 'put', key: nodeKey, value_b64: encodeRecord(nodeRec), lease_id: leaseId, prev_kv: false },
      ],
      failure: [exactRange(nodeKey)],
    });
    if (!txn.succeeded) {
      await this._clusterRpc({ op: 'lease_revoke', lease_id: leaseId }).catch(() => {});
      throw Object.assign(new Error('node registration CAS conflict'), { errno: 'ESTALE' });
    }
    this.nodeGeneration = nextGen;
    this.leaseId = leaseId;
    this.nodeModRevision = txn.revision;
    this.selfFenceDeadlineMs = computeSelfFenceDeadlineMs(sendMs, ttlSecs);
    return { nodeGeneration: nextGen, leaseId, ttlSecs, modRevision: txn.revision };
  }

  _abortActiveAttempt(reason) {
    const act = this.activeAttempt;
    if (!act) return;
    act.abortedReason = reason;
    if (act.worker) {
      try { act.worker.terminate(); } catch { /* already terminated */ }
    }
    if (act.abortResolve) {
      const fn = act.abortResolve;
      act.abortResolve = null;
      fn({ aborted: true, reason });
    }
  }

  _handleSelfFence(revoked = false) {
    this.selfFenceDeadlineMs = 0;
    this.leaseId = 0;
    if (revoked) {
      this.state = 'revoked';
      this.lastError = 'node credential revoked';
      this._stopRequested = true;
    }
    this._abortActiveAttempt(revoked ? 'revoked' : 'self-fenced');
    this._wake();
  }

  async _connectWatch() {
    if (!this.WebSocketImpl || !this.enrollment || this._stopRequested) return;
    const en = this.enrollment;
    try {
      const ticketResp = await this.fetchImpl(normalizeUrl(this.baseUrl, '/api/cluster/watch-ticket'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-OS-Instance': en.instance_id,
          'X-Process-Token': en.token,
        },
        credentials: 'omit',
        body: JSON.stringify({ version: WATCH_TICKET_VERSION, cluster: en.cluster }),
      });
      if (!ticketResp.ok) {
        if (ticketResp.status === 403) this._handleSelfFence(true);
        return;
      }
      const { ticket } = await ticketResp.json();
      const wsBase = this.baseUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
      const wsUrl = `${wsBase}/api/cluster/watch?cluster=${encodeURIComponent(en.cluster)}&ticket=${encodeURIComponent(ticket)}`;
      const ws = new this.WebSocketImpl(wsUrl);
      this._ws = ws;
      const wlPrefix = `/t/${en.tenant}/workloads/`;
      const nodesPrefix = `/t/${en.tenant}/nodes/`;

      ws.addEventListener('open', () => {
        try {
          ws.send(JSON.stringify({ op: 'hello', versions: [CLUSTER_PROTOCOL_VERSION] }));
        } catch { /* ignore */ }
      });
      ws.addEventListener('message', ev => {
        try {
          const text = typeof ev.data === 'string' ? ev.data : decoder.decode(new Uint8Array(ev.data));
          const frame = JSON.parse(text);
          if (frame.kind === 'welcome') {
            ws.send(JSON.stringify({ op: 'subscribe', watch_id: 1, key: wlPrefix, range_end: 'prefix', from_revision: 0, prev_kv: false }));
            ws.send(JSON.stringify({ op: 'subscribe', watch_id: 2, key: nodesPrefix, range_end: 'prefix', from_revision: 0, prev_kv: false }));
          } else if (frame.kind === 'events' && Array.isArray(frame.events)) {
            for (const e of frame.events) {
              const key = e.kv?.key || '';
              if (key.startsWith(wlPrefix) && key.endsWith('/canceled')) {
                const wid = key.slice(wlPrefix.length, -'/canceled'.length);
                if (this.activeAttempt && this.activeAttempt.workloadId === wid) {
                  this._abortActiveAttempt('canceled');
                }
              }
            }
            this._wake();
          } else if (frame.kind === 'compacted' || frame.kind === 'error') {
            this._wake();
          }
        } catch { /* ignore malformed frame */ }
      });
      ws.addEventListener('close', () => {
        if (this._ws === ws) this._ws = null;
        if (!this._stopRequested && this.running) {
          setTimeout(() => { if (!this._stopRequested && this.running) void this._connectWatch(); }, 500);
        }
      });
      ws.addEventListener('error', () => {
        try { ws.close(); } catch { /* ignore */ }
      });
    } catch {
      if (!this._stopRequested && this.running) {
        setTimeout(() => { if (!this._stopRequested && this.running) void this._connectWatch(); }, 500);
      }
    }
  }

  async _deriveStorageToken(workloadId) {
    const en = this.enrollment;
    const reply = await this._serviceAuthPost({
      derive_service_cred: {
        instance_id: en.instance_id,
        host_proof: en.host_proof,
        parent_token: en.token,
        scope: {
          cloud_fs: false,
          devices: [],
          containers: false,
          relay: false,
          volumes: true,
          volume_ids: [],
          volumes_ro: true,
          registry_pull: true,
          registry_push: true,
          registry_repos: [],
          cluster_read: false,
          cluster_write: false,
          cluster_watch: false,
          cluster_lease: false,
          cluster_compact: false,
          cluster_prefixes: [],
          cluster_node_id: null,
        },
        cloud_access: false,
        cgroup: `/services/kubelet/attempts/${workloadId}`,
        revoke_parent: false,
      },
    }, en.enrollment_id);
    if (!reply?.cred?.token) throw Object.assign(new Error('derive_service_cred failed'), { errno: 'EACCES' });
    return reply.cred.token;
  }

  async _revokeTokens(tokens) {
    if (!tokens.length || !this.enrollment) return;
    const en = this.enrollment;
    await this._serviceAuthPost({
      revoke_tokens: {
        instance_id: en.instance_id,
        host_proof: en.host_proof,
        tokens,
      },
    }, en.enrollment_id).catch(() => {});
  }

  async _pollAndExecuteOne() {
    if (this.draining || this.isSelfFenced() || this._stopRequested) return false;
    const en = this.enrollment;
    const wlPrefix = `/t/${en.tenant}/workloads/`;
    const list = await this._clusterRpc({
      op: 'range',
      key: wlPrefix,
      range_end: 'prefix',
      limit: 256,
    });
    const kvs = list.kvs || [];
    const canceledSet = new Set();
    const workloads = [];
    for (const kv of kvs) {
      const rest = kv.key.slice(wlPrefix.length);
      if (rest.endsWith('/canceled')) {
        canceledSet.add(rest.slice(0, -'/canceled'.length));
      } else if (!rest.includes('/')) {
        workloads.push(kv);
      }
    }

    for (const wlKv of workloads) {
      if (this.draining || this.isSelfFenced() || this._stopRequested) return false;
      let wl;
      try { wl = decodeRecord(wlKv); } catch { continue; }
      if (canceledSet.has(wl.workload_id)) continue;
      if (wl.desired_state !== 'pending' && wl.desired_state !== 'running') continue;

      const spec = parseTaskSpec(wl);
      if (!spec) continue;
      if (spec.required_host && spec.required_host !== this.hostKind) continue;
      if (spec.required_node && spec.required_node !== en.node_id) continue;
      if (spec.required_caps.some(c => !this.capabilities.includes(c))) continue;

      // Attempt claim (pending) or dead-node reclaim (running).
      let claimed = null;
      if (wl.desired_state === 'pending' && wl.current_attempt === 0) {
        claimed = await this._tryClaimPending(wlKv, wl);
      } else if (wl.desired_state === 'running' && wl.current_attempt >= 1) {
        claimed = await this._tryReclaimDead(wlKv, wl);
      }
      if (!claimed) continue;

      await this._executeClaimed(spec, claimed);
      return true;
    }
    return false;
  }

  async _tryClaimPending(wlKv, wl) {
    const en = this.enrollment;
    const wid = wl.workload_id;
    const attemptGen = 1;
    const cancelK = `/t/${en.tenant}/workloads/${wid}/canceled`;
    const wlK = `/t/${en.tenant}/workloads/${wid}`;
    const nodeK = `/t/${en.tenant}/nodes/${en.node_id}`;
    const attK = `/t/${en.tenant}/attempts/${wid}/${attemptGen}`;
    const updatedWl = { ...wl, desired_state: 'running', current_attempt: attemptGen };
    const attempt = {
      workload_id: wid,
      attempt_generation: attemptGen,
      node_id: en.node_id,
      node_generation: this.nodeGeneration,
      node_lease_id: this.leaseId,
      state: 'running',
      claimed_at: nowSecs(),
    };
    const res = await this._clusterRpc({
      op: 'txn',
      compare: [
        { key: cancelK, op: 'equal', target: { version: 0 } },
        { key: wlK, op: 'equal', target: { mod_revision: wlKv.mod_revision } },
        { key: nodeK, op: 'equal', target: { mod_revision: this.nodeModRevision } },
        { key: nodeK, op: 'equal', target: { lease: this.leaseId } },
        { key: attK, op: 'equal', target: { version: 0 } },
      ],
      success: [
        { op: 'put', key: wlK, value_b64: encodeRecord(updatedWl), lease_id: 0, prev_kv: false },
        { op: 'put', key: attK, value_b64: encodeRecord(attempt), lease_id: 0, prev_kv: false },
      ],
      failure: [exactRange(cancelK), exactRange(wlK), exactRange(nodeK), exactRange(attK)],
    });
    if (!res.succeeded) return null;
    return {
      workload: updatedWl,
      workloadModRev: res.revision,
      attempt,
      attemptModRev: res.revision,
    };
  }

  async _tryReclaimDead(wlKv, wl) {
    const en = this.enrollment;
    const wid = wl.workload_id;
    const prevGen = wl.current_attempt;
    const prevAttK = `/t/${en.tenant}/attempts/${wid}/${prevGen}`;
    const prevAttR = await this._clusterRpc({ op: 'range', key: prevAttK, range_end: 'exact', limit: 1 });
    if (!prevAttR.kvs?.length) return null;
    const prevAttKv = prevAttR.kvs[0];
    let prevAtt;
    try { prevAtt = decodeRecord(prevAttKv); } catch { return null; }

    // Fast pre-check: is prior node still holding prevAtt.node_lease_id?
    const prevNodeK = `/t/${en.tenant}/nodes/${prevAtt.node_id}`;
    const prevNodeR = await this._clusterRpc({ op: 'range', key: prevNodeK, range_end: 'exact', limit: 1 });
    if (prevNodeR.kvs?.length && prevNodeR.kvs[0].lease_id === prevAtt.node_lease_id) {
      return null;
    }

    const nextGen = prevGen + 1;
    const cancelK = `/t/${en.tenant}/workloads/${wid}/canceled`;
    const resK = `/t/${en.tenant}/results/${wid}`;
    const wlK = `/t/${en.tenant}/workloads/${wid}`;
    const nodeK = `/t/${en.tenant}/nodes/${en.node_id}`;
    const attK = `/t/${en.tenant}/attempts/${wid}/${nextGen}`;
    const now = nowSecs();
    const abortedPrev = { ...prevAtt, state: 'aborted', finished_at: now };
    const updatedWl = { ...wl, desired_state: 'running', current_attempt: nextGen };
    const newAttempt = {
      workload_id: wid,
      attempt_generation: nextGen,
      node_id: en.node_id,
      node_generation: this.nodeGeneration,
      node_lease_id: this.leaseId,
      state: 'running',
      claimed_at: now,
    };
    const res = await this._clusterRpc({
      op: 'txn',
      compare: [
        { key: cancelK, op: 'equal', target: { version: 0 } },
        { key: resK, op: 'equal', target: { version: 0 } },
        { key: wlK, op: 'equal', target: { mod_revision: wlKv.mod_revision } },
        { key: prevAttK, op: 'equal', target: { mod_revision: prevAttKv.mod_revision } },
        { key: prevNodeK, op: 'not_equal', target: { lease: prevAtt.node_lease_id } },
        { key: nodeK, op: 'equal', target: { mod_revision: this.nodeModRevision } },
        { key: nodeK, op: 'equal', target: { lease: this.leaseId } },
        { key: attK, op: 'equal', target: { version: 0 } },
      ],
      success: [
        { op: 'put', key: prevAttK, value_b64: encodeRecord(abortedPrev), lease_id: 0, prev_kv: false },
        { op: 'put', key: wlK, value_b64: encodeRecord(updatedWl), lease_id: 0, prev_kv: false },
        { op: 'put', key: attK, value_b64: encodeRecord(newAttempt), lease_id: 0, prev_kv: false },
      ],
      failure: [exactRange(cancelK), exactRange(resK), exactRange(wlK), exactRange(prevNodeK), exactRange(nodeK), exactRange(attK)],
    });
    if (!res.succeeded) return null;
    return {
      workload: updatedWl,
      workloadModRev: res.revision,
      attempt: newAttempt,
      attemptModRev: res.revision,
    };
  }

  async _executeClaimed(spec, claimed) {
    const en = this.enrollment;
    const wid = spec.workload_id;
    const attemptGen = claimed.attempt.attempt_generation;
    const nodeGen = claimed.attempt.node_generation;
    const SandboxKernel = this.getSandboxKernel();
    if (!SandboxKernel) {
      throw Object.assign(new Error('SandboxKernel wasm binding unavailable'), { errno: 'ENOSYS' });
    }

    const storageToken = await this._deriveStorageToken(wid);
    const active = {
      workloadId: wid,
      attemptGeneration: attemptGen,
      worker: null,
      abortedReason: null,
      abortResolve: null,
    };
    this.activeAttempt = active;

    let sb = null;
    let staged = null;
    try {
      const bootCfg = {
        workload_id: wid,
        attempt_generation: attemptGen,
        node_generation: nodeGen,
        node_id: en.node_id,
        image_ref: spec.image_ref,
        entrypoint: spec.entrypoint,
        args: spec.args,
        env: spec.env,
        input_ref: spec.input_snapshot_ref,
        extra_inputs: spec.extra_inputs,
        base_url: this.baseUrl,
        storage_token: storageToken,
        instance_id: en.instance_id,
        memory_max_bytes: spec.memory_max_bytes,
        pids_max: spec.pids_max,
      };
      const ociFetch = defaultOciFetch(this.fetchImpl, this.baseUrl);
      let exitCode = 0;
      let summary = null;
      try {
        sb = await SandboxKernel.boot(JSON.stringify(bootCfg), ociFetch);
      } catch (bootErr) {
        const rawMsg = String(bootErr?.message ?? bootErr ?? '');
        let errnoName = String(bootErr?.errno ?? bootErr?.code ?? '');
        if (!errnoName) {
          try { errnoName = JSON.parse(rawMsg)?.errno || ''; } catch { /* ignore */ }
        }
        if (errnoName === 'ENOEXEC' || rawMsg.includes('ENOEXEC') || /exec format error/i.test(rawMsg)) {
          await this._publishResult(spec, claimed, 126, null, 'ENOEXEC: ELF or non-Wasm binaries are not supported');
          this.completedAttempts++;
          return;
        }
        await this._publishResult(spec, claimed, 127, null, `sandbox boot failed: ${rawMsg}`.slice(0, 900));
        this.completedAttempts++;
        return;
      }

      if (active.abortedReason || this.isSelfFenced()) return;

      // Spawn isolated zero-token WASI worker & serve SAB syscalls via `sb.wasi_call`.
      const sab = new SharedArrayBuffer(SAB_BYTES);
      const ctrl = new Int32Array(sab, 0, 16);
      const data = new Uint8Array(sab, 64);
      const worker = await this.createSandboxWorker();
      active.worker = worker;

      const handleWasiReq = async () => {
        try {
          const reqJsonLen = Atomics.load(ctrl, 1);
          const reqBinLen = Atomics.load(ctrl, 2);
          const reqJson = decoder.decode(data.slice(0, reqJsonLen));
          const reqBin = reqBinLen > 0 ? data.slice(reqJsonLen, reqJsonLen + reqBinLen) : new Uint8Array(0);
          const reply = await sb.wasi_call(reqJson, reqBin);
          const errno = Number(reply?.errno ?? 29);
          const outBytes = reply?.bytes instanceof Uint8Array ? reply.bytes : new Uint8Array(0);
          const meta = {};
          if (reply && typeof reply === 'object') {
            for (const [k, v] of Object.entries(reply)) {
              if (k !== 'errno' && k !== 'bytes') meta[k] = v;
            }
          }
          const respJson = encoder.encode(JSON.stringify(meta));
          if (respJson.byteLength + outBytes.byteLength <= data.byteLength) {
            data.set(respJson, 0);
            if (outBytes.byteLength > 0) data.set(outBytes, respJson.byteLength);
            Atomics.store(ctrl, 3, respJson.byteLength);
            Atomics.store(ctrl, 4, outBytes.byteLength);
            Atomics.store(ctrl, 5, errno);
          } else {
            Atomics.store(ctrl, 3, 0);
            Atomics.store(ctrl, 4, 0);
            Atomics.store(ctrl, 5, 29);
          }
        } catch {
          Atomics.store(ctrl, 3, 0);
          Atomics.store(ctrl, 4, 0);
          Atomics.store(ctrl, 5, 29);
        }
        Atomics.store(ctrl, 0, 2);
        Atomics.notify(ctrl, 0, 1);
      };

      const runResult = await new Promise(resolve => {
        let settled = false;
        const finish = val => {
          if (settled) return;
          settled = true;
          clearTimeout(timeoutId);
          active.abortResolve = null;
          resolve(val);
        };
        active.abortResolve = finish;
        const timeoutId = setTimeout(() => {
          active.abortedReason = 'timeout';
          try { worker.terminate(); } catch { /* ignore */ }
          finish({ aborted: true, reason: 'timeout' });
        }, spec.timeout_secs * 1000);

        const onMsg = msg => {
          if (msg?.type === 'wasi_req') {
            void handleWasiReq();
          } else if (msg?.type === 'exit') {
            finish({ aborted: false, code: Number(msg.code ?? 0) });
          } else if (msg?.type === 'error') {
            finish({ aborted: false, code: Number(msg.code ?? 1), error: msg.message || msg.errno || 'error' });
          }
        };

        if (typeof worker.on === 'function') {
          worker.on('message', onMsg);
          worker.on('error', err => finish({ aborted: false, code: 1, error: String(err?.message ?? err) }));
          worker.on('exit', code => finish({ aborted: Boolean(active.abortedReason), reason: active.abortedReason, code: code || 137 }));
        } else {
          worker.onmessage = ev => onMsg(ev.data);
          worker.onerror = ev => finish({ aborted: false, code: 1, error: String(ev?.message || 'worker error') });
        }

        const wasmBytes = sb.executable_bytes();
        const argv = JSON.parse(sb.argv_json());
        const env = JSON.parse(sb.env_json());
        const memoryMaxBytes = Number(sb.memory_max_bytes());
        worker.postMessage({ type: 'boot', wasmBytes, argv, env, memoryMaxBytes, sab });
      });

      try { await worker.terminate(); } catch { /* ignore */ }
      active.worker = null;

      if (runResult.aborted || active.abortedReason) {
        if (runResult.reason === 'timeout') {
          await this._publishResult(spec, claimed, 124, null, 'task timed out');
          this.completedAttempts++;
        }
        return;
      }

      exitCode = runResult.code;
      summary = (await sb.read_summary()) || runResult.error || null;
      if (summary && summary.length > 900) summary = summary.slice(0, 900);

      if (exitCode === 0 && !this.isSelfFenced() && !active.abortedReason) {
        const stagingTag = `staging-${wid}-${attemptGen}-${nodeGen}`;
        const annotation = `${wid}:${attemptGen}:${nodeGen}`;
        const stagedJson = await sb.stage_output(spec.output_repo, stagingTag, annotation);
        staged = JSON.parse(stagedJson);
      }

      if (this.isSelfFenced() || active.abortedReason) {
        if (staged) await this._cleanupStaged(storageToken, staged);
        return;
      }

      const published = await this._publishResult(
        spec,
        claimed,
        exitCode,
        staged ? staged.output_ref : null,
        summary,
      );
      if (published.succeeded) {
        if (staged) {
          await this._promoteStaged(storageToken, wid, staged);
          staged = null;
        }
        this.completedAttempts++;
      } else {
        if (staged) {
          await this._cleanupStaged(storageToken, staged);
          staged = null;
        }
        if (published.nodeFenced) {
          this._handleSelfFence(false);
        }
      }
    } finally {
      if (staged) {
        await this._cleanupStaged(storageToken, staged).catch(() => {});
      }
      if (sb) {
        try { await sb.close(); } catch { /* ignore */ }
        try { sb.free?.(); } catch { /* ignore */ }
      }
      if (this.activeAttempt === active) this.activeAttempt = null;
      await this._revokeTokens([storageToken]);
    }
  }

  async _publishResult(spec, claimed, exitCode, outputRef, summary) {
    const en = this.enrollment;
    const wid = spec.workload_id;
    const attemptGen = claimed.attempt.attempt_generation;
    const now = nowSecs();
    const cancelK = `/t/${en.tenant}/workloads/${wid}/canceled`;
    const wlK = `/t/${en.tenant}/workloads/${wid}`;
    const nodeK = `/t/${en.tenant}/nodes/${en.node_id}`;
    const attK = `/t/${en.tenant}/attempts/${wid}/${attemptGen}`;
    const resK = `/t/${en.tenant}/results/${wid}`;

    const finishedWl = {
      ...claimed.workload,
      desired_state: exitCode === 0 ? 'succeeded' : 'failed',
    };
    const finishedAtt = {
      ...claimed.attempt,
      state: exitCode === 0 ? 'succeeded' : 'failed',
      finished_at: now,
    };
    const resultRec = {
      workload_id: wid,
      attempt_generation: attemptGen,
      node_id: en.node_id,
      node_generation: claimed.attempt.node_generation,
      exit_code: exitCode,
      ...(outputRef ? { output_ref: outputRef } : {}),
      ...(summary ? { summary } : {}),
      published_at: now,
    };

    const reply = await this._clusterRpc({
      op: 'txn',
      compare: [
        { key: cancelK, op: 'equal', target: { version: 0 } },
        { key: wlK, op: 'equal', target: { mod_revision: claimed.workloadModRev } },
        { key: nodeK, op: 'equal', target: { mod_revision: this.nodeModRevision } },
        { key: nodeK, op: 'equal', target: { lease: this.leaseId } },
        { key: attK, op: 'equal', target: { mod_revision: claimed.attemptModRev } },
        { key: resK, op: 'equal', target: { version: 0 } },
      ],
      success: [
        { op: 'put', key: resK, value_b64: encodeRecord(resultRec), lease_id: 0, prev_kv: false },
        { op: 'put', key: attK, value_b64: encodeRecord(finishedAtt), lease_id: 0, prev_kv: false },
        { op: 'put', key: wlK, value_b64: encodeRecord(finishedWl), lease_id: 0, prev_kv: false },
      ],
      failure: [exactRange(cancelK), exactRange(resK), exactRange(nodeK), exactRange(attK), exactRange(wlK)],
    });
    if (reply.succeeded) return { succeeded: true, nodeFenced: false };
    const nodeFail = reply.responses?.[2]?.kvs?.[0];
    const nodeFenced = !nodeFail || nodeFail.mod_revision !== this.nodeModRevision || nodeFail.lease_id !== this.leaseId;
    return { succeeded: false, nodeFenced };
  }

  async _promoteStaged(token, wid, staged) {
    const repo = staged.repo;
    const getResp = await this._ociRequest(
      token,
      'GET',
      `/v2/${repo}/manifests/${staged.manifest_digest}`,
      { Accept: staged.media_type },
    );
    if (!getResp.ok) return;
    const raw = new Uint8Array(await getResp.arrayBuffer());
    const ct = getResp.headers.get('content-type') || staged.media_type;
    await this._ociRequest(
      token,
      'PUT',
      `/v2/${repo}/manifests/result-${wid}`,
      { 'Content-Type': ct },
      raw,
    );
    await this._ociRequest(
      token,
      'DELETE',
      `/v2/${repo}/manifests/${staged.staging_tag}`,
    ).catch(() => {});
  }

  async _cleanupStaged(token, staged) {
    const repo = staged.repo;
    await this._ociRequest(
      token,
      'DELETE',
      `/v2/${repo}/manifests/${staged.staging_tag}`,
    ).catch(() => {});
    await this._ociRequest(
      token,
      'DELETE',
      `/v2/${repo}/manifests/${staged.manifest_digest}`,
    ).catch(() => {});
  }

  async start(opts = {}) {
    await this.loadEnrollment();
    if (!this.enrollment) {
      throw Object.assign(new Error('node not enrolled; run enroll first'), { errno: 'ENOENT' });
    }
    if (opts.controlPlaneUrl) this.baseUrl = opts.controlPlaneUrl.replace(/\/+$/, '');
    if (opts.labels && typeof opts.labels === 'object') this.labels = { ...this.labels, ...opts.labels };
    if (opts.leaseTtlSecs) this.leaseTtlSecs = Math.max(5, Math.min(300, Number(opts.leaseTtlSecs)));
    if (this.running) return this.status();

    this._stopRequested = false;
    this.draining = false;
    await this._registerNode();
    this.running = true;
    this.state = 'running';
    this.lastError = null;

    // Periodic ClusterState LeaseKeepAlive.
    const kaMs = Math.max(1000, Math.floor((this.leaseTtlSecs * 1000) / 3));
    this._kaTimer = setInterval(async () => {
      if (!this.running || this._stopRequested || this.leaseId === 0) return;
      const sendMs = monoMs();
      if (this.isSelfFenced()) {
        this._handleSelfFence(false);
        return;
      }
      const sentLeaseId = this.leaseId;
      try {
        const res = await this._clusterRpc({ op: 'lease_keep_alive', lease_id: sentLeaseId });
        if (this.running && !this._stopRequested && this.leaseId === sentLeaseId) {
          this.selfFenceDeadlineMs = computeSelfFenceDeadlineMs(sendMs, res.ttl_secs);
        }
      } catch (e) {
        if (!this.running || this._stopRequested || this.leaseId !== sentLeaseId) return;
        if (e.errno === 'EACCES') {
          this._handleSelfFence(true);
        } else if (e.errno === 'ENOENT' || e.errno === 'ESTALE') {
          this._handleSelfFence(false);
        }
      }
    }, kaMs);

    // Periodic client-monotonic self-fence watchdog.
    this._fenceTimer = setInterval(() => {
      if (this.running && this.leaseId !== 0 && monoMs() >= this.selfFenceDeadlineMs) {
        this._handleSelfFence(false);
      }
    }, 250);

    // Periodic ServiceAuth v2 RenewInstance (every 30s).
    this._authRenewTimer = setInterval(async () => {
      if (!this.running || this._stopRequested || !this.enrollment) return;
      const en = this.enrollment;
      try {
        const reply = await this._serviceAuthPost({
          renew_instance: {
            instance_id: en.instance_id,
            host_proof: en.host_proof,
            active_tokens: [en.token],
          },
        }, en.enrollment_id);
        if (reply?.renewed?.revoked?.includes(en.token)) {
          this._handleSelfFence(true);
        }
      } catch (e) {
        if (e.errno === 'EACCES' || e.status === 403 || e.status === 404) {
          this._handleSelfFence(true);
        }
      }
    }, 30_000);

    // Live WebSocket watch for instant workload discovery & instant cancel kill.
    void this._connectWatch();

    // Main poll & execute loop.
    this._loopPromise = (async () => {
      while (!this._stopRequested) {
        try {
          if (this.isSelfFenced()) {
            if (this.state === 'revoked') break;
            try {
              await this._registerNode();
              this.state = this.draining ? 'draining' : 'running';
              this.lastError = null;
            } catch (e) {
              this.lastError = String(e?.message ?? e);
              if (e.errno === 'EACCES') {
                this._handleSelfFence(true);
                break;
              }
              await this._waitWake(1000);
              continue;
            }
          }
          const didWork = await this._pollAndExecuteOne();
          if (didWork) continue;
        } catch (e) {
          this.lastError = String(e?.message ?? e);
          if (e.errno === 'EACCES') {
            this._handleSelfFence(true);
            break;
          }
        }
        await this._waitWake(500);
      }
      this.running = false;
      if (this.state !== 'revoked') this.state = this.enrollment ? 'enrolled' : 'stopped';
    })();

    return this.status();
  }

  async drain() {
    this.draining = true;
    if (this.running) this.state = 'draining';
    this._wake();
    return this.status();
  }

  async stop() {
    this._stopRequested = true;
    this.draining = true;
    this._abortActiveAttempt('stop');
    this._wake();
    clearInterval(this._kaTimer);
    clearInterval(this._fenceTimer);
    clearInterval(this._authRenewTimer);
    this._kaTimer = null;
    this._fenceTimer = null;
    this._authRenewTimer = null;
    if (this._ws) {
      try { this._ws.close(); } catch { /* ignore */ }
      this._ws = null;
    }
    if (this._loopPromise) {
      await Promise.race([this._loopPromise.catch(() => {}), new Promise(r => setTimeout(r, 2000))]);
      this._loopPromise = null;
    }
    if (this.leaseId !== 0 && this.enrollment) {
      const lid = this.leaseId;
      this.leaseId = 0;
      await this._clusterRpc({ op: 'lease_revoke', lease_id: lid }).catch(() => {});
    }
    this.running = false;
    if (this.state !== 'revoked') this.state = this.enrollment ? 'enrolled' : 'stopped';
    return this.status();
  }

  async handleHostControlRequest(reqJson) {
    try {
      const req = JSON.parse(reqJson);
      switch (req.op) {
        case 'hello':
          if (!Array.isArray(req.versions) || !req.versions.includes(1)) {
            return JSON.stringify({ kind: 'error', errno: 'EPROTONOSUPPORT', message: 'kubelet_ctl v1 required' });
          }
          return JSON.stringify({ kind: 'welcome', version: 1, host_kind: this.hostKind });
        case 'enroll': {
          const en = await this.enroll(req.bootstrap_token, {
            controlPlaneUrl: req.control_plane_url || undefined,
            labels: req.labels || {},
          });
          return JSON.stringify({
            kind: 'enrolled',
            node_id: en.node_id,
            cluster: en.cluster,
            tenant: en.tenant,
            enrollment_id: en.enrollment_id,
            instance_id: en.instance_id,
          });
        }
        case 'start': {
          const status = await this.start({
            controlPlaneUrl: req.control_plane_url || undefined,
            labels: req.labels || {},
            leaseTtlSecs: req.lease_ttl_secs || undefined,
          });
          return JSON.stringify({ kind: 'started', status });
        }
        case 'status':
          await this.loadEnrollment();
          return JSON.stringify({ kind: 'status', status: this.status() });
        case 'drain':
          return JSON.stringify({ kind: 'draining', status: await this.drain() });
        case 'stop':
          return JSON.stringify({ kind: 'stopped', status: await this.stop() });
        default:
          return JSON.stringify({ kind: 'error', errno: 'EINVAL', message: `unknown op ${req.op}` });
      }
    } catch (e) {
      return JSON.stringify({
        kind: 'error',
        errno: e?.errno || 'EIO',
        message: String(e?.message ?? e),
      });
    }
  }
}

// Lazy browser `/run/kubelet/host.sock` host bridge — instantiated ONLY when `/usr/bin/kubelet`
// is actually launched by `kubelet.service` (ZERO network calls and ZERO overhead at default boot).
let activeHost = null;

async function sendKubeletFrame(socketOp, sockId, payloadStr) {
  const payload = encoder.encode(payloadStr);
  const frame = new Uint8Array(4 + payload.length);
  const dv = new DataView(frame.buffer);
  dv.setUint32(0, payload.length, false);
  frame.set(payload, 4);
  let sent = 0;
  while (sent < frame.length) {
    try {
      const chunk = frame.subarray(sent, Math.min(frame.length, sent + 4096));
      const r = await socketOp({ op: 'sendmsg', sockId, fds: [], data: bytesToB64(chunk) });
      if (!r?.sent) throw Object.assign(new Error('peer closed'), { errno: 'EPIPE' });
      sent += r.sent;
    } catch (err) {
      if (err?.errno === 'EAGAIN') {
        await new Promise(r => setTimeout(r, 5));
        continue;
      }
      throw err;
    }
  }
}

export async function ensureKubeletHost({ kernel, asset, socketOp }) {
  if (activeHost) return activeHost;
  const listenerId = await kernel.bind_kubelet_host_socket();
  const agent = new KubeletAgent({
    hostKind: 'browser',
    sandboxWorkerUrl: asset('/sandbox-worker.js'),
  });
  let closed = false;

  const handleClient = async (clientSockId, acceptedCred) => {
    try {
      const cred = acceptedCred ?? await socketOp({ op: 'peercred', sockId: clientSockId });
      if (!cred || cred.uid !== 0 || !kernel.is_service_image(cred.pid, 'kubelet')) {
        return;
      }
      const chunks = [];
      let totalBytes = 0;
      let expectedTotal = null;
      const deadline = Date.now() + 5000;
      while (!closed && Date.now() < deadline) {
        const r = await socketOp({ op: 'recvmsg', sockId: clientSockId, sabStream: true, bufLen: 4096, maxFds: 0 });
        if (r?.wouldBlock) {
          await new Promise(res => setTimeout(res, 10));
          continue;
        }
        const part = typeof r?.data === 'string'
          ? b64ToBytes(r.data)
          : r?.data instanceof Uint8Array ? r.data : new Uint8Array(r?.data ?? []);
        if (!part.length) break;
        totalBytes += part.length;
        if (totalBytes > 65_536 + 4) break;
        chunks.push(part);
        if (expectedTotal === null && totalBytes >= 4) {
          const head = new Uint8Array(4);
          let off = 0;
          for (const c of chunks) {
            const take = Math.min(4 - off, c.length);
            head.set(c.subarray(0, take), off);
            off += take;
            if (off >= 4) break;
          }
          const len = new DataView(head.buffer).getUint32(0, false);
          expectedTotal = 4 + len;
        }
        if (expectedTotal !== null && totalBytes >= expectedTotal) break;
      }
      let replyJson;
      if (expectedTotal !== null && totalBytes >= expectedTotal && expectedTotal <= 65_536 + 4) {
        const merged = new Uint8Array(totalBytes);
        let pos = 0;
        for (const c of chunks) {
          merged.set(c, pos);
          pos += c.length;
        }
        const reqJson = decoder.decode(merged.subarray(4, expectedTotal));
        replyJson = await agent.handleHostControlRequest(reqJson);
      } else {
        replyJson = JSON.stringify({ kind: 'error', errno: 'EINVAL', message: 'incomplete kubelet control frame' });
      }
      await sendKubeletFrame(socketOp, clientSockId, replyJson);
    } catch {
      /* peer closed or timed out */
    } finally {
      await socketOp({ op: 'close', sockId: clientSockId }).catch(() => {});
    }
  };

  const pollLoop = (async () => {
    while (!closed) {
      try {
        const res = await socketOp({ op: 'accept', sockId: listenerId });
        if (closed) break;
        if (res?.wouldBlock) {
          await new Promise(r => setTimeout(r, 20));
          continue;
        }
        if (res?.sockId != null) {
          void handleClient(res.sockId, res.peerCred);
        }
      } catch {
        if (closed) break;
        await new Promise(r => setTimeout(r, 50));
      }
    }
  })();

  activeHost = {
    agent,
    listenerId,
    async stop() {
      closed = true;
      await agent.stop().catch(() => {});
      await socketOp({ op: 'close', sockId: listenerId }).catch(() => {});
      await pollLoop.catch(() => {});
      if (activeHost?.listenerId === listenerId) activeHost = null;
    },
  };
  return activeHost;
}

export async function resetKubeletHost() {
  if (!activeHost) return;
  const host = activeHost;
  activeHost = null;
  await host.stop();
}
