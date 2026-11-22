import { verifyRelease, resolveOfflineInstalledRelease } from './release.js';
import { attachConsole, dimensions } from './kernel/page.js';
import { createBootProfileStore } from './kernel/boot-profile.js';
import { createCowfsStore } from './kernel/cowfs-store.js';
import { createImagePager } from './kernel/image-pager.js';
import { createOfflineInstaller, registerOfflineServiceWorker } from './kernel/offline-installer.js';

const IS_WORKER = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(digest));
}

// =============================================================================
// Dedicated Worker entrypoint: hosts real OPFS FileSystemSyncAccessHandle +
// strict IndexedDB + Web Locks (`os-vol:<uuid>`) + compiled `OfflineBootRuntime`
// with ZERO outbound network requests.
// =============================================================================
if (IS_WORKER) {
  let runtime = null;
  let kernel = null;
  let wasmBindgenCached = null;
  let executorMod = null;
  let store = null;
  let pager = null;
  let lastBootArgs = null;
  let pid1Job = null;
  let pid1Promise = null;
  let pid1Owner = null;
  let pid1Ended = false;
  let pid1Error = '';
  let standaloneSessionId = '';
  const kernelId = self.crypto?.randomUUID?.() ?? `standalone-${Date.now()}-${Math.random()}`;

  function randomHex32() {
    return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  }

  function parseKernelErr(error) {
    if (typeof error === 'string') {
      try {
        const parsed = JSON.parse(error);
        if (parsed && typeof parsed === 'object' && parsed.errno) {
          return Object.assign(new Error(parsed.detail ?? parsed.errno), parsed);
        }
      } catch { /* plain string */ }
    }
    if (error && typeof error === 'object' && error.errno) return error;
    return Object.assign(new Error(error?.message ?? String(error)), { errno: 'EIO' });
  }

  async function dispatchStandaloneKernel(type, args = {}) {
    if (!kernel) throw Object.assign(new Error('standalone kernel not booted'), { errno: 'ENODEV' });
    const host = kernelId;
    try {
      switch (type) {
        case 'boot_init': return JSON.parse(await kernel.boot_init(JSON.stringify(args.owner), args.token, host));
        case 'execs': {
          const stages = (args.stages ?? []).map(stage => ({
            path: stage.path,
            local: stage.local,
            runtime: stage.runtime,
            parentPid: stage.parentPid,
            sessionId: stage.sessionId,
            serviceGrant: stage.serviceGrant,
            ...(stage.remote !== undefined ? { remote: stage.remote } : {}),
            argv: stage.argv ?? [],
            env: stage.env ?? [],
            cwd: stage.cwd ?? '/',
            cgroup: stage.cgroup ?? '',
          }));
          return JSON.parse(await kernel.execs(JSON.stringify(stages), !!args.sudo, '', host));
        }
        case 'exec': {
          const [res] = await dispatchStandaloneKernel('execs', { stages: [args], sudo: args.sudo });
          if (res.err) throw res.err;
          return res.ok;
        }
        case 'reexec': return JSON.parse(await kernel.reexec(args.pid, JSON.stringify(args.local ?? null), args.path, JSON.stringify(args.argv ?? []), JSON.stringify(args.env ?? []), args.cwd ?? '/', '', host));
        case 'fork': return JSON.parse(await kernel.fork(args.pid, host, args.emptyMemory === true));
        case 'session': return JSON.parse(await kernel.session(JSON.stringify(args.pids), host));
        case 'process_call': return JSON.parse(await kernel.process_call(args.pid, JSON.stringify(args.call), host));
        case 'exit': return JSON.parse(await kernel.exit(args.pid, args.status ?? 0, args.signal ?? undefined, host));
        case 'wait': return JSON.parse(await kernel.wait(args.pid, host));
        case 'waitchild': return JSON.parse(await kernel.waitchild(args.ppid, args.pid ?? undefined, host));
        case 'kill': return JSON.parse(await kernel.kill(args.pid, args.signal ?? undefined, args.from ?? undefined, host));
        case 'poll': return JSON.parse(await kernel.poll(JSON.stringify(args.pids ?? [])));
        case 'tty_fds': return kernel.terminal(args.pid, args.tty, JSON.stringify(args.fds), host);
        case 'sync': return JSON.parse(await kernel.sync(host, JSON.stringify(args?.acknowledged ?? {})));
        case 'getpid': return JSON.parse(await kernel.getpid(args.pid));
        case 'getcreds_proc': return JSON.parse(await kernel.getcreds_proc(args.pid, host));
        case 'set_proc_cred': return JSON.parse(await kernel.set_proc_cred(args.pid, args.uid, args.gid ?? args.uid, new Uint32Array(args.groups ?? []), args.remote != null ? JSON.stringify(args.remote) : undefined, host));
        case 'reserve_memory': kernel.reserve_memory(args.pid, BigInt(args.bytes ?? 0), host); return null;
        case 'cgroup_create': return JSON.parse(await kernel.cgroup_create(args.path));
        case 'cgroup_set': return JSON.parse(await kernel.cgroup_set(args.path, args.key, args.value));
        case 'cgroup_attach': return JSON.parse(await kernel.cgroup_attach(args.pid, args.path));
        case 'cgroup_remove': return JSON.parse(await kernel.cgroup_remove(args.path));
        case 'cgroup_stat': return JSON.parse(await kernel.cgroup_stat(args.path));
        case 'cgroup_list': return JSON.parse(await kernel.cgroup_list(args.path ?? '/'));
        case 'session_begin': return await kernel.session_begin(args.sessionId, args.uid, args.gid ?? args.uid, new Uint32Array(args.groups ?? []));
        case 'set_active_session': kernel.set_active_session(args.sessionId ?? undefined); return null;
        case 'session_end': await kernel.session_end(args.sessionId); return null;
        case 'proc_spawn_init': return await kernel.proc_spawn_init(typeof args.opts === 'string' ? args.opts : JSON.stringify(args.opts));
        case 'proc_authorize_service_grant': return kernel.proc_authorize_service_grant(args.pid);
        case 'proc_apply_service_grant': return await kernel.proc_apply_service_grant(args.pid, args.parentPid, typeof args.grant === 'string' ? args.grant : JSON.stringify(args.grant));
        case 'proc_fork': return kernel.proc_fork(args.parentPid, args.childPid, args.cloneFlags ?? 0);
        case 'proc_exec_preserve': await kernel.proc_exec_preserve(args.pid); return null;
        case 'proc_set_creds': kernel.proc_set_creds(args.pid, args.uid, args.gid, new Uint32Array(args.groups ?? []), args.token ?? undefined, args.cloudAccess !== false); return null;
        case 'proc_set_umask': return kernel.proc_set_umask(args.pid, args.umask);
        case 'proc_close_server_fds': await kernel.proc_close_server_fds(args.pid); return null;
        case 'proc_exit': await kernel.proc_exit(args.pid); return null;
        case 'sys_chdir': await kernel.sys_chdir(args.pid, args.path); return null;
        case 'sys_fchdir': await kernel.sys_fchdir(args.pid, args.kfd); return null;
        case 'sys_chroot': await kernel.sys_chroot(args.pid, args.path); return null;
        case 'sys_getcwd': return await kernel.sys_getcwd(args.pid);
        case 'sys_mount': await kernel.sys_mount(args.pid, args.source ?? undefined, args.target, args.fstype ?? undefined, BigInt(args.flags ?? 0), args.data ?? undefined); return null;
        case 'sys_umount2': await kernel.sys_umount2(args.pid, args.target, args.flags ?? 0); return null;
        case 'sys_statfs': return await kernel.sys_statfs(args.pid, args.dirfd ?? 0x7ffffffe, args.path);
        case 'sys_fstatfs': return await kernel.sys_fstatfs(args.pid, args.kfd);
        case 'sys_unshare': kernel.sys_unshare(args.pid, args.flags ?? 0); return null;
        case 'sys_setns': kernel.sys_setns(args.pid, args.kfd, args.nstype ?? 0); return null;
        case 'proc_openat': return await kernel.proc_openat(args.pid, args.dirfd, args.path, args.oflags ?? 0, args.mode ?? 0, !!args.cloexec);
        case 'proc_statat': return await kernel.proc_statat(args.pid, args.dirfd, args.path, args.follow !== false);
        case 'proc_accessat': await kernel.proc_accessat(args.pid, args.dirfd, args.path, args.amode ?? 0, args.follow !== false); return null;
        case 'proc_mkdirat': await kernel.proc_mkdirat(args.pid, args.dirfd, args.path, args.mode ?? 0o777); return null;
        case 'proc_mknodat': await kernel.proc_mknodat(args.pid, args.dirfd, args.path, args.mode, args.rdev ?? undefined); return null;
        case 'proc_unlinkat': await kernel.proc_unlinkat(args.pid, args.dirfd, args.path, !!args.removedir); return null;
        case 'proc_renameat': await kernel.proc_renameat(args.pid, args.olddirfd, args.oldpath, args.newdirfd, args.newpath, args.flags ?? 0); return null;
        case 'proc_linkat': await kernel.proc_linkat(args.pid, args.olddirfd, args.oldpath, args.newdirfd, args.newpath, !!args.follow); return null;
        case 'proc_symlinkat': await kernel.proc_symlinkat(args.pid, args.target, args.newdirfd, args.linkpath); return null;
        case 'proc_readlinkat': return await kernel.proc_readlinkat(args.pid, args.dirfd, args.path);
        case 'proc_utimensat': {
          const enc = v => (typeof v === 'string' && (v.startsWith('"') || v.startsWith('{'))) ? v : JSON.stringify(v ?? 'now');
          await kernel.proc_utimensat(args.pid, args.dirfd, args.path, enc(args.atime), enc(args.mtime), args.follow !== false);
          return null;
        }
        case 'proc_sys': return JSON.parse(await kernel.proc_sys(args.pid, typeof args.batch === 'string' ? args.batch : JSON.stringify(args.batch)));
        case 'kfd_read': return await kernel.kfd_read(args.pid, args.kfd, args.len);
        case 'kfd_write': return await kernel.kfd_write(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data));
        case 'kfd_pread': return await kernel.kfd_pread(args.pid, args.kfd, args.len, BigInt(args.offset ?? 0));
        case 'kfd_pwrite': return await kernel.kfd_pwrite(args.pid, args.kfd, args.data instanceof Uint8Array ? args.data : new Uint8Array(args.data), BigInt(args.offset ?? 0));
        case 'kfd_seek': return (await kernel.kfd_seek(args.pid, args.kfd, BigInt(args.offset ?? 0), args.whence ?? 0)).toString();
        case 'kfd_readdir': return await kernel.kfd_readdir(args.pid, args.kfd);
        case 'kfd_fstat': return await kernel.kfd_fstat(args.pid, args.kfd);
        case 'kfd_ftruncate': await kernel.kfd_ftruncate(args.pid, args.kfd, BigInt(args.size ?? 0)); return null;
        case 'kfd_futimens': {
          const enc = v => (typeof v === 'string' && (v.startsWith('"') || v.startsWith('{'))) ? v : JSON.stringify(v ?? 'now');
          await kernel.kfd_futimens(args.pid, args.kfd, enc(args.atime), enc(args.mtime));
          return null;
        }
        case 'kfd_fsync': await kernel.kfd_fsync(args.pid, args.kfd, !!args.dataOnly); return null;
        case 'kfd_set_append': kernel.kfd_set_append(args.pid, args.kfd, !!args.append); return null;
        case 'kfd_is_append': return kernel.kfd_is_append(args.pid, args.kfd);
        case 'kfd_lock': await kernel.kfd_lock(args.pid, args.kfd, args.family, args.kind, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined, !!args.wait); return null;
        case 'kfd_cancel': kernel.kfd_cancel(args.pid, args.kfd); return null;
        case 'kfd_unlock': await kernel.kfd_unlock(args.pid, args.kfd, args.family, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined); return null;
        case 'kfd_test_lock': return await kernel.kfd_test_lock(args.pid, args.kfd, args.kind, BigInt(args.start ?? 0), args.end != null ? BigInt(args.end) : undefined);
        case 'kfd_dup': return kernel.kfd_dup(args.pid, args.kfd);
        case 'kfd_dup2': return await kernel.kfd_dup2(args.pid, args.oldKfd, args.newKfd);
        case 'kfd_set_cloexec': kernel.kfd_set_cloexec(args.pid, args.kfd, !!args.cloexec); return null;
        case 'kfd_is_cloexec': return kernel.kfd_is_cloexec(args.pid, args.kfd);
        case 'kfd_close': await kernel.kfd_close(args.pid, args.kfd); return null;
        case 'pty_register': kernel.pty_register(args.index, args.uid ?? 0, args.gid ?? 0, args.mode ?? 0o600); return null;
        case 'pty_close': return kernel.pty_close(args.index);
        case 'proc_resolve_exec': return await kernel.proc_resolve_exec(args.pid, args.file, typeof args.argv === 'string' ? args.argv : JSON.stringify(args.argv ?? []), args.pathEnv ?? undefined, !!args.searchPath);
        case 'session_resolve_exec': return await kernel.session_resolve_exec(args.sessionId ?? '', args.file, typeof args.argv === 'string' ? args.argv : JSON.stringify(args.argv ?? []), args.cwd ?? '/', args.pathEnv ?? undefined, !!args.searchPath, !!args.sudo);
        case 'release_exec_ticket': kernel.release_exec_ticket(args.ticket); return null;
        case 'take_local_exec_bytes': return kernel.take_local_exec_bytes(args.ticket ?? args.digest, args.checkOnly);
        default:
          throw Object.assign(new Error(`unsupported standalone kernel call ${type}`), { errno: 'ENOSYS' });
      }
    } catch (err) {
      throw parseKernelErr(err);
    }
  }

  async function stopStandalonePid1() {
    if (!pid1Promise && !pid1Job) return;
    if (executorMod && pid1Job && !pid1Ended) {
      try {
        await Promise.race([
          executorMod.exec([['/usr/bin/service', 'poweroff']], {
            stdin: '',
            sudo: true,
            sessionId: standaloneSessionId || undefined,
          }).catch(() => {}),
          new Promise(r => setTimeout(r, 2500)),
        ]);
      } catch { /* fallback to signal */ }
    }
    if (pid1Promise) {
      await Promise.race([pid1Promise.catch(() => {}), new Promise(r => setTimeout(r, 2500))]);
    }
    if (pid1Job && !pid1Ended) {
      try { pid1Job.signal(15); } catch {}
      if (pid1Promise) {
        await Promise.race([pid1Promise.catch(() => {}), new Promise(r => setTimeout(r, 1000))]);
      }
      if (!pid1Ended) {
        try { pid1Job.signal(9); } catch {}
      }
    }
    pid1Job = null;
    pid1Promise = null;
    if (pid1Owner && kernel) {
      try {
        await kernel.machine_init_action(JSON.stringify({ op: 'release', owner: pid1Owner }), kernelId);
      } catch { /* ignore */ }
    }
    pid1Owner = null;
  }

  async function bootStandaloneOnKernel(bootProfile, bootArgs) {
    await stopStandalonePid1();
    if (kernel) {
      try { await kernel.close_clean_root(); } catch {}
    }
    kernel = new wasmBindgenCached.Kernel('', kernelId);
    self.kernel = kernel;
    self.wasm_bindgen = wasmBindgenCached;
    self.kernelRequest = dispatchStandaloneKernel;
    pid1Job = null;
    pid1Promise = null;
    pid1Owner = null;
    pid1Ended = false;
    pid1Error = '';
    standaloneSessionId = '';

    const stage1Status = JSON.parse(await kernel.boot_stage1_standalone(
      store,
      JSON.stringify(bootProfile),
      bootArgs.initramfsJson,
      bootArgs.rootTemplateJson,
      bootArgs.baseJson,
      bootArgs.extensionsJson ?? [],
    ));
    if (stage1Status.stage !== 'stage1') {
      return { status: stage1Status, bootHealthy: false, pagerStats: pager.stats() };
    }

    // Codex Findings #2 & #10: execute real packaged Stage 1 `/init` (`early_init.wasm`) ->
    // `/bin/switch_root` -> Stage 2 `/usr/bin/init` (`init.wasm`) as PID 1 through the executor
    // preserving PID 1 & start time, and wait for PID 1 to write `/run/os/boot-healthy`!
    const execUrl = new URL('/executor-host.js', self.location.href).href;
    executorMod ??= await import(/* @vite-ignore */ execUrl);
    const proof = randomHex32();
    const inspected = JSON.parse(await kernel.machine_init_action(JSON.stringify({ op: 'inspect' }), kernelId));
    const claimed = JSON.parse(await kernel.machine_init_action(
      JSON.stringify({ op: 'claim', owner: { boot: inspected.boot, host: kernelId, proof, generation: inspected.generation } }),
      kernelId,
    ));
    const owner = { boot: claimed.boot, host: kernelId, proof, generation: claimed.generation };
    pid1Owner = owner;
    const token = randomHex32();
    pid1Promise = executorMod.exec([['/init']], {
      stdin: '',
      prepare: async () => [{ ok: await self.kernelRequest('boot_init', { owner, token }) }],
      onJob: job => { pid1Job = job; },
      onOutput: (fd, text) => {
        if (fd === 2) pid1Error = (pid1Error + text).slice(-4096);
      },
    }).then(res => {
      pid1Ended = true;
      return res;
    }).catch(err => {
      pid1Ended = true;
      pid1Error = (pid1Error + `\n${err?.message ?? String(err)}`).slice(-4096);
      return { status: 1 };
    });

    const deadline = Date.now() + 30_000;
    let healthy = false;
    while (Date.now() < deadline) {
      if (pid1Ended) {
        throw new Error(`PID 1 init exited prematurely before boot-healthy: ${pid1Error.trim() || 'exit'}`);
      }
      try {
        await kernel.proc_statat(1, 0x7ffffffd, '/run/os/boot-healthy', true);
        healthy = true;
        break;
      } catch {
        await new Promise(r => setTimeout(r, 40));
      }
    }
    if (!healthy) {
      throw new Error(`Timed out waiting for PID 1 /usr/bin/init boot-healthy (${pid1Error.trim() || 'no stderr'})`);
    }

    const finalStatus = JSON.parse(await kernel.standalone_finalize_stage2(kernelId));
    if (finalStatus.stage === 'stage2' && finalStatus.console_proc) {
      const cp = finalStatus.console_proc;
      const sid = `standalone-${cp.uid}-${Date.now()}`;
      await kernel.session_begin(sid, cp.uid, cp.gid, new Uint32Array(cp.groups ?? [cp.gid]));
      kernel.set_active_session(sid);
      standaloneSessionId = sid;
    }
    return {
      status: finalStatus,
      bootHealthy: finalStatus.stage === 'stage2',
      pagerStats: pager.stats(),
    };
  }

  async function loadVerifiedWasmBindgen(jsBytes, wasmBytes, expectedWasmSha256) {
    const actualSha = await sha256Hex(wasmBytes);
    if (expectedWasmSha256 && actualSha !== expectedWasmSha256) {
      throw new Error(`client_kernel_bg.wasm SHA-256 mismatch (got ${actualSha}, expected ${expectedWasmSha256})`);
    }
    const jsText = new TextDecoder('utf-8', { fatal: true }).decode(jsBytes);
    const moduleSrc = `${jsText}\nexport default (typeof wasm_bindgen !== 'undefined' ? wasm_bindgen : globalThis.wasm_bindgen);\n`;
    const blobUrl = URL.createObjectURL(new Blob([moduleSrc], { type: 'text/javascript' }));
    let wasmBindgen;
    try {
      const mod = await import(/* @vite-ignore */ blobUrl);
      wasmBindgen = mod.default;
    } finally {
      URL.revokeObjectURL(blobUrl);
    }
    if (typeof wasmBindgen !== 'function') {
      throw new Error('Verified client_kernel.js did not export wasm_bindgen initializer.');
    }
    await wasmBindgen({ module_or_path: wasmBytes });
    return wasmBindgen;
  }

  self.onmessage = async ({ data }) => {
    const { id, cmd, args = {} } = data;
    try {
      let result;
      switch (cmd) {
        case 'boot': {
          pager = createImagePager({
            fetch: async () => {
              throw Object.assign(new Error('Offline standalone boot forbids network fetches.'), { errno: 'ENOTCONN' });
            },
          });
          self.imageBlobRead = pager.imageBlobRead;
          store = createCowfsStore({ dbName: args.cowfsDbName ?? 'os-cowfs-v1' });
          wasmBindgenCached ??= await loadVerifiedWasmBindgen(
            args.clientKernelJsBytes,
            args.clientKernelWasmBytes,
            args.expectedWasmSha256,
          );
          lastBootArgs = {
            bootProfile: structuredClone(args.bootProfile),
            initramfsJson: args.initramfsJson,
            rootTemplateJson: args.rootTemplateJson,
            baseJson: args.baseJson,
            extensionsJson: args.extensionsJson ?? [],
          };
          if (globalThis.crossOriginIsolated) {
            runtime = null;
            result = await bootStandaloneOnKernel(args.bootProfile, lastBootArgs);
          } else {
            kernel = null;
            runtime = await wasmBindgenCached.OfflineBootRuntime.boot(
              store,
              JSON.stringify(args.bootProfile),
              args.initramfsJson,
              args.rootTemplateJson,
              args.baseJson,
              args.extensionsJson ?? [],
            );
            result = {
              status: runtime.status(),
              // Never mark a release healthy without real PID 1 readiness (Codex Finding #10).
              bootHealthy: false,
              pagerStats: pager.stats(),
            };
          }
          break;
        }
        case 'reboot_with_profile': {
          lastBootArgs.bootProfile = structuredClone(args.bootProfile);
          if (globalThis.crossOriginIsolated) {
            result = await bootStandaloneOnKernel(args.bootProfile, lastBootArgs);
          } else {
            if (runtime) {
              try { await runtime.close_clean_with_prune(); } catch {}
            }
            runtime = await wasmBindgenCached.OfflineBootRuntime.boot(
              store,
              JSON.stringify(args.bootProfile),
              lastBootArgs.initramfsJson,
              lastBootArgs.rootTemplateJson,
              lastBootArgs.baseJson,
              lastBootArgs.extensionsJson ?? [],
            );
            result = {
              status: runtime.status(),
              bootHealthy: false,
              pagerStats: pager.stats(),
            };
          }
          break;
        }
        case 'status':
          result = kernel ? JSON.parse(kernel.standalone_status()) : runtime.status();
          break;
        case 'exec': {
          if (kernel && executorMod) {
            const st = JSON.parse(kernel.standalone_status());
            const cp = st.console_proc;
            let output = '';
            const res = await executorMod.exec([['/bin/sh', '-c', args.line ?? '']], {
              stdin: '',
              sudo: false,
              sessionId: standaloneSessionId || undefined,
              cwd: cp?.home ?? '/',
              home: cp?.home ?? '/',
              user: cp?.user ?? 'user',
              tty: true,
              onOutput: (_fd, text) => { output += text; },
            });
            result = { code: res?.status ?? 0, output: output || (res?.stdout ?? '') };
          } else {
            result = await runtime.exec_command(args.line ?? '');
          }
          break;
        }
        case 'read_file':
          result = [...(kernel
            ? await kernel.standalone_read_file(args.path, Boolean(args.sudo))
            : await runtime.read_file(args.path, Boolean(args.sudo)))];
          break;
        case 'write_file':
          result = kernel
            ? await kernel.standalone_write_file(args.path, new Uint8Array(args.bytes), args.mode ?? 0o644, Boolean(args.sudo))
            : await runtime.write_file(args.path, new Uint8Array(args.bytes), args.mode ?? 0o644, Boolean(args.sudo));
          break;
        case 'mkdir':
          if (kernel) await kernel.standalone_mkdir(args.path, args.mode ?? 0o755, Boolean(args.sudo));
          else await runtime.mkdir(args.path, args.mode ?? 0o755, Boolean(args.sudo));
          result = true;
          break;
        case 'unlink':
          if (kernel) await kernel.standalone_unlink(args.path, Boolean(args.sudo));
          else await runtime.unlink(args.path, Boolean(args.sudo));
          result = true;
          break;
        case 'stat':
          result = kernel
            ? JSON.parse(await kernel.standalone_stat(args.path, args.follow ?? true, Boolean(args.sudo)))
            : await runtime.stat(args.path, args.follow ?? true, Boolean(args.sudo));
          break;
        case 'statfs':
          result = kernel
            ? JSON.parse(await kernel.standalone_statfs(args.path))
            : await runtime.statfs(args.path);
          break;
        case 'readdir':
          result = kernel
            ? JSON.parse(await kernel.standalone_readdir(args.path, Boolean(args.sudo)))
            : await runtime.readdir(args.path, Boolean(args.sudo));
          break;
        case 'sync_fs':
          result = kernel ? JSON.parse(await kernel.standalone_sync_fs()) : await runtime.sync_fs();
          break;
        case 'snapshot':
          result = kernel ? JSON.parse(await kernel.standalone_snapshot(args.name)) : await runtime.snapshot(args.name);
          break;
        case 'run_cowfsck':
          result = kernel
            ? JSON.parse(await kernel.standalone_run_cowfsck(store, args.volumeUuid ?? null))
            : await runtime.run_cowfsck(args.volumeUuid ?? null);
          break;
        case 'rollback_snapshot':
          if (kernel) {
            const rolledUuid = await kernel.standalone_rollback_fork(store, args.snapshotName);
            const nextProfile = structuredClone(lastBootArgs.bootProfile);
            nextProfile.recovery = false;
            nextProfile.root = { cow_fs: { volume_uuid: rolledUuid, writer_mode: 'fork_on_busy' } };
            lastBootArgs.bootProfile = nextProfile;
            const rb = await bootStandaloneOnKernel(nextProfile, lastBootArgs);
            result = rb.status;
          } else {
            result = await runtime.rollback_snapshot(args.snapshotName);
          }
          break;
        case 'fork_from_recovery':
          if (kernel) {
            const nextProfile = structuredClone(lastBootArgs.bootProfile);
            nextProfile.recovery = false;
            if (nextProfile.root?.cow_fs) nextProfile.root.cow_fs.writer_mode = 'fork_on_busy';
            lastBootArgs.bootProfile = nextProfile;
            const fk = await bootStandaloneOnKernel(nextProfile, lastBootArgs);
            result = fk.status;
          } else {
            result = await runtime.fork_from_recovery();
          }
          break;
        case 'switch_root_attempt':
          if (kernel) await kernel.standalone_switch_root_attempt(args.callerPid, args.newroot, args.initPath);
          else await runtime.switch_root_attempt(args.callerPid, args.newroot, args.initPath);
          result = true;
          break;
        case 'list_volumes':
          result = await store.listVolumes({ probeLocks: args.probeLocks ?? true });
          break;
        case 'flush_for_suspend':
          result = kernel
            ? JSON.parse(await kernel.flush_root())
            : (runtime ? await runtime.flush_for_suspend() : null);
          break;
        case 'close_clean_with_prune':
          if (kernel) {
            await stopStandalonePid1();
            result = JSON.parse(await kernel.close_clean_root());
          } else {
            result = runtime ? await runtime.close_clean_with_prune() : null;
          }
          break;
        default:
          throw new Error(`Unknown standalone worker command: ${cmd}`);
      }
      self.postMessage({ id, ok: true, result });
    } catch (err) {
      const e = parseKernelErr(err);
      self.postMessage({
        id,
        ok: false,
        errno: e?.errno ?? null,
        message: e?.detail ?? e?.message ?? String(err),
      });
    }
  };
}

// =============================================================================
// Window entrypoint: preserves exact attached-terminal behavior when opened
// from a parent terminal (`window.opener`) or when no offline Release v2 is
// installed; otherwise boots Stage 0 -> Stage 1 -> os-cowfs -> switch_root ->
// Stage 2 standalone offline console with ZERO outbound network requests.
// =============================================================================

function runAttachedConsole(owner) {
  const nonce = crypto.randomUUID();
  let listener, peer, activeInput, connected = false, ended = false, access = 'view', state = 'running';
  let status = owner ? 'Connecting to the selected command…' : 'Open this window from a running terminal.';
  const emit = value => listener?.(value);
  const notify = () => emit({ type: 'status', text: status, live: connected && !ended, input: !!activeInput && !ended });
  const left = () => { try { owner?.postMessage({ type: 'os-console-left', nonce }, location.origin); } catch { /* owner gone */ } };
  const close = message => {
    if (ended) return;
    ended = true; connected = false; activeInput = null; status = message; clearTimeout(timeout); notify(); left();
  };
  const describe = () => { if (ended) return; status = state === 'stopped' ? 'Command stopped' : access === 'view' ? 'View only · live output' : activeInput ? 'Keyboard connected' : 'Waiting for foreground input'; notify(); };
  const fit = () => {
    if (!activeInput || ended) return;
    const viewport = document.querySelector('.console-window .transcript');
    if (viewport) void activeInput.resize(dimensions(viewport)).catch(() => {});
  };
  const timeout = owner ? setTimeout(() => close('The connection timed out. Open a new window from the original terminal.'), 30_000) : null;
  window.addEventListener('message', async event => {
    if (ended || connected || !listener || event.origin !== location.origin || event.source !== owner || event.data?.nonce !== nonce) return;
    if (event.data.type === 'os-console-error') { close('The selected command is no longer available.'); return; }
    if (event.data.type !== 'os-console-port' || event.ports.length !== 1) return;
    connected = true; clearTimeout(timeout);
    try {
      peer = await attachConsole(event.ports[0], {
        onOutput: (fd, text) => emit({ type: 'output', text }),
        onMode: mode => emit({ type: 'mode', echo: mode.echo }),
        onSize: size => emit({ type: 'size', columns: size.columns, rows: size.rows }),
        onState: value => { state = value; if (peer) describe(); },
        onTty: input => { activeInput = input; if (peer) { describe(); requestAnimationFrame(fit); } },
        onClose: error => close(error.errno === 'EPIPE' ? 'Command ended' : error.errno === 'ECANCELED' ? 'Sharing ended' : error.errno === 'EOVERFLOW' ? 'Disconnected: output arrived too quickly.' : 'Connection lost. The original window may have closed.'),
      });
      if (ended) { await peer.detach(); return; }
      access = peer.access; describe(); requestAnimationFrame(fit);
    } catch { close('The connection could not be established. Open a new window to try again.'); }
  });
  let writing = Promise.resolve(), queued = 0;
  window.osConsole = {
    listen(callback) {
      listener = callback; notify();
      if (owner) owner.postMessage({ type: 'os-console-ready', nonce }, location.origin);
      const viewport = document.querySelector('.console-window .transcript');
      if (viewport) new ResizeObserver(fit).observe(viewport);
    },
    send(operation, text) {
      if (!activeInput || ended) return;
      const input = activeInput;
      if (queued + text.length > 65536) { status = 'Input is too large; paste a smaller amount.'; notify(); return; }
      queued += text.length;
      writing = writing.then(async () => {
        if (input !== activeInput || ended) return;
        for (let at = 0; at < text.length;) {
          if (input !== activeInput || ended) return;
          let end = Math.min(at + 4096, text.length);
          if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1]) && /[\uDC00-\uDFFF]/.test(text[end])) end--;
          await input[operation === 'reply' ? 'reply' : 'write'](text.slice(at, end)); at = end;
        }
      }).catch(() => { if (!ended) { status = 'Input is unavailable; use the original window to restore control.'; notify(); } })
        .finally(() => { queued -= text.length; });
    },
    detach() { void peer?.detach().catch(() => {}); close('Disconnected. The command remains in the original window.'); },
  };
  window.addEventListener('pagehide', () => { void peer?.detach().catch(() => {}); left(); });
  verifyRelease()
    .then(() => import('./pkg/frontend.js'))
    .then(mod => mod.default())
    .catch(() => {
      document.getElementById('app').textContent = 'The terminal could not load. Close this window and try again.';
      left();
    });
}

function createWorkerRpc() {
  const worker = new Worker(import.meta.url, { type: 'module' });
  const pending = new Map();
  let nextId = 1;
  worker.onmessage = ({ data }) => {
    const waiter = pending.get(data.id);
    if (!waiter) return;
    pending.delete(data.id);
    if (data.ok) {
      waiter.resolve(data.result);
    } else {
      waiter.reject(Object.assign(new Error(data.message || 'Worker error'), { errno: data.errno }));
    }
  };
  worker.onerror = err => {
    for (const waiter of pending.values()) {
      waiter.reject(new Error(err.message || 'Standalone boot worker crashed'));
    }
    pending.clear();
  };
  function call(cmd, args = {}, transfer = []) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, cmd, args }, transfer);
    });
  }
  return { worker, call };
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'className') node.className = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, String(v));
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

async function runStandaloneOfflineBoot(params) {
  document.title = 'Standalone Console · OS';
  const app = document.getElementById('app');
  app.removeAttribute('data-attached-console');
  app.setAttribute('data-standalone-console', '1');

  const profileStore = createBootProfileStore();
  const installer = createOfflineInstaller();
  const cowfsDbName = params.get('cowfs_db') || 'os-cowfs-v1';
  const rpc = createWorkerRpc();
  let currentStatus = null;
  let bootMeta = null;
  let closed = false;

  const transcriptLines = [];

  function render() {
    app.replaceChildren();
    const container = el('div', { className: 'standalone-boot' });
    const stage = currentStatus?.stage ?? 'stage0';
    const rootInfo = currentStatus?.mounted_root ?? null;
    const recovery = currentStatus?.recovery ?? null;

    const badges = el('div', { className: 'standalone-badges' },
      el('span', { className: `standalone-badge${stage === 'stage1_recovery' ? ' recovery' : ''}`, 'data-boot-stage': stage }, `Stage: ${stage}`),
    );
    if (bootMeta?.releaseId) {
      badges.append(el('span', { className: 'standalone-badge', 'data-release-id': bootMeta.releaseId }, `Release: ${bootMeta.releaseId.slice(0, 12)}`));
    }
    if (rootInfo) {
      badges.append(el('span', { className: 'standalone-badge', 'data-volume-uuid': rootInfo.volume_uuid }, `Root: ${rootInfo.volume_uuid.slice(0, 12)}`));
      if (rootInfo.forked_from) {
        badges.append(el('span', { className: 'standalone-badge fork', 'data-forked-from': rootInfo.forked_from }, `Fork of ${rootInfo.forked_from.slice(0, 12)}`));
      }
    }

    const actions = el('div', { className: 'standalone-actions' });
    if (stage === 'stage2' && !closed) {
      actions.append(el('button', {
        className: 'standalone-btn',
        type: 'button',
        'data-action': 'shutdown',
        onClick: async () => {
          const outcome = await api.closeClean();
          transcriptLines.push(`[shutdown] ${JSON.stringify(outcome)}`);
          render();
        },
      }, 'Clean Shutdown'));
    }

    container.append(el('div', { className: 'standalone-header' }, badges, actions));

    if (currentStatus?.banners?.length) {
      for (const msg of currentStatus.banners) {
        container.append(el('div', { className: 'standalone-banner', 'data-fork-banner': '1' }, msg));
      }
    }

    if (stage === 'stage1_recovery' && recovery) {
      const recBox = el('div', { className: 'standalone-recovery', 'data-recovery-chooser': '1', 'data-recovery-kind': recovery.reason?.kind ?? 'unknown' },
        el('strong', {}, 'Stage 1 Recovery Chooser'),
        el('div', { 'data-recovery-message': '1' }, recovery.message),
      );
      const recActions = el('div', { className: 'standalone-actions' });
      if (recovery.reason?.kind === 'volume_busy') {
        recActions.append(el('button', {
          className: 'standalone-btn',
          type: 'button',
          'data-recovery-fork': '1',
          onClick: async () => {
            currentStatus = await api.forkFromRecovery();
            transcriptLines.push(`[recovery] Forked & booted into ${currentStatus.mounted_root?.volume_uuid}`);
            render();
          },
        }, 'Fork & Boot (Copy-on-Write)'));
      }
      if (Array.isArray(recovery.available_snapshots) && recovery.available_snapshots.length > 0) {
        for (const snap of recovery.available_snapshots) {
          recActions.append(el('button', {
            className: 'standalone-btn',
            type: 'button',
            'data-rollback-snapshot': snap,
            onClick: async () => {
              currentStatus = await api.rollbackSnapshot(snap);
              transcriptLines.push(`[recovery] Rolled back to snapshot "${snap}" -> ${currentStatus.mounted_root?.volume_uuid}`);
              render();
            },
          }, `Rollback to snapshot "${snap}"`));
        }
      }
      recActions.append(el('button', {
        className: 'standalone-btn',
        type: 'button',
        'data-recovery-reload': '1',
        onClick: () => location.reload(),
      }, 'Retry Boot'));
      recBox.append(recActions);
      container.append(recBox);
    }

    const output = el('pre', { className: 'standalone-output', 'data-console-output': '1' }, transcriptLines.join('\n'));
    container.append(output);

    if (stage === 'stage2' && !closed) {
      const input = el('input', {
        className: 'standalone-input',
        type: 'text',
        placeholder: 'Type offline command (uname, mount, ls /, cat /etc/sudoers, cowfsck, sync, help)…',
        'data-console-input': '1',
      });
      const form = el('form', {
        className: 'standalone-form',
        onSubmit: async ev => {
          ev.preventDefault();
          const line = input.value.trim();
          if (!line) return;
          input.value = '';
          transcriptLines.push(`$ ${line}`);
          try {
            const res = await api.exec(line);
            if (res.output) transcriptLines.push(res.output.trimEnd());
          } catch (err) {
            transcriptLines.push(`error: ${err.message}`);
          }
          render();
          document.querySelector('[data-console-input]')?.focus();
        },
      }, input, el('button', { className: 'standalone-btn', type: 'submit' }, 'Run'));
      container.append(form);
    }

    app.append(container);
    output.scrollTop = output.scrollHeight;
  }

  async function bootSequence() {
    transcriptLines.push('[stage0] Loading local BootProfile (os-boot-profile-v1)...');
    render();

    const bootProfile = await profileStore.load();
    const overrideRecovery = params.get('recovery') === '1';
    if (overrideRecovery) bootProfile.recovery = true;

    transcriptLines.push('[stage0] Verifying installed Release v2 offline (zero network)...');
    render();
    const boot = await installer.resolveInstalledForBoot({
      generation: bootProfile.generation,
      verifyAllBlobs: true,
      verifyCache: true,
    });
    bootMeta = { releaseId: boot.releaseId, rolledBack: Boolean(boot.rolledBack) };

    const wasmPath = boot.release.loader.client_kernel_wasm;
    const expectedWasmSha = boot.release.loader.client_kernel_sha256;
    const [clientKernelJsBytes, clientKernelWasmBytes] = await Promise.all([
      installer.readVerifiedBootAsset(boot, '/client_kernel.js'),
      installer.readVerifiedBootAsset(boot, wasmPath),
    ]);

    const actualWasmSha = await sha256Hex(clientKernelWasmBytes);
    if (actualWasmSha !== expectedWasmSha) {
      throw new Error(`Stage 0 loader verification failed: client_kernel_bg.wasm digest mismatch.`);
    }

    const initramfsJson = JSON.stringify(boot.images.initramfs);
    const rootTemplateJson = JSON.stringify(boot.images.root_template);
    const baseJson = JSON.stringify(boot.images.base);
    const extensionsJson = [
      ...(boot.images.sysext ?? []),
      ...(boot.images.confext ?? []),
    ].map(img => JSON.stringify(img));

    transcriptLines.push('[stage1] Booting Stage 1 initramfs -> cowfsck -> os-cowfs -> switch_root...');
    render();

    const jsCopy = new Uint8Array(clientKernelJsBytes);
    const wasmCopy = new Uint8Array(clientKernelWasmBytes);
    const runBootWorker = async profileToBoot => {
      const jBuf = new Uint8Array(jsCopy);
      const wBuf = new Uint8Array(wasmCopy);
      return rpc.call(
        'boot',
        {
          cowfsDbName,
          bootProfile: profileToBoot,
          initramfsJson,
          rootTemplateJson,
          baseJson,
          extensionsJson,
          clientKernelJsBytes: jBuf,
          clientKernelWasmBytes: wBuf,
          expectedWasmSha256: expectedWasmSha,
        },
        [jBuf.buffer, wBuf.buffer],
      );
    };

    // Codex Finding #11: serialize initial first-boot volume provisioning across concurrent tabs
    // and compare-and-set the minted UUID before exposing the root; losing tabs reopen winner!
    let bootRes;
    const needsInitialUuid = Boolean(bootProfile.root?.cow_fs && !bootProfile.root.cow_fs.volume_uuid);
    if (needsInitialUuid) {
      bootRes = await profileStore.withProvisionLock(async () => {
        const freshProfile = await profileStore.load();
        if (overrideRecovery) freshProfile.recovery = true;
        const firstRes = await runBootWorker(freshProfile);
        const mintedUuid = firstRes.status?.mounted_root?.volume_uuid ?? null;
        if (
          firstRes.status?.mounted_root?.first_boot_seeded
          && freshProfile.root?.cow_fs
          && !freshProfile.root.cow_fs.volume_uuid
          && mintedUuid
        ) {
          const claim = await profileStore.claimVolumeUuid(mintedUuid, { locked: true });
          if (!claim.won && claim.volumeUuid && claim.volumeUuid !== mintedUuid) {
            await rpc.call('close_clean_with_prune').catch(() => {});
            const winnerProfile = structuredClone(claim.profile);
            if (overrideRecovery) winnerProfile.recovery = true;
            return rpc.call('reboot_with_profile', { bootProfile: winnerProfile });
          }
        }
        return firstRes;
      });
    } else {
      bootRes = await runBootWorker(bootProfile);
    }

    currentStatus = bootRes.status;

    // Codex Finding #10: mark installed Release v2 generation healthy strictly for `boot.releaseId`
    // AND ONLY after PID 1 `/usr/bin/init` writes `/run/os/boot-healthy` (multi-user + user-session).
    if (bootRes.bootHealthy === true && currentStatus.stage === 'stage2' && !boot.pinnedGeneration) {
      await installer.markBootHealthy(boot.releaseId).catch(() => {});
    }

    if (currentStatus.stage === 'stage2') {
      transcriptLines.push(
        `[stage2] Ready on os-cowfs volume ${currentStatus.mounted_root.volume_uuid} (PID 1 = ${currentStatus.pid1.path}, started=${currentStatus.pid1.started})`,
      );
    } else if (currentStatus.stage === 'stage1_recovery') {
      transcriptLines.push(`[stage1] Paused in Stage 1 Recovery: ${currentStatus.recovery?.message}`);
    }
    render();

    const summary = {
      status: currentStatus,
      releaseId: boot.releaseId,
      rolledBack: Boolean(boot.rolledBack),
      bootProfile: await profileStore.load(),
      pagerStats: bootRes.pagerStats,
    };
    window.__osStandaloneBoot = summary;
    return summary;
  }

  const api = {
    bootProfileStore: profileStore,
    installer,
    registerOfflineServiceWorker,
    status: () => rpc.call('status'),
    exec: line => rpc.call('exec', { line }),
    readFile: async (path, opts = {}) => new Uint8Array(await rpc.call('read_file', { path, sudo: Boolean(opts?.sudo) })),
    readText: async (path, opts = {}) => new TextDecoder('utf-8').decode(new Uint8Array(await rpc.call('read_file', { path, sudo: Boolean(opts?.sudo) }))),
    writeFile: (path, bytes, mode = 0o644, opts = {}) => {
      const data = typeof bytes === 'string' ? [...new TextEncoder().encode(bytes)] : [...bytes];
      return rpc.call('write_file', { path, bytes: data, mode, sudo: Boolean(opts?.sudo) });
    },
    mkdir: (path, mode = 0o755, opts = {}) => rpc.call('mkdir', { path, mode, sudo: Boolean(opts?.sudo) }),
    unlink: (path, opts = {}) => rpc.call('unlink', { path, sudo: Boolean(opts?.sudo) }),
    stat: (path, follow = true, opts = {}) => rpc.call('stat', { path, follow, sudo: Boolean(opts?.sudo) }),
    statfs: path => rpc.call('statfs', { path }),
    readdir: (path, opts = {}) => rpc.call('readdir', { path, sudo: Boolean(opts?.sudo) }),
    syncFs: () => rpc.call('sync_fs'),
    flushForSuspend: () => rpc.call('flush_for_suspend'),
    snapshot: name => rpc.call('snapshot', { name }),
    runCowfsck: (volumeUuid = null) => rpc.call('run_cowfsck', { volumeUuid }),
    rollbackSnapshot: async snapshotName => {
      currentStatus = await rpc.call('rollback_snapshot', { snapshotName });
      if (currentStatus.mounted_root?.volume_uuid) {
        await profileStore.setVolumeUuid(currentStatus.mounted_root.volume_uuid);
      }
      render();
      return currentStatus;
    },
    forkFromRecovery: async () => {
      currentStatus = await rpc.call('fork_from_recovery');
      render();
      return currentStatus;
    },
    switchRootAttempt: (callerPid, newroot, initPath) =>
      rpc.call('switch_root_attempt', { callerPid, newroot, initPath }),
    listVolumes: (probeLocks = true) => rpc.call('list_volumes', { probeLocks }),
    closeClean: async () => {
      if (closed) return null;
      closed = true;
      const outcome = await rpc.call('close_clean_with_prune');
      rpc.worker.terminate();
      return outcome;
    },
  };

  window.addEventListener('pagehide', event => {
    if (!closed) {
      // Codex Finding #16: preserve mounted root on bfcache suspension (`event.persisted === true`).
      if (event.persisted) {
        void rpc.call('flush_for_suspend').catch(() => {});
      } else {
        void rpc.call('close_clean_with_prune').catch(() => {});
      }
    }
  });

  window.osStandaloneConsole = api;
  api.ready = bootSequence().catch(err => {
    transcriptLines.push(`[boot-error] ${err?.message ?? String(err)}`);
    currentStatus = {
      stage: 'stage1_recovery',
      recovery: {
        reason: { kind: 'boot_error' },
        message: err?.message ?? String(err),
        available_snapshots: [],
      },
      banners: [],
    };
    render();
    const failed = { error: err?.message ?? String(err), status: currentStatus };
    window.__osStandaloneBoot = failed;
    return failed;
  });
}

if (!IS_WORKER) {
  const owner = window.opener;
  const params = new URLSearchParams(location.search);
  if (owner) {
    runAttachedConsole(owner);
  } else if (params.get('standalone') === '1') {
    void runStandaloneOfflineBoot(params);
  } else {
    // Codex Finding #33: check installed generation state (not only readable active manifest!)
    // so a corrupt active manifest still enters standalone boot and triggers trusted-generation
    // fallback inside `resolveInstalledForBoot()` instead of dropping into attached-console mode!
    const checkInstalled = async () => {
      try {
        const st = await createOfflineInstaller().getState();
        if (st && (st.active || st.previous || Object.keys(st.generations ?? {}).length > 0)) {
          return true;
        }
      } catch { /* fall through to quick OPFS check */ }
      return Boolean(await resolveOfflineInstalledRelease().catch(() => null));
    };
    checkInstalled()
      .then(hasInstalled => {
        if (hasInstalled) {
          void runStandaloneOfflineBoot(params);
        } else {
          runAttachedConsole(null);
        }
      })
      .catch(() => runAttachedConsole(null));
  }
}
