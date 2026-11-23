// Host-backed mount store preparation for `crates/client-kernel` (`mount_user`).
// All path resolution, mount-table state, open descriptors, and permission enforcement live
// exclusively in `os_vfs::Vfs` inside `crates/client-kernel`.
import { pinImage } from './local-mounts.js';
import { NativeMount } from './native-mount.js';
import { createOpfsStore, createDirectoryStore } from './fs-store.js';

export const LOCAL_ROOT = '/mnt/local';
export const CLIENT_PAGE_FD_BASE = 0x40000000;

const bad = (errno, message = errno) => Object.assign(new Error(message), { errno });

function ownerCredential(identity) {
  return {
    id: identity.uid,
    group: identity.gid ?? identity.uid,
    groups: identity.groups ?? [],
  };
}

/**
 * Prepare a browser/helper host backing object and `MountUserSpec` for `Kernel::mount_user`.
 */
export async function prepareUserMount(args, identity, { wasm, storeOptions } = {}) {
  globalThis.__osPinImage ??= pinImage;
  if (typeof args?.cloud !== 'boolean') throw bad('EINVAL', 'cloud delegation must be explicit');
  const name = String(args.name ?? args.handle?.name ?? 'files');
  if ((!args.target && !/^[\p{L}\p{N}_. -]{1,80}$/u.test(name)) || !name || name.includes('/') || name.includes('\0') || name === '.' || name === '..') {
    throw bad('EINVAL', 'invalid mount name');
  }
  if (!args.files && !args.url && !args.handle && args.storage !== true && args.originPrivate !== true) {
    throw bad('EINVAL', 'a directory handle, helper connection or browser storage is required');
  }

  const owner = ownerCredential(identity);
  if (args.url) {
    const transport = await NativeMount.connect(
      { ...args, name, owner, wasm, connectHelper: async raw => raw },
      owner,
    );
    return {
      spec: {
        kind: 'helperfs',
        name,
        writable: !!args.writable,
        execute: !!args.execute,
        cloud: args.cloud,
        source: args.url,
      },
      hostObj: transport,
      cleanup: () => transport.close?.(),
    };
  }

  if (args.files) {
    return {
      spec: {
        kind: 'snapshot',
        name,
        writable: false,
        execute: !!args.execute,
        cloud: args.cloud,
        source: 'Selected files',
      },
      hostObj: args.files,
      cleanup: null,
    };
  }

  if (args.storage === true || args.originPrivate === true) {
    const store = await createOpfsStore(args.storage === true ? null : args.handle, {
      execute: !!args.execute,
      writable: !!args.writable,
      ...storeOptions,
    });
    return {
      spec: {
        kind: 'opfs',
        name,
        writable: !!args.writable,
        execute: !!args.execute,
        cloud: args.cloud,
        source: args.storage === true ? 'os-workspace' : (args.handle?.name ?? name),
      },
      hostObj: store,
      cleanup: () => store.close?.(),
    };
  }

  const store = await createDirectoryStore(args.handle, {
    execute: !!args.execute,
    writable: !!args.writable,
    ...storeOptions,
  });
  return {
    spec: {
      kind: 'hostfs',
      name,
      writable: !!args.writable,
      execute: !!args.execute,
      cloud: args.cloud,
      source: args.handle?.name ?? name,
    },
    hostObj: store,
    cleanup: () => store.close?.(),
  };
}
