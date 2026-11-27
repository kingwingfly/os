// Worker entry point exporting the OS Durable Object classes and routing `/api/mounts/*`.
import worker, * as exports from './build/index.js';
import { mountRoute } from './mount-relay.js';
export { MountRelay } from './mount-relay.js';
export default class OsWorker extends worker {
  fetch(request) {
    return new URL(request.url).pathname.startsWith('/api/mounts/')
      ? mountRoute(request, this.env)
      : super.fetch(request);
  }
}
export const OsAuthority = exports.OsAuthority;
export const Machine = exports.Machine;
export const JobRunner = exports.JobRunner;
export const ModuleCompiler = exports.ModuleCompiler;
export const StorageVolume = exports.StorageVolume;
export const ClusterState = exports.ClusterState;
export const OverlayRelay = exports.OverlayRelay;
