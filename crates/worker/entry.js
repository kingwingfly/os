// Existing installations may keep their Durable Object binding/storage identity while
// adopting the new code. The old class export is only an upgrade compatibility alias.
import worker, * as exports from './build/index.js';
import { mountRoute } from './mount-relay.js';
export { MountRelay } from './mount-relay.js';
export default class OsWorker extends worker {
  fetch(request) {
    return new URL(request.url).pathname.startsWith('/api/mounts/')
      ? mountRoute(request, this.env, this.ctx, { fetch: request => super.fetch(request) })
      : super.fetch(request);
  }
}
export const OsAuthority = exports.OsAuthority ?? exports.TerminalAuthority;
export { OsAuthority as TerminalAuthority };
export const Machine = exports.Machine;
export const JobRunner = exports.JobRunner;
export const ModuleCompiler = exports.ModuleCompiler;
