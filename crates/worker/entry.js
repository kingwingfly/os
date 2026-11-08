// Existing installations may keep their Durable Object binding/storage identity while
// adopting the new code. The old class export is only an upgrade compatibility alias.
import worker, * as exports from './build/index.js';
export default worker;
export const OsAuthority = exports.OsAuthority ?? exports.TerminalAuthority;
export { OsAuthority as TerminalAuthority };
export const Machine = exports.Machine;
export const JobRunner = exports.JobRunner;
export const ModuleCompiler = exports.ModuleCompiler;
