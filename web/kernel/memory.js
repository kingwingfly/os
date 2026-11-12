// Trusted compiler instrumentation. Original applications cannot import this namespace;
// every memory.grow is wrapped before instantiation, including unexported memories.
import { prepareImage } from './image.js';
import { FEATURES } from './asyncify.js';
const NAMES = ['memory_grow_pre', 'memory_grow_post'];
export function instrumentMemory(binaryen, bytes, prepare = true) {
  const module = binaryen.readBinary(bytes);
  try {
    module.setFeatures(FEATURES.reduce((all, name) => all | (binaryen.Features[name] ?? 0), 0));
    for (const name of [...NAMES, 'load_ptr', 'store_ptr', ...['load', 'store'].flatMap(op => ['i32', 'i64', 'f32', 'f64'].map(type => `${op}_val_${type}`))]) {
      if (module.getFunction(name)) throw new Error('reserved memory instrumentation name');
    }
    binaryen.setPassArgument('instrument-memory', 'memory.grow');
    try { module.runPasses(['instrument-memory', 'remove-unused-module-elements']); }
    finally { binaryen.clearPassArguments(); }
    for (const name of NAMES) {
      const fn = module.getFunction(name);
      if (!fn) continue;
      const { params, results } = binaryen.getFunctionInfo(fn);
      module.removeFunction(name);
      module.addFunctionImport(name, 'os_runtime', name, params, results);
    }
    const output = module.emitBinary();
    return prepare ? prepareImage(output) : output;
  } finally { module.dispose(); }
}
