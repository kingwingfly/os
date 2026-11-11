// What the loader (web/kernel/loader.js) does to an image that forks, setjmps or longjmps, as
// WASIX does them (owner's plan, issue #20: fork must work for any wasm): binaryen's asyncify
// pass, limited to the imports that unwind (`asyncify-imports`). Old instrumentation is
// normalized before the same pass gives it separate scratch memory (`unwind` false). A fork's child is its parent's state in an instance of its own (web/wasi/fork.js),
// so what the image keeps to itself is exported:
// - every mutable global (the shadow stack's pointer, thread-local storage's base): its own is
//   named as wasm-ld names it, or, where the image has no names, the first mutable i32 is taken
//   for it, as wasm-ld puts it first;
// - every table it defines, whose entries it may change as it runs (table.set, table.grow), and
//   one more, `__tw_functions`, of every function in order, by which a child finds its own
//   instance's function for each of its parent's entries.
// The features an image may use: those the browsers run, and none that would change how the
// image is written out (binaryen's compact imports would).
import { prepareImage } from './image.js';

export const FEATURES = ['MultiMemory', 'Atomics', 'MutableGlobals', 'NontrappingFPToInt', 'SIMD128', 'BulkMemory', 'BulkMemoryOpt', 'SignExt',
  'ReferenceTypes', 'Multivalue', 'ExtendedConst', 'TailCall', 'ExceptionHandling', 'CallIndirectOverlong'];
export const FUNCTIONS = '__tw_functions';

export function asyncify(binaryen, bytes, imports, unwind = true) {
  const module = binaryen.readBinary(bytes);
  try {
    module.setFeatures(FEATURES.reduce((all, name) => all | (binaryen.Features[name] ?? 0), 0));
    if (!unwind) {
      // Old toolchains put Asyncify's scratch in guest memory. Remove the host controls and
      // simplify the dormant instrumentation before applying our secondary-memory pass.
      // Do this before exporting globals, which would prevent constant-state elimination.
      for (let index = module.getNumExports() - 1; index >= 0; index--) {
        const name = binaryen.getExportInfo(module.getExportByIndex(index)).name;
        if (name.startsWith('asyncify_')) module.removeExport(name);
      }
      module.optimize();
    }
    // The globals and tables exported, by their names inside and out.
    const globals = new Set(), tables = new Set(), names = new Set();
    for (let index = 0; index < module.getNumExports(); index++) {
      const info = binaryen.getExportInfo(module.getExportByIndex(index));
      if (info.name.startsWith('__tw_')) throw new Error('reserved runtime export: ' + info.name);
      names.add(info.name);
      if (info.kind === binaryen.ExternalGlobal) globals.add(info.value);
      if (info.kind === binaryen.ExternalTable) tables.add(info.value);
    }
    let pointer = null;
    for (let index = 0; index < module.getNumGlobals(); index++) {
      const info = binaryen.getGlobalInfo(module.getGlobalByIndex(index));
      if (!info.mutable || info.module) continue;
      if (info.name === '__stack_pointer' || (pointer == null && info.type === binaryen.i32)) pointer = info.name;
      if (!globals.has(info.name)) module.addGlobalExport(info.name, info.name === '__stack_pointer' ? '__stack_pointer' : `__tw_global_${index}`);
    }
    if (pointer && !names.has('__stack_pointer') && pointer !== '__stack_pointer') module.addGlobalExport(pointer, '__tw_stack_pointer');
    {
      binaryen.setPassArgument('asyncify-imports', imports.join(','));
      binaryen.setPassArgument('asyncify-in-secondary-memory', '1');
      binaryen.setPassArgument('asyncify-secondary-memory-size', '4');
      try { module.runPasses(['asyncify']); } finally { binaryen.clearPassArguments(); }
    }
    // The tables, once asyncify has made what it makes: each the image's own.
    let defined = 0;
    for (let index = 0; index < module.getNumTables(); index++) {
      const info = binaryen.getTableInfo(module.getTableByIndex(index));
      if (info.module) continue;
      defined++;
      if (!tables.has(info.name)) module.addTableExport(info.name, `__tw_table_${index}`);
    }
    if (defined && !names.has(FUNCTIONS)) {
      const functions = [];
      for (let index = 0; index < module.getNumFunctions(); index++) {
        functions.push(binaryen.getFunctionInfo(module.getFunctionByIndex(index)).name);
      }
      module.addTable(FUNCTIONS, functions.length, functions.length);
      module.addActiveElementSegment(FUNCTIONS, FUNCTIONS, functions, module.i32.const(0));
      module.addTableExport(FUNCTIONS, FUNCTIONS);
    }
    return prepareImage(module.emitBinary(), true);
  } finally {
    module.dispose();
  }
}
