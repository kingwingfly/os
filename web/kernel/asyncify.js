// What the loader (web/kernel/loader.js) does to an image that forks, setjmps or longjmps, as
// WASIX does them (owner's plan, issue #20: fork must work for any wasm): binaryen's asyncify
// pass, limited to the imports that unwind (`asyncify-imports`), so that only code that can
// reach them pays for it. Every mutable global the image keeps to itself is exported, so that a
// fork's child can be given its parent's values (the shadow stack's pointer, thread-local
// storage's base): its own is named as wasm-ld names it, or, where the image has no names, the
// first mutable i32 is taken for it, as wasm-ld puts it first.
// The features an image may use: those the browsers run, and none that would change how the
// image is written out (binaryen's compact imports would).
const FEATURES = ['Atomics', 'MutableGlobals', 'NontrappingFPToInt', 'SIMD128', 'BulkMemory', 'BulkMemoryOpt', 'SignExt',
  'ReferenceTypes', 'Multivalue', 'ExtendedConst', 'TailCall', 'ExceptionHandling', 'CallIndirectOverlong'];

export function asyncify(binaryen, bytes, imports) {
  const module = binaryen.readBinary(bytes);
  try {
    module.setFeatures(FEATURES.reduce((all, name) => all | (binaryen.Features[name] ?? 0), 0));
    // The globals exported, by their names inside and out.
    const exported = new Set(), names = new Set();
    for (let index = 0; index < module.getNumExports(); index++) {
      const info = binaryen.getExportInfo(module.getExportByIndex(index));
      names.add(info.name);
      if (info.kind === binaryen.ExternalGlobal) exported.add(info.value);
    }
    let pointer = null;
    for (let index = 0; index < module.getNumGlobals(); index++) {
      const info = binaryen.getGlobalInfo(module.getGlobalByIndex(index));
      if (!info.mutable || info.module) continue;
      if (info.name === '__stack_pointer' || (pointer == null && info.type === binaryen.i32)) pointer = info.name;
      if (!exported.has(info.name)) module.addGlobalExport(info.name, info.name === '__stack_pointer' ? '__stack_pointer' : `__tw_global_${index}`);
    }
    if (pointer && !names.has('__stack_pointer') && pointer !== '__stack_pointer') module.addGlobalExport(pointer, '__tw_stack_pointer');
    binaryen.setPassArgument('asyncify-imports', imports.join(','));
    module.runPasses(['asyncify']);
    binaryen.clearPassArguments();
    return module.emitBinary();
  } finally {
    module.dispose();
  }
}
