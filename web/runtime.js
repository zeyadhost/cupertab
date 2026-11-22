/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

addToLibrary({
  touchhle_yield__async: 'auto',
  touchhle_yield: () => {
    if (globalThis.scheduler?.yield &&
        document.visibilityState === 'visible' &&
        performance.now() < Module['touchHLEFastUntil']) {
      return globalThis.scheduler.yield();
    }
    return new Promise((resolve) => setTimeout(resolve, 0));
  },
  touchhle_jit_enabled: () => Module['touchHLEJit'] !== false,
  touchhle_jit_compile__deps: ['$addFunction', '$wasmMemory'],
  touchhle_jit_compile: (ptr, size) => {
    try {
      const bytes = HEAPU8.subarray(ptr >>> 0, (ptr >>> 0) + size);
      const module = new WebAssembly.Module(bytes);
      const instance = new WebAssembly.Instance(module, {env: {memory: wasmMemory}});
      return addFunction(instance.exports.run);
    } catch (e) {
      console.warn('touchHLE: Wasm JIT unavailable; using the interpreter', e);
      return 0;
    }
  },
  touchhle_jit_release__deps: ['$removeFunction'],
  touchhle_jit_release: (slot) => removeFunction(slot),
});
