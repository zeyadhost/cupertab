/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
// Allow the crate to have a non-snake-case name (touchHLE).
// This also allows items in the crate to have non-snake-case names.
#![allow(non_snake_case)]

fn main() -> Result<(), String> {
    let result = touchHLE::main(std::env::args());
    // Let the web page know the emulator stopped, so it can offer to load another app.
    #[cfg(target_os = "emscripten")]
    {
        extern "C" {
            fn emscripten_run_script(script: *const std::ffi::c_char);
        }
        let script = if result.is_ok() {
            c"globalThis.touchHLEExited?.(0)"
        } else {
            c"globalThis.touchHLEExited?.(1)"
        };
        unsafe { emscripten_run_script(script.as_ptr()) };
    }
    result
}
