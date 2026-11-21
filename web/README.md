# touchHLE in the browser

A WebAssembly build of touchHLE. Open the page, pick an `.ipa` you own, and it
runs in the tab; nothing is uploaded anywhere.

## How it differs from the native build

| Part | Native | Web |
| --- | --- | --- |
| CPU | Dynarmic JIT | Rust interpreter (`src/cpu/interp`), ARMv6 slices preferred |
| Guest memory | 4 GiB reservation | 1 GiB window; the top 16 MiB (main thread stack) folds into its end |
| Coroutines | corosensei | Emscripten fibers (`src/coroutine.rs`), needs `-sASYNCIFY` |
| OpenGL | GLES 1.1 or GL 2.1 compat | GL 2.1 from [gl4es](https://github.com/ptitSeb/gl4es) on WebGL 1, one gl4es state per touchHLE context |
| Windowing, audio | SDL2, OpenAL Soft | Emscripten's SDL2 and OpenAL ports |
| Main loop | blocking | blocking, yields to the browser on each frame and while polling events |

The interpreter can also be used natively: `cargo build --no-default-features --features static`.

## Building

Needs the [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html)
(activated, so `emcc` is on `PATH`), the `wasm32-unknown-emscripten` Rust
target and the `vendor/gl4es` submodule.

```sh
rustup target add wasm32-unknown-emscripten
git submodule update --init vendor/gl4es
web/build.sh
python3 -m http.server -d web/dist 8080
```

`.github/workflows/web.yml` runs the same build and deploys `web/dist` to GitHub
Pages on every push to `trunk`.

## Known limitations

- Expect it to be several times slower than native: there is no JIT, and Asyncify adds overhead.
- Needs a browser that allows a WebAssembly memory of about 1.2 GiB (desktop Chrome, Firefox, Safari).
- Only iPhone OS 2.x to iOS 4.0 apps, same as touchHLE itself. Many games have only been tested natively.
