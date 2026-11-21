#!/usr/bin/env bash
# Builds the browser version of touchHLE into web/dist.
# Requires an activated Emscripten SDK (emcc on PATH) and the
# wasm32-unknown-emscripten Rust target.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f vendor/gl4es/lib/libGL.a ]; then
    (
        mkdir -p vendor/gl4es/build && cd vendor/gl4es/build
        emcmake cmake .. -DCMAKE_BUILD_TYPE=Release -DNOX11=ON -DNOEGL=ON -DSTATICLIB=ON
        make -j"$(nproc)"
    )
fi
cargo build --release --target wasm32-unknown-emscripten --no-default-features --bin touchHLE
out=web/dist
rm -rf "$out"
mkdir -p "$out"
cp target/wasm32-unknown-emscripten/release/touchHLE.js target/wasm32-unknown-emscripten/release/touchHLE.wasm "$out/"
python3 "$(dirname "$(command -v emcc)")/tools/file_packager.py" "$out/touchHLE.data" \
    --preload touchHLE_dylibs touchHLE_fonts touchHLE_default_options.txt \
    --js-output="$out/touchHLE.data.js"
cp web/index.html "$out/"
touch "$out/.nojekyll"
