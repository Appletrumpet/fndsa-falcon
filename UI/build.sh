#!/usr/bin/env bash
# Baut die Web-Oberfläche (UI/README.md): Rust und C als WebAssembly, das
# Python-Paket für Pyodide und die KAT-Fälle.
#
# Einmal vorher:
#   Rust:   rustup target add wasm32-unknown-unknown
#           cargo install wasm-bindgen-cli --version 0.2.100 --locked
#           (Version wie wasm-bindgen in Rust/wasm/Cargo.toml)
#   C:      emcc (Emscripten 3.1.74) oder Docker; ohne emcc wird das Image
#           emscripten/emsdk:3.1.74 benutzt
#   Python: nichts; Pyodide lädt der Browser beim ersten Gebrauch vom CDN
#
# Aufruf: UI/build.sh [rust] [c] [python] [kat]   (ohne Angabe: alles)
# Danach: python -m http.server -d UI 8000  →  http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")/.."
EMSDK_IMAGE=emscripten/emsdk:3.1.74
PARTS="${*:-rust c python kat}"
want() { [[ " $PARTS " == *" $1 "* ]]; }

if want rust; then
echo "== Rust: WASM bauen"
cargo build --release --target wasm32-unknown-unknown --manifest-path Rust/wasm/Cargo.toml
WASM="${CARGO_TARGET_DIR:-Rust/wasm/target}/wasm32-unknown-unknown/release/fndsa_wasm.wasm"
wasm-bindgen --target web --no-typescript --out-dir UI/pkg/rust "$WASM"
fi

if want c; then
echo "== C: WASM bauen (Emscripten)"
# Gleiche Gleitkomma-Optionen wie C/Makefile: ohne -ffp-contract=off wäre
# das Ergebnis nicht mehr bitgleich mit Python.
EMFLAGS=(
  -std=c11 -O2 -Wall -ffp-contract=off -fno-math-errno -IC/src
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createFalconC -sENVIRONMENT=web
  -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=8MB
  -sEXPORTED_FUNCTIONS=_malloc,_free,_fw_keygen,_fw_sign,_fw_verify,_fw_free,_fw_sk_length
  -sEXPORTED_RUNTIME_METHODS=HEAPU8,HEAPF64
  C/src/*.c UI/c/wasm_api.c -o UI/pkg/c/falcon_c.js
)
mkdir -p UI/pkg/c
if command -v emcc >/dev/null; then
  emcc "${EMFLAGS[@]}"
else
  # Git Bash unter Windows: Pfad für Docker im Windows-Format
  HERE="$(pwd -W 2>/dev/null || pwd)"
  MSYS_NO_PATHCONV=1 docker run --rm -v "$HERE:/src" -w /src "$EMSDK_IMAGE" emcc "${EMFLAGS[@]}"
fi
fi

if want python; then
echo "== Python: Paket für Pyodide"
rm -rf UI/py/falcon
mkdir -p UI/py/falcon
cp Python/falcon/*.py UI/py/falcon/
(cd UI/py && ls falcon/*.py | sed 's/.*/"&"/' | paste -sd, - | sed 's/.*/[&]/') > UI/py/files.json
fi

if want kat; then
echo "== KAT-Fälle"
cargo run -q --manifest-path Rust/Cargo.toml --example export_kat_json -- "$(pwd)/UI/kat.json"
fi

echo "fertig: $PARTS"
echo "starten: python -m http.server -d UI 8000"
