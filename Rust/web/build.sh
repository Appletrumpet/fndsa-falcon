#!/usr/bin/env bash
# Baut die Web-Oberfläche (UI-PLAN.md §7): WASM-Hülle, JS-Bindung, KAT-Daten.
#
# Einmal vorher:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.100 --locked
# (Version wie wasm-bindgen in wasm/Cargo.toml.)
#
# Danach: python -m http.server -d web 8000  →  http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== WASM bauen"
cargo build --release --target wasm32-unknown-unknown --manifest-path wasm/Cargo.toml
WASM="${CARGO_TARGET_DIR:-wasm/target}/wasm32-unknown-unknown/release/fndsa_wasm.wasm"

echo "== JS-Bindung (wasm-bindgen)"
wasm-bindgen --target web --no-typescript --out-dir web/pkg "$WASM"

echo "== KAT-Fälle"
cargo run -q --example export_kat_json -- web/kat.json

echo "fertig: $(du -k web/pkg/fndsa_wasm_bg.wasm | cut -f1) kB WASM; python -m http.server -d web 8000"
