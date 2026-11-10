#!/usr/bin/env bash
# CI-Prüfungen für das Rust-Crate (PLAN.md, Phase 0).
# Lokal: `bash ci.sh` im Ordner Rust/. Auf GitHub: .github/workflows/rust.yml
# (x86-64 und aarch64, PLAN.md Abschnitt 10).
set -euo pipefail
cd "$(dirname "$0")"

echo "== Formatierung"
cargo fmt --check

# Alle Features ausser native-fpu: Standard ist die emulierte Gleitkomma-
# arithmetik. native-fpu wird zusätzlich einzeln gebaut und getestet.
FEATURES="fuzzing,ctgrind,dudect"

echo "== Clippy (Warnungen sind Fehler)"
cargo clippy --all-targets --features "$FEATURES" -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings

echo "== Tests (emuliert, Standard)"
cargo test --features "$FEATURES"

echo "== Tests (native-fpu)"
cargo test --features native-fpu

echo "== Build ohne Test-Code und Release"
cargo build --release

echo "== Doku"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

echo "Alles in Ordnung."
