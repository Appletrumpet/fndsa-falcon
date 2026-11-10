#!/usr/bin/env bash
# CI-Prüfungen für das Rust-Crate (PLAN.md, Phase 0).
# Lokal: `bash ci.sh` im Ordner Rust/. Auf GitHub: .github/workflows/rust.yml
# (x86-64 und aarch64, PLAN.md Abschnitt 10).
set -euo pipefail
cd "$(dirname "$0")"

echo "== Formatierung"
cargo fmt --check

echo "== Clippy (Warnungen sind Fehler)"
cargo clippy --all-targets --all-features -- -D warnings

echo "== Tests"
cargo test --all-features

echo "== Build ohne Test-Code und Release"
cargo build --release

echo "== Doku"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

echo "Alles in Ordnung."
