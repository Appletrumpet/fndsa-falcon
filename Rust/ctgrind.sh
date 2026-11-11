#!/usr/bin/env bash
# Prüfung der konstanten Laufzeit mit Valgrind (PLAN.md §6, Prüfung 1).
# Nur unter Linux mit installiertem Valgrind. Lokal z. B. im Docker-Container,
# auf GitHub im Job "ctgrind" (x86-64 und aarch64).
#
#   bash ctgrind.sh            Release und opt-level 0
#   bash ctgrind.sh --matrix   zusätzlich alle Varianten unten
#
# 1. Selbsttest: eine absichtliche Verzweigung auf einem geheimen Byte muss
#    gemeldet werden, sonst greift die Markierung nicht.
# 2. Keygen, Laden, Sign, Verify im Release-Build: keine Meldung erlaubt.
# 3. Dasselbe mit opt-level 0 ohne Überlaufprüfungen (die Überlaufprüfungen
#    des Debug-Builds sind selbst Verzweigungen auf den Werten).
# 4. Mit --matrix: weitere Compiler-Einstellungen (PLAN.md 6.3). Die
#    Optimierungsbarrieren müssen unter jeder Einstellung halten; ein anderes
#    opt-level, LTO oder andere Befehlssätze können Masken sonst wieder in
#    Sprünge verwandeln.
set -euo pipefail
cd "$(dirname "$0")"
BASE="${CARGO_TARGET_DIR:-target/ctgrind}"
MATRIX=0
[ "${1:-}" = "--matrix" ] && MATRIX=1

# Variante: Name, dann Umgebung und Cargo-Argumente für `cargo build`.
build() {
    local name="$1"
    shift
    echo "== Bauen: $name"
    env CARGO_TARGET_DIR="$BASE/$name" "$@" --example ctgrind -q
}

build release CARGO_PROFILE_RELEASE_DEBUG=true \
    cargo build --release --features ctgrind
build opt0 CARGO_PROFILE_DEV_OVERFLOW_CHECKS=false CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false \
    cargo build --features ctgrind
BINS=("$BASE/release/release/examples/ctgrind" "$BASE/opt0/debug/examples/ctgrind")

if [ "$MATRIX" = 1 ]; then
    for lvl in 1 2 s z; do
        build "opt$lvl" CARGO_PROFILE_RELEASE_OPT_LEVEL="$lvl" CARGO_PROFILE_RELEASE_DEBUG=true \
            cargo build --release --features ctgrind
        BINS+=("$BASE/opt$lvl/release/examples/ctgrind")
    done
    # ganzes Programm auf einmal optimiert: mehr Inlining über Crate-Grenzen
    build lto CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
        CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --features ctgrind
    BINS+=("$BASE/lto/release/examples/ctgrind")
    # neuere Befehlssätze (AVX2, BMI2, FMA). Fest x86-64-v3 statt
    # target-cpu=native: Valgrind kennt nicht jeden Befehl neuer CPUs und
    # bricht sonst mit "illegal instruction" ab. Auf aarch64 entfällt das.
    if [ "$(uname -m)" = x86_64 ]; then
        build x86-64-v3 RUSTFLAGS="-C target-cpu=x86-64-v3" CARGO_PROFILE_RELEASE_DEBUG=true \
            cargo build --release --features ctgrind
        BINS+=("$BASE/x86-64-v3/release/examples/ctgrind")
    fi
    # Hardware-Gleitkomma statt Emulation (Phase 8)
    build native-fpu CARGO_PROFILE_RELEASE_DEBUG=true \
        cargo build --release --features ctgrind,native-fpu
    BINS+=("$BASE/native-fpu/release/examples/ctgrind")
    # kleinste unterstützte Rust-Version, falls installiert
    if rustup toolchain list 2>/dev/null | grep -q '^1\.87'; then
        build msrv CARGO_PROFILE_RELEASE_DEBUG=true \
            cargo +1.87 build --release --features ctgrind
        BINS+=("$BASE/msrv/release/examples/ctgrind")
    fi
fi

echo "== Selbsttest (muss eine Meldung ergeben)"
if CTGRIND_SELFTEST=1 valgrind -q --error-exitcode=1 "${BINS[0]}" >/dev/null 2>&1; then
    echo "FEHLER: Valgrind hat die absichtliche Verzweigung nicht gemeldet"
    exit 1
fi
echo "ok, gemeldet"

for bin in "${BINS[@]}"; do
    echo "== $bin"
    valgrind -q --error-exitcode=1 --track-origins=yes --num-callers=16 "$bin"
done
echo "Keine Verzweigung und kein Speicherzugriff auf geheimen Daten gefunden" \
    "(${#BINS[@]} Varianten)."
