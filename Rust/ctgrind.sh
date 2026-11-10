#!/usr/bin/env bash
# Prüfung der konstanten Laufzeit mit Valgrind (PLAN.md §6, Prüfung 1).
# Nur unter Linux mit installiertem Valgrind. Lokal z. B. im Docker-Container,
# auf GitHub im Job "ctgrind" (x86-64 und aarch64).
#
#   bash ctgrind.sh
#
# 1. Selbsttest: eine absichtliche Verzweigung auf einem geheimen Byte muss
#    gemeldet werden, sonst greift die Markierung nicht.
# 2. Keygen, Laden, Sign, Verify im Release-Build: keine Meldung erlaubt.
# 3. Dasselbe mit opt-level 0 ohne Überlaufprüfungen (die Überlaufprüfungen
#    des Debug-Builds sind selbst Verzweigungen auf den Werten).
set -euo pipefail
cd "$(dirname "$0")"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/ctgrind}"

echo "== Bauen (Release und opt-level 0)"
CARGO_PROFILE_RELEASE_DEBUG=true cargo build -q --release --example ctgrind --features ctgrind
CARGO_PROFILE_DEV_OVERFLOW_CHECKS=false CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false \
    cargo build -q --example ctgrind --features ctgrind

REL="$CARGO_TARGET_DIR/release/examples/ctgrind"
DBG="$CARGO_TARGET_DIR/debug/examples/ctgrind"

echo "== Selbsttest (muss eine Meldung ergeben)"
if CTGRIND_SELFTEST=1 valgrind -q --error-exitcode=1 "$REL" >/dev/null 2>&1; then
    echo "FEHLER: Valgrind hat die absichtliche Verzweigung nicht gemeldet"
    exit 1
fi
echo "ok, gemeldet"

for bin in "$REL" "$DBG"; do
    echo "== $bin"
    valgrind --error-exitcode=1 --track-origins=yes --num-callers=16 "$bin"
done
echo "Keine Verzweigung und kein Speicherzugriff auf geheimen Daten gefunden."
