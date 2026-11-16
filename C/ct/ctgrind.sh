#!/bin/sh
# Valgrind-Prüfung der konstanten Laufzeit (ct/ctgrind.c) in einem Linux-Container.
#
#   sh ct/ctgrind.sh [CFLAGS]      aus C/, Standard: -O2
#
# Ausgabe: je Fundstelle (oberster Aufruf mit Datei und Zeile) die Art der Meldung und wie oft
# Memcheck sie gemeldet hat; das volle Protokoll liegt in build/ctgrind.log.
set -eu
OPT="${1:--O2}"
IMAGE=falcon-ctgrind
cd "$(dirname "$0")/.."
mkdir -p build

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -q -t "$IMAGE" - <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev valgrind make \
    && rm -rf /var/lib/apt/lists/*
EOF
fi

docker run --rm -v "$PWD":/src:ro -v "$PWD/build":/out "$IMAGE" sh -c "
  cd /src &&
  gcc -std=c11 -Wall -Wextra -Wconversion -Werror -ffp-contract=off -fno-math-errno -g $OPT -DFALCON_CTGRIND -DFALCON_NO_DIT -Isrc -Itests \
      -DFALCON_DATA_DIR='\"../Python/data\"' src/*.c tests/vectors.c ct/ctgrind.c -lm -o /tmp/ctgrind &&
  gcc --version | head -n 1 &&
  valgrind --error-limit=no --num-callers=6 /tmp/ctgrind > /out/ctgrind.log 2>&1; true"

python3 - build/ctgrind.log <<'EOF'
import re, sys, collections
log = open(sys.argv[1]).read().split("\n")
found = collections.Counter()
kind = None
for line in log:
    m = re.search(r"==\d+== (Conditional jump or move|Use of uninitialised value|Syscall param)", line)
    if m:
        kind = "Verzweigung" if m.group(1).startswith("Conditional") else "Adresse/Wert"
        continue
    m = re.search(r"==\d+==\s+at 0x[0-9A-F]+: (\S+) \((\S+?):(\d+)\)", line)
    if kind and m:
        found[(m.group(2), int(m.group(3)), m.group(1), kind)] += 1
        kind = None
for (f, l, fn, k), c in sorted(found.items()):
    print(f"{f}:{l:<5} {fn:<32} {k:<13} {c}")
print("Fundstellen:", len(found))
print([x for x in log if "ERROR SUMMARY" in x or "ctgrind:" in x])
EOF
