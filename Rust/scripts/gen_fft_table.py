#!/usr/bin/env python3
"""Erzeugt Rust/src/fft_table.rs aus C/src/fft_table.h.

Die C-Tabelle enthält die Wurzeln ζ genau so, wie Python sie berechnet hat
(cmath.exp, siehe Python/scripts/gen_c_tables.py). Rust übernimmt dieselben
Bits, damit die FFT bitgleich mit Python und C rechnet. Rust kennt keine
hexadezimalen Gleitkomma-Literale; deshalb stehen die Werte als u64-Bits da.

Aufruf aus Rust/:  python scripts/gen_fft_table.py
"""

import re
import struct
from pathlib import Path

RUST = Path(__file__).resolve().parent.parent
SRC = RUST.parent / "C" / "src" / "fft_table.h"
OUT = RUST / "src" / "fft_table.rs"

FLOAT = r"(-?0x[0-9a-f.]+p[+-]?\d+|-?0\.0)"


def bits(text: str) -> int:
    value = float.fromhex(text) if "x" in text else float(text)
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def main() -> None:
    pairs = re.findall(r"\{" + FLOAT + r",\s*" + FLOAT + r"\}", SRC.read_text())
    assert len(pairs) == 1024, len(pairs)
    lines = [
        "// Erzeugt von Rust/scripts/gen_fft_table.py aus C/src/fft_table.h,",
        "// nicht von Hand ändern.",
        "//",
        "// ζ(n, k) = exp(i(2k+1)π/n) für n = 2h und k < h steht an Index h + k",
        "// als (Realteil, Imaginärteil) in IEEE-754-Bits. Index 0 bleibt frei.",
        "",
        "pub(crate) static ZETA_BITS: [(u64, u64); 1024] = [",
    ]
    for re_, im in pairs:
        lines.append(f"    (0x{bits(re_):016x}, 0x{bits(im):016x}),")
    lines += ["];", ""]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
