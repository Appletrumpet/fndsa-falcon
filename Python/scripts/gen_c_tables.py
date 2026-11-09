#!/usr/bin/env python3
"""Erzeugt die Konstantentabellen der C-Portierung aus der Python-Implementierung.

Aufruf aus Python/:  python scripts/gen_c_tables.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from falcon.modq import Q, _ntt_tables, _primitive_root  # noqa: E402
from falcon.fft import _zeta_table  # noqa: E402
from falcon.sampler import LOG2, RCDT, _EXP_C  # noqa: E402

MAX_N = 1024
SRC = ROOT.parent / "C" / "src"
OUT = SRC / "ntt_table.h"


def write_fft_table() -> None:
    """Wurzeln ζ_k = exp(i(2k+1)π/n) für n = 2h und k < h, Index h + k.

    Exakt aus Python übernommen (cmath.exp hängt von der Mathematikbibliothek ab);
    Hexadezimal-Literale geben jeden double bitgenau wieder."""
    lines = [
        "/* Erzeugt von Python/scripts/gen_c_tables.py, nicht von Hand ändern. */",
        "#ifndef FALCON_FFT_TABLE_H",
        "#define FALCON_FFT_TABLE_H",
        "",
        '#include "datatypes.h"',
        "",
        "/* zeta(n, k) für n = 2h, k < h steht an Index h + k; Index 0 bleibt frei. */",
        f"static const falcon_cplx FALCON_ZETAS[{MAX_N}] = {{",
        "    {0.0, 0.0},",
    ]
    h = 1
    while h < MAX_N:
        zetas = _zeta_table(2 * h)
        for k in range(h):
            z = zetas[k]
            lines.append(f"    {{{z.real.hex()}, {z.imag.hex()}}},")
        h *= 2
    lines += ["};", "", "#endif", ""]
    (SRC / "fft_table.h").write_text("\n".join(lines))


def write_sampler_table() -> None:
    lines = [
        "/* Erzeugt von Python/scripts/gen_c_tables.py, nicht von Hand ändern. */",
        "#ifndef FALCON_SAMPLER_TABLE_H",
        "#define FALCON_SAMPLER_TABLE_H",
        "",
        "#include <stdint.h>",
        "",
        "/* RCDT aus Tab. 3.1, 72-Bit-Werte als obere 64 und untere 8 Bit. */",
        "typedef struct {",
        "    uint64_t high;",
        "    uint8_t low;",
        "} falcon_u72;",
        "",
        "static const falcon_u72 FALCON_RCDT[18] = {",
    ]
    for x in RCDT[:18]:
        lines.append(f"    {{0x{x >> 8:016x}u, 0x{x & 0xFF:02x}u}},")
    lines += ["};", "", "/* Konstanten C[] aus Alg. 13. */", "static const uint64_t FALCON_EXP_C[13] = {"]
    for c in _EXP_C:
        lines.append(f"    0x{c:016x}u,")
    lines += ["};", "", "/* math.log(2.0) */", f"#define FALCON_LOG2 ({LOG2.hex()})", "", "#endif", ""]
    (SRC / "sampler_table.h").write_text("\n".join(lines))


def main() -> None:
    write_fft_table()
    write_sampler_table()
    psi = pow(_primitive_root(Q), (Q - 1) // (2 * MAX_N), Q)
    powers = [pow(psi, e, Q) for e in range(2 * MAX_N)]

    # Dieselben Werte wie die Tabellen je Grad in modq.py
    for n in (1 << k for k in range(0, 11)):
        zetas, inv_zetas = _ntt_tables(n, Q)
        step = MAX_N // n
        for k in range(n):
            e = ((2 * k + 1) * step) % (2 * MAX_N)
            assert powers[e] == zetas[k]
            assert powers[(2 * MAX_N - e) % (2 * MAX_N)] == inv_zetas[k]

    lines = [
        "/* Erzeugt von Python/scripts/gen_c_tables.py, nicht von Hand ändern. */",
        "#ifndef FALCON_NTT_TABLE_H",
        "#define FALCON_NTT_TABLE_H",
        "",
        "#include <stdint.h>",
        "",
        f"/* psi^e mod q für e = 0 .. {2 * MAX_N - 1}, psi = primitive {2 * MAX_N}-te Einheitswurzel. */",
        f"static const uint16_t FALCON_PSI_POWERS[{2 * MAX_N}] = {{",
    ]
    for i in range(0, len(powers), 12):
        lines.append("    " + ", ".join(f"{x:5d}" for x in powers[i:i + 12]) + ",")
    lines += ["};", "", "#endif", ""]
    OUT.write_text("\n".join(lines))
    print(OUT)


if __name__ == "__main__":
    main()
