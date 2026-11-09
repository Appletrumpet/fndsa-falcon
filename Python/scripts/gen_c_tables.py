#!/usr/bin/env python3
"""Erzeugt die Konstantentabellen der C-Portierung aus der Python-Implementierung.

Aufruf aus Python/:  python scripts/gen_c_tables.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from falcon.modq import Q, _ntt_tables, _primitive_root  # noqa: E402

MAX_N = 1024
OUT = ROOT.parent / "C" / "src" / "ntt_table.h"


def main() -> None:
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
