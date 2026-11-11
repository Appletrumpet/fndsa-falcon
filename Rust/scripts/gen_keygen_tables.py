#!/usr/bin/env python3
"""Erzeugt Rust/src/keygen_tables.rs aus dem Quelltext der Referenz.

Übernommen werden die Primzahltabelle PRIMES aus keygen.c und die
Wurzeltabelle fpr_gm_tab aus fpr.c (PQClean, crypto_sign/falcon-512/clean).
Beide sind reine Konstanten; die Funktionen sind in Rust neu geschrieben.

Aufruf aus Rust/:  python scripts/gen_keygen_tables.py <Ordner mit keygen.c und fpr.c>

Quelle: https://github.com/PQClean/PQClean, crypto_sign/falcon-512/clean/
"""

import re
import sys
from pathlib import Path

RUST = Path(__file__).resolve().parent.parent
OUT = RUST / "src" / "keygen_tables.rs"


def main() -> None:
    ref = Path(sys.argv[1])
    keygen = (ref / "keygen.c").read_text()
    fpr = (ref / "fpr.c").read_text()

    body = keygen[keygen.index("PRIMES[] = {"):]
    body = body[:body.index("};")]
    primes = re.findall(r"\{\s*(\d+),\s*(\d+),\s*(\d+)\s*\}", body)
    assert primes[-1] == ("0", "0", "0"), primes[-1]
    primes = primes[:-1]

    gm = fpr[fpr.index("fpr_gm_tab[] = {"):]
    gm = gm[:gm.index("};")]
    gm_vals = re.findall(r"(\d+)U?", gm.split("{", 1)[1])
    assert len(gm_vals) == 2048, len(gm_vals)

    lines = [
        "// Erzeugt von Rust/scripts/gen_keygen_tables.py aus keygen.c und fpr.c",
        "// der Referenz (PQClean), nicht von Hand ändern.",
        "",
        "/// Primzahlen p ≡ 1 mod 2048, 2³⁰ < p < 2³¹, absteigend: (p, g, s) mit",
        "/// g Wurzel von xⁿ+1 in ℤ_p und s Inverse des Produkts aller vorigen",
        "/// Primzahlen mod p (Montgomery). Referenz: keygen.c, PRIMES.",
        f"pub(crate) static PRIMES: [(u32, u32, u32); {len(primes)}] = [",
    ]
    lines += [f"    ({p}, {g}, {s})," for p, g, s in primes]
    lines += [
        "];",
        "",
        "/// Wurzeln für die FFT der Referenz, als (re, im) in IEEE-754-Bits,",
        "/// flach. Referenz: fpr.c, fpr_gm_tab.",
        "pub(crate) static GM_TAB: [u64; 2048] = [",
    ]
    lines += [f"    {v}," for v in gm_vals]
    lines += ["];", ""]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(OUT, len(primes))


if __name__ == "__main__":
    main()
