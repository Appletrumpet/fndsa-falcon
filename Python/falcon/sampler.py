"""
Zufallsquelle und Gauss-verteilte ganze Zahlen.

Spec-Referenz: §3.9.3, Alg. 12–15, Tab. 3.1, Tab. 3.2.
Extern: os.urandom (SYSTEM_RNG).

Hinweis: Diese Implementierung ist NICHT konstante Laufzeit und damit
nicht seitenkanalresistent. Spec §3.9.3, §2.7.2 fordert konstante
Laufzeit für SamplerZ – dies ist in reinem Python praktisch nicht
sinnvoll umsetzbar und bleibt hier ausdrücklich ausserhalb des Ziels.

Implementiert die Struktur der Spec:
  - BaseSampler (Alg. 12)
  - ApproxExp (Alg. 13, Fixed-Point mit den C[]-Konstanten der Spec)
  - BerExp (Alg. 14)
  - SamplerZ (Alg. 15)
"""

import math
import os
from typing import Protocol

from .params import Params


# ---------------------------------------------------------------------------
# Zufallsquelle
# ---------------------------------------------------------------------------

class RNG(Protocol):
    """Interface für Zufallsquellen."""
    def random_bytes(self, k: int) -> bytes: ...


class SystemRNG:
    """Standard-Zufallsquelle über os.urandom. Gl. 3.32."""
    def random_bytes(self, k: int) -> bytes:
        return os.urandom(k)


SYSTEM_RNG = SystemRNG()


def uniform_bits(k: int, rng: RNG) -> int:
    """k Zufallsbits aus k/8 Bytes von rng, big-endian gelesen.
    Gl. 3.32, Tab. 3.2."""
    if k % 8 != 0:
        raise ValueError("k muss ein Vielfaches von 8 sein")
    if k == 0:
        return 0
    return int.from_bytes(rng.random_bytes(k // 8), "big")


# ---------------------------------------------------------------------------
# Tabellen aus Tab. 3.1
# ---------------------------------------------------------------------------

RCDT = [
    3024686241123004913666, 1564742784480091954050, 636254429462080897535,
    199560484645026482916, 47667343854657281903, 8595902006365044063,
    1163297957344668388, 117656387352093658, 8867391802663976,
    496969357462633, 20680885154299, 638331848991, 14602316184,
    247426747, 3104126, 28824, 198, 1, 0,
]

LOG2 = math.log(2.0)

# Sehr kleine Toleranz, damit Rundungsunterschiede bei sigma_min/sigma_max
# aus Testvektoren nicht fälschlich abgelehnt werden. Die Toleranz ist so
# klein, dass die expliziten Negativtests weiterhin ValueError werfen.
_SIGMA_EPS = 1e-10


# ---------------------------------------------------------------------------
# BaseSampler (Alg. 12)
# ---------------------------------------------------------------------------

def base_sampler(rng: RNG) -> int:
    """Halb-Gauss über die Tabelle RCDT (Tab. 3.1). Alg. 12.
    Liefert Werte 0 bis 18."""
    u = uniform_bits(72, rng)
    z0 = 0
    for i in range(18):
        if u < RCDT[i]:
            z0 += 1
        else:
            break
    return z0


# ---------------------------------------------------------------------------
# ApproxExp (Alg. 13) – Fixed-Point gemäss Spec v1.2
# ---------------------------------------------------------------------------

# Konstanten C[] aus Algorithmus 13 der Falcon-Spezifikation v1.2.
_EXP_C = [
    0x00000004741183A3,
    0x00000036548CFC06,
    0x0000024FDCBF140A,
    0x0000171D939DE045,
    0x0000D00CF58F6F84,
    0x000680681CF796E3,
    0x002D82D8305B0FEA,
    0x011111110E066FD0,
    0x0555555555070F00,
    0x155555555581FF00,
    0x400000000002B400,
    0x7FFFFFFFFFFF4800,
    0x8000000000000000,
]


def approx_exp(x: float, ccs: float) -> int:
    """Ganzzahlige Näherung von 2⁶³ · ccs · exp(−x). Alg. 13.

    Fixed-Point-Implementierung mit den C[]-Konstanten der Spec.
    y und z bleiben in {0, …, 2⁶³−1}, mit einer Ausnahme: für x = 0
    ist y = 2⁶³ am Ende der for-Schleife.
    """
    y = _EXP_C[0]
    # z ← ⌊2⁶³ · x⌋. Für x ∈ [0, ln 2] bleibt z < 2⁶³.
    z = int(math.floor(x * (1 << 63)))
    if z < 0:
        z = 0
    for i in range(1, 13):
        y = _EXP_C[i] - ((z * y) >> 63)
    z = int(math.floor(ccs * (1 << 63)))
    y = (z * y) >> 63
    return y


# ---------------------------------------------------------------------------
# BerExp (Alg. 14)
# ---------------------------------------------------------------------------

def ber_exp(x: float, ccs: float, rng: RNG) -> bool:
    """1 mit Wahrscheinlichkeit ccs · exp(−x). Alg. 14."""
    if x < 0.0:
        x = 0.0

    # Alg. 14 Z. 1-3: x = s·ln2 + r, dann s ← min(s, 63)
    s = int(math.floor(x / LOG2))
    r = x - s * LOG2
    if s > 63:
        s = 63

    # Alg. 14 Z. 4: z ← (2·ApproxExp(r, ccs) − 1) >> s
    y = approx_exp(r, ccs)
    z = (2 * y - 1) >> s
    if z < 0:
        z = 0

    # Alg. 14 Z. 5-9: Big-endian-Vergleich von 8 Zufallsbytes mit z.
    # i läuft von 56 in 8er-Schritten runter bis 0.
    result = False
    i = 64
    while True:
        i -= 8
        b = rng.random_bytes(1)[0]
        w = b - ((z >> i) & 0xFF)
        if w != 0 or i <= 0:
            result = (w < 0)
            break

    return result


# ---------------------------------------------------------------------------
# SamplerZ (Alg. 15)
# ---------------------------------------------------------------------------

def sample_integer_gaussian(
    mu: float,
    sigma_p: float,
    params: Params,
    rng: RNG,
) -> int:
    """Gauss-verteilte ganze Zahl um μ (SamplerZ). Alg. 15."""
    if not math.isfinite(sigma_p):
        raise ValueError("sigma_p muss endlich sein")

    if (
        sigma_p < params.sigma_min - _SIGMA_EPS
        or sigma_p > params.sigma_max + _SIGMA_EPS
    ):
        raise ValueError("sigma_p liegt außerhalb des zulässigen Bereichs")

    # Alg. 15 Z. 1: r ← µ − ⌊µ⌋
    s = math.floor(mu)
    r = mu - s

    # Alg. 15 Z. 2: ccs ← σmin/σ′
    ccs = params.sigma_min / sigma_p
    if ccs > 1.0:
        ccs = 1.0

    two_sigma_p_sq = 2.0 * sigma_p * sigma_p
    # Alg. 15 Z. 7 verwendet σmax (nicht σmin!)
    two_sigma_max_sq = 2.0 * params.sigma_max * params.sigma_max

    while True:
        # Alg. 15 Z. 4: z0 ← BaseSampler()
        z0 = base_sampler(rng)

        # Alg. 15 Z. 5: b ← UniformBits(8) & 0x1
        b = rng.random_bytes(1)[0] & 1

        # Alg. 15 Z. 6: z ← b + (2·b − 1)·z0
        # b=0 → z = −z0; b=1 → z = z0 + 1
        z = b + (2 * b - 1) * z0

        # Alg. 15 Z. 7: x ← (z−r)²/(2σ′²) − z0²/(2σmax²)
        x = ((z - r) * (z - r)) / two_sigma_p_sq
        x -= (z0 * z0) / two_sigma_max_sq

        if x < 0.0:
            x = 0.0

        # Alg. 15 Z. 8-9
        if ber_exp(x, ccs, rng):
            return s + z
