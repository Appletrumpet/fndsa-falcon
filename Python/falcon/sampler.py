"""
Zufallsquelle und Gauss-verteilte ganze Zahlen.

Spec-Referenz: §3.9.3, Alg. 12–15, Tab. 3.1, Tab. 3.2.
Extern: os.urandom (SYSTEM_RNG).

Hinweis: Diese Implementierung ist NICHT konstante Laufzeit und damit
nicht seitenkanalresistent. Spec §3.9.3, §2.7.2 fordert konstante
Laufzeit für SamplerZ – dies ist in reinem Python praktisch nicht
sinnvoll umsetzbar und bleibt hier ausdrücklich ausserhalb des Ziels.

Diese Version entfernt:
  - den Inverse-CDF-Ersatz-Sampler
  - jegliche Replay-/Testvektor-Auswertung

und implementiert stattdessen die Struktur der Spec:
  - BaseSampler (Alg. 12)
  - ApproxExp (Alg. 13, hier als Polynomial-Näherung)
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
# ApproxExp (Alg. 13)
# ---------------------------------------------------------------------------

def _make_exp_neg_coefficients() -> tuple:
    """Koeffizienten für die Taylor-Entwicklung von exp(-x).

    Die Falcon-Spec verlangt eine Näherung für ccs·exp(-x) auf
    x ∈ [0, ln 2]. Hier wird eine hochgenaue Polynomialnäherung verwendet.
    Für bit-exakte Referenzvektoren sind die offiziellen Fixed-Point-
    Koeffizienten der Referenzimplementierung zu verwenden.
    """
    coeff = []
    for i in range(30, -1, -1):
        sign = -1.0 if (i & 1) else 1.0
        coeff.append(sign / float(math.factorial(i)))
    return tuple(coeff)


_EXP_NEG_COEFFICIENTS = _make_exp_neg_coefficients()


def _exp_neg_approx(x: float) -> float:
    """Polynomialnäherung für exp(-x) auf [0, ln 2]."""
    y = _EXP_NEG_COEFFICIENTS[0]
    for c in _EXP_NEG_COEFFICIENTS[1:]:
        y = y * x + c
    return y


def approx_exp(x: float, ccs: float) -> int:
    """Ganzzahlige Näherung von 2⁶³ · ccs · exp(-x). Alg. 13."""
    if ccs <= 0.0:
        return 0

    if x <= 0.0:
        if ccs >= 1.0:
            return 1 << 63

        y = math.floor(math.ldexp(float(ccs), 63))
        if y < 0:
            return 0
        if y > ((1 << 63) - 1):
            y = (1 << 63) - 1
        return int(y)

    if x > LOG2:
        x = LOG2

    val = float(ccs) * _exp_neg_approx(x)

    if val <= 0.0:
        return 0

    y = math.floor(math.ldexp(val, 63))
    if y < 0:
        return 0

    # Für x > 0 muss der Wert strikt kleiner als 2^63 sein.
    if y >= (1 << 63):
        y = (1 << 63) - 1

    return int(y)


# ---------------------------------------------------------------------------
# BerExp (Alg. 14)
# ---------------------------------------------------------------------------

def ber_exp(x: float, ccs: float, rng: RNG) -> bool:
    """1 mit Wahrscheinlichkeit ccs · exp(-x). Alg. 14."""
    if x < 0.0:
        x = 0.0

    # x = s·ln 2 + r, mit r ∈ [0, ln 2). Falls x sehr gross ist,
    # wird s auf 63 begrenzt.
    if x > 63.0 * LOG2:
        s = 63
        r = 0.0
    else:
        s = int(math.floor(x / LOG2))
        if s > 63:
            s = 63
        r = x - s * LOG2

        if r < 0.0:
            r = 0.0
        elif r >= LOG2:
            r -= LOG2
            s += 1
            if s > 63:
                s = 63
                r = 0.0

    y = approx_exp(r, ccs)

    if y <= 0:
        z = 0
    else:
        z = (2 * y - 1) >> s

    if z < 0:
        z = 0
    if z > ((1 << 64) - 1):
        z = (1 << 64) - 1

    zb = z.to_bytes(8, "big")

    # Big-endian-Vergleich von 8 Zufallsbytes mit z.
    for i in range(8):
        b = rng.random_bytes(1)[0]
        if b < zb[i]:
            return True
        if b > zb[i]:
            return False

    return False


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
    if not (params.sigma_min <= sigma_p <= params.sigma_max):
        raise ValueError("sigma_p liegt außerhalb des zulässigen Bereichs")

    s = math.floor(mu)
    r = mu - s
    ccs = params.sigma_min / sigma_p

    two_sigma_p_sq = 2.0 * sigma_p * sigma_p
    two_sigma_min_sq = 2.0 * params.sigma_min * params.sigma_min

    while True:
        z0 = base_sampler(rng)

        # Ein Zufallsbit für das Vorzeichen.
        b = rng.random_bytes(1)[0] & 1

        # Kandidat: +z0 oder -z0.
        z = -z0 if b else z0

        # x ist der zu testende Exponent. Negative Werte werden auf 0
        # geklemmt, da BerExp nur x >= 0 erwartet.
        x = ((z - r) * (z - r)) / two_sigma_p_sq
        x -= (z0 * z0) / two_sigma_min_sq

        if x < 0.0:
            x = 0.0

        if ber_exp(x, ccs, rng):
            return s + z
