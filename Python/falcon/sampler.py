"""
Zufallsquelle und Gauss-verteilte ganze Zahlen.

Spec-Referenz: §3.9.3, Alg. 12–15, Tab. 3.1, Tab. 3.2.
Extern: os.urandom (SYSTEM_RNG).

Hinweis: Diese Implementierung ist NICHT konstante Laufzeit und damit
nicht seitenkanalresistent. Spec §3.9.3, §2.7.2 fordert konstante
Laufzeit für SamplerZ – dies ist nicht Teil des Kernumfangs.
"""

from typing import Protocol
import os

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
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Gauss-Sampler (Alg. 12–15)
# ---------------------------------------------------------------------------

def base_sampler(rng: RNG) -> int:
    """Halb-Gauss über die Tabelle RCDT (Tab. 3.1). Alg. 12.
    Liefert Werte 0 bis 18."""
    raise NotImplementedError


def approx_exp(x: float, ccs: float) -> int:
    """Ganzzahlige Näherung von 2⁶³ · ccs · exp(-x). Alg. 13."""
    raise NotImplementedError


def ber_exp(x: float, ccs: float, rng: RNG) -> bool:
    """1 mit Wahrscheinlichkeit ccs · exp(-x). Alg. 14."""
    raise NotImplementedError


def sample_integer_gaussian(
    mu: float,
    sigma_p: float,
    params: Params,
    rng: RNG,
) -> int:
    """Gauss-verteilte ganze Zahl um μ (SamplerZ). Alg. 15."""
    raise NotImplementedError