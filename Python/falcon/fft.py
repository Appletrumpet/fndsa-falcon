"""
Rechnen mit komplexen Werten, Splitten und Mergen.

Konvention: Index k enthält den Wert an der Wurzel ζ_k = exp(i·(2k+1)·π/n)
(Spec Gl. 3.19); gespeichert werden alle n Werte.

Indexregeln:
  - -ζ_k = ζ_{k+n/2}
  - ζ_k² = ζ'_{k mod n/2}
  - merge_fft: f[k] = f₀[k mod n/2] + ζ_k · f₁[k mod n/2]
  - split_fft (k < n/2):
        f₀[k] = (f[k] + f[k+n/2]) / 2
        f₁[k] = (f[k] - f[k+n/2]) / (2·ζ_k)

Spec-Referenz: §3.5, §3.6, §4.2.1.
"""

import cmath
import math
from functools import lru_cache
from typing import List, Tuple


def _check_power_of_two(n: int) -> None:
    if n <= 0 or (n & (n - 1)) != 0:
        raise ValueError("Länge muss eine Zweierpotenz > 0 sein")


@lru_cache(maxsize=None)
def _zeta_table(n: int) -> Tuple[complex, ...]:
    _check_power_of_two(n)
    return tuple(cmath.exp(1j * (2 * k + 1) * math.pi / n) for k in range(n))


def fft(a: List[float]) -> List[complex]:
    """Rekursiv: Koeffizienten mit split in gerade/ungerade trennen,
    beide Hälften transformieren, mit merge_fft zusammenführen.
    Basisfall n = 1. Spec §3.5, §3.6, Gl. 3.19."""
    n = len(a)
    _check_power_of_two(n)
    if n == 1:
        return [complex(a[0])]

    h = n // 2
    a0 = a[0::2]
    a1 = a[1::2]
    f0 = fft(a0)
    f1 = fft(a1)
    return merge_fft(f0, f1)


def ifft(a_hat: List[complex]) -> List[float]:
    """Umkehrung von fft, rekursiv über split_fft. Spec §3.5, §3.6."""
    n = len(a_hat)
    _check_power_of_two(n)
    if n == 1:
        return [float(a_hat[0].real)]

    f0_hat, f1_hat = split_fft(a_hat)
    a0 = ifft(f0_hat)
    a1 = ifft(f1_hat)

    out = [0.0] * n
    out[0::2] = a0
    out[1::2] = a1
    return out


def fft_add(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise addieren. Spec §3.5."""
    if len(a_hat) != len(b_hat):
        raise ValueError("Längen müssen übereinstimmen")
    return [x + y for x, y in zip(a_hat, b_hat)]


def fft_sub(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise subtrahieren. Spec §3.5."""
    if len(a_hat) != len(b_hat):
        raise ValueError("Längen müssen übereinstimmen")
    return [x - y for x, y in zip(a_hat, b_hat)]


def fft_mul(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise multiplizieren. Spec §3.5."""
    if len(a_hat) != len(b_hat):
        raise ValueError("Längen müssen übereinstimmen")
    return [x * y for x, y in zip(a_hat, b_hat)]


def fft_div(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise dividieren. Spec §3.5."""
    if len(a_hat) != len(b_hat):
        raise ValueError("Längen müssen übereinstimmen")
    return [x / y for x, y in zip(a_hat, b_hat)]


def fft_adj(a_hat: List[complex]) -> List[complex]:
    """Adjungierte: jeden Wert komplex konjugieren. Spec Gl. 3.6, §4.2.1."""
    return [x.conjugate() for x in a_hat]


def fft_norm_sq(a_hat: List[complex]) -> float:
    """Quadrierte Norm direkt in FFT-Form. Spec Gl. 3.8."""
    n = len(a_hat)
    if n == 0:
        raise ValueError("leere FFT-Form ist ungültig")
    s = 0.0
    for x in a_hat:
        s += (x.real * x.real) + (x.imag * x.imag)
    return s / n


def split_fft(a_hat: List[complex]) -> Tuple[List[complex], List[complex]]:
    """Ein Polynom in zwei halb so grosse aufteilen. Alg. 1."""
    n = len(a_hat)
    if n < 2:
        raise ValueError("split_fft benötigt Länge >= 2")
    _check_power_of_two(n)

    h = n // 2
    zetas = _zeta_table(n)
    f0 = [0j] * h
    f1 = [0j] * h

    for k in range(h):
        x = a_hat[k]
        y = a_hat[k + h]
        f0[k] = (x + y) / 2
        f1[k] = (x - y) / (2 * zetas[k])

    return f0, f1


def merge_fft(a0_hat: List[complex], a1_hat: List[complex]) -> List[complex]:
    """Umkehrung von split_fft. Alg. 2."""
    h = len(a0_hat)
    if len(a1_hat) != h:
        raise ValueError("Längen müssen übereinstimmen")
    if h <= 0 or (h & (h - 1)) != 0:
        raise ValueError("Länge der Hälften muss eine Zweierpotenz > 0 sein")

    n = 2 * h
    zetas = _zeta_table(n)
    out = [0j] * n

    for k in range(h):
        v0 = a0_hat[k]
        v1 = a1_hat[k]
        z = zetas[k]
        out[k] = v0 + z * v1
        out[k + h] = v0 - z * v1

    return out
