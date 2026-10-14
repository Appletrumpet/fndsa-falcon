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

from typing import List, Tuple


def fft(a: List[float]) -> List[complex]:
    """Rekursiv: Koeffizienten mit split in gerade/ungerade trennen,
    beide Hälften transformieren, mit merge_fft zusammenführen.
    Basisfall n = 1. Spec §3.5, §3.6, Gl. 3.19."""
    raise NotImplementedError


def ifft(a_hat: List[complex]) -> List[float]:
    """Umkehrung von fft, rekursiv über split_fft. Spec §3.5, §3.6."""
    raise NotImplementedError


def fft_add(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise addieren. Spec §3.5."""
    raise NotImplementedError


def fft_sub(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise subtrahieren. Spec §3.5."""
    raise NotImplementedError


def fft_mul(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise multiplizieren. Spec §3.5."""
    raise NotImplementedError


def fft_div(a_hat: List[complex], b_hat: List[complex]) -> List[complex]:
    """Punktweise dividieren. Spec §3.5."""
    raise NotImplementedError


def fft_adj(a_hat: List[complex]) -> List[complex]:
    """Adjungierte: jeden Wert komplex konjugieren. Spec Gl. 3.6, §4.2.1."""
    raise NotImplementedError


def fft_norm_sq(a_hat: List[complex]) -> float:
    """Quadrierte Norm direkt in FFT-Form. Spec Gl. 3.8."""
    raise NotImplementedError


def split_fft(a_hat: List[complex]) -> Tuple[List[complex], List[complex]]:
    """Ein Polynom in zwei halb so grosse aufteilen. Alg. 1."""
    raise NotImplementedError


def merge_fft(a0_hat: List[complex], a1_hat: List[complex]) -> List[complex]:
    """Umkehrung von split_fft. Alg. 2."""
    raise NotImplementedError