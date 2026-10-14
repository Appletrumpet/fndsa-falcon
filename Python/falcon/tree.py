"""
Geheime Basis und Falcon-Baum.

Datenform:
  - Knoten = (ℓ, linker Teilbaum, rechter Teilbaum)
  - Blatt  = Zahl σ (§3.4.2)

Spec-Referenz: §3.8.3, Alg. 4 (Z. 2–7), Alg. 8, Alg. 9.
"""

from typing import List, Tuple
from .params import Params


def build_basis_fft(
    f: List[int], g: List[int], F: List[int], G: List[int]
) -> Tuple:
    """[[ĝ, -f̂], [Ĝ, -F̂]] in FFT-Form. Alg. 4, Z. 2–3."""
    raise NotImplementedError


def build_falcon_tree(basis_fft: Tuple, params: Params) -> object:
    """Falcon-Baum aufbauen aus gram_matrix, ff_ldl, normalize_leaves.
    Alg. 4, Z. 4–7."""
    raise NotImplementedError


def gram_matrix(basis_fft: Tuple) -> Tuple:
    """Basis mal adjungierte Basis. Alg. 4, Z. 4."""
    raise NotImplementedError


def ldl(G: Tuple) -> Tuple:
    """LDL*-Zerlegung einer 2×2-Matrix. Alg. 8."""
    raise NotImplementedError


def ff_ldl(G: Tuple) -> object:
    """Baum rekursiv aufbauen. Alg. 9."""
    raise NotImplementedError


def normalize_leaves(tree: object, sigma: float) -> object:
    """Jedes Blatt zu σ / √Blatt. Alg. 4, Z. 6–7."""
    raise NotImplementedError