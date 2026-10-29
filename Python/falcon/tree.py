"""
Geheime Basis und Falcon-Baum.

Datenform:
  - Knoten = (ℓ, linker Teilbaum, rechter Teilbaum)
  - Blatt  = Zahl σ (§3.4.2)

Spec-Referenz: §3.8.3, Alg. 4 (Z. 2–7), Alg. 8, Alg. 9.
"""

import math
from typing import List, Tuple
from .params import Params
from .fft import fft, fft_add, fft_sub, fft_mul, fft_div, fft_adj, split_fft


def _is_leaf(t: object) -> bool:
    return isinstance(t, (int, float)) and not isinstance(t, bool)


def build_basis_fft(
    f: List[int], g: List[int], F: List[int], G: List[int]
) -> Tuple:
    """[[ĝ, -f̂], [Ĝ, -F̂]] in FFT-Form. Alg. 4, Z. 2–3."""
    return (
        (fft(g), fft([-x for x in f])),
        (fft(G), fft([-x for x in F])),
    )


def build_falcon_tree(basis_fft: Tuple, params: Params) -> object:
    """Falcon-Baum aufbauen aus gram_matrix, ff_ldl, normalize_leaves.
    Alg. 4, Z. 4–7."""
    G = gram_matrix(basis_fft)
    T = ff_ldl(G)
    return normalize_leaves(T, params.sigma)


def gram_matrix(basis_fft: Tuple) -> Tuple:
    """Basis mal adjungierte Basis. Alg. 4, Z. 4."""
    (b00, b01), (b10, b11) = basis_fft

    g00 = fft_add(
        fft_mul(b00, fft_adj(b00)),
        fft_mul(b01, fft_adj(b01)),
    )
    g01 = fft_add(
        fft_mul(b00, fft_adj(b10)),
        fft_mul(b01, fft_adj(b11)),
    )
    g10 = fft_add(
        fft_mul(b10, fft_adj(b00)),
        fft_mul(b11, fft_adj(b01)),
    )
    g11 = fft_add(
        fft_mul(b10, fft_adj(b10)),
        fft_mul(b11, fft_adj(b11)),
    )

    return ((g00, g01), (g10, g11))


def ldl(G: Tuple) -> Tuple:
    """LDL*-Zerlegung einer 2×2-Matrix. Alg. 8."""
    G00, G01 = G[0]
    G10, G11 = G[1]

    L10 = fft_div(G10, G00)
    D00 = list(G00)
    D11 = fft_sub(
        G11,
        fft_mul(fft_mul(L10, fft_adj(L10)), G00),
    )

    return L10, D00, D11


def ff_ldl(G: Tuple) -> object:
    """Baum rekursiv aufbauen. Alg. 9."""
    n = len(G[0][0])
    L10, D00, D11 = ldl(G)

    if n == 1:
        return D00[0].real

    if n == 2:
        return (L10, D00[0].real, D11[0].real)

    d0, d1 = split_fft(D00)
    left = ff_ldl(((d0, d1), (fft_adj(d1), d0)))

    e0, e1 = split_fft(D11)
    right = ff_ldl(((e0, e1), (fft_adj(e1), e0)))

    return (L10, left, right)


def normalize_leaves(tree: object, sigma: float) -> object:
    """Jedes Blatt zu σ / √Blatt. Alg. 4, Z. 6–7."""
    if _is_leaf(tree):
        return sigma / math.sqrt(float(tree))

    ell, left, right = tree
    return (
        ell,
        normalize_leaves(left, sigma),
        normalize_leaves(right, sigma),
    )
