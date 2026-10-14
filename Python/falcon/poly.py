"""
Polynome in Koeffizientenform über ℤ.

Alle Polynome leben im Ring R = ℤ[x]/(xⁿ + 1). Beim Multiplizieren wird
xⁿ = -1 angewendet (Vorzeichenwechsel beim Zurückfalten).

Spec-Referenz: §3.1, §3.3.
"""

from typing import List, Tuple


def poly_add(a: List[int], b: List[int]) -> List[int]:
    """Koeffizientenweise addieren. Spec §3.1."""
    raise NotImplementedError


def poly_sub(a: List[int], b: List[int]) -> List[int]:
    """Koeffizientenweise subtrahieren. Spec §3.1."""
    raise NotImplementedError


def poly_neg(a: List[int]) -> List[int]:
    """Alle Koeffizienten negieren. Alg. 4, Z. 2."""
    raise NotImplementedError


def poly_mul(a: List[int], b: List[int]) -> List[int]:
    """Multiplizieren mit xⁿ = -1.

    Exakte ganze Zahlen beliebiger Grösse (Python-Int).
    Spec §3.1.
    """
    raise NotImplementedError


def split(a: List[int]) -> Tuple[List[int], List[int]]:
    """Gerade und ungerade Koeffizienten trennen.

    a(x) → a₀(x²) + x·a₁(x²)
    Spec Gl. 3.20.
    """
    raise NotImplementedError


def lift(a: List[int]) -> List[int]:
    """a(x) zu a(x²): Grad n/2 zu Grad n.

    Alg. 6, Z. 11–12.
    """
    raise NotImplementedError


def galois_conjugate(a: List[int]) -> List[int]:
    """a(x) zu a(-x). Alg. 6, Z. 11–12."""
    raise NotImplementedError


def norm_sq(a: List[int]) -> int:
    """Summe der quadrierten Koeffizienten. Spec Gl. 3.10."""
    raise NotImplementedError