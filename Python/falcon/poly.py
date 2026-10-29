"""
Polynome in Koeffizientenform über ℤ.

Alle Polynome leben im Ring R = ℤ[x]/(xⁿ + 1). Beim Multiplizieren wird
xⁿ = -1 angewendet (Vorzeichenwechsel beim Zurückfalten).

Spec-Referenz: §3.1, §3.3.
"""

from typing import List, Tuple


def _check_same_length(a: List[int], b: List[int]) -> int:
    if len(a) != len(b):
        raise ValueError("Polynome müssen dieselbe Länge haben")
    return len(a)


def poly_add(a: List[int], b: List[int]) -> List[int]:
    """Koeffizientenweise addieren. Spec §3.1."""
    n = _check_same_length(a, b)
    return [a[i] + b[i] for i in range(n)]


def poly_sub(a: List[int], b: List[int]) -> List[int]:
    """Koeffizientenweise subtrahieren. Spec §3.1."""
    n = _check_same_length(a, b)
    return [a[i] - b[i] for i in range(n)]


def poly_neg(a: List[int]) -> List[int]:
    """Alle Koeffizienten negieren. Alg. 4, Z. 2."""
    return [-x for x in a]


def poly_mul(a: List[int], b: List[int]) -> List[int]:
    """Multiplizieren mit xⁿ = -1.

    Exakte ganze Zahlen beliebiger Grösse (Python-Int).
    Spec §3.1.
    """
    n = _check_same_length(a, b)
    if n == 0:
        return []
    if n == 1:
        return [a[0] * b[0]]

    nz_a = [(i, x) for i, x in enumerate(a) if x != 0]
    nz_b = [(j, y) for j, y in enumerate(b) if y != 0]
    if not nz_a or not nz_b:
        return [0] * n

    res = [0] * n

    # Für dünne Polynome direkt über die Nichtnull-Einträge.
    if len(nz_a) * len(nz_b) <= max(64, (n * n) // 8):
        for i, ai in nz_a:
            for j, bj in nz_b:
                k = i + j
                if k < n:
                    res[k] += ai * bj
                else:
                    res[k - n] -= ai * bj
        return res

    # Dichtere Fälle: schoolbook, aber ohne unnötige Multiplikationen mit 0.
    if len(nz_b) == n:
        for i, ai in nz_a:
            m = n - i
            for j in range(m):
                res[i + j] += ai * b[j]
            for j in range(m, n):
                res[i + j - n] -= ai * b[j]
    elif len(nz_b) > n // 2:
        for i, ai in nz_a:
            m = n - i
            for j in range(m):
                bj = b[j]
                if bj:
                    res[i + j] += ai * bj
            for j in range(m, n):
                bj = b[j]
                if bj:
                    res[i + j - n] -= ai * bj
    else:
        for i, ai in nz_a:
            for j, bj in nz_b:
                k = i + j
                if k < n:
                    res[k] += ai * bj
                else:
                    res[k - n] -= ai * bj

    return res


def split(a: List[int]) -> Tuple[List[int], List[int]]:
    """Gerade und ungerade Koeffizienten trennen.

    a(x) → a₀(x²) + x·a₁(x²)
    Spec Gl. 3.20.
    """
    n = len(a)
    if n < 2 or (n & 1) != 0:
        raise ValueError("split benötigt eine gerade Länge >= 2")
    return a[0::2], a[1::2]


def lift(a: List[int]) -> List[int]:
    """a(x) zu a(x²): Grad n/2 zu Grad n.

    Alg. 6, Z. 11–12.
    """
    out: List[int] = []
    for x in a:
        out.append(x)
        out.append(0)
    return out


def galois_conjugate(a: List[int]) -> List[int]:
    """a(x) zu a(-x). Alg. 6, Z. 11–12."""
    return [x if (i % 2 == 0) else -x for i, x in enumerate(a)]


def norm_sq(a: List[int]) -> int:
    """Summe der quadrierten Koeffizienten. Spec Gl. 3.10."""
    s = 0
    for x in a:
        s += x * x
    return s
