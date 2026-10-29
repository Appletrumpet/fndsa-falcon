"""
Rechnen mod q = 12289 über NTT (Number Theoretic Transform).

Spec-Referenz: §3.5, §4.2.2.
"""

from functools import lru_cache
from typing import List, Optional

Q = 12289


def _check_length(n: int) -> None:
    if n <= 0 or (n & (n - 1)) != 0:
        raise ValueError("Länge muss eine Zweierpotenz > 0 sein")
    if (Q - 1) % (2 * n) != 0:
        raise ValueError("für diese Länge zerfällt x^n + 1 mod q nicht vollständig")


@lru_cache(maxsize=None)
def _primitive_root() -> int:
    # q - 1 = 2^12 * 3. Ein Generator muss zu beiden Primfaktoren Ordnung != 1 haben.
    for g in range(2, Q):
        if pow(g, (Q - 1) // 2, Q) != 1 and pow(g, (Q - 1) // 3, Q) != 1:
            return g
    raise RuntimeError("keine primitive Wurzel gefunden")


@lru_cache(maxsize=None)
def _ntt_tables(n: int):
    _check_length(n)
    psi = pow(_primitive_root(), (Q - 1) // (2 * n), Q)
    zetas = [pow(psi, 2 * k + 1, Q) for k in range(n)]
    inv_zetas = [pow(z, Q - 2, Q) for z in zetas]
    return zetas, inv_zetas


def _ntt_rec(a: List[int]) -> List[int]:
    n = len(a)
    if n == 1:
        return [a[0] % Q]

    h = n // 2
    a0 = a[0::2]
    a1 = a[1::2]

    v0 = _ntt_rec(a0)
    v1 = _ntt_rec(a1)
    zetas, _ = _ntt_tables(n)

    out = [0] * n
    for k in range(h):
        t = (zetas[k] * v1[k]) % Q
        s = v0[k]
        out[k] = (s + t) % Q
        out[k + h] = (s - t) % Q
    return out


def _intt_rec(a_hat: List[int]) -> List[int]:
    n = len(a_hat)
    if n == 1:
        return [a_hat[0] % Q]

    h = n // 2
    zetas, inv_zetas = _ntt_tables(n)
    inv2 = (Q + 1) // 2

    v0 = [0] * h
    v1 = [0] * h

    for k in range(h):
        x = a_hat[k] % Q
        y = a_hat[k + h] % Q
        s = (x + y) % Q
        d = (x - y) % Q
        v0[k] = (s * inv2) % Q
        v1[k] = (d * inv_zetas[k] % Q) * inv2 % Q

    c0 = _intt_rec(v0)
    c1 = _intt_rec(v1)

    out = [0] * n
    out[0::2] = c0
    out[1::2] = c1
    return out


def ntt(a: List[int]) -> List[int]:
    """Polynom mod q in Wertedarstellung (NTT-Form). Spec §3.5, §4.2.2."""
    n = len(a)
    _check_length(n)
    return _ntt_rec(a)


def intt(a_hat: List[int]) -> List[int]:
    """Zurück in Koeffizientenform. Spec §3.5."""
    n = len(a_hat)
    _check_length(n)
    return _intt_rec(a_hat)


def mul_mod_q(a: List[int], b: List[int]) -> List[int]:
    """Multiplizieren mod q über NTT. Spec §4.2.2."""
    if len(a) != len(b):
        raise ValueError("Längen müssen übereinstimmen")
    n = len(a)
    _check_length(n)

    ah = ntt(a)
    bh = ntt(b)
    ch = [(x * y) % Q for x, y in zip(ah, bh)]
    return intt(ch)


def div_mod_q(a: List[int], b: List[int]) -> List[int]:
    """a · b⁻¹ mod q, punktweise in NTT-Form. Spec §3.4.3, §4.2.2."""
    if len(a) != len(b):
        raise ValueError("Längen müssen übereinstimmen")
    n = len(a)
    _check_length(n)

    ah = ntt(a)
    bh = ntt(b)

    ch = [0] * n
    for i, bi in enumerate(bh):
        if bi % Q == 0:
            raise ValueError("Divisor ist nicht invertierbar mod q")
        ch[i] = (ah[i] * pow(bi, Q - 2, Q)) % Q

    return intt(ch)


def is_invertible_mod_q(a: List[int]) -> bool:
    """NTT(a) enthält keine Null. Alg. 5, Z. 7."""
    n = len(a)
    _check_length(n)
    return all(x != 0 for x in ntt(a))


def center_mod_q(a: List[int]) -> List[int]:
    """Koeffizienten auf [-q/2, q/2] abbilden. Alg. 16, Z. 5."""
    out = []
    half = Q // 2
    for x in a:
        y = x % Q
        if y > half:
            y -= Q
        out.append(y)
    return out
