"""
Rechnen mod q über NTT (Number Theoretic Transform).

Spec-Referenz: §3.5, §4.2.2.

Standardmodulus ist q = 12289. Für benutzerdefinierte Parametersätze kann
q explizit übergeben werden. Die NTT benötigt eine Primzahl q mit
q ≡ 1 (mod 2n).
"""

from functools import lru_cache
from typing import List

from .params import _is_prime

Q = 12289


def _check_length(n: int, q: int) -> None:
    if n <= 0 or (n & (n - 1)) != 0:
        raise ValueError("Länge muss eine Zweierpotenz > 0 sein")
    if q < 3 or (q & 1) == 0:
        raise ValueError("q muss eine ungerade Primzahl sein")
    if (q - 1) % (2 * n) != 0:
        raise ValueError("für diese Länge zerfällt x^n + 1 mod q nicht vollständig")


@lru_cache(maxsize=None)
def _factorize(x: int):
    factors = []
    n = x
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return tuple(factors)


@lru_cache(maxsize=None)
def _primitive_root(q: int) -> int:
    if not _is_prime(q):
        raise ValueError("q muss prim sein")
    if q == 2:
        return 1

    factors = _factorize(q - 1)
    for g in range(2, q):
        ok = True
        for p in factors:
            if pow(g, (q - 1) // p, q) == 1:
                ok = False
                break
        if ok:
            return g

    raise RuntimeError("keine primitive Wurzel gefunden")


@lru_cache(maxsize=None)
def _ntt_tables(n: int, q: int):
    _check_length(n, q)
    psi = pow(_primitive_root(q), (q - 1) // (2 * n), q)
    zetas = [pow(psi, 2 * k + 1, q) for k in range(n)]
    inv_zetas = [pow(z, q - 2, q) for z in zetas]
    return tuple(zetas), tuple(inv_zetas)


def _ntt_rec(a: List[int], q: int) -> List[int]:
    n = len(a)
    if n == 1:
        return [a[0] % q]

    h = n // 2
    a0 = a[0::2]
    a1 = a[1::2]

    v0 = _ntt_rec(a0, q)
    v1 = _ntt_rec(a1, q)
    zetas, _ = _ntt_tables(n, q)

    out = [0] * n
    for k in range(h):
        t = (zetas[k] * v1[k]) % q
        s = v0[k]
        out[k] = (s + t) % q
        out[k + h] = (s - t) % q
    return out


def _intt_rec(a_hat: List[int], q: int) -> List[int]:
    n = len(a_hat)
    if n == 1:
        return [a_hat[0] % q]

    h = n // 2
    _, inv_zetas = _ntt_tables(n, q)
    inv2 = (q + 1) // 2

    v0 = [0] * h
    v1 = [0] * h

    for k in range(h):
        x = a_hat[k] % q
        y = a_hat[k + h] % q
        s = (x + y) % q
        d = (x - y) % q
        v0[k] = (s * inv2) % q
        v1[k] = (d * inv_zetas[k] % q) * inv2 % q

    c0 = _intt_rec(v0, q)
    c1 = _intt_rec(v1, q)

    out = [0] * n
    out[0::2] = c0
    out[1::2] = c1
    return out


def ntt(a: List[int], q: int = Q) -> List[int]:
    """Polynom mod q in Wertedarstellung (NTT-Form). Spec §3.5, §4.2.2."""
    n = len(a)
    _check_length(n, q)
    return _ntt_rec(a, q)


def intt(a_hat: List[int], q: int = Q) -> List[int]:
    """Zurück in Koeffizientenform. Spec §3.5."""
    n = len(a_hat)
    _check_length(n, q)
    return _intt_rec(a_hat, q)


def mul_mod_q(a: List[int], b: List[int], q: int = Q) -> List[int]:
    """Multiplizieren mod q über NTT. Spec §4.2.2."""
    if len(a) != len(b):
        raise ValueError("Längen müssen übereinstimmen")
    n = len(a)
    _check_length(n, q)

    ah = ntt(a, q)
    bh = ntt(b, q)
    ch = [(x * y) % q for x, y in zip(ah, bh)]
    return intt(ch, q)


def div_mod_q(a: List[int], b: List[int], q: int = Q) -> List[int]:
    """a · b⁻¹ mod q, punktweise in NTT-Form. Spec §3.4.3, §4.2.2."""
    if len(a) != len(b):
        raise ValueError("Längen müssen übereinstimmen")
    n = len(a)
    _check_length(n, q)

    ah = ntt(a, q)
    bh = ntt(b, q)

    ch = [0] * n
    for i, bi in enumerate(bh):
        if bi % q == 0:
            raise ValueError("Divisor ist nicht invertierbar mod q")
        ch[i] = (ah[i] * pow(bi, q - 2, q)) % q

    return intt(ch, q)


def is_invertible_mod_q(a: List[int], q: int = Q) -> bool:
    """NTT(a) enthält keine Null. Alg. 5, Z. 7."""
    n = len(a)
    _check_length(n, q)
    return all(x != 0 for x in ntt(a, q))


def center_mod_q(a: List[int], q: int = Q) -> List[int]:
    """Koeffizienten auf [-q/2, q/2] abbilden. Alg. 16, Z. 5."""
    if q <= 0:
        raise ValueError("q muss positiv sein")

    out = []
    half = q // 2
    for x in a:
        y = x % q
        if y > half:
            y -= q
        out.append(y)
    return out
