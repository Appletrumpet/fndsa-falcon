"""
Erzeugung der NTRU-Schlüsselkomponenten f, g, F, G.

Spec-Referenz: §3.8.2, §4.4.3, Alg. 5–7, Gl. 3.25, 3.28, 3.29, 3.35.

Ablauf (Alg. 5):
  1. f, g kurz samplen
  2. f invertierbar mod q und Gram-Schmidt-Norm ≤ 1.17·√q ?
  3. fG - gF = q rekursiv lösen (Alg. 6)
  4. F, G gegen f, g verkleinern (Alg. 7)
  5. Bei Misserfolg: Neustart
"""

import math
from typing import List, Optional, Tuple

from .params import Params
from .sampler import RNG, sample_integer_gaussian
from .fft import fft, ifft
from .poly import (
    poly_mul,
    poly_sub,
    lift,
    galois_conjugate,
    norm_sq,
)
from .modq import is_invertible_mod_q, mul_mod_q, div_mod_q, center_mod_q, Q


class KeygenError(RuntimeError):
    """Wird geworfen, wenn die Schlüsselerzeugung nach zu vielen Versuchen
    keinen gültigen Schlüssel produziert hat."""
    pass


def generate_ntru_keys(
    params: Params, rng: RNG, max_attempts: int = 5000
) -> Tuple[List[int], List[int], List[int], List[int]]:
    """f, g, F, G ziehen, prüfen, lösen; bei Misserfolg Neustart. Alg. 5.

    Nach max_attempts Fehlversuchen wird KeygenError geworfen mit einer
    Zusammenfassung der Ablehnungsgründe.
    """
    gs_bound = 1.17 * math.sqrt(params.q)

    reasons = {"not_invertible": 0, "gamma_too_large": 0, "solve_failed": 0}

    for attempt in range(max_attempts):
        f = sample_short_poly(params, rng)
        g = sample_short_poly(params, rng)

        if not is_invertible_mod_q(f, params.q):
            reasons["not_invertible"] += 1
            continue

        gamma = gram_schmidt_norm(f, g, params)
        if not math.isfinite(gamma) or gamma > gs_bound:
            reasons["gamma_too_large"] += 1
            continue

        sol = solve_ntru(f, g, params)
        if sol is None:
            reasons["solve_failed"] += 1
            continue

        F, G = sol
        return f, g, F, G

    raise KeygenError(
        f"generate_ntru_keys: kein gültiger Schlüssel nach {max_attempts} Versuchen. "
        f"Ablehnungsgründe: f nicht invertierbar={reasons['not_invertible']}, "
        f"gamma zu gross={reasons['gamma_too_large']}, "
        f"NTRUSolve fehlgeschlagen={reasons['solve_failed']}. "
        f"gs_bound={gs_bound:.4f}"
    )


def sample_short_poly(params: Params, rng: RNG) -> List[int]:
    """Koeffizienten als Summe von 4096/n Ziehungen aus
    sample_integer_gaussian. Alg. 5, Z. 1–6; Gl. 3.29."""
    n = params.n
    m = 4096 // n
    sigma_star = 1.17 * math.sqrt(params.q / 8192.0)

    out = []
    for _ in range(n):
        s = 0
        for _ in range(m):
            s += sample_integer_gaussian(0.0, sigma_star, params, rng)
        out.append(s)

    return out


def gram_schmidt_norm(f: List[int], g: List[int], params: Params) -> float:
    """Qualität der Basis, Grenze 1.17·√q. Gl. 3.28.

    γ = max{ ‖(g, −f)‖, ‖(q·f⋆/(ff⋆+gg⋆), q·g⋆/(ff⋆+gg⋆))‖ }

    Erster Term: sqrt(‖f‖² + ‖g‖²) = sqrt(norm_sq(f) + norm_sq(g)).
    Zweiter Term: sqrt((1/n)·Σ q²/(|f̂_k|² + |ĝ_k|²)) via Parseval (Gl. 3.8).
    """
    first = math.sqrt(norm_sq(f) + norm_sq(g))

    fh = fft(f)
    gh = fft(g)
    q = params.q

    total = 0.0
    for a, b in zip(fh, gh):
        den = (a.real * a.real + a.imag * a.imag) + (b.real * b.real + b.imag * b.imag)
        if den <= 0.0:
            return float("inf")
        total += (q * q) / den

    second = math.sqrt(total / len(f))
    return max(first, second)


def _ntru_lhs(f, g, F, G):
    """fG − gF in ℤ[x]/(xⁿ+1), exakt."""
    fg = poly_mul(f, G)
    gF = poly_mul(g, F)
    return [a - b for a, b in zip(fg, gF)]


def solve_ntru(
    f: List[int], g: List[int], params: Params
) -> Optional[Tuple[List[int], List[int]]]:
    """fG - gF = q rekursiv lösen; am Ende Prüfung der NTRU-Gleichung,
    bei Verletzung None. Alg. 6, §4.4.3."""
    if len(f) != len(g):
        return None

    n = len(f)
    if n == 0 or (n & (n - 1)) != 0:
        return None

    if n == 1:
        d, u, v = xgcd(f[0], g[0])
        if d != 1:
            return None
        F = [v * params.q]
        G = [u * params.q]
        # Prüfung im Basisfall
        if f[0] * G[0] - g[0] * F[0] != params.q:
            return None
        return F, G

    try:
        fn = field_norm(f)
        gn = field_norm(g)
    except ValueError:
        return None

    sub = solve_ntru(fn, gn, params)
    if sub is None:
        return None

    Fp, Gp = sub

    F = poly_mul(lift(Fp), galois_conjugate(g))
    G = poly_mul(lift(Gp), galois_conjugate(f))

    F, G = reduce(f, g, F, G)

    # Prüfung der NTRU-Gleichung nach der Reduktion.
    lhs = _ntru_lhs(f, g, F, G)
    if lhs != [params.q] + [0] * (n - 1):
        return None

    return F, G


def field_norm(a: List[int]) -> List[int]:
    """a²₀ - x·a²₁, Grad n zu Grad n/2. Gl. 3.25.

    N(a) = a₀(x²)² − x·a₁(x²)² im Ring ℤ[x]/(x^{n/2}+1).
    Äquivalent: N(a)(x²) = a(x)·a(−x) (Gl. 3.26).
    """
    n = len(a)
    if n < 2 or (n & 1) != 0:
        raise ValueError("field_norm benötigt eine gerade Länge >= 2")

    a0 = a[0::2]
    a1 = a[1::2]

    s0 = poly_mul(a0, a0)
    s1 = poly_mul(a1, a1)

    # Multiplikation mit x im Ring ℤ[x]/(x^{n/2}+1):
    # x·(c₀ + c₁x + … + c_{m−1}x^{m−1}) = −c_{m−1} + c₀x + … + c_{m−2}x^{m−1}
    xs1 = [-s1[-1]] + s1[:-1]

    return [x - y for x, y in zip(s0, xs1)]


def xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """Erweiterter euklidischer Algorithmus über ℤ. Alg. 6, Z. 2.

    Liefert (d, u, v) mit u·a − v·b = d = gcd(a, b) (Vorzeichenkonvention
    der Spec), sodass Alg. 6 Z. 5 direkt (F, G) = (v·q, u·q) ergibt."""
    if a == 0 and b == 0:
        return (0, 0, 0)

    aa = abs(a)
    bb = abs(b)

    old_r, r = aa, bb
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    d = old_r
    x = old_s
    y = old_t

    sa = -1 if a < 0 else 1
    sb = -1 if b < 0 else 1

    u = x * sa
    v = -y * sb

    return d, u, v


def _max_bit(polys) -> int:
    m = 0
    for p in polys:
        for c in p:
            if c:
                b = abs(c).bit_length()
                if b > m:
                    m = b
    return m


def _scaled_float(c: int, scale: int) -> float:
    """Konvertiert einen Integer zu Float, skaliert um 2^{-scale}.
    Behält die oberen 53 Bits (Mantisse eines Double)."""
    if c == 0:
        return 0.0

    sign = 1 if c > 0 else -1
    av = abs(c)
    bl = av.bit_length()

    if bl <= 53:
        return math.ldexp(float(c), -scale)

    shift = bl - 53
    mant = av >> shift

    # Rundung: wenn das nächste Bit 1 ist, aufrunden
    if shift > 0 and ((av >> (shift - 1)) & 1):
        mant += 1
        if mant == (1 << 53):
            mant >>= 1
            shift += 1

    return math.ldexp(sign * float(mant), shift - scale)


def _round_scaled_float(x: float, exp: int) -> int:
    """Berechnet round(x · 2^exp) für einen Float x und Integer-Exponent exp."""
    if x == 0.0 or not math.isfinite(x):
        return 0

    m, e = math.frexp(x)
    # m ist in [0.5, 1.0), e ist der Exponent: x = m * 2^e
    m_int = int(round(m * (1 << 53)))

    if m_int == 0:
        return 0

    if abs(m_int) == (1 << 53):
        m_int //= 2
        e += 1

    # x * 2^exp = m_int * 2^{e + exp - 53}
    shift = e + exp - 53

    if shift >= 0:
        return m_int << shift

    # Runden: m_int / 2^{-shift}
    denom = 1 << (-shift)
    sign = -1 if m_int < 0 else 1
    a = abs(m_int)
    q = (a + denom // 2) // denom
    return sign * q


def reduce(
    f: List[int], g: List[int], F: List[int], G: List[int]
) -> Tuple[List[int], List[int]]:
    """F, G gegen f, g verkleinern (Babai-Reduktion).

    k = ⌊(Ff⋆ + Gg⋆)/(ff⋆ + gg⋆)⌉, dann F ← F − kf, G ← G − kg.
    Wiederholen bis k = 0.

    Hinweis: Koeffizienten erreichen in der Rekursion rund 9'400 Bit und
    übersteigen den Wertebereich von Gleitkommazahlen; daher skalieren,
    k in Gleitkomma berechnen und runden, k·f und k·g exakt ganzzahlig
    abziehen, wiederholen solange k != 0.
    Alg. 7, §4.4.3.
    """
    n = len(f)
    F = list(F)
    G = list(G)

    if n == 0:
        return F, G

    if all(x == 0 for x in f) and all(x == 0 for x in g):
        return F, G

    # f und g werden so skaliert, dass ihre FFT-Werte sicher im
    # Double-Bereich bleiben.
    scale_f = max(0, _max_bit((f, g)) - 350)

    f_hat = fft([_scaled_float(c, scale_f) for c in f])
    g_hat = fft([_scaled_float(c, scale_f) for c in g])

    # Denominator |f̂|² + |ĝ|² für jede FFT-Komponente
    denom = []
    for fh, gh in zip(f_hat, g_hat):
        d = (fh * fh.conjugate() + gh * gh.conjugate()).real
        if math.isinf(d):
            d = 1e308
        elif not math.isfinite(d) or d <= 0.0:
            d = 1e-300
        denom.append(d)

    while True:
        max_fg = _max_bit((F, G))
        if max_fg == 0:
            break

        # F und G skalieren: genug führende Bits behalten für Präzision
        scale_F = max(0, max_fg - 500)

        F_hat = fft([_scaled_float(c, scale_F) for c in F])
        G_hat = fft([_scaled_float(c, scale_F) for c in G])

        mu_hat = []
        for fh, gh, Fh, Gh, d in zip(f_hat, g_hat, F_hat, G_hat, denom):
            num = Fh * fh.conjugate() + Gh * gh.conjugate()
            mu_hat.append(num / d)

        mu = ifft(mu_hat)

        exp = scale_F - scale_f
        k = [_round_scaled_float(x, exp) for x in mu]

        if all(x == 0 for x in k):
            break

        F = poly_sub(F, poly_mul(k, f))
        G = poly_sub(G, poly_mul(k, g))

    return F, G


def recompute_G(
    f: List[int], g: List[int], F: List[int], q: int = Q
) -> List[int]:
    """G aus der NTRU-Gleichung, für decode_sk. Gl. 3.35."""
    gF = mul_mod_q(g, F, q)
    G_mod = div_mod_q(gF, f, q)
    return center_mod_q(G_mod, q)
