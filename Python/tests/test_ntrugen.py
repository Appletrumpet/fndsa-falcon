"""Tests für ntrugen.py – Erzeugung von f, g, F, G.

Spec-Referenz: §3.8.2 (Alg. 5, Alg. 6, Alg. 7, Gl. 3.28, Gl. 3.29),
Gl. 3.15 (NTRU-Gleichung), Gl. 3.25 (Feldnorm), Gl. 3.35 (G neu berechnen),
§4.4.3 (Grössenordnungen, Babai-Reduktion). Doku: Falcon_Documentation §6.10.

Spec-Konventionen (die Spec ist massgebend):
  - xgcd über ℤ mit u·a − v·b = d = gcd(a, b) (Alg. 6 Z. 2), daher
    (F, G) = (v·q, u·q) im Basisfall (Z. 5).
  - generate_ntru_keys prüft genau, was Alg. 5 verlangt: f invertierbar mod q
    (Z. 7), γ ≤ 1.17·√q (Z. 9–10), NTRUSolve erfolgreich (Z. 12–13).

Testdaten: data/sampler/test-vector-sampler-falcon{512,1024}.txt enthält je
einen echten Schlüssel (f, g, F, G). Vorab mit Wegwerf-Orakel bestätigt:
  - NTRUSolve(f, g) liefert genau dieses (F, G). Grund: Alg. 7 reduziert bis
    k = 0; das legt den Vertreter eindeutig fest (jede Verschiebung um k·(f, g)
    verschiebt μ = (Ff⋆ + Gg⋆)/(ff⋆ + gg⋆) um k).
  - Reduce findet (F, G) auch nach Addition eines 2000-Bit-Vielfachen von (f, g)
    exakt wieder.
"""

import copy
import math
import random

import pytest
import falcon.ntrugen as ntrugen_module
import falcon.sampler as sampler_module
from falcon.fft import fft, ifft
from falcon.modq import is_invertible_mod_q
from falcon.ntrugen import (
    generate_ntru_keys, sample_short_poly, gram_schmidt_norm,
    solve_ntru, field_norm, xgcd, reduce, recompute_G,
)
from falcon.params import FALCON_512, FALCON_1024
from support import SeededRNG, load_kat, load_sampler_vectors, nmul

Q = 12289
GS_BOUND = 1.17 * math.sqrt(Q)          # Alg. 5 Z. 10
SIGMA_STAR = 1.43300980528773           # Gl. 3.29
PARAMS_BY_N = {512: FALCON_512, 1024: FALCON_1024}
KEY_SETS = pytest.mark.parametrize("n", [512, 1024], ids=["falcon512", "falcon1024"])


# ---------------------------------------------------------------------------
# Hilfen (exakt, unabhängig von der Implementierung)
# ---------------------------------------------------------------------------

def ntru_lhs(f, g, F, G):
    """fG − gF in ℤ[x]/(xⁿ+1)."""
    return [a - b for a, b in zip(nmul(f, G), nmul(g, F))]


def is_ntru(f, g, F, G, q=Q):
    return ntru_lhs(f, g, F, G) == [q] + [0] * (len(f) - 1)


def norm_down(a):
    """Feldnorm nach Gl. 3.25 (für Testdaten), unabhängig von field_norm."""
    a0, a1 = a[0::2], a[1::2]
    s0, s1 = nmul(a0, a0), nmul(a1, a1)
    xs1 = [-s1[-1]] + s1[:-1]
    return [x - y for x, y in zip(s0, xs1)]


def resultant(a):
    """Res(a, xⁿ+1) bis aufs Vorzeichen: Feldnorm bis auf Grad 1 (Alg. 6 Z. 8–9)."""
    while len(a) > 1:
        a = norm_down(a)
    return a[0]


def projection(f, g, F, G):
    """μ = (Ff⋆ + Gg⋆)/(ff⋆ + gg⋆) in Koeffizientenform (Alg. 7 Z. 2, ohne Rundung).
    Nur für kleine Koeffizienten (Gleitkomma)."""
    fh, gh, Fh, Gh = fft(f), fft(g), fft(F), fft(G)
    num = [a * b.conjugate() + c * d.conjugate() for a, b, c, d in zip(Fh, fh, Gh, gh)]
    den = [abs(a) ** 2 + abs(b) ** 2 for a, b in zip(fh, gh)]
    return ifft([x / y for x, y in zip(num, den)])


def expected_gamma(f, g, q=Q):
    """γ nach Gl. 3.28, direkt aus der Definition."""
    n = len(f)
    first = math.sqrt(sum(x * x for x in f) + sum(x * x for x in g))
    fh, gh = fft(f), fft(g)
    # ‖(q f⋆/(ff⋆+gg⋆), q g⋆/(ff⋆+gg⋆))‖² = (1/n)·Σ q²/(|f̂|² + |ĝ|²)  (Gl. 3.8)
    second = math.sqrt(sum(q * q / (abs(a) ** 2 + abs(b) ** 2) for a, b in zip(fh, gh)) / n)
    return max(first, second)


def real_key(n):
    v = load_sampler_vectors(n)
    return v.f, v.g, v.F, v.G


def small_params(n):
    import dataclasses
    return dataclasses.replace(FALCON_512, n=n)


@pytest.fixture
def rng():
    return random.Random(0x5EED)


@pytest.fixture
def fake_samplerz(monkeypatch):
    """SamplerZ ersetzen: protokolliert (μ, σ′) und liefert 1."""
    log = []

    def fake(mu, sigma_p, params, rng):
        log.append((mu, sigma_p))
        return 1

    monkeypatch.setattr(sampler_module, "sample_integer_gaussian", fake)
    if hasattr(ntrugen_module, "sample_integer_gaussian"):
        monkeypatch.setattr(ntrugen_module, "sample_integer_gaussian", fake)
    return log


# ---------------------------------------------------------------------------
# Testdaten selbst prüfen
# ---------------------------------------------------------------------------

class TestData:
    @KEY_SETS
    def test_vector_key_is_valid(self, n):
        f, g, F, G = real_key(n)
        assert is_ntru(f, g, F, G)
        assert expected_gamma(f, g) <= GS_BOUND

    @KEY_SETS
    def test_vector_key_is_reduced(self, n):
        # Alg. 7 endet bei k = ⌊μ⌉ = 0, d. h. alle Koeffizienten von μ in [−½, ½]
        mu = projection(*real_key(n))
        assert max(abs(x) for x in mu) <= 0.5

    def test_sigma_star_matches_formula(self):
        # Gl. 3.29: σ* = 1.17·√(q/8192)
        assert 1.17 * math.sqrt(Q / 8192) == pytest.approx(SIGMA_STAR, abs=1e-13)


# ---------------------------------------------------------------------------
# field_norm
# ---------------------------------------------------------------------------

class TestFieldNorm:
    """field_norm – Gl. 3.25: N(a) = a₀² − x·a₁², Grad n → n/2."""

    def test_example_n4(self):
        # a = 1 + 2x + 3x² + 4x³: a₀ = 1 + 3x, a₁ = 2 + 4x (in ℤ[x]/(x²+1))
        #   a₀² = 1 + 6x + 9x² = −8 + 6x
        #   a₁² = 4 + 16x + 16x² = −12 + 16x,  x·a₁² = −12x + 16x² = −16 − 12x
        #   N(a) = (−8 + 6x) − (−16 − 12x) = 8 + 18x
        assert field_norm([1, 2, 3, 4]) == [8, 18]

    def test_example_n2(self):
        # In ℤ[x]/(x+1) ist x = −1: N(a₀ + a₁x) = a₀² + a₁²
        assert field_norm([3, 4]) == [25]

    def test_norm_of_x(self):
        # N(x) = x·(−x) = −x² → in ℤ[x]/(x²+1) als Polynom in y = x²: −y
        assert field_norm([0, 1, 0, 0]) == [0, -1]

    @pytest.mark.parametrize("n", [2, 4, 8, 64, 512])
    def test_equals_a_times_galois_conjugate(self, rng, n):
        # Gl. 3.26: N(a)(x²) = a(x)·a(−x)
        a = [rng.randint(-20, 20) for _ in range(n)]
        prod = nmul(a, [c if i % 2 == 0 else -c for i, c in enumerate(a)])
        assert field_norm(a) == prod[0::2]
        assert all(c == 0 for c in prod[1::2])

    @pytest.mark.parametrize("n", [2, 4, 16])
    def test_multiplicative(self, rng, n):
        a = [rng.randint(-9, 9) for _ in range(n)]
        b = [rng.randint(-9, 9) for _ in range(n)]
        assert field_norm(nmul(a, b)) == nmul(field_norm(a), field_norm(b))

    def test_halves_degree(self, rng):
        assert len(field_norm([rng.randint(-5, 5) for _ in range(1024)])) == 512

    def test_big_integers_exact(self):
        # Koeffizienten verdoppeln ihre Grösse pro Stufe (§4.4.3)
        B = 2 ** 3000
        assert field_norm([B, 1]) == [B * B + 1]

    @pytest.mark.parametrize("a", [[7], [], [1, 2, 3]])
    def test_rejects_unsplittable_length(self, a):
        with pytest.raises(ValueError):
            field_norm(a)

    def test_does_not_mutate_input(self):
        a = [1, 2, 3, 4]
        field_norm(a)
        assert a == [1, 2, 3, 4]


# ---------------------------------------------------------------------------
# xgcd
# ---------------------------------------------------------------------------

class TestXgcd:
    """xgcd – Alg. 6 Z. 2: (d, u, v) mit u·a − v·b = d = gcd(a, b)."""

    @pytest.mark.parametrize("a, b, d", [
        (3, 5, 1), (5, 3, 1), (12, 18, 6), (17, 17, 17),
        (1, 0, 1), (0, 7, 7), (12289, 2, 1), (2 ** 64, 6, 2),
    ])
    def test_values(self, a, b, d):
        dd, u, v = xgcd(a, b)
        assert dd == d
        assert u * a - v * b == d

    @pytest.mark.parametrize("a, b", [(-3, 5), (3, -5), (-12, -18)])
    def test_negative_inputs(self, a, b):
        d, u, v = xgcd(a, b)
        assert d == math.gcd(a, b) and d > 0
        assert u * a - v * b == d

    def test_spec_sign_convention_gives_ntru_solution(self):
        # Alg. 6 Z. 5 mit n = 1: (F, G) = (v·q, u·q) ⇒ fG − gF = q·(u·f − v·g) = q
        f, g = 3, 5
        d, u, v = xgcd(f, g)
        F, G = v * Q, u * Q
        assert f * G - g * F == Q

    def test_big_integers(self, rng):
        a = rng.getrandbits(9400) | 1
        b = rng.getrandbits(9400) | 1
        d, u, v = xgcd(a, b)
        assert d == math.gcd(a, b)
        assert u * a - v * b == d

    def test_returns_ints(self):
        assert all(type(x) is int for x in xgcd(10, 4))


# ---------------------------------------------------------------------------
# reduce
# ---------------------------------------------------------------------------

class TestReduce:
    """reduce – Alg. 7: (F, G) ← (F, G) − k·(f, g) mit k = ⌊(Ff⋆+Gg⋆)/(ff⋆+gg⋆)⌉,
    wiederholt bis k = 0."""

    def test_example_f_one_g_zero(self):
        # ff⋆ + gg⋆ = 1, k = ⌊F⌉ = F ⇒ F′ = 0, G′ = G − F·0 = G
        assert reduce([1, 0], [0, 0], [5, -3], [2, 7]) == ([0, 0], [2, 7])

    def test_example_f_g_one(self):
        # f = g = 1: k = ⌊(F + G)/2⌉ = ⌊(10 + 0)/2⌉ = 5 ⇒ (F, G) = (5, −5)
        assert reduce([1, 0], [1, 0], [10, 0], [0, 0]) == ([5, 0], [-5, 0])

    @KEY_SETS
    def test_reduced_key_unchanged(self, n):
        f, g, F, G = real_key(n)
        assert reduce(f, g, F, G) == (F, G)

    @pytest.mark.parametrize("n", [512, pytest.param(1024, marks=pytest.mark.slow)],
                             ids=["falcon512", "falcon1024"])
    def test_recovers_from_huge_offset(self, n):
        # (F + K·f, G + K·g) mit 2000-Bit-Koeffizienten in K → wieder (F, G);
        # Docstring: Koeffizienten übersteigen den Gleitkommabereich
        f, g, F, G = real_key(n)
        r = random.Random(n)
        K = [r.getrandbits(2000) - (1 << 1999) for _ in range(n)]
        F2 = [a + b for a, b in zip(F, nmul(K, f))]
        G2 = [a + b for a, b in zip(G, nmul(K, g))]
        assert reduce(f, g, F2, G2) == (F, G)

    @pytest.mark.slow
    def test_recovers_from_9400_bit_offset(self):
        # Grössenordnung aus §4.4.3 (Tabelle: ≈ 9'400 Bit)
        f, g, F, G = real_key(512)
        r = random.Random(9400)
        K = [r.getrandbits(9400) - (1 << 9399) for _ in range(512)]
        F2 = [a + b for a, b in zip(F, nmul(K, f))]
        G2 = [a + b for a, b in zip(G, nmul(K, g))]
        assert reduce(f, g, F2, G2) == (F, G)

    @pytest.mark.parametrize("n", [2, 4, 16, 64])
    def test_properties_random(self, rng, n):
        # Für beliebige Eingaben:
        #   - Differenz ist ein Vielfaches k·(f, g) ⇒ (F − F′)·g = (G − G′)·f
        #   - fG − gF bleibt gleich
        #   - Ergebnis ist reduziert: μ in [−½, ½]
        #   - erneutes Reduzieren ändert nichts
        f = [rng.randint(-5, 5) for _ in range(n)]
        g = [rng.randint(-5, 5) for _ in range(n)]
        F = [rng.randint(-10 ** 6, 10 ** 6) for _ in range(n)]
        G = [rng.randint(-10 ** 6, 10 ** 6) for _ in range(n)]
        F2, G2 = reduce(f, g, F, G)
        dF = [a - b for a, b in zip(F, F2)]
        dG = [a - b for a, b in zip(G, G2)]
        assert nmul(dF, g) == nmul(dG, f)
        assert ntru_lhs(f, g, F2, G2) == ntru_lhs(f, g, F, G)
        assert max(abs(x) for x in projection(f, g, F2, G2)) <= 0.5 + 1e-9
        assert reduce(f, g, F2, G2) == (F2, G2)

    def test_does_not_increase_norm(self, rng):
        n = 16
        f = [rng.randint(-5, 5) for _ in range(n)]
        g = [rng.randint(-5, 5) for _ in range(n)]
        F = [rng.randint(-10 ** 4, 10 ** 4) for _ in range(n)]
        G = [rng.randint(-10 ** 4, 10 ** 4) for _ in range(n)]
        F2, G2 = reduce(f, g, F, G)
        assert sum(x * x for x in F2 + G2) <= sum(x * x for x in F + G)

    def test_returns_exact_ints(self):
        F2, G2 = reduce(*real_key(512))
        assert all(type(x) is int for x in F2 + G2)

    def test_does_not_mutate_inputs(self):
        key = tuple(list(x) for x in real_key(512))
        before = copy.deepcopy(key)
        reduce(*key)
        assert key == before


# ---------------------------------------------------------------------------
# solve_ntru
# ---------------------------------------------------------------------------

class TestSolveNtru:
    """solve_ntru – Alg. 6: fG − gF = q, rekursiv über die Feldnorm."""

    @pytest.mark.parametrize("n", [512, pytest.param(1024, marks=pytest.mark.slow)],
                             ids=["falcon512", "falcon1024"])
    def test_reproduces_vector_key(self, n):
        # Eindeutig dank vollständiger Reduktion (siehe Moduldocstring)
        f, g, F, G = real_key(n)
        assert solve_ntru(f, g, PARAMS_BY_N[n]) == (F, G)

    def test_base_case_n1(self):
        # Alg. 6 Z. 1–6: u·3 − v·5 = 1, (F, G) = (v·q, u·q), keine Reduktion
        F, G = solve_ntru([3], [5], small_params(2))
        assert 3 * G[0] - 5 * F[0] == Q

    @pytest.mark.parametrize("f, g", [
        ([2, 0], [0, 2]),     # beide gerade → gcd der Resultanten gerade
        ([1, 1], [1, 1]),     # f = g → Resultanten gleich (= 2)
        ([4], [6]),           # n = 1, gcd = 2
    ])
    def test_returns_none_if_gcd_not_one(self, f, g):
        # Alg. 6 Z. 3–4
        assert solve_ntru(f, g, small_params(max(2, len(f)))) is None

    @pytest.mark.parametrize("n", [2, 4, 8, 16, 64])
    def test_random_small(self, rng, n):
        # Lösung genau dann, wenn gcd(Res f, Res g) = 1 (Alg. 6 Z. 3)
        found = 0
        for _ in range(6):
            f = [rng.randint(-4, 4) for _ in range(n)]
            g = [rng.randint(-4, 4) for _ in range(n)]
            r = solve_ntru(f, g, small_params(n))
            if math.gcd(resultant(f), resultant(g)) == 1:
                assert r is not None
                assert is_ntru(f, g, *r)
                found += 1
            else:
                assert r is None
        assert found > 0, "kein lösbarer Fall gezogen – Saat anpassen"

    @pytest.mark.parametrize("n", [16, 64])
    def test_solution_is_reduced(self, rng, n):
        # Alg. 6 Z. 13: Ergebnis ist bezüglich (f, g) reduziert
        while True:
            f = [rng.randint(-4, 4) for _ in range(n)]
            g = [rng.randint(-4, 4) for _ in range(n)]
            if math.gcd(resultant(f), resultant(g)) == 1:
                break
        F, G = solve_ntru(f, g, small_params(n))
        assert max(abs(x) for x in projection(f, g, F, G)) <= 0.5 + 1e-9

    def test_does_not_mutate_inputs(self):
        f, g, _, _ = real_key(512)
        f0, g0 = list(f), list(g)
        solve_ntru(f, g, FALCON_512)
        assert (f, g) == (f0, g0)


# ---------------------------------------------------------------------------
# recompute_G
# ---------------------------------------------------------------------------

class TestRecomputeG:
    """recompute_G – Gl. 3.35: G = (q + gF)/f mod ϕ."""

    def test_example_n1(self):
        # 111·111 − 4·8 = 12321 − 32 = 12289 = q
        assert recompute_G([111], [4], [8]) == [111]

    @KEY_SETS
    def test_vector_key(self, n):
        f, g, F, G = real_key(n)
        assert recompute_G(f, g, F) == G

    @KEY_SETS
    def test_kat_keys(self, n):
        # §3.11.5: G wird beim Laden neu berechnet; NTRU-Gleichung muss gelten
        from falcon.encoding import decode_sk
        for rec in load_kat(n)[:5]:
            f, g, F = decode_sk(rec.sk)
            assert is_ntru(f, g, F, recompute_G(f, g, F)), f"count {rec.count}"

    def test_returns_ints(self):
        assert all(type(x) is int for x in recompute_G(*real_key(512)[:3]))

    def test_does_not_mutate_inputs(self):
        f, g, F, _ = real_key(512)
        before = (list(f), list(g), list(F))
        recompute_G(f, g, F)
        assert (f, g, F) == before


# ---------------------------------------------------------------------------
# gram_schmidt_norm
# ---------------------------------------------------------------------------

class TestGramSchmidtNorm:
    """gram_schmidt_norm – Gl. 3.28:
    γ = max{‖(g, −f)‖, ‖(q·f⋆/(ff⋆+gg⋆), q·g⋆/(ff⋆+gg⋆))‖}."""

    @pytest.mark.parametrize("n", [2, 4, 16])
    def test_example_f_one_g_zero(self, n):
        # ‖(0, −1)‖ = 1; zweiter Term: |f̂| = 1 an jeder Wurzel ⇒ √(q²) = q
        f = [1] + [0] * (n - 1)
        assert gram_schmidt_norm(f, [0] * n, small_params(n)) == pytest.approx(Q)

    @pytest.mark.parametrize("n", [2, 4, 16])
    def test_example_f_g_one(self, n):
        # ‖(1, −1)‖ = √2; zweiter Term: q/√2 (|f̂|² + |ĝ|² = 2)
        one = [1] + [0] * (n - 1)
        assert gram_schmidt_norm(one, one, small_params(n)) == pytest.approx(Q / math.sqrt(2))

    def test_first_term_can_dominate(self):
        # f = 200, g = 0 (n = 2): ‖(g, −f)‖ = 200, zweiter Term q/200 ≈ 61.4
        assert gram_schmidt_norm([200, 0], [0, 0], small_params(2)) == pytest.approx(200)

    @KEY_SETS
    def test_vector_key(self, n):
        f, g, _, _ = real_key(n)
        gamma = gram_schmidt_norm(f, g, PARAMS_BY_N[n])
        assert gamma == pytest.approx(expected_gamma(f, g), rel=1e-9)
        assert gamma <= GS_BOUND

    @pytest.mark.parametrize("n", [4, 16, 64])
    def test_matches_definition_random(self, rng, n):
        f = [rng.randint(-6, 6) for _ in range(n)]
        g = [rng.randint(-6, 6) for _ in range(n)]
        assert gram_schmidt_norm(f, g, small_params(n)) == pytest.approx(
            expected_gamma(f, g), rel=1e-9
        )

    def test_returns_real_number(self):
        f, g, _, _ = real_key(512)
        x = gram_schmidt_norm(f, g, FALCON_512)
        assert isinstance(x, float) and not isinstance(x, complex)


# ---------------------------------------------------------------------------
# sample_short_poly
# ---------------------------------------------------------------------------

class TestSampleShortPoly:
    """sample_short_poly – Alg. 5 Z. 1–6, Gl. 3.29: jeder Koeffizient ist die Summe
    von 4096/n Ziehungen SamplerZ(0, σ*), σ* = 1.17·√(q/8192); Ergebnis
    ~ D_{ℤ, σ{f,g}} mit σ{f,g} = 1.17·√(q/2n)."""

    @pytest.mark.parametrize("n", [2, 16, 512, 1024])
    def test_uses_eq_3_29(self, n, fake_samplerz):
        # Mit SamplerZ ≡ 1: Koeffizient = 4096/n, insgesamt 4096 Aufrufe mit (0, σ*)
        a = sample_short_poly(small_params(n), SeededRNG(1))
        assert a == [4096 // n] * n
        assert len(fake_samplerz) == 4096
        assert all(mu == 0 for mu, _ in fake_samplerz)
        assert all(s == pytest.approx(SIGMA_STAR, abs=1e-12) for _, s in fake_samplerz)

    @pytest.mark.parametrize("params", [FALCON_512, FALCON_1024], ids=["512", "1024"])
    def test_distribution(self, params):
        # Mittel ≈ 0, Standardabweichung ≈ σ{f,g} (4.053 bzw. 2.866)
        rng = SeededRNG(2)
        xs = [x for _ in range(8) for x in sample_short_poly(params, rng)]
        N = len(xs)
        sigma_fg = 1.17 * math.sqrt(Q / (2 * params.n))
        mean = sum(xs) / N
        sd = math.sqrt(sum((x - mean) ** 2 for x in xs) / (N - 1))
        assert abs(mean) < 5 * sigma_fg / math.sqrt(N)
        assert sd == pytest.approx(sigma_fg, rel=0.05)

    @pytest.mark.parametrize("params", [FALCON_512, FALCON_1024], ids=["512", "1024"])
    def test_shape_and_type(self, params):
        a = sample_short_poly(params, SeededRNG(3))
        assert len(a) == params.n and all(type(x) is int for x in a)

    def test_deterministic_for_same_randomness(self):
        assert sample_short_poly(FALCON_512, SeededRNG(4)) == sample_short_poly(FALCON_512, SeededRNG(4))


# ---------------------------------------------------------------------------
# generate_ntru_keys
# ---------------------------------------------------------------------------

def assert_valid_key(f, g, F, G, n):
    # Alles, was Alg. 5 garantiert
    assert len(f) == len(g) == len(F) == len(G) == n
    assert all(type(x) is int for x in f + g + F + G)
    assert is_ntru(f, g, F, G)                       # Z. 12, Gl. 3.15
    assert is_invertible_mod_q(f)                    # Z. 7
    assert expected_gamma(f, g) <= GS_BOUND          # Z. 9–10, Gl. 3.28


class TestGenerateNtruKeys:
    """generate_ntru_keys – Alg. 5."""

    @pytest.mark.parametrize("seed", [10, 11])
    def test_falcon_512(self, seed):
        assert_valid_key(*generate_ntru_keys(FALCON_512, SeededRNG(seed)), 512)

    @pytest.mark.slow
    def test_falcon_1024(self):
        assert_valid_key(*generate_ntru_keys(FALCON_1024, SeededRNG(12)), 1024)

    @pytest.mark.parametrize("n", [16, 64])
    def test_reduced_degrees(self, n):
        assert_valid_key(*generate_ntru_keys(small_params(n), SeededRNG(13)), n)

    def test_F_G_are_reduced(self):
        # Z. 12 → NTRUSolve endet mit Reduce (Alg. 6 Z. 13)
        f, g, F, G = generate_ntru_keys(FALCON_512, SeededRNG(14))
        assert max(abs(x) for x in projection(f, g, F, G)) <= 0.5 + 1e-9

    def test_deterministic_for_same_randomness(self):
        a = generate_ntru_keys(small_params(64), SeededRNG(15))
        b = generate_ntru_keys(small_params(64), SeededRNG(15))
        assert a == b

    def test_different_randomness_gives_different_keys(self):
        a = generate_ntru_keys(small_params(64), SeededRNG(16))
        b = generate_ntru_keys(small_params(64), SeededRNG(17))
        assert a != b

    # --- Neustarts (Alg. 5 Z. 8, 11, 14) --------------------------------------------

    def test_restarts_if_f_not_invertible(self, monkeypatch):
        # Z. 7–8: erste Ziehung liefert f = 0 (nicht invertierbar)
        real = ntrugen_module.sample_short_poly
        calls = []

        def patched(params, rng):
            calls.append(1)
            return [0] * params.n if len(calls) <= 2 else real(params, rng)

        monkeypatch.setattr(ntrugen_module, "sample_short_poly", patched)
        f, g, F, G = generate_ntru_keys(small_params(64), SeededRNG(18))
        assert_valid_key(f, g, F, G, 64)
        assert len(calls) > 2

    def test_restarts_if_gamma_too_large(self, monkeypatch):
        # Z. 9–11: f = 1, g = 0 ist invertierbar, aber γ = q > 1.17·√q
        real = ntrugen_module.sample_short_poly
        calls = []

        def patched(params, rng):
            calls.append(1)
            if len(calls) == 1:
                return [1] + [0] * (params.n - 1)
            if len(calls) == 2:
                return [0] * params.n
            return real(params, rng)

        monkeypatch.setattr(ntrugen_module, "sample_short_poly", patched)
        f, g, F, G = generate_ntru_keys(small_params(64), SeededRNG(19))
        assert_valid_key(f, g, F, G, 64)
        assert len(calls) > 2

    def test_restarts_if_solve_fails(self, monkeypatch):
        # Z. 13–14: NTRUSolve liefert ⊥ → neu ziehen
        real = ntrugen_module.solve_ntru
        calls = []

        def patched(f, g, params):
            calls.append(1)
            return None if len(calls) == 1 else real(f, g, params)

        monkeypatch.setattr(ntrugen_module, "solve_ntru", patched)
        f, g, F, G = generate_ntru_keys(small_params(64), SeededRNG(20))
        assert_valid_key(f, g, F, G, 64)
        assert len(calls) >= 2
