"""Tests für fft.py – komplexe FFT, Splitten und Mergen.

Spec-Referenz: §3.3 (Gl. 3.6, 3.8, 3.10), §3.5 (Gl. 3.18, 3.19), §3.6 (Alg. 1,
Alg. 2, Gl. 3.20–3.24, Abb. 3.2), §4.2.1 (Gl. 4.1).

Was die Spec festlegt:
  - FFT(f) = (f(ζ))_ζ über alle komplexen Wurzeln ζ von xⁿ + 1, nicht skaliert
    (§3.5, Gl. 3.18/3.19).
  - Reihenfolge frei, aber einheitlich für FFT, invFFT, splitfft, mergefft (§3.6).
  - Adjungierte in FFT-Form = komplex konjugieren (§4.2.1), in Koeffizientenform
    a⋆ = a₀ − Σ aᵢ·x^(n−i) (Gl. 3.6).
  - ‖a‖² = (1/n)·Σ |a(ζ)|² (Gl. 3.8) = Σ aᵢ² (Gl. 3.10).
  - FFT(split(f)) = splitfft(FFT(f)), FFT(merge(f₀, f₁)) = mergefft(…) (Abb. 3.2).

Was der Scaffold festlegt (fft.py-Docstring), und die Tests deshalb prüfen:
  - Index k ↔ ζ_k = exp(i·(2k+1)·π/n), alle n Werte gespeichert.
  - merge_fft: f[k] = f₀[k mod n/2] + ζ_k·f₁[k mod n/2]
  - split_fft (k < n/2): f₀[k] = (f[k] + f[k+n/2])/2,
                         f₁[k] = (f[k] − f[k+n/2])/(2·ζ_k)

Annahmen (siehe ENTSCHEIDUNGEN.md):
  - Vergleiche mit Toleranz (Gleitkomma), relativ zur Grössenordnung der Werte.
  - Ungleiche Längen, Längen ohne Zweierpotenz → ValueError.
  - fft_div durch einen exakten Nullwert → ZeroDivisionError (Python-Standard
    für komplexe Division).
"""

import cmath
import copy
import math
import random

import pytest
from falcon.fft import (
    fft, ifft, fft_add, fft_sub, fft_mul, fft_div,
    fft_adj, fft_norm_sq, split_fft, merge_fft,
)
from falcon.poly import poly_add, poly_mul, split, lift, norm_sq


# ---------------------------------------------------------------------------
# Hilfen (unabhängig von der Implementierung)
# ---------------------------------------------------------------------------

def zeta(k: int, n: int) -> complex:
    """ζ_k = exp(i·(2k+1)·π/n), Gl. 3.19 mit Scaffold-Indexierung."""
    return cmath.exp(1j * (2 * k + 1) * math.pi / n)


def evaluate(f: list, z: complex) -> complex:
    """f(z) nach Horner."""
    acc = 0j
    for c in reversed(f):
        acc = acc * z + c
    return acc


def direct_fft(f: list) -> list:
    """FFT per Definition (Gl. 3.18): f an allen ζ_k auswerten, O(n²)."""
    n = len(f)
    return [evaluate(f, zeta(k, n)) for k in range(n)]


def monomial(k: int, n: int, c: int = 1) -> list:
    a = [0] * n
    a[k] = c
    return a


def rand_poly(rng: random.Random, n: int, bound: int = 1000) -> list:
    return [rng.randint(-bound, bound) for _ in range(n)]


def rand_complex(rng: random.Random, n: int, bound: float = 1000.0) -> list:
    return [complex(rng.uniform(-bound, bound), rng.uniform(-bound, bound))
            for _ in range(n)]


def assert_close(actual, expected, rel=1e-9, abs_floor=1e-9):
    """Elementweiser Vergleich mit Toleranz relativ zum grössten Betrag."""
    actual, expected = list(actual), list(expected)
    assert len(actual) == len(expected)
    scale = max([abs(x) for x in expected] + [1.0])
    tol = max(rel * scale, abs_floor)
    worst = max((abs(a - e) for a, e in zip(actual, expected)), default=0.0)
    assert worst <= tol, f"max. Abweichung {worst} > {tol}"


def is_real_number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


@pytest.fixture
def rng():
    return random.Random(0xF7F7)


ALL_DEGREES = pytest.mark.parametrize("n", [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024])
DEGREES = pytest.mark.parametrize("n", [1, 2, 4, 64, 512, 1024])
SPLITTABLE = pytest.mark.parametrize("n", [2, 4, 8, 64, 512, 1024])
INVALID_LENGTHS = pytest.mark.parametrize("n", [0, 3, 6, 12])


# ---------------------------------------------------------------------------
# Hilfen selbst prüfen
# ---------------------------------------------------------------------------

class TestHelpers:
    @ALL_DEGREES
    def test_zetas_are_roots_of_phi(self, n):
        for k in range(n):
            assert abs(zeta(k, n) ** n + 1) < 1e-9

    @ALL_DEGREES
    def test_zetas_are_distinct(self, n):
        zs = [zeta(k, n) for k in range(n)]
        assert min((abs(a - b) for i, a in enumerate(zs) for b in zs[i + 1:]),
                   default=1.0) > 1e-6

    @SPLITTABLE
    def test_scaffold_index_rules(self, n):
        # −ζ_k = ζ_{k+n/2}  und  ζ_k² = ζ'_{k mod n/2}
        for k in range(n // 2):
            assert abs(-zeta(k, n) - zeta(k + n // 2, n)) < 1e-12
        for k in range(n):
            assert abs(zeta(k, n) ** 2 - zeta(k % (n // 2), n // 2)) < 1e-12


# ---------------------------------------------------------------------------
# fft
# ---------------------------------------------------------------------------

class TestFft:
    """fft – §3.5, §3.6, Gl. 3.18/3.19; Reihenfolge laut Scaffold."""

    # --- Beispiele ---------------------------------------------------------

    def test_n_equals_1(self):
        # x + 1: einzige Wurzel −1, f = a₀ konstant
        assert_close(fft([3]), [3])

    def test_example_n2(self):
        # ζ₀ = i, ζ₁ = −i: [1, 2] ↦ [1 + 2i, 1 − 2i]
        assert_close(fft([1, 2]), [1 + 2j, 1 - 2j])

    def test_example_n4(self):
        # ζ_k = exp(i(2k+1)π/4) = (±1 ± i)/√2
        r = 1 / math.sqrt(2)
        z = [complex(r, r), complex(-r, r), complex(-r, -r), complex(r, -r)]
        f = [1, 2, 3, 4]
        expected = [1 + 2 * w + 3 * w ** 2 + 4 * w ** 3 for w in z]
        assert_close(fft(f), expected)

    @DEGREES
    def test_constant_is_not_scaled(self, n):
        assert_close(fft([5] + [0] * (n - 1)), [5] * n)

    @SPLITTABLE
    def test_fft_of_x_gives_roots_in_scaffold_order(self, n):
        assert_close(fft(monomial(1, n)), [zeta(k, n) for k in range(n)])

    # --- Definition ---------------------------------------------------------

    @ALL_DEGREES
    def test_matches_direct_evaluation(self, rng, n):
        f = rand_poly(rng, n)
        assert_close(fft(f), direct_fft(f))

    @DEGREES
    def test_accepts_float_coefficients(self, rng, n):
        f = [rng.uniform(-10, 10) for _ in range(n)]
        assert_close(fft(f), direct_fft(f))

    @DEGREES
    def test_output_is_complex_list_of_length_n(self, rng, n):
        out = fft(rand_poly(rng, n))
        assert isinstance(out, list) and len(out) == n
        assert all(isinstance(x, complex) for x in out)

    # --- Struktur -----------------------------------------------------------

    @SPLITTABLE
    def test_real_input_is_conjugate_symmetric(self, rng, n):
        # ζ_{n−1−k} = conj(ζ_k) ⇒ f(ζ_{n−1−k}) = conj(f(ζ_k)) für reelles f (§4.2.1)
        v = fft(rand_poly(rng, n))
        assert_close([v[n - 1 - k] for k in range(n)], [x.conjugate() for x in v])

    @DEGREES
    def test_linear(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert_close(fft(poly_add(a, b)), [x + y for x, y in zip(fft(a), fft(b))])

    @DEGREES
    def test_multiplication_becomes_pointwise(self, rng, n):
        # §3.5: FFT ist ein Ring-Isomorphismus
        a, b = rand_poly(rng, n, 100), rand_poly(rng, n, 100)
        assert_close(fft(poly_mul(a, b)), [x * y for x, y in zip(fft(a), fft(b))])

    @pytest.mark.parametrize("n", [512, 1024])
    def test_precision_with_signing_sized_values(self, rng, n):
        # c-Koeffizienten bis q − 1, Basis-Koeffizienten bis ~ 2⁷ (§3.11.5)
        f = [rng.randint(0, 12288) for _ in range(n)]
        assert_close(fft(f), direct_fft(f), rel=1e-11)

    @INVALID_LENGTHS
    def test_rejects_length_not_power_of_two(self, n):
        with pytest.raises(ValueError):
            fft([1] * n)

    def test_does_not_mutate_input(self, rng):
        f = rand_poly(rng, 8)
        f0 = copy.copy(f)
        fft(f)
        assert f == f0


# ---------------------------------------------------------------------------
# ifft
# ---------------------------------------------------------------------------

class TestIfft:
    """ifft – §3.5, §3.6: Umkehrung von fft, liefert reelle Koeffizienten."""

    def test_n_equals_1(self):
        assert_close(ifft([3 + 0j]), [3])

    def test_example_n2(self):
        assert_close(ifft([1 + 2j, 1 - 2j]), [1, 2])

    @DEGREES
    def test_constant_values_give_constant_polynomial(self, n):
        assert_close(ifft([5 + 0j] * n), [5] + [0] * (n - 1))

    @ALL_DEGREES
    def test_inverts_fft(self, rng, n):
        f = rand_poly(rng, n)
        assert_close(ifft(fft(f)), f)

    @DEGREES
    def test_fft_inverts_ifft(self, rng, n):
        # Für Werte, die von einem reellen Polynom stammen
        v = direct_fft(rand_poly(rng, n))
        assert_close(fft(ifft(v)), v)

    @DEGREES
    def test_returns_real_numbers(self, rng, n):
        # Docstring: List[float]; Imaginärteil ist bei reellen Polynomen 0
        out = ifft(direct_fft(rand_poly(rng, n)))
        assert isinstance(out, list) and len(out) == n
        assert all(is_real_number(x) for x in out)

    @pytest.mark.parametrize("n", [512, 1024])
    def test_roundtrip_rounds_to_exact_integers(self, rng, n):
        # Alg. 10 Z. 9: nach ifft wird gerundet – Fehler muss klar unter 0.5 liegen
        f = [rng.randint(-12288, 12288) for _ in range(n)]
        out = ifft(fft(f))
        assert [round(x) for x in out] == f
        assert max(abs(x - y) for x, y in zip(out, f)) < 1e-6

    @INVALID_LENGTHS
    def test_rejects_length_not_power_of_two(self, n):
        with pytest.raises(ValueError):
            ifft([1 + 0j] * n)

    def test_does_not_mutate_input(self, rng):
        v = direct_fft(rand_poly(rng, 8))
        v0 = copy.copy(v)
        ifft(v)
        assert v == v0


# ---------------------------------------------------------------------------
# Punktweise Operationen
# ---------------------------------------------------------------------------

class TestFftAdd:
    """fft_add – §3.5: punktweise Addition."""

    def test_example(self):
        assert fft_add([1 + 2j, 3 - 1j], [2 - 2j, -3 + 4j]) == [3 + 0j, 0 + 3j]

    @DEGREES
    def test_corresponds_to_poly_add(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert_close(fft_add(fft(a), fft(b)), fft(poly_add(a, b)))

    @DEGREES
    def test_commutative(self, rng, n):
        a, b = rand_complex(rng, n), rand_complex(rng, n)
        assert fft_add(a, b) == fft_add(b, a)

    @DEGREES
    def test_zero_is_neutral(self, rng, n):
        a = rand_complex(rng, n)
        assert fft_add(a, [0j] * n) == a

    @pytest.mark.parametrize("a, b", [([1j], [1j, 2j]), ([1j, 2j], [])])
    def test_rejects_mismatched_lengths(self, a, b):
        with pytest.raises(ValueError):
            fft_add(a, b)

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_complex(rng, 8), rand_complex(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        fft_add(a, b)
        assert (a, b) == (a0, b0)


class TestFftSub:
    """fft_sub – §3.5: punktweise Subtraktion."""

    def test_example(self):
        assert fft_sub([1 + 2j, 3 - 1j], [2 - 2j, -3 + 4j]) == [-1 + 4j, 6 - 5j]

    @DEGREES
    def test_corresponds_to_poly_sub(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        diff = [x - y for x, y in zip(a, b)]
        assert_close(fft_sub(fft(a), fft(b)), fft(diff))

    @DEGREES
    def test_minus_self_is_zero(self, rng, n):
        a = rand_complex(rng, n)
        assert fft_sub(a, a) == [0j] * n

    @DEGREES
    def test_inverse_of_add(self, rng, n):
        a, b = rand_complex(rng, n), rand_complex(rng, n)
        assert_close(fft_sub(fft_add(a, b), b), a)

    @pytest.mark.parametrize("a, b", [([1j], [1j, 2j]), ([1j, 2j], [])])
    def test_rejects_mismatched_lengths(self, a, b):
        with pytest.raises(ValueError):
            fft_sub(a, b)

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_complex(rng, 8), rand_complex(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        fft_sub(a, b)
        assert (a, b) == (a0, b0)


class TestFftMul:
    """fft_mul – §3.5: punktweise Multiplikation = Polynommultiplikation mod ϕ."""

    def test_example(self):
        # (1 + 2i)(3 − i) = 5 + 5i;  i·i = −1
        assert fft_mul([1 + 2j, 1j], [3 - 1j, 1j]) == [5 + 5j, -1 + 0j]

    @DEGREES
    def test_corresponds_to_poly_mul(self, rng, n):
        a, b = rand_poly(rng, n, 100), rand_poly(rng, n, 100)
        assert_close(fft_mul(fft(a), fft(b)), fft(poly_mul(a, b)))

    @SPLITTABLE
    def test_x_to_the_n_is_minus_one(self, n):
        # In FFT-Form: (fft(x))ⁿ = fft(−1)
        x_hat = fft(monomial(1, n))
        acc = [1 + 0j] * n
        for _ in range(n):
            acc = fft_mul(acc, x_hat)
        assert_close(acc, [-1] * n)

    @DEGREES
    def test_one_is_neutral(self, rng, n):
        a = rand_complex(rng, n)
        assert fft_mul(a, [1 + 0j] * n) == a

    @DEGREES
    def test_commutative(self, rng, n):
        a, b = rand_complex(rng, n), rand_complex(rng, n)
        assert fft_mul(a, b) == fft_mul(b, a)

    @pytest.mark.parametrize("a, b", [([1j], [1j, 2j]), ([1j, 2j], [])])
    def test_rejects_mismatched_lengths(self, a, b):
        with pytest.raises(ValueError):
            fft_mul(a, b)

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_complex(rng, 8), rand_complex(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        fft_mul(a, b)
        assert (a, b) == (a0, b0)


class TestFftDiv:
    """fft_div – §3.5: punktweise Division."""

    def test_example(self):
        # (5 + 5i)/(3 − i) = 1 + 2i;  −1/i = i
        assert_close(fft_div([5 + 5j, -1 + 0j], [3 - 1j, 1j]), [1 + 2j, 1j])

    @DEGREES
    def test_undoes_poly_mul(self, rng, n):
        a, b = rand_poly(rng, n, 100), rand_poly(rng, n, 100)
        assert_close(fft_div(fft(poly_mul(a, b)), fft(b)), fft(a), rel=1e-7)

    @DEGREES
    def test_inverse_of_mul(self, rng, n):
        a, b = rand_complex(rng, n), rand_complex(rng, n)
        assert_close(fft_div(fft_mul(a, b), b), a)

    @DEGREES
    def test_divide_by_self_is_one(self, rng, n):
        a = rand_complex(rng, n)
        assert_close(fft_div(a, a), [1] * n)

    @SPLITTABLE
    def test_inverse_of_x(self, n):
        # x⁻¹ = −x^(n−1) (wie in modq)
        assert_close(
            fft_div([1 + 0j] * n, fft(monomial(1, n))),
            fft(monomial(n - 1, n, -1)),
        )

    def test_rejects_exact_zero(self):
        with pytest.raises(ZeroDivisionError):
            fft_div([1 + 0j, 1 + 0j], [1 + 0j, 0j])

    @pytest.mark.parametrize("a, b", [([1j], [1j, 2j]), ([1j, 2j], [1j])])
    def test_rejects_mismatched_lengths(self, a, b):
        with pytest.raises(ValueError):
            fft_div(a, b)

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_complex(rng, 8), rand_complex(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        fft_div(a, b)
        assert (a, b) == (a0, b0)


# ---------------------------------------------------------------------------
# fft_adj
# ---------------------------------------------------------------------------

class TestFftAdj:
    """fft_adj – Gl. 3.6, §4.2.1: Hermitesch adjungiert = komplex konjugieren."""

    def test_example(self):
        assert fft_adj([1 + 2j, -3 - 4j, 5 + 0j]) == [1 - 2j, -3 + 4j, 5 - 0j]

    def test_example_matches_eq_3_6(self):
        # a = 1 + 2x + 3x² + 4x³  ⇒  a⋆ = 1 − 4x − 3x² − 2x³  (Gl. 3.6, n = 4)
        assert_close(fft_adj(fft([1, 2, 3, 4])), fft([1, -4, -3, -2]))

    @SPLITTABLE
    def test_matches_eq_3_6_in_general(self, rng, n):
        # a⋆ = a₀ − Σ_{i≥1} aᵢ·x^(n−i)
        a = rand_poly(rng, n)
        a_star = [a[0]] + [-a[n - i] for i in range(1, n)]
        assert_close(fft_adj(fft(a)), fft(a_star))

    @DEGREES
    def test_involution(self, rng, n):
        a = rand_complex(rng, n)
        assert fft_adj(fft_adj(a)) == a

    @SPLITTABLE
    def test_self_adjoint_product_is_real(self, rng, n):
        # §4.2.1: a·a⋆ (z. B. ff⋆ + gg⋆) hat rein reelle FFT-Werte ≥ 0
        a_hat = fft(rand_poly(rng, n))
        prod = fft_mul(a_hat, fft_adj(a_hat))
        assert all(abs(x.imag) <= 1e-9 * max(1.0, abs(x)) for x in prod)
        assert all(x.real >= 0 for x in prod)

    @DEGREES
    def test_multiplicative(self, rng, n):
        a, b = rand_complex(rng, n), rand_complex(rng, n)
        assert_close(fft_adj(fft_mul(a, b)), fft_mul(fft_adj(a), fft_adj(b)))

    def test_does_not_mutate_input(self, rng):
        a = rand_complex(rng, 8)
        a0 = copy.copy(a)
        fft_adj(a)
        assert a == a0


# ---------------------------------------------------------------------------
# fft_norm_sq
# ---------------------------------------------------------------------------

class TestFftNormSq:
    """fft_norm_sq – Gl. 3.8: ‖a‖² = (1/n)·Σ |a(ζ)|²."""

    def test_example_n2(self):
        # [1 + 2i, 1 − 2i] = fft([1, 2]) ⇒ (5 + 5)/2 = 5 = 1² + 2²
        assert fft_norm_sq([1 + 2j, 1 - 2j]) == pytest.approx(5)

    @DEGREES
    def test_includes_factor_one_over_n(self, n):
        # fft(1) = [1]·n hat Norm 1, nicht n
        assert fft_norm_sq([1 + 0j] * n) == pytest.approx(1)

    @DEGREES
    def test_zero(self, n):
        assert fft_norm_sq([0j] * n) == 0

    @ALL_DEGREES
    def test_parseval_matches_coefficient_norm(self, rng, n):
        # Gl. 3.8 = Gl. 3.10
        a = rand_poly(rng, n)
        assert fft_norm_sq(fft(a)) == pytest.approx(norm_sq(a), rel=1e-10)

    @DEGREES
    def test_returns_real_number(self, rng, n):
        assert is_real_number(fft_norm_sq(rand_complex(rng, n)))

    @DEGREES
    def test_scales_quadratically(self, rng, n):
        a = rand_complex(rng, n)
        assert fft_norm_sq([3 * x for x in a]) == pytest.approx(9 * fft_norm_sq(a))

    @DEGREES
    def test_invariant_under_adjoint(self, rng, n):
        a = rand_complex(rng, n)
        assert fft_norm_sq(fft_adj(a)) == pytest.approx(fft_norm_sq(a))

    @pytest.mark.parametrize("n, bound", [(512, 34034726), (1024, 70265242)])
    def test_precision_near_signature_bound(self, rng, n, bound):
        # Alg. 10 Z. 8 vergleicht mit ⌊β²⌋ – Fehler muss weit unter 1 liegen
        a = [rng.randint(-250, 250) for _ in range(n)]
        exact = norm_sq(a)
        assert exact < 2 * bound
        assert abs(fft_norm_sq(fft(a)) - exact) < 1e-3

    def test_does_not_mutate_input(self, rng):
        a = rand_complex(rng, 8)
        a0 = copy.copy(a)
        fft_norm_sq(a)
        assert a == a0


# ---------------------------------------------------------------------------
# split_fft / merge_fft
# ---------------------------------------------------------------------------

class TestSplitFft:
    """split_fft – Alg. 1; Indexregeln laut Scaffold."""

    def test_example_n2(self):
        # f = 1 + 2x: f₀ = 1, f₁ = 2 (konstante Polynome, Wert an ζ' = −1)
        f0, f1 = split_fft([1 + 2j, 1 - 2j])
        assert_close(f0, [1])
        assert_close(f1, [2])

    @SPLITTABLE
    def test_commutes_with_split_fig_3_2(self, rng, n):
        # splitfft(FFT(f)) = (FFT(f₀), FFT(f₁)) mit (f₀, f₁) = split(f)
        f = rand_poly(rng, n)
        f0, f1 = split(f)
        h0, h1 = split_fft(fft(f))
        assert_close(h0, fft(f0))
        assert_close(h1, fft(f1))

    @SPLITTABLE
    def test_scaffold_index_formula(self, rng, n):
        # Auch für beliebige (nicht hermitesche) komplexe Vektoren
        v = rand_complex(rng, n)
        h = n // 2
        f0, f1 = split_fft(v)
        assert_close(f0, [(v[k] + v[k + h]) / 2 for k in range(h)])
        assert_close(f1, [(v[k] - v[k + h]) / (2 * zeta(k, n)) for k in range(h)])

    @SPLITTABLE
    def test_halves_have_length_n_over_2(self, rng, n):
        f0, f1 = split_fft(rand_complex(rng, n))
        assert len(f0) == len(f1) == n // 2

    @SPLITTABLE
    def test_inverted_by_merge(self, rng, n):
        v = rand_complex(rng, n)
        assert_close(merge_fft(*split_fft(v)), v)

    @pytest.mark.parametrize("n", [1, 0, 3, 6])
    def test_rejects_unsplittable_length(self, n):
        with pytest.raises(ValueError):
            split_fft([1j] * n)

    def test_does_not_mutate_input(self, rng):
        v = rand_complex(rng, 8)
        v0 = copy.copy(v)
        split_fft(v)
        assert v == v0


class TestMergeFft:
    """merge_fft – Alg. 2; Indexregeln laut Scaffold."""

    def test_example_n2(self):
        # f₀ = 1, f₁ = 2 ⇒ f = 1 + 2x ⇒ FFT = [1 + 2i, 1 − 2i]
        assert_close(merge_fft([1 + 0j], [2 + 0j]), [1 + 2j, 1 - 2j])

    @SPLITTABLE
    def test_commutes_with_merge_fig_3_2(self, rng, n):
        # mergefft(FFT(f₀), FFT(f₁)) = FFT(f₀(x²) + x·f₁(x²))
        f0, f1 = rand_poly(rng, n // 2), rand_poly(rng, n // 2)
        x_f1 = poly_mul(monomial(1, n), lift(f1))
        assert_close(merge_fft(fft(f0), fft(f1)), fft(poly_add(lift(f0), x_f1)))

    @SPLITTABLE
    def test_scaffold_index_formula(self, rng, n):
        h = n // 2
        a, b = rand_complex(rng, h), rand_complex(rng, h)
        expected = [a[k % h] + zeta(k, n) * b[k % h] for k in range(n)]
        assert_close(merge_fft(a, b), expected)

    @SPLITTABLE
    def test_doubles_length(self, rng, n):
        h = n // 2
        assert len(merge_fft(rand_complex(rng, h), rand_complex(rng, h))) == n

    @SPLITTABLE
    def test_inverted_by_split(self, rng, n):
        a, b = rand_complex(rng, n // 2), rand_complex(rng, n // 2)
        r0, r1 = split_fft(merge_fft(a, b))
        assert_close(r0, a)
        assert_close(r1, b)

    @SPLITTABLE
    def test_ring_compatibility_eq_3_24(self, rng, n):
        # a = b·c  ⇔  a₀ = b₀c₀ + x·b₁c₁,  a₁ = b₀c₁ + b₁c₀  (Gl. 3.24, FFT-Form)
        h = n // 2
        b, c = rand_complex(rng, n), rand_complex(rng, n)
        b0, b1 = split_fft(b)
        c0, c1 = split_fft(c)
        x_half = [zeta(k, h) for k in range(h)]
        a0 = [b0[k] * c0[k] + x_half[k] * b1[k] * c1[k] for k in range(h)]
        a1 = [b0[k] * c1[k] + b1[k] * c0[k] for k in range(h)]
        assert_close(merge_fft(a0, a1), fft_mul(b, c))

    @pytest.mark.parametrize("a, b", [([1j], [1j, 2j]), ([1j, 2j], [1j])])
    def test_rejects_mismatched_lengths(self, a, b):
        with pytest.raises(ValueError):
            merge_fft(a, b)

    @pytest.mark.parametrize("h", [0, 3])
    def test_rejects_invalid_half_length(self, h):
        with pytest.raises(ValueError):
            merge_fft([1j] * h, [1j] * h)

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_complex(rng, 4), rand_complex(rng, 4)
        a0, b0 = copy.copy(a), copy.copy(b)
        merge_fft(a, b)
        assert (a, b) == (a0, b0)
