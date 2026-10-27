"""Tests für poly.py – Polynome in ℤ[x]/(xⁿ + 1).

Spec-Referenz: §3.1, §3.3, Gl. 3.10, Gl. 3.20, Gl. 3.22, Gl. 3.25/3.26, Alg. 6.

Darstellung: Liste von n ganzen Zahlen, Index i = Koeffizient von xⁱ
(f = Σ aᵢ·xⁱ, §3.3). Koeffizienten sind unbeschränkte ganze Zahlen (§3.1:
„the polynomials use nominally unbounded integers“); in NTRUSolve erreichen
sie rund 9'400 Bit (§4.4.3).

Testarten:
  - Beispiele von Hand gerechnet
  - algebraische Eigenschaften (neutrales Element, Kommutativität, Homomorphismen)
  - Randfälle: n = 1 (Rekursionsende in Alg. 6), grosse Zahlen, negative
    Koeffizienten, Eingaben werden nicht verändert
"""

import copy
import random

import pytest
from falcon.poly import (
    poly_add, poly_sub, poly_neg, poly_mul,
    split, lift, galois_conjugate, norm_sq,
)


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

BIG = 2 ** 9400  # Grössenordnung der Koeffizienten in NTRUSolve (§4.4.3)


def monomial(k: int, n: int, c: int = 1) -> list:
    """c·x^k als Liste der Länge n (0 ≤ k < n)."""
    a = [0] * n
    a[k] = c
    return a


def zero(n: int) -> list:
    return [0] * n


def one(n: int) -> list:
    return monomial(0, n)


def times_x(a: list) -> list:
    """x·a in ℤ[x]/(xⁿ + 1) als negazyklische Verschiebung, ohne poly_mul.
    Funktioniert auch für n = 1, wo x = −1 gilt."""
    return [-a[-1]] + a[:-1]


def rand_poly(rng: random.Random, n: int, bound: int = 2 ** 20) -> list:
    return [rng.randint(-bound, bound) for _ in range(n)]


@pytest.fixture
def rng():
    return random.Random(0xFA1C0)  # fester Seed → reproduzierbar


# Grade für Eigenschaftstests: Randfall n = 1 (wo sinnvoll), klein, Falcon.
DEGREES = pytest.mark.parametrize("n", [1, 2, 4, 512, 1024])
DEGREES_SPLITTABLE = pytest.mark.parametrize("n", [2, 4, 512, 1024])


def assert_int_list(a, n):
    assert isinstance(a, list)
    assert len(a) == n
    assert all(type(c) is int for c in a)


# ---------------------------------------------------------------------------
# poly_add
# ---------------------------------------------------------------------------

class TestPolyAdd:
    """poly_add – §3.1: koeffizientenweise Addition."""

    def test_example(self):
        assert poly_add([1, 2, 3, 4], [10, -20, 30, -40]) == [11, -18, 33, -36]

    def test_n_equals_1(self):
        assert poly_add([7], [-3]) == [4]

    @DEGREES
    def test_returns_int_list_of_same_length(self, rng, n):
        assert_int_list(poly_add(rand_poly(rng, n), rand_poly(rng, n)), n)

    @DEGREES
    def test_zero_is_neutral(self, rng, n):
        a = rand_poly(rng, n)
        assert poly_add(a, zero(n)) == a
        assert poly_add(zero(n), a) == a

    @DEGREES
    def test_commutative(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert poly_add(a, b) == poly_add(b, a)

    @DEGREES
    def test_associative(self, rng, n):
        a, b, c = (rand_poly(rng, n) for _ in range(3))
        assert poly_add(poly_add(a, b), c) == poly_add(a, poly_add(b, c))

    def test_no_reduction_mod_q(self):
        # Koeffizienten in ℤ, nicht in ℤ_q: 12288 + 1 bleibt 12289.
        assert poly_add([12288, 0], [1, 0]) == [12289, 0]

    def test_big_integers_exact(self):
        assert poly_add([BIG, -BIG], [1, -1]) == [BIG + 1, -BIG - 1]

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_poly(rng, 8), rand_poly(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        poly_add(a, b)
        assert (a, b) == (a0, b0)

    @pytest.mark.parametrize("a, b", [([1, 2], [1, 2, 3, 4]), ([1, 2, 3, 4], [1]), ([], [1])])
    def test_rejects_mismatched_lengths(self, a, b):
        # Beide Operanden müssen im selben Ring liegen; zip würde stillschweigend kürzen.
        with pytest.raises(ValueError):
            poly_add(a, b)


# ---------------------------------------------------------------------------
# poly_sub
# ---------------------------------------------------------------------------

class TestPolySub:
    """poly_sub – §3.1: koeffizientenweise Subtraktion."""

    def test_example(self):
        assert poly_sub([1, 2, 3, 4], [10, -20, 30, -40]) == [-9, 22, -27, 44]

    def test_n_equals_1(self):
        assert poly_sub([7], [-3]) == [10]

    @DEGREES
    def test_returns_int_list_of_same_length(self, rng, n):
        assert_int_list(poly_sub(rand_poly(rng, n), rand_poly(rng, n)), n)

    @DEGREES
    def test_minus_self_is_zero(self, rng, n):
        a = rand_poly(rng, n)
        assert poly_sub(a, a) == zero(n)

    @DEGREES
    def test_minus_zero_is_identity(self, rng, n):
        a = rand_poly(rng, n)
        assert poly_sub(a, zero(n)) == a

    @DEGREES
    def test_anticommutative(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert poly_sub(a, b) == poly_neg(poly_sub(b, a))

    @DEGREES
    def test_inverse_of_add(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert poly_sub(poly_add(a, b), b) == a

    def test_no_reduction_mod_q(self):
        assert poly_sub([0, 0], [12289, 1]) == [-12289, -1]

    def test_big_integers_exact(self):
        assert poly_sub([BIG, 0], [1, BIG]) == [BIG - 1, -BIG]

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_poly(rng, 8), rand_poly(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        poly_sub(a, b)
        assert (a, b) == (a0, b0)

    @pytest.mark.parametrize("a, b", [([1, 2], [1, 2, 3, 4]), ([1, 2, 3, 4], [1]), ([], [1])])
    def test_rejects_mismatched_lengths(self, a, b):
        # Beide Operanden müssen im selben Ring liegen; zip würde stillschweigend kürzen.
        with pytest.raises(ValueError):
            poly_sub(a, b)


# ---------------------------------------------------------------------------
# poly_neg
# ---------------------------------------------------------------------------

class TestPolyNeg:
    """poly_neg – Alg. 4, Z. 2 (−f, −F in der Basis)."""

    def test_example(self):
        assert poly_neg([1, -2, 0, 4]) == [-1, 2, 0, -4]

    def test_n_equals_1(self):
        assert poly_neg([5]) == [-5]

    @DEGREES
    def test_zero_stays_zero(self, n):
        assert poly_neg(zero(n)) == zero(n)

    @DEGREES
    def test_involution(self, rng, n):
        a = rand_poly(rng, n)
        assert poly_neg(poly_neg(a)) == a

    @DEGREES
    def test_additive_inverse(self, rng, n):
        a = rand_poly(rng, n)
        assert poly_add(a, poly_neg(a)) == zero(n)

    def test_big_integers_exact(self):
        assert poly_neg([BIG, -BIG]) == [-BIG, BIG]

    def test_does_not_mutate_input(self, rng):
        a = rand_poly(rng, 8)
        a0 = copy.copy(a)
        poly_neg(a)
        assert a == a0


# ---------------------------------------------------------------------------
# poly_mul
# ---------------------------------------------------------------------------

class TestPolyMul:
    """poly_mul – §3.1: Multiplikation in ℤ[x]/(xⁿ + 1), d. h. xⁿ = −1."""

    # --- Beispiele von Hand -------------------------------------------------

    def test_example_n4(self):
        # (1 + 2x + 3x² + 4x³)(5 + 6x + 7x² + 8x³), Terme ab x⁴ mit −1 zurückgefaltet:
        #   x⁰:  1·5                 − (2·8 + 3·7 + 4·6) = 5 − 61  = −56
        #   x¹:  1·6 + 2·5           − (3·8 + 4·7)       = 16 − 52 = −36
        #   x²:  1·7 + 2·6 + 3·5     − (4·8)             = 34 − 32 = 2
        #   x³:  1·8 + 2·7 + 3·6 + 4·5                   = 60
        assert poly_mul([1, 2, 3, 4], [5, 6, 7, 8]) == [-56, -36, 2, 60]

    def test_example_with_negative_coefficients(self):
        # (1 − x)(1 + x) = 1 − x² in ℤ[x]/(x⁴ + 1)
        assert poly_mul([1, -1, 0, 0], [1, 1, 0, 0]) == [1, 0, -1, 0]

    def test_n_equals_1(self):
        # ℤ[x]/(x + 1) ≅ ℤ: einfache Zahlmultiplikation
        assert poly_mul([6], [-7]) == [-42]

    def test_n_equals_2(self):
        # (a + bx)(c + dx) = (ac − bd) + (ad + bc)x, da x² = −1 (wie komplexe Zahlen)
        assert poly_mul([3, 4], [5, -2]) == [3 * 5 + 4 * 2, 3 * -2 + 4 * 5]

    # --- Reduktion xⁿ = −1 ----------------------------------------------------

    @DEGREES_SPLITTABLE
    def test_x_to_the_n_is_minus_one(self, n):
        # x^(n−1) · x = xⁿ = −1
        assert poly_mul(monomial(n - 1, n), monomial(1, n)) == monomial(0, n, -1)

    @DEGREES_SPLITTABLE
    def test_highest_monomial_squared(self, n):
        # x^(n−1) · x^(n−1) = x^(2n−2) = −x^(n−2)
        assert poly_mul(monomial(n - 1, n), monomial(n - 1, n)) == monomial(n - 2, n, -1)

    @DEGREES_SPLITTABLE
    def test_mul_by_x_is_negacyclic_shift(self, rng, n):
        # x·(a₀ + … + a_{n−1}x^{n−1}) = −a_{n−1} + a₀x + … + a_{n−2}x^{n−1}
        a = rand_poly(rng, n)
        assert poly_mul(a, monomial(1, n)) == [-a[-1]] + a[:-1]

    @pytest.mark.parametrize("n", [2, 4, 8])
    def test_x_to_the_2n_is_one(self, rng, n):
        # n-mal mit x multiplizieren negiert, 2n-mal ergibt wieder a
        a = rand_poly(rng, n)
        b = a
        for i in range(2 * n):
            b = poly_mul(b, monomial(1, n))
            if i == n - 1:
                assert b == poly_neg(a)
        assert b == a

    def test_not_cyclic_convolution(self):
        # Abgrenzung zu ℤ[x]/(xⁿ − 1): dort wäre x^(n−1)·x = +1.
        assert poly_mul(monomial(3, 4), monomial(1, 4)) != one(4)

    # --- Ring-Eigenschaften -----------------------------------------------------

    @DEGREES
    def test_returns_int_list_of_same_length(self, rng, n):
        assert_int_list(poly_mul(rand_poly(rng, n), rand_poly(rng, n)), n)

    @DEGREES
    def test_one_is_neutral(self, rng, n):
        a = rand_poly(rng, n)
        assert poly_mul(a, one(n)) == a
        assert poly_mul(one(n), a) == a

    @DEGREES
    def test_zero_annihilates(self, rng, n):
        assert poly_mul(rand_poly(rng, n), zero(n)) == zero(n)

    @DEGREES
    def test_commutative(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert poly_mul(a, b) == poly_mul(b, a)

    @pytest.mark.parametrize("n", [1, 2, 4, 64])
    def test_associative(self, rng, n):
        a, b, c = (rand_poly(rng, n) for _ in range(3))
        assert poly_mul(poly_mul(a, b), c) == poly_mul(a, poly_mul(b, c))

    @DEGREES
    def test_distributive(self, rng, n):
        a, b, c = (rand_poly(rng, n) for _ in range(3))
        assert poly_mul(a, poly_add(b, c)) == poly_add(poly_mul(a, b), poly_mul(a, c))

    @DEGREES
    def test_negation_commutes(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert poly_mul(poly_neg(a), b) == poly_neg(poly_mul(a, b))

    # --- Exaktheit ----------------------------------------------------------------

    def test_no_reduction_mod_q(self):
        assert poly_mul([12289, 0], [2, 0]) == [24578, 0]

    def test_big_integers_exact(self):
        # Gleitkomma würde hier Stellen verlieren.
        assert poly_mul([BIG + 1, 0], [BIG - 1, 0]) == [BIG * BIG - 1, 0]

    def test_big_integers_with_wraparound(self):
        # (BIG·x)·(BIG·x) = BIG²·x² = −BIG² in ℤ[x]/(x² + 1)
        assert poly_mul([0, BIG], [0, BIG]) == [-(BIG * BIG), 0]

    def test_big_random_integers_distributive(self, rng):
        n = 64
        a, b, c = (rand_poly(rng, n, bound=BIG) for _ in range(3))
        assert poly_mul(a, poly_add(b, c)) == poly_add(poly_mul(a, b), poly_mul(a, c))

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_poly(rng, 8), rand_poly(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        poly_mul(a, b)
        assert (a, b) == (a0, b0)

    @pytest.mark.parametrize("a, b", [([1, 2], [1, 2, 3, 4]), ([1, 2, 3, 4], [1]), ([], [1])])
    def test_rejects_mismatched_lengths(self, a, b):
        # Beide Operanden müssen im selben Ring liegen; zip würde stillschweigend kürzen.
        with pytest.raises(ValueError):
            poly_mul(a, b)


# ---------------------------------------------------------------------------
# split
# ---------------------------------------------------------------------------

class TestSplit:
    """split – Gl. 3.20: f₀ = gerade, f₁ = ungerade Koeffizienten,
    f(x) = f₀(x²) + x·f₁(x²)."""

    def test_example(self):
        assert split([0, 1, 2, 3, 4, 5, 6, 7]) == ([0, 2, 4, 6], [1, 3, 5, 7])

    def test_n_equals_2(self):
        # Kleinster teilbarer Fall: Hälften haben Grad n/2 = 1
        assert split([5, -9]) == ([5], [-9])

    @DEGREES_SPLITTABLE
    def test_halves_have_length_n_over_2(self, rng, n):
        f0, f1 = split(rand_poly(rng, n))
        assert_int_list(f0, n // 2)
        assert_int_list(f1, n // 2)

    @DEGREES_SPLITTABLE
    def test_reconstruction_eq_3_22(self, rng, n):
        # f = f₀(x²) + x·f₁(x²) = lift(f₀) + x·lift(f₁)
        f = rand_poly(rng, n)
        f0, f1 = split(f)
        x = monomial(1, n)
        assert poly_add(lift(f0), poly_mul(x, lift(f1))) == f

    @DEGREES_SPLITTABLE
    def test_linear(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        a0, a1 = split(a)
        b0, b1 = split(b)
        assert split(poly_add(a, b)) == (poly_add(a0, b0), poly_add(a1, b1))

    @DEGREES_SPLITTABLE
    def test_split_of_galois_conjugate(self, rng, n):
        # f(−x) = f₀(x²) − x·f₁(x²)  ⇒  split(f(−x)) = (f₀, −f₁)
        f = rand_poly(rng, n)
        f0, f1 = split(f)
        assert split(galois_conjugate(f)) == (f0, poly_neg(f1))

    def test_big_integers_exact(self):
        assert split([BIG, -BIG, BIG + 1, 1]) == ([BIG, BIG + 1], [-BIG, 1])

    def test_does_not_mutate_input(self, rng):
        a = rand_poly(rng, 8)
        a0 = copy.copy(a)
        split(a)
        assert a == a0

    @pytest.mark.parametrize("a", [[7], [], [1, 2, 3], [1, 2, 3, 4, 5]],
                             ids=["n=1", "empty", "n=3", "n=5"])
    def test_rejects_unsplittable_length(self, a):
        # Gl. 3.20 setzt n gerade voraus (f₀, f₁ ∈ ℚ[x]/(x^(n/2)+1)); n = 1 ist
        # das Rekursionsende und wird nicht weiter geteilt.
        with pytest.raises(ValueError):
            split(a)


# ---------------------------------------------------------------------------
# lift
# ---------------------------------------------------------------------------

class TestLift:
    """lift – Alg. 6, Z. 11–12: a(x) ↦ a(x²), Grad n/2 → n."""

    def test_example(self):
        assert lift([1, 2, 3, 4]) == [1, 0, 2, 0, 3, 0, 4, 0]

    def test_n_equals_1(self):
        # Rekursionsende von Alg. 6: F′, G′ haben Grad 1
        assert lift([7]) == [7, 0]

    @pytest.mark.parametrize("m", [1, 2, 256, 512])
    def test_doubles_length(self, rng, m):
        assert_int_list(lift(rand_poly(rng, m)), 2 * m)

    @pytest.mark.parametrize("m", [1, 2, 256, 512])
    def test_split_inverts_lift(self, rng, m):
        a = rand_poly(rng, m)
        assert split(lift(a)) == (a, zero(m))

    @pytest.mark.parametrize("m", [1, 2, 4, 64])
    def test_ring_homomorphism_mul(self, rng, m):
        # (x²)^m = x^(2m) = −1 in ℤ[x]/(x^(2m)+1), passt zu x^m = −1 in ℤ[x]/(x^m+1).
        # Daher lift(a·b) = lift(a)·lift(b) – Grundlage für Alg. 6, Z. 11–12.
        a, b = rand_poly(rng, m), rand_poly(rng, m)
        assert lift(poly_mul(a, b)) == poly_mul(lift(a), lift(b))

    @pytest.mark.parametrize("m", [1, 2, 256, 512])
    def test_ring_homomorphism_add(self, rng, m):
        a, b = rand_poly(rng, m), rand_poly(rng, m)
        assert lift(poly_add(a, b)) == poly_add(lift(a), lift(b))

    @pytest.mark.parametrize("m", [1, 2, 256, 512])
    def test_invariant_under_galois_conjugate(self, rng, m):
        # a((−x)²) = a(x²)
        b = lift(rand_poly(rng, m))
        assert galois_conjugate(b) == b

    @pytest.mark.parametrize("m", [1, 2, 256, 512])
    def test_preserves_norm(self, rng, m):
        a = rand_poly(rng, m)
        assert norm_sq(lift(a)) == norm_sq(a)

    def test_does_not_mutate_input(self, rng):
        a = rand_poly(rng, 4)
        a0 = copy.copy(a)
        lift(a)
        assert a == a0


# ---------------------------------------------------------------------------
# galois_conjugate
# ---------------------------------------------------------------------------

class TestGaloisConjugate:
    """galois_conjugate – Alg. 6, Z. 11–12: a(x) ↦ a(−x), d. h. aᵢ ↦ (−1)ⁱ·aᵢ."""

    def test_example(self):
        assert galois_conjugate([1, 2, 3, 4, 5, 6, 7, 8]) == [1, -2, 3, -4, 5, -6, 7, -8]

    def test_n_equals_1(self):
        # Nur a₀, keine Änderung
        assert galois_conjugate([9]) == [9]

    def test_negative_coefficients(self):
        assert galois_conjugate([-1, -2, -3, -4]) == [-1, 2, -3, 4]

    @DEGREES
    def test_returns_int_list_of_same_length(self, rng, n):
        assert_int_list(galois_conjugate(rand_poly(rng, n)), n)

    @DEGREES
    def test_involution(self, rng, n):
        a = rand_poly(rng, n)
        assert galois_conjugate(galois_conjugate(a)) == a

    @DEGREES
    def test_homomorphism_add(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert galois_conjugate(poly_add(a, b)) == poly_add(
            galois_conjugate(a), galois_conjugate(b)
        )

    @DEGREES
    def test_homomorphism_mul(self, rng, n):
        # x ↦ −x respektiert xⁿ + 1 (n gerade bzw. n = 1), also Ring-Automorphismus
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert galois_conjugate(poly_mul(a, b)) == poly_mul(
            galois_conjugate(a), galois_conjugate(b)
        )

    @DEGREES_SPLITTABLE
    def test_field_norm_has_only_even_coefficients(self, rng, n):
        # Gl. 3.25 = Gl. 3.26: a(x)·a(−x) = N(a)(x²) hat nur gerade Koeffizienten,
        # und die geraden sind a₀² − x·a₁² (Gl. 3.25).
        a = rand_poly(rng, n)
        prod = poly_mul(a, galois_conjugate(a))
        a0, a1 = split(a)
        expected = poly_sub(poly_mul(a0, a0), times_x(poly_mul(a1, a1)))
        assert split(prod) == (expected, zero(n // 2))

    @DEGREES
    def test_preserves_norm(self, rng, n):
        a = rand_poly(rng, n)
        assert norm_sq(galois_conjugate(a)) == norm_sq(a)

    def test_big_integers_exact(self):
        assert galois_conjugate([BIG, BIG]) == [BIG, -BIG]

    def test_does_not_mutate_input(self, rng):
        a = rand_poly(rng, 8)
        a0 = copy.copy(a)
        galois_conjugate(a)
        assert a == a0


# ---------------------------------------------------------------------------
# norm_sq
# ---------------------------------------------------------------------------

class TestNormSq:
    """norm_sq – Gl. 3.10: ‖a‖² = Σ aᵢ²."""

    def test_example(self):
        assert norm_sq([1, -2, 3, 0]) == 1 + 4 + 9

    def test_n_equals_1(self):
        assert norm_sq([-5]) == 25

    @DEGREES
    def test_zero(self, n):
        assert norm_sq(zero(n)) == 0

    @DEGREES
    def test_monomial(self, n):
        assert norm_sq(monomial(n - 1, n, -3)) == 9

    @DEGREES
    def test_returns_exact_int(self, rng, n):
        assert type(norm_sq(rand_poly(rng, n))) is int

    @DEGREES
    def test_non_negative(self, rng, n):
        assert norm_sq(rand_poly(rng, n)) >= 0

    @DEGREES
    def test_invariant_under_negation(self, rng, n):
        a = rand_poly(rng, n)
        assert norm_sq(poly_neg(a)) == norm_sq(a)

    @DEGREES_SPLITTABLE
    def test_invariant_under_mul_by_x(self, rng, n):
        # Negazyklische Verschiebung permutiert die Koeffizienten bis aufs Vorzeichen
        a = rand_poly(rng, n)
        assert norm_sq(poly_mul(a, monomial(1, n))) == norm_sq(a)

    @DEGREES_SPLITTABLE
    def test_split_is_isometry(self, rng, n):
        # Gl. 3.5: Koeffizienten werden nur umverteilt
        a = rand_poly(rng, n)
        a0, a1 = split(a)
        assert norm_sq(a) == norm_sq(a0) + norm_sq(a1)

    def test_scales_quadratically(self, rng):
        a = rand_poly(rng, 16)
        assert norm_sq([3 * c for c in a]) == 9 * norm_sq(a)

    def test_signature_bound_scale(self):
        # Grössenordnung von ⌊β²⌋: muss exakt bleiben, keine Gleitkommarundung
        a = [2 ** 40 + 1] * 1024
        assert norm_sq(a) == 1024 * (2 ** 40 + 1) ** 2

    def test_big_integers_exact(self):
        assert norm_sq([BIG, 1]) == BIG * BIG + 1

    def test_does_not_mutate_input(self, rng):
        a = rand_poly(rng, 8)
        a0 = copy.copy(a)
        norm_sq(a)
        assert a == a0
