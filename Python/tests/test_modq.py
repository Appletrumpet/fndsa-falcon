"""Tests für modq.py – Rechnen mod q = 12289 über NTT.

Spec-Referenz: §3.5, §3.8.2, §4.2.2, Alg. 5 (Z. 7), Alg. 16 (Z. 5).

Was die Spec festlegt:
  - NTT(f) = (f(ω) mod q) für alle Wurzeln ω von xⁿ + 1 in ℤ_q (§3.5, §4.2.2).
    Nicht skaliert (wie die FFT, §3.5).
  - Die Reihenfolge der Wurzeln ist frei, muss aber konsistent sein (§3.5).
    Darum wird keine Reihenfolge fest kodiert: ntt(x) liefert die Wurzeln in der
    Reihenfolge der Implementierung, und für jedes f muss ntt(f)[k] = f(ntt(x)[k])
    gelten.
  - f invertierbar mod q ⇔ NTT(f) enthält keine 0 (§3.8.2, Alg. 5 Z. 7).
  - s₁ wird auf ⌈−q/2⌉ … ⌊q/2⌋ = −6144 … 6144 normalisiert (Alg. 16, Z. 5).

Annahmen (siehe ENTSCHEIDUNGEN.md):
  - Ausgaben liegen in 0 … q−1 (ausser center_mod_q).
  - Eingaben dürfen beliebige ganze Zahlen sein (auch negativ / ≥ q) und werden
    mod q reduziert – f, g sind vorzeichenbehaftet.
  - mul_mod_q / div_mod_q arbeiten in Koeffizientenform (Ein- und Ausgabe).
  - Nicht invertierbarer Divisor, ungleiche Längen, Länge ohne Wurzeln → ValueError.
"""

import copy
import random
from functools import lru_cache

import pytest
from falcon.modq import (
    ntt, intt, mul_mod_q, div_mod_q, is_invertible_mod_q, center_mod_q,
)
from falcon.poly import poly_mul

Q = 12289


# ---------------------------------------------------------------------------
# Hilfen (unabhängig von der Implementierung)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=None)
def roots_of_phi(n: int) -> frozenset:
    """Alle ω ∈ ℤ_q mit ωⁿ ≡ −1 (mod q), per Brute Force."""
    return frozenset(w for w in range(1, Q) if pow(w, n, Q) == Q - 1)


def evaluate(f: list, w: int) -> int:
    """f(w) mod q nach Horner."""
    acc = 0
    for c in reversed(f):
        acc = (acc * w + c) % Q
    return acc


def monomial(k: int, n: int, c: int = 1) -> list:
    a = [0] * n
    a[k] = c
    return a


def one(n: int) -> list:
    return monomial(0, n)


def rand_poly(rng: random.Random, n: int, lo: int = 0, hi: int = Q - 1) -> list:
    return [rng.randint(lo, hi) for _ in range(n)]


def rand_invertible(rng: random.Random, n: int) -> list:
    while True:
        f = rand_poly(rng, n)
        if all(evaluate(f, w) for w in roots_of_phi(n)):
            return f


def mod_q(a: list) -> list:
    return [c % Q for c in a]


def in_range(a: list) -> bool:
    return all(type(c) is int and 0 <= c < Q for c in a)


@pytest.fixture
def rng():
    return random.Random(0x12289)


# Alle Grade, für die xⁿ + 1 mod q in Linearfaktoren zerfällt: q ≡ 1 mod 2n
# gilt bis n = 2048 (12288 = 6·2048). Tests decken 1 … 1024 ab.
ALL_DEGREES = pytest.mark.parametrize("n", [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024])
DEGREES = pytest.mark.parametrize("n", [1, 2, 4, 64, 512, 1024])
SMALL_DEGREES = pytest.mark.parametrize("n", [1, 2, 4, 8, 64])

# Längen, für die xⁿ + 1 keine n Wurzeln in ℤ_q hat bzw. die keine Zweierpotenz sind
INVALID_LENGTHS = pytest.mark.parametrize("n", [0, 3, 6, 12, 4096])


# ---------------------------------------------------------------------------
# Hilfen selbst prüfen (sonst sind die Tests nichts wert)
# ---------------------------------------------------------------------------

class TestHelpers:
    @ALL_DEGREES
    def test_phi_has_exactly_n_roots(self, n):
        assert len(roots_of_phi(n)) == n

    def test_known_root_n2(self):
        # 1479² = 2'187'441 = 178·12289 − 1 ≡ −1
        assert roots_of_phi(2) == {1479, Q - 1479}


# ---------------------------------------------------------------------------
# ntt
# ---------------------------------------------------------------------------

class TestNtt:
    """ntt – §3.5, §4.2.2: f ↦ (f(ω) mod q) für alle Wurzeln ω von xⁿ + 1."""

    # --- Beispiele ---------------------------------------------------------

    def test_example_n2(self):
        # Wurzeln ±1479: [3, 1] ↦ {3 + 1479, 3 − 1479} = {1482, 10813}
        assert sorted(ntt([3, 1])) == [1482, 10813]

    def test_n_equals_1(self):
        # x + 1 hat die Wurzel −1; f = a₀ ist konstant
        assert ntt([5]) == [5]

    @DEGREES
    def test_constant_is_not_scaled(self, n):
        # §3.5: keine Skalierung (z. B. kein Faktor 1/n)
        assert ntt([7] + [0] * (n - 1)) == [7] * n

    @DEGREES
    def test_zero(self, n):
        assert ntt([0] * n) == [0] * n

    # --- Wurzeln -------------------------------------------------------------

    @pytest.mark.parametrize("n", [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024])
    def test_ntt_of_x_is_permutation_of_all_roots(self, n):
        # n ≥ 2: für n = 1 gibt es kein Monom x
        # ntt(x) = (ω_k)_k: jede Wurzel genau einmal
        w = ntt(monomial(1, n))
        assert len(w) == n
        assert set(w) == roots_of_phi(n)

    @pytest.mark.parametrize("n", [2, 4, 64, 512, 1024])
    def test_evaluates_at_roots_in_consistent_order(self, rng, n):
        # Reihenfolge frei, aber für alle Polynome dieselbe (§3.5)
        w = ntt(monomial(1, n))
        for _ in range(3):
            f = rand_poly(rng, n)
            assert ntt(f) == [evaluate(f, wk) for wk in w]

    @SMALL_DEGREES
    def test_multiset_equals_evaluations(self, rng, n):
        # Unabhängig von der Reihenfolge: gleiche Werte wie direkte Auswertung
        f = rand_poly(rng, n)
        assert sorted(ntt(f)) == sorted(evaluate(f, w) for w in roots_of_phi(n))

    # --- Ein-/Ausgabeformat -----------------------------------------------------

    @DEGREES
    def test_output_in_range(self, rng, n):
        out = ntt(rand_poly(rng, n))
        assert len(out) == n and in_range(out)

    @DEGREES
    def test_reduces_negative_and_large_inputs(self, rng, n):
        # f, g sind vorzeichenbehaftet und klein; Eingaben mod q gleichwertig
        f = rand_poly(rng, n, lo=-5 * Q, hi=5 * Q)
        assert ntt(f) == ntt(mod_q(f))

    # --- Ring-Isomorphismus -----------------------------------------------------

    @DEGREES
    def test_linear(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        lhs = ntt([x + y for x, y in zip(a, b)])
        rhs = [(x + y) % Q for x, y in zip(ntt(a), ntt(b))]
        assert lhs == rhs

    @SMALL_DEGREES
    def test_multiplication_becomes_pointwise(self, rng, n):
        # §3.5: Multiplikation mod ϕ und q ist in NTT-Form punktweise
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        lhs = ntt(mod_q(poly_mul(a, b)))
        rhs = [(x * y) % Q for x, y in zip(ntt(a), ntt(b))]
        assert lhs == rhs

    # --- Ungültige Eingaben -------------------------------------------------------

    @INVALID_LENGTHS
    def test_rejects_length_without_roots(self, n):
        # n keine Zweierpotenz, oder 4096 (q ≢ 1 mod 8192: xⁿ + 1 zerfällt nicht)
        with pytest.raises(ValueError):
            ntt([1] * n)

    def test_does_not_mutate_input(self, rng):
        f = rand_poly(rng, 8)
        f0 = copy.copy(f)
        ntt(f)
        assert f == f0


# ---------------------------------------------------------------------------
# intt
# ---------------------------------------------------------------------------

class TestIntt:
    """intt – §3.5: Umkehrung von ntt."""

    def test_example_n2(self):
        # Umkehrung von test_example_n2 in TestNtt, Reihenfolge aus ntt übernehmen
        assert intt(ntt([3, 1])) == [3, 1]

    def test_n_equals_1(self):
        assert intt([5]) == [5]

    @DEGREES
    def test_constant_values_give_constant_polynomial(self, n):
        # Alle Werte gleich c ⇔ f = c (Gegenstück zur fehlenden Skalierung)
        assert intt([7] * n) == [7] + [0] * (n - 1)

    @DEGREES
    def test_inverts_ntt(self, rng, n):
        f = rand_poly(rng, n)
        assert intt(ntt(f)) == f

    @DEGREES
    def test_ntt_inverts_intt(self, rng, n):
        v = rand_poly(rng, n)
        assert ntt(intt(v)) == v

    @DEGREES
    def test_roundtrip_reduces_signed_input(self, rng, n):
        f = rand_poly(rng, n, lo=-200, hi=200)
        assert intt(ntt(f)) == mod_q(f)

    @DEGREES
    def test_output_in_range(self, rng, n):
        out = intt(rand_poly(rng, n))
        assert len(out) == n and in_range(out)

    @DEGREES
    def test_reduces_negative_and_large_inputs(self, rng, n):
        v = rand_poly(rng, n, lo=-5 * Q, hi=5 * Q)
        assert intt(v) == intt(mod_q(v))

    @INVALID_LENGTHS
    def test_rejects_length_without_roots(self, n):
        with pytest.raises(ValueError):
            intt([1] * n)

    def test_does_not_mutate_input(self, rng):
        v = rand_poly(rng, 8)
        v0 = copy.copy(v)
        intt(v)
        assert v == v0


# ---------------------------------------------------------------------------
# mul_mod_q
# ---------------------------------------------------------------------------

class TestMulModQ:
    """mul_mod_q – §4.2.2: a·b mod (xⁿ + 1, q), Ein-/Ausgabe in Koeffizientenform."""

    def test_example_n4(self):
        # Gleiches Beispiel wie poly_mul: [−56, −36, 2, 60], hier mod q
        assert mul_mod_q([1, 2, 3, 4], [5, 6, 7, 8]) == [Q - 56, Q - 36, 2, 60]

    def test_n_equals_1(self):
        assert mul_mod_q([6], [Q - 7]) == [Q - 42]

    def test_wraparound_mod_q(self):
        # 6145·2 = 12290 ≡ 1
        assert mul_mod_q([6145, 0], [2, 0]) == [1, 0]

    @pytest.mark.parametrize("n", [2, 4, 512, 1024])
    def test_x_to_the_n_is_minus_one(self, n):
        assert mul_mod_q(monomial(n - 1, n), monomial(1, n)) == monomial(0, n, Q - 1)

    @SMALL_DEGREES
    def test_matches_poly_mul_mod_q(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert mul_mod_q(a, b) == mod_q(poly_mul(a, b))

    @DEGREES
    def test_one_is_neutral(self, rng, n):
        a = rand_poly(rng, n)
        assert mul_mod_q(a, one(n)) == a

    @DEGREES
    def test_commutative(self, rng, n):
        a, b = rand_poly(rng, n), rand_poly(rng, n)
        assert mul_mod_q(a, b) == mul_mod_q(b, a)

    @DEGREES
    def test_associative(self, rng, n):
        a, b, c = (rand_poly(rng, n) for _ in range(3))
        assert mul_mod_q(mul_mod_q(a, b), c) == mul_mod_q(a, mul_mod_q(b, c))

    @DEGREES
    def test_output_in_range(self, rng, n):
        out = mul_mod_q(rand_poly(rng, n), rand_poly(rng, n))
        assert len(out) == n and in_range(out)

    @DEGREES
    def test_accepts_signed_inputs(self, rng, n):
        # Typischer Fall: kurze f, g mit negativen Koeffizienten
        a = rand_poly(rng, n, lo=-30, hi=30)
        b = rand_poly(rng, n, lo=-30, hi=30)
        assert mul_mod_q(a, b) == mul_mod_q(mod_q(a), mod_q(b))

    @pytest.mark.parametrize("a, b", [([1, 2], [1, 2, 3, 4]), ([1, 2, 3, 4], [1])])
    def test_rejects_mismatched_lengths(self, a, b):
        with pytest.raises(ValueError):
            mul_mod_q(a, b)

    @INVALID_LENGTHS
    def test_rejects_length_without_roots(self, n):
        with pytest.raises(ValueError):
            mul_mod_q([1] * n, [1] * n)

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_poly(rng, 8), rand_poly(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        mul_mod_q(a, b)
        assert (a, b) == (a0, b0)


# ---------------------------------------------------------------------------
# div_mod_q
# ---------------------------------------------------------------------------

class TestDivModQ:
    """div_mod_q – §3.4.3, §4.2.2: a·b⁻¹ mod (xⁿ + 1, q), Koeffizientenform."""

    def test_inverse_of_two(self):
        # 2⁻¹ = (q + 1)/2 = 6145
        assert div_mod_q([1, 0, 0, 0], [2, 0, 0, 0]) == [6145, 0, 0, 0]

    @pytest.mark.parametrize("n", [2, 4, 512, 1024])
    def test_inverse_of_x(self, n):
        # x · (−x^(n−1)) = −xⁿ = 1  ⇒  x⁻¹ = −x^(n−1)
        assert div_mod_q(one(n), monomial(1, n)) == monomial(n - 1, n, Q - 1)

    def test_n_equals_1(self):
        assert div_mod_q([1], [2]) == [6145]

    @DEGREES
    def test_divide_by_one(self, rng, n):
        a = rand_poly(rng, n)
        assert div_mod_q(a, one(n)) == a

    @DEGREES
    def test_divide_by_self(self, rng, n):
        b = rand_invertible(rng, n)
        assert div_mod_q(b, b) == one(n)

    @DEGREES
    def test_quotient_times_divisor(self, rng, n):
        # h = a/b  ⇒  h·b = a  (so wird h = g/f in Alg. 4 Z. 9 berechnet)
        a, b = rand_poly(rng, n), rand_invertible(rng, n)
        assert mul_mod_q(div_mod_q(a, b), b) == a

    @DEGREES
    def test_undoes_multiplication(self, rng, n):
        a, b = rand_poly(rng, n), rand_invertible(rng, n)
        assert div_mod_q(mul_mod_q(a, b), b) == a

    @DEGREES
    def test_output_in_range(self, rng, n):
        out = div_mod_q(rand_poly(rng, n), rand_invertible(rng, n))
        assert len(out) == n and in_range(out)

    @DEGREES
    def test_accepts_signed_inputs(self, rng, n):
        a = rand_poly(rng, n, lo=-30, hi=30)
        b = rand_invertible(rng, n)
        b_signed = [c - Q if c > Q // 2 else c for c in b]
        assert div_mod_q(a, b_signed) == div_mod_q(mod_q(a), b)

    # --- Nicht invertierbar ----------------------------------------------------

    @DEGREES
    def test_rejects_zero_divisor(self, n):
        with pytest.raises(ValueError):
            div_mod_q(one(n), [0] * n)

    @pytest.mark.parametrize("n", [2, 4, 512, 1024])
    def test_rejects_divisor_vanishing_at_one_root(self, n):
        # b = x − ω hat genau eine Nullstelle unter den Wurzeln → nicht invertierbar
        w = min(roots_of_phi(n))
        b = [(-w) % Q, 1] + [0] * (n - 2)
        with pytest.raises(ValueError):
            div_mod_q(one(n), b)

    def test_rejects_multiple_of_q(self):
        # q·x ≡ 0 mod q
        with pytest.raises(ValueError):
            div_mod_q(one(4), [0, Q, 0, 0])

    @pytest.mark.parametrize("a, b", [([1, 2], [1, 2, 3, 4]), ([1, 2, 3, 4], [1])])
    def test_rejects_mismatched_lengths(self, a, b):
        with pytest.raises(ValueError):
            div_mod_q(a, b)

    def test_does_not_mutate_inputs(self, rng):
        a, b = rand_poly(rng, 8), rand_invertible(rng, 8)
        a0, b0 = copy.copy(a), copy.copy(b)
        div_mod_q(a, b)
        assert (a, b) == (a0, b0)


# ---------------------------------------------------------------------------
# is_invertible_mod_q
# ---------------------------------------------------------------------------

class TestIsInvertibleModQ:
    """is_invertible_mod_q – Alg. 5, Z. 7; §3.8.2: invertierbar ⇔ NTT(f) ohne 0."""

    @DEGREES
    def test_one_is_invertible(self, n):
        assert is_invertible_mod_q(one(n)) is True

    @DEGREES
    def test_zero_is_not_invertible(self, n):
        assert is_invertible_mod_q([0] * n) is False

    @pytest.mark.parametrize("n", [2, 4, 512, 1024])
    def test_x_is_invertible(self, n):
        assert is_invertible_mod_q(monomial(1, n)) is True

    @pytest.mark.parametrize("n", [2, 4, 512, 1024])
    def test_vanishing_at_single_root_is_not_invertible(self, n):
        # Nur ein einziger NTT-Wert ist 0 – darf nicht übersehen werden
        w = min(roots_of_phi(n))
        f = [(-w) % Q, 1] + [0] * (n - 2)
        assert is_invertible_mod_q(f) is False

    @pytest.mark.parametrize("n", [2, 4, 512, 1024])
    def test_signed_vanishing_polynomial(self, n):
        # Gleiches f, aber mit negativem Koeffizienten statt q − ω
        w = min(roots_of_phi(n))
        f = [-w, 1] + [0] * (n - 2)
        assert is_invertible_mod_q(f) is False

    def test_multiple_of_q_is_not_invertible(self):
        assert is_invertible_mod_q([Q, 2 * Q, -Q, 0]) is False

    def test_constant_multiple_of_q_plus_one(self):
        assert is_invertible_mod_q([Q + 1, 0, 0, 0]) is True

    @SMALL_DEGREES
    def test_agrees_with_direct_evaluation(self, rng, n):
        # Zufällige Polynome, Erwartung direkt aus den Wurzeln
        for _ in range(5):
            f = rand_poly(rng, n)
            expected = all(evaluate(f, w) for w in roots_of_phi(n))
            assert is_invertible_mod_q(f) is expected

    @pytest.mark.parametrize("n", [512, 1024])
    def test_short_signed_polynomials(self, rng, n):
        # Typische f aus keygen: kleine Koeffizienten mit Vorzeichen
        for _ in range(3):
            f = rand_poly(rng, n, lo=-6, hi=6)
            expected = all(evaluate(f, w) for w in roots_of_phi(n))
            assert is_invertible_mod_q(f) is expected

    @DEGREES
    def test_consistent_with_div_mod_q(self, rng, n):
        # invertierbar ⇔ div_mod_q wirft keinen Fehler
        f = rand_invertible(rng, n)
        assert is_invertible_mod_q(f) is True
        div_mod_q(one(n), f)

    @INVALID_LENGTHS
    def test_rejects_length_without_roots(self, n):
        with pytest.raises(ValueError):
            is_invertible_mod_q([1] * n)

    def test_does_not_mutate_input(self, rng):
        f = rand_poly(rng, 8)
        f0 = copy.copy(f)
        is_invertible_mod_q(f)
        assert f == f0


# ---------------------------------------------------------------------------
# center_mod_q
# ---------------------------------------------------------------------------

class TestCenterModQ:
    """center_mod_q – Alg. 16, Z. 5: auf ⌈−q/2⌉ … ⌊q/2⌋ = −6144 … 6144 abbilden."""

    @pytest.mark.parametrize(
        "x, expected",
        [
            (0, 0),
            (1, 1),
            (6144, 6144),        # ⌊q/2⌋: obere Grenze, bleibt
            (6145, -6144),       # erster Wert über ⌊q/2⌋ kippt auf ⌈−q/2⌉
            (12288, -1),         # q − 1
            (Q, 0),
            (-1, -1),            # bereits zentriert
            (-6144, -6144),      # untere Grenze, bleibt
            (-6145, 6144),       # knapp darunter → kippt nach oben
            (3 * Q + 5, 5),
            (-3 * Q - 5, -5),
            (2 ** 100, (2 ** 100) % Q if (2 ** 100) % Q <= 6144 else (2 ** 100) % Q - Q),
        ],
    )
    def test_single_values(self, x, expected):
        assert center_mod_q([x]) == [expected]

    def test_range_is_symmetric(self):
        # q ungerade ⇒ ⌈−q/2⌉ = −6144 und ⌊q/2⌋ = 6144
        out = center_mod_q(list(range(Q)))
        assert min(out) == -6144 and max(out) == 6144

    def test_bijective_on_residues(self):
        # Jede Restklasse genau einmal getroffen
        out = center_mod_q(list(range(Q)))
        assert sorted(out) == list(range(-6144, 6145))

    def test_congruent_and_in_range(self, rng):
        xs = [rng.randint(-10 ** 9, 10 ** 9) for _ in range(1000)]
        out = center_mod_q(xs)
        assert all(type(y) is int for y in out)
        assert all(-6144 <= y <= 6144 for y in out)
        assert all((x - y) % Q == 0 for x, y in zip(xs, out))

    def test_idempotent(self, rng):
        xs = [rng.randint(0, Q - 1) for _ in range(100)]
        once = center_mod_q(xs)
        assert center_mod_q(once) == once

    def test_preserves_length_and_order(self):
        assert center_mod_q([1, 12288, 6145, 0]) == [1, -1, -6144, 0]

    def test_empty(self):
        assert center_mod_q([]) == []

    def test_does_not_mutate_input(self):
        xs = [12288, 1, 6145]
        center_mod_q(xs)
        assert xs == [12288, 1, 6145]
