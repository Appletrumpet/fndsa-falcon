"""Tests für tree.py – geheime Basis und Falcon-Baum.

Spec-Referenz: §3.4.2 (Falcon-Baum, Gl. 3.16), §3.8.3, Alg. 4 (Z. 2–7),
Alg. 8 (LDL⋆), Alg. 9 (ffLDL⋆), Gl. 3.30. Doku: Falcon_Documentation §6.11.

Datenform (Scaffold / Doku):
  - basis_fft = ((ĝ, −f̂), (Ĝ, −F̂))            (Gl. 3.16)
  - Gram-Matrix G = B̂·B̂⋆, 2×2 in FFT-Form       (Alg. 4 Z. 4)
  - ldl(G) → (L10, D00, D11)                     (Alg. 8)
  - Baum: Knoten = (ℓ, links, rechts), Blatt = Zahl (§3.4.2)
  - Normalisierung: Blatt ↦ σ / √Blatt          (Alg. 4 Z. 6–7)

Testdaten: data/sampler/test-vector-sampler-falcon{512,1024}.txt enthält einen
echten Schlüssel (f, g, F, G) und für jeden SamplerZ-Aufruf das verwendete σ′.
Nach Alg. 11 liefert jedes Blatt des normalisierten Baums σ′ für zwei
aufeinanderfolgende SamplerZ-Aufrufe, rechter Teilbaum zuerst. Die Folge der
σ′ in der Datei ist damit ein Vektor für die ganze Kette
build_basis_fft → gram_matrix → ff_ldl → normalize_leaves.

Invarianten (vorab mit Wegwerf-Orakel bestätigt):
  - Produkt aller Blätter (vor Normalisierung) = Π_k |det B̂(ζ_k)|;
    für NTRU-Basen (fG − gF = q) also qⁿ.
  - Normalisierte Blätter liegen in [σmin, σmax] (Alg. 11 Z. 2).
"""

import cmath
import copy
import math
import random

import pytest
from falcon.fft import fft, split_fft
from falcon.params import FALCON_512, FALCON_1024
from falcon.tree import (
    build_basis_fft, build_falcon_tree, gram_matrix,
    ldl, ff_ldl, normalize_leaves,
)
from support import load_sampler_vectors

Q = 12289
PARAMS_BY_N = {512: FALCON_512, 1024: FALCON_1024}
KEY_SETS = pytest.mark.parametrize("n", [512, 1024], ids=["falcon512", "falcon1024"])
SMALL = pytest.mark.parametrize("n", [2, 4, 8, 16, 64])


# ---------------------------------------------------------------------------
# Hilfen (unabhängig von der Implementierung, ausser fft/split_fft)
# ---------------------------------------------------------------------------

def adj(a):
    return [x.conjugate() for x in a]


def pmul(a, b):
    return [x * y for x, y in zip(a, b)]


def padd(a, b):
    return [x + y for x, y in zip(a, b)]


def neg(a):
    return [-x for x in a]


def assert_close(actual, expected, rel=1e-9):
    actual, expected = list(actual), list(expected)
    assert len(actual) == len(expected)
    scale = max([abs(x) for x in expected] + [1.0])
    worst = max((abs(a - e) for a, e in zip(actual, expected)), default=0.0)
    assert worst <= rel * scale, f"max. Abweichung {worst} > {rel * scale}"


def negacyclic_mul(a, b):
    """Schulbuch-Multiplikation in ℤ[x]/(xⁿ+1), nur für Datenprüfungen."""
    n = len(a)
    c = [0] * n
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if i + j < n:
                    c[i + j] += ai * bj
                else:
                    c[i + j - n] -= ai * bj
    return c


def rand_key(rng, n, bound=5):
    """Zufällige (nicht NTRU-) Basis mit kleinen Koeffizienten; fast sicher vollen Rang."""
    return tuple([rng.randint(-bound, bound) for _ in range(n)] for _ in range(4))


def real_key(n):
    v = load_sampler_vectors(n)
    return v.f, v.g, v.F, v.G


def is_leaf(t):
    return isinstance(t, (int, float)) and not isinstance(t, bool)


def leaves_in_order(t):
    """Blätter von links nach rechts."""
    if is_leaf(t):
        return [t]
    return leaves_in_order(t[1]) + leaves_in_order(t[2])


def leaves_sampling_order(t):
    """Blätter in der Reihenfolge, in der ffSampling sie nutzt (rechts zuerst, Alg. 11)."""
    if is_leaf(t):
        return [t]
    return leaves_sampling_order(t[2]) + leaves_sampling_order(t[1])


def internal_nodes(t, depth=0):
    if is_leaf(t):
        return []
    return [(t, depth)] + internal_nodes(t[1], depth + 1) + internal_nodes(t[2], depth + 1)


def det_B(B):
    (b00, b01), (b10, b11) = B
    return [x * w - y * z for x, y, z, w in zip(b00, b01, b10, b11)]


def expected_gram(B):
    (b00, b01), (b10, b11) = B
    return (
        (padd(pmul(b00, adj(b00)), pmul(b01, adj(b01))),
         padd(pmul(b00, adj(b10)), pmul(b01, adj(b11)))),
        (padd(pmul(b10, adj(b00)), pmul(b11, adj(b01))),
         padd(pmul(b10, adj(b10)), pmul(b11, adj(b11)))),
    )


@pytest.fixture
def rng():
    return random.Random(0x7EE)


# ---------------------------------------------------------------------------
# Testdaten selbst prüfen
# ---------------------------------------------------------------------------

class TestData:
    @KEY_SETS
    def test_vector_key_satisfies_ntru_equation(self, n):
        # Gl. 3.15: fG − gF = q mod ϕ
        f, g, F, G = real_key(n)
        lhs = [a - b for a, b in zip(negacyclic_mul(f, G), negacyclic_mul(g, F))]
        assert lhs == [Q] + [0] * (n - 1)

    @KEY_SETS
    def test_vector_sigmas_come_in_pairs(self, n):
        # Alg. 11 Z. 3–4: z0 und z1 mit demselben σ′
        sig = [t.sigma for t in load_sampler_vectors(n).samplerz]
        assert len(sig) == 2 * n
        assert all(sig[2 * i] == sig[2 * i + 1] for i in range(n))


# ---------------------------------------------------------------------------
# build_basis_fft
# ---------------------------------------------------------------------------

class TestBuildBasisFft:
    """build_basis_fft – Alg. 4 Z. 2–3, Gl. 3.16: ((ĝ, −f̂), (Ĝ, −F̂))."""

    @SMALL
    def test_layout(self, rng, n):
        f, g, F, G = rand_key(rng, n)
        B = build_basis_fft(f, g, F, G)
        assert_close(B[0][0], fft(g))
        assert_close(B[0][1], fft(neg(f)))
        assert_close(B[1][0], fft(G))
        assert_close(B[1][1], fft(neg(F)))

    def test_example_n2(self):
        # f = 1, g = x, F = 0, G = 1 → ĝ = (i, −i), −f̂ = (−1, −1), Ĝ = (1, 1), −F̂ = 0
        B = build_basis_fft([1, 0], [0, 1], [0, 0], [1, 0])
        assert_close(B[0][0], [1j, -1j])
        assert_close(B[0][1], [-1, -1])
        assert_close(B[1][0], [1, 1])
        assert_close(B[1][1], [0, 0])

    @KEY_SETS
    def test_determinant_is_q(self, n):
        # det B = g·(−F) − (−f)·G = fG − gF = q an jeder Wurzel
        B = build_basis_fft(*real_key(n))
        assert_close(det_B(B), [Q] * n)

    @SMALL
    def test_shape(self, rng, n):
        B = build_basis_fft(*rand_key(rng, n))
        assert len(B) == 2 and all(len(row) == 2 for row in B)
        assert all(len(B[i][j]) == n for i in range(2) for j in range(2))

    def test_does_not_mutate_inputs(self, rng):
        key = rand_key(rng, 8)
        before = copy.deepcopy(key)
        build_basis_fft(*key)
        assert key == before


# ---------------------------------------------------------------------------
# gram_matrix
# ---------------------------------------------------------------------------

class TestGramMatrix:
    """gram_matrix – Alg. 4 Z. 4: G = B̂ × B̂⋆ (B̂⋆ = komponentenweise adjungiert,
    transponiert, Gl. 3.7)."""

    def test_example_scalar(self):
        # Ein Punkt (n = 1): B = [[1+i, 2], [3, −i]]
        #   G00 = |1+i|² + 4 = 6,  G01 = (1+i)·3 + 2·i = 3 + 5i,
        #   G10 = conj(G01) = 3 − 5i,  G11 = 9 + 1 = 10
        G = gram_matrix((([1 + 1j], [2 + 0j]), ([3 + 0j], [-1j])))
        assert_close(G[0][0], [6])
        assert_close(G[0][1], [3 + 5j])
        assert_close(G[1][0], [3 - 5j])
        assert_close(G[1][1], [10])

    @SMALL
    def test_matches_definition(self, rng, n):
        B = build_basis_fft(*rand_key(rng, n))
        G = gram_matrix(B)
        E = expected_gram(B)
        for i in range(2):
            for j in range(2):
                assert_close(G[i][j], E[i][j])

    @SMALL
    def test_self_adjoint(self, rng, n):
        # G⋆ = G: Diagonale reell, G10 = conj(G01)
        G = gram_matrix(build_basis_fft(*rand_key(rng, n)))
        assert all(abs(x.imag) <= 1e-9 * max(1.0, abs(x)) for x in G[0][0] + G[1][1])
        assert_close(G[1][0], adj(G[0][1]))

    @SMALL
    def test_positive_diagonal(self, rng, n):
        G = gram_matrix(build_basis_fft(*rand_key(rng, n)))
        assert all(x.real > 0 for x in G[0][0] + G[1][1])

    @KEY_SETS
    def test_determinant_is_q_squared(self, n):
        # det G = |det B|² = q²
        G = gram_matrix(build_basis_fft(*real_key(n)))
        det = [a * d - b * c for a, b, c, d in zip(G[0][0], G[0][1], G[1][0], G[1][1])]
        assert_close(det, [Q * Q] * n)

    def test_does_not_mutate_input(self, rng):
        B = build_basis_fft(*rand_key(rng, 8))
        before = copy.deepcopy(B)
        gram_matrix(B)
        assert B == before


# ---------------------------------------------------------------------------
# ldl
# ---------------------------------------------------------------------------

class TestLdl:
    """ldl – Alg. 8: D00 = G00, L10 = G10/G00, D11 = G11 − L10·L10⋆·G00."""

    def test_example_scalar(self):
        # G = [[4, 2−2i], [2+2i, 6]]: L10 = (2+2i)/4 = 0.5+0.5i,
        # D11 = 6 − |0.5+0.5i|²·4 = 6 − 0.5·4 = 4
        L10, D00, D11 = ldl((([4 + 0j], [2 - 2j]), ([2 + 2j], [6 + 0j])))
        assert_close(L10, [0.5 + 0.5j])
        assert_close(D00, [4])
        assert_close(D11, [4])

    def test_example_diagonal(self):
        # Bereits diagonal: L10 = 0, D = G
        L10, D00, D11 = ldl((([3 + 0j, 5 + 0j], [0j, 0j]), ([0j, 0j], [7 + 0j, 2 + 0j])))
        assert_close(L10, [0, 0])
        assert_close(D00, [3, 5])
        assert_close(D11, [7, 2])

    @SMALL
    def test_reconstructs_G(self, rng, n):
        # G = L·D·L⋆ mit L = [[1, 0], [L10, 1]], D = diag(D00, D11)
        G = gram_matrix(build_basis_fft(*rand_key(rng, n)))
        L10, D00, D11 = ldl(G)
        assert_close(D00, G[0][0])
        assert_close(pmul(D00, adj(L10)), G[0][1])
        assert_close(pmul(L10, D00), G[1][0])
        assert_close(padd(pmul(pmul(L10, D00), adj(L10)), D11), G[1][1])

    @SMALL
    def test_diagonal_real_and_positive(self, rng, n):
        L10, D00, D11 = ldl(gram_matrix(build_basis_fft(*rand_key(rng, n))))
        for d in (D00, D11):
            assert all(abs(x.imag) <= 1e-9 * max(1.0, abs(x)) and x.real > 0 for x in d)

    @KEY_SETS
    def test_det_equals_D00_times_D11(self, n):
        # det G = D00·D11 = q² für NTRU-Basen
        L10, D00, D11 = ldl(gram_matrix(build_basis_fft(*real_key(n))))
        assert_close(pmul(D00, D11), [Q * Q] * n)

    def test_does_not_mutate_input(self, rng):
        G = gram_matrix(build_basis_fft(*rand_key(rng, 8)))
        before = copy.deepcopy(G)
        ldl(G)
        assert G == before


# ---------------------------------------------------------------------------
# ff_ldl
# ---------------------------------------------------------------------------

class TestFfLdl:
    """ff_ldl – Alg. 9: rekursive LDL⋆-Zerlegung, Knoten (ℓ, links, rechts)."""

    # --- Struktur ---------------------------------------------------------------

    @SMALL
    def test_structure(self, rng, n):
        # Höhe log₂ n, n Blätter, Knoten auf Tiefe d haben ℓ der Länge n/2^d (§3.4.2)
        T = ff_ldl(gram_matrix(build_basis_fft(*rand_key(rng, n))))
        assert len(leaves_in_order(T)) == n
        for node, depth in internal_nodes(T):
            assert len(node) == 3
            assert len(node[0]) == n >> depth
        assert max(d for _, d in internal_nodes(T)) == int(math.log2(n)) - 1

    @SMALL
    def test_leaves_are_positive_reals(self, rng, n):
        T = ff_ldl(gram_matrix(build_basis_fft(*rand_key(rng, n))))
        assert all(is_leaf(x) and x > 0 for x in leaves_in_order(T))

    # --- Inhalt -----------------------------------------------------------------

    @SMALL
    def test_root_value_is_L10(self, rng, n):
        G = gram_matrix(build_basis_fft(*rand_key(rng, n)))
        assert_close(ff_ldl(G)[0], ldl(G)[0])

    def test_base_case_n2(self, rng):
        # Alg. 9 Z. 3–6: bei n = 2 sind die Kinder D00 und D11. Diese sind selbst-
        # adjungiert in ℚ[x]/(x²+1), also konstant: beide FFT-Werte gleich und reell.
        G = gram_matrix(build_basis_fft(*rand_key(rng, 2)))
        L10, D00, D11 = ldl(G)
        assert D00[0] == pytest.approx(D00[1]) and D11[0] == pytest.approx(D11[1])
        T = ff_ldl(G)
        assert_close(T[0], L10)
        assert T[1] == pytest.approx(D00[0].real)
        assert T[2] == pytest.approx(D11[0].real)

    @pytest.mark.parametrize("n", [4, 8, 64])
    def test_recursion_on_split_diagonal(self, rng, n):
        # Alg. 9 Z. 8–12: Kinder = ffLDL von [[d0, d1], [d1⋆, d0]] mit (d0, d1) = splitfft(D)
        G = gram_matrix(build_basis_fft(*rand_key(rng, n)))
        _, D00, D11 = ldl(G)
        T = ff_ldl(G)
        for D, child in ((D00, T[1]), (D11, T[2])):
            d0, d1 = split_fft(D)
            sub = ff_ldl(((d0, d1), (adj(d1), d0)))
            assert_close(leaves_in_order(child), leaves_in_order(sub))
            assert_close(child[0], sub[0])

    @SMALL
    def test_leaf_product_equals_abs_det(self, rng, n):
        # Π Blätter = Π_k |det B̂(ζ_k)| (Determinante multipliziert sich durch die Zerlegung)
        B = build_basis_fft(*rand_key(rng, n))
        T = ff_ldl(gram_matrix(B))
        lhs = sum(math.log(x) for x in leaves_in_order(T))
        rhs = sum(math.log(abs(d)) for d in det_B(B))
        assert lhs == pytest.approx(rhs, rel=1e-9)

    @KEY_SETS
    def test_leaf_product_is_q_to_the_n(self, n):
        T = ff_ldl(gram_matrix(build_basis_fft(*real_key(n))))
        log_prod = sum(math.log(x) for x in leaves_in_order(T))
        assert log_prod == pytest.approx(n * math.log(Q), rel=1e-12)

    def test_does_not_mutate_input(self, rng):
        G = gram_matrix(build_basis_fft(*rand_key(rng, 8)))
        before = copy.deepcopy(G)
        ff_ldl(G)
        assert G == before


# ---------------------------------------------------------------------------
# normalize_leaves
# ---------------------------------------------------------------------------

class TestNormalizeLeaves:
    """normalize_leaves – Alg. 4 Z. 6–7: Blatt ↦ σ / √Blatt."""

    def test_example(self):
        # σ = 6: 4 ↦ 3, 9 ↦ 2; ℓ bleibt unverändert
        ell = [0.5 + 0.5j, 0.5 - 0.5j]
        T = normalize_leaves((ell, 4.0, 9.0), 6.0)
        assert_close(T[0], ell)
        assert T[1] == pytest.approx(3.0) and T[2] == pytest.approx(2.0)

    def test_example_nested(self):
        inner_l, inner_r = ([1j, -1j], 1.0, 4.0), ([2j, -2j], 16.0, 25.0)
        T = normalize_leaves(([0.1j] * 4, inner_l, inner_r), 20.0)
        assert leaves_in_order(T) == pytest.approx([20.0, 10.0, 5.0, 4.0])
        assert_close(T[1][0], [1j, -1j])
        assert_close(T[2][0], [2j, -2j])

    @SMALL
    def test_preserves_structure_and_values(self, rng, n):
        T = ff_ldl(gram_matrix(build_basis_fft(*rand_key(rng, n))))
        N = normalize_leaves(T, 165.0)
        for (a, da), (b, db) in zip(internal_nodes(T), internal_nodes(N)):
            assert da == db
            assert_close(b[0], a[0])
        assert leaves_in_order(N) == pytest.approx(
            [165.0 / math.sqrt(x) for x in leaves_in_order(T)]
        )

    def test_does_not_mutate_input(self):
        T = ([0.5j, -0.5j], 4.0, 9.0)
        before = copy.deepcopy(T)
        normalize_leaves(T, 6.0)
        assert T == before


# ---------------------------------------------------------------------------
# build_falcon_tree
# ---------------------------------------------------------------------------

class TestBuildFalconTree:
    """build_falcon_tree – Alg. 4 Z. 4–7: gram_matrix → ff_ldl → normalize_leaves(σ)."""

    @KEY_SETS
    def test_matches_nist_sampler_sigmas(self, n):
        # Vektor für die ganze Kette: Blätter (rechts zuerst) = σ′ aus der Testvektor-Datei
        params = PARAMS_BY_N[n]
        T = build_falcon_tree(build_basis_fft(*real_key(n)), params)
        used = [t.sigma for t in load_sampler_vectors(n).samplerz][0::2]
        assert leaves_sampling_order(T) == pytest.approx(used, rel=1e-9)

    @KEY_SETS
    def test_leaves_within_sampler_bounds(self, n):
        # Alg. 11 Z. 2: σ′ ∈ [σmin, σmax]
        params = PARAMS_BY_N[n]
        T = build_falcon_tree(build_basis_fft(*real_key(n)), params)
        assert all(params.sigma_min <= x <= params.sigma_max for x in leaves_in_order(T))

    @pytest.mark.parametrize("n", [4, 16, 64])
    def test_is_composition(self, rng, n):
        B = build_basis_fft(*rand_key(rng, n))
        expected = normalize_leaves(ff_ldl(gram_matrix(B)), FALCON_512.sigma)
        T = build_falcon_tree(B, FALCON_512)
        assert leaves_in_order(T) == pytest.approx(leaves_in_order(expected))
        for (a, _), (b, _) in zip(internal_nodes(T), internal_nodes(expected)):
            assert_close(a[0], b[0])

    def test_uses_sigma_from_params(self, rng):
        B = build_basis_fft(*rand_key(rng, 8))
        a = leaves_in_order(build_falcon_tree(B, FALCON_512))
        b = leaves_in_order(build_falcon_tree(B, FALCON_1024))
        ratio = FALCON_1024.sigma / FALCON_512.sigma
        assert [y / x for x, y in zip(a, b)] == pytest.approx([ratio] * 8)
