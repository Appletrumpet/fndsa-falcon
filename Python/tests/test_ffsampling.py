"""Tests für ffsampling.py – Fast Fourier Sampling.

Spec-Referenz: §3.9.2, Alg. 11; Alg. 10 Z. 3 und Z. 7 (Ziel t, Vektor s).
Doku: Falcon_Documentation §6.12.

Alg. 11 (ffSampling_n(t, T)), alles in FFT-Form:
  n = 1:  σ′ = T.value; z0 = SamplerZ(t0, σ′); z1 = SamplerZ(t1, σ′)
  sonst:  (ℓ, T0, T1) = T
          z1 = mergefft(ffSampling(splitfft(t1), T1))       ← rechts zuerst
          t0′ = t0 + (t1 − z1)⊙ℓ
          z0 = mergefft(ffSampling(splitfft(t0′), T0))

Testdaten: data/sampler/test-vector-sampler-falcon{512,1024}.txt. Daraus ist
ein vollständiger End-to-End-Vektor ableitbar (vorab mit Wegwerf-Orakel
bestätigt): Schlüssel (f, g, F, G), c = „hashed message“, alle Zufallsbytes in
Reihenfolge, für jeden SamplerZ-Aufruf (μ, σ′), und s₂ = „signature vector“.
Mit t aus Alg. 10 Z. 3 und s = (t − z)·B̂ (Z. 7) ergibt sich genau s₂; alle
Bytes werden verbraucht.

Für die kleinen Beispiele wird SamplerZ im Test durch eine deterministische
Rundung ersetzt (⌊μ + ½⌋). Damit lässt sich die Baumlogik (Reihenfolge,
σ′ pro Blatt, Einfluss von ℓ) von Hand nachrechnen.
"""

import copy
import math

import pytest
import falcon.ffsampling as ffsampling_module
import falcon.sampler as sampler_module
from falcon.ffsampling import ff_sampling
from falcon.fft import fft, ifft
from falcon.params import FALCON_512, FALCON_1024
from falcon.tree import build_basis_fft, build_falcon_tree
from support import FixedRNG, load_sampler_vectors, nmul

Q = 12289
PARAMS_BY_N = {512: FALCON_512, 1024: FALCON_1024}
KEY_SETS = pytest.mark.parametrize("n", [512, 1024], ids=["falcon512", "falcon1024"])


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

def compute_t(c, f, F):
    """Alg. 10 Z. 3: t = (−FFT(c)⊙FFT(F)/q, FFT(c)⊙FFT(f)/q)."""
    c_hat, f_hat, F_hat = fft(c), fft(f), fft(F)
    return ([-x * y / Q for x, y in zip(c_hat, F_hat)],
            [x * y / Q for x, y in zip(c_hat, f_hat)])


def compute_s(t, z, B):
    """Alg. 10 Z. 7: s = (t − z)·B̂, Ergebnis in Koeffizientenform gerundet."""
    d0 = [a - b for a, b in zip(t[0], z[0])]
    d1 = [a - b for a, b in zip(t[1], z[1])]
    s0 = [x * b00 + y * b10 for x, y, b00, b10 in zip(d0, d1, B[0][0], B[1][0])]
    s1 = [x * b01 + y * b11 for x, y, b01, b11 in zip(d0, d1, B[0][1], B[1][1])]
    return [round(v) for v in ifft(s0)], [round(v) for v in ifft(s1)]


def to_int_poly(v_hat, tol=1e-6):
    """FFT-Vektor → ganzzahliges Polynom; prüft, dass er wirklich ganzzahlig ist."""
    coeffs = ifft(v_hat)
    rounded = [round(x) for x in coeffs]
    assert max(abs(x - r) for x, r in zip(coeffs, rounded)) < tol
    return rounded


def real_setup(n):
    v = load_sampler_vectors(n)
    params = PARAMS_BY_N[n]
    B = build_basis_fft(v.f, v.g, v.F, v.G)
    T = build_falcon_tree(B, params)
    t = compute_t(v.hashed_message, v.f, v.F)
    rb = b"".join(tr.random_bytes for tr in v.samplerz)
    return v, params, B, T, t, rb


def assert_close(actual, expected, tol=1e-9):
    assert len(actual) == len(expected)
    assert max((abs(a - e) for a, e in zip(actual, expected)), default=0.0) <= tol


@pytest.fixture
def fake_samplerz(monkeypatch):
    """Ersetzt SamplerZ durch ⌊μ + ½⌋ und protokolliert (μ, σ′).

    Ersetzt wird sowohl falcon.sampler.sample_integer_gaussian als auch ein
    eventuell in ffsampling importierter Name – beide Importstile funktionieren.
    """
    log = []

    def fake(mu, sigma_p, params, rng):
        log.append((mu, sigma_p))
        return math.floor(mu + 0.5)

    monkeypatch.setattr(sampler_module, "sample_integer_gaussian", fake)
    if hasattr(ffsampling_module, "sample_integer_gaussian"):
        monkeypatch.setattr(ffsampling_module, "sample_integer_gaussian", fake)
    return log


@pytest.fixture
def recording_samplerz(monkeypatch):
    """Echter SamplerZ, aber (μ, σ′) jedes Aufrufs wird protokolliert."""
    log = []
    real = sampler_module.sample_integer_gaussian

    def wrapper(mu, sigma_p, params, rng):
        log.append((mu, sigma_p))
        return real(mu, sigma_p, params, rng)

    monkeypatch.setattr(sampler_module, "sample_integer_gaussian", wrapper)
    if hasattr(ffsampling_module, "sample_integer_gaussian"):
        monkeypatch.setattr(ffsampling_module, "sample_integer_gaussian", wrapper)
    return log


class NoRandomness:
    """Für Tests mit ersetztem SamplerZ: es darf kein Zufall gelesen werden."""

    def random_bytes(self, k):
        raise AssertionError("ff_sampling darf selbst keinen Zufall lesen")


def leaves_sampling_order(t):
    if isinstance(t, (int, float)):
        return [t]
    return leaves_sampling_order(t[2]) + leaves_sampling_order(t[1])


# ---------------------------------------------------------------------------
# Testdaten selbst prüfen
# ---------------------------------------------------------------------------

class TestData:
    @KEY_SETS
    def test_one_ffsampling_call_per_file(self, n):
        # 2n SamplerZ-Aufrufe = genau ein Durchlauf (Signatur im ersten Versuch akzeptiert)
        assert len(load_sampler_vectors(n).samplerz) == 2 * n


# ---------------------------------------------------------------------------
# ff_sampling – Vektoren aus dem NIST-Paket
# ---------------------------------------------------------------------------

class TestFfSamplingNistVectors:
    """End-to-End mit echtem Schlüssel, echtem Zufall und echtem SamplerZ."""

    @KEY_SETS
    def test_reproduces_signature_vector(self, n):
        v, params, B, T, t, rb = real_setup(n)
        rng = FixedRNG(rb)
        z = ff_sampling(t, T, params, rng)
        _, s2 = compute_s(t, z, B)
        assert s2 == v.signature_vector
        assert rng.remaining == 0, "falsche Anzahl Zufallsbytes gelesen"

    @KEY_SETS
    def test_output_is_integral(self, n):
        _, params, _, T, t, rb = real_setup(n)
        z0, z1 = ff_sampling(t, T, params, FixedRNG(rb))
        assert len(z0) == len(z1) == n
        to_int_poly(z0)
        to_int_poly(z1)

    @KEY_SETS
    def test_samplerz_inputs_match_file(self, n, recording_samplerz):
        # Jeder Aufruf: (μ, σ′) wie in der Datei, in derselben Reihenfolge
        v, params, _, T, t, rb = real_setup(n)
        ff_sampling(t, T, params, FixedRNG(rb))
        assert len(recording_samplerz) == 2 * n
        for k, ((mu, sig), tr) in enumerate(zip(recording_samplerz, v.samplerz)):
            assert mu == pytest.approx(tr.mu, abs=1e-9), f"Aufruf {k}"
            assert sig == pytest.approx(tr.sigma, rel=1e-9), f"Aufruf {k}"

    @KEY_SETS
    def test_signature_is_short(self, n):
        # Alg. 10 Z. 8: ‖s‖² ≤ ⌊β²⌋ (für diesen Vektor im ersten Versuch)
        _, params, B, T, t, rb = real_setup(n)
        s1, s2 = compute_s(t, ff_sampling(t, T, params, FixedRNG(rb)), B)
        assert sum(x * x for x in s1 + s2) <= params.sig_bound

    @KEY_SETS
    def test_s1_plus_s2_h_equals_c(self, n):
        # Alg. 10 Z. 9: s₁ + s₂·h = c mod q ⇔ s₁·f + s₂·g = c·f mod q (h = g/f)
        v, params, B, T, t, rb = real_setup(n)
        s1, s2 = compute_s(t, ff_sampling(t, T, params, FixedRNG(rb)), B)
        lhs = [(x + y) % Q for x, y in zip(nmul(s1, v.f), nmul(s2, v.g))]
        rhs = [x % Q for x in nmul(v.hashed_message, v.f)]
        assert lhs == rhs

    def test_shift_by_integer_polynomial(self):
        # SamplerZ ist verschiebungsinvariant (gleiche Bytes, μ + k ↦ z + k);
        # daher ff_sampling(t + k̂) = ff_sampling(t) + k̂ für ganzzahliges k.
        _, params, _, T, t, rb = real_setup(512)
        k0 = [(i % 7) - 3 for i in range(512)]
        k1 = [(i % 5) - 2 for i in range(512)]
        t_shift = ([a + b for a, b in zip(t[0], fft(k0))], [a + b for a, b in zip(t[1], fft(k1))])
        z = ff_sampling(t, T, params, FixedRNG(rb))
        zs = ff_sampling(t_shift, T, params, FixedRNG(rb))
        assert to_int_poly(zs[0]) == [a + b for a, b in zip(to_int_poly(z[0]), k0)]
        assert to_int_poly(zs[1]) == [a + b for a, b in zip(to_int_poly(z[1]), k1)]

    def test_does_not_mutate_inputs(self):
        _, params, _, T, t, rb = real_setup(512)
        t_before, T_before = copy.deepcopy(t), copy.deepcopy(T)
        ff_sampling(t, T, params, FixedRNG(rb))
        assert t == t_before and T == T_before


# ---------------------------------------------------------------------------
# ff_sampling – Baumlogik mit ersetztem SamplerZ
# ---------------------------------------------------------------------------

class TestFfSamplingTreeLogic:
    """Alg. 11 mit SamplerZ = ⌊μ + ½⌋: Reihenfolge, σ′ je Blatt, Rolle von ℓ."""

    def test_base_case_n1(self, fake_samplerz):
        # n = 1: T ist ein Blatt σ′; zuerst t0, dann t1, beide mit demselben σ′
        z = ff_sampling(([2.3 + 0j], [-1.7 + 0j]), 1.5, FALCON_512, NoRandomness())
        assert_close(z[0], [2])
        assert_close(z[1], [-2])
        assert fake_samplerz == [(pytest.approx(2.3), 1.5), (pytest.approx(-1.7), 1.5)]

    def test_example_n2_order_and_ell(self, fake_samplerz):
        # T = (ℓ, σa, σb) mit ℓ = FFT(1) (konstant 1), σa = 1.3, σb = 1.7
        # t1 = FFT(0.5): splitfft → (0.5, 0)  → rechts zuerst, mit σb:
        #   SamplerZ(0.5) = ⌊1.0⌋ = 1,  SamplerZ(0) = 0  → z1 = 1 (konstant)
        # t0′ = t0 + (t1 − z1)·ℓ = (0.2 + 0.3x) + (−0.5) = −0.3 + 0.3x
        #   splitfft → (−0.3, 0.3), mit σa: ⌊0.2⌋ = 0, ⌊0.8⌋ = 0 → z0 = 0
        ell = fft([1, 0])
        T = (ell, 1.3, 1.7)
        t = (fft([0.2, 0.3]), fft([0.5, 0.0]))
        z0, z1 = ff_sampling(t, T, FALCON_512, NoRandomness())
        assert to_int_poly(z1) == [1, 0]
        assert to_int_poly(z0) == [0, 0]
        mus = [m for m, _ in fake_samplerz]
        sigmas = [s for _, s in fake_samplerz]
        assert mus == pytest.approx([0.5, 0.0, -0.3, 0.3])
        assert sigmas == [1.7, 1.7, 1.3, 1.3]

    def test_example_n2_ell_zero_ignores_t1(self, fake_samplerz):
        # Mit ℓ = 0 hängt z0 nicht vom Rundungsfehler in t1 ab: t0′ = t0
        T = (fft([0, 0]), 1.3, 1.7)
        t = (fft([0.2, 0.3]), fft([0.5, 0.0]))
        z0, _ = ff_sampling(t, T, FALCON_512, NoRandomness())
        assert to_int_poly(z0) == [0, 0]
        assert [m for m, _ in fake_samplerz][2:] == pytest.approx([0.2, 0.3])

    @pytest.mark.parametrize("n", [2, 4, 8, 64])
    def test_calls_and_sigmas_follow_leaves(self, n, fake_samplerz):
        # 2n Aufrufe; σ′ = Blätter in Reihenfolge rechts zuerst, jedes zweimal
        T = self._tree(n)
        t = (fft([0.25 * i for i in range(n)]), fft([0.1 * i for i in range(n)]))
        ff_sampling(t, T, FALCON_512, NoRandomness())
        expected = [s for leaf in leaves_sampling_order(T) for s in (leaf, leaf)]
        assert [s for _, s in fake_samplerz] == expected

    @pytest.mark.parametrize("n", [2, 4, 8, 64])
    def test_integral_target_is_fixed_point(self, n, fake_samplerz):
        # t ganzzahlig ⇒ alle μ ganzzahlig ⇒ Rundung ändert nichts ⇒ z = t
        a = [(3 * i) % 11 - 5 for i in range(n)]
        b = [(7 * i) % 13 - 6 for i in range(n)]
        z0, z1 = ff_sampling((fft(a), fft(b)), self._tree(n), FALCON_512, NoRandomness())
        assert to_int_poly(z0) == a
        assert to_int_poly(z1) == b

    @pytest.mark.parametrize("n", [2, 4, 8, 64])
    def test_output_shape(self, n, fake_samplerz):
        t = (fft([0.3] * n), fft([-0.6] * n))
        z0, z1 = ff_sampling(t, self._tree(n), FALCON_512, NoRandomness())
        assert len(z0) == len(z1) == n
        to_int_poly(z0)
        to_int_poly(z1)

    @staticmethod
    def _tree(n, depth_tag=0):
        """Künstlicher Baum mit unterscheidbaren Blättern und ℓ = FFT(0.5)."""
        counter = iter(range(10_000))

        def build(m):
            if m == 1:
                return 1.3 + 0.001 * next(counter)
            return (fft([0.5] + [0.0] * (m - 1)), build(m // 2), build(m // 2))

        return build(n)
