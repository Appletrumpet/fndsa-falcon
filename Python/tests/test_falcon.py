"""Tests für falcon.py – öffentliche API und interne Bausteine.

Spec-Referenz: §3.8–§3.10, Alg. 4 (Keygen), Alg. 10 (Sign), Alg. 16 (Verify),
§3.11.5 (sk laden). Doku: Falcon_Documentation §5.2–§5.4, §6.13, §7.

Ablauf laut Doku §5.3 / Alg. 10:
  salt = rng.random_bytes(40)                          (Z. 1, genau einmal)
  c = hash_to_point(salt + m); t = compute_target(c, sk) (Z. 2–3)
  wiederholen: z = ff_sampling(…); s = compute_signature_vector(…)
               bis is_short_fft(s)                      (Z. 4–8)
  s1, s2 = to_coefficients(s); s2_enc = compress(s2)    (Z. 9–10)
  bei s2_enc = None: zurück zum Sampling, Salt bleibt   (Z. 11)

Testdaten:
  - Sampler-Testvektoren: Schlüssel, nonce, data = b"data1", alle Zufallsbytes
    und s₂ = „signature vector“ → exakter Vektor für sign (FixedRNG mit
    nonce ‖ Zufallsbytes).
  - KAT: pk, sk und signierte Nachrichten (100 je Parametersatz).
"""

import math

import pytest
import falcon.falcon as falcon_module
from falcon.datatypes import SecretKey, PublicKey, Signature
from falcon.encoding import compress, decode_pk, decode_sk, decode_kat_message, encode_sig
from falcon.falcon import (
    keygen, sign, verify, load_secret_key,
    compute_public_key, compute_target, compute_signature_vector,
    is_short_fft, to_coefficients, compute_s1, is_short,
)
from falcon.fft import fft, ifft
from falcon.modq import div_mod_q
from falcon.ntrugen import generate_ntru_keys
from falcon.params import FALCON_512, FALCON_1024
from falcon.tree import build_basis_fft, build_falcon_tree
from support import FixedRNG, SeededRNG, load_kat, load_sampler_vectors

Q = 12289
PARAMS_BY_N = {512: FALCON_512, 1024: FALCON_1024}
KEY_SETS = pytest.mark.parametrize("n", [512, 1024], ids=["falcon512", "falcon1024"])


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

def nmul(a, b):
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


def centered(x):
    x %= Q
    return x - Q if x > Q // 2 else x


def assert_close(actual, expected, tol=1e-6):
    assert len(actual) == len(expected)
    assert max((abs(a - e) for a, e in zip(actual, expected)), default=0.0) <= tol


def squares_summing_to(target, count):
    """Ganze Zahlen, deren Quadrate sich zu target summieren (gierig, mit Prüfung)."""
    out = []
    while target:
        r = math.isqrt(target)
        out.append(r)
        target -= r * r
    assert len(out) <= count
    return out + [0] * (count - len(out))


@pytest.fixture(scope="module")
def vector_keys():
    """SecretKey/PublicKey aus den Sampler-Testvektoren (512 und 1024)."""
    keys = {}
    for n in (512, 1024):
        v = load_sampler_vectors(n)
        params = PARAMS_BY_N[n]
        B = build_basis_fft(v.f, v.g, v.F, v.G)
        sk = SecretKey(v.f, v.g, v.F, v.G, B, build_falcon_tree(B, params))
        pk = PublicKey(div_mod_q(v.g, v.f))
        keys[n] = (v, params, sk, pk)
    return keys


@pytest.fixture(scope="module")
def generated_512():
    """Ein mit keygen erzeugtes Schlüsselpaar (deterministisch)."""
    return keygen(FALCON_512, SeededRNG(100))


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

class TestKeygen:
    """keygen – Alg. 4, Doku §5.2."""

    def test_types(self, generated_512):
        sk, pk = generated_512
        assert isinstance(sk, SecretKey) and isinstance(pk, PublicKey)

    def test_ntru_equation(self, generated_512):
        sk, _ = generated_512
        lhs = [a - b for a, b in zip(nmul(sk.f, sk.G), nmul(sk.g, sk.F))]
        assert lhs == [Q] + [0] * 511

    def test_public_key_is_g_over_f(self, generated_512):
        # Alg. 4 Z. 9: h = g·f⁻¹ mod q ⇔ h·f ≡ g
        sk, pk = generated_512
        assert len(pk.h) == 512 and all(0 <= x < Q for x in pk.h)
        assert [x % Q for x in nmul(pk.h, sk.f)] == [x % Q for x in sk.g]

    def test_basis_and_tree_derived_from_key(self, generated_512):
        # Alg. 4 Z. 2–7
        sk, _ = generated_512
        B = build_basis_fft(sk.f, sk.g, sk.F, sk.G)
        for i in range(2):
            for j in range(2):
                assert_close(sk.basis_fft[i][j], B[i][j], tol=1e-9)
        T = build_falcon_tree(B, FALCON_512)
        assert _leaves(sk.tree) == pytest.approx(_leaves(T))

    def test_uses_generate_ntru_keys_with_rng(self):
        # Doku §5.2: f, g, F, G = generate_ntru_keys(params, rng) ist der erste Schritt
        sk, _ = keygen(FALCON_512, SeededRNG(101))
        assert (sk.f, sk.g, sk.F, sk.G) == generate_ntru_keys(FALCON_512, SeededRNG(101))

    def test_deterministic_for_same_randomness(self):
        a, _ = keygen(FALCON_512, SeededRNG(102))
        b, _ = keygen(FALCON_512, SeededRNG(102))
        assert (a.f, a.g, a.F, a.G) == (b.f, b.g, b.F, b.G)

    def test_default_rng_gives_different_keys(self):
        a, _ = keygen(FALCON_512)
        b, _ = keygen(FALCON_512)
        assert a.f != b.f

    def test_falcon_1024(self):
        sk, pk = keygen(FALCON_1024, SeededRNG(103))
        assert len(sk.f) == len(pk.h) == 1024
        lhs = [a - b for a, b in zip(nmul(sk.f, sk.G), nmul(sk.g, sk.F))]
        assert lhs == [Q] + [0] * 1023


def _leaves(t):
    if isinstance(t, (int, float)):
        return [t]
    return _leaves(t[1]) + _leaves(t[2])


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

class TestSign:
    """sign – Alg. 10, Doku §5.3."""

    @KEY_SETS
    def test_nist_vector(self, n, vector_keys):
        # Zufall = nonce (Salt, Z. 1) ‖ alle SamplerZ-Bytes → genau diese Signatur
        v, params, sk, _ = vector_keys[n]
        rng = FixedRNG(v.nonce + b"".join(t.random_bytes for t in v.samplerz))
        sig = sign(sk, v.data, params, rng)
        assert sig.salt == v.nonce
        assert sig.s2_encoded == compress(v.signature_vector, params)
        assert rng.remaining == 0

    @KEY_SETS
    def test_signature_verifies(self, n, vector_keys):
        _, params, sk, pk = vector_keys[n]
        sig = sign(sk, b"hello", params, SeededRNG(200))
        assert verify(pk, b"hello", sig, params) is True

    @KEY_SETS
    def test_format(self, n, vector_keys):
        # Salt 40 Bytes (Z. 1), s₂ gepolstert auf sbytelen − 41 (Z. 10)
        _, params, sk, _ = vector_keys[n]
        sig = sign(sk, b"format", params, SeededRNG(201))
        assert isinstance(sig, Signature)
        assert len(sig.salt) == 40
        assert len(sig.s2_encoded) == params.sig_bytelen - 41
        assert len(encode_sig(sig, params)) == params.sig_bytelen

    def test_salt_is_first_40_bytes(self, vector_keys):
        _, params, sk, _ = vector_keys[512]
        rng = SeededRNG(202)
        expected_salt = SeededRNG(202).random_bytes(40)
        assert sign(sk, b"m", params, rng).salt == expected_salt

    def test_deterministic_for_same_randomness(self, vector_keys):
        _, params, sk, _ = vector_keys[512]
        assert sign(sk, b"m", params, SeededRNG(203)) == sign(sk, b"m", params, SeededRNG(203))

    def test_default_rng_randomizes(self, vector_keys):
        _, params, sk, pk = vector_keys[512]
        a, b = sign(sk, b"m", params), sign(sk, b"m", params)
        assert a.salt != b.salt
        assert verify(pk, b"m", a, params) and verify(pk, b"m", b, params)

    @pytest.mark.parametrize("message", [b"", b"\x00", b"x" * 10_000])
    def test_messages(self, message, vector_keys):
        _, params, sk, pk = vector_keys[512]
        assert verify(pk, message, sign(sk, message, params, SeededRNG(204)), params)

    # --- Schleifen in Alg. 10: Salt bleibt, nur neu sampeln ------------------------

    def test_restart_when_too_long_keeps_salt(self, vector_keys, monkeypatch):
        # Z. 4–8: erste Stichprobe als „zu lang“ verwerfen → neue Stichprobe, gleicher Salt
        _, params, sk, pk = vector_keys[512]
        real = falcon_module.is_short_fft
        calls = []

        def patched(s, p):
            calls.append(1)
            return False if len(calls) == 1 else real(s, p)

        monkeypatch.setattr(falcon_module, "is_short_fft", patched)
        sig = sign(sk, b"m", params, SeededRNG(205))
        assert len(calls) >= 2
        assert sig.salt == SeededRNG(205).random_bytes(40)
        assert verify(pk, b"m", sig, params)

    def test_restart_when_compress_fails_keeps_salt(self, vector_keys, monkeypatch):
        # Z. 10–11: Kompression ⊥ → zurück zum Sampling, Salt bleibt (Z. 1 nur einmal)
        _, params, sk, pk = vector_keys[512]
        real = falcon_module.compress
        calls = []

        def patched(s, p):
            calls.append(1)
            return None if len(calls) == 1 else real(s, p)

        monkeypatch.setattr(falcon_module, "compress", patched)
        sig = sign(sk, b"m", params, SeededRNG(206))
        assert len(calls) == 2
        assert sig.salt == SeededRNG(206).random_bytes(40)
        assert verify(pk, b"m", sig, params)

    def test_retry_produces_different_s2(self, vector_keys, monkeypatch):
        # Nach einem Neustart wird z neu gezogen (nicht dieselbe Signatur wiederholt)
        _, params, sk, _ = vector_keys[512]
        first = sign(sk, b"m", params, SeededRNG(207))
        real = falcon_module.is_short_fft
        calls = []

        def patched(s, p):
            calls.append(1)
            return False if len(calls) == 1 else real(s, p)

        monkeypatch.setattr(falcon_module, "is_short_fft", patched)
        second = sign(sk, b"m", params, SeededRNG(207))
        assert second.salt == first.salt
        assert second.s2_encoded != first.s2_encoded


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

class TestVerify:
    """verify – Alg. 16, Doku §5.4."""

    @KEY_SETS
    def test_nist_vector(self, n, vector_keys):
        v, params, _, pk = vector_keys[n]
        sig = Signature(salt=v.nonce, s2_encoded=compress(v.signature_vector, params))
        assert verify(pk, v.data, sig, params) is True

    @KEY_SETS
    def test_kat_samples(self, n):
        # Vollständig in test_kat.py; hier je 5 Fälle inkl. Falcon-1024 count = 82
        params = PARAMS_BY_N[n]
        recs = load_kat(n)
        picks = [0, 1, 2, 50, 82] if n == 1024 else [0, 1, 2, 50, 99]
        for i in picks:
            msg, sig = decode_kat_message(recs[i].sm)
            assert verify(PublicKey(decode_pk(recs[i].pk)), msg, sig, params) is True, f"count {i}"

    # --- Ablehnung ---------------------------------------------------------------

    @pytest.fixture
    def good(self, vector_keys):
        v, params, _, pk = vector_keys[512]
        return pk, v.data, Signature(salt=v.nonce, s2_encoded=compress(v.signature_vector, params)), params

    def test_rejects_wrong_message(self, good):
        pk, msg, sig, params = good
        assert verify(pk, msg + b"!", sig, params) is False

    def test_rejects_modified_salt(self, good):
        pk, msg, sig, params = good
        salt = bytes([sig.salt[0] ^ 1]) + sig.salt[1:]
        assert verify(pk, msg, Signature(salt, sig.s2_encoded), params) is False

    def test_rejects_wrong_public_key(self, good, vector_keys):
        _, msg, sig, params = good
        other = PublicKey(decode_pk(load_kat(512)[0].pk))
        assert verify(other, msg, sig, params) is False

    @pytest.mark.parametrize("pos", [0, 10, 300])
    def test_rejects_modified_s2(self, good, pos):
        # Ein Bit im komprimierten s₂ kippen: ungültige Kodierung oder falsches s₂
        pk, msg, sig, params = good
        b = bytearray(sig.s2_encoded)
        b[pos] ^= 0x10
        assert verify(pk, msg, Signature(sig.salt, bytes(b)), params) is False

    @pytest.mark.parametrize("s2_encoded", [b"", b"\xff" * 625, b"\x00" * 625, b"\x80"])
    def test_invalid_encoding_returns_false(self, good, s2_encoded):
        # Alg. 16 Z. 3–4: ungültige Kodierung → ablehnen (kein Fehler werfen)
        pk, msg, sig, params = good
        assert verify(pk, msg, Signature(sig.salt, s2_encoded), params) is False

    def test_rejects_s2_zero(self, good):
        # s₂ = 0 ist gültig kodiert, aber s₁ = c ist viel zu lang (Z. 6–9)
        pk, msg, sig, params = good
        zero = compress([0] * 512, params)
        assert verify(pk, msg, Signature(sig.salt, zero), params) is False

    def test_rejects_signature_from_other_key(self, vector_keys):
        _, params, sk, _ = vector_keys[512]
        other_pk = PublicKey(decode_pk(load_kat(512)[3].pk))
        sig = sign(sk, b"m", params, SeededRNG(300))
        assert verify(other_pk, b"m", sig, params) is False

    def test_returns_bool(self, good):
        pk, msg, sig, params = good
        assert type(verify(pk, msg, sig, params)) is bool


# ---------------------------------------------------------------------------
# load_secret_key
# ---------------------------------------------------------------------------

class TestLoadSecretKey:
    """load_secret_key – §3.11.5, Alg. 4 Z. 2–7: decode_sk → recompute_G → Basis → Baum."""

    @KEY_SETS
    def test_kat_key_fields(self, n):
        params = PARAMS_BY_N[n]
        rec = load_kat(n)[0]
        sk = load_secret_key(rec.sk, params)
        assert isinstance(sk, SecretKey)
        assert (sk.f, sk.g, sk.F) == decode_sk(rec.sk)
        lhs = [a - b for a, b in zip(nmul(sk.f, sk.G), nmul(sk.g, sk.F))]
        assert lhs == [Q] + [0] * (n - 1)
        assert sk.basis_fft is not None and sk.tree is not None

    @KEY_SETS
    def test_sign_with_kat_sk_verify_with_kat_pk(self, n):
        # Doku §7: mit dem KAT-sk signieren und mit dem KAT-pk verifizieren
        params = PARAMS_BY_N[n]
        for rec in load_kat(n)[:2]:
            sk = load_secret_key(rec.sk, params)
            pk = PublicKey(decode_pk(rec.pk))
            sig = sign(sk, rec.msg, params, SeededRNG(rec.count))
            assert verify(pk, rec.msg, sig, params), f"count {rec.count}"

    def test_derived_parts_match_build_functions(self):
        rec = load_kat(512)[0]
        sk = load_secret_key(rec.sk, FALCON_512)
        B = build_basis_fft(sk.f, sk.g, sk.F, sk.G)
        assert_close(sk.basis_fft[1][1], B[1][1], tol=1e-9)
        assert _leaves(sk.tree) == pytest.approx(_leaves(build_falcon_tree(B, FALCON_512)))

    def test_rejects_key_for_other_parameter_set(self):
        with pytest.raises(ValueError):
            load_secret_key(load_kat(1024)[0].sk, FALCON_512)

    def test_rejects_invalid_encoding(self):
        with pytest.raises(ValueError):
            load_secret_key(b"\x59" + bytes(10), FALCON_512)


# ---------------------------------------------------------------------------
# compute_public_key
# ---------------------------------------------------------------------------

class TestComputePublicKey:
    """compute_public_key – Alg. 4 Z. 9: h = g·f⁻¹ mod q."""

    def test_example_f_one(self):
        assert compute_public_key([1, 0], [3, 4], FALCON_512) == [3, 4]

    def test_example_f_two(self):
        # 2⁻¹ = 6145 mod q: h = 6145·(3 + 4x) = 18435 + 24580x ≡ 6146 + 2x
        assert compute_public_key([2, 0], [3, 4], FALCON_512) == [6146, 2]

    def test_signed_g(self):
        assert compute_public_key([1, 0], [-1, 0], FALCON_512) == [Q - 1, 0]

    @KEY_SETS
    def test_kat_keys(self, n):
        params = PARAMS_BY_N[n]
        for rec in load_kat(n)[:10]:
            f, g, _ = decode_sk(rec.sk)
            assert compute_public_key(f, g, params) == decode_pk(rec.pk), f"count {rec.count}"

    def test_rejects_non_invertible_f(self):
        with pytest.raises(ValueError):
            compute_public_key([0, 0], [1, 0], FALCON_512)


# ---------------------------------------------------------------------------
# compute_target / compute_signature_vector
# ---------------------------------------------------------------------------

class TestComputeTarget:
    """compute_target – Alg. 10 Z. 3: t = (−ĉ⊙F̂/q, ĉ⊙f̂/q) = (ĉ, 0)·B̂⁻¹."""

    @KEY_SETS
    def test_formula(self, n, vector_keys):
        v, _, sk, _ = vector_keys[n]
        t0, t1 = compute_target(v.hashed_message, sk)
        c, f, F = fft(v.hashed_message), fft(v.f), fft(v.F)
        assert_close(t0, [-a * b / Q for a, b in zip(c, F)], tol=1e-6)
        assert_close(t1, [a * b / Q for a, b in zip(c, f)], tol=1e-6)

    @KEY_SETS
    def test_t_times_basis_is_c_zero(self, n, vector_keys):
        # t·B̂ = (ĉ·(fG − gF)/q, 0) = (ĉ, 0)
        v, _, sk, _ = vector_keys[n]
        t0, t1 = compute_target(v.hashed_message, sk)
        B = sk.basis_fft
        first = [a * b00 + b * b10 for a, b, b00, b10 in zip(t0, t1, B[0][0], B[1][0])]
        second = [a * b01 + b * b11 for a, b, b01, b11 in zip(t0, t1, B[0][1], B[1][1])]
        assert_close(first, fft(v.hashed_message), tol=1e-6)
        assert_close(second, [0] * n, tol=1e-6)


class TestComputeSignatureVector:
    """compute_signature_vector – Alg. 10 Z. 7: s = (t − z)·B̂."""

    def test_formula_example(self):
        # Ein Punkt, B = [[1, 2], [3, 4]], t − z = (1, 1) → s = (1+3, 2+4) = (4, 6)
        sk = SecretKey([0], [0], [0], [0], (([1 + 0j], [2 + 0j]), ([3 + 0j], [4 + 0j])))
        s0, s1 = compute_signature_vector(([1.5 + 0j], [2.5 + 0j]), ([0.5 + 0j], [1.5 + 0j]), sk)
        assert_close(s0, [4])
        assert_close(s1, [6])

    @KEY_SETS
    def test_z_zero_gives_c_zero(self, n, vector_keys):
        v, _, sk, _ = vector_keys[n]
        t = compute_target(v.hashed_message, sk)
        s0, s1 = compute_signature_vector(t, ([0j] * n, [0j] * n), sk)
        assert_close(s0, fft(v.hashed_message), tol=1e-6)
        assert_close(s1, [0] * n, tol=1e-6)

    @KEY_SETS
    def test_vector_gives_signature(self, n, vector_keys):
        # Mit z aus dem NIST-Lauf: s₂ = signature vector
        from falcon.ffsampling import ff_sampling
        v, params, sk, _ = vector_keys[n]
        t = compute_target(v.hashed_message, sk)
        z = ff_sampling(t, sk.tree, params, FixedRNG(b"".join(x.random_bytes for x in v.samplerz)))
        s = compute_signature_vector(t, z, sk)
        assert [round(x) for x in ifft(s[1])] == v.signature_vector


# ---------------------------------------------------------------------------
# is_short_fft / is_short
# ---------------------------------------------------------------------------

def _vector_with_norm(target, n):
    """Zwei ganzzahlige Polynome mit Σ Koeffizienten² = target."""
    sq = squares_summing_to(target, 2 * n)
    return sq[:n], sq[n:]


class TestIsShortFft:
    """is_short_fft – Alg. 10 Z. 8: ‖s‖² (FFT, Gl. 3.8) ≤ ⌊β²⌋."""

    @KEY_SETS
    def test_just_below_and_above_bound(self, n):
        # ±1 um die Grenze; Gleitkommafehler der FFT ≪ 1
        params = PARAMS_BY_N[n]
        lo = _vector_with_norm(params.sig_bound - 1, n)
        hi = _vector_with_norm(params.sig_bound + 1, n)
        assert is_short_fft((fft(lo[0]), fft(lo[1])), params) is True
        assert is_short_fft((fft(hi[0]), fft(hi[1])), params) is False

    def test_counts_both_components(self):
        # Nur zusammen über der Grenze
        n, params = 512, FALCON_512
        half = squares_summing_to(params.sig_bound // 2 + 1, n)
        assert is_short_fft((fft(half), fft([0] * n)), params) is True
        assert is_short_fft((fft(half), fft(half)), params) is False

    def test_zero(self):
        assert is_short_fft(([0j] * 512, [0j] * 512), FALCON_512) is True


class TestToCoefficients:
    """to_coefficients – Alg. 10 Z. 9: invFFT beider Komponenten, auf ganze Zahlen runden."""

    def test_exact_integers(self):
        a, b = [3, -1, 0, 7], [-5, 2, 2, 0]
        s1, s2 = to_coefficients((fft(a), fft(b)))
        assert (s1, s2) == (a, b)
        assert all(type(x) is int for x in s1 + s2)

    def test_rounds_to_nearest(self):
        # Kleine Abweichungen (Gleitkomma) werden gerundet
        a = [3.2, -0.8, 0.0, 6.7]
        b = [-4.6, 2.3, 1.9, -0.1]
        s1, s2 = to_coefficients((fft(a), fft(b)))
        assert (s1, s2) == ([3, -1, 0, 7], [-5, 2, 2, 0])

    @KEY_SETS
    def test_vector(self, n, vector_keys):
        from falcon.ffsampling import ff_sampling
        v, params, sk, _ = vector_keys[n]
        t = compute_target(v.hashed_message, sk)
        z = ff_sampling(t, sk.tree, params, FixedRNG(b"".join(x.random_bytes for x in v.samplerz)))
        _, s2 = to_coefficients(compute_signature_vector(t, z, sk))
        assert s2 == v.signature_vector


class TestComputeS1:
    """compute_s1 – Alg. 16 Z. 5: s₁ = c − s₂·h mod q, zentriert auf ⌈−q/2⌉ … ⌊q/2⌋."""

    def test_example_s2_zero(self):
        assert compute_s1([5, 12288], [0, 0], [7, 9], FALCON_512) == [5, -1]

    def test_example_constant(self):
        # c = 0, s₂ = 1, h = 3 → s₁ = −3
        assert compute_s1([0, 0], [1, 0], [3, 0], FALCON_512) == [-3, 0]

    def test_example_wraparound(self):
        # s₂ = x, h = x → s₂·h = x² = −1 → s₁ = c + 1
        assert compute_s1([10, 20], [0, 1], [0, 1], FALCON_512) == [11, 20]

    def test_centering_boundaries(self):
        # 6144 bleibt, 6145 → −6144
        assert compute_s1([6144, 6145], [0, 0], [0, 0], FALCON_512) == [6144, -6144]

    @KEY_SETS
    def test_vector(self, n, vector_keys):
        # s₁ + s₂·h ≡ c (mod q), zentriert, und (s₁, s₂) kurz
        v, params, _, pk = vector_keys[n]
        s1 = compute_s1(v.hashed_message, v.signature_vector, pk.h, params)
        assert all(-6144 <= x <= 6144 for x in s1)
        lhs = [(a + b) % Q for a, b in zip(s1, nmul(v.signature_vector, pk.h))]
        assert lhs == [x % Q for x in v.hashed_message]
        assert sum(x * x for x in s1 + v.signature_vector) <= params.sig_bound

    def test_accepts_signed_s2(self):
        assert compute_s1([0, 0], [-1, 0], [3, 0], FALCON_512) == [3, 0]


class TestIsShort:
    """is_short – Alg. 16 Z. 6: ‖s₁‖² + ‖s₂‖² ≤ ⌊β²⌋, exakt ganzzahlig."""

    @KEY_SETS
    def test_exact_boundary(self, n):
        params = PARAMS_BY_N[n]
        at = _vector_with_norm(params.sig_bound, n)
        above = _vector_with_norm(params.sig_bound + 1, n)
        assert is_short(at[0], at[1], params) is True
        assert is_short(above[0], above[1], params) is False

    def test_counts_both(self):
        a = squares_summing_to(FALCON_512.sig_bound // 2 + 1, 512)
        assert is_short(a, [0] * 512, FALCON_512) is True
        assert is_short(a, a, FALCON_512) is False

    def test_negative_coefficients(self):
        a = [-x for x in squares_summing_to(FALCON_512.sig_bound, 512)]
        assert is_short(a, [0] * 512, FALCON_512) is True
