"""Tests für params.py – Parametersätze.

Spec-Referenz: Tabelle 3.3, §2.6 (Gl. 2.10–2.14), §3.4.1, §3.9.3,
§3.11.4, §3.11.5, §3.13.
Längen und Header-Bytes zusätzlich gegen die NIST-KAT-Dateien geprüft
(count = 0: pk 897 / 1793 Bytes, sk-Header 0x59 / 0x5A).
"""

import dataclasses
import math

import pytest
from falcon.params import Params, FALCON_512, FALCON_1024


# Erwartete Werte aus Tab. 3.3 (Spec v1.2, S. 51).
# lam = Sicherheitsniveau λ aus §2.6 (128 für Level I, 256 für Level V).
TABLE_3_3 = {
    "FALCON_512": dict(
        params=FALCON_512, n=512, q=12289, lam=128,
        sigma=165.736617183, sigma_min=1.277833697, sigma_max=1.8205,
        sig_bound=34034726, sig_bytelen=666, pk_bytes=897,
    ),
    "FALCON_1024": dict(
        params=FALCON_1024, n=1024, q=12289, lam=256,
        sigma=168.388571447, sigma_min=1.298280334, sigma_max=1.8205,
        sig_bound=70265242, sig_bytelen=1280, pk_bytes=1793,
    ),
}

PARAM_SETS = pytest.mark.parametrize(
    "row", TABLE_3_3.values(), ids=TABLE_3_3.keys()
)

# Alle zulässigen Grade n = 2^ℓ, ℓ = 1..10 (§3.11.3–§3.11.5).
ALL_LOGN = pytest.mark.parametrize("logn", range(1, 11))

Q_S = 2 ** 64      # maximale Anzahl Signaturanfragen, §2.6
TAU_SIG = 1.1      # Tailcut-Rate, Gl. 2.14
GS_FACTOR = 1.17   # ‖B‖_GS ≤ 1.17·√q, Gl. 2.11

# Tab. 3.3 gibt σ und σmin auf 9 Nachkommastellen an.
TABLE_PRECISION = 1e-9


def params_with_n(n: int) -> Params:
    """Params mit beliebigem Grad n (reduzierte Varianten, nur für Tests).
    Die übrigen Werte sind für pk_bytes / sk_header_byte irrelevant."""
    return dataclasses.replace(FALCON_512, n=n)


class TestParamSets:
    """FALCON_512 / FALCON_1024 – Werte gegen Tab. 3.3."""

    # --- Werte direkt aus der Tabelle -------------------------------------

    @PARAM_SETS
    @pytest.mark.parametrize(
        "field",
        ["n", "q", "sigma", "sigma_min", "sigma_max", "sig_bound", "sig_bytelen"],
    )
    def test_value_matches_table_3_3(self, row, field):
        assert getattr(row["params"], field) == row[field]

    @PARAM_SETS
    @pytest.mark.parametrize("field", ["n", "q", "sig_bound", "sig_bytelen"])
    def test_integer_fields_are_int(self, row, field):
        # 512.0 == 512 wäre wahr, würde aber z. B. range(n) brechen.
        value = getattr(row["params"], field)
        assert type(value) is int

    # --- Strukturelle Bedingungen (§3.4.1, §3.11) --------------------------

    @PARAM_SETS
    def test_n_is_power_of_two_with_allowed_log(self, row):
        # n = 2^ℓ, ℓ im Bereich 1 bis 10
        n = row["params"].n
        assert n & (n - 1) == 0
        assert 1 <= n.bit_length() - 1 <= 10

    @PARAM_SETS
    def test_sigma_min_below_sigma_max(self, row):
        # §3.4.1, Punkt 4; §3.9.3: 1 ≤ σmin < σmax
        p = row["params"]
        assert 1 <= p.sigma_min < p.sigma_max

    @PARAM_SETS
    def test_sig_bound_positive(self, row):
        # §3.4.1, Punkt 3: ⌊β²⌋ > 0
        assert row["params"].sig_bound > 0

    # --- Herleitung aus §2.6 (Kontrolle der Tabellenwerte) ------------------

    @PARAM_SETS
    def test_q_is_smallest_prime_of_form_k_2n_plus_1(self, row):
        # Gl. 2.10: q = 12·1024 + 1, prim, q ≡ 1 mod 2n (für die NTT)
        p = row["params"]
        assert p.q % (2 * p.n) == 1
        assert all(p.q % d for d in range(2, math.isqrt(p.q) + 1))

    @PARAM_SETS
    def test_sigma_matches_formula_2_13(self, row):
        # σ = (1/π)·√(ln(4n(1 + 1/ε)) / 2) · 1.17·√q, ε = 1/√(Qs·λ)
        p = row["params"]
        eps = 1 / math.sqrt(Q_S * row["lam"])
        expected = (
            (1 / math.pi)
            * math.sqrt(math.log(4 * p.n * (1 + 1 / eps)) / 2)
            * GS_FACTOR * math.sqrt(p.q)
        )
        assert p.sigma == pytest.approx(expected, abs=TABLE_PRECISION)

    @PARAM_SETS
    def test_sig_bound_matches_formula_2_14(self, row):
        # ⌊β²⌋ mit β = τ_sig · σ · √(2n), τ_sig = 1.1
        p = row["params"]
        beta = TAU_SIG * p.sigma * math.sqrt(2 * p.n)
        assert p.sig_bound == math.floor(beta ** 2)

    @PARAM_SETS
    def test_sigma_min_equals_sigma_over_gs_bound(self, row):
        # Nicht explizit in der Spec als Formel angegeben, aber von den
        # Tabellenwerten erfüllt: σmin = σ / (1.17·√q). Folgt daraus, dass die
        # Blätter σ/√Blatt sind und ‖B‖_GS ≤ 1.17·√q (Gl. 2.11, Alg. 4).
        p = row["params"]
        expected = p.sigma / (GS_FACTOR * math.sqrt(p.q))
        assert p.sigma_min == pytest.approx(expected, abs=TABLE_PRECISION)

    # --- Querbezüge ---------------------------------------------------------

    def test_sigma_max_shared(self):
        # Tab. 3.3: σmax = 1.8205 für beide Parametersätze
        assert FALCON_512.sigma_max == FALCON_1024.sigma_max == 1.8205

    def test_sampler_vectors_use_falcon_512_sigma_min(self):
        # §3.9.3: Tab. 3.2 verwendet σmin = 1.277833697,
        # „the value of σmin for Falcon-512“
        assert FALCON_512.sigma_min == 1.277833697

    # --- Datenklasse ----------------------------------------------------------

    def test_params_are_immutable(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            FALCON_512.n = 1024

    def test_param_sets_are_distinct(self):
        assert FALCON_512 != FALCON_1024


class TestParamsValidation:
    """Params.__init__ lehnt ungültige Parameter mit ValueError ab.

    Designentscheidung (siehe ENTSCHEIDUNGEN.md), gestützt auf:
      - §3.4.1: n = 2^κ, ⌊β²⌋ > 0, σmin < σmax
      - §3.11.3–§3.11.5: ℓ im Bereich 1 bis 10
      - §3.9.3: 1 ≤ σmin < σmax
      - Gl. 2.10: q prim, q ≡ 1 mod 2n (für die NTT)
      - sig_bytelen > 0: eigene Ergänzung
    Jeweils beide Seiten der Grenze: gültiger Grenzwert wird angenommen,
    knapp ungültiger abgelehnt.
    """

    @staticmethod
    def make(**changes) -> Params:
        return dataclasses.replace(FALCON_512, **changes)

    def test_official_sets_are_accepted(self):
        for p in (FALCON_512, FALCON_1024):
            assert dataclasses.replace(p) == p

    # --- n = 2^ℓ, 1 ≤ ℓ ≤ 10 ------------------------------------------------

    @ALL_LOGN
    def test_accepts_all_allowed_degrees(self, logn):
        assert self.make(n=1 << logn).n == 1 << logn

    @pytest.mark.parametrize(
        "n",
        [1, 2048],  # ℓ = 0 und ℓ = 11: Zweierpotenzen, aber ausserhalb 1..10
        ids=["logn=0", "logn=11"],
    )
    def test_rejects_power_of_two_outside_range(self, n):
        with pytest.raises(ValueError):
            self.make(n=n)

    @pytest.mark.parametrize("n", [0, -512, 3, 6, 1000, 1023, 1025])
    def test_rejects_non_power_of_two(self, n):
        with pytest.raises(ValueError):
            self.make(n=n)

    # --- 1 ≤ σmin < σmax, σ > 0 --------------------------------------------

    def test_accepts_sigma_min_exactly_one(self):
        assert self.make(sigma_min=1.0).sigma_min == 1.0

    @pytest.mark.parametrize("sigma_min", [0.999, 0.0, -1.277833697])
    def test_rejects_sigma_min_below_one(self, sigma_min):
        with pytest.raises(ValueError):
            self.make(sigma_min=sigma_min)

    def test_rejects_sigma_min_equal_sigma_max(self):
        with pytest.raises(ValueError):
            self.make(sigma_min=1.8205, sigma_max=1.8205)

    def test_rejects_sigma_min_above_sigma_max(self):
        with pytest.raises(ValueError):
            self.make(sigma_min=1.9, sigma_max=1.8205)

    @pytest.mark.parametrize("sigma", [0.0, -165.736617183])
    def test_rejects_non_positive_sigma(self, sigma):
        with pytest.raises(ValueError):
            self.make(sigma=sigma)

    # --- ⌊β²⌋ > 0, sig_bytelen > 0 ------------------------------------------

    def test_accepts_minimal_positive_bounds(self):
        p = self.make(sig_bound=1, sig_bytelen=1)
        assert (p.sig_bound, p.sig_bytelen) == (1, 1)

    @pytest.mark.parametrize("sig_bound", [0, -1])
    def test_rejects_non_positive_sig_bound(self, sig_bound):
        with pytest.raises(ValueError):
            self.make(sig_bound=sig_bound)

    @pytest.mark.parametrize("sig_bytelen", [0, -1])
    def test_rejects_non_positive_sig_bytelen(self, sig_bytelen):
        with pytest.raises(ValueError):
            self.make(sig_bytelen=sig_bytelen)

    # --- q prim, q ≡ 1 mod 2n -------------------------------------------------

    @pytest.mark.parametrize(
        "q, n",
        [
            (12289, 1024),  # offizieller Wert
            (7681, 256),    # 7680 = 2⁹·15 → reicht genau bis n = 256
            (17, 8),        # 16 = 2·8
        ],
    )
    def test_accepts_ntt_friendly_prime(self, q, n):
        p = self.make(q=q, n=n)
        assert (p.q, p.n) == (q, n)

    @pytest.mark.parametrize(
        "q, n",
        [
            (7681, 512),   # prim, aber 7680 nicht durch 1024 teilbar
            (17, 16),      # prim, aber 16 nicht durch 32 teilbar
            (12301, 4),    # prim, 12300 ≡ 4 mod 8
        ],
    )
    def test_rejects_prime_without_root_of_unity(self, q, n):
        with pytest.raises(ValueError):
            self.make(q=q, n=n)

    @pytest.mark.parametrize("q", [12288, 12290, 1, 0, -12289])
    def test_rejects_non_prime_q(self, q):
        with pytest.raises(ValueError):
            self.make(q=q)


class TestPkBytes:
    """Params.pk_bytes – §3.11.4.

    1 Header-Byte + ⌈14n/8⌉ Bytes: alle n Koeffizienten von h werden mit
    je 14 Bit kodiert.
    """

    @PARAM_SETS
    def test_matches_table_3_3(self, row):
        assert row["params"].pk_bytes == row["pk_bytes"]

    @ALL_LOGN
    def test_matches_formula_for_all_degrees(self, logn):
        n = 1 << logn
        assert params_with_n(n).pk_bytes == 1 + math.ceil(14 * n / 8)

    @pytest.mark.parametrize(
        "n, expected",
        [(2, 5), (4, 8), (8, 15)],  # 1 + ⌈28/8⌉, 1 + ⌈56/8⌉, 1 + ⌈112/8⌉
    )
    def test_rounds_up_partial_bytes(self, n, expected):
        # Bei n = 2 bleiben 4 Bit übrig, bei n = 4 genau 0 – beide Fälle prüfen.
        assert params_with_n(n).pk_bytes == expected


class TestSkHeaderByte:
    """Params.sk_header_byte – §3.11.5.

    Header 0101nnnn mit nnnn = ℓ = log₂(n).
    """

    @pytest.mark.parametrize(
        "params, expected",
        [(FALCON_512, 0x59), (FALCON_1024, 0x5A)],
        ids=["FALCON_512", "FALCON_1024"],
    )
    def test_value(self, params, expected):
        assert params.sk_header_byte == expected

    @ALL_LOGN
    def test_structure_for_all_degrees(self, logn):
        header = params_with_n(1 << logn).sk_header_byte
        assert header >> 4 == 0b0101
        assert header & 0x0F == logn
