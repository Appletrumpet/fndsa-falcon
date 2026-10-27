"""Tests für sampler.py – Zufallsquelle und Gauss-Sampler.

Spec-Referenz: §3.9.3, Alg. 12–15, Tab. 3.1, Tab. 3.2, Gl. 3.31–3.34.
Doku: Falcon_Documentation §6.9.

Testdaten:
  - Tab. 3.2 (16 SamplerZ-Vektoren, σmin von Falcon-512), aus der Spec übernommen.
  - data/sampler/test-vector-sampler-falcon{512,1024}.txt aus dem NIST-Paket:
    je eine Signatur mit 1024 bzw. 2048 SamplerZ-Aufrufen, Schritt für Schritt
    protokolliert (u → z0 der BaseSampler, Bit b, BerExp mit x, ccs, s, r, z,
    verbrauchte Bytes und Ergebnis). Die ersten 16 Einträge der 512-Datei sind
    genau Tab. 3.2 (geprüft).

Zufall: UniformBits(k) liest k/8 Bytes big-endian (Doku §6.9; in den Vektoren
z. B. u = 0x0FC5442FF043D66E91 aus den Bytes 0f c5 44 … 91). Pro Iteration von
SamplerZ: 9 Bytes BaseSampler, 1 Byte für b, ≥ 1 Byte BerExp (§3.9.3).
Die Tests prüfen jeweils auch, dass **genau** alle Bytes verbraucht werden.
"""

import math
import random

import pytest
from falcon.params import FALCON_512, FALCON_1024
from falcon.sampler import (
    RNG, SystemRNG, SYSTEM_RNG, uniform_bits,
    base_sampler, approx_exp, ber_exp, sample_integer_gaussian,
)
from support import FixedRNG, load_sampler_vectors


# ---------------------------------------------------------------------------
# Tabellen aus der Spec
# ---------------------------------------------------------------------------

# Tab. 3.1, Spalte pdt[i] (skaliert mit 2⁷²)
PDT = [
    1697680241746640300030, 1459943456642912959616, 928488355018011056515,
    436693944817054414619, 151893140790369201013, 39071441848292237840,
    7432604049020375675, 1045641569992574730, 108788995549429682,
    8370422445201343, 476288472308334, 20042553305308, 623729532807,
    14354889437, 244322621, 3075302, 28626, 197, 1,
]

# Tab. 3.1, Spalte RCDT[i] = Σ_{j>i} pdt[j] = 2⁷² − cdt[i]
RCDT = [
    3024686241123004913666, 1564742784480091954050, 636254429462080897535,
    199560484645026482916, 47667343854657281903, 8595902006365044063,
    1163297957344668388, 117656387352093658, 8867391802663976,
    496969357462633, 20680885154299, 638331848991, 14602316184,
    247426747, 3104126, 28824, 198, 1, 0,
]

# Tab. 3.2: (μ, σ′, randombytes, z), σmin = 1.277833697 (Falcon-512)
TABLE_3_2 = [
    (-91.90471153063714, 1.7037990414754918, "0fc5442ff043d66e91d1eacac64ea5450a22941edc6c", -92),
    (-8.322564895434937, 1.7037990414754918, "f4da0f8d8444d1a77265c2ef6f98bbbb4bee7db8d9b3", -8),
    (-19.096516109216804, 1.7035823083824078, "db47f6d7fb9b19f25c36d6b9334d477a8bc0be68145d", -20),
    (-11.335543982423326, 1.7035823083824078, "ae41b4f5209665c74d00dcc1a8168a7bb516b3190cb42c1ded26cd52aed770eca7dd334e0547bcc3c163ce0b", -12),
    (7.9386734193997555, 1.6984647769450156, "31054166c1012780c603ae9b833cec73f2f41ca5807cc89c92158834632f9b1555", 8),
    (-28.990850086867255, 1.6984647769450156, "737e9d68a50a06dbbc6477", -30),
    (-9.071257914091655, 1.6980782114808988, "a98ddd14bf0bf22061d632", -10),
    (-43.88754568839566, 1.6980782114808988, "3cbf6818a68f7ab9991514", -41),
    (-58.17435547946095, 1.7010983419195522, "6f8633f5bfa5d26848668e3d5ddd46958e97630410587c", -61),
    (-43.58664906684732, 1.7010983419195522, "272bc6c25f5c5ee53f83c43a361fbc7cc91dc783e20a", -46),
    (-34.70565203313315, 1.7009387219711465, "45443c59574c2c3b07e2e1d9071e6d133dbe32754b0a", -34),
    (-44.36009577368896, 1.7009387219711465, "6ac116ed60c258e2cbaeab728c4823e6da36e18d08da5d0cc104e21cc7fd1f5ca8d9dbb675266c928448059e", -44),
    (-21.783037079346236, 1.6958406126012802, "68163bc1e2cbf3e18e7426", -23),
    (-39.68827784633828, 1.6958406126012802, "d6a1b51d76222a705a0259", -40),
    (-18.488607061056847, 1.6955259305261838, "f0523bfaa8a394bf4ea5c10f842366fde286d6a30803", -22),
    (-48.39610939101591, 1.6955259305261838, "87bd87e63374cee62127fc6931104aab64f136a0485b", -50),
]

TWO_63 = 2 ** 63
LN2 = math.log(2)

PARAMS_BY_N = {512: FALCON_512, 1024: FALCON_1024}
VECTOR_FILES = pytest.mark.parametrize("n", [512, 1024], ids=["falcon512", "falcon1024"])


class SeededRNG:
    """Reproduzierbare Zufallsquelle für statistische Tests."""

    def __init__(self, seed: int):
        self._r = random.Random(seed)

    def random_bytes(self, k: int) -> bytes:
        return self._r.randbytes(k)


def u_bytes(u: int) -> bytes:
    """72-Bit-Wert als 9 Bytes big-endian (Eingabe für BaseSampler)."""
    return u.to_bytes(9, "big")


# ---------------------------------------------------------------------------
# Testdaten selbst prüfen
# ---------------------------------------------------------------------------

class TestTables:
    """Abschrift von Tab. 3.1 / 3.2 und Testvektor-Dateien auf Konsistenz prüfen."""

    def test_pdt_sums_to_2_72(self):
        assert sum(PDT) == 2 ** 72

    def test_rcdt_is_reverse_cumulative(self):
        for i in range(19):
            assert RCDT[i] == sum(PDT[i + 1:])

    def test_rcdt_strictly_decreasing(self):
        assert all(RCDT[i] > RCDT[i + 1] for i in range(18))

    def test_table_3_2_equals_first_vectors_in_file(self):
        traces = load_sampler_vectors(512).samplerz[:16]
        for (mu, sigma, rb, z), t in zip(TABLE_3_2, traces):
            assert (mu, sigma, rb, z) == (t.mu, t.sigma, t.random_bytes.hex(), t.result)

    @VECTOR_FILES
    def test_vector_file_complete(self, n):
        v = load_sampler_vectors(n)
        # ffSampling zieht 2n ganze Zahlen (zwei Polynome der Länge n)
        assert len(v.samplerz) == 2 * n
        assert all(t.result is not None and t.iterations for t in v.samplerz)

    @VECTOR_FILES
    def test_vector_file_sigma_min_matches_params(self, n):
        # ccs = σmin/σ′ (Alg. 15 Z. 2) ⇒ σmin = ccs · σ′.
        # Die Dateien verwenden σmin ungerundet (≈ 1.2778336969128 bzw.
        # 1.2982803343443), Tab. 3.3 rundet auf 9 Stellen → Toleranz 1e-9.
        # Die Ergebnisse aller Vektoren hängen davon nicht ab (test_all_vectors
        # läuft mit dem gerundeten params.sigma_min).
        params = PARAMS_BY_N[n]
        for t in load_sampler_vectors(n).samplerz[:50]:
            ccs = t.iterations[0].berexp.ccs
            assert ccs * t.sigma == pytest.approx(params.sigma_min, abs=1e-9)


# ---------------------------------------------------------------------------
# SystemRNG
# ---------------------------------------------------------------------------

class TestSystemRNG:
    """SystemRNG.random_bytes – Gl. 3.32, über os.urandom."""

    @pytest.mark.parametrize("k", [0, 1, 9, 40, 1000])
    def test_returns_k_bytes(self, k):
        out = SYSTEM_RNG.random_bytes(k)
        assert type(out) is bytes and len(out) == k

    def test_successive_calls_differ(self):
        # 40 Bytes = 320 Bit (Salt-Länge): Kollision praktisch ausgeschlossen
        assert SYSTEM_RNG.random_bytes(40) != SYSTEM_RNG.random_bytes(40)

    def test_default_instance(self):
        assert isinstance(SYSTEM_RNG, SystemRNG)

    def test_fixed_rng_satisfies_protocol(self):
        # Test-Zufallsquelle hat dieselbe Schnittstelle (Doku §6.9)
        rng: RNG = FixedRNG(b"\x01")
        assert rng.random_bytes(1) == b"\x01"


# ---------------------------------------------------------------------------
# uniform_bits
# ---------------------------------------------------------------------------

class TestUniformBits:
    """uniform_bits – Gl. 3.32: k Bits aus k/8 Bytes, big-endian."""

    def test_k8_single_byte(self):
        assert uniform_bits(8, FixedRNG(b"\xd1")) == 0xD1

    def test_k16_big_endian(self):
        # 01 02 → 0x0102 = 258 (little-endian wäre 513)
        assert uniform_bits(16, FixedRNG(b"\x01\x02")) == 258

    def test_k72_big_endian_from_table_3_2(self):
        # Tab. 3.2 Zeile 1 / Testvektor: u = 0x0FC5442FF043D66E91
        rng = FixedRNG.from_hex("0fc5442ff043d66e91")
        assert uniform_bits(72, rng) == 0x0FC5442FF043D66E91

    @pytest.mark.parametrize("k", [8, 16, 64, 72])
    def test_extremes(self, k):
        assert uniform_bits(k, FixedRNG(b"\x00" * (k // 8))) == 0
        assert uniform_bits(k, FixedRNG(b"\xff" * (k // 8))) == 2 ** k - 1

    @pytest.mark.parametrize("k", [8, 16, 64, 72])
    def test_consumes_exactly_k_over_8_bytes(self, k):
        rng = FixedRNG(bytes(range(20)))
        uniform_bits(k, rng)
        assert rng.consumed == k // 8

    def test_sequential_calls_continue_stream(self):
        rng = FixedRNG(b"\xaa\xbb\xcc")
        assert [uniform_bits(8, rng) for _ in range(3)] == [0xAA, 0xBB, 0xCC]

    def test_returns_int(self):
        assert type(uniform_bits(72, SeededRNG(1))) is int


# ---------------------------------------------------------------------------
# base_sampler
# ---------------------------------------------------------------------------

class TestBaseSampler:
    """base_sampler – Alg. 12: z0 = #{i ∈ 0..17 : u < RCDT[i]}."""

    # --- Grenzen der Tabelle ---------------------------------------------------

    def test_u_zero_gives_18(self):
        assert base_sampler(FixedRNG(u_bytes(0))) == 18

    def test_u_max_gives_0(self):
        assert base_sampler(FixedRNG(u_bytes(2 ** 72 - 1))) == 0

    @pytest.mark.parametrize("i", range(18))
    def test_u_equal_rcdt_i_gives_i(self, i):
        # u = RCDT[i]: Vergleich u < RCDT[i] ist falsch (strikt)
        assert base_sampler(FixedRNG(u_bytes(RCDT[i]))) == i

    @pytest.mark.parametrize("i", range(18))
    def test_u_just_below_rcdt_i_gives_i_plus_1(self, i):
        assert base_sampler(FixedRNG(u_bytes(RCDT[i] - 1))) == i + 1

    # --- Vektoren ------------------------------------------------------------------

    def test_table_3_2_first_iteration(self):
        # Testvektor-Protokoll zu Tab. 3.2 Zeile 1: u = 0x0FC5…91 → z0 = 3
        assert base_sampler(FixedRNG.from_hex("0fc5442ff043d66e91")) == 3

    @VECTOR_FILES
    def test_all_vectors(self, n):
        its = [it for t in load_sampler_vectors(n).samplerz for it in t.iterations]
        for k, it in enumerate(its):
            rng = FixedRNG(it.u_bytes)
            assert base_sampler(rng) == it.z0, f"Iteration {k}: u = {it.u:#x}"
            assert rng.remaining == 0

    # --- Eigenschaften ---------------------------------------------------------------

    def test_consumes_exactly_9_bytes(self):
        rng = FixedRNG(bytes(20))
        base_sampler(rng)
        assert rng.consumed == 9

    def test_output_range_and_type(self):
        rng = SeededRNG(2)
        for _ in range(2000):
            z0 = base_sampler(rng)
            assert type(z0) is int and 0 <= z0 <= 18

    def test_distribution_matches_pdt(self):
        # P(z0 = i) = pdt[i] / 2⁷² (Gl. 3.33). 100'000 Ziehungen, Toleranz 5σ.
        N = 100_000
        counts = [0] * 19
        rng = SeededRNG(3)
        for _ in range(N):
            counts[base_sampler(rng)] += 1
        for i in range(6):
            p = PDT[i] / 2 ** 72
            sd = math.sqrt(N * p * (1 - p))
            assert abs(counts[i] - N * p) < 5 * sd, f"z0 = {i}"


# ---------------------------------------------------------------------------
# approx_exp
# ---------------------------------------------------------------------------

class TestApproxExp:
    """approx_exp – Alg. 13: ganzzahlige Näherung von 2⁶³·ccs·exp(−x),
    x ∈ [0, ln 2], ccs ∈ [0, 1]."""

    # --- Exakte Werte -------------------------------------------------------------

    def test_x0_ccs1_is_2_63(self):
        # §3.9.3: für x = 0 ist y nach der Schleife 2⁶³ (einzige Ausnahme vom
        # Bereich 0 … 2⁶³−1); mit ccs = 1 bleibt es 2⁶³.
        assert approx_exp(0.0, 1.0) == TWO_63

    @pytest.mark.parametrize("ccs", [0.75, 0.5, 0.125, 1.277833697 / 1.8205])
    def test_x0_gives_floor_2_63_ccs(self, ccs):
        # y = 2⁶³ ⇒ (⌊2⁶³·ccs⌋ · 2⁶³) >> 63 = ⌊2⁶³·ccs⌋
        assert approx_exp(0.0, ccs) == math.floor(TWO_63 * ccs)

    def test_ccs_zero_gives_zero(self):
        assert approx_exp(0.3, 0.0) == 0

    # --- Vektoren ----------------------------------------------------------------------

    @VECTOR_FILES
    def test_all_vectors_via_berexp_trace(self, n):
        # Alg. 14 Z. 4: z = (2·ApproxExp(r, ccs) − 1) >> s, protokolliert in den Vektoren
        bes = [it.berexp for t in load_sampler_vectors(n).samplerz for it in t.iterations]
        for k, be in enumerate(bes):
            got = (2 * approx_exp(be.r, be.ccs) - 1) >> be.s
            assert got == be.z, f"BerExp {k}: r = {be.r!r}, ccs = {be.ccs!r}, s = {be.s}"

    # --- Genauigkeit und Form ------------------------------------------------------------

    @pytest.mark.parametrize("ccs", [1.0, 0.75, 1.277833697 / 1.8205])
    def test_accuracy_over_domain(self, ccs):
        # f(−x) nähert exp(−x) auf [0, ln 2] sehr gut an (§3.9.3, [ZSS20]).
        # Relativer Fehler gegenüber 2⁶³·ccs·exp(−x) klein (Toleranz 2⁻⁴⁰).
        for j in range(101):
            x = LN2 * j / 100
            exact = TWO_63 * ccs * math.exp(-x)
            assert abs(approx_exp(x, ccs) - exact) <= exact * 2 ** -40

    def test_decreasing_in_x(self):
        values = [approx_exp(LN2 * j / 50, 0.9) for j in range(51)]
        assert all(a > b for a, b in zip(values, values[1:]))

    def test_increasing_in_ccs(self):
        values = [approx_exp(0.4, c / 20) for c in range(1, 21)]
        assert all(a < b for a, b in zip(values, values[1:]))

    def test_upper_end_of_domain(self):
        # x = ln 2: ≈ 2⁶³·ccs/2
        assert approx_exp(LN2, 1.0) == pytest.approx(2 ** 62, rel=2 ** -40)

    def test_returns_int_in_range(self):
        for j in range(21):
            y = approx_exp(LN2 * j / 20, 0.8)
            assert type(y) is int and 0 <= y <= TWO_63


# ---------------------------------------------------------------------------
# ber_exp
# ---------------------------------------------------------------------------

class TestBerExp:
    """ber_exp – Alg. 14: True mit Wahrscheinlichkeit ≈ ccs·exp(−x)."""

    # --- Vektoren -------------------------------------------------------------------

    @VECTOR_FILES
    def test_all_vectors(self, n):
        bes = [it.berexp for t in load_sampler_vectors(n).samplerz for it in t.iterations]
        for k, be in enumerate(bes):
            rng = FixedRNG(be.random_bytes)
            assert ber_exp(be.x, be.ccs, rng) is bool(be.ret), f"BerExp {k}"
            assert rng.remaining == 0, f"BerExp {k}: falsche Anzahl Bytes gelesen"

    @VECTOR_FILES
    def test_vectors_contain_multi_byte_cases(self, n):
        # §3.9.3: mit Wahrscheinlichkeit 1/128 mehr als ein Byte; muss abgedeckt sein
        bes = [it.berexp for t in load_sampler_vectors(n).samplerz for it in t.iterations]
        assert sum(len(be.random_bytes) > 1 for be in bes) >= 5

    def test_table_3_2_line_9_uses_two_bytes(self):
        # Tab. 3.2 Zeile 9: eine BerExp-Iteration liest 2 Bytes
        t = load_sampler_vectors(512).samplerz[8]
        assert any(len(it.berexp.random_bytes) == 2 for it in t.iterations)

    # --- Randfälle (von Hand aus Alg. 14) -------------------------------------------------

    def test_x0_ccs1_first_byte_decides(self):
        # z = 2⁶⁴ − 1: erstes Byte 0xFE − 0xFF < 0 → True nach 1 Byte
        rng = FixedRNG(b"\xfe")
        assert ber_exp(0.0, 1.0, rng) is True
        assert rng.remaining == 0

    def test_x0_ccs1_tie_moves_to_next_byte(self):
        # 0xFF − 0xFF = 0 → nächstes Byte: 0x00 − 0xFF < 0 → True nach 2 Bytes
        rng = FixedRNG(b"\xff\x00")
        assert ber_exp(0.0, 1.0, rng) is True
        assert rng.remaining == 0

    def test_x0_ccs1_all_ties_returns_false(self):
        # Alle 8 Bytes gleich → w = 0 bei i = 0 → ⟦w < 0⟧ = 0
        rng = FixedRNG(b"\xff" * 8)
        assert ber_exp(0.0, 1.0, rng) is False
        assert rng.remaining == 0

    def test_never_reads_more_than_8_bytes(self):
        rng = FixedRNG(b"\xff" * 8)   # FixedRNG schlägt bei einem 9. Byte fehl
        ber_exp(0.0, 1.0, rng)

    @pytest.mark.parametrize("x", [50.0, 1000.0, 1e6])
    def test_large_x_clamps_shift(self, x):
        # Alg. 14 Z. 3: s ← min(s, 63). z ∈ {0, 1} ⇒ erstes Byte 0x01 > z → False
        rng = FixedRNG(b"\x01")
        assert ber_exp(x, 1.0, rng) is False
        assert rng.remaining == 0

    def test_returns_bool(self):
        assert type(ber_exp(0.5, 0.8, SeededRNG(4))) is bool

    # --- Verteilung ------------------------------------------------------------------------

    @pytest.mark.parametrize("x, ccs", [(0.0, 0.75), (0.5, 0.8), (2.0, 1.0), (5.0, 0.7)])
    def test_probability(self, x, ccs):
        N = 20_000
        rng = SeededRNG(5)
        hits = sum(ber_exp(x, ccs, rng) for _ in range(N))
        p = ccs * math.exp(-x)
        sd = math.sqrt(N * p * (1 - p))
        assert abs(hits - N * p) < 5 * sd + 1


# ---------------------------------------------------------------------------
# sample_integer_gaussian
# ---------------------------------------------------------------------------

class TestSampleIntegerGaussian:
    """sample_integer_gaussian – Alg. 15 (SamplerZ)."""

    # --- Tab. 3.2 -------------------------------------------------------------------

    @pytest.mark.parametrize("mu, sigma, rb, z", TABLE_3_2,
                             ids=[f"line{i}" for i in range(1, 17)])
    def test_table_3_2(self, mu, sigma, rb, z):
        rng = FixedRNG.from_hex(rb)
        assert sample_integer_gaussian(mu, sigma, FALCON_512, rng) == z
        assert rng.remaining == 0

    # --- Testvektor-Dateien -----------------------------------------------------------

    @VECTOR_FILES
    def test_all_vectors(self, n):
        params = PARAMS_BY_N[n]
        for k, t in enumerate(load_sampler_vectors(n).samplerz):
            rng = FixedRNG(t.random_bytes)
            got = sample_integer_gaussian(t.mu, t.sigma, params, rng)
            assert got == t.result, f"SamplerZ {k}: μ = {t.mu!r}, σ′ = {t.sigma!r}"
            assert rng.remaining == 0, f"SamplerZ {k}: falsche Anzahl Bytes gelesen"

    # --- Eigenschaften ------------------------------------------------------------------------

    def test_returns_int(self):
        assert type(sample_integer_gaussian(0.5, 1.5, FALCON_512, SeededRNG(6))) is int

    @pytest.mark.parametrize("k", [1, 7, 1000, -1000])
    def test_shift_by_integer(self, k):
        # Gleiche Bytes, μ um ganze Zahl k verschoben ⇒ Ergebnis um k verschoben
        # (r = μ − ⌊μ⌋ bleibt gleich; 0.25 + k ist exakt darstellbar)
        seed_bytes = SeededRNG(7).random_bytes(500)
        base = sample_integer_gaussian(0.25, 1.6, FALCON_512, FixedRNG(seed_bytes))
        shifted = sample_integer_gaussian(0.25 + k, 1.6, FALCON_512, FixedRNG(seed_bytes))
        assert shifted == base + k

    def test_floor_for_negative_mu(self):
        # Tab. 3.2 Zeile 1: μ = −91.9…, ⌊μ⌋ = −92 (nicht int() = −91)
        mu, sigma, rb, z = TABLE_3_2[0]
        assert sample_integer_gaussian(mu, sigma, FALCON_512, FixedRNG.from_hex(rb)) == -92

    @pytest.mark.parametrize("mu, sigma", [(0.0, 1.5), (0.3, 1.8205), (-12.7, 1.277833697)])
    def test_mean_and_variance(self, mu, sigma):
        # D_{ℤ,σ′,μ}: Mittel ≈ μ, Varianz ≈ σ′² (σ′ ≥ σmin > Glättungsparameter).
        N = 20_000
        rng = SeededRNG(8)
        xs = [sample_integer_gaussian(mu, sigma, FALCON_512, rng) for _ in range(N)]
        mean = sum(xs) / N
        var = sum((x - mean) ** 2 for x in xs) / (N - 1)
        assert abs(mean - mu) < 5 * sigma / math.sqrt(N)
        assert var == pytest.approx(sigma ** 2, rel=0.05)

    def test_symmetric_around_integer_mu(self):
        N = 20_000
        rng = SeededRNG(9)
        xs = [sample_integer_gaussian(5.0, 1.7, FALCON_512, rng) for _ in range(N)]
        above = sum(x > 5 for x in xs)
        below = sum(x < 5 for x in xs)
        assert abs(above - below) < 5 * math.sqrt(above + below)

    def test_consumes_at_least_11_bytes(self):
        # Mindestens eine Iteration: 9 (BaseSampler) + 1 (b) + 1 (BerExp)
        rng = FixedRNG(SeededRNG(10).random_bytes(1000))
        sample_integer_gaussian(0.0, 1.5, FALCON_512, rng)
        assert rng.consumed >= 11

    # --- Gültiger Bereich von σ′ (Alg. 15: σ′ ∈ [σmin, σmax]) -------------------------------

    @pytest.mark.parametrize("params", [FALCON_512, FALCON_1024], ids=["512", "1024"])
    def test_accepts_sigma_bounds(self, params):
        rng = SeededRNG(11)
        sample_integer_gaussian(0.0, params.sigma_min, params, rng)
        sample_integer_gaussian(0.0, params.sigma_max, params, rng)

    @pytest.mark.parametrize("sigma", [1.0, 1.277833696, 1.8206, 2.5, 0.0, -1.5])
    def test_rejects_sigma_outside_bounds(self, sigma):
        with pytest.raises(ValueError):
            sample_integer_gaussian(0.0, sigma, FALCON_512, SeededRNG(12))
