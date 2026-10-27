"""Tests für hashing.py – HashToPoint.

Spec-Referenz: §3.7, Alg. 3; §3.9.1 / Alg. 10 Z. 1–2 (Salt ‖ Nachricht).
Doku: Falcon_Documentation §6.7.

Alg. 3 mit q = 12289:
  k = ⌊2¹⁶ / q⌋ = 5, Annahmegrenze k·q = 61445
  SHAKE-256 über die Eingabe, dann wiederholt 16 Bit lesen (big-endian, §3.7):
    t < 61445 → cᵢ = t mod q, i += 1
    sonst     → t verwerfen (nicht reduzieren!), nächste 16 Bit
  bis n Koeffizienten vorliegen.

Die Spec selbst enthält keine Testvektoren für HashToPoint. Zwei Quellen:
  - Beispiele, die aus den rohen SHAKE-256-Bytes von Hand nachvollziehbar sind
    (Bytes → 16-Bit-Blöcke → annehmen/verwerfen → mod q).
  - Offizielle Vektoren aus dem NIST-Paket: test-vector-sampler-falcon{512,1024}.txt
    enthält „nonce“, „data“ und „hashed message“ = HashToPoint(nonce ‖ data).
Indirekt zusätzlich über die KAT-Verifikation geprüft (test_kat.py).
"""

import dataclasses
import hashlib

import pytest
from falcon.hashing import hash_to_point
from falcon.params import FALCON_512, FALCON_1024
from support import load_sampler_vectors

Q = 12289
KQ = 5 * Q  # 61445


def raw_chunks(data: bytes, m: int) -> list:
    """Erste m 16-Bit-Blöcke (big-endian) aus SHAKE-256(data)."""
    s = hashlib.shake_256(data).digest(2 * m)
    return [int.from_bytes(s[2 * i:2 * i + 2], "big") for i in range(m)]


def params_with_n(n: int):
    return dataclasses.replace(FALCON_512, n=n)


PARAM_SETS = pytest.mark.parametrize(
    "params", [FALCON_512, FALCON_1024], ids=["FALCON_512", "FALCON_1024"]
)


# ---------------------------------------------------------------------------
# Beispiele aus rohen SHAKE-Bytes prüfen (sonst sind die Beispiele nichts wert)
# ---------------------------------------------------------------------------

class TestExampleInputs:
    def test_empty_input_raw_bytes(self):
        # SHAKE-256("") beginnt mit 46 b9 dd 2b 0b a8 8d 13 23 3b 3f eb 74 3e eb 24
        assert hashlib.shake_256(b"").digest(16).hex() == "46b9dd2b0ba88d13233b3feb743eeb24"

    def test_reject_first_raw_bytes(self):
        # fd9d = 64925 ≥ 61445 → verworfen
        assert raw_chunks(b"Falcon\r", 4) == [64925, 24173, 56020, 61188]

    def test_reject_third_raw_bytes(self):
        assert raw_chunks(b"Falcon\x04", 6) == [26311, 2891, 63890, 37727, 23307, 16988]

    def test_boundary_raw_bytes(self):
        assert raw_chunks(bytes.fromhex("00011c0a"), 3) == [61444, 20026, 55187]
        assert raw_chunks(bytes.fromhex("000035af"), 3) == [61445, 35715, 18478]


# ---------------------------------------------------------------------------
# hash_to_point
# ---------------------------------------------------------------------------

class TestHashToPoint:
    """hash_to_point – Alg. 3."""

    # --- Beispiele von Hand ---------------------------------------------------

    def test_example_empty_input(self):
        # Blöcke 18105, 56619, 2984, 36115, 9019, 16363, 29758, 60196 (alle < 61445)
        #   mod q: 5816, 7463, 2984, 11537, 9019, 4074, 5180, 11040
        c = hash_to_point(b"", params_with_n(8))
        assert c == [5816, 7463, 2984, 11537, 9019, 4074, 5180, 11040]

    def test_big_endian(self):
        # Erster Block 0x46b9 = 18105 → 5816. Little-endian wäre 0xb946 = 47430 → 10563.
        assert hash_to_point(b"", params_with_n(2))[0] == 5816

    def test_rejected_first_chunk_is_skipped(self):
        # 64925 verworfen; 24173 → 11884, 56020 → 6864, 61188 → 12032.
        # Fehlerbild „reduzieren statt verwerfen“ ergäbe 64925 mod q = 3480 an erster Stelle.
        assert hash_to_point(b"Falcon\r", params_with_n(2)) == [11884, 6864]

    def test_rejected_middle_chunk_is_skipped(self):
        # 26311 → 1733, 2891 → 2891, 63890 verworfen, 37727 → 860, 23307 → 11018
        c = hash_to_point(b"Falcon\x04", params_with_n(4))
        assert c == [1733, 2891, 860, 11018]

    def test_boundary_61444_is_accepted(self):
        # Grösster angenommener Wert: 61444 = 4q + 12288 → q − 1
        c = hash_to_point(bytes.fromhex("00011c0a"), params_with_n(2))
        assert c == [12288, 7737]

    def test_boundary_61445_is_rejected(self):
        # Kleinster verworfener Wert: 61445 = 5q (wäre sonst 0)
        c = hash_to_point(bytes.fromhex("000035af"), params_with_n(2))
        assert c == [11137, 6189]

    # --- Offizielle Vektoren (NIST-Paket) -------------------------------------

    @PARAM_SETS
    def test_nist_vector(self, params):
        # Alg. 10 Z. 2: c = HashToPoint(r ‖ m) mit 40-Byte-Nonce r und m = b"data1"
        v = load_sampler_vectors(params.n)
        assert len(v.nonce) == 40
        assert hash_to_point(v.nonce + v.data, params) == v.hashed_message

    # --- Struktur der Ausgabe ---------------------------------------------------

    @PARAM_SETS
    def test_length_is_n(self, params):
        assert len(hash_to_point(b"msg", params)) == params.n

    @pytest.mark.parametrize("n", [2, 4, 16, 256])
    def test_length_for_reduced_degrees(self, n):
        assert len(hash_to_point(b"msg", params_with_n(n))) == n

    @PARAM_SETS
    def test_coefficients_are_ints_in_range(self, params):
        c = hash_to_point(b"range check", params)
        assert all(type(x) is int and 0 <= x < Q for x in c)

    @PARAM_SETS
    def test_deterministic(self, params):
        assert hash_to_point(b"same", params) == hash_to_point(b"same", params)

    @PARAM_SETS
    def test_different_inputs_differ(self, params):
        assert hash_to_point(b"message A", params) != hash_to_point(b"message B", params)

    def test_empty_input_allowed(self):
        assert len(hash_to_point(b"", FALCON_512)) == 512

    def test_long_input(self):
        assert len(hash_to_point(b"\xab" * 100_000, FALCON_512)) == 512

    # --- Ein Strom für alle Sicherheitsstufen (§3.7) -------------------------------

    def test_falcon_512_is_prefix_of_falcon_1024(self):
        # §3.7: ein XOF für alle Stufen, Hashen ohne Kenntnis der Stufe möglich
        # → die ersten 512 Koeffizienten sind identisch.
        data = b"\x00" * 40 + b"prefix property"
        assert hash_to_point(data, FALCON_1024)[:512] == hash_to_point(data, FALCON_512)

    @pytest.mark.parametrize("n", [2, 4, 64, 512])
    def test_prefix_property_for_all_degrees(self, n):
        data = b"tower"
        assert hash_to_point(data, params_with_n(2 * n))[:n] == hash_to_point(data, params_with_n(n))

    # --- Hashfunktion und Eingabe ---------------------------------------------------

    def test_uses_shake_256_not_shake_128(self):
        # SHAKE-128("") beginnt mit 7f9c… → 0x7f9c = 32668 → 8090
        c = hash_to_point(b"", params_with_n(2))
        assert c[0] != 32668 % Q

    def test_hashes_salt_then_message(self):
        # Alg. 10 Z. 2 / Alg. 16 Z. 1: Hash über r ‖ m, Reihenfolge zählt
        salt, msg = b"\x11" * 40, b"hello"
        assert hash_to_point(salt + msg, FALCON_512) != hash_to_point(msg + salt, FALCON_512)

    def test_single_bit_change_changes_output(self):
        a = b"\x00" * 40 + b"m"
        b = b"\x01" + b"\x00" * 39 + b"m"
        assert hash_to_point(a, FALCON_512) != hash_to_point(b, FALCON_512)

    def test_accepts_bytearray(self):
        assert hash_to_point(bytearray(b"abc"), FALCON_512) == hash_to_point(b"abc", FALCON_512)

    def test_rejects_str(self):
        # Text muss vorher kodiert werden; kein stillschweigendes Kodieren
        with pytest.raises(TypeError):
            hash_to_point("abc", FALCON_512)

    # --- Verteilung -------------------------------------------------------------------

    def test_roughly_uniform(self):
        # Durch das Verwerfen ist jeder Wert 0 … q−1 genau gleich wahrscheinlich.
        # 200 × 1024 = 204'800 Werte, 8 gleich grosse Bereiche: Erwartung je 25'600.
        # Abweichung > 3 % wäre bei Gleichverteilung praktisch ausgeschlossen
        # (Standardabweichung ≈ 150, also > 5σ). Feste Eingaben → nicht flaky.
        counts = [0] * 8
        for i in range(200):
            for x in hash_to_point(i.to_bytes(2, "big"), FALCON_1024):
                counts[x * 8 // Q] += 1
        expected = 200 * 1024 / 8
        assert all(abs(c - expected) < 0.03 * expected for c in counts)

    def test_rejection_rate(self):
        # Pro Block Annahmewahrscheinlichkeit 61445/65536 ≈ 93.76 %:
        # für n = 1024 Koeffizienten im Mittel ≈ 1092 Blöcke. Prüft indirekt, dass
        # wirklich verworfen wird: Die n Koeffizienten müssen den angenommenen
        # Blöcken des Stroms in Reihenfolge entsprechen.
        data = b"rejection rate"
        accepted = [t % Q for t in raw_chunks(data, 1300) if t < KQ]
        assert hash_to_point(data, FALCON_1024) == accepted[:1024]
