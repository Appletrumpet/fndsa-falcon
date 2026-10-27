"""Tests für encoding.py – Kompression und Byteformate.

Spec-Referenz: §3.11.1 (Bits und Bytes), §3.11.2 (Alg. 17, Alg. 18),
§3.11.3 (Signaturen), §3.11.4 (Public Key), §3.11.5 (Secret Key),
§3.11.6 (NIST-API / KAT). Doku: Falcon_Documentation §6.8, §7.

Formate:
  - Bits werden von links nach rechts in Bytes gefüllt, oberstes Bit zuerst;
    Füllbits am Ende MÜSSEN 0 sein (§3.11.1).
  - Komprimiertes s: je Koeffizient Vorzeichen, 7 tiefe Bits von |s|, dann
    ⌊|s|/2⁷⌋ = k unär als 0ᵏ1 (Alg. 17). slen = 8·sbytelen − 328 Bit
    (= sbytelen − 41 Bytes: 1 Header + 40 Salt).
  - Signatur: Header 0cc1nnnn mit cc = 01 (komprimiert) → 0x39 / 0x3A,
    dann Salt (40 Bytes), dann komprimiertes s (§3.11.3).
  - Public Key: Header 0000nnnn → 0x09 / 0x0A, 14 Bit je Koeffizient (§3.11.4).
  - Secret Key: Header 0101nnnn → 0x59 / 0x5A, f, g mit 8/7/6/5 Bit (je nach n),
    F mit 8 Bit, Zweierkomplement, Minimalwert verboten (§3.11.5).
  - KAT: 2 Bytes Signaturlänge, Nonce, Nachricht, Signatur mit Header 0010nnnn
    (0x29 / 0x2A), ohne Padding (§3.11.6).

Entscheidungen (siehe ENTSCHEIDUNGEN.md):
  - decompress: gepolstert (genau slen) und ungepolstert (Ende im letzten Byte,
    Restbits 0) gültig, auch länger als slen (KAT Falcon-1024 count = 82);
    teilweises Padding ungültig. Ungültig → None (Scaffold: Optional).
  - Dekodierfunktionen für Schlüssel/Signaturen: ungültig → ValueError.
  - encode_sig / decode_sig erhalten params (Header braucht n).
  - Unkomprimiertes Signaturformat (cc = 10) wird nicht unterstützt → ValueError.
"""

import dataclasses
import random

import pytest
from falcon.datatypes import Signature
from falcon.encoding import (
    compress, decompress,
    encode_pk, decode_pk,
    encode_sk, decode_sk,
    encode_sig, decode_sig,
    decode_kat_message,
)
from falcon.params import FALCON_512, FALCON_1024
from falcon.poly import poly_mul
from support import load_kat

Q = 12289
PARAMS_BY_N = {512: FALCON_512, 1024: FALCON_1024}
KAT_SETS = pytest.mark.parametrize("n", [512, 1024], ids=["falcon512", "falcon1024"])
PARAM_SETS = pytest.mark.parametrize(
    "params", [FALCON_512, FALCON_1024], ids=["FALCON_512", "FALCON_1024"]
)
ALL_LOGN = pytest.mark.parametrize("logn", range(1, 11))

# §3.11.5: Bitbreite für f und g je nach Grad
FG_BITS = {2: 8, 4: 8, 8: 8, 16: 8, 32: 8, 64: 7, 128: 7, 256: 6, 512: 6, 1024: 5}


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

def bits(*fields: str) -> bytes:
    """Bitfolge (als '0'/'1'-Strings) in Bytes, oberstes Bit zuerst,
    mit Nullen auf volle Bytes aufgefüllt (§3.11.1)."""
    s = "".join(f.replace(" ", "") for f in fields)
    s += "0" * (-len(s) % 8)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def sig_params(n: int, sbytelen: int):
    """Reduzierte Parameter für kleine Kompressionsbeispiele."""
    return dataclasses.replace(FALCON_512, n=n, sig_bytelen=sbytelen)


def padded_len(params) -> int:
    """Länge des gepolsterten komprimierten s in Bytes: slen/8 = sbytelen − 41."""
    return params.sig_bytelen - 41


def rand_signature_poly(rng: random.Random, n: int, sigma: float = 165.7) -> list:
    """Kurzes s₂ mit typischer Verteilung (§3.11.2: σ ≈ 1.55·√q)."""
    return [round(rng.gauss(0, sigma)) for _ in range(n)]


def kat_signature_parts(rec, n):
    """(Header, s ohne Header) der KAT-Signatur (§3.11.6)."""
    siglen = int.from_bytes(rec.sm[:2], "big")
    sig = rec.sm[2 + 40 + len(rec.msg):]
    assert len(sig) == siglen
    return sig[0], sig[1:]


@pytest.fixture
def rng():
    return random.Random(0xC0DE)


# Beispiel für Kompression, n = 4 (von Hand nach Alg. 17):
#   s₀ =   1: 0 0000001 1          (9 Bit)
#   s₁ =  −1: 1 0000001 1          (9 Bit)
#   s₂ =   0: 0 0000000 1          (9 Bit)
#   s₃ = 130: 0 0000010 01         (10 Bit: 130 = 2⁷ + 2 → tiefe Bits 2, k = 1)
#   zusammen 37 Bit → mit Nullen auf 40: 01 C0 C0 20 48
EX_S = [1, -1, 0, 130]
EX_BITS = ("0 0000001 1", "1 0000001 1", "0 0000000 1", "0 0000010 01")
EX_BYTES = bytes.fromhex("01c0c02048")


class TestHelpers:
    def test_bits_helper(self):
        assert bits("1", "0000000") == b"\x80"
        assert bits("1") == b"\x80"
        assert bits("00000001", "1") == b"\x01\x80"

    def test_example_bytes(self):
        assert bits(*EX_BITS) == EX_BYTES


# ---------------------------------------------------------------------------
# compress
# ---------------------------------------------------------------------------

class TestCompress:
    """compress – Alg. 17: auf slen = 8·sbytelen − 328 Bit gepolstert, sonst None."""

    def test_example(self):
        # sbytelen = 46 → slen = 40 Bit = 5 Bytes
        assert compress(EX_S, sig_params(4, 46)) == EX_BYTES

    def test_example_padded_with_zero_bytes(self):
        # sbytelen = 50 → 9 Bytes, Rest Nullbytes
        assert compress(EX_S, sig_params(4, 50)) == EX_BYTES + bytes(4)

    def test_exact_fit(self):
        # s₃ = 514 = 4·2⁷ + 2 → 0 0000010 00001 (13 Bit); 27 + 13 = 40 Bit = slen
        assert compress([1, -1, 0, 514], sig_params(4, 46)) == bits(
            "0 0000001 1", "1 0000001 1", "0 0000000 1", "0 0000010 00001"
        )

    def test_one_bit_too_long_gives_none(self):
        # s₃ = 642 = 5·2⁷ + 2 → 14 Bit; 41 > 40
        assert compress([1, -1, 0, 642], sig_params(4, 46)) is None

    def test_too_long_gives_none(self):
        # Beispiel braucht 37 Bit, slen = 32
        assert compress(EX_S, sig_params(4, 45)) is None

    def test_zero_has_positive_sign(self):
        # Alg. 17 Z. 3: b = 1 nur für s < 0 → 0 wird als 0 0000000 1 kodiert
        assert compress([0, 0], sig_params(2, 44)) == bits("0 0000000 1", "0 0000000 1")

    @pytest.mark.parametrize("v, field", [
        (127, "0 1111111 1"),          # grösster Wert ohne unären Anteil
        (128, "0 0000000 01"),         # erster Wert mit k = 1
        (-128, "1 0000000 01"),
        (255, "0 1111111 01"),
        (2047, "0 1111111 0000000000000001"),  # k = 15
    ])
    def test_single_coefficient_boundaries(self, v, field):
        assert compress([v, 0], sig_params(2, 46)) == bits(field, "0 0000000 1") + bytes(
            5 - len(bits(field, "0 0000000 1"))
        )

    @PARAM_SETS
    def test_output_length_is_padded_length(self, rng, params):
        out = compress(rand_signature_poly(rng, params.n), params)
        assert out is not None
        assert type(out) is bytes and len(out) == padded_len(params)

    @PARAM_SETS
    def test_padded_length_from_spec(self, params):
        # 625 / 1239 Bytes (sbytelen 666 / 1280 minus Header und Salt)
        assert padded_len(params) == {512: 625, 1024: 1239}[params.n]

    @KAT_SETS
    def test_kat_signatures_recompress_to_padded(self, n):
        # KAT-Signaturen sind ungepolstert: compress(decompress(s)) = s + Nullbytes.
        # Ausnahme Falcon-1024 count = 82: 1240 Bytes > 1239 → compress liefert None.
        params = PARAMS_BY_N[n]
        for rec in load_kat(n):
            _, s_enc = kat_signature_parts(rec, n)
            s = decompress(s_enc, params)
            out = compress(s, params)
            if len(s_enc) > padded_len(params):
                assert out is None, f"count {rec.count}"
            else:
                assert out == s_enc + bytes(padded_len(params) - len(s_enc)), f"count {rec.count}"

    def test_kat_1024_count_82_too_long(self):
        rec = load_kat(1024)[82]
        _, s_enc = kat_signature_parts(rec, 1024)
        assert len(s_enc) == 1240
        assert compress(decompress(s_enc, FALCON_1024), FALCON_1024) is None

    def test_does_not_mutate_input(self):
        s = list(EX_S)
        compress(s, sig_params(4, 46))
        assert s == EX_S


# ---------------------------------------------------------------------------
# decompress
# ---------------------------------------------------------------------------

class TestDecompress:
    """decompress – Alg. 18 und §3.11.3."""

    # --- Gültige Kodierungen ------------------------------------------------------

    def test_example_padded(self):
        assert decompress(EX_BYTES, sig_params(4, 46)) == EX_S

    def test_example_padded_with_zero_bytes(self):
        assert decompress(EX_BYTES + bytes(4), sig_params(4, 50)) == EX_S

    def test_example_unpadded(self):
        # §3.11.3: ungepolstert = endet im letzten Byte, Restbits 0
        assert decompress(EX_BYTES, sig_params(4, 50)) == EX_S

    def test_unpadded_longer_than_slen(self):
        # Wie KAT Falcon-1024 count = 82: 5 Bytes bei slen = 4 Bytes
        assert decompress(EX_BYTES, sig_params(4, 45)) == EX_S

    @PARAM_SETS
    def test_roundtrip(self, rng, params):
        for _ in range(5):
            s = rand_signature_poly(rng, params.n)
            enc = compress(s, params)
            assert enc is not None
            assert decompress(enc, params) == s

    @KAT_SETS
    def test_all_kat_signatures(self, n):
        params = PARAMS_BY_N[n]
        for rec in load_kat(n):
            _, s_enc = kat_signature_parts(rec, n)
            s = decompress(s_enc, params)
            assert s is not None, f"count {rec.count}"
            assert len(s) == n and all(type(c) is int for c in s)

    def test_kat_1024_count_82_accepted(self):
        _, s_enc = kat_signature_parts(load_kat(1024)[82], 1024)
        assert decompress(s_enc, FALCON_1024) is not None

    # --- Eindeutigkeit (Alg. 18) -------------------------------------------------------

    def test_rejects_negative_zero(self):
        # Alg. 18 Z. 9–10: 1 0000000 1 ist keine gültige Kodierung von 0
        params = sig_params(2, 44)
        assert decompress(bits("0 0000000 1", "0 0000000 1"), params) == [0, 0]
        assert decompress(bits("1 0000000 1", "0 0000000 1"), params) is None

    def test_rejects_nonzero_padding_bits(self):
        # Alg. 18 Z. 12–13: 0x48 = 01001|000 → 0x49 setzt ein Füllbit
        assert decompress(EX_BYTES[:-1] + b"\x49", sig_params(4, 46)) is None

    def test_rejects_nonzero_padding_byte(self):
        assert decompress(EX_BYTES + b"\x00\x00\x01\x00", sig_params(4, 50)) is None

    def test_rejects_nonzero_tail_bits_unpadded(self):
        # Restbits im letzten Byte: 0x4C = 01001|100
        assert decompress(EX_BYTES[:-1] + b"\x4c", sig_params(4, 50)) is None

    # --- Länge ------------------------------------------------------------------------

    @pytest.mark.parametrize("extra", [1, 2, 3])
    def test_rejects_partial_padding(self, extra):
        # §3.11.3: Padding nur vollständig bis slen; 5 + 1..3 Nullbytes bei slen = 9
        assert decompress(EX_BYTES + bytes(extra), sig_params(4, 50)) is None

    def test_rejects_padding_beyond_slen(self):
        assert decompress(EX_BYTES + bytes(5), sig_params(4, 50)) is None

    def test_rejects_truncated(self):
        # Letztes Byte fehlt → s₃ unvollständig
        assert decompress(EX_BYTES[:-1], sig_params(4, 50)) is None

    def test_rejects_unterminated_unary(self):
        # Nur Nullen: der unäre Teil endet nie
        assert decompress(bytes(3), sig_params(2, 44)) is None

    def test_rejects_empty(self):
        assert decompress(b"", FALCON_512) is None

    @PARAM_SETS
    def test_rejects_truncated_real_signature(self, rng, params):
        enc = compress(rand_signature_poly(rng, params.n), params)
        unpadded = enc.rstrip(b"\x00")
        assert decompress(unpadded[:-1], params) is None

    @PARAM_SETS
    def test_rejects_padded_plus_one_byte(self, rng, params):
        enc = compress(rand_signature_poly(rng, params.n), params)
        assert decompress(enc + b"\x00", params) is None


# ---------------------------------------------------------------------------
# encode_pk / decode_pk
# ---------------------------------------------------------------------------

class TestEncodePk:
    """encode_pk – §3.11.4: Header 0000nnnn, 14 Bit je Koeffizient."""

    def test_example_n2(self):
        # Header 0x01 (ℓ = 1); 1 → 00000000000001, 12288 → 11000000000000, 4 Füllbits
        assert encode_pk([1, 12288]) == b"\x01" + bits("00000000000001", "11000000000000")
        assert encode_pk([1, 12288]) == bytes.fromhex("0100070000")

    def test_example_n4(self):
        h = [12288, 0, 1, 4096]
        expected = b"\x02" + bits(
            "11000000000000", "00000000000000", "00000000000001", "01000000000000"
        )
        assert encode_pk(h) == expected

    @KAT_SETS
    def test_kat_roundtrip(self, n):
        for rec in load_kat(n):
            assert encode_pk(decode_pk(rec.pk)) == rec.pk, f"count {rec.count}"

    @PARAM_SETS
    def test_header_and_length(self, rng, params):
        h = [rng.randrange(Q) for _ in range(params.n)]
        out = encode_pk(h)
        assert out[0] == {512: 0x09, 1024: 0x0A}[params.n]
        assert len(out) == {512: 897, 1024: 1793}[params.n]

    @ALL_LOGN
    def test_header_and_length_all_degrees(self, logn):
        n = 1 << logn
        out = encode_pk([0] * n)
        assert out[0] == logn
        assert len(out) == 1 + (14 * n + 7) // 8

    @pytest.mark.parametrize("bad", [Q, Q + 1, 2 ** 14 - 1, -1])
    def test_rejects_value_out_of_range(self, bad):
        with pytest.raises(ValueError):
            encode_pk([0, bad, 0, 0])

    @pytest.mark.parametrize("n", [0, 1, 3, 2048])
    def test_rejects_invalid_degree(self, n):
        # n = 2^ℓ mit 1 ≤ ℓ ≤ 10
        with pytest.raises(ValueError):
            encode_pk([0] * n)


class TestDecodePk:
    """decode_pk – Umkehrung von encode_pk, lehnt ungültige Kodierungen ab."""

    def test_example_n2(self):
        assert decode_pk(bytes.fromhex("0100070000")) == [1, 12288]

    @KAT_SETS
    def test_kat_keys(self, n):
        for rec in load_kat(n):
            h = decode_pk(rec.pk)
            assert len(h) == n
            assert all(type(c) is int and 0 <= c < Q for c in h)

    @KAT_SETS
    def test_kat_key_matches_secret_key(self, n):
        # h = g/f mod q ⇔ h·f ≡ g (mod q) – prüft, dass decode_pk und decode_sk
        # nicht nur symmetrisch, sondern inhaltlich richtig dekodieren
        for rec in load_kat(n)[:3]:
            h = decode_pk(rec.pk)
            f, g, _ = decode_sk(rec.sk)
            assert [c % Q for c in poly_mul(h, f)] == [c % Q for c in g], f"count {rec.count}"

    # --- Ungültig --------------------------------------------------------------------

    @pytest.mark.parametrize("header", [0x19, 0x89, 0x59, 0x39])
    def test_rejects_wrong_header_type(self, header):
        with pytest.raises(ValueError):
            decode_pk(bytes([header]) + bytes(896))

    @pytest.mark.parametrize("header", [0x00, 0x0B, 0x0F])
    def test_rejects_logn_out_of_range(self, header):
        with pytest.raises(ValueError):
            decode_pk(bytes([header]) + bytes(896))

    @pytest.mark.parametrize("delta", [-1, 1])
    def test_rejects_wrong_length(self, delta):
        good = load_kat(512)[0].pk
        bad = good[:-1] if delta < 0 else good + b"\x00"
        with pytest.raises(ValueError):
            decode_pk(bad)

    @pytest.mark.parametrize("value", ["11000000000001", "11111111111111"])  # q, 2¹⁴−1
    def test_rejects_coefficient_not_below_q(self, value):
        with pytest.raises(ValueError):
            decode_pk(b"\x01" + bits(value, "00000000000000"))

    def test_rejects_nonzero_padding_bits(self):
        # n = 2: 28 Bit Daten + 4 Füllbits, letztes Byte 0x00 → 0x01
        with pytest.raises(ValueError):
            decode_pk(bytes.fromhex("0100070001"))

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            decode_pk(b"")


# ---------------------------------------------------------------------------
# encode_sk / decode_sk
# ---------------------------------------------------------------------------

def zero_sk(n):
    return [0] * n, [0] * n, [0] * n


class TestEncodeSk:
    """encode_sk – §3.11.5: Header 0101nnnn, f/g mit 8/7/6/5 Bit, F mit 8 Bit."""

    def test_example_n2(self):
        # n = 2 → 8 Bit je Koeffizient, Zweierkomplement:
        #   f = [1, −1] → 01 FF, g = [0, −127] → 00 81, F = [127, −127] → 7F 81
        assert encode_sk([1, -1], [0, -127], [127, -127]) == bytes.fromhex("5101ff00817f81")

    def test_example_six_bits_n512(self):
        # n = 512 → 6 Bit: −31 → 100001, 31 → 011111, 0 → 000000, −1 → 111111
        #   → 10000101 11110000 00111111 = 85 F0 3F
        f = [-31, 31, 0, -1] + [0] * 508
        out = encode_sk(f, [0] * 512, [0] * 512)
        assert out[:4] == bytes.fromhex("59" "85f03f")

    def test_example_five_bits_n1024(self):
        # n = 1024 → 5 Bit: 15 → 01111, −15 → 10001 → 01111100 01... = 7C 4…
        f = [15, -15] + [0] * 1022
        out = encode_sk(f, [0] * 1024, [0] * 1024)
        assert out[:3] == b"\x5a" + bits("01111", "10001", "000000")

    def test_field_order_f_g_F(self):
        # §3.11.5: f, g, F in dieser Reihenfolge
        out = encode_sk([1, 0], [2, 0], [3, 0])
        assert out == bytes.fromhex("51" "0100" "0200" "0300")

    @KAT_SETS
    def test_kat_roundtrip(self, n):
        for rec in load_kat(n):
            assert encode_sk(*decode_sk(rec.sk)) == rec.sk, f"count {rec.count}"

    @ALL_LOGN
    def test_header_and_length_all_degrees(self, logn):
        n = 1 << logn
        out = encode_sk(*zero_sk(n))
        assert out[0] == 0x50 | logn
        assert len(out) == 1 + (2 * n * FG_BITS[n]) // 8 + n

    @PARAM_SETS
    def test_kat_lengths(self, params):
        assert len(encode_sk(*zero_sk(params.n))) == {512: 1281, 1024: 2305}[params.n]

    @ALL_LOGN
    def test_extreme_allowed_values_roundtrip(self, logn):
        n = 1 << logn
        m = 2 ** (FG_BITS[n] - 1) - 1          # grösster erlaubter Betrag für f, g
        f = [m, -m] * (n // 2)
        g = [-m, m] * (n // 2)
        F = [127, -127] * (n // 2)
        assert decode_sk(encode_sk(f, g, F)) == (f, g, F)

    # --- Ungültig --------------------------------------------------------------------

    @pytest.mark.parametrize("value", [-32, 32, 100])
    def test_rejects_f_out_of_range_n512(self, value):
        # 6 Bit: gültig −31 … 31, −32 verboten (§3.11.5)
        f = [value] + [0] * 511
        with pytest.raises(ValueError):
            encode_sk(f, [0] * 512, [0] * 512)

    @pytest.mark.parametrize("value", [-32, 32])
    def test_rejects_g_out_of_range_n512(self, value):
        with pytest.raises(ValueError):
            encode_sk([0] * 512, [value] + [0] * 511, [0] * 512)

    @pytest.mark.parametrize("value", [-16, 16])
    def test_rejects_f_out_of_range_n1024(self, value):
        with pytest.raises(ValueError):
            encode_sk([value] + [0] * 1023, [0] * 1024, [0] * 1024)

    @pytest.mark.parametrize("value", [-128, 128])
    def test_rejects_F_out_of_range(self, value):
        with pytest.raises(ValueError):
            encode_sk([0] * 512, [0] * 512, [value] + [0] * 511)

    def test_rejects_mismatched_lengths(self):
        with pytest.raises(ValueError):
            encode_sk([0] * 512, [0] * 512, [0] * 256)

    @pytest.mark.parametrize("n", [0, 1, 3, 2048])
    def test_rejects_invalid_degree(self, n):
        with pytest.raises(ValueError):
            encode_sk(*zero_sk(n))


class TestDecodeSk:
    """decode_sk – Umkehrung von encode_sk, lehnt ungültige Kodierungen ab."""

    def test_example_n2(self):
        assert decode_sk(bytes.fromhex("5101ff00817f81")) == ([1, -1], [0, -127], [127, -127])

    @KAT_SETS
    def test_kat_keys(self, n):
        bound = 2 ** (FG_BITS[n] - 1) - 1
        for rec in load_kat(n):
            f, g, F = decode_sk(rec.sk)
            assert len(f) == len(g) == len(F) == n
            assert all(-bound <= c <= bound for c in f + g)
            assert all(-127 <= c <= 127 for c in F)

    # --- Ungültig --------------------------------------------------------------------

    @pytest.mark.parametrize("header", [0x09, 0x39, 0xD9, 0x19])
    def test_rejects_wrong_header_type(self, header):
        with pytest.raises(ValueError):
            decode_sk(bytes([header]) + bytes(1280))

    @pytest.mark.parametrize("header", [0x50, 0x5B, 0x5F])
    def test_rejects_logn_out_of_range(self, header):
        with pytest.raises(ValueError):
            decode_sk(bytes([header]) + bytes(1280))

    @pytest.mark.parametrize("delta", [-1, 1])
    def test_rejects_wrong_length(self, delta):
        good = load_kat(512)[0].sk
        bad = good[:-1] if delta < 0 else good + b"\x00"
        with pytest.raises(ValueError):
            decode_sk(bad)

    def test_rejects_minimum_value_in_f(self):
        # n = 512: 100000 = −32 ist verboten
        bad = b"\x59" + bits("100000") + bytes(1279)
        with pytest.raises(ValueError):
            decode_sk(bad)

    def test_rejects_minimum_value_in_g(self):
        # g beginnt nach 512·6 Bit = 384 Bytes
        bad = b"\x59" + bytes(384) + bits("100000") + bytes(895)
        with pytest.raises(ValueError):
            decode_sk(bad)

    def test_rejects_minimum_value_in_F(self):
        # F beginnt nach 2·384 Bytes; 0x80 = −128 verboten
        bad = b"\x59" + bytes(768) + b"\x80" + bytes(511)
        with pytest.raises(ValueError):
            decode_sk(bad)

    def test_rejects_minimum_value_n2(self):
        # n = 2: 8 Bit, 0x80 = −128 verboten
        with pytest.raises(ValueError):
            decode_sk(bytes.fromhex("5180000000" "0000"))

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            decode_sk(b"")


# ---------------------------------------------------------------------------
# encode_sig / decode_sig
# ---------------------------------------------------------------------------

SALT = bytes(range(40))


def example_signature(rng, params):
    s2 = rand_signature_poly(rng, params.n)
    return Signature(salt=SALT, s2_encoded=compress(s2, params))


class TestEncodeSig:
    """encode_sig – §3.11.3: Header 0cc1nnnn (cc = 01) + Salt + komprimiertes s₂."""

    @PARAM_SETS
    def test_layout(self, rng, params):
        sig = example_signature(rng, params)
        out = encode_sig(sig, params)
        assert out[0] == {512: 0x39, 1024: 0x3A}[params.n]
        assert out[1:41] == SALT
        assert out[41:] == sig.s2_encoded

    @PARAM_SETS
    def test_padded_length_is_sig_bytelen(self, rng, params):
        # 666 / 1280 Bytes (Tab. 3.3)
        assert len(encode_sig(example_signature(rng, params), params)) == params.sig_bytelen

    @ALL_LOGN
    def test_header_all_degrees(self, logn):
        params = dataclasses.replace(FALCON_512, n=1 << logn)
        out = encode_sig(Signature(salt=SALT, s2_encoded=b"\x80"), params)
        assert out[0] == 0x30 | logn

    def test_unpadded_s2_kept_as_is(self):
        sig = Signature(salt=SALT, s2_encoded=b"\x12\x34")
        assert encode_sig(sig, FALCON_512) == b"\x39" + SALT + b"\x12\x34"

    @pytest.mark.parametrize("salt_len", [0, 39, 41])
    def test_rejects_wrong_salt_length(self, salt_len):
        with pytest.raises(ValueError):
            encode_sig(Signature(salt=bytes(salt_len), s2_encoded=b"\x80"), FALCON_512)


class TestDecodeSig:
    """decode_sig – Umkehrung von encode_sig; Header muss zu params passen."""

    @PARAM_SETS
    def test_roundtrip(self, rng, params):
        sig = example_signature(rng, params)
        assert decode_sig(encode_sig(sig, params), params) == sig

    def test_unpadded(self):
        sig = decode_sig(b"\x39" + SALT + b"\x12\x34", FALCON_512)
        assert sig == Signature(salt=SALT, s2_encoded=b"\x12\x34")

    def test_longer_than_sig_bytelen_allowed(self):
        # Ungepolstert darf länger sein (KAT Falcon-1024 count = 82: 1281 > 1280)
        _, s_enc = kat_signature_parts(load_kat(1024)[82], 1024)
        b = b"\x3a" + SALT + s_enc
        assert len(b) == 1281
        assert decode_sig(b, FALCON_1024).s2_encoded == s_enc

    # --- Ungültig --------------------------------------------------------------------

    def test_rejects_header_for_other_degree(self):
        with pytest.raises(ValueError):
            decode_sig(b"\x3a" + SALT + b"\x80", FALCON_512)

    @pytest.mark.parametrize("header, why", [
        (0x59, "cc = 10: unkomprimiertes Format, nicht unterstützt"),
        (0x19, "cc = 00"),
        (0x79, "cc = 11"),
        (0x29, "viertes Bit 0: KAT-Format ohne Nonce"),
        (0xB9, "oberstes Bit 1"),
        (0x30, "ℓ = 0"),
        (0x3B, "ℓ = 11"),
    ])
    def test_rejects_invalid_header(self, header, why):
        with pytest.raises(ValueError):
            decode_sig(bytes([header]) + SALT + b"\x80", FALCON_512)

    @pytest.mark.parametrize("length", [0, 1, 40, 41])
    def test_rejects_too_short(self, length):
        # Header + 40 Bytes Salt + mindestens 1 Byte s
        with pytest.raises(ValueError):
            decode_sig((b"\x39" + SALT)[:length], FALCON_512)


# ---------------------------------------------------------------------------
# decode_kat_message
# ---------------------------------------------------------------------------

class TestDecodeKatMessage:
    """decode_kat_message – §3.11.6: Länge (2 Bytes), Nonce, Nachricht,
    Signatur mit Header 0010nnnn ohne Nonce und ohne Padding."""

    def test_example(self):
        # Signatur = Header 0x29 + s (3 Bytes) → Länge 4
        sm = b"\x00\x04" + SALT + b"hello" + b"\x29\xaa\xbb\xcc"
        msg, sig = decode_kat_message(sm)
        assert msg == b"hello"
        assert sig == Signature(salt=SALT, s2_encoded=b"\xaa\xbb\xcc")

    def test_empty_message(self):
        msg, sig = decode_kat_message(b"\x00\x02" + SALT + b"\x29\x80")
        assert msg == b"" and sig.s2_encoded == b"\x80"

    @KAT_SETS
    def test_all_kat_records(self, n):
        params = PARAMS_BY_N[n]
        for rec in load_kat(n):
            msg, sig = decode_kat_message(rec.sm)
            assert msg == rec.msg, f"count {rec.count}"
            assert sig.salt == rec.sm[2:42]
            header, s_enc = kat_signature_parts(rec, n)
            assert header == {512: 0x29, 1024: 0x2A}[n]
            assert sig.s2_encoded == s_enc
            assert decompress(sig.s2_encoded, params) is not None

    def test_length_is_big_endian(self):
        # Länge 0x0102 = 258 Bytes Signatur
        sm = b"\x01\x02" + SALT + b"m" + b"\x29" + bytes(257)
        msg, sig = decode_kat_message(sm)
        assert msg == b"m" and len(sig.s2_encoded) == 257

    # --- Ungültig --------------------------------------------------------------------

    @pytest.mark.parametrize("header", [0x39, 0x59, 0x09, 0x20, 0x2B])
    def test_rejects_wrong_header(self, header):
        with pytest.raises(ValueError):
            decode_kat_message(b"\x00\x02" + SALT + bytes([header, 0x80]))

    def test_rejects_length_larger_than_data(self):
        with pytest.raises(ValueError):
            decode_kat_message(b"\x00\x50" + SALT + b"\x29\x80")

    @pytest.mark.parametrize("length", [0, 1, 2, 41, 42])
    def test_rejects_too_short(self, length):
        with pytest.raises(ValueError):
            decode_kat_message((b"\x00\x02" + SALT + b"\x29\x80")[:length])
