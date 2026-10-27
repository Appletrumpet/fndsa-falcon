"""Tests für datatypes.py – SecretKey, PublicKey, Signature.

Spec-Referenz: §3.4.2, §3.4.3, §3.11.3. Doku: Falcon_Documentation §5.1, §6.3.
"""

import dataclasses

import pytest
from falcon.datatypes import SecretKey, PublicKey, Signature


class TestSecretKey:
    """SecretKey – §3.4.2: Kern f, g, F, G; abgeleitet basis_fft und tree."""

    def test_fields_in_order(self):
        assert [f.name for f in dataclasses.fields(SecretKey)] == [
            "f", "g", "F", "G", "basis_fft", "tree",
        ]

    def test_derived_parts_default_to_none(self):
        # Doku §5.4: Basis und Baum werden aus f, g, F, G berechnet
        sk = SecretKey([1], [2], [3], [4])
        assert sk.basis_fft is None and sk.tree is None

    def test_positional_construction(self):
        sk = SecretKey([1], [2], [3], [4], "B", "T")
        assert (sk.f, sk.g, sk.F, sk.G, sk.basis_fft, sk.tree) == ([1], [2], [3], [4], "B", "T")

    def test_equality_by_value(self):
        assert SecretKey([1], [2], [3], [4]) == SecretKey([1], [2], [3], [4])
        assert SecretKey([1], [2], [3], [4]) != SecretKey([1], [2], [3], [5])


class TestPublicKey:
    """PublicKey – §3.4.3: h = g·f⁻¹ mod q."""

    def test_field(self):
        assert [f.name for f in dataclasses.fields(PublicKey)] == ["h"]
        assert PublicKey([5, 6]).h == [5, 6]

    def test_equality_by_value(self):
        assert PublicKey([1, 2]) == PublicKey([1, 2])
        assert PublicKey([1, 2]) != PublicKey([2, 1])


class TestSignature:
    """Signature – §3.11.3: Salt (40 Bytes) und komprimiertes s₂."""

    def test_fields(self):
        assert [f.name for f in dataclasses.fields(Signature)] == ["salt", "s2_encoded"]

    def test_keyword_construction(self):
        sig = Signature(salt=b"\x00" * 40, s2_encoded=b"\x80")
        assert sig.salt == b"\x00" * 40 and sig.s2_encoded == b"\x80"

    def test_equality_by_value(self):
        a = Signature(b"\x01" * 40, b"\x02")
        assert a == Signature(b"\x01" * 40, b"\x02")
        assert a != Signature(b"\x01" * 40, b"\x03")
