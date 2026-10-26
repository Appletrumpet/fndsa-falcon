"""Tests für encoding.py – Kompression und Byteformate.

Spec-Referenz: §3.11.3–§3.11.6, Alg. 17, Alg. 18.
"""

import pytest
from falcon.encoding import (
    compress, decompress,
    encode_pk, decode_pk,
    encode_sk, decode_sk,
    encode_sig, decode_sig,
    decode_kat_message,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestCompress:
    """compress – Alg. 17."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestDecompress:
    """decompress – Alg. 18, §3.11.3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestEncodePk:
    """encode_pk – §3.11.4."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestDecodePk:
    """decode_pk – §3.11.4."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestEncodeSk:
    """encode_sk – §3.11.5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestDecodeSk:
    """decode_sk – §3.11.5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestEncodeSig:
    """encode_sig – §3.11.3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestDecodeSig:
    """decode_sig – §3.11.3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestDecodeKatMessage:
    """decode_kat_message – §3.11.6."""

    def test_todo(self):
        raise NotImplementedError
