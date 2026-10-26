"""Tests für modq.py – Rechnen mod q = 12289 über NTT.

Spec-Referenz: §3.4.3, §3.5, §4.2.2, Alg. 5, Alg. 16.
"""

import pytest
from falcon.modq import (
    ntt, intt, mul_mod_q, div_mod_q, is_invertible_mod_q, center_mod_q,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestNtt:
    """ntt – §3.5, §4.2.2."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestIntt:
    """intt – §3.5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestMulModQ:
    """mul_mod_q – §4.2.2."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestDivModQ:
    """div_mod_q – §3.4.3, §4.2.2."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestIsInvertibleModQ:
    """is_invertible_mod_q – Alg. 5, Z. 7."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestCenterModQ:
    """center_mod_q – Alg. 16, Z. 5."""

    def test_todo(self):
        raise NotImplementedError
