"""Tests für ntrugen.py – Erzeugung von f, g, F, G.

Spec-Referenz: §3.8.2, §4.4.3, Alg. 5–7, Gl. 3.25, 3.28, 3.29, 3.35.
"""

import pytest
from falcon.ntrugen import (
    generate_ntru_keys, sample_short_poly, gram_schmidt_norm,
    solve_ntru, field_norm, xgcd, reduce, recompute_G,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestGenerateNtruKeys:
    """generate_ntru_keys – Alg. 5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestSampleShortPoly:
    """sample_short_poly – Alg. 5, Z. 1–6; Gl. 3.29."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestGramSchmidtNorm:
    """gram_schmidt_norm – Gl. 3.28."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestSolveNtru:
    """solve_ntru – Alg. 6, §4.4.3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFieldNorm:
    """field_norm – Gl. 3.25."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestXgcd:
    """xgcd – Alg. 6, Z. 2."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestReduce:
    """reduce – Alg. 7, §4.4.3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestRecomputeG:
    """recompute_G – Gl. 3.35."""

    def test_todo(self):
        raise NotImplementedError
