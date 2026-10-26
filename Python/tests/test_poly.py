"""Tests für poly.py – Polynome in ℤ[x]/(xⁿ + 1).

Spec-Referenz: §3.1, §3.3, Gl. 3.10, Gl. 3.20, Alg. 6.
"""

import pytest
from falcon.poly import (
    poly_add, poly_sub, poly_neg, poly_mul,
    split, lift, galois_conjugate, norm_sq,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestPolyAdd:
    """poly_add – §3.1."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestPolySub:
    """poly_sub – §3.1."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestPolyNeg:
    """poly_neg – Alg. 4, Z. 2."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestPolyMul:
    """poly_mul – §3.1 (xⁿ = -1)."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestSplit:
    """split – Gl. 3.20."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestLift:
    """lift – Alg. 6, Z. 11–12."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestGaloisConjugate:
    """galois_conjugate – Alg. 6, Z. 11–12."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestNormSq:
    """norm_sq – Gl. 3.10."""

    def test_todo(self):
        raise NotImplementedError
