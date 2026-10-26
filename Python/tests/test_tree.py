"""Tests für tree.py – geheime Basis und Falcon-Baum.

Spec-Referenz: §3.4.2, §3.8.3, Alg. 4 (Z. 2–7), Alg. 8, Alg. 9.
"""

import pytest
from falcon.tree import (
    build_basis_fft, build_falcon_tree, gram_matrix,
    ldl, ff_ldl, normalize_leaves,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestBuildBasisFft:
    """build_basis_fft – Alg. 4, Z. 2–3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestBuildFalconTree:
    """build_falcon_tree – Alg. 4, Z. 4–7."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestGramMatrix:
    """gram_matrix – Alg. 4, Z. 4."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestLdl:
    """ldl – Alg. 8."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFfLdl:
    """ff_ldl – Alg. 9."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestNormalizeLeaves:
    """normalize_leaves – Alg. 4, Z. 6–7."""

    def test_todo(self):
        raise NotImplementedError
