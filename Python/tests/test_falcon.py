"""Tests für falcon.py – öffentliche API und interne Bausteine.

Spec-Referenz: §3.8–§3.10, Alg. 4, Alg. 10, Alg. 16.
"""

import pytest
from falcon.falcon import (
    keygen, sign, verify, load_secret_key,
    compute_public_key, compute_target, compute_signature_vector,
    is_short_fft, to_coefficients, compute_s1, is_short,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


# ---------------------------------------------------------------------------
# Top-Level API
# ---------------------------------------------------------------------------

@TODO
class TestKeygen:
    """keygen – Alg. 4."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestSign:
    """sign – Alg. 10."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestVerify:
    """verify – Alg. 16."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestLoadSecretKey:
    """load_secret_key – §3.11.5, Alg. 4, Z. 2–7."""

    def test_todo(self):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Interne Bausteine
# ---------------------------------------------------------------------------

@TODO
class TestComputePublicKey:
    """compute_public_key – Alg. 4, Z. 9."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestComputeTarget:
    """compute_target – Alg. 10, Z. 3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestComputeSignatureVector:
    """compute_signature_vector – Alg. 10, Z. 7."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestIsShortFft:
    """is_short_fft – Alg. 10, Z. 8."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestToCoefficients:
    """to_coefficients – Alg. 10, Z. 9."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestComputeS1:
    """compute_s1 – Alg. 16, Z. 5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestIsShort:
    """is_short – Alg. 16, Z. 6."""

    def test_todo(self):
        raise NotImplementedError
