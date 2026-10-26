"""Sampler-Tests gegen Tab. 3.2 und Sampler-Testvektoren.

Spec-Referenz: §3.9.3, Alg. 12–15, Tab. 3.1, Tab. 3.2, Gl. 3.32.
"""

import pytest
from falcon.sampler import (
    SystemRNG, SYSTEM_RNG, uniform_bits,
    base_sampler, approx_exp, ber_exp, sample_integer_gaussian,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestSystemRNG:
    """SystemRNG.random_bytes – Gl. 3.32."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestUniformBits:
    """uniform_bits – Gl. 3.32, Tab. 3.2."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestBaseSampler:
    """base_sampler – Alg. 12, Tab. 3.1."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestApproxExp:
    """approx_exp – Alg. 13."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestBerExp:
    """ber_exp – Alg. 14."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestSampleIntegerGaussian:
    """sample_integer_gaussian – Alg. 15."""

    def test_todo(self):
        raise NotImplementedError


@pytest.mark.skip(reason="Implementierung noch nicht abgeschlossen")
def test_sampler_against_table_3_2():
    """sample_integer_gaussian gegen Tab. 3.2."""
    raise NotImplementedError


@pytest.mark.skip(reason="Implementierung noch nicht abgeschlossen")
def test_sampler_test_vectors():
    """Sampler-Testvektoren aus dem NIST-Paket."""
    raise NotImplementedError
