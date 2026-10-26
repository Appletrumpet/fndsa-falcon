"""Tests für fft.py – komplexe FFT, Splitten und Mergen.

Spec-Referenz: §3.5, §3.6, §4.2.1, Gl. 3.6, 3.8, 3.19, Alg. 1–2.
"""

import pytest
from falcon.fft import (
    fft, ifft, fft_add, fft_sub, fft_mul, fft_div,
    fft_adj, fft_norm_sq, split_fft, merge_fft,
)

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestFft:
    """fft – §3.5, §3.6, Gl. 3.19."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestIfft:
    """ifft – §3.5, §3.6."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFftAdd:
    """fft_add – §3.5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFftSub:
    """fft_sub – §3.5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFftMul:
    """fft_mul – §3.5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFftDiv:
    """fft_div – §3.5."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFftAdj:
    """fft_adj – Gl. 3.6, §4.2.1."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestFftNormSq:
    """fft_norm_sq – Gl. 3.8."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestSplitFft:
    """split_fft – Alg. 1."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestMergeFft:
    """merge_fft – Alg. 2."""

    def test_todo(self):
        raise NotImplementedError
