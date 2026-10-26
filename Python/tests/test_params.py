"""Tests für params.py – Parametersätze.

Spec-Referenz: Tabelle 3.3, §3.11.4, §3.11.5, §3.13.
"""

import pytest
from falcon.params import Params, FALCON_512, FALCON_1024

TODO = pytest.mark.skip(reason="Testfälle noch nicht definiert")


@TODO
class TestParamSets:
    """FALCON_512 / FALCON_1024 – Werte gegen Tab. 3.3."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestPkBytes:
    """Params.pk_bytes – §3.11.4."""

    def test_todo(self):
        raise NotImplementedError


@TODO
class TestSkHeaderByte:
    """Params.sk_header_byte – §3.11.5."""

    def test_todo(self):
        raise NotImplementedError
