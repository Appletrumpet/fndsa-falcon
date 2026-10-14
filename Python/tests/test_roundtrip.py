"""Einfacher Roundtrip-Test: keygen → sign → verify."""

import pytest
from falcon import FALCON_512, keygen, sign, verify


@pytest.mark.skip(reason="Implementierung noch nicht abgeschlossen")
def test_roundtrip_512():
    message = b"Falcon Roundtrip Test"
    sk, pk = keygen(FALCON_512)
    sig = sign(sk, message, FALCON_512)
    assert verify(pk, message, sig, FALCON_512)


@pytest.mark.skip(reason="Implementierung noch nicht abgeschlossen")
def test_verify_rejects_wrong_message():
    message = b"Falcon Roundtrip Test"
    sk, pk = keygen(FALCON_512)
    sig = sign(sk, message, FALCON_512)
    assert not verify(pk, b"wrong message", sig, FALCON_512)