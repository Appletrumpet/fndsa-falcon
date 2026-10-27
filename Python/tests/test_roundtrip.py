"""Roundtrip-Tests: keygen → sign → verify, auch über die Byteformate.

Spec-Referenz: Alg. 4, Alg. 10, Alg. 16, §3.11.3–§3.11.5.
"""

import pytest
from falcon import FALCON_512, FALCON_1024, keygen, sign, verify, load_secret_key
from falcon.datatypes import PublicKey
from falcon.encoding import decode_pk, decode_sig, encode_pk, encode_sig, encode_sk
from support import SeededRNG

PARAM_SETS = pytest.mark.parametrize(
    "params",
    [FALCON_512, pytest.param(FALCON_1024, marks=pytest.mark.slow)],
    ids=["FALCON_512", "FALCON_1024"],
)


class _LazyKeys(dict):
    """Erzeugt jedes Schlüsselpaar erst bei Bedarf (keygen 1024 ist langsam)."""

    def __missing__(self, n):
        params = {512: FALCON_512, 1024: FALCON_1024}[n]
        self[n] = keygen(params, SeededRNG(n))
        return self[n]


@pytest.fixture(scope="module")
def keys():
    return _LazyKeys()


@PARAM_SETS
def test_roundtrip(params, keys):
    message = b"Falcon Roundtrip Test"
    sk, pk = keys[params.n]
    sig = sign(sk, message, params, SeededRNG(1))
    assert verify(pk, message, sig, params)


@PARAM_SETS
def test_verify_rejects_wrong_message(params, keys):
    message = b"Falcon Roundtrip Test"
    sk, pk = keys[params.n]
    sig = sign(sk, message, params, SeededRNG(2))
    assert not verify(pk, b"wrong message", sig, params)


@PARAM_SETS
def test_roundtrip_through_byte_formats(params, keys):
    # pk, sk und Signatur in Bytes und zurück; G wird beim Laden neu berechnet
    sk, pk = keys[params.n]
    pk2 = PublicKey(decode_pk(encode_pk(pk.h)))
    sk2 = load_secret_key(encode_sk(sk.f, sk.g, sk.F), params)
    assert sk2.G == sk.G
    message = b"bytes all the way"
    sig_bytes = encode_sig(sign(sk2, message, params, SeededRNG(3)), params)
    assert len(sig_bytes) == params.sig_bytelen
    assert verify(pk2, message, decode_sig(sig_bytes, params), params)


@PARAM_SETS
def test_many_messages(params, keys):
    sk, pk = keys[params.n]
    for i in range(5):
        m = f"message {i}".encode()
        assert verify(pk, m, sign(sk, m, params, SeededRNG(10 + i)), params)


@pytest.mark.slow
def test_signature_not_valid_for_other_parameter_set(keys):
    # Falcon-512-Signatur unter Falcon-1024-Parametern: Kodierung passt nicht → ablehnen
    sk, _ = keys[512]
    _, pk1024 = keys[1024]
    sig = sign(sk, b"m", FALCON_512, SeededRNG(4))
    assert verify(pk1024, b"m", sig, FALCON_1024) is False
