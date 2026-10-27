"""Tests für falcon/__init__.py – öffentliche Schnittstelle des Pakets.

Doku: Falcon_Documentation §5 (Ebene 2: Top-Level-Methoden und Datenstrukturen).
"""

import falcon
import falcon.datatypes
import falcon.falcon
import falcon.params

EXPECTED = [
    "FALCON_512", "FALCON_1024",
    "SecretKey", "PublicKey", "Signature",
    "keygen", "sign", "verify", "load_secret_key",
]


def test_all_lists_public_api():
    assert sorted(falcon.__all__) == sorted(EXPECTED)


def test_exports_are_the_module_objects():
    # Re-Exports, keine Kopien oder Wrapper
    assert falcon.keygen is falcon.falcon.keygen
    assert falcon.sign is falcon.falcon.sign
    assert falcon.verify is falcon.falcon.verify
    assert falcon.load_secret_key is falcon.falcon.load_secret_key
    assert falcon.SecretKey is falcon.datatypes.SecretKey
    assert falcon.PublicKey is falcon.datatypes.PublicKey
    assert falcon.Signature is falcon.datatypes.Signature
    assert falcon.FALCON_512 is falcon.params.FALCON_512
    assert falcon.FALCON_1024 is falcon.params.FALCON_1024


def test_star_import():
    ns = {}
    exec("from falcon import *", ns)
    assert all(name in ns for name in EXPECTED)
