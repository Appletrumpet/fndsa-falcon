"""
Falcon (FN-DSA) – Python-Implementierung nach Spec v1.2.

Top-Level-Exports:
    keygen, sign, verify
    FALCON_512, FALCON_1024
    SecretKey, PublicKey, Signature
"""

from .params import FALCON_512, FALCON_1024
from .datatypes import SecretKey, PublicKey, Signature
from .falcon import keygen, sign, verify, load_secret_key

__all__ = [
    "FALCON_512", "FALCON_1024",
    "SecretKey", "PublicKey", "Signature",
    "keygen", "sign", "verify", "load_secret_key",
]