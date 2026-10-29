"""
HashToPoint: Nachricht auf Polynom in ℤ_q[x]/(xⁿ+1) abbilden.

Verwendet SHAKE-256 (FIPS 202). Pro Koeffizient werden 16 Bits gelesen;
nur Werte < 5·q werden akzeptiert (Rejection Sampling), dann mod q.

Spec-Referenz: §3.7, Alg. 3.
Extern: SHAKE-256 aus hashlib.
"""

import hashlib
from typing import List
from .params import Params


def hash_to_point(data: bytes, params: Params) -> List[int]:
    """SHAKE-256, je 16 Bit lesen, Werte < 5q annehmen,
    Koeffizient = Wert mod q. Alg. 3."""
    if isinstance(data, str):
        raise TypeError("data muss Bytes sein, nicht str")

    n = params.n
    q = params.q
    limit = 5 * q

    shake = hashlib.shake_256(data)

    # Großzügige Startlänge; bei Bedarf wird der Stream verlängert.
    buf_len = max(64, int(2 * n * 1.2) + 64)
    buf = shake.digest(buf_len)
    pos = 0

    out: List[int] = []
    while len(out) < n:
        if pos + 2 > len(buf):
            buf_len *= 2
            buf = shake.digest(buf_len)

        chunk = int.from_bytes(buf[pos:pos + 2], "big")
        pos += 2

        if chunk < limit:
            out.append(chunk % q)

    return out
