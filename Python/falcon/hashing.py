"""
HashToPoint: Nachricht auf Polynom in ℤ_q[x]/(xⁿ+1) abbilden.

Verwendet SHAKE-256 (FIPS 202). Pro Koeffizient werden 16 Bits gelesen;
nur Werte < 5·q werden akzeptiert (Rejection Sampling), dann mod q.

Spec-Referenz: §3.7, Alg. 3.
Extern: SHAKE-256 aus hashlib.
"""

from typing import List
from .params import Params


def hash_to_point(data: bytes, params: Params) -> List[int]:
    """SHAKE-256, je 16 Bit lesen, Werte < 5q annehmen,
    Koeffizient = Wert mod q. Alg. 3."""
    raise NotImplementedError