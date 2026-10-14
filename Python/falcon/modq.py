"""
Rechnen mod q = 12289 über NTT (Number Theoretic Transform).

Spec-Referenz: §3.5, §4.2.2.
"""

from typing import List, Optional


def ntt(a: List[int]) -> List[int]:
    """Polynom mod q in Wertedarstellung (NTT-Form). Spec §3.5, §4.2.2."""
    raise NotImplementedError


def intt(a_hat: List[int]) -> List[int]:
    """Zurück in Koeffizientenform. Spec §3.5."""
    raise NotImplementedError


def mul_mod_q(a: List[int], b: List[int]) -> List[int]:
    """Multiplizieren mod q über NTT. Spec §4.2.2."""
    raise NotImplementedError


def div_mod_q(a: List[int], b: List[int]) -> List[int]:
    """a · b⁻¹ mod q, punktweise in NTT-Form. Spec §3.4.3, §4.2.2."""
    raise NotImplementedError


def is_invertible_mod_q(a: List[int]) -> bool:
    """NTT(a) enthält keine Null. Alg. 5, Z. 7."""
    raise NotImplementedError


def center_mod_q(a: List[int]) -> List[int]:
    """Koeffizienten auf [-q/2, q/2] abbilden. Alg. 16, Z. 5."""
    raise NotImplementedError