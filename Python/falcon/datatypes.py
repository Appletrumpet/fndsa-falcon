"""
Datenklassen für Schlüssel und Signaturen.

Spec-Referenz: §3.4 (SecretKey, PublicKey), §3.11.3 (Signature).
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class SecretKey:
    """Geheimer Schlüssel.

    Kern: die vier kurzen Polynome f, g, F, G (Alg. 4, Z. 8; §3.4.2).
    Abgeleitet: basis_fft (für schnelles Rechnen) und tree (Falcon-Baum).
    """
    f: List[int]
    g: List[int]
    F: List[int]
    G: List[int]
    basis_fft: Optional[Tuple] = None   # [[ĝ, -f̂], [Ĝ, -F̂]] in FFT-Form
    tree: Optional[object] = None       # Falcon-Baum (Knoten/Blatt-Struktur)


@dataclass
class PublicKey:
    """Öffentlicher Schlüssel: h = g · f⁻¹ mod q (§3.4.3)."""
    h: List[int]


@dataclass
class Signature:
    """Signatur bestehend aus Salt und komprimiertem s₂ (§3.11.3).

    salt:        40 zufällige Bytes (320 Bit)
    s2_encoded:  komprimiertes s₂ (variable Länge, ≤ sig_bytelen - 40 - 1)
    """
    salt: bytes
    s2_encoded: bytes