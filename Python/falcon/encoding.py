"""
Kompression und Byteformate für Schlüssel und Signaturen.

Spec-Referenz: §3.11 (insbesondere §3.11.3–§3.11.6).

Kodierung von s₂: Vorzeichen, 7 tiefe Bits, Rest unär, auf feste Länge
auffüllen (Alg. 17). Dekompression lehnt mehrdeutige Kodierungen ab,
akzeptiert aber sowohl gepolsterte (feste Länge) als auch ungepolsterte
Kodierungen (§3.11.3); teilweises Padding ist ungültig.
"""

from typing import List, Optional, Tuple
from .params import Params
from .datatypes import Signature


# ---------------------------------------------------------------------------
# Signatur-Kompression (Alg. 17 / Alg. 18)
# ---------------------------------------------------------------------------

def compress(s: List[int], params: Params) -> Optional[bytes]:
    """Vorzeichen, 7 tiefe Bits, Rest unär, auf feste Länge auffüllen.
    Alg. 17. Gibt None zurück, wenn die Kodierung die feste Signaturlänge
    überschreitet."""
    raise NotImplementedError


def decompress(b: bytes, params: Params) -> Optional[List[int]]:
    """Umkehrung von compress.

    Lehnt mehrdeutige Kodierungen ab. Akzeptiert:
      - gepolsterte Kodierungen fester Länge (Alg. 18)
      - ungepolsterte Kodierungen (§3.11.3)
    Teilweises Padding ist ungültig.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Public-Key-Kodierung (§3.11.4)
# ---------------------------------------------------------------------------

def encode_pk(h: List[int]) -> bytes:
    """Header + 14 Bit pro Koeffizient. §3.11.4."""
    raise NotImplementedError


def decode_pk(b: bytes) -> List[int]:
    """Umkehrung von encode_pk. §3.11.4."""
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Secret-Key-Kodierung (§3.11.5)
# ---------------------------------------------------------------------------

def encode_sk(f: List[int], g: List[int], F: List[int]) -> bytes:
    """Header + f, g, F mit fester Bitbreite. §3.11.5."""
    raise NotImplementedError


def decode_sk(b: bytes) -> Tuple[List[int], List[int], List[int]]:
    """Umkehrung von encode_sk. §3.11.5."""
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Signatur-Kodierung (§3.11.3)
# ---------------------------------------------------------------------------

def encode_sig(sig: Signature) -> bytes:
    """Header + Salt + komprimiertes s₂. §3.11.3."""
    raise NotImplementedError


def decode_sig(b: bytes) -> Signature:
    """Umkehrung von encode_sig. §3.11.3."""
    raise NotImplementedError


# ---------------------------------------------------------------------------
# KAT-Format (§3.11.6)
# ---------------------------------------------------------------------------

def decode_kat_message(sm: bytes) -> Tuple[bytes, Signature]:
    """KAT-Format der NIST-API: Länge, Salt, Nachricht, Signatur mit
    Header 0x29 bzw. 0x2A, ohne Padding. Nur für Tests. §3.11.6."""
    raise NotImplementedError