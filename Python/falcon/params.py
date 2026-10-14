"""
Parametersätze für Falcon-512 und Falcon-1024.

Spec-Referenz: Tabelle 3.3, §3.13.
Ebene 0: Falcon Specification v1.2, Tab. 3.3.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Params:
    """Parametersatz für eine Falcon-Instanz.

    Attribute:
        n:            Polynomgrad (512 oder 1024)
        q:            Primzahl-Modulus (12289)
        sigma:        Breite der Gaussverteilung beim Signieren (σ)
        sigma_min:    Untere Grenze für den Integer-Sampler (σmin)
        sigma_max:    Obere Grenze für den Integer-Sampler (σmax)
        sig_bound:    Maximale quadrierte Länge einer Signatur (⌊β²⌋)
        sig_bytelen:  Feste Signaturlänge in Bytes
    """
    n: int
    q: int
    sigma: float
    sigma_min: float
    sigma_max: float
    sig_bound: int
    sig_bytelen: int

    @property
    def pk_bytes(self) -> int:
        """Länge des Public Keys in Bytes (§3.11.4)."""
        # Header (1 Byte) + 14 Bit pro Koeffizient (n-1 Einträge, da a_n = 1)
        return 1 + ((self.n - 1) * 14 + 7) // 8

    @property
    def sk_header_byte(self) -> int:
        """Header-Byte für Secret-Key-Kodierung (§3.11.5)."""
        return 0x50 if self.n == 512 else 0x51


# Falcon-512: NIST-Sicherheitsstufe I
FALCON_512 = Params(
    n=512,
    q=12289,
    sigma=165.736617183,
    sigma_min=1.277833697,
    sigma_max=1.8205,
    sig_bound=34034726,
    sig_bytelen=666,
)

# Falcon-1024: NIST-Sicherheitsstufe V
FALCON_1024 = Params(
    n=1024,
    q=12289,
    sigma=168.388571447,
    sigma_min=1.298280334,
    sigma_max=1.8205,
    sig_bound=70265242,
    sig_bytelen=1280,
)