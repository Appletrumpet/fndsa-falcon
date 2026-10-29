"""
Parametersätze für Falcon-512 und Falcon-1024.

Spec-Referenz: Tabelle 3.3, §3.13.
Ebene 0: Falcon Specification v1.2, Tab. 3.3.
"""

from dataclasses import dataclass


def _is_prime(x: int) -> bool:
    if x < 2:
        return False
    if x % 2 == 0:
        return x == 2
    if x % 3 == 0:
        return x == 3
    i = 5
    w = 2
    while i * i <= x:
        if x % i == 0:
            return False
        i += w
        w = 6 - w
    return True


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

    def __post_init__(self) -> None:
        if not isinstance(self.n, int):
            raise ValueError("n muss ein Integer sein")
        if self.n <= 0 or (self.n & (self.n - 1)) != 0:
            raise ValueError("n muss eine Zweierpotenz sein")
        logn = self.n.bit_length() - 1
        if not (1 <= logn <= 10):
            raise ValueError("log n muss im Bereich 1..10 liegen")

        if not isinstance(self.q, int) or not _is_prime(self.q):
            raise ValueError("q muss prim sein")
        if (self.q - 1) % (2 * self.n) != 0:
            raise ValueError("q muss eine primitive 2n-te Einheitswurzel besitzen")

        if not (self.sigma > 0.0):
            raise ValueError("sigma muss positiv sein")
        if not (1.0 <= self.sigma_min < self.sigma_max):
            raise ValueError("es muss 1 <= sigma_min < sigma_max gelten")
        if not (self.sig_bound > 0):
            raise ValueError("sig_bound muss positiv sein")
        if not (self.sig_bytelen > 0):
            raise ValueError("sig_bytelen muss positiv sein")

    @property
    def logn(self) -> int:
        return self.n.bit_length() - 1

    @property
    def pk_bytes(self) -> int:
        """Länge des Public Keys in Bytes (§3.11.4)."""
        return 1 + (14 * self.n + 7) // 8

    @property
    def sk_header_byte(self) -> int:
        """Header-Byte für Secret-Key-Kodierung (§3.11.5)."""
        return 0x50 | self.logn


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
