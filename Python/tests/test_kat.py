"""Known Answer Tests gegen NIST-Testdaten.

KAT-Format: §3.11.6. 100 Fälle pro Parametersatz.
"""

import pytest
from pathlib import Path
from falcon import FALCON_512, FALCON_1024


KAT_DIR = Path(__file__).parent.parent / "data" / "kat"


@pytest.mark.skip(reason="KAT-Dateien müssen in data/kat/ abgelegt werden")
def test_kat_verify_512():
    """Alle 100 KAT-Signaturen für Falcon-512 müssen akzeptiert werden."""
    raise NotImplementedError


@pytest.mark.skip(reason="KAT-Dateien müssen in data/kat/ abgelegt werden")
def test_kat_verify_1024():
    """Alle 100 KAT-Signaturen für Falcon-1024 müssen akzeptiert werden.

    Hinweis: Fall count=82 bei Falcon-1024 überschreitet die gepolsterte
    Länge – decompress muss auch ungepolsterte Kodierungen akzeptieren
    (§3.11.3).
    """
    raise NotImplementedError


@pytest.mark.skip(reason="Implementierung noch nicht abgeschlossen")
def test_kat_key_formats():
    """decode_pk und decode_sk gegen KAT; für jeden sk gilt:
    fG - gF = q und g·f⁻¹ mod q = h."""
    raise NotImplementedError