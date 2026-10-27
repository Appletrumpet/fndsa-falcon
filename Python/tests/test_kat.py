"""Known Answer Tests gegen NIST-Testdaten.

KAT-Format: §3.11.6. 100 Fälle pro Parametersatz (data/kat/falcon{512,1024}-KAT.rsp).
Validierungsplan: Falcon_Documentation §7.

  - verify: muss alle KAT-Signaturen akzeptieren. Diese liegen ohne Padding vor;
    Falcon-1024 count = 82 überschreitet die gepolsterte Länge.
  - Schlüsselformate: decode_pk und decode_sk; für jeden sk gilt fG − gF = q
    und g·f⁻¹ mod q = h.
  - sign: mit dem KAT-sk signieren und mit dem KAT-pk verifizieren.

Die KAT-Signaturen selbst lassen sich nicht byte-genau nachbilden: Sie hängen
vom NIST-Zufallsgenerator (AES-256-CTR-DRBG aus „seed“) ab, der nicht Teil der
Falcon-Spezifikation ist.
"""

import pytest
from falcon import FALCON_512, FALCON_1024
from falcon.datatypes import PublicKey
from falcon.encoding import decode_kat_message, decode_pk, decode_sk, encode_pk, encode_sk
from falcon.falcon import compute_public_key, load_secret_key, sign, verify
from falcon.ntrugen import recompute_G
from support import SeededRNG, load_kat, nmul

Q = 12289
PARAMS_BY_N = {512: FALCON_512, 1024: FALCON_1024}


def kat_cases(n):
    return pytest.mark.parametrize("rec", load_kat(n), ids=lambda r: f"count{r.count}")



@kat_cases(512)
def test_kat_verify_512(rec):
    """Alle 100 KAT-Signaturen für Falcon-512 müssen akzeptiert werden."""
    msg, sig = decode_kat_message(rec.sm)
    assert msg == rec.msg
    assert verify(PublicKey(decode_pk(rec.pk)), msg, sig, FALCON_512) is True


@kat_cases(1024)
def test_kat_verify_1024(rec):
    """Alle 100 KAT-Signaturen für Falcon-1024 müssen akzeptiert werden.

    Hinweis: Fall count=82 bei Falcon-1024 überschreitet die gepolsterte
    Länge – decompress muss auch ungepolsterte Kodierungen akzeptieren
    (§3.11.3).
    """
    msg, sig = decode_kat_message(rec.sm)
    assert msg == rec.msg
    assert verify(PublicKey(decode_pk(rec.pk)), msg, sig, FALCON_1024) is True


@pytest.mark.slow
@pytest.mark.parametrize("n", [512, 1024])
def test_kat_key_formats(n):
    """decode_pk und decode_sk gegen KAT; für jeden sk gilt:
    fG - gF = q und g·f⁻¹ mod q = h."""
    params = PARAMS_BY_N[n]
    for rec in load_kat(n):
        h = decode_pk(rec.pk)
        f, g, F = decode_sk(rec.sk)
        G = recompute_G(f, g, F)
        assert [a - b for a, b in zip(nmul(f, G), nmul(g, F))] == [Q] + [0] * (n - 1), rec.count
        assert compute_public_key(f, g, params) == h, rec.count
        assert encode_pk(h) == rec.pk and encode_sk(f, g, F) == rec.sk, rec.count


@pytest.mark.parametrize("n", [512, 1024])
def test_kat_sign_with_kat_key(n):
    """Mit dem KAT-sk signieren, mit dem KAT-pk verifizieren (Doku §7)."""
    params = PARAMS_BY_N[n]
    for rec in load_kat(n)[:3]:
        sk = load_secret_key(rec.sk, params)
        pk = PublicKey(decode_pk(rec.pk))
        sig = sign(sk, rec.msg, params, SeededRNG(rec.count))
        assert verify(pk, rec.msg, sig, params), rec.count


@pytest.mark.parametrize("n", [512, 1024])
def test_kat_rejects_tampered_message(n):
    """Gegenprobe: dieselben Signaturen mit veränderter Nachricht ablehnen."""
    params = PARAMS_BY_N[n]
    for rec in load_kat(n)[:5]:
        msg, sig = decode_kat_message(rec.sm)
        tampered = bytes([msg[0] ^ 1]) + msg[1:]
        assert verify(PublicKey(decode_pk(rec.pk)), tampered, sig, params) is False, rec.count


@pytest.mark.parametrize("n", [512, 1024])
def test_kat_rejects_signature_under_other_key(n):
    """Gegenprobe: Signatur von count k mit dem pk von count k+1 ablehnen."""
    params = PARAMS_BY_N[n]
    recs = load_kat(n)
    for a, b in zip(recs[:5], recs[1:6]):
        msg, sig = decode_kat_message(a.sm)
        assert verify(PublicKey(decode_pk(b.pk)), msg, sig, params) is False, a.count
