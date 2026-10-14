#!/usr/bin/env python3
"""Kleines End-to-End Beispiel für Falcon."""

from falcon import FALCON_512, keygen, sign, verify


def main():
    print("=== Falcon (FN-DSA) Demo ===")
    print(f"Parametersatz: Falcon-{FALCON_512.n}, q={FALCON_512.q}")
    print()

    message = b"Hello, Falcon!"
    print(f"Nachricht: {message!r}")
    print()

    print("1. Schlüsselerzeugung (keygen)...")
    sk, pk = keygen(FALCON_512)
    print(f"   Public Key  : {len(pk.h)} Koeffizienten")
    print()

    print("2. Signatur erzeugen (sign)...")
    sig = sign(sk, message, FALCON_512)
    print(f"   Salt        : {sig.salt.hex()[:32]}...")
    print(f"   s₂ encoded  : {len(sig.s2_encoded)} Bytes")
    print()

    print("3. Signatur verifizieren (verify)...")
    ok = verify(pk, message, sig, FALCON_512)
    print(f"   Gültig      : {ok}")
    assert ok, "Signatur sollte gültig sein!"

    print()
    print("✓ Demo erfolgreich.")


if __name__ == "__main__":
    main()