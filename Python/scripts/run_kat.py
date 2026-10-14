#!/usr/bin/env python3
"""KAT-Runner: führt alle Known Answer Tests aus."""

from pathlib import Path

KAT_DIR = Path(__file__).parent.parent / "data" / "kat"


def main():
    if not KAT_DIR.exists():
        print(f"KAT-Verzeichnis nicht gefunden: {KAT_DIR}")
        print("Bitte NIST-Testdaten in data/kat/ ablegen.")
        return

    print("=== Falcon KAT Runner ===")
    for f in sorted(KAT_DIR.glob("*")):
        print(f"  {f.name}")
    # TODO: KAT-Parser und Verifikation implementieren


if __name__ == "__main__":
    main()