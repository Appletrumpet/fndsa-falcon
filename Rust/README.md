# FN-DSA (Falcon) in Rust – Ebene 5 der Dokumentation

Rust-Implementierung von Falcon-512 und Falcon-1024 mit konstanter Laufzeit
auf geheimen Daten. Der Plan dazu steht in [PLAN.md](PLAN.md); dieses
Dokument beschreibt, was umgesetzt ist und wo die Rust-Version bewusst von
der Python-Version (`../Python`) abweicht.

## Stand

| Phase (PLAN.md §5) | Inhalt | Stand |
|---|---|---|
| 0 | Crate, Parameter, Testdaten, CI | fertig |
| 1 | mod q (NTT), HashToPoint, Byteformate, Verify | fertig |
| 2–8 | `fpr`, FFT, Sampler, Sign, Keygen, Seitenkanal-Prüfung, KAT-Schlüssel | offen |

Bisher kann das Crate also Signaturen **prüfen**, aber noch nicht erzeugen.

## Bauen und testen

```bash
cd Rust
cargo test          # alle Tests, liest die Testdaten aus ../Python/data/
bash ci.sh          # Formatierung, Clippy, Tests, Release-Build, Doku
```

Kleinste unterstützte Rust-Version: 1.87 (`rust-version` in `Cargo.toml`).

Die CI auf GitHub (`.github/workflows/rust.yml`) hat drei Jobs:

- `check`: `ci.sh` auf x86-64 und aarch64;
- `msrv`: Tests mit Rust 1.87;
- `fuzz`: baut die Fuzz-Ziele und lässt jedes 60 Sekunden laufen.

Fuzzing (nur Linux oder WSL, Nightly-Rust):

```bash
cargo install cargo-fuzz
cd Rust
cargo +nightly fuzz run verify      # auch: decode_pk, decode_sk, decompress
```

Die Logik der Fuzz-Ziele liegt in `src/fuzzing.rs` und wird von `cargo test`
mit Zufallsdaten und beschädigten KAT-Daten mitgeprüft.

## Was getestet ist

- alle 200 NIST-KAT-Signaturen werden akzeptiert (auch Falcon-1024 count 82,
  ungepolstert länger als die feste Länge);
- Public- und Secret-Key-Format byte-genau gegen alle KAT-Schlüssel;
- h = g/f aus dem KAT-Secret-Key ergibt den KAT-Public-Key;
- zweite, unabhängige Quelle: Schlüssel und Signatur aus den
  Sampler-Testvektoren werden akzeptiert, HashToPoint stimmt mit dem
  dortigen „hashed message“ überein;
- die Beispiele und Ablehnungsfälle aus `Python/tests/test_encoding.py` und
  `test_hashing.py`;
- veränderte Nachricht, Salt, s₂, Header oder fremder Schlüssel werden
  abgelehnt (gezielt und mit zufälligen Bitfehlern).

## Unterschiede zur Python-Version

Python wird nicht angepasst (PLAN.md 2.2). Die Unterschiede sind gewollt:

| Punkt | Python | Rust | Grund |
|---|---|---|---|
| \|sᵢ\| in `decompress` | keine Obergrenze | > 2047 wird abgelehnt | L5: fester Typ, wie die Referenz |
| Keygen, nicht speicherbare Schlüssel | möglich (selten) | werden verworfen | L6, kommt mit Phase 5 |
| Secret-Key-Format | normaler Code | Laufzeit unabhängig von f, g, F; Fehler verrät nicht, welcher Koeffizient | Seitenkanal |
| Gleitkomma | `float`/`complex` | emuliert (`fpr`), ab Phase 2 | L3 |
| Vergleich der Gleitkommawerte | – | mit Toleranz, nicht bitgleich | `cmath.exp` und CPythons komplexe Division (PLAN.md 3.3) |
| BerExp | bricht nach dem ersten entscheidenden Byte ab | immer 8 Bytes, ab Phase 3 | L7 |
| Parametersätze | `Params` für 512/1024, Grad 1..10 erlaubt | `LogN` 1..=10 für Formate und NTT; Verify nur für 512/1024 (`UnsupportedLogN`) | verkleinerte Parameter kommen mit Phase 5 |

## Seitenkanal: was bisher gilt

Geheime Daten sind f, g, F, G und alles daraus (PLAN.md 3.1). Davon berührt
der bisherige Code nur das Secret-Key-Format und h = g/f:

- keine Verzweigung und kein Speicherzugriff, der von geheimen Werten
  abhängt; Auswahl über Masken (`src/ct.rs`);
- jede Maske läuft durch eine Optimierungsbarriere: auf x86-64 und aarch64
  eine leere Assembler-Anweisung, die den Wert im Register lässt, sonst
  `core::hint::black_box` (das den Wert über den Stack schickt);
- keine Hardware-Division auf geheimen Werten (Barrett-Reduktion mod q);
- Inverse mod q per Fermat mit fester Exponentenkette;
- geheime Puffer werden gelöscht (`zeroize`); Ausgabepuffer werden in voller
  Länge angelegt, damit beim Vergrössern keine ungelöschten Kopien bleiben.

**Stichprobe im Assembler (Release):** Auf x86-64 werden die Masken in
`modq::ntt` und im Code für das Secret-Key-Format mit `sar` gebildet und
bleiben im Register; es gibt keine Sprünge, die von Werten abhängen. Auf
aarch64 (nur übersetzt, nicht ausgeführt) gilt dasselbe für `modq::ntt`
mit `asr`. Die übrigen
Sprünge kommen von Schleifen, Grenzprüfungen und Längen, die nur von n
abhängen. Die einzige Verzweigung auf geheimen Daten ist die gewollte
Endprüfung „Secret Key gültig?“. Das ist eine Stichprobe, kein Nachweis.

**Bekannte Grenze:** Lokale Variablen mit geheimen Werten, die der Compiler
in Register oder auf den Stack legt, werden nicht gelöscht. `zeroize`
erreicht nur Puffer, die das Programm selbst besitzt; Rust bietet keinen
Weg, den Stack nach einem Aufruf sicher zu löschen.

**Noch nicht nachgewiesen:** Den vollständigen Nachweis, dass der Compiler
keine geheimabhängigen Sprünge erzeugt, liefert erst Phase 6 (Assembler auf
beiden Plattformen, Valgrind, dudect). Gegen Power- und EM-Angriffe schützt
die Implementierung nicht (PLAN.md §1).

## Aufbau

```
src/
  lib.rs       öffentliche API: VerifyingKey, Signature, LogN, Params, Error
  params.rs    Tab. 3.3, LogN
  ct.rs        Masken und Auswahl ohne Verzweigung
  modq.rs      Arithmetik mod 12289, NTT
  hashing.rs   HashToPoint (öffentlich, variable Laufzeit erlaubt)
  encoding.rs  Kompression von s₂, pk- und sk-Format
  falcon.rs    Verify, h = g/f
  fuzzing.rs   Einstiegspunkte für cargo fuzz (Feature `fuzzing`)
tests/         KAT-Tests, Parser für die Testdaten
fuzz/          Fuzz-Ziele (cargo fuzz)
```
