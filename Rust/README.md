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
| 2 | emulierte Gleitkommazahlen (`fpr`), FFT | fertig |
| 3 | Zufallsquelle (`prng`), Sampler | fertig |
| 4 | Falcon-Baum, ffSampling, Sign, Secret Key laden | fertig |
| 5–8 | Keygen, Seitenkanal-Prüfung, KAT-Schlüssel, Messungen | offen |

Das Crate kann Signaturen **prüfen** und mit einem geladenen Secret Key
**erzeugen**. Schlüssel erzeugen kann es noch nicht (Phase 5); bis dahin
stammen die Secret Keys z. B. aus den NIST-KAT-Dateien.

```rust
let sk = SigningKey::from_bytes(&sk_bytes)?;   // berechnet G, Basis, Baum
let sig = sk.sign(msg, &mut rng);              // rng: CryptoRngCore, z. B. OsRng
assert!(sk.verifying_key().verify(msg, &sig));
```

Laufzeit (Release, ein Kern, x86-64-Laptop): Laden ≈ 4 ms / 10 ms,
Signieren ≈ 6 ms / 12 ms für Falcon-512 / Falcon-1024, alles mit
emulierten Gleitkommazahlen.

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
- `fuzz`: baut die Fuzz-Ziele, erzeugt den Start-Korpus und lässt jedes
  Ziel 60 Sekunden laufen.

Fuzzing (nur Linux oder WSL, Nightly-Rust):

```bash
cargo install cargo-fuzz
cd Rust
cargo run --example seed_corpus -- fuzz/corpus   # Start-Korpus aus den KATs
cargo +nightly fuzz run verify      # auch: decode_pk, decode_sk, decompress
```

Der Start-Korpus ist nötig: Ein zufälliger Public Key ist fast nie gültig
(alle 512 Koeffizienten müssen unter q liegen, ≈ 0,75⁵¹²). Ohne gültige
Startdaten käme der Fuzzer nicht bis Verify. `examples/seed_corpus.rs`
legt je Ziel 20 Dateien aus den KAT-Daten an und prüft dabei, dass jede
Verify-Eingabe gültig ist. `fuzz/Cargo.lock` ist eingecheckt, damit die CI
immer dieselben Versionen baut.

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
  abgelehnt (gezielt und mit zufälligen Bitfehlern);
- `fpr` bitgleich gegen Hardware-`f64` (add, sub, mul, div, sqrt, Umwandlung,
  Runden; je 300 000 Zufallswerte mit vielen Rundungsfällen, dazu ±0 und
  Unterlauf);
- FFT, iFFT, split/merge und alle punktweisen Operationen **bitgleich** gegen
  `Python/data/vectors/fft.*` (auch das Vorzeichen von Nullen);
- Sampler bitgleich gegen `Python/data/vectors/sampler.*`: BaseSampler,
  ApproxExp, Schwelle z und Ergebnis von BerExp, x aus SamplerZ und SamplerZ
  selbst (mit einem Test-Generator, der den Byteverbrauch von Alg. 14
  nachbildet); dazu Mittelwert, Varianz und χ²-Test der SamplerZ-Ausgabe;
- Basis, Gram-Matrix, LDL*, ffLDL*, Normalisierung, Falcon-Baum,
  ffSampling, G aus dem Secret Key, Ziel t, Signaturvektor, Normprüfung und
  Runden bitgleich gegen `Python/data/vectors/tree.*`, `ffsampling.*`,
  `falcon.*`;
- **ganze Signaturen byte-genau wie Python** (`flow.sign`, dazu
  `flow.sign_restart` mit knappen Schranken, die beide Neustarts aus
  Alg. 10 erzwingen), wenn Rust denselben SHAKE-Zufallsstrom bekommt;
- mit den KAT-Schlüsseln: Laden und Speichern byte-genau, abgeleiteter
  Public Key gleich dem KAT-Public-Key, Signaturen mit fester Länge, die
  Verify annimmt und die bei veränderter Nachricht abgelehnt werden;
- ungültige Secret Keys: f nicht invertierbar, Grad ohne Parametersatz.

## Unterschiede zur Python-Version

Python wird nicht angepasst (PLAN.md 2.2). Die Unterschiede sind gewollt:

| Punkt | Python | Rust | Grund |
|---|---|---|---|
| \|sᵢ\| in `decompress` | keine Obergrenze | > 2047 wird abgelehnt | L5: fester Typ, wie die Referenz |
| Keygen, nicht speicherbare Schlüssel | möglich (selten) | werden verworfen | L6, kommt mit Phase 5 |
| Secret-Key-Format | normaler Code | Laufzeit unabhängig von f, g, F; Fehler verrät nicht, welcher Koeffizient | Seitenkanal |
| Gleitkomma | `float`/`complex` | emuliert (`fpr`), nur Ganzzahlbefehle | L3 |
| Vergleich der Gleitkommawerte | – | bitgleich mit Python und C | gleiche Wurzeltabelle, gleiche Reihenfolge, korrekt gerundetes `fpr` (PLAN.md 3.3) |
| FFT-Darstellung | alle n Werte | alle n Werte (nicht n/2 wie geplant) | sonst andere Rechenwege und andere Bits (PLAN.md L8) |
| Zufall im Sampler | Bytes direkt aus der Quelle | Seed → SHAKE256 → ChaCha20 | L9 |
| Sign: Zufall | alles aus einer Quelle | aus `rng` 40 Bytes Salt und 56 Bytes Seed, dann ChaCha20 | L9; Signaturen deshalb nicht byte-gleich mit Python oder den KAT-Dateien (bei gleichem Zufall aber schon, siehe Tests) |
| BerExp | bricht nach dem ersten entscheidenden Byte ab | immer 8 Bytes | L7 |
| Parametersätze | `Params` für 512/1024, Grad 1..10 erlaubt | `LogN` 1..=10 für Formate und NTT; Verify nur für 512/1024 (`UnsupportedLogN`) | verkleinerte Parameter kommen mit Phase 5 |

## Seitenkanal: was bisher gilt

Geheime Daten sind f, g, F, G und alles daraus (PLAN.md 3.1). Davon berührt
der bisherige Code das Secret-Key-Format, h = g/f, das Laden des Secret
Keys (G, Basis, Baum) und Sign: `fpr`, FFT, Sampler, ffSampling.

- keine Verzweigung und kein Speicherzugriff, der von geheimen Werten
  abhängt; Auswahl über Masken (`src/ct.rs`);
- Gleitkomma nur emuliert (`src/fpr.rs`): Division und Wurzel Bit für Bit
  mit fester Rundenzahl, Normalisierung in sechs festen Schritten, kein
  Befehl der Gleitkommaeinheit; Schiebebefehle mit variabler Weite gelten
  auf x86-64 und aarch64 als Befehle mit fester Laufzeit;
- Sampler: BaseSampler vergleicht mit allen 18 Tabelleneinträgen, BerExp
  zieht immer 8 Bytes (L7). Einzige Verzweigung ist „SamplerZ nimmt an“,
  deren Häufigkeit nicht von μ und σ′ abhängt (PLAN.md 3.4);
- Zufall im Sampler aus ChaCha20, Puffer werden nach Gebrauch gelöscht;
- Sign: erlaubte Verzweigungen nur bei „Norm zu gross“ und „s₂ passt nicht
  in die Länge“ (Neustart, PLAN.md §6); `SigningKey` und alle
  FFT-Zwischenwerte (`Poly`) werden beim Verwerfen gelöscht;
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
  lib.rs       öffentliche API: SigningKey, VerifyingKey, Signature, LogN, Params, Error
  params.rs    Tab. 3.3, LogN
  ct.rs        Masken und Auswahl ohne Verzweigung (32 und 64 Bit)
  fpr.rs       emulierte IEEE-754-Gleitkommazahlen, konstante Laufzeit
  fft.rs       FFT, split/merge, komplexe Operationen (Smith-Division)
  fft_table.rs Wurzeln ζ (erzeugt mit scripts/gen_fft_table.py)
  prng.rs      Seed → SHAKE256 → ChaCha20
  sampler.rs   BaseSampler, ApproxExp, BerExp, SamplerZ
  tree.rs      Basis, Gram-Matrix, ffLDL*, Falcon-Baum
  ffsampling.rs ffSampling (Alg. 11)
  modq.rs      Arithmetik mod 12289, NTT
  hashing.rs   HashToPoint (öffentlich, variable Laufzeit erlaubt)
  encoding.rs  Kompression von s₂, pk- und sk-Format
  falcon.rs    Verify, h = g/f, G neu berechnen, Sign
  fuzzing.rs   Einstiegspunkte für cargo fuzz (Feature `fuzzing`)
tests/         KAT-Tests, Leser für KAT- und Python-Testvektoren
scripts/       Erzeugung von src/fft_table.rs
examples/      seed_corpus: Start-Korpus für die Fuzz-Ziele
fuzz/          Fuzz-Ziele (cargo fuzz)
```
