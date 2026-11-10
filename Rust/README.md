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
| 5 | Keygen (NTRUSolve fester Länge, Portierung der Referenz) | fertig |
| 6 | Seitenkanal-Prüfung (Valgrind, dudect, Assembler) | fertig für x86-64 (aarch64: Valgrind in der CI) |
| 7 | KAT-Schlüssel byte-genau aus den Seeds | fertig (alle 200) |
| 8 | Messungen, `native-fpu` | offen |

Das Crate kann Schlüssel **erzeugen**, Signaturen **erzeugen** und
**prüfen**, für Falcon-512 und Falcon-1024.

```rust
let (sk, pk) = fndsa::keygen(LogN::FALCON_512, &mut rng)?; // rng: z. B. OsRng
let sk_bytes = sk.to_bytes();                // speichern (Zeroizing)
let sk = SigningKey::from_bytes(&sk_bytes)?; // laden: G, Basis, Baum, Prüfung
let sig = sk.sign(msg, &mut rng);
assert!(pk.verify(msg, &sig));
```

`keygen_from_seed(logn, &seed)` erzeugt denselben Schlüssel aus demselben
Seed (48 Bytes); mit den Seeds der NIST-KAT-Dateien entstehen byte-genau
die KAT-Schlüssel.

Laufzeit (Release, ein Kern, x86-64-Laptop), alles mit emulierten
Gleitkommazahlen:

| | Falcon-512 | Falcon-1024 |
|---|---|---|
| Keygen | ≈ 25 ms | ≈ 61 ms |
| Secret Key laden | ≈ 5 ms | ≈ 11 ms |
| Signieren | ≈ 6 ms | ≈ 12 ms |

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

Konstante Laufzeit prüfen (PLAN.md §6):

```bash
bash ctgrind.sh     # Valgrind, nur Linux (z. B. in Docker); CI-Job "ctgrind"
cargo run --release --example dudect --features dudect   # Zeitmessung
```

Fuzzing (nur Linux oder WSL, Nightly-Rust):

```bash
cargo install cargo-fuzz
cd Rust
cargo run --example seed_corpus -- fuzz/corpus   # Start-Korpus aus den KATs
cargo +nightly fuzz run verify      # auch: decode_pk, decode_sk, decompress, signing_key
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
- **Keygen byte-genau gegen alle 200 KAT-Schlüssel** (f, g, F und h): der
  Seed der KAT-Datei geht wie im NIST-Programm durch den AES-256-CTR-DRBG
  (`tests/common/drbg.rs`, prüft sich selbst an allen Seeds und
  Nachrichten der KAT-Dateien), daraus 48 Bytes für `keygen_from_seed`;
- Keygen für verkleinerte Grade n = 2 … 256: fG − gF = q, kleine
  Koeffizienten; zufällige Schlüssel lassen sich speichern, laden,
  signieren und prüfen; gleicher Seed, gleicher Schlüssel;
- Bausteine von NTRUSolve: Primzahltabelle (p ≡ 1 mod 2048, Wurzel g,
  CRT-Faktor s), Rechnen mod p, NTT, binärer GCD, FFT der Referenz;
- ungültige Secret Keys: f nicht invertierbar, Grad ohne Parametersatz,
  erfundene Schlüssel (`InvalidKey`, siehe unten); alle 200 KAT-Schlüssel
  bestehen die Schlüsselprüfung.

## Unterschiede zur Python-Version

Python wird nicht angepasst (PLAN.md 2.2). Die Unterschiede sind gewollt:

| Punkt | Python | Rust | Grund |
|---|---|---|---|
| \|sᵢ\| in `decompress` | keine Obergrenze | > 2047 wird abgelehnt | L5: fester Typ, wie die Referenz |
| Keygen, nicht speicherbare Schlüssel | möglich (selten) | werden verworfen | L6 |
| Keygen | eigener Ablauf, Python-Ganzzahlen | Portierung der Referenz: Tabellen-Gauss, NTRUSolve fester Länge im RNS, FFT der Referenz | L4, L10; ergibt die KAT-Schlüssel byte-genau |
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
- erlaubte Verzweigungen sind im Code mit `ct::declassify` markiert; nur
  dort gibt die Valgrind-Prüfung geheime Werte frei;
- Sign: erlaubte Verzweigungen nur bei „Norm zu gross“ und „s₂ passt nicht
  in die Länge“ (Neustart, PLAN.md §6); `SigningKey` und alle
  FFT-Zwischenwerte (`Poly`) werden beim Verwerfen gelöscht;
- Keygen wie die Referenz: f, g mit vollständigem Tabellendurchlauf,
  NTRUSolve mit Ganzzahlen fester Länge (RNS, CRT, binärer GCD mit fester
  Rundenzahl, `reduce` mit fester Zahl von Durchläufen). Erlaubte
  Verzweigungen: einzelnen Koeffizienten neu ziehen (ausserhalb ±127 oder
  falsche Parität beim letzten) und Kandidat verwerfen (PLAN.md 3.1, §6).
  Die Masken im portierten Code laufen wie in der Referenz nicht durch die
  Barriere; das prüft Phase 6 im Assembler;
- Laden des Secret Keys prüft ohne Verzweigung auf den Werten, dass es ein
  echter Falcon-Schlüssel ist: |G| ≤ 127, fG − gF = q exakt und alle Blätter
  in [σmin, σmax] (L11, Toleranz 1e-10 wie Python). Sonst `InvalidKey`;
  ohne diese Prüfung lief Sign mit erfundenen Schlüsseln endlos;
- Schutz gegen Fault-Angriffe: jede Signatur wird vor der Ausgabe mit
  Verify geprüft (PLAN.md 3.6);
- jede Maske läuft durch eine Optimierungsbarriere: auf x86-64 und aarch64
  eine leere Assembler-Anweisung, die den Wert im Register lässt, sonst
  `core::hint::black_box` (das den Wert über den Stack schickt);
- keine Hardware-Division auf geheimen Werten (Barrett-Reduktion mod q);
- Inverse mod q per Fermat mit fester Exponentenkette;
- geheime Puffer werden gelöscht (`zeroize`); Ausgabepuffer werden in voller
  Länge angelegt, damit beim Vergrössern keine ungelöschten Kopien bleiben.

**Stichprobe im Assembler (Release):** Im ganzen Crate gibt es keinen
Gleitkomma- oder Divisionsbefehl der Hardware (x86-64 und aarch64). Die
`fpr`-Operationen, die Smith-Division und die Gleitkommateile des Samplers
haben keinen bedingten Sprung; einzige Ausnahme ist die feste Schleife der
Division. Wo LLVM Masken umbaut, entsteht `cmov`/`csel` (ohne Sprung). Alle
Masken laufen durch die Barriere (`ct::mask64_from_bit`, `cond_neg64`).
Auf x86-64 werden die Masken in
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

**Nachweis (Phase 6, Einzelheiten in PLAN.md 6.1):**
- **Valgrind** (Prinzip ctgrind): Keygen-Seed und Zufall des Samplers als
  geheim markiert; Keygen, Laden, Sign, Verify ohne jede Meldung auf
  x86-64 (Release und opt-level 0). Ein Selbsttest und zwei Gegenproben
  zeigen, dass die Prüfung greift. Sechs Befunde wurden dabei behoben,
  u. a. Sprünge, die LLVM im portierten Keygen aus Masken gebaut hatte,
  und Schiebungen mit geheimer Weite (jetzt `ct::shr64`/`shl64`).
- **dudect** auf x86-64-Hardware: alle Bausteine |t| < 4.5 (Gleitkomma
  ≤ 1.7, Sampler ≤ 1.0, Sign 3.7, erklärt durch die erlaubte,
  schlüsselabhängige Zahl der Neustarts).
- **Assembler:** keine Gleitkomma- oder Divisionsbefehle der Hardware,
  keine bedingten Sprünge in den Gleitkomma- und Sampler-Funktionen
  (x86-64 und aarch64).

Offen: Valgrind auf aarch64 läuft im CI-Job `ctgrind`; dudect auf aarch64
braucht echte Hardware. Gegen Power- und EM-Angriffe schützt die
Implementierung nicht (PLAN.md §1).

## Aufbau

```
src/
  lib.rs       öffentliche API: keygen, keygen_from_seed, SigningKey,
               VerifyingKey, Signature, LogN, Params, Error
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
  ntrugen.rs   Keygen: f, g ziehen, Prüfungen, NTRUSolve (Portierung)
  zint.rs      Ganzzahlen fester Länge, Rechnen mod p, NTT (Portierung)
  fft_ref.rs   FFT der Referenz (n/2 Werte), nur für NTRUSolve
  keygen_tables.rs  Primzahlen und Wurzeln der Referenz (erzeugt)
  fuzzing.rs   Einstiegspunkte für cargo fuzz (Feature `fuzzing`)
tests/         KAT-Tests, Leser für KAT- und Python-Testvektoren
scripts/       Erzeugung von src/fft_table.rs und src/keygen_tables.rs
examples/      seed_corpus: Start-Korpus für die Fuzz-Ziele;
               ctgrind, dudect: Prüfung der konstanten Laufzeit
fuzz/          Fuzz-Ziele (cargo fuzz)
ctgrind.sh     Valgrind-Prüfung (examples/ctgrind.rs)
```
