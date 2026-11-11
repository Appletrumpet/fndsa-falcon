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
| 6 | Seitenkanal-Prüfung (Valgrind, dudect, Assembler) | fertig (dudect auf aarch64 nur im CI-Job) |
| 7 | KAT-Schlüssel byte-genau aus den Seeds | fertig (alle 200) |
| 8 | Messungen nach Messprotokoll, Feature `native-fpu` | fertig |

Das Crate kann Schlüssel **erzeugen**, Signaturen **erzeugen** und
**prüfen**, für Falcon-512 und Falcon-1024.

```rust
let (sk, pk) = fndsa::keygen(LogN::FALCON_512, &mut rng)?; // rng: z. B. OsRng
let sk_bytes = sk.to_bytes();                // speichern (Zeroizing)
let sk = SigningKey::from_bytes(&sk_bytes)?; // laden: G, Basis, Baum, Prüfung
let sig = sk.sign(msg, &mut rng);           // oder try_sign: Result statt Panik
assert!(pk.verify(msg, &sig));
```

`keygen_from_seed(logn, &seed)` erzeugt denselben Schlüssel aus demselben
Seed (48 Bytes); mit den Seeds der NIST-KAT-Dateien entstehen byte-genau
die KAT-Schlüssel.

Laufzeit nach dem Messprotokoll aus PLAN.md 5.2 (Median, Release, ein
Thread, AMD Zen 3 unter Windows 11; Faktor = Python / Rust):

| Operation | n | Python | Rust emuliert | Faktor | Rust `native-fpu` | Faktor |
|---|---|---|---|---|---|---|
| Keygen | 512 | 736 ms | 21,8 ms | 34 | 11,6 ms | 63 |
| sk laden | 512 | 11,6 ms | 5,38 ms | 2,2 | 2,77 ms | 4,2 |
| Sign | 512 | 17,2 ms | 6,66 ms | 2,6 | 3,39 ms | 5,1 |
| Verify | 512 | 2,89 ms | 18,4 µs | 157 | 17,7 µs | 163 |
| Keygen | 1024 | 2720 ms | 67,2 ms | 40 | 38,8 ms | 70 |
| sk laden | 1024 | 29,3 ms | 12,5 ms | 2,4 | 6,51 ms | 4,5 |
| Sign | 1024 | 48,8 ms | 14,3 ms | 3,4 | 7,33 ms | 6,7 |
| Verify | 1024 | 8,16 ms | 36,8 µs | 222 | 36,8 µs | 222 |

Standard sind emulierte Gleitkommazahlen. Das Feature `native-fpu` nutzt
für Addition, Multiplikation und Wurzel die Gleitkommaeinheit (gleiche
Ergebnisse, Division bleibt emuliert); es ist nur für Prozessoren gedacht,
auf denen diese Befehle nachweislich konstante Laufzeit haben.

```bash
cargo run --release --example bench                        # emuliert
cargo run --release --example bench --features native-fpu  # Hardware-FPU
python scripts/bench_python.py                             # Python
```

## Bauen und testen

```bash
cd Rust
cargo test          # alle Tests, liest die Testdaten aus ../Python/data/
bash ci.sh          # Formatierung, Clippy, Tests, Release-Build, Doku
```

Kleinste unterstützte Rust-Version: 1.87 (`rust-version` in `Cargo.toml`).

**Web-Oberfläche** (Vorführung im Browser, [UI-PLAN.md](UI-PLAN.md)):
Signaturen prüfen mit den fünf Schritten von Verify, Bit kippen, eigene
Daten, Schlüssel erzeugen und signieren, dazu ein Chat, in dem jede
Nachricht signiert und beim Empfänger geprüft wird (mit Prüfbericht und
„Nachricht verfälschen“). Bauen und starten (Linux oder WSL;
einmal vorher `rustup target add wasm32-unknown-unknown` und
`cargo install wasm-bindgen-cli --version 0.2.100 --locked`):

```bash
bash web/build.sh
python -m http.server -d web 8000     # http://localhost:8000
```

Für Erklärungen gibt es `VerifyingKey::verify_report`: Schritt, an dem
Verify scheitert, Norm ‖(s₁, s₂)‖² und Schranke ⌊β²⌋.

Die CI auf GitHub (`.github/workflows/rust.yml`) hat neun Jobs:

- `check`: `ci.sh` auf x86-64 und aarch64;
- `ctgrind`: Valgrind-Prüfung der konstanten Laufzeit
  (`ctgrind.sh --matrix`, zehn Compiler-Einstellungen) auf x86-64 und
  aarch64;
- `platforms`: alle Tests auf i686 (32 Bit) und s390x (Big-Endian, QEMU),
  wasm32 übersetzen;
- `sanitizer`: alle Tests mit AddressSanitizer;
- `web`: Tests der WASM-Hülle, Web-Oberfläche bauen; `pages`
  veröffentlicht sie auf `main` über GitHub Pages;
- `dudect`: Zeitmessung auf x86-64 und aarch64, Tabelle in der
  Zusammenfassung des Laufs (geteilte Maschinen: nur ein Hinweis, der Job
  schlägt nicht fehl);
- `msrv`: Tests mit Rust 1.87;
- `fuzz`: baut die acht Fuzz-Ziele, erzeugt den Start-Korpus und lässt
  jedes Ziel 60 Sekunden laufen.

KAT-Dateien mit Rust erzeugen und mit den offiziellen vergleichen
(PLAN.md 5.1):

```bash
cargo run --release --example kat_rsp      # schreibt nach target/kat
```

Konstante Laufzeit prüfen (PLAN.md §6):

```bash
bash ctgrind.sh     # Valgrind, nur Linux (z. B. in Docker); CI-Job "ctgrind"
bash ctgrind.sh --matrix   # zusätzlich opt-level 1/2/s/z, LTO, x86-64-v3, native-fpu, 1.87
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
- **alle 200 KAT-Fälle wie im NIST-Programm** (`tests/kat_keygen.rs`):
  der Seed der KAT-Datei geht durch den AES-256-CTR-DRBG
  (`tests/common/drbg.rs`, prüft sich selbst an allen Seeds und
  Nachrichten der KAT-Dateien), daraus 48 Bytes für `keygen_from_seed` und
  danach Salt und Zufall für `sign`. sk und pk sind byte-genau gleich, das
  Salt der Signatur ebenfalls; die Signatur selbst weicht wegen L7/L9 ab
  und besteht Verify mit dem KAT-pk. `examples/kat_rsp.rs` schreibt
  daraus KAT-Dateien im NIST-Format und vergleicht Feld für Feld;
- Keygen für verkleinerte Grade n = 2 … 256: fG − gF = q, kleine
  Koeffizienten; zufällige Schlüssel lassen sich speichern, laden,
  signieren und prüfen; gleicher Seed, gleicher Schlüssel;
- Bausteine von NTRUSolve: Primzahltabelle (p ≡ 1 mod 2048, Wurzel g,
  CRT-Faktor s), Rechnen mod p, NTT, binärer GCD, FFT der Referenz;
- ungültige Secret Keys: f nicht invertierbar, Grad ohne Parametersatz,
  erfundene Schlüssel (`InvalidKey`, siehe unten); alle 200 KAT-Schlüssel
  bestehen die Schlüsselprüfung; jede Teilprüfung von `key_valid_mask`
  einzeln mit kleinen Beispielen (n = 2).

Erweiterte Tests (Einzelheiten und Zahlen in PLAN.md 7.1):

- **Mutationstests** mit `cargo-mutants`: absichtlich eingebaute Fehler
  müssen einen Test scheitern lassen; überlebende Mutationen wurden
  ausgewertet und die echten Lücken geschlossen;
- **alle übrigen Python-Testvektoren** (`src/python_vectors.rs`):
  Kodierung, mod q, HashToPoint, Bausteine von Verify, `flow.verify` und
  die Schlüssel aus `flow.keygen` (n = 2 … 1024), 510 Fälle;
- **Grenzfälle für Verify** (`tests/verify_edge.rs`): Norm genau auf β²
  angenommen, β² + 1 abgelehnt; jedes einzelne gekippte Bit abgelehnt; nur
  die gepolsterte und die ungepolsterte Länge gültig; nur das passende
  Header-Byte; leere und 1 MiB lange Nachrichten;
- **Statistik** (`tests/statistics.rs`): s₂ ist gaussverteilt mit dem σ
  aus Tab. 3.3 (χ²-Test) und für verschiedene Schlüssel gleich verteilt;
- **Fehlersimulation**: zufällig gekippte Bits im geladenen Schlüssel
  werden alle erkannt;
- **Löschtest** (`tests/zeroize.rs`): kein Stück von f, g, F bleibt in
  freigegebenem Speicher;
- **Valgrind** unter zehn Compiler-Einstellungen (`ctgrind.sh --matrix`);
- **andere Plattformen**: 32 Bit und Big-Endian (alle Tests), wasm32
  (übersetzt); **AddressSanitizer** ohne Meldung;
- **Dauertest** (`cargo test --release --test soak -- --ignored`);
- weitere **Fuzz-Ziele** für Sign, Keygen und die Gleitkomma-Emulation.

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
- Schutz gegen Fault-Angriffe (PLAN.md 6.2): jede Signatur muss Verify
  bestehen und eine Norm² von mindestens β²/2 haben (erkennt einen
  ausgefallenen Sampler, dessen Signaturen Verify bestehen); vor und nach
  jedem Sign wird eine Prüfsumme (SHAKE256) über den ganzen Schlüssel
  verglichen. `try_sign` gibt dann `Error::FaultDetected` zurück, `sign`
  bricht mit einer Panik ab. Kostet rund 7 % beim Signieren;
- auf aarch64 ist während Keygen, Laden und Sign das DIT-Flag gesetzt
  (Data Independent Timing), wenn die CPU es kennt (`dit_available()`);
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
  x86-64 und aarch64 (Release und opt-level 0; lokal in Docker und im
  CI-Job `ctgrind`). Ein Selbsttest und zwei Gegenproben
  zeigen, dass die Prüfung greift. Sechs Befunde wurden dabei behoben,
  u. a. Sprünge, die LLVM im portierten Keygen aus Masken gebaut hatte,
  und Schiebungen mit geheimer Weite (jetzt `ct::shr64`/`shl64`).
- **dudect** auf x86-64-Hardware: alle Bausteine |t| < 4.5 (Gleitkomma
  ≤ 2.0, Sampler ≤ 1.9, Sign 1.7, ein Sign-Versuch ohne Neustart 1.7,
  gemessen mit Fault-Schutz); die Zahl der SamplerZ-Runden ist für alle
  Schlüssel gleich. Messfehler im Prüfprogramm (ungleiche Vorbereitung der
  Eingaben, feste Speicheradresse des festen Schlüssels) sind in PLAN.md
  6.1 und 6.2 beschrieben.
- **Assembler:** keine Gleitkomma- oder Divisionsbefehle der Hardware,
  keine bedingten Sprünge in den Gleitkomma- und Sampler-Funktionen
  (x86-64 und aarch64).

dudect auf aarch64 läuft im CI-Job `dudect` auf dem ARM-Runner (echter
Prozessor, aber geteilte Maschine, also nur ein Hinweis); ein eigenes
ARM-Gerät wäre genauer. Gegen Power- und EM-Angriffe schützt die
Implementierung nicht (PLAN.md §1). Die Laufzeiten oben sind vor dem
Fault-Schutz und vor der schnelleren Division gemessen. Seither (PLAN.md
5.3): Sign 4,28 ms (Falcon-512) bzw. 9,12 ms (Falcon-1024) emuliert, mit
Fault-Schutz, also gut 40 % schneller als in der Tabelle; Verify und Keygen
im Wesentlichen unverändert.

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
tests/         KAT-Tests, Leser für KAT- und Python-Testvektoren;
               verify_edge (Grenzfälle Verify), statistics (Verteilung
               von s₂), zeroize (Löschtest), soak (Dauertest, --ignored)
scripts/       Erzeugung von src/fft_table.rs und src/keygen_tables.rs;
               bench_python.py: Laufzeit der Python-Version
examples/      seed_corpus: Start-Korpus für die Fuzz-Ziele;
               ctgrind, dudect: Prüfung der konstanten Laufzeit;
               kat_rsp: KAT-Dateien im NIST-Format erzeugen;
               export_kat_json: KAT-Fälle für die Web-Oberfläche;
               bench: Laufzeitmessung nach Messprotokoll
wasm/          WASM-Hülle für die Web-Oberfläche (eigenes Paket)
web/           Web-Oberfläche: index.html, style.css, app.js, logo.svg,
               build.sh (erzeugt pkg/ und kat.json)
fuzz/          Fuzz-Ziele (cargo fuzz): decode_pk, decode_sk, decompress,
               verify, signing_key, sign, keygen, fpr
ctgrind.sh     Valgrind-Prüfung (examples/ctgrind.rs)
```
