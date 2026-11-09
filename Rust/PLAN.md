# Plan: FN-DSA (Falcon) in Rust, seitenkanalresistent

Stand: 9. November 2026, Branch `Rust`. Phase 0 und 1 sind umgesetzt
(Crate, `params`, `ct` in Grundform, `modq`, `hashing`, `encoding`, Verify;
alle 200 KAT-Signaturen werden akzeptiert, pk- und sk-Format byte-genau).
Noch offen aus Phase 0: CI-Skript. Abweichung: Vollständige Parametersätze
(σ, β², Signaturlänge) gibt es bisher nur für 512 und 1024; die verkleinerten
Varianten kommen mit Phase 5.

Grundlage: Falcon Specification v1.2 (Ebene 0 der Dokumentation), die
Dokumentation „FN-DSA (Falcon)“ (Ebenen 1–4) und die Python-Implementierung
in `Python/`. FIPS 206 ist noch nicht final (Stand Ende 2026); sobald es
erscheint, wird abgeglichen.

---

## 1. Ziel und Abgrenzung

**Ziel:** Eine Rust-Implementierung von Falcon-512 und Falcon-1024
(KeyGen, Sign, Verify, alle Byteformate). Alle Operationen auf geheimen Daten
laufen in **konstanter Zeit**.

**Was „sicher vor Side-Channel-Attacks“ hier heisst** (das muss festgelegt
werden, weil der Begriff sonst unerfüllbar ist):

| Angriffsklasse | Abgedeckt? | Massnahme |
|---|---|---|
| Timing (Laufzeit hängt vom Geheimnis ab) | **ja** | konstante Laufzeit, keine geheimabhängigen Verzweigungen |
| Cache / Speicherzugriff (Tabellenindex hängt vom Geheimnis ab) | **ja** | keine geheimabhängigen Speicheradressen, Tabellen ganz durchlaufen |
| Branch-Prediction / Spectre-artige Leaks über Kontrollfluss | **ja** (Kontrollfluss) | wie Timing |
| Reste im Speicher (Schlüssel bleibt nach Gebrauch im RAM) | **ja** | `zeroize` für alle geheimen Puffer |
| Leistungsaufnahme / EM (DPA, z. B. „FALCON Down“, 2021) | **nein**, nur benennen | bräuchte Masking; Forschungsstand, nicht Kernumfang |
| Fault-Angriffe (Fehler einschleusen) | **teilweise** | optional Verify-nach-Sign, Plausibilitätsprüfungen |

Konstante Laufzeit schützt gegen Angreifer, die Zeit messen (auch über das
Netz) und Cache-Zustände beobachten. Gegen jemanden mit Oszilloskop am Gerät
schützt sie nicht. Das gehört so in die Doku.

---

## 2. Was die Dokumentation liefert, und was nicht

### 2.1 Direkt übernehmbar

- Ebenen 1–3: Algorithmen, Modulstruktur, Bausteine und Abhängigkeiten. Die
  Rust-Module entsprechen den Python-Modulen (Abschnitt 4).
- Parameter (Tab. 3.3), Byteformate (§3.11), HashToPoint (Alg. 3),
  SamplerZ-Struktur (Alg. 12–15), ffLDL/ffSampling (Alg. 8–11).
- Testdaten: KAT und Sampler-Testvektoren (`Python/data/`).

### 2.2 Lücken und Widersprüche in der Doku

Wo die Doku nichts sagt oder für Rust/konstante Laufzeit nicht passt, nehme
ich die **Standard-Implementierung** (Referenzimplementierung von T. Pornin
aus dem NIST-Paket, beschrieben in „New Efficient, Constant-Time
Implementations of Falcon“, 2019):

| # | Punkt | Doku | Problem | Vorschlag |
|---|---|---|---|---|
| L1 | Seitenkanalresistenz | 7.8: ausdrücklich **nicht** im Umfang | keine Vorgaben vorhanden | Techniken der Referenz (Abschnitt 3) |
| L2 | Quellen | 8: „Bestehende Implementierungen dienen nicht als Vorlage“ | widerspricht der Nutzung der Referenz | **entschieden (9.11.2026):** Referenz wird für die Techniken der konstanten Laufzeit genutzt; in der Doku als Änderung des Vorgehens festhalten (neuer Abschnitt „Ebene 5: Rust“) |
| L3 | Gleitkomma | Python `float`/`complex` | Hardware-Division und -Wurzel, Rundung und Umwandlung in Ganzzahl sind nicht überall konstante Laufzeit | emulierte IEEE-754-Arithmetik nur mit Ganzzahlen (`fpr`, wie die Referenz) |
| L4 | NTRUSolve | Python-Ganzzahlen beliebiger Grösse | Bigints sind nie konstante Laufzeit; `reduce` läuft geheimabhängig oft | Ganzzahlen fester Länge (31-Bit-Wörter), RNS/CRT und feste Grössen pro Tiefe wie in der Referenz |
| L5 | `decompress` | „keine Obergrenze für \|sᵢ\|“ | in Rust braucht es einen festen Typ (`i16`) | **entschieden (9.11.2026):** wie die Referenz, \|sᵢ\| > 2047 ablehnen; im Rahmen der Normschranke kommt das bei echten Signaturen praktisch nie vor |
| L6 | Keygen und sk-Format | 7.5: keine Prüfung, ob f, g, F ins sk-Format passen | bei Falcon-1024 lässt sich etwa 1 von 10⁴ Schlüsseln nicht speichern | **entschieden (9.11.2026):** wie die Referenz, solche Kandidaten verwerfen (f, g nach FG_BITS, F, G mit 8 Bit) |
| L7 | BerExp | Alg. 14: Schleife bricht ab, sobald ein Byte entscheidet | Zahl der gezogenen Bytes hängt von z ab | **entschieden (9.11.2026):** nur streng konstant, immer 8 Bytes, siehe 3.4 |
| L8 | FFT-Darstellung | alle n Werte, Reihenfolge ζₖ | doppelte Arbeit | nur n/2 Werte (der Rest ist konjugiert); Reihenfolge der Doku beibehalten, damit die Python-Werte vergleichbar bleiben (mit Toleranz, siehe Abschnitt 7) |
| L9 | Zufall | beliebiges `rng.random_bytes` | SamplerZ braucht pro Signatur Tausende Bytes | Seed aus OS-Zufall → SHAKE256 → ChaCha20-PRNG (Referenz) |
| L10 | KAT byte-genau | 7.3: nicht reproduzierbar | stimmt nur ohne den RNG-Ablauf der Referenz | **entschieden (9.11.2026):** die **KAT-Schlüssel** werden byte-genau reproduziert, mit dem Keygen-Ablauf der Referenz (Seed → SHAKE256 → Tabellen-Gauss), siehe 3.5 und Phase 7. Die **KAT-Signaturen** nicht: wegen L7 zieht BerExp andere Bytes als die Referenz |
| L11 | `_SIGMA_EPS` (Python) | nicht dokumentiert | nur wegen gerundetem σmin nötig | in Rust exakte Konstanten, keine Toleranz; die Prüfung σ′ ∈ [σmin, σmax] wird zur Debug-Assertion, weil σ′ geheim ist |

**Entschieden:** L2, L5, L6, L7, L10. Alle Punkte aus 2.2 sind damit
entschieden.

**Folge von L5/L6 für die Python-Version:** Rust und Python verhalten sich an
zwei Stellen unterschiedlich. Python akzeptiert Signaturen mit \|sᵢ\| > 2047
(sofern die Norm passt) und kann in seltenen Fällen nicht speicherbare
Schlüssel erzeugen; Rust nicht. **Entschieden (9.11.2026):** Python wird
**nicht** angeglichen. Der Unterschied wird in der Doku festgehalten (Ebene 5:
Rust); `test_rejects_huge_valid_coefficient` und die Designentscheidung in 7.5
bleiben für Python bestehen.

**Umfang der Referenznutzung (zu L2):** Die Referenz dient als Quelle für
*Techniken*: emulierte Gleitkommazahlen, Vergleiche ohne Verzweigung im
Sampler, NTRUSolve mit fester Länge, RNG-Ablauf. Der Algorithmus selbst bleibt
aus der Spezifikation hergeleitet (Ebenen 1–3). Jede Stelle, die einer
Technik der Referenz folgt, bekommt im Code einen Verweis
(`// Referenz: <Datei>, <Funktion>`), damit sie in der Doku nachvollziehbar
bleibt. Code wird nicht wörtlich übernommen, sondern in Rust neu geschrieben.

**Ausnahme Keygen (Folge von L10):** Damit die KAT-Schlüssel byte-genau
herauskommen, muss der Keygen-Teil Schritt für Schritt wie die Referenz
arbeiten: f, g ziehen (`keygen.c`), Reihenfolge der Prüfungen und vor allem
`solve_NTRU` mit `reduce` (dieselben Skalierungen, dieselbe Zahl an
Durchläufen, dieselben Gleitkommanäherungen). Schon eine andere Rundung in
`reduce` ergibt ein anderes F. Für diesen Teil ist die Rust-Version deshalb
eine **Portierung** der Referenz, nicht eine Herleitung aus der Spezifikation.
So wird es auch in der Doku (Ebene 5) benannt. Für Sign, Verify, Sampler, FFT
und Formate gilt weiter die Herleitung aus der Spezifikation.

---

## 3. Seitenkanal-Konzept

### 3.1 Was ist geheim?

| Daten | geheim? | Folge |
|---|---|---|
| f, g, F, G, Basis, Falcon-Baum | **ja** | alles konstante Laufzeit |
| Zwischenwerte in ffSampling (t, z, Zielwerte der Blätter) | **ja** | konstante Laufzeit |
| SamplerZ: μ, σ′, z₀, b, x | **ja** | konstante Laufzeit |
| Zufallsbytes des Samplers | **ja** | nicht loggen, nach Gebrauch löschen |
| Salt r, Nachricht m, c = HashToPoint(r‖m) | nein | normaler Code erlaubt |
| s₂ (wird veröffentlicht), Kompression | nein | normaler Code erlaubt |
| h, Verify komplett | nein | normaler Code erlaubt |
| Ob eine Signatur neu gezogen wurde (Norm zu gross) | nein* | Neustart erlaubt |
| Ob ein Keygen-Kandidat verworfen wurde | nein* | Neustart erlaubt, Kandidat wird verworfen |

\* Verworfene Kandidaten werden nie verwendet. Die Zahl der Neustarts verrät
deshalb nichts über den Schlüssel, der am Ende benutzt wird.

**Ausnahme: Neuziehen einzelner Koeffizienten im Keygen (3.5).** Das passiert
*innerhalb* des Schlüssels, der später benutzt wird. Die Laufzeit verrät, wie
oft ein Koeffizient ausserhalb von ±`lim` lag und wie oft der letzte
Koeffizient wegen der Parität neu gezogen wurde. Die verworfenen Werte selbst
werden nicht verwendet; übrig bleibt höchstens ein sehr kleiner Hinweis auf die
Parität der Koeffizientensumme, die ohnehin festgelegt (ungerade) ist. Die
Referenz nimmt das genauso in Kauf, und wegen L10 muss Rust es übernehmen. In
der Doku als bewusste, begründete Ausnahme festhalten.

**Verify und HashToPoint brauchen also keine konstante Laufzeit.** Das spart
Aufwand und hält diese Teile einfach. Nur falls die Nachricht selbst geheim
wäre, bräuchte es die konstante Variante von HashToPoint (§3.7); das ist hier
nicht nötig.

### 3.2 Regeln für den Code auf geheimen Daten

1. Kein `if`, `match`, `while` oder `&&`/`||`, das von geheimen Werten abhängt.
2. Kein Array-Index, der von geheimen Werten abhängt. Tabellen (RCDT, Gauss)
   werden ganz durchlaufen.
3. Auswahl über Masken: `x ^ (mask & (x ^ y))`, Masken aus Vorzeichenbits
   (`(v >> 63)` bei Ganzzahlen mit Vorzeichen).
4. Keine Hardware-Division `/`, `%` auf geheimen Ganzzahlen (auf manchen CPUs
   variabel); Reduktion mod q über Montgomery bzw. Barrett.
5. Keine `f64`-Operationen auf geheimen Daten im Standardmodus (siehe 3.3).
6. Gegen LLVM-Optimierungen: Masken über `subtle::Choice` bzw.
   `core::hint::black_box` als Barriere; kritische Funktionen im Assembler
   prüfen (`cargo asm`). `black_box` ist laut Rust-Doku nur „best effort“,
   keine Garantie; deshalb ist die Assembler- und Valgrind-Prüfung (Abschnitt 6)
   Pflicht und nicht nur Ergänzung.
7. Geheime Puffer in `Zeroizing<…>` bzw. mit `ZeroizeOnDrop`.
8. Kein `Debug`/`Display`, das geheime Werte ausgibt.

### 3.3 Gleitkomma (`fpr`)

Signieren und Keygen rechnen mit Gleitkomma (FFT, LDL, ffSampling, Wurzel bei
der Normalisierung der Blätter, Division in `fft_div`). Auf geheimen Werten
ist das kritisch:

- Division und Wurzel haben auf vielen CPUs datenabhängige Latenz.
- Subnormale Zahlen sind auf vielen CPUs viel langsamer.
- `f64 as i64` (Runden, Abschneiden) erzeugt je nach Ziel Verzweigungen.

**Vorschlag:** Typ `Fpr(u64)` mit **emulierter** IEEE-754-Arithmetik nur aus
64-Bit-Ganzzahloperationen (add, sub, mul, div, sqrt, rint, floor, trunc,
of_i64), jede mit konstanter Laufzeit und korrekt gerundet wie IEEE-754. Das
ist der Ansatz der Referenz. Da IEEE-754 korrekt rundet, liefert die
Emulation für normale Zahlen bitgleich dieselben Ergebnisse wie Hardware-`f64`,
wenn die Reihenfolge der Operationen gleich ist.

**Zahlenbereich:** Wie die Referenz unterstützt `fpr` keine subnormalen Zahlen,
kein ±∞ und kein NaN (beim Umsetzen in `fpr.h` der Referenz nachprüfen).
Unterlauf ergibt 0. In Falcon kommen diese Fälle nicht vor; sie werden in der
Doku als bewusste Einschränkung genannt. Die Tests gegen `f64` decken deshalb
nur Eingaben und Ergebnisse im normalen Bereich ab, plus gezielte Tests für
das Verhalten bei Unterlauf.

**Kein bitgleicher Vergleich mit Python:** Python wird nicht angepasst (2.2),
und dort weichen die Rechenwege ab: ζₖ kommt aus `cmath.exp` (nicht korrekt
gerundet, je nach Plattform verschieden), `split_fft` und `fft_div` teilen
durch komplexe Zahlen mit CPythons eigenem Divisionsalgorithmus, und die
ζ-Tabelle wird auf jeder Ebene neu berechnet. Rust rechnet mit exakten
Konstanten und `conj(ζ)/2` statt Division durch `2ζ`. Gleitkommawerte werden
deshalb mit Toleranz verglichen (Abschnitt 7).

Optional als Feature `native-fpu`: `f64` direkt, nur für Ziele, auf denen
add/mul/sqrt nachweislich konstante Laufzeit haben (z. B. x86-64 mit SSE2, ohne
Division auf geheimen Daten). Standard bleibt die Emulation.

### 3.4 Sampler

- **BaseSampler (Alg. 12):** 72-Bit-Zufallswert, Vergleich mit allen 18
  RCDT-Einträgen in drei 24-Bit-Teilen ohne Verzweigung; Summe der
  Vergleichsbits. (Die Python-Version macht das schon ähnlich.)
- **ApproxExp (Alg. 13):** Festkomma mit `u128`-Multiplikation, keine
  Verzweigung. Auf x86-64 und aarch64 ist das eine native Multiplikation
  (Abschnitt 10).
- **BerExp (Alg. 14), entschieden (L7): streng konstant.** `s = min(s, 63)`
  über Maske, dann immer **8 Bytes** ziehen, big-endian zu `u` (64 Bit)
  zusammensetzen und `u < z` ohne Verzweigung bestimmen (Borrow einer
  128-Bit- bzw. 64-Bit-Subtraktion). Kein Abbruch nach dem ersten Byte, die
  Zahl der gezogenen Bytes ist immer gleich.
  - **Gleiches Ergebnis wie Alg. 14:** Alg. 14 vergleicht `u` und `z` Byte für
    Byte von oben und hört beim ersten Unterschied auf. Das ist genau der
    Vergleich `u < z` auf 64 Bit. Bei gleichen Zufallsbytes liefern beide
    Varianten also dasselbe Bit; nur der **Verbrauch** an Zufall ist anders
    (immer 8 statt meist 1 Byte).
  - **Folge:** Die Sampler-Testvektoren stimmen ab dem ersten BerExp-Aufruf
    nicht mehr Byte für Byte, und damit auch nicht die exakte Signatur aus dem
    Testvektor. Wie trotzdem getestet wird, steht in Abschnitt 7.
  - Mehrverbrauch: pro SamplerZ-Runde 7 Bytes mehr. Bei rund 2 Runden pro
    Aufruf und 1024 Aufrufen (Falcon-512) etwa 14 KB ChaCha20-Ausgabe mehr
    pro Signatur. Messbar, aber klein gegenüber der emulierten FFT.
- **SamplerZ (Alg. 15):** Die Zahl der Ablehnungsrunden ist durch
  ccs = σmin/σ′ **unabhängig von σ′ und μ** („isochrone“ Gauss-Stichprobe,
  Howe/Prest/Ricosset/Rossi 2020). Die Schleife darf also bleiben; nur das
  Innere muss konstante Laufzeit haben. `floor(μ)` und die Berechnung von x
  laufen über `fpr`.

### 3.5 Keygen

- **f, g ziehen (wegen L10 wie die Referenz):** Tabellen-Gauss mit
  vollständigem Tabellendurchlauf statt der Summe von SamplerZ-Ziehungen aus
  der Doku (K9). Beides erfüllt Gl. 3.29, die Spezifikation lässt den Weg
  offen. Es gibt nur **einen** Weg, damit Keygen nicht doppelt gebaut und
  getestet werden muss.
- **Keygen-Ablauf der Referenz (L10).** Alle Punkte sind beim Umsetzen in der
  Referenz nachzuprüfen (`nist.c`, `keygen.c`), sie stammen aus meiner
  Erinnerung an die Referenz:
  - KAT: AES-256-CTR-DRBG der NIST-API (`rng.c`), gestartet mit dem Seed aus
    der `.req`/`.rsp`-Datei, liefert 48 Bytes. Diese gehen in SHAKE256; aus
    dem SHAKE-Strom zieht Keygen alle Zufallswerte.
  - Normaler Betrieb: 48 Bytes OS-Zufall statt DRBG, sonst **derselbe** Weg.
    Damit prüft der KAT-Test genau den Code, der auch produktiv läuft.
  - Tabellen-Gauss: 64-Bit-Zufallswerte aus SHAKE, Vergleich mit allen
    Tabelleneinträgen, bei kleinem n Summe mehrerer Ziehungen (Faktor
    1024/n). Die 64-Bit-Werte werden nach meiner Erinnerung
    **little-endian** zusammengesetzt (`get_rng_u64`); nachprüfen.
  - Ablehnung innerhalb des Ziehens: Die Referenz zieht **einzelne
    Koeffizienten** neu, nicht das ganze f bzw. g (`poly_small_mkgauss`):
    - Liegt ein Koeffizient ausserhalb von ±`lim` (aus FG_BITS), wird nur
      dieser Koeffizient neu gezogen. Damit ist L6 für f und g schon beim
      Ziehen erfüllt, nicht erst durch Verwerfen des Kandidaten.
    - Beim **letzten** Koeffizienten wird so lange neu gezogen, bis die Summe
      aller Koeffizienten ungerade ist (sonst ist die Resultante gerade und
      NTRUSolve scheitert sicher).

    Diese Regeln müssen genau übernommen werden, sonst verschiebt sich der
    Zufallsstrom.
  - Prüfungen in derselben Reihenfolge und mit denselben Schranken wie die
    Referenz. Nach meiner Erinnerung: (1) ‖(g, −f)‖² gegen 1.17²·q (ganzzahlig),
    (2) orthogonalisierte Norm γ in `fpr` gegen ≈ 16822.41, (3) Public Key
    h = g/f, scheitert, wenn f nicht invertierbar ist, (4) NTRUSolve inkl.
    Prüfung, ob F und G in 8 Bit passen (L6). Jede Abweichung bei *welcher*
    Kandidat angenommen wird, ändert den Schlüssel.
- Das Ziel ist: gleicher Seed → gleiche Bytes für f, g, F und damit
  für sk und pk wie in den KAT-Dateien. Weil NTRUSolve wie die Referenz mit
  fester Länge arbeitet, muss dabei auch exakt dasselbe (F, G) herauskommen;
  das ist der strengste Test für `zint`/`ntrugen`.
- **Prüfungen** (invertierbar, γ, sk-Format, NTRUSolve erfolgreich): Ergebnis
  ja/nein darf verzweigen (Kandidat wird verworfen). Die Berechnung selbst
  (NTT, FFT-Norm) läuft mit konstanter Laufzeit.
- **NTRUSolve (L4):** Hier liegt der grösste Aufwand.
  - Ganzzahlen mit fester Wortzahl je Rekursionstiefe (Tabellen der maximalen
    Bitlängen wie in der Referenz), keine dynamischen Bigints (`num-bigint`
    ist nicht konstant und scheidet aus).
  - Feldnormen und Resultanten über RNS: Rechnen modulo vieler 31-Bit-Primzahlen
    mit NTT, Rückweg per CRT.
  - xgcd im Basisfall: binärer erweiterter GCD mit fester Rundenzahl.
  - `reduce` mit fester Zahl von Durchläufen, abhängig von der Tiefe und
    nicht von den Daten. Gleitkommanäherung der oberen Wörter (`fpr`),
    k·f und k·g exakt abziehen.
  - **Achtung:** Diese Reduktion endet nicht zwingend auf demselben
    Repräsentanten (F, G) wie die Python-Version (die bis k = 0 läuft). Der
    Vergleich mit den Sampler-Testvektoren prüft deshalb die
    **Eigenschaften** (fG − gF = q, Grösse innerhalb des sk-Formats). Exakt
    geprüft wird (F, G) über die KAT-Schlüssel (L10), die mit der Referenz
    erzeugt wurden.

### 3.6 Sign

- `compute_target`, `ff_ldl`, `normalize_leaves`, `ff_sampling`,
  `compute_signature_vector`: alles `fpr`, kein Kontrollfluss auf Daten. Die
  Rekursion von ffSampling hängt nur von n ab, ist also unproblematisch.
- Normprüfung: Summe in konstanter Zeit; nur das Ergebnis ja/nein darf
  verzweigen (Neustart).
- Ab hier ist s₂ öffentlich: Kompression mit normalem Code.
- Passt das komprimierte s₂ nicht in die feste Signaturlänge (Tab. 3.3), wird
  neu signiert (neues Salt, neue Zufallswerte). Das Ergebnis ja/nein darf
  verzweigen.
- Optional (Fault-Schutz): nach dem Signieren `verify` aufrufen; das kostet
  wenig im Vergleich zum Signieren.

### 3.7 Modulare Arithmetik (mod q)

- NTT mit Montgomery-Multiplikation in `u32`, Reduktion über bedingte
  Subtraktion mit Masken. Wird für den Invertierbarkeitstest auf f (geheim) und
  für h = g/f gebraucht.
- Invertierbarkeit: „enthält NTT(f) eine 0?“ ohne Abbruch über alle Werte
  sammeln (OR über Masken).
- Inverse mod q: per Potenzierung (Fermat) mit fester Exponentenkette, nicht
  über den euklidischen Algorithmus.

---

## 4. Aufbau des Crates

```
Rust/
  Cargo.toml          # crate "fndsa", edition 2021, std; Ziele x86-64 und aarch64
  src/
    lib.rs            # öffentliche API: keygen, sign, verify, Typen, Byteformate
    params.rs         # Tab. 3.3, logn 1..=10 (reduzierte Varianten für Tests)
    ct.rs             # Hilfen für konstante Laufzeit: Masken, Auswahl, Vergleich
    fpr.rs            # emulierte Gleitkommazahlen (L3), optional native-fpu
    poly.rs           # Ganzzahlpolynome kleiner Grösse (i16/i32)
    modq.rs           # NTT mod 12289, Montgomery
    fft.rs            # FFT auf Fpr, n/2 komplexe Werte (L8), split/merge
    hashing.rs        # HashToPoint (variable Laufzeit, öffentlich)
    encoding.rs       # Kompression, pk/sk/sig-Formate (öffentlich)
    prng.rs           # SHAKE256-Seed → ChaCha20 (L9)
    sampler.rs        # BaseSampler, ApproxExp, BerExp, SamplerZ
    zint.rs           # Ganzzahlen fester Länge, RNS, CRT (für NTRUSolve)
    ntrugen.rs        # f, g ziehen, Prüfungen, NTRUSolve, reduce
    tree.rs           # Basis, Gram-Matrix, ffLDL, Normalisierung
    ffsampling.rs     # Alg. 11
    falcon.rs         # keygen, sign, verify (Ebene 2)
  tests/              # KAT, Sampler-Vektoren, Vergleich mit Python
  benches/            # criterion + dudect (Abschnitt 6)
```

Die Modulnamen entsprechen Ebene 3 der Doku. Neu sind nur `ct`, `fpr`,
`prng` und `zint`; sie kommen aus der Seitenkanal-Anforderung.

**Abhängigkeiten** (bewusst wenige, alle aus RustCrypto bzw. etabliert):

| Crate | Wofür | Bemerkung |
|---|---|---|
| `sha3` | SHAKE256 | Keccak arbeitet ohne Tabellen, konstante Laufzeit |
| `chacha20` | PRNG des Samplers | konstante Laufzeit |
| `zeroize` | Löschen geheimer Puffer | |
| `subtle` | `Choice`, konstante Auswahl/Vergleiche | Optimierungsbarriere |
| `rand_core` / `getrandom` | OS-Zufall, RNG-Trait | `CryptoRngCore` |
| dev: `criterion`, `dudect-bencher`, `serde_json`, `hex` | Benchmarks, Timing-Tests, Testvektoren | nur für Tests |
| dev: `aes` | AES-256-CTR-DRBG der NIST-API für die KAT-Seeds (L10) | nur für Tests, nicht im Produktcode |

**API (Entwurf):**

```rust
pub struct SigningKey { /* f, g, F, G, Baum; ZeroizeOnDrop */ }
pub struct VerifyingKey { /* h */ }
pub struct Signature { salt: [u8; 40], s2_enc: Vec<u8> }

pub struct LogN(u32); // nur 1..=10, geprüft in LogN::new(u32) -> Result<LogN, Error>
pub fn keygen(logn: LogN, rng: &mut impl CryptoRngCore) -> (SigningKey, VerifyingKey);
// zieht 48 Bytes aus rng und ruft keygen_from_seed auf (L10)
pub fn keygen_from_seed(logn: LogN, seed: &[u8; 48]) -> (SigningKey, VerifyingKey);
// deterministisch; für KAT und reproduzierbare Tests
impl SigningKey   { pub fn sign(&self, msg: &[u8], rng: &mut impl CryptoRngCore) -> Signature;
                    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>>; pub fn from_bytes(b: &[u8]) -> Result<Self, Error>; }
impl VerifyingKey { pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool;
                    pub fn to_bytes(&self) -> Vec<u8>; pub fn from_bytes(b: &[u8]) -> Result<Self, Error>; }
```

Die Signaturen folgen den Funktionen aus Ebene 2. `LogN` statt eines
`Params`-Objekts, weil alle Werte daraus folgen; als eigener Typ, damit ein
ungültiges `logn` schon beim Erzeugen als `Err` auffällt und keygen nicht
abbrechen muss. Die Fehlertypen
entsprechen den Designentscheidungen aus 7.5 (`decode_*` → `Err`,
`decompress` ungültig → `verify` liefert `false`).

---

## 5. Reihenfolge der Umsetzung

Jede Phase endet mit grünen Tests. Reihenfolge wie in der Doku (unten nach
oben); Verify kommt zuerst, weil es öffentlich ist und früh gegen alle
200 KAT-Signaturen geprüft werden kann.

Phase 5 und 7 hängen eng zusammen: Ein byte-genaues F gelingt nur, wenn
NTRUSolve von Anfang an wie die Referenz gebaut wird (2.2, Ausnahme Keygen).
Deshalb wird schon in Phase 5 gegen KAT count 0 geprüft; Phase 7 erweitert das
nur noch auf alle Seeds.

| Phase | Inhalt | Prüfung am Ende | Aufwand |
|---|---|---|---|
| 0 | Crate, `params`, Testdaten aus `Python/data/` einbinden, CI-Skript | Build, Tab. 3.3 | klein |
| 1 | `modq` (konstant), `hashing`, `encoding`, `verify` | alle 200 KAT-Signaturen gültig, pk/sk-Formate gegen KAT | klein–mittel |
| 2 | `ct`, `fpr` (emuliert), `fft` | `fpr` bitgleich gegen `f64` für Millionen Zufallswerte im normalen Zahlenbereich inkl. Grenzfälle; FFT gegen Python-Werte mit Toleranz | mittel |
| 3 | `prng`, `sampler` | BaseSampler und ApproxExp gegen alle Schritte der Sampler-Testvektoren; BerExp-Äquivalenztest; statistische Tests für SamplerZ (Abschnitt 7) | mittel |
| 4 | `tree`, `ffsampling`, `sign` (mit KAT-sk, `load_secret_key` inkl. `recompute_G`) | Falcon-Baum exakt gegen Testvektor; ffSampling mit Test-RNG gegen Python (ganzzahlige Ausgabe gleich, Gleitkomma mit Toleranz); KAT-sk → sign → verify | mittel |
| 5 | `zint`, `ntrugen` (NTRUSolve fester Länge, Portierung der Referenz), `keygen`; AES-CTR-DRBG für Tests von Anfang an | fG − gF = q, γ-Schranke, sk-Format, keygen → sign → verify für 512/1024, reduzierte n; **KAT count 0 byte-genau** (f, g, dann F) für beide Varianten | **gross** |
| 6 | Seitenkanal-Prüfung (Abschnitt 6) | dudect ohne Befund, Valgrind ohne Befund auf geheimen Daten | mittel |
| 7 | KAT-Schlüssel byte-genau (L10), alle Seeds | alle 200 KAT-Seeds ergeben exakt sk und pk der KAT-Dateien (Signaturen wegen L7 nicht) | klein, wenn count 0 in Phase 5 stimmt |
| 8 (optional) | Benchmarks gegen Python, `native-fpu` | Zahlen für die Arbeit | klein |

---

## 6. Wie wir die Seitenkanalresistenz prüfen

Konstante Laufzeit lässt sich nicht durch normale Tests zeigen. Geplant sind
drei voneinander unabhängige Prüfungen:

1. **Statische Prüfung mit Valgrind (ctgrind-Prinzip):** Geheime Puffer
   werden für Memcheck als „uninitialisiert“ markiert (z. B. über das Crate
   `crabgrind`). Jede Verzweigung oder jeder Speicherzugriff, der davon
   abhängt, meldet Valgrind als Fehler. Läuft für keygen und sign. Am
   aussagekräftigsten der drei Verfahren.

   **Erlaubte Verzweigungen freigeben:** Einige Entscheidungen hängen von
   geheimen Daten ab, dürfen aber verzweigen (3.1). Valgrind würde sie
   melden. Ihr Ergebnis (nur das Bit ja/nein) wird deshalb an genau diesen
   Stellen ausdrücklich als „definiert“ markiert (`MAKE_MEM_DEFINED`, im Code
   über eine Funktion `ct::declassify` gebündelt):

   | Stelle | freigegebenes Bit |
   |---|---|
   | SamplerZ (Alg. 15) | Ablehnung ja/nein pro Runde (isochron, 3.4) |
   | Sign: Normprüfung | Neustart ja/nein |
   | Sign: Kompression von s₂ | passt in die feste Länge ja/nein (s₂ ist danach öffentlich) |
   | Keygen: Koeffizient ausserhalb ±`lim`, Parität des letzten Koeffizienten | neu ziehen ja/nein (3.1, Ausnahme) |
   | Keygen: Norm, γ, Invertierbarkeit, NTRUSolve, Grösse von F und G | Kandidat verwerfen ja/nein |

   Jede weitere Valgrind-Meldung gilt als Befund. Die Liste gehört in die Doku.
2. **Statistische Zeitmessung (dudect):** zwei Klassen von Eingaben (z. B.
   fester gegen zufälligen Schlüssel, Sampler mit festem gegen zufälliges μ),
   Welch-t-Test über Millionen Messungen. Ein |t| > 4.5 gilt als Leak.
   Pro Baustein: `fpr`-Operationen, BaseSampler, SamplerZ, ffSampling, sign.
3. **Assembler-Kontrolle:** Für `ct.rs`, `fpr.rs` und den Sampler mit
   `cargo asm` prüfen, dass keine bedingten Sprünge auf geheimen Werten
   entstanden sind (LLVM ersetzt Masken manchmal durch Sprünge). Im Release-
   und im Debug-Profil, auf x86-64 und aarch64.

Alle drei Prüfungen laufen auf beiden Zielplattformen (Abschnitt 10).

Zusätzlich: Durchsicht, dass alle geheimen Puffer gelöscht werden.

---

## 7. Tests

- **Portiert aus Python:** die Tests aus `Python/tests/` dort, wo sie
  Spezifikationseigenschaften prüfen (Parameter, Kompression, Formate, NTT,
  FFT-Eigenschaften, Sampler, ffLDL-Invarianten).
- **Differenztests gegen Python:** Ein Skript in `Python/scripts/` erzeugt
  JSON-Vektoren (FFT, split/merge, Baum für die KAT-Schlüssel, ffSampling mit
  festen Zufallsbytes). Python bleibt unverändert, daher **nicht bitgleich**
  (Gründe in 3.3): Gleitkommawerte mit relativer Toleranz (Richtwert 2⁻⁴⁰,
  beim Umsetzen festlegen), ganzzahlige Ergebnisse (z aus ffSampling, s₁, s₂)
  müssen gleich sein. Bei sehr seltenen Abweichungen durch Rundung an einer
  Ganzzahlgrenze den Fall einzeln prüfen. Exakte Referenzwerte für Baum und
  Signaturvektor liefern die Sampler-Testvektoren.
- **Nicht bitgleich zu erwarten:** (F, G) aus NTRUSolve (3.5) und wegen L7
  alles, was auf die Zufallsfolge nach dem ersten BerExp-Aufruf angewiesen ist
  (SamplerZ-Folgen, exakte Signatur aus dem Testvektor).
- **Testen trotz streng konstantem BerExp (L7):**
  - *BerExp-Äquivalenz:* Für jeden BerExp-Aufruf in den Sampler-Testvektoren
    sind (x, ccs) und die von Alg. 14 gelesenen Bytes bekannt. Diese Bytes,
    aufgefüllt auf 8 Bytes mit beliebigem Rest, müssen im strengen BerExp
    dasselbe Bit ergeben. Zusätzlich gezielt: Fälle, in denen Alg. 14 2 oder
    mehr Bytes braucht (gleiche obere Bytes von u und z).
  - *SamplerZ-Äquivalenz:* Ein Test-RNG, der pro BerExp-Aufruf die Bytes des
    Testvektors liefert und mit festen Bytes auf 8 auffüllt, ergibt genau die
    z-Folge der Testvektoren. Damit ist der ganze Sampler gegen die NIST-Daten
    geprüft, obwohl der Verbrauch an Zufall anders ist.
  - *ffSampling und Sign:* Mit demselben Test-RNG (Abbildung pro
    SamplerZ-Aufruf) ergibt sich wieder exakt der „signature vector“ des
    Testvektors.
  - *Statistik:* Mittelwert, Varianz und χ²-Test der SamplerZ-Ausgabe gegen
    die diskrete Gaussverteilung für mehrere (μ, σ′), mit festen Seeds wie in
    7.2 der Doku.
- **Fuzzing** (`cargo fuzz`) für `decode_pk`, `decode_sk`, `decode_sig`,
  `decompress` und `verify`: diese verarbeiten Daten von aussen.

---

## 8. Risiken

| Risiko | Folge | Gegenmassnahme |
|---|---|---|
| NTRUSolve mit fester Länge ist aufwendig und fehleranfällig | Phase 5 dauert am längsten | früh mit reduzierten n (2…64) testen; Eigenschaftstests |
| `fpr`-Emulation hat Rundungsfehler in Grenzfällen | falsche Signaturen | Vergleich mit Hardware-`f64` über sehr viele Zufallswerte und alle Sonderfälle |
| LLVM baut konstanten Code in Sprünge um | Timing-Leak trotz korrektem Quelltext | `subtle`/`black_box`, Assembler-Kontrolle, Valgrind |
| Emulierte Gleitkommazahlen sind langsam | Signieren deutlich langsamer als nativ | für Bachelorarbeit unkritisch; `native-fpu` als Option |
| Keygen-Ablauf weicht in einem Detail von der Referenz ab (Byte-Reihenfolge, Ablehnungsregel, Schranke) | KAT-Schlüssel stimmen nicht, Ursache schwer zu finden | Zwischenwerte (f, g des ersten angenommenen Kandidaten) zuerst für count 0 prüfen; Abweichungen schrittweise eingrenzen |
| FIPS 206 ändert Details (Namen, evtl. Formate, HashToPoint mit Kontext) | Anpassungen nötig | Formate und Hashing in eigenen Modulen; beim Erscheinen abgleichen |
| Power/EM-Angriffe | nicht abgedeckt | in der Arbeit klar abgrenzen (Abschnitt 1) |

---

## 9. Offene Entscheidungen

1. ~~**L2:** Referenzimplementierung für konstante Laufzeit verwenden?~~
   **Ja** (9.11.2026), Umfang siehe Abschnitt 2.2.
2. ~~**L5/L6:** \|sᵢ\| ≤ 2047 und Verwerfen nicht speicherbarer Schlüssel?~~
   **Ja, wie Referenz** (9.11.2026). Python wird nicht angeglichen, der
   Unterschied wird dokumentiert (Abschnitt 2.2).
3. ~~**L7:** BerExp wie die Spezifikation oder streng konstant?~~
   **Nur streng konstant** (9.11.2026), siehe 3.4 und 7.
4. ~~**L10 / Phase 7:** KAT-Schlüssel byte-genau reproduzieren?~~
   **Ja** (9.11.2026), Phase 7 ist fester Teil des Plans; Keygen zieht f, g
   wie die Referenz (3.5).
5. ~~Zielplattformen?~~ **x86-64 und aarch64** (9.11.2026), siehe Abschnitt 10.

Alle Designentscheidungen sind getroffen; der Plan ist bereit zur Umsetzung.

Noch offen (blockiert erst Phase 6, nicht den Start):

- aarch64-Hardware für Valgrind und dudect beschaffen bzw. klären
  (Abschnitt 10).
- Die Keygen-Details aus 3.5 (Byte-Reihenfolge, Neuziehen, Reihenfolge der
  Prüfungen) und der Zahlenbereich von `fpr` (3.3) beruhen auf meiner
  Erinnerung an die Referenz und werden zu Beginn von Phase 2 bzw. 5 im
  Quelltext der Referenz nachgeprüft.

---

## 10. Zielplattformen: x86-64 und aarch64

| Thema | x86-64 | aarch64 |
|---|---|---|
| 64×64→128-Multiplikation (ApproxExp, `fpr`, `zint`) | `mul` nativ | `mul`/`umulh` nativ |
| Hardware-Hilfe für konstante Laufzeit | keine allgemeine Garantie; Intel DOITM auf neueren CPUs (vom Betriebssystem gesteuert) | DIT-Flag (Data Independent Timing, ab ARMv8.4): beim Signieren und im Keygen setzen, wo verfügbar |
| `native-fpu` | add/mul/sqrt in SSE2 gelten als konstant für normale Zahlen; Division nicht verwenden | nur mit DIT zulassen; welche FP-Befehle DIT abdeckt, in der ARM-Doku nachprüfen |
| Valgrind-Prüfung (Abschnitt 6) | Linux x86-64 | Linux aarch64 (z. B. Raspberry Pi 5, AWS Graviton); macOS wird von Valgrind nicht unterstützt |
| dudect-Messungen | echte Hardware | echte Hardware (z. B. Apple-Silicon-Mac oder Raspberry Pi 5); **nicht** unter QEMU, dort sind Zeiten bedeutungslos |
| Assembler-Kontrolle | `cargo asm` für x86-64 | `cargo asm --target aarch64-unknown-linux-gnu`; bedingte Sprünge (`b.cond`, `cbz`, `tbz`) und `csel` prüfen |
| Funktionstests | nativ | nativ oder per `cross`/QEMU (nur Korrektheit, keine Zeiten) |

Folgen für den Plan:

- Weil beide Ziele 64 Bit haben, entfällt die Sorge um eine
  `u128`-Softwareroutine (3.4); ApproxExp und `fpr` nutzen die native
  Multiplikation.
- Standard bleibt die emulierte Gleitkommaarithmetik auf beiden Zielen.
  `native-fpu` ist nur ein Feature für Messungen und wird erst nach
  bestandener Prüfung (Abschnitt 6) auf dem jeweiligen Ziel empfohlen.
- Phase 6 läuft auf beiden Zielen: Valgrind und dudect je einmal auf
  x86-64-Linux und aarch64-Linux, Assembler-Kontrolle für beide.
- `no_std` ist nicht nötig; das Crate nutzt `std` (`alloc` würde reichen,
  ist aber kein Ziel).
- Hardware für aarch64-Messungen muss beschafft bzw. geklärt werden
  (eigenes Gerät, Hochschul-Server oder Cloud-Instanz).
