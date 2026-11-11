# Plan: FN-DSA (Falcon) in Rust, seitenkanalresistent

Stand: 11. November 2026, Branch `Rust`. Alle Phasen 0 bis 8 sind
umgesetzt (Phase 8: Messungen und Feature `native-fpu`, Abschnitt 5.2).
Phase 6 (Seitenkanal-Prüfung): Valgrind ohne Befund auf x86-64 und
aarch64 (Release und opt-level 0; lokal in Docker und im CI-Job `ctgrind`,
erster grüner Lauf für Commit `c02768f`), dudect ohne Befund auf
x86-64-Hardware, Assembler-Stichprobe auf beiden Zielen.
Ergebnisse und Befunde in Abschnitt 6. Danach ergänzt (6.2): Fault-Schutz
in Sign (`try_sign`: Prüfsumme des Schlüssels, untere Normschranke), DIT
auf aarch64 und ein CI-Job `dudect` auf x86-64- und ARM-Runnern.
Keygen ist eine Portierung der Referenz (PQClean, `keygen.c`, `fft.c`) und
erzeugt aus allen 200 KAT-Seeds byte-genau die KAT-Schlüssel. Zuvor:
Phase 0 bis 4 sind umgesetzt:
Phase 2 (`fpr`, FFT), Phase 3 (`prng`, Sampler) und Phase 4 (Baum,
ffSampling, Sign) rechnen **bitgleich** mit Python, geprüft gegen
`Python/data/vectors/` (siehe Änderung zu 3.3); auch ganze Signaturen aus
`flow.sign` stimmen Byte für Byte, wenn Rust denselben Zufall bekommt.
Abweichung in Phase 4: Bei einem Neustart behält Sign das Salt (wie Alg. 10
und Python), statt wie in 3.6 beschrieben ein neues zu ziehen. Ergänzt nach
der Analyse von Phase 1–4: `SigningKey::from_bytes` prüft |G| ≤ 127,
fG − gF = q und σ′ ∈ [σmin, σmax] für alle Blätter (sonst lief Sign mit
erfundenen Schlüsseln endlos); Verify nach Sign ist umgesetzt; neues
Fuzz-Ziel `signing_key`.
Phase 0 und 1 sind vollständig
umgesetzt (Crate, `params`, `ct` in Grundform mit Optimierungsbarriere,
`modq`, `hashing`, `encoding`, Verify, CI-Skript `ci.sh` und GitHub-Workflow
für x86-64/aarch64 mit Jobs für Rust 1.87 und die Fuzz-Ziele aus §7). Alle 200 KAT-Signaturen werden
akzeptiert, pk- und sk-Format byte-genau. Was umgesetzt ist und wie Rust von
Python abweicht, steht in [README.md](README.md) (Ebene 5 der Doku).
Abweichungen vom Plan: Vollständige Parametersätze (σ, β², Signaturlänge)
gibt es bisher nur für 512 und 1024, die verkleinerten Varianten kommen mit
Phase 5; `Signature` speichert zusätzlich `logn`, damit `to_bytes` ohne
Parameter auskommt.

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
| Fault-Angriffe (Fehler einschleusen) | **teilweise** (Erkennung) | Verify nach Sign, untere Normschranke, Prüfsumme des Schlüssels vor und nach Sign (6.2); keine Doppelrechnung |

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
| L8 | FFT-Darstellung | alle n Werte, Reihenfolge ζₖ | doppelte Arbeit | ~~nur n/2 Werte~~ **geändert (10.11.2026):** alle n Werte wie Python, damit die Rechenwege und damit die Bits gleich bleiben (siehe 3.3); die doppelte Arbeit ist für die Arbeit unkritisch |
| L9 | Zufall | beliebiges `rng.random_bytes` | SamplerZ braucht pro Signatur Tausende Bytes | Seed aus OS-Zufall → SHAKE256 → ChaCha20-PRNG (Referenz) |
| L10 | KAT byte-genau | 7.3: nicht reproduzierbar | stimmt nur ohne den RNG-Ablauf der Referenz | **entschieden (9.11.2026):** die **KAT-Schlüssel** werden byte-genau reproduziert, mit dem Keygen-Ablauf der Referenz (Seed → SHAKE256 → Tabellen-Gauss), siehe 3.5 und Phase 7. Die **KAT-Signaturen** nicht: wegen L7 zieht BerExp andere Bytes als die Referenz |
| L11 | `_SIGMA_EPS` (Python) | nicht dokumentiert | nur wegen gerundetem σmin nötig | ~~Debug-Assertion~~ **umgesetzt (Phase 4):** σ′ ∈ [σmin − 1e-10, σmax + 1e-10] wird einmal beim Laden des Secret Keys für alle Blätter geprüft, ohne Verzweigung auf den Werten (`InvalidKey` sonst). Die Toleranz bleibt nötig, weil σmin in Tab. 3.3 gerundet ist |

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
   Pflicht und nicht nur Ergänzung. Umgesetzt (Phase 1): auf x86-64 und
   aarch64 eine leere `asm!`-Anweisung mit dem Wert als `inout(reg)`, weil
   `black_box` jeden Wert über den Stack schickt (langsamer, und Masken aus
   geheimen Daten bleiben im Stack); `black_box` nur als Rückfall.
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

**Geändert (10.11.2026, Phase 2):** Die Voraussetzung oben gilt nicht mehr.
Mit dem Merge von `main` rechnet Python reproduzierbar (Smith-Division als
einzelne Operationen, Ziel Z1 der C-Portierung), und die Wurzeln ζ liegen als
feste Tabelle vor (`C/src/fft_table.h`, aus den Python-Werten erzeugt). Rust
übernimmt dieselbe Tabelle (`src/fft_table.rs`, erzeugt mit
`scripts/gen_fft_table.py`) und dieselbe Reihenfolge der Operationen. Weil
`fpr` korrekt rundet, sind FFT, Sampler und x/z im Sampler **bitgleich** mit
den Testvektoren in `Python/data/vectors/`, einschliesslich des Vorzeichens
von Nullen. Die Smith-Division hat keine Verzweigung: beide Zweige sind mit
vertauschten Operanden dieselbe Formel, die Auswahl läuft über Masken.
Zahlenbereich von `fpr` (umgesetzt): keine subnormalen Zahlen, kein ±∞,
kein NaN; Unterlauf ergibt ±0.

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
  neu signiert (neue Zufallswerte; das Salt bleibt wie in Alg. 10 und
  Python gleich, umgesetzt in Phase 4). Das Ergebnis ja/nein darf
  verzweigen.
- Optional (Fault-Schutz): nach dem Signieren `verify` aufrufen; das kostet
  wenig im Vergleich zum Signieren. **Umgesetzt (Phase 4):** bei Fehlschlag
  neu signieren, nach drei Fehlschlägen Panik statt falscher Signatur.
  **Erweitert (6.2):** `try_sign` mit Fehler `FaultDetected`, untere
  Normschranke und Prüfsumme des Schlüssels; `sign` ruft `try_sign` auf
  und bricht bei einem Fehler mit einer Panik ab.

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
    fft.rs            # FFT auf Fpr, n komplexe Werte wie Python (L8), split/merge
    fft_table.rs      # Wurzeln ζ als Bits, erzeugt aus C/src/fft_table.h
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
| 2 | `ct`, `fpr` (emuliert), `fft` | `fpr` bitgleich gegen `f64` für Millionen Zufallswerte im normalen Zahlenbereich inkl. Grenzfälle; FFT **bitgleich** gegen `Python/data/vectors/fft.*` (**erledigt**) | mittel |
| 3 | `prng`, `sampler` | BaseSampler und ApproxExp gegen alle Schritte der Sampler-Testvektoren; BerExp-Äquivalenztest; statistische Tests für SamplerZ (Abschnitt 7) (**erledigt**, gegen `Python/data/vectors/sampler.*`) | mittel |
| 4 | `tree`, `ffsampling`, `sign` (mit KAT-sk, `load_secret_key` inkl. `recompute_G`) | Falcon-Baum und ffSampling bitgleich gegen `Python/data/vectors/tree.*` und `ffsampling.*` (Test-Generator wie beim SamplerZ); KAT-sk → sign → verify (**erledigt**; dazu `flow.sign` und `flow.sign_restart` byte-genau) | mittel |
| 5 | `zint`, `ntrugen` (NTRUSolve fester Länge, Portierung der Referenz), `keygen`; AES-CTR-DRBG für Tests von Anfang an | fG − gF = q, γ-Schranke, sk-Format, keygen → sign → verify für 512/1024, reduzierte n; **KAT count 0 byte-genau** (f, g, dann F) für beide Varianten (**erledigt**; dazu `fft_ref.rs`, die FFT der Referenz, weil `reduce` mit ihr rundet) | **gross** |
| 6 | Seitenkanal-Prüfung (Abschnitt 6) | dudect ohne Befund, Valgrind ohne Befund auf geheimen Daten (**erledigt**: Valgrind auf x86-64 und aarch64, dudect auf x86-64; dudect auf aarch64 als CI-Job auf dem ARM-Runner, 6.2) | mittel |
| 7 | KAT-Schlüssel byte-genau (L10), alle Seeds | alle 200 KAT-Seeds ergeben exakt sk und pk der KAT-Dateien (Signaturen wegen L7 nicht) (**erledigt**, siehe 5.1) | klein, wenn count 0 in Phase 5 stimmt |
| 8 (optional) | Benchmarks gegen Python, `native-fpu` | Zahlen für die Arbeit (**erledigt**, siehe 5.2) | klein |

### 5.1 Ergebnis Phase 7 (10.11.2026)

Der Test `tests/kat_keygen.rs` bildet für alle 200 KAT-Fälle den Ablauf von
`PQCgenKAT_sign` nach: AES-256-CTR-DRBG mit dem `seed` der KAT-Datei,
48 Bytes für `keygen_from_seed`, danach `sign` aus demselben Strom.
`examples/kat_rsp.rs` schreibt daraus KAT-Dateien im NIST-Format und
vergleicht sie Feld für Feld mit den offiziellen:

| Datei | Fälle | pk, sk gleich | Salt gleich | sm gleich | Verify ok |
|---|---|---|---|---|---|
| falcon512 | 100 | 100 | 100 | 0 | 100 |
| falcon1024 | 100 | 100 | 100 | 0 | 100 |

Das Salt stimmt, weil Rust es wie die Referenz als erste 40 Bytes nach dem
Keygen-Seed aus dem DRBG liest; damit ist auch die Reihenfolge der Aufrufe
bestätigt. Die komprimierte Signatur weicht erwartungsgemäss ab (BerExp
liest immer 8 Bytes, L7; Sampler mit ChaCha20, L9); ihre Länge stimmt nur
zufällig (11 von 100). Jede Rust-Signatur besteht Verify mit dem
offiziellen pk.

### 5.2 Ergebnis Phase 8 (11.11.2026)

**Messprotokoll** (gemeinsam für Rust, C und Python; `examples/bench.rs`,
`scripts/bench_python.py`):
- Operationen: Keygen aus einem Seed, sk laden, Sign, Verify, je für
  Falcon-512 und Falcon-1024;
- feste Eingaben: Seeds 0, 1, 2, … (48 gleiche Bytes), Nachricht 32 Bytes;
  ein Thread, Release-Build;
- Aufwärmen, dann N Läufe (Rust: Keygen 50/30, sk laden 200, Sign 500,
  Verify 2000; Python: 8/4, 20, 50, 200); gemeldet werden Median sowie
  10- und 90-%-Perzentil, in Rust zusätzlich in Zyklen (`rdtsc`);
- Umgebung angeben: CPU, Betriebssystem, Compiler bzw. Python-Version.

**Ergebnis** (Median; AMD Zen 3, „AMD64 Family 25 Model 97“, Windows 11;
Rust 1.99.1, Python 3.13.14; Faktor = Python / Rust):

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

Einordnung:
- Keygen schwankt stark (10/90 %: in Rust 14–49 ms für Falcon-512), weil
  verworfene Kandidaten vom Seed abhängen; bei Python mit nur 8 bzw. 4
  Läufen ist der Median entsprechend unsicher.
- Verify kommt ohne Gleitkomma aus; der Unterschied zu Python stammt aus
  Ganzzahlen fester Breite und der NTT statt Python-Listen.
- Sign ist mit emulierten Gleitkommazahlen nur 2,6- bis 3,4-mal schneller
  als Python, das die Gleitkommaeinheit der Hardware benutzt. Mit
  `native-fpu` halbiert sich die Zeit; den Rest kostet vor allem die
  weiterhin emulierte Division (rund 400 Zyklen je Division).

**Feature `native-fpu`** (3.3, §10): Addition, Subtraktion, Multiplikation
und Wurzel über die Gleitkommaeinheit, Division und Runden emuliert.
Alle Tests einschliesslich der bitgleichen Vergleiche mit Python und der
200 KAT-Schlüssel bestehen damit unverändert (keine subnormalen Zahlen in
Falcon). dudect auf demselben Prozessor: alle Bausteine |t| ≤ 2,2 (Sign
1,39, Sign-Versuch 1,11). Standard bleibt die Emulation: Ob `addsd`,
`mulsd` und `sqrtsd` auf einer CPU konstante Laufzeit haben, hängt vom
Modell ab und ist hier nur für diesen Prozessor gemessen; auf aarch64
bräuchte es zusätzlich das DIT-Flag (§10). `ci.sh` testet beide
Varianten.

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

### 6.1 Ergebnisse (Phase 6, 10.11.2026)

**Valgrind** (`examples/ctgrind.rs`, `ctgrind.sh`, Feature `ctgrind`):
Keygen-Seed und Seed des Samplers werden als geheim markiert (`ct::poison`),
dann laufen Keygen, Speichern, Laden, Sign und Verify für 512 und 1024. Die
erlaubten Stellen aus der Tabelle oben geben `ct::declassify` bzw.
`ct::unpoison` (h, s₂ nach der Annahme) frei.
- Ergebnis: **keine Meldung** auf x86-64, im Release-Build und mit
  opt-level 0 ohne Überlaufprüfungen (die Überlaufprüfungen des
  Debug-Builds sind selbst Verzweigungen auf Werten und gehören nicht zum
  Konstantzeit-Code). Ebenso **keine Meldung auf aarch64** im CI-Job
  `ctgrind` (GitHub-Runner `ubuntu-24.04-arm`, beide Builds, Selbsttest
  schlägt an; erster Lauf für Commit `c02768f`).
- Wirksamkeit belegt: Selbsttest (absichtliche Verzweigung auf geheimem
  Byte wird gemeldet) und zwei Gegenproben (ohne die Freigabe in SamplerZ
  bzw. beim Neuziehen in Keygen meldet Valgrind sofort).
- **Befunde, behoben:**
  1. `zint_sub`, `zint_norm_zero`, `zint_bezout` (portierter Keygen):
     LLVM baute Auswahlen über Masken ohne Barriere in Sprünge um →
     Masken durch `ct::barrier`.
  2. Schiebungen mit geheimer Weite in `fpr` und im Sampler (Memcheck
     verlangt bekannte Schiebeweiten) → `ct::shr64`/`ct::shl64` mit sechs
     festen Schritten; Runden in `make` bitweise statt über `0xC8 >> x`.
     Damit hängt die Laufzeit auch auf CPUs ohne konstante Schiebebefehle
     nicht von den Werten ab.
  3. `is_short` in Sign: `saturating_mul/add` und `unsigned_abs`
     verzweigen → Begrenzung über Maske, Summe in u128.
  4. Prüfungen mit `||` bzw. `contains` werten in zwei Schritten aus und
     verzweigen vor der Freigabe → Masken (`out_of_range_mask`).
  5. `check_fg` brach beim ersten zu grossen Koeffizienten ab (`any`) →
     Maske über alle Koeffizienten.
  6. Im Prüfprogramm selbst: `poison(&[T])` wirkte im Release-Build nicht,
     weil der Compiler hinter `&` unveränderliche Daten annimmt → `&mut`.

**dudect** (`examples/dudect.rs`, Feature `dudect`), x86-64-Laptop,
Windows, Zyklenzähler; fest gegen zufällig, |t| (Schwelle 4.5):

| Baustein | Messungen | \|t\| |
|---|---|---|
| fpr Division, Multiplikation, Addition, Wurzel, Runden | je 10⁶ | 0.76 – 1.56 |
| BaseSampler | 10⁶ | 1.26 |
| SamplerZ (μ, σ′) | 2·10⁵ | 0.75 |
| Sign (fester Schlüssel gegen 16 andere) | 3000 | 1.71 |
| ein Sign-Versuch ohne Neustart (ffSampling, Signaturvektor) | 3000 | 1.01 |
| Zahl der SamplerZ-Runden je Versuch (1778.3 gegen 1778.1) | 4000 | 0.21 |

Messfehler im Prüfprogramm, gefunden und behoben:
- BaseSampler zuerst |t| = 13: Die Eingaben beider Klassen wurden
  unterschiedlich vorbereitet (nur Klasse 1 zog Zufallsbytes).
- Sign zuerst |t| = 6.2, nach Leeren des Caches 3.7; ein einzelner
  Sign-Versuch ohne Neustarts sogar 5 bis 19 (mit `native-fpu` höher, weil
  das Rauschen kleiner ist). Die frühere Erklärung (schlüsselabhängige Zahl
  der Neustarts) war **falsch**: Auch ohne Neustarts schlug der Test an,
  und die Zahl der SamplerZ-Runden ist für alle Schlüssel gleich. Ursache
  war die Lage im Speicher: Der feste Schlüssel lag immer an derselben
  Adresse, die anderen an verschiedenen, und die Konflikte im Cache
  unterschieden sich. Seit der Schlüssel vor jeder Messung neu geladen wird
  (beide Klassen mit wechselnden Adressen), liegen alle Werte deutlich
  unter der Schwelle. Gemessen wird damit der Wert des Schlüssels, nicht
  seine Adresse; Adressen hängen nicht von geheimen Daten ab.
Keygen wird nicht gemessen: Es verwirft Kandidaten absichtlich (erlaubte
Verzweigung), seine Laufzeit hängt deshalb vom Seed ab.

**Assembler:** keine Gleitkomma- und Divisionsbefehle der Hardware im
ganzen Crate (x86-64, aarch64); `fpr`-Operationen, Smith-Division und
Gleitkommateile des Samplers ohne bedingte Sprünge (einzige Ausnahme: die
feste Schleife der Division). Für den portierten Keygen-Code ersetzt die
Valgrind-Prüfung die Durchsicht von Hand.

**Gelöschte Puffer:** zusätzlich gelöscht werden jetzt der Keccak-Zustand
(`sha3` mit Feature `zeroize`) und die Zwischenfelder der γ-Berechnung.
Bekannte Grenze: der Ausgabepuffer im XOF-Leser von `digest` und Werte in
Registern und auf dem Stack.

**dudect auf aarch64:** siehe 6.2 (CI-Job `dudect`). Valgrind auf aarch64
ist erledigt (CI-Job `ctgrind`).

### 6.2 Nachträge: Fault-Schutz, DIT, dudect auf aarch64 (11.11.2026)

**Fault-Schutz in Sign** (`SigningKey::try_sign`, Fehler `FaultDetected`;
`sign` bricht dann mit einer Panik ab). Drei Prüfungen, alle auf Daten,
die entweder öffentlich werden oder nur ja/nein verraten:

| Prüfung | erkennt | Kosten |
|---|---|---|
| Verify nach Sign (seit Phase 4) | Fehler, die eine ungültige Signatur ergeben | ≈ 20 µs |
| untere Schranke ‖(s₁, s₂)‖² ≥ ⌊β²⌋/2 | Ausfall des Samplers (Zufall null, Schleife übersprungen): Die Signatur besteht Verify, ist aber nur auf den Mittelwert gerundet und verrät über viele Signaturen die Basis (wie bei NTRUSign) | vernachlässigbar |
| Prüfsumme SHAKE256 über f, g, F, Basis, Baum und h, beim Laden berechnet, vor und nach jedem Sign verglichen | dauerhaft veränderter Schlüssel im Speicher (gekippte Bits, Rowhammer); ein veränderter Baum liefert sonst gültige, aber falsch verteilte Signaturen | ≈ 7 % von Sign |

Begründung der Schranke: β = 1.1·σ·√(2n), die Norm² liegt im Mittel bei
2nσ² ≈ 0.83·β² und streut um 4.4 % (n = 512) bzw. 3.1 % (n = 1024); β²/2
liegt 9 bzw. 13 Standardabweichungen darunter. Gemessen (Tests in
`lib.rs`): ehrliche Signaturen 0.72–0.94·β² (512) bzw. 0.75–0.89·β²
(1024); mit eingeschleustem Ausfall des Samplers (nur im Test-Build,
`sampler::testing::FAULT_ROUND`) 0.03·β², und diese Signaturen bestehen
Verify. Weitere Tests verändern f, F, die Basis, ein Blatt des Baums und h
und erwarten `FaultDetected`. Valgrind meldet nach der Änderung nichts.

dudect nach der Änderung (x86-64, zwei Läufe): fpr ≤ 1.97, BaseSampler
≤ 1.88, SamplerZ ≤ 0.84, Sign ≤ 1.73, Sign-Versuch ≤ 1.73, Runden 0.21.
Dabei ein dritter Messfehler im Prüfprogramm: Die Addition stieg ohne
jede Änderung an `fpr` auf |t| = 4.2 bis 5.6 (der Maschinencode von
`fpr_add` ist mit dem alten Stand identisch und hat keinen Sprung). Ursache
war wie beim BaseSampler die ungleiche Vorbereitung: Nur Klasse 1 zog
Zufallszahlen, Klasse 0 nahm Konstanten; ob das vor der Zeitnahme
sichtbar wird, hängt von der Lage des Codes ab. Jetzt ziehen beide
Klassen für alle Bausteine dieselben Zufallszahlen, erst danach wird der
feste Wert gewählt; die Addition liegt wieder bei 0.3 bis 1.1.

Grenze: Ein einzelner Fehler mitten in einer Rechnung, der eine gültige
**und** plausible Signatur ergibt, wird nicht erkannt; dafür bräuchte es
eine Doppelrechnung (Sign zweimal mit demselben Zufall, doppelte Kosten).
Fehler in der Zufallsquelle selbst (z. B. immer derselbe Seed) erkennt
Sign ebenfalls nicht. Die Laufzeiten in 5.2 sind vor dem Fault-Schutz
gemessen.

**DIT auf aarch64** (§10): `ct::DitGuard` setzt das Flag (Register
`S3_3_C4_C2_5`, Bit 24) während Keygen, Laden und Sign, wenn die CPU es
kennt (`is_aarch64_feature_detected!("dit")`), und stellt danach den
alten Wert her. Öffentlich abfragbar mit `fndsa::dit_available()`.
Geprüft: Assembler für aarch64, Test `dit_guard_sets_and_restores` in
der CI auf dem ARM-Runner.

**dudect auf aarch64:** Der neue CI-Job `dudect` lässt `examples/dudect.rs`
auf `ubuntu-24.04` und `ubuntu-24.04-arm` laufen und schreibt die Tabelle
in die Zusammenfassung des Laufs. Zeitquelle auf aarch64 ist der
Systemzähler `cntvct_el0` (Frequenz wird ausgegeben); das Programm meldet
auch, ob DIT gesetzt wird. Die Runner sind echte Prozessoren (kein QEMU),
aber geteilte virtuelle Maschinen: Ein Wert unter 4.5 ist ein Hinweis,
kein Nachweis, und ein einzelner Ausreisser kann vom Nachbarn auf der
Maschine kommen. Der Job schlägt deshalb nicht fehl. Eine Messung auf
einem eigenen ARM-Gerät (Raspberry Pi 5, Apple Silicon) bleibt die
bessere Prüfung. Ergebnis des ersten Laufs: steht aus.

---

## 7. Tests

- **Portiert aus Python:** die Tests aus `Python/tests/` dort, wo sie
  Spezifikationseigenschaften prüfen (Parameter, Kompression, Formate, NTT,
  FFT-Eigenschaften, Sampler, ffLDL-Invarianten).
- **Differenztests gegen Python:** `Python/scripts/gen_vectors.py` (aus der
  C-Portierung) erzeugt Vektoren für jede Funktion
  (`Python/data/vectors/*.txt`, Leser in `tests/common/vectors.rs`).
  **Geändert (10.11.2026):** Vergleich **bitgleich**, nicht mit Toleranz
  (Begründung in 3.3). Umgesetzt für FFT und Sampler.
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
  `decompress` und `verify`: diese verarbeiten Daten von aussen. Dazu
  `signing_key` (laden, signieren, prüfen).

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

- ~~aarch64-Hardware für dudect beschaffen bzw. klären (Abschnitt 10).~~
  dudect läuft als CI-Job auf dem ARM-Runner (6.2); ein eigenes Gerät
  wäre genauer. Valgrind auf aarch64 läuft ebenfalls auf den GitHub-Runnern
  (`ubuntu-24.04-arm`).
- ~~Die Keygen-Details aus 3.5 … werden … nachgeprüft.~~ **Nachgeprüft
  (Phase 5, PQClean `keygen.c`):** Seed (48 Bytes) → SHAKE256 → alle
  Zufallswerte; 64-Bit-Werte little-endian (`get_rng_u64`); Tabellen-Gauss
  mit Summe von 1024/n Ziehungen; neu gezogen wird ein einzelner
  Koeffizient ausserhalb **±127** (nicht ±`lim`) und der letzte bis zur
  ungeraden Summe; danach verwirft die Referenz den ganzen Kandidaten,
  wenn ein Koeffizient nicht in FG_BITS passt. Reihenfolge der Prüfungen:
  FG_BITS, ‖(g, −f)‖² < 16823, γ² < 16822.4121, h = g/f (invertierbar),
  NTRUSolve mit |F|, |G| ≤ 127. Zusätzlich gefunden: `reduce` rundet mit
  der FFT der Referenz (n/2 Werte, `fpr_gm_tab`); sie ist mitportiert
  (`fft_ref.rs`). γ rechnet Rust mit der eigenen FFT, weil γ nur
  „verwerfen ja/nein“ entscheidet. Zahlenbereich von `fpr` siehe 3.3.

---

## 10. Zielplattformen: x86-64 und aarch64

| Thema | x86-64 | aarch64 |
|---|---|---|
| 64×64→128-Multiplikation (ApproxExp, `fpr`, `zint`) | `mul` nativ | `mul`/`umulh` nativ |
| Hardware-Hilfe für konstante Laufzeit | keine allgemeine Garantie; Intel DOITM auf neueren CPUs (vom Betriebssystem gesteuert) | DIT-Flag (Data Independent Timing, ab ARMv8.4): beim Signieren, Laden und im Keygen setzen, wo verfügbar (**umgesetzt**, 6.2) |
| `native-fpu` | add/mul/sqrt in SSE2 gelten als konstant für normale Zahlen; Division nicht verwenden | nur mit DIT zulassen; welche FP-Befehle DIT abdeckt, in der ARM-Doku nachprüfen |
| Valgrind-Prüfung (Abschnitt 6) | Linux x86-64 | Linux aarch64 (z. B. Raspberry Pi 5, AWS Graviton); macOS wird von Valgrind nicht unterstützt |
| dudect-Messungen | echte Hardware | echte Hardware (z. B. Apple-Silicon-Mac oder Raspberry Pi 5); **nicht** unter QEMU, dort sind Zeiten bedeutungslos. CI-Job auf dem ARM-Runner als Hinweis (6.2) |
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
- Hardware für aarch64-Messungen: vorerst der GitHub-ARM-Runner (6.2);
  ein eigenes Gerät, ein Hochschul-Server oder eine Cloud-Instanz ohne
  Nachbarn wäre genauer.
