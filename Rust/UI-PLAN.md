# Plan: Web-Oberfläche für die Rust-Implementierung

Stand: 11. November 2026, Branch `Rust`. Ergänzt [PLAN.md](PLAN.md); die
Implementierung selbst (Phasen 0–8) bleibt dort beschrieben.

**Umgesetzt (11.11.2026): W0 bis W5 und W7**, W6 vorbereitet (CI-Job
`pages`, wartet auf die Pages-Einstellung und einen Merge nach `main`).
Ergebnis und Abweichungen in Abschnitt 10.

## 1. Ziel

Eine Web-App, die die Rust-Implementierung im Browser vorführt, vor allem
für die **Präsentation** des Bachelorprojekts:

- Signaturen **prüfen** (geht heute schon, Phase 1);
- zeigen, **wie** Verify zu seinem Ergebnis kommt (fünf Schritte, Norm
  gegen Schranke);
- zeigen, dass eine **veränderte** Signatur abgelehnt wird (Bit kippen);
- **Signieren** und **Schlüssel erzeugen** schon vorsehen, aber gesperrt,
  bis Phase 4/5 fertig sind.

Nicht Ziel: ein Werkzeug für echte Schlüssel. Die App verarbeitet nur
öffentliche Daten (Public Key, Signatur, Nachricht). Solange Sign fehlt,
gibt es im Browser keine geheimen Daten.

## 2. Entscheidungen

| # | Frage | Entscheidung | Grund |
|---|---|---|---|
| U1 | Plattform | Web-App, Rust als WebAssembly | ohne Installation vorführbar, läuft auf jedem Beamer-Laptop |
| U2 | Brücke Rust ↔ JS | `wasm-bindgen`, gebaut mit `wasm-pack --target web` | Standard, erzeugt ES-Modul ohne Bundler |
| U3 | Oberfläche | HTML, CSS, JavaScript ohne Framework und ohne npm-Build | eine Ansicht mit wenig Zustand; nichts, was gepflegt werden muss |
| U4 | Rust-API | neue öffentliche Funktion `verify_report` im Crate `fndsa`, die Zwischenergebnisse liefert | die UI braucht Norm, Schranke und den Schritt, an dem Verify scheitert |
| U5 | Ort im Repository | `Rust/wasm/` (Hülle) und `Rust/web/` (Oberfläche) | nahe am Crate, eigenes Cargo-Paket hält `wasm-bindgen` aus `fndsa` heraus |
| U6 | Testdaten in der App | ausgewählte KAT-Fälle als JSON, erzeugt aus `Python/data/kat/` | keine Eingabe nötig, um die Demo zu starten |
| U7 | Hosting | GitHub Pages, gebaut von GitHub Actions | statische Dateien reichen |
| U8 | Darstellung der Schritte | die UI blendet die fünf Schritte verzögert ein (≈ 0,4 s je Schritt) | Verify dauert in WASM nur Bruchteile einer Millisekunde; ohne Verzögerung sähe man nur das Ergebnis |

Zu U8: Die Verzögerung ist reine Darstellung. Rust rechnet Verify in einem
Aufruf durch, die UI spielt den Bericht danach ab. Die angezeigte Laufzeit
ist die gemessene, nicht die Dauer der Animation.

## 3. Design

Grundlage ist der letzte Entwurf (Aufbau von 5c, Leiste aus 5a, gedämpfte
Farben, kräftiges Türkis nur im Logo).

### 3.1 Aufbau

```
┌─────────────────────────────────────────────────────────────────┐
│ [Logo] FALCON   [Signieren 🔒 | Prüfen]       Falcon-512 · WASM │
├──────────────────────────────┬──────────────────────────────────┤
│ Public Key                   │ Signatur                         │
│ 09a34f1c77e0d2…  897 B       │ 395d2a910bc4e8…  652 B           │
├──────────────────────────────┴───────────────────┬──────────────┤
│ Nachricht                                        │   Status     │
│ Hallo Bern, …                                    │   gültig     │
├──────────────────────────────────────────────────┴──────────────┤
│ Verifikation                              5 / 5 abgeschlossen   │
│ ▬▬▬▬▬  ▬▬▬▬▬  ▬▬▬▬▬  ▬▬▬▬▬  ▬▬▬▬▬                               │
│ ✓ Dekodieren ✓ HashToPoint ✓ s₂ entpacken ✓ s₁ = c − s₂h ✓ Norm │
└─────────────────────────────────────────────────────────────────┘
  [Prüfen]  [KAT-Fall wählen]  [Bit kippen]          [512 | 1024]
```

### 3.2 Farben

Als CSS-Variablen in `web/style.css`, damit sie an einer Stelle stehen.

| Variable | Wert | Verwendung |
|---|---|---|
| `--bg` | `#2C2C2A` | Hintergrund der App |
| `--tile` | `#383836` | Kacheln |
| `--line` | `#444441` | Ränder, leere Abschnitte |
| `--text` | `#D3D1C7` | Haupttext |
| `--text-2` | `#B4B2A9` | Werte in Kacheln |
| `--muted` | `#888780` | Beschriftungen |
| `--brand` | `#0F6E56` / `#E1F5EE` | nur Logo (kräftiges Türkis) |
| `--run` | `#1D9E75` | Abschnitt läuft |
| `--ok` | `#3B6D11` / Text `#97C459` | Abschnitt fertig, „gültig“ |
| `--bad` | `#A32D2D` / Text `#F09595` | Abschnitt gescheitert, „abgelehnt“ |

Grün und Rot erscheinen nur als Rand der Statuskachel, als Abschnitte der
Leiste und als Text; nie als grosse Fläche.

### 3.3 Zustände

| Zustand | Statuskachel | Leiste |
|---|---|---|
| bereit | grau, „bereit“ | alle Abschnitte leer |
| prüft | türkis, „prüft …“, Schritt k von 5 | Abschnitte 1..k türkis |
| gültig | grüner Rand, „gültig“, Laufzeit | alle grün, Häkchen |
| abgelehnt | roter Rand, „abgelehnt“, Grund | bis zum Fehler grün, Fehlerabschnitt rot mit ✕, Rest leer |
| ungültige Eingabe | roter Rand, „Eingabe ungültig“, Grund aus `Error` | Abschnitt „Dekodieren“ rot |

### 3.4 Logo

Im Entwurf ist das Logo ein vereinfachter Falke als Platzhalter. Ob das
offizielle Falcon-Logo (falcon-sign.info) verwendet werden darf, wird vor
der Präsentation geklärt (Lizenz, Erlaubnis der Autoren). Bis dahin bleibt
der eigene Platzhalter als `web/logo.svg`.

### 3.5 Präsentation

- Ausgelegt auf 1920 × 1080 (Beamer); Schrift so gross, dass sie aus der
  letzten Reihe lesbar ist (Ergebnis ≥ 32 px, Beschriftungen ≥ 16 px).
- Funktioniert ab 1280 px Breite; auf dem Handy nur einspaltig, ohne
  Anspruch auf Schönheit.
- Bedienbar mit der Tastatur: `Enter` prüft, `B` kippt ein Bit, `R` setzt
  zurück, `1`/`2` wählen 512/1024. So geht die Vorführung auch mit einem
  Presenter.
- Fokus sichtbar, Zustände nicht nur über Farbe (Häkchen, ✕, Text).

## 4. Änderungen am Crate `fndsa`

Die UI braucht mehr als `bool`. Neu im Crate (öffentliche API):

```rust
/// Ergebnis von Verify mit Zwischenwerten, für Erklärungen und Tests.
#[non_exhaustive]
pub struct VerifyReport {
    pub accepted: bool,
    /// Schritt, an dem Verify abgebrochen hat; None, wenn gültig.
    pub failed_at: Option<VerifyStep>,
    /// ‖(s₁, s₂)‖², falls bis zur Norm gerechnet wurde.
    pub norm: Option<u64>,
    /// ⌊β²⌋ des Parametersatzes.
    pub bound: u64,
}

#[non_exhaustive]
pub enum VerifyStep {
    Decode,       // Grad von Signatur und Schlüssel passt nicht
    HashToPoint,  // kann nicht scheitern, für die Anzeige
    Decompress,   // s₂ ungültig kodiert
    ComputeS1,    // kann nicht scheitern, für die Anzeige
    Norm,         // Norm über der Schranke
}

impl VerifyingKey {
    pub fn verify_report(&self, msg: &[u8], sig: &Signature) -> VerifyReport;
}
```

- `verify` ruft künftig `verify_report(..).accepted` auf, damit es nur
  einen Rechenweg gibt.
- Verify ist öffentlich (PLAN.md 3.1); die Zwischenwerte verraten nichts
  Geheimes.
- Tests: Für alle 200 KAT-Fälle gilt `accepted == true` und
  `norm ≤ bound`; manipulierte Fälle scheitern am erwarteten Schritt
  (fremder Grad → `Decode`, kaputte Kodierung → `Decompress`, gekipptes
  Bit im Salt → `Norm`).

Fehler beim Dekodieren von Public Key oder Signatur kommen weiter als
`Error` aus `from_bytes`; die UI zeigt sie als Zustand „ungültige Eingabe“.

## 5. WASM-Hülle `Rust/wasm/`

Eigenes Paket `fndsa-wasm` (`crate-type = ["cdylib"]`), abhängig von
`fndsa` und `wasm-bindgen`. Es enthält nur Umwandlungen, keine Logik.

```rust
#[wasm_bindgen]
pub fn verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<JsValue, JsError>;
// liefert { accepted, failedAt, norm, bound, logn, micros }

#[wasm_bindgen]
pub fn version() -> String;  // Crate-Version und Phase, für die Fusszeile
```

- Laufzeit misst JavaScript mit `performance.now()` über 100 Aufrufe und
  teilt durch 100, weil ein einzelner Aufruf unter der Auflösung des
  Browsers liegt.
- Grösse: Ziel < 200 kB `.wasm` mit `opt-level = "s"` und `wasm-opt`.
- `ct::barrier` nutzt auf `wasm32` den Rückfall `black_box`. Für Verify
  unkritisch; für Sign im Browser später gesondert bewerten (PLAN.md §6
  gilt nur für x86-64 und aarch64).
- Für Sign braucht es später Zufall im Browser: `getrandom` mit
  JavaScript-Unterstützung (`crypto.getRandomValues`).

## 6. Oberfläche `Rust/web/`

```
web/
  index.html      Aufbau aus 3.1, Texte auf Deutsch
  style.css       Farben aus 3.2, Raster, Zustände
  app.js          Zustand, Animation, Tastatur, Aufruf der WASM-Hülle
  kat.json        ausgewählte KAT-Fälle (erzeugt, siehe unten)
  logo.svg        Platzhalter-Logo
  pkg/            Ausgabe von wasm-pack (nicht eingecheckt)
```

### 6.1 Funktionen

- **KAT-Fall wählen:** Liste mit 10 Fällen je Parametersatz; Auswahl füllt
  Public Key, Signatur und Nachricht.
- **Eigene Daten:** Hex einfügen oder Datei laden (pk, sig, msg); Länge
  und Header werden sofort angezeigt.
- **Prüfen:** ruft `verify`, spielt danach die fünf Schritte ab.
- **Bit kippen:** wählt ein zufälliges Bit im Salt oder in s₂, markiert das
  Byte rot in der Signaturkachel und prüft neu. „Original wiederherstellen“
  macht es rückgängig.
- **512 | 1024:** wechselt den Parametersatz und lädt den ersten KAT-Fall.
- **Signieren (gesperrt):** Schloss mit Hinweis „kommt mit Phase 4“.

### 6.2 KAT-Daten

Ein Beispielprogramm `examples/export_kat_json.rs` (wie `seed_corpus.rs`)
liest `Python/data/kat/`, nimmt je Parametersatz 10 Fälle, prüft sie mit
`verify` und schreibt `web/kat.json`:

```json
{ "512": [ { "count": 0, "pk": "09…", "sig": "39…", "msg": "d8…" } ], "1024": [ … ] }
```

Die Signatur steht im Format der Spezifikation (Header 0x3n), wie
`split_kat_sm` es liefert.

## 7. Bauen, Testen, Ausliefern

Lokal:

```bash
cd Rust
cargo install wasm-pack
wasm-pack build wasm --target web --out-dir ../web/pkg
cargo run --example export_kat_json -- web/kat.json
python -m http.server -d web 8000     # http://localhost:8000
```

CI (`.github/workflows/rust.yml`, neuer Job `web`):

1. `rustup target add wasm32-unknown-unknown`, `wasm-pack` installieren;
2. `wasm-pack test --node wasm`: Tests der Hülle (KAT-Fall gültig,
   gekipptes Bit abgelehnt, kaputte Eingabe ergibt Fehler statt Absturz);
3. `wasm-pack build` und `export_kat_json`;
4. auf `main`: `web/` als Artefakt hochladen und mit
   `actions/deploy-pages` veröffentlichen.

Vorher einmal in den Repository-Einstellungen GitHub Pages auf „GitHub
Actions“ stellen; das kann nur der Besitzer des Repositorys.

Getestet wird von Hand in Chrome, Firefox und Safari (falls verfügbar) und
einmal am Beamer in voller Grösse.

## 8. Phasen

| Phase | Inhalt | fertig, wenn |
|---|---|---|
| W0 | `wasm32`-Ziel, `wasm-pack`, leere Hülle, CI-Job baut sie | `wasm-pack build` läuft lokal und in der CI |
| W1 | `verify_report` im Crate, Tests aus §4 | `ci.sh` grün, alle KAT-Fälle mit Norm |
| W2 | Hülle `verify`/`version`, `wasm-pack test` | Tests der Hülle grün |
| W3 | statische Seite nach §3 mit festen Werten | sieht aus wie der Entwurf, 1920 × 1080 und 1280 px |
| W4 | KAT-Auswahl, Prüfen, Animation, Bit kippen, Tastatur | alle Zustände aus §3.3 erreichbar |
| W5 | eigene Daten (Hex, Datei), Fehlermeldungen | ungültige Eingaben zeigen Grund statt Absturz |
| W6 | GitHub Pages | App unter der Pages-Adresse erreichbar |
| W7 | Sign und Keygen freischalten (nach PLAN.md Phase 4/5) | Signieren im Browser, danach Prüfen derselben Signatur |

W1 und W3 hängen nicht voneinander ab und können parallel laufen.

Bewusst ausgelassen: Darstellung der Polynome und der NTT, Vergleich mit
Python oder C im Browser, Messung der Laufzeit als Benchmark. Das kann
später als eigene Ansicht dazukommen.

## 9. Offene Punkte

- Darf das offizielle Falcon-Logo verwendet werden (3.4)?
- Soll die Seite öffentlich auf GitHub Pages stehen oder nur lokal für die
  Präsentation laufen?
- Gibt es am Präsentationsort Internet? Wenn nicht, die App lokal mit
  `python -m http.server` starten (alle Dateien liegen im Ordner `web/`,
  ohne Abhängigkeiten aus dem Netz).

## 10. Ergebnis der Umsetzung (11.11.2026)

| Phase | Stand |
|---|---|
| W0 | Paket `wasm/` (`fndsa-wasm`, `cdylib` + `rlib`), Ziel `wasm32-unknown-unknown`; CI-Job `web` |
| W1 | `VerifyingKey::verify_report`, `VerifyReport`, `VerifyStep` im Crate; `verify` ruft es auf. Test `verify_report_steps`: alle 200 KAT-Fälle gültig mit Norm ≤ Schranke; gekipptes Bit im Salt → `Norm`, gekürztes s₂ → `Decompress`, fremder Grad → `Decode` |
| W2 | Hülle mit `verify`, `version` und `Signer`; 4 Tests (`cargo test` in `wasm/`, auch in `ci.sh`) |
| W3 | Seite nach §3 (`web/index.html`, `style.css`, `logo.svg`); geprüft in 1920 × 1080, 1280 × 800 und 375 px (einspaltig, ohne seitliches Scrollen) |
| W4 | KAT-Auswahl (10 je Parametersatz), Prüfen mit Animation, Bit kippen mit markiertem Byte, Original, 512/1024, Tastatur (Enter, B, R, 1, 2); alle Zustände aus §3.3 erreicht |
| W5 | Dialog „Eigene Daten“: Hex oder Datei für pk, Signatur, Nachricht (Text oder Hex). Ungültiges Hex: Meldung im Dialog; ungültiges Format: Zustand „Eingabe ungültig“ mit dem Grund aus `Error` |
| W6 | CI-Job `pages` (nur bei Push auf `main`); offen: Pages in den Einstellungen auf „GitHub Actions“ stellen und die Frage aus §9, ob die Seite öffentlich sein soll |
| W7 | Ansicht „Signieren“: Schlüssel erzeugen, signieren, „In Prüfen übernehmen“ |

Gemessen im Browser der Vorschau (Chromium, gleicher Rechner wie
PLAN.md 5.2): Verify Falcon-512 42–75 µs, Falcon-1024 133–141 µs;
Signieren Falcon-1024 30 ms. Eine durchgängige Probe (Keygen 1024 →
Sign → Prüfen) ergab „gültig“.

**Abweichungen vom Plan:**

- **`wasm-bindgen-cli` statt `wasm-pack`:** `wasm-pack` lädt beim Bauen
  Werkzeuge aus dem Netz nach; `cargo build` plus `wasm-bindgen` (von
  crates.io, Version 0.2.100 wie in `wasm/Cargo.toml`) ergibt dasselbe.
  Bauen mit `web/build.sh`.
- **Tests der Hülle nativ** statt `wasm-pack test --node`: Die Logik steht
  in Funktionen ohne `wasm-bindgen` (`verify_bytes`, `Signer::generate`,
  `sign_bytes`), die `cargo test` prüft. Die Seite selbst ist von Hand im
  Browser geprüft (Chromium); Firefox, Safari und der Beamer stehen noch
  aus.
- **Grösse 236 kB** statt < 200 kB: ohne `wasm-opt` (müsste ebenfalls aus
  dem Netz geladen werden). Für eine lokale Vorführung unkritisch.
- **Zufall für Sign** kommt aus `crypto.getRandomValues` und wird als
  Bytes übergeben (48 für Keygen, 40 je Sign, daraus SHAKE256); kein
  `getrandom` nötig.
- **`kat.json`** wird erzeugt (`web/build.sh`) und nicht eingecheckt, wie
  `web/pkg/`.
- **Beamer-Grössen:** ab 1600 × 900 grössere Schrift (Ergebnis 56 px,
  Beschriftungen 18 px), damit die Fläche genutzt wird.

**Sicherheitshinweis in der App:** Auf `wasm32` gibt es keine
Optimierungsbarriere in Assembler, und die Prüfungen der konstanten
Laufzeit (PLAN.md §6) gelten nur für x86-64 und aarch64. Die Ansicht
„Signieren“ sagt deshalb „nur zur Vorführung, keine echten Schlüssel“. Der
Secret Key verlässt den WASM-Speicher nicht und wird beim Verwerfen
gelöscht (`zeroize` im Crate).

## 11. Ergänzung: Chat (11.11.2026)

Dritte Ansicht „Chat“ nach Entwurf 3 (Messenger mit Prüfbericht), ohne
Änderung an „Signieren“ und „Prüfen“ und ohne neue Rust-Funktion (nutzt
`Signer` und `verify` der WASM-Hülle):

- Beim ersten Öffnen entstehen zwei Schlüsselpaare (du und Alice) für den
  gewählten Parametersatz; ein Wechsel 512/1024 erzeugt neue. Drei
  Startnachrichten sind schon signiert und geprüft.
- Jede Nachricht wird mit dem Schlüssel des Absenders signiert (Zufall aus
  `crypto.getRandomValues`) und mit dessen Public Key geprüft, wie es der
  Empfänger täte. Die Blase zeigt „✓ signiert · gültig“ bzw. „✕ ungültig“.
- Ein Klick auf eine Nachricht zeigt rechts den Prüfbericht: Ergebnis,
  gemessene Zeit (Mittel aus 20 Aufrufen), die fünf Schritte, Norm gegen
  Schranke, Salt und Längen.
- „Nachricht verfälschen“ ändert ein Zeichen der Nachricht bei
  unveränderter Signatur; Verify scheitert dann am Schritt „Norm“.
  „Original“ stellt den Text wieder her.
- Ein Fenster, Alice wird simuliert („Schreiben als: Du | Alice“); kein
  Server nötig.

Geprüft in der Vorschau (Chromium) bei 1920 × 1080, 1280 × 800 und 375 px:
Senden als du und als Alice, Verfälschen und Wiederherstellen, Wechsel auf
Falcon-1024, keine Fehler in der Konsole.
