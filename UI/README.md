# Web-Oberfläche

Vorführung von FN-DSA (Falcon) im Browser mit allen drei Implementierungen
des Projekts: Rust, C und Python. Entstanden aus `Rust/web/`, Plan und
Entscheidungen in [Rust/UI-PLAN.md](../Rust/UI-PLAN.md) (Abschnitt 12).

## Bedienung

- **Menü oben links:** Signieren, Prüfen, Chat, Vergleich. Die Seite steht
  auch in der Adresse (`#verify`, `#sign`, `#chat`, `#compare`).
- **Oben rechts:** Parametersatz (512/1024, Tasten 1 und 2) und die
  Implementierung, mit der Prüfen, Signieren und Chat rechnen. Die Wahl
  bleibt beim nächsten Öffnen erhalten.
- **Vergleich:** gleiche Nachricht und gleicher Seed für alle drei
  Implementierungen; danach prüft jede die Signaturen der anderen.

## Bauen und starten

```bash
bash UI/build.sh                      # alles; einzeln: rust, c, python, kat
python -m http.server -d UI 8000      # http://localhost:8000
```

Voraussetzungen stehen oben in `build.sh`: für Rust `wasm-bindgen-cli`
0.2.100, für C `emcc` oder Docker (Image `emscripten/emsdk:3.1.74`). Python
braucht nichts; der Browser lädt Pyodide 0.26.4 beim ersten Gebrauch von
jsDelivr, dafür ist eine Internetverbindung nötig.

## Aufbau

| Datei | Inhalt |
|---|---|
| `index.html`, `style.css`, `app.js` | Oberfläche |
| `engines.js` | gemeinsame Schnittstelle der drei Implementierungen |
| `c/wasm_api.c` | Hülle der C-Implementierung für Emscripten |
| `py/webapi.py` | Hülle der Python-Implementierung |
| `python-worker.js` | Pyodide in einem Web Worker |
| `pkg/`, `py/falcon/`, `kat.json` | von `build.sh` erzeugt, nicht eingecheckt |

Die Rust-Hülle liegt weiterhin in `Rust/wasm`.

Schnittstelle in `engines.js`, für alle drei gleich:

- `keygen(logn, seed)`: Schlüsselpaar aus 48 Bytes Seed;
- `sign(key, msg, random)`: Signatur mit Zufall des Aufrufers;
- `verify(pk, sig, msg, runs)`: Prüfbericht mit Ergebnis, Fehlerschritt,
  Norm, Schranke und mittlerer Laufzeit.

C und Python bekommen ihren Zufall als SHAKE-256-Strom über dem Seed und
erzeugen daraus bitgleiche Schlüssel. Rust erzeugt Schlüssel wie die
Referenzimplementierung (NIST-KAT) und kommt deshalb auf einen anderen
Schlüssel; Signaturen prüfen alle drei gegenseitig.

Nur zur Vorführung: Auf WebAssembly gelten die Prüfungen der konstanten
Laufzeit nicht, und Pyodide ist um ein Vielfaches langsamer als natives
Python. Keine echten Schlüssel verwenden.
