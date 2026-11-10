//! Leser für die Testvektoren in `Python/data/vectors/` (erzeugt von
//! `Python/scripts/gen_vectors.py`, dieselben Dateien wie für die C-Tests).
//!
//! Aufbau einer Datei: Kommentarzeilen mit `#`, dann Fälle. Ein Fall beginnt
//! mit `case`; jede weitere Zeile hat die Form `name typ anzahl werte…`, dazu
//! `status ok|error|none`. Gleitkommazahlen stehen als IEEE-754-Bits in Hex,
//! damit sie bitgenau verglichen werden können.

use std::collections::HashMap;
use std::path::PathBuf;

pub struct Case {
    /// Nummer des Falls in der Datei, ab 0.
    pub index: usize,
    pub status: String,
    fields: HashMap<String, (String, Vec<String>)>,
}

impl Case {
    pub fn ok(&self) -> bool {
        self.status == "ok"
    }

    fn field(&self, key: &str, ty: &str) -> &[String] {
        let (t, vals) = self
            .fields
            .get(key)
            .unwrap_or_else(|| panic!("Fall {}: Feld {key} fehlt", self.index));
        assert_eq!(t, ty, "Fall {}: Feld {key}", self.index);
        vals
    }

    pub fn has(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Liste von Gleitkommazahlen als Bits.
    pub fn floats(&self, key: &str) -> Vec<u64> {
        self.field(key, "floats").iter().map(|h| hex64(h)).collect()
    }

    /// Falcon-Baum, flach: ℓ-Werte als (re, im), dann links, dann rechts.
    pub fn tree(&self, key: &str) -> Vec<u64> {
        self.field(key, "tree").iter().map(|h| hex64(h)).collect()
    }

    /// Eine Gleitkommazahl als Bits.
    pub fn float(&self, key: &str) -> u64 {
        hex64(&self.field(key, "float")[0])
    }

    /// Liste komplexer Zahlen als (Realteil, Imaginärteil) in Bits.
    pub fn cplx(&self, key: &str) -> Vec<(u64, u64)> {
        self.field(key, "cplx")
            .chunks(2)
            .map(|p| (hex64(&p[0]), hex64(&p[1])))
            .collect()
    }

    /// Eine Ganzzahl (dezimal).
    pub fn int(&self, key: &str) -> i128 {
        self.field(key, "int")[0].parse().expect("int")
    }

    /// Liste von Ganzzahlen.
    pub fn ints(&self, key: &str) -> Vec<i128> {
        self.field(key, "ints")
            .iter()
            .map(|x| x.parse().expect("ints"))
            .collect()
    }

    /// Bytes (Hex).
    pub fn bytes(&self, key: &str) -> Vec<u8> {
        self.field(key, "bytes")
            .first()
            .map(|h| super::hex(h))
            .unwrap_or_default()
    }

    /// Wahrheitswert (0/1).
    pub fn bool(&self, key: &str) -> bool {
        self.field(key, "bool")[0] == "1"
    }
}

fn hex64(h: &str) -> u64 {
    u64::from_str_radix(h, 16).unwrap_or_else(|_| panic!("ungültiges Hex: {h}"))
}

pub fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("Python")
        .join("data")
        .join("vectors")
        .join(format!("{name}.txt"))
}

/// Liest alle Fälle einer Datei, z. B. `load("fft.fft")`.
pub fn load(name: &str) -> Vec<Case> {
    let p = path(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let mut cases: Vec<Case> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "case" {
            cases.push(Case {
                index: cases.len(),
                status: String::new(),
                fields: HashMap::new(),
            });
            continue;
        }
        let case = cases
            .last_mut()
            .unwrap_or_else(|| panic!("{}: Zeile vor dem ersten Fall", p.display()));
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap().to_string();
        if key == "status" {
            case.status = parts.next().unwrap_or("").to_string();
            continue;
        }
        let ty = parts.next().unwrap_or("").to_string();
        // Die Anzahl wird nur geprüft, wo sie eindeutig ist.
        let count: usize = parts
            .next()
            .map(|c| c.parse().expect("Anzahl"))
            .unwrap_or(0);
        let vals: Vec<String> = parts.map(str::to_string).collect();
        match ty.as_str() {
            "floats" | "ints" => assert_eq!(vals.len(), count, "{}: {key}", p.display()),
            "cplx" => assert_eq!(vals.len(), 2 * count, "{}: {key}", p.display()),
            _ => {}
        }
        case.fields.insert(key, (ty, vals));
    }
    cases
}
