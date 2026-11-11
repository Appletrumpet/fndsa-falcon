//! Parser für die NIST-KAT-Dateien in `Python/data/kat/`.
//!
//! Wird von den Integrationstests (`mod common;`) und von den Unit-Tests im
//! Crate (`#[path]` in lib.rs) benutzt; deshalb nur `std`.
#![allow(dead_code)]

pub mod drbg;
pub mod vectors;

use std::path::PathBuf;

pub struct KatRecord {
    pub count: usize,
    pub seed: Vec<u8>,
    pub msg: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub sm: Vec<u8>,
}

pub fn hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2), "ungerade Hex-Länge");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("ungültiges Hex"))
        .collect()
}

pub fn kat_path(n: usize) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("Python")
        .join("data")
        .join("kat")
        .join(format!("falcon{n}-KAT.rsp"))
}

/// Liest alle 100 Fälle einer `.rsp`-Datei.
pub fn load_kat(n: usize) -> Vec<KatRecord> {
    let path = kat_path(n);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    for block in text.split("count = ").skip(1) {
        let count: usize = block.lines().next().unwrap().trim().parse().unwrap();
        let get = |key: &str| -> Vec<u8> {
            let prefix = format!("{key} = ");
            let line = block
                .lines()
                .find(|l| l.starts_with(&prefix))
                .unwrap_or_else(|| panic!("count {count}: {key} fehlt"));
            hex(&line[prefix.len()..])
        };
        out.push(KatRecord {
            count,
            seed: get("seed"),
            msg: get("msg"),
            pk: get("pk"),
            sk: get("sk"),
            sm: get("sm"),
        });
    }
    assert_eq!(out.len(), 100, "{}: erwartet 100 Fälle", path.display());
    out
}

/// Kopfteil der Sampler-Testvektoren (`Python/data/sampler/`): Nonce,
/// Nachricht, Schlüssel, gehashte Nachricht und s₂ der Beispielsignatur.
/// Die SamplerZ-Abläufe darin werden erst in Phase 3 gebraucht.
pub struct SamplerVector {
    pub nonce: Vec<u8>,
    pub data: Vec<u8>,
    pub f: Vec<i32>,
    pub g: Vec<i32>,
    pub big_f: Vec<i32>,
    pub big_g: Vec<i32>,
    pub hashed: Vec<u32>,
    pub s2: Vec<i32>,
}

pub fn load_sampler_vector(n: usize) -> SamplerVector {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("Python")
        .join("data")
        .join("sampler")
        .join(format!("test-vector-sampler-falcon{n}.txt"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let field = |key: &str| -> &str {
        let prefix = format!("{key} = ");
        text.lines()
            .map(str::trim)
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{}: {key} fehlt", path.display()))[prefix.len()..]
            .trim()
    };
    let ints = |key: &str| -> Vec<i32> {
        field(key)
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect()
    };
    let v = SamplerVector {
        nonce: hex(field("nonce")),
        data: hex(field("data")),
        f: ints("f"),
        g: ints("g"),
        big_f: ints("F"),
        big_g: ints("G"),
        hashed: ints("hashed message")
            .into_iter()
            .map(|x| x as u32)
            .collect(),
        s2: ints("signature vector"),
    };
    for (name, len) in [
        ("f", v.f.len()),
        ("hashed", v.hashed.len()),
        ("s2", v.s2.len()),
    ] {
        assert_eq!(len, n, "{}: Länge von {name}", path.display());
    }
    v
}

/// Zerlegt `sm` im Format der NIST-API (§3.11.6):
/// Länge (2 Bytes), Salt (40), Nachricht, Signatur mit Header 0x2n ohne
/// Padding. Gibt Nachricht und Signatur im Format der Spezifikation zurück
/// (Header 0x3n ‖ Salt ‖ s₂).
pub fn split_kat_sm(sm: &[u8], mlen: usize) -> (Vec<u8>, Vec<u8>) {
    let siglen = u16::from_be_bytes([sm[0], sm[1]]) as usize;
    let salt = &sm[2..42];
    let msg = &sm[42..42 + mlen];
    let sig = &sm[42 + mlen..];
    assert_eq!(sig.len(), siglen, "KAT-Signaturlänge");
    assert_eq!(sig[0] & 0xF0, 0x20, "KAT-Signatur-Header");
    let mut std_sig = vec![0x30 | (sig[0] & 0x0F)];
    std_sig.extend_from_slice(salt);
    std_sig.extend_from_slice(&sig[1..]);
    (msg.to_vec(), std_sig)
}
