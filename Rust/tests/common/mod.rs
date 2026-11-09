//! Parser für die NIST-KAT-Dateien in `Python/data/kat/`.
//!
//! Wird von den Integrationstests (`mod common;`) und von den Unit-Tests im
//! Crate (`#[path]` in lib.rs) benutzt; deshalb nur `std`.
#![allow(dead_code)]

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
    assert!(s.len() % 2 == 0, "ungerade Hex-Länge");
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
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    for block in text.split("count = ").skip(1) {
        let count: usize = block.lines().next().unwrap().trim().parse().unwrap();
        let get =|key: &str| -> Vec<u8> {
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
