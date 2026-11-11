//! Schreibt ausgewählte NIST-KAT-Fälle als JSON für die Web-Oberfläche
//! (UI-PLAN.md §6.2).
//!
//! Je Parametersatz 10 Fälle: Public Key, Signatur im Format der
//! Spezifikation (Header 0x3n, wie `split_kat_sm` es liefert) und
//! Nachricht, alles als Hex. Jeder Fall wird vorher mit Verify geprüft.
//!
//! ```text
//! cargo run --example export_kat_json -- web/kat.json
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use fndsa::{Signature, VerifyingKey};

const PER_SET: usize = 10;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("Aufruf: export_kat_json <Zieldatei>");
    let mut sets = Vec::new();
    for n in [512, 1024] {
        let mut cases = Vec::new();
        for rec in common::load_kat(n).iter().take(PER_SET) {
            let (msg, sig) = common::split_kat_sm(&rec.sm, rec.msg.len());
            let pk = VerifyingKey::from_bytes(&rec.pk).expect("KAT-pk");
            let s = Signature::from_bytes(&sig).expect("KAT-Signatur");
            assert!(pk.verify(&msg, &s), "KAT {n} count {}", rec.count);
            cases.push(format!(
                "    {{ \"count\": {}, \"pk\": \"{}\", \"sig\": \"{}\", \"msg\": \"{}\" }}",
                rec.count,
                hex(&rec.pk),
                hex(&sig),
                hex(&msg)
            ));
        }
        sets.push(format!("  \"{n}\": [\n{}\n  ]", cases.join(",\n")));
    }
    let json = format!("{{\n{}\n}}\n", sets.join(",\n"));
    std::fs::write(&out, json).expect("Datei schreiben");
    println!("{} Fälle je Parametersatz in {out}", PER_SET);
}
