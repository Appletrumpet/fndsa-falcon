//! Erzeugt den Start-Korpus für `cargo fuzz` aus den NIST-KAT-Dateien.
//!
//! Ohne Korpus kommt der Fuzzer kaum über die Eingabeprüfung hinaus: Ein
//! zufälliger Public Key ist nur gültig, wenn alle 512 Koeffizienten unter q
//! liegen (Wahrscheinlichkeit ≈ 0,75⁵¹²). Mit gültigen Startdaten verändert
//! libFuzzer echte Schlüssel und Signaturen und erreicht so Verify.
//!
//! Aufruf (im Ordner Rust/):
//!
//! ```text
//! cargo run --example seed_corpus -- fuzz/corpus
//! ```
//!
//! Legt je Ziel einen Ordner an (`decode_pk`, `decode_sk`, `decompress`,
//! `verify`, `signing_key`) mit dem Aufbau, den `src/fuzzing.rs` erwartet.

#[path = "../tests/common/mod.rs"]
mod common;

use std::fs;
use std::path::PathBuf;

use fndsa::{Signature, VerifyingKey};

/// Fälle je Parametersatz; mehr bringt dem Fuzzer kaum neue Pfade.
const PER_SET: usize = 10;

fn main() {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("Aufruf: seed_corpus <Zielordner>"),
    );
    let mut files = 0;
    for n in [512, 1024] {
        for rec in common::load_kat(n).iter().take(PER_SET) {
            let (msg, sig) = common::split_kat_sm(&rec.sm, rec.msg.len());

            // Eingabe für das Verify-Ziel: pk ‖ Signaturlänge (2 Bytes) ‖
            // Signatur ‖ Nachricht. Muss wirklich gültig sein, sonst nützt
            // sie als Startpunkt nichts.
            let pk = VerifyingKey::from_bytes(&rec.pk).expect("KAT-pk");
            let s = Signature::from_bytes(&sig).expect("KAT-Signatur");
            assert!(pk.verify(&msg, &s), "KAT {n} count {}", rec.count);
            let siglen = u16::try_from(sig.len()).expect("Signaturlänge");
            let mut verify = rec.pk.clone();
            verify.extend(siglen.to_be_bytes());
            verify.extend(&sig);
            verify.extend(&msg);

            let name = format!("kat{n}-{:03}", rec.count);
            for (target, data) in [
                ("decode_pk", &rec.pk[..]),
                ("decode_sk", &rec.sk[..]),
                ("signing_key", &rec.sk[..]),
                ("decompress", &sig[41..]),
                ("verify", &verify[..]),
            ] {
                let dir = out.join(target);
                fs::create_dir_all(&dir).expect("Ordner anlegen");
                fs::write(dir.join(&name), data).expect("Datei schreiben");
                files += 1;
            }
        }
    }
    println!("{files} Dateien in {}", out.display());
}
