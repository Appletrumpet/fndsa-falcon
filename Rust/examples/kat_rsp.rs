//! KAT-Dateien im Format der NIST-API mit Rust erzeugen und mit den
//! offiziellen Dateien vergleichen (PLAN.md Phase 7, L10).
//!
//! Wie `PQCgenKAT_sign`: Für jeden Fall wird der AES-256-CTR-DRBG mit dem
//! `seed` der offiziellen Datei gestartet, daraus erzeugt Rust Schlüssel
//! und Signatur. Geschrieben wird `falcon512-KAT.rsp` und
//! `falcon1024-KAT.rsp` in den angegebenen Ordner (Standard:
//! `target/kat`), danach ein Vergleich Feld für Feld.
//!
//! Erwartet: count, seed, mlen, msg, pk und sk gleich; in `sm` sind Länge,
//! Salt und Nachricht gleich oder die Länge weicht ab, die komprimierte
//! Signatur weicht ab (BerExp liest immer 8 Bytes, L7; Sampler mit
//! ChaCha20, L9); jede Rust-Signatur besteht Verify.
//!
//! ```text
//! cargo run --release --example kat_rsp [Zielordner]
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use std::fmt::Write as _;
use std::path::PathBuf;

use common::drbg::Drbg;
use common::{load_kat, split_kat_sm, KatRecord};
use fndsa::{keygen_from_seed, LogN, Signature, VerifyingKey};
use rand_core::{CryptoRng, RngCore};

struct DrbgRng(Drbg);

impl RngCore for DrbgRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DrbgRng {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Signatur im Format der NIST-API: Länge (2 Bytes), Salt, Nachricht,
/// Header 0010nnnn und s₂ ungepolstert (ohne Nullbytes am Ende).
fn kat_sm(sig: &Signature, msg: &[u8]) -> Vec<u8> {
    let b = sig.to_bytes();
    let mut s2 = &b[41..];
    while let [rest @ .., 0] = s2 {
        s2 = rest;
    }
    let siglen = 1 + s2.len();
    let mut sm = Vec::with_capacity(2 + 40 + msg.len() + siglen);
    sm.extend((siglen as u16).to_be_bytes());
    sm.extend(sig.salt());
    sm.extend(msg);
    sm.push(0x20 | sig.logn().get() as u8);
    sm.extend(s2);
    sm
}

#[derive(Default)]
struct Summary {
    cases: usize,
    pk_sk_equal: usize,
    salt_equal: usize,
    sm_equal: usize,
    smlen_equal: usize,
    verify_ok: usize,
}

fn run(n: usize, logn: LogN, out: &mut String) -> Summary {
    let mut s = Summary::default();
    let _ = write!(out, "# Falcon-{n}\n\n");
    for rec in load_kat(n) {
        let KatRecord {
            count,
            seed,
            msg,
            pk,
            sk,
            sm,
            ..
        } = &rec;
        let mut drbg = Drbg::new(seed);
        let mut kseed = [0u8; 48];
        drbg.fill(&mut kseed);
        let (rsk, rpk) = keygen_from_seed(logn, &kseed).expect("Keygen");
        let sig = rsk.sign(msg, &mut DrbgRng(drbg));
        let rsm = kat_sm(&sig, msg);

        let _ = write!(
            out,
            "count = {count}\nseed = {}\nmlen = {}\nmsg = {}\npk = {}\nsk = {}\nsmlen = {}\nsm = {}\n\n",
            hex(seed),
            msg.len(),
            hex(msg),
            hex(&rpk.to_bytes()),
            hex(&rsk.to_bytes()),
            rsm.len(),
            hex(&rsm)
        );

        s.cases += 1;
        s.pk_sk_equal += (rpk.to_bytes() == *pk && rsk.to_bytes()[..] == sk[..]) as usize;
        s.salt_equal += (rsm[2..42] == sm[2..42]) as usize;
        s.sm_equal += (rsm == *sm) as usize;
        s.smlen_equal += (rsm.len() == sm.len()) as usize;
        // Rust-Signatur im KAT-Format mit dem offiziellen pk prüfen
        let (m, std_sig) = split_kat_sm(&rsm, msg.len());
        let ok = VerifyingKey::from_bytes(pk)
            .ok()
            .zip(Signature::from_bytes(&std_sig).ok())
            .is_some_and(|(k, sg)| k.verify(&m, &sg));
        s.verify_ok += ok as usize;
    }
    s
}

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "target/kat".into()),
    );
    std::fs::create_dir_all(&dir).expect("Zielordner anlegen");
    println!(
        "{:<12} {:>6} {:>12} {:>10} {:>12} {:>10} {:>10}",
        "Datei", "Fälle", "pk, sk gleich", "Salt gleich", "smlen gleich", "sm gleich", "Verify ok"
    );
    for (n, logn) in [(512, LogN::FALCON_512), (1024, LogN::FALCON_1024)] {
        let mut out = String::new();
        let s = run(n, logn, &mut out);
        let path = dir.join(format!("falcon{n}-KAT.rsp"));
        std::fs::write(&path, out).expect("Datei schreiben");
        println!(
            "{:<12} {:>6} {:>12} {:>10} {:>12} {:>10} {:>10}",
            format!("falcon{n}"),
            s.cases,
            s.pk_sk_equal,
            s.salt_equal,
            s.smlen_equal,
            s.sm_equal,
            s.verify_ok
        );
    }
    println!("geschrieben nach {}", dir.display());
}
