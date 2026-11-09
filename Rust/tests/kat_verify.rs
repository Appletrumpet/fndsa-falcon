//! Phase 1: Verify gegen die NIST-KAT-Dateien (PLAN.md, Abschnitt 5).
//!
//! - alle 100 Signaturen je Parametersatz werden akzeptiert (Falcon-1024
//!   count = 82 ist ungepolstert länger als die feste Länge);
//! - pk-Format byte-genau (dekodieren und wieder kodieren);
//! - Gegenproben: veränderte Nachricht, fremder Schlüssel, verändertes s₂.

mod common;

use common::{load_kat, split_kat_sm};
use fndsa::{Signature, VerifyingKey};

fn check_all(n: usize) {
    for rec in load_kat(n) {
        let (msg, sig_bytes) = split_kat_sm(&rec.sm, rec.msg.len());
        assert_eq!(msg, rec.msg, "count {}", rec.count);
        let pk = VerifyingKey::from_bytes(&rec.pk).unwrap();
        assert_eq!(pk.to_bytes(), rec.pk, "pk count {}", rec.count);
        let sig = Signature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig.to_bytes(), sig_bytes);
        assert!(pk.verify(&msg, &sig), "verify count {}", rec.count);
    }
}

#[test]
fn kat_verify_512() {
    check_all(512);
}

#[test]
fn kat_verify_1024() {
    check_all(1024);
}

#[test]
fn kat_rejects_tampered() {
    for n in [512, 1024] {
        let recs = load_kat(n);
        for (a, b) in recs.iter().zip(recs.iter().skip(1)).take(5) {
            let (msg, sig_bytes) = split_kat_sm(&a.sm, a.msg.len());
            let sig = Signature::from_bytes(&sig_bytes).unwrap();
            let pk_a = VerifyingKey::from_bytes(&a.pk).unwrap();
            let pk_b = VerifyingKey::from_bytes(&b.pk).unwrap();

            let mut tampered = msg.clone();
            tampered[0] ^= 1;
            assert!(!pk_a.verify(&tampered, &sig), "Nachricht count {}", a.count);
            assert!(!pk_b.verify(&msg, &sig), "fremder pk count {}", a.count);

            // Salt verändern
            let mut bad = sig_bytes.clone();
            bad[1] ^= 1;
            assert!(!pk_a.verify(&msg, &Signature::from_bytes(&bad).unwrap()));

            // Erstes Bit von s₂ (Vorzeichen) umdrehen
            let mut bad = sig_bytes.clone();
            bad[41] ^= 0x80;
            assert!(!pk_a.verify(&msg, &Signature::from_bytes(&bad).unwrap()));
        }
    }
}

#[test]
fn signature_of_other_degree_is_rejected() {
    let r512 = &load_kat(512)[0];
    let r1024 = &load_kat(1024)[0];
    let (msg, sig_bytes) = split_kat_sm(&r512.sm, r512.msg.len());
    let sig = Signature::from_bytes(&sig_bytes).unwrap();
    let pk1024 = VerifyingKey::from_bytes(&r1024.pk).unwrap();
    assert!(!pk1024.verify(&msg, &sig));
}

#[test]
fn malformed_inputs() {
    assert!(Signature::from_bytes(&[0x39; 41]).is_err());
    assert!(Signature::from_bytes(&[0x29; 50]).is_err());
    assert!(Signature::from_bytes(&[0x30; 50]).is_err()); // logn = 0
    assert!(VerifyingKey::from_bytes(&[]).is_err());
    assert!(VerifyingKey::from_bytes(&[0x09; 10]).is_err());
}
